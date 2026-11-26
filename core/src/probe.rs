use crate::config::ShieldConfig;
use reqwest::{Client, Proxy};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChannelProbe {
    pub ip: String,
    pub latency_ms: Option<u64>,
    pub colo: Option<String>,
    pub loc: Option<String>,
    pub tls: Option<String>,
    pub http: Option<String>,
    pub warp: Option<String>,
    pub reachable: bool,
}

impl ChannelProbe {
    pub fn unreachable() -> Self {
        Self {
            ip: "无法连通".to_string(),
            latency_ms: None,
            colo: None,
            loc: None,
            tls: None,
            http: None,
            warp: None,
            reachable: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiLatencyMetrics {
    /// Calibrated real-world 1-RTT HTTP/2 latency (warmed keep-alive median/min, zero handshake inflation)
    pub warm_rtt_ms: Option<u64>,
    /// Cold TCP + TLS 1.3 + HTTP/2 initial handshake time (for diagnostics)
    pub cold_connect_ms: Option<u64>,
    /// Wire jitter between consecutive warmed HTTP/2 probes
    pub jitter_ms: Option<u64>,
    /// HTTP status observed on api.anthropic.com edge
    pub status_code: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkProbeResult {
    pub proxy: ChannelProbe,
    pub tun: ChannelProbe,
    pub claude_edge: ChannelProbe,
    pub api_latency: ApiLatencyMetrics,
}

const UA: &str = "curl/8.7.1";

pub fn build_proxy_client(cfg: &ShieldConfig, timeout_secs: u64) -> Result<Client, reqwest::Error> {
    Client::builder()
        .proxy(Proxy::all(cfg.proxy_http_url())?)
        .local_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        .user_agent(UA)
        .timeout(Duration::from_secs(timeout_secs))
        .connect_timeout(Duration::from_secs(timeout_secs.min(4)))
        .pool_max_idle_per_host(6)
        .pool_idle_timeout(Duration::from_secs(30))
        .tcp_nodelay(true)
        .build()
}

pub fn build_direct_v4_client(timeout_secs: u64) -> Result<Client, reqwest::Error> {
    Client::builder()
        .no_proxy()
        .local_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        .user_agent(UA)
        .timeout(Duration::from_secs(timeout_secs))
        .connect_timeout(Duration::from_secs(timeout_secs.min(4)))
        .pool_max_idle_per_host(6)
        .pool_idle_timeout(Duration::from_secs(30))
        .tcp_nodelay(true)
        .build()
}

pub fn build_direct_v6_client(timeout_secs: u64) -> Result<Client, reqwest::Error> {
    Client::builder()
        .no_proxy()
        .local_address(IpAddr::V6(Ipv6Addr::UNSPECIFIED))
        .user_agent(UA)
        .timeout(Duration::from_secs(timeout_secs))
        .connect_timeout(Duration::from_secs(timeout_secs.min(2)))
        .tcp_nodelay(true)
        .build()
}

pub(crate) struct CfTrace {
    pub ip: String,
    pub colo: Option<String>,
    pub loc: Option<String>,
    pub tls: Option<String>,
    pub http: Option<String>,
    pub warp: Option<String>,
}

pub(crate) fn parse_cf_trace(body: &str) -> CfTrace {
    let mut ip = String::new();
    let mut colo = None;
    let mut loc = None;
    let mut tls = None;
    let mut http = None;
    let mut warp = None;
    for line in body.lines() {
        if let Some(v) = line.strip_prefix("ip=") {
            ip = v.trim().to_string();
        } else if let Some(v) = line.strip_prefix("colo=") {
            colo = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("loc=") {
            loc = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("tls=") {
            tls = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("http=") {
            http = Some(v.trim().to_string());
        } else if let Some(v) = line.strip_prefix("warp=") {
            warp = Some(v.trim().to_string());
        }
    }
    CfTrace { ip, colo, loc, tls, http, warp }
}

pub(crate) fn is_valid_ip_str(s: &str) -> bool {
    !s.is_empty() && s.len() <= 45 && !s.contains(char::is_whitespace) && s.parse::<IpAddr>().is_ok()
}

/// Probe Cloudflare trace URLs in priority order:
/// req1 fetches IP/metadata & warms HTTP/2 keep-alive;
/// req2-3 (warmed GET on same HTTP/2 stream, ~196B payload, zero redirects) measure true calibrated 1-RTT wire latency.
/// Note: HEAD on 1.1.1.1/cdn-cgi/trace returns 302 -> one.one.one.one (inflating RTT 2-3x),
/// and HEAD on claude.ai/cdn-cgi/trace returns 403 challenge; GET returns 200 directly on all endpoints.
pub async fn probe_trace_channel(client: &Client, primary_url: &str, measure_rtt: bool) -> ChannelProbe {
    let trace_urls: Vec<&str> = if primary_url.contains("1.1.1.1") {
        vec![primary_url, "https://www.cloudflare.com/cdn-cgi/trace"]
    } else {
        vec![primary_url, "https://1.1.1.1/cdn-cgi/trace"]
    };

    for trace_url in trace_urls {
        if let Ok(resp) = client.get(trace_url).send().await {
            if resp.status().is_success() {
                if let Ok(body) = resp.text().await {
                    let trace = parse_cf_trace(&body);
                    if is_valid_ip_str(&trace.ip) {
                        let mut rtt = None;
                        if measure_rtt {
                            let mut samples = Vec::with_capacity(2);
                            for _ in 0..2 {
                                let t0 = Instant::now();
                                if let Ok(r2) = client.get(trace_url).send().await {
                                    let _ = r2.bytes().await;
                                    samples.push(t0.elapsed().as_millis().max(1) as u64);
                                }
                            }
                            rtt = samples.into_iter().min();
                        }
                        return ChannelProbe {
                            ip: trace.ip,
                            latency_ms: rtt,
                            colo: trace.colo,
                            loc: trace.loc,
                            tls: trace.tls,
                            http: trace.http,
                            warp: trace.warp,
                            reachable: true,
                        };
                    }
                }
            }
        }
    }

    // Fallback plain IP providers
    for fallback in ["https://api.ipify.org", "https://ifconfig.me/ip"] {
        let t0 = Instant::now();
        if let Ok(resp) = client.get(fallback).send().await {
            if resp.status().is_success() {
                if let Ok(text) = resp.text().await {
                    let ip = text.trim().to_string();
                    if is_valid_ip_str(&ip) {
                        let rtt = if measure_rtt {
                            let t1 = Instant::now();
                            if client.head(fallback).send().await.is_ok() {
                                Some(t1.elapsed().as_millis().max(1) as u64)
                            } else {
                                Some(t0.elapsed().as_millis().max(1) as u64)
                            }
                        } else {
                            None
                        };
                        return ChannelProbe {
                            ip,
                            latency_ms: rtt,
                            colo: None,
                            loc: None,
                            tls: None,
                            http: None,
                            warp: None,
                            reachable: true,
                        };
                    }
                }
            }
        }
    }

    ChannelProbe::unreachable()
}

const API_PROBE_URL: &str = "https://api.anthropic.com/";
const API_WARM_SAMPLES: usize = 4;
const API_SAMPLE_PACING_MS: u64 = 25;

struct ApiWarmupState {
    cold_connect_ms: u64,
    status_code: Option<u16>,
}

/// Compute robust `(warm_rtt_ms, jitter_ms)` from warmed HTTP/2 RTT samples:
/// - With >= 4 samples, trims the single highest outlier spike before taking the median RTT
///   and symmetric half-range `(max - min) / 2` so one proxy/origin micro-stutter does not
///   inflate `±` jitter, while genuinely unstable lines still report high jitter honestly.
/// - With 2-3 samples, uses median/midpoint and symmetric half-range.
fn compute_robust_latency(raw_samples: &[u64]) -> Option<(u64, u64)> {
    if raw_samples.is_empty() {
        return None;
    }
    let mut sorted = raw_samples.to_vec();
    sorted.sort_unstable();

    match sorted.as_slice() {
        [a] => Some((*a, 0)),
        [a, b] => {
            let mid = (*a + *b) / 2;
            let half_spread = (*b - *a) / 2;
            Some((mid, half_spread))
        }
        [a, b, c] => {
            let half_spread = (*c - *a) / 2;
            Some((*b, half_spread))
        }
        many => {
            // Trim single highest tail spike (1 of N) to suppress isolated proxy/origin stutters
            let trimmed = &many[..many.len() - 1];
            let median = trimmed[trimmed.len() / 2];
            let half_spread = (trimmed[trimmed.len() - 1] - trimmed[0]) / 2;
            Some((median, half_spread))
        }
    }
}

async fn warmup_anthropic_api(client: &Client) -> Option<ApiWarmupState> {
    let t_cold = Instant::now();
    let warm_resp = client.head(API_PROBE_URL).send().await.ok()?;
    let cold_connect_ms = t_cold.elapsed().as_millis().max(1) as u64;
    let status_code = Some(warm_resp.status().as_u16());
    let _ = warm_resp.bytes().await;
    Some(ApiWarmupState {
        cold_connect_ms,
        status_code,
    })
}

async fn sample_anthropic_api_warm_rtt(client: &Client, warm: Option<ApiWarmupState>) -> ApiLatencyMetrics {
    let Some(warm) = warm else {
        return ApiLatencyMetrics {
            warm_rtt_ms: None,
            cold_connect_ms: None,
            jitter_ms: None,
            status_code: None,
        };
    };

    let mut samples: Vec<u64> = Vec::with_capacity(API_WARM_SAMPLES);
    for idx in 0..API_WARM_SAMPLES {
        if idx > 0 {
            tokio::time::sleep(Duration::from_millis(API_SAMPLE_PACING_MS)).await;
        }
        let t = Instant::now();
        if let Ok(r) = client.head(API_PROBE_URL).send().await {
            let _ = r.bytes().await;
            samples.push(t.elapsed().as_millis().max(1) as u64);
        }
    }

    match compute_robust_latency(&samples) {
        Some((warm_rtt_ms, jitter_ms)) => ApiLatencyMetrics {
            warm_rtt_ms: Some(warm_rtt_ms),
            cold_connect_ms: Some(warm.cold_connect_ms),
            jitter_ms: Some(jitter_ms),
            status_code: warm.status_code,
        },
        None => ApiLatencyMetrics {
            warm_rtt_ms: None,
            cold_connect_ms: Some(warm.cold_connect_ms),
            jitter_ms: None,
            status_code: warm.status_code,
        },
    }
}

/// Fast dual-channel gate verification for CLI/Desktop launch (<300ms typical)
pub async fn quick_gate_probe(cfg: &ShieldConfig) -> (ChannelProbe, ChannelProbe, ChannelProbe) {
    let proxy_client = build_proxy_client(cfg, 4);
    let direct_client = build_direct_v4_client(4);

    match (proxy_client, direct_client) {
        (Ok(pc), Ok(dc)) => {
            // Probe claude.ai edge via proxy AND 1.1.1.1 via TUN concurrently!
            // Using claude.ai/cdn-cgi/trace directly verifies BOTH proxy channel AND actual Anthropic edge routing!
            let (claude_edge, tun) = tokio::join!(
                probe_trace_channel(&pc, "https://claude.ai/cdn-cgi/trace", false),
                probe_trace_channel(&dc, "https://1.1.1.1/cdn-cgi/trace", false)
            );
            let proxy = claude_edge.clone();
            (proxy, tun, claude_edge)
        }
        _ => {
            let err = ChannelProbe::unreachable();
            (err.clone(), err.clone(), err)
        }
    }
}

/// Full telemetry network probe for Menu Bar Radar (all channels + calibrated Anthropic API 1-RTT in parallel)
pub async fn full_telemetry_probe(cfg: &ShieldConfig) -> NetworkProbeResult {
    let proxy_client_cf = build_proxy_client(cfg, 5);
    let proxy_client_api = build_proxy_client(cfg, 5);
    let direct_client = build_direct_v4_client(5);

    let err_probe = ChannelProbe::unreachable();

    let (claude_edge, tun, api_latency) = match (proxy_client_cf, proxy_client_api, direct_client) {
        (Ok(pc_cf), Ok(pc_api), Ok(dc)) => {
            // Phase 1: probe CF/TUN channels while concurrently warming the HTTP/2 TLS 1.3 tunnel
            // to api.anthropic.com so cold handshakes overlap without wasting wall-clock time.
            let (claude_edge, tun, api_warm) = tokio::join!(
                probe_trace_channel(&pc_cf, "https://claude.ai/cdn-cgi/trace", true),
                probe_trace_channel(&dc, "https://1.1.1.1/cdn-cgi/trace", true),
                warmup_anthropic_api(&pc_api)
            );
            // Phase 2: sample warmed HTTP/2 API RTT on a quiet proxy tunnel (zero concurrent burst contention).
            let api_latency = sample_anthropic_api_warm_rtt(&pc_api, api_warm).await;
            (claude_edge, tun, api_latency)
        }
        _ => (
            err_probe.clone(),
            err_probe.clone(),
            ApiLatencyMetrics {
                warm_rtt_ms: None,
                cold_connect_ms: None,
                jitter_ms: None,
                status_code: None,
            },
        ),
    };

    NetworkProbeResult {
        proxy: claude_edge.clone(),
        tun,
        claude_edge,
        api_latency,
    }
}

#[cfg(test)]
mod tests {
    use super::{compute_robust_latency, is_valid_ip_str, parse_cf_trace, ChannelProbe};

    #[test]
    fn robust_latency_suppresses_single_outlier_spike() {
        assert_eq!(compute_robust_latency(&[315, 464, 319, 324]), Some((319, 4)));
    }

    #[test]
    fn robust_latency_clean_line_reports_tight_jitter() {
        assert_eq!(compute_robust_latency(&[238, 241, 237, 240]), Some((238, 1)));
    }

    #[test]
    fn robust_latency_preserves_genuinely_unstable_jitter() {
        assert_eq!(compute_robust_latency(&[250, 310, 380, 460]), Some((310, 65)));
        assert_eq!(compute_robust_latency(&[306, 414, 405, 317]), Some((317, 49)));
    }

    #[test]
    fn robust_latency_handles_small_sample_counts() {
        assert_eq!(compute_robust_latency(&[]), None);
        assert_eq!(compute_robust_latency(&[210]), Some((210, 0)));
        assert_eq!(compute_robust_latency(&[200, 240]), Some((220, 20)));
        assert_eq!(compute_robust_latency(&[200, 210, 230]), Some((210, 15)));
    }

    #[test]
    fn parse_cf_trace_extracts_fields_and_validates_ip() {
        let trace = parse_cf_trace("ip=45.77.12.34\ncolo=LAX\nloc=US\ntls=TLSv1.3\nhttp=http/2\nwarp=off\n");
        assert_eq!(trace.ip, "45.77.12.34");
        assert_eq!(trace.colo.as_deref(), Some("LAX"));
        assert_eq!(trace.loc.as_deref(), Some("US"));
        assert_eq!(trace.tls.as_deref(), Some("TLSv1.3"));
        assert_eq!(trace.http.as_deref(), Some("http/2"));
        assert_eq!(trace.warp.as_deref(), Some("off"));
        assert!(is_valid_ip_str(&trace.ip));
        assert!(is_valid_ip_str("2001:db8::1"));
        assert!(!is_valid_ip_str("45.77.12.34/bad"));
        assert!(!is_valid_ip_str("<html>error</html>"));
        assert_eq!(ChannelProbe::unreachable().ip, "无法连通");
    }
}
