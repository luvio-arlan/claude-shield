use crate::config::ShieldConfig;
use crate::latency::{ChannelRttTracker, RECONNECT_SUSPECT_FLOOR_MS};
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
    /// Calibrated real-world 1-RTT HTTP/2 latency (warmed keep-alive median, zero handshake inflation)
    pub warm_rtt_ms: Option<u64>,
    /// Cold TCP + TLS 1.3 + HTTP/2 initial handshake time (for diagnostics)
    pub cold_connect_ms: Option<u64>,
    /// Wire jitter between consecutive warmed HTTP/2 probes
    pub jitter_ms: Option<u64>,
    /// HTTP status observed on api.anthropic.com edge
    pub status_code: Option<u16>,
}

impl ApiLatencyMetrics {
    pub(crate) fn empty() -> Self {
        Self {
            warm_rtt_ms: None,
            cold_connect_ms: None,
            jitter_ms: None,
            status_code: None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkProbeResult {
    pub proxy: ChannelProbe,
    pub tun: ChannelProbe,
    pub claude_edge: ChannelProbe,
    pub api_latency: ApiLatencyMetrics,
}

const UA: &str = "curl/8.7.1";
const API_PROBE_URL: &str = "https://api.anthropic.com/";
const API_FULL_WARM_SAMPLES: usize = 4;
const API_LIVE_BOOTSTRAP_SAMPLES: usize = 2;
const API_SAMPLE_PACING_MS: u64 = 25;
const TRACE_SAMPLE_PACING_MS: u64 = 20;
const HTTP2_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(12);
const HTTP2_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(5);
/// With HTTP/2 PING frames sent every 12s while idle, pooled Cloudflare/Anthropic sockets stay
/// warm across 3-15s ticks; treat connections idle >= 45s (e.g. after sleep) as cold.
const WARM_CONN_TTL: Duration = Duration::from_secs(45);

pub fn build_proxy_client(cfg: &ShieldConfig, timeout_secs: u64) -> Result<Client, reqwest::Error> {
    Client::builder()
        .proxy(Proxy::all(cfg.proxy_http_url())?)
        .local_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        .user_agent(UA)
        .timeout(Duration::from_secs(timeout_secs))
        .connect_timeout(Duration::from_secs(timeout_secs.min(5)))
        .pool_max_idle_per_host(4)
        .pool_idle_timeout(Duration::from_secs(120))
        .tcp_keepalive(Some(Duration::from_secs(20)))
        .http2_keep_alive_interval(Some(HTTP2_KEEPALIVE_INTERVAL))
        .http2_keep_alive_timeout(HTTP2_KEEPALIVE_TIMEOUT)
        .http2_keep_alive_while_idle(true)
        .tcp_nodelay(true)
        .build()
}

pub fn build_direct_v4_client(timeout_secs: u64) -> Result<Client, reqwest::Error> {
    Client::builder()
        .no_proxy()
        .local_address(IpAddr::V4(Ipv4Addr::UNSPECIFIED))
        .user_agent(UA)
        .timeout(Duration::from_secs(timeout_secs))
        .connect_timeout(Duration::from_secs(timeout_secs.min(5)))
        .pool_max_idle_per_host(4)
        .pool_idle_timeout(Duration::from_secs(120))
        .tcp_keepalive(Some(Duration::from_secs(20)))
        .http2_keep_alive_interval(Some(HTTP2_KEEPALIVE_INTERVAL))
        .http2_keep_alive_timeout(HTTP2_KEEPALIVE_TIMEOUT)
        .http2_keep_alive_while_idle(true)
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
    CfTrace {
        ip,
        colo,
        loc,
        tls,
        http,
        warp,
    }
}

pub(crate) fn is_valid_ip_str(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 45
        && !s.contains(char::is_whitespace)
        && s.parse::<IpAddr>().is_ok()
}

fn trace_url_candidates(primary_url: &str) -> [&str; 2] {
    if primary_url.contains("1.1.1.1") {
        [primary_url, "https://www.cloudflare.com/cdn-cgi/trace"]
    } else {
        [primary_url, "https://1.1.1.1/cdn-cgi/trace"]
    }
}

async fn sample_warm_get_ms(client: &Client, url: &str) -> Option<u64> {
    let t0 = Instant::now();
    let resp = client.get(url).send().await.ok()?;
    let _ = resp.bytes().await;
    Some(t0.elapsed().as_millis().max(1) as u64)
}

async fn sample_warm_head_ms(client: &Client, url: &str) -> Option<(u64, u16)> {
    let t0 = Instant::now();
    let resp = client.head(url).send().await.ok()?;
    let status = resp.status().as_u16();
    let _ = resp.bytes().await;
    Some((t0.elapsed().as_millis().max(1) as u64, status))
}

/// Probe Cloudflare trace URLs in priority order (one-shot helper for gate/detect/purity):
/// req1 fetches IP/metadata & warms HTTP/2 keep-alive;
/// req2-3 (warmed GET on same HTTP/2 stream, ~196B payload, zero redirects) measure calibrated 1-RTT.
pub async fn probe_trace_channel(
    client: &Client,
    primary_url: &str,
    measure_rtt: bool,
) -> ChannelProbe {
    for trace_url in trace_url_candidates(primary_url) {
        if let Ok(resp) = client.get(trace_url).send().await {
            if resp.status().is_success() {
                if let Ok(body) = resp.text().await {
                    let trace = parse_cf_trace(&body);
                    if is_valid_ip_str(&trace.ip) {
                        let rtt = if measure_rtt {
                            let mut samples = Vec::with_capacity(2);
                            for idx in 0..2 {
                                if idx > 0 {
                                    tokio::time::sleep(Duration::from_millis(TRACE_SAMPLE_PACING_MS))
                                        .await;
                                }
                                if let Some(ms) = sample_warm_get_ms(client, trace_url).await {
                                    samples.push(ms);
                                }
                            }
                            samples.into_iter().min()
                        } else {
                            None
                        };
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

    // Fallback plain IP providers (always measure a warm follow-up GET when measure_rtt=true)
    for fallback in ["https://api.ipify.org", "https://ifconfig.me/ip"] {
        if let Ok(resp) = client.get(fallback).send().await {
            if resp.status().is_success() {
                if let Ok(text) = resp.text().await {
                    let ip = text.trim().to_string();
                    if is_valid_ip_str(&ip) {
                        let rtt = if measure_rtt {
                            sample_warm_get_ms(client, fallback).await
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

async fn calibrate_live_get_rtt(
    client: &Client,
    url: &str,
    first_ms: u64,
    assume_warm: bool,
    tracker: &mut ChannelRttTracker,
    burst_samples: usize,
    bootstrap_min: usize,
) {
    let now = Instant::now();
    if !assume_warm || tracker.is_empty() {
        let count = burst_samples.max(bootstrap_min);
        let mut warm_samples = Vec::with_capacity(count);
        for idx in 0..count {
            if idx > 0 {
                tokio::time::sleep(Duration::from_millis(TRACE_SAMPLE_PACING_MS)).await;
            }
            if let Some(ms) = sample_warm_get_ms(client, url).await {
                warm_samples.push(ms);
            }
        }
        if !warm_samples.is_empty() {
            tracker.record_bootstrap_samples(Instant::now(), &warm_samples);
        } else if first_ms < RECONNECT_SUSPECT_FLOOR_MS {
            tracker.record_sample(now, first_ms);
        }
    } else if burst_samples > 1 {
        let mut warm_samples = Vec::with_capacity(burst_samples);
        if !tracker.is_suspect_spike(first_ms) {
            warm_samples.push(first_ms);
        }
        while warm_samples.len() < burst_samples {
            tokio::time::sleep(Duration::from_millis(TRACE_SAMPLE_PACING_MS)).await;
            if let Some(ms) = sample_warm_get_ms(client, url).await {
                warm_samples.push(ms);
            } else {
                break;
            }
        }
        if !warm_samples.is_empty() {
            tracker.record_bootstrap_samples(Instant::now(), &warm_samples);
        }
    } else if tracker.needs_confirmation(first_ms) {
        tokio::time::sleep(Duration::from_millis(TRACE_SAMPLE_PACING_MS)).await;
        if let Some(confirm_ms) = sample_warm_get_ms(client, url).await {
            tracker.record_confirmed_pair(Instant::now(), first_ms, confirm_ms);
        }
    } else {
        tracker.record_sample(now, first_ms);
    }
}

/// Real-time spike-proof trace channel probe backed by a rolling `ChannelRttTracker`:
/// - On a warm persistent HTTP/2 stream, a single ~196B trace GET verifies IP/colo AND measures 1-RTT.
/// - On a cold socket (startup/wake/reset/node switch), req1 warms TCP+TLS and is NEVER emitted as RTT;
///   instead 2 quick warm GETs bootstrap the tracker immediately.
/// - On any suspect spike or sudden step drop, fires 1 immediate warm confirmation GET so isolated
///   reconnects / retransmits NEVER spike the UI while genuine route shifts snap instantly.
pub(crate) async fn probe_trace_channel_live(
    client: &Client,
    primary_url: &str,
    assume_warm: bool,
    tracker: &mut ChannelRttTracker,
    channel_tag: &str,
    burst_samples: usize,
) -> ChannelProbe {
    for trace_url in trace_url_candidates(primary_url) {
        let t0 = Instant::now();
        if let Ok(resp) = client.get(trace_url).send().await {
            if resp.status().is_success() {
                if let Ok(body) = resp.text().await {
                    let first_ms = t0.elapsed().as_millis().max(1) as u64;
                    let trace = parse_cf_trace(&body);
                    if is_valid_ip_str(&trace.ip) {
                        let identity = format!(
                            "{}|{}|{}",
                            trace.ip,
                            trace.colo.as_deref().unwrap_or(""),
                            channel_tag
                        );
                        tracker.sync_identity(&identity);
                        calibrate_live_get_rtt(client, trace_url, first_ms, assume_warm, tracker, burst_samples, 2).await;
                        return ChannelProbe {
                            ip: trace.ip,
                            latency_ms: tracker.baseline_rtt(),
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

    // Fallback plain IP providers: still warm-verify so a 2500ms cold handshake never leaks into UI
    for fallback in ["https://api.ipify.org", "https://ifconfig.me/ip"] {
        let t0 = Instant::now();
        if let Ok(resp) = client.get(fallback).send().await {
            if resp.status().is_success() {
                if let Ok(text) = resp.text().await {
                    let ip = text.trim().to_string();
                    if is_valid_ip_str(&ip) {
                        let first_ms = t0.elapsed().as_millis().max(1) as u64;
                        let identity = format!("{}|fallback|{}", ip, channel_tag);
                        tracker.sync_identity(&identity);
                        calibrate_live_get_rtt(client, fallback, first_ms, assume_warm, tracker, 1, 1).await;
                        return ChannelProbe {
                            ip,
                            latency_ms: tracker.baseline_rtt(),
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

pub(crate) struct ApiWarmupState {
    pub(crate) cold_connect_ms: u64,
    pub(crate) status_code: Option<u16>,
}

pub(crate) async fn warmup_anthropic_api(client: &Client) -> Option<ApiWarmupState> {
    let (cold_connect_ms, status) = sample_warm_head_ms(client, API_PROBE_URL).await?;
    Some(ApiWarmupState {
        cold_connect_ms,
        status_code: Some(status),
    })
}

/// Real-time calibrated Anthropic API 1-RTT sampler:
/// - In live mode (`full_burst = false`) on a warm stream: 1 single HEAD (~290ms), plus 1 instant
///   confirmation HEAD only when `needs_confirmation` detects a spike or sharp drop.
/// - On cold start / empty tracker: warms first (never counting cold handshake as RTT) and takes
///   2 warm samples (live) or 4 warm samples (full burst) to populate the rolling window cleanly.
pub(crate) async fn sample_anthropic_api_live(
    client: &Client,
    warm: Option<ApiWarmupState>,
    already_warm: bool,
    full_burst: bool,
    tracker: &mut ChannelRttTracker,
) -> (ApiLatencyMetrics, Option<ApiWarmupState>) {
    let Some(mut warm) = warm else {
        return (ApiLatencyMetrics::empty(), None);
    };

    let target_burst = if full_burst {
        API_FULL_WARM_SAMPLES
    } else {
        API_LIVE_BOOTSTRAP_SAMPLES
    };

    if !already_warm || tracker.is_empty() {
        // Cold socket or empty baseline: collect clean warm samples on the freshly warmed H2 stream
        let mut samples = Vec::with_capacity(target_burst);
        for idx in 0..target_burst {
            if idx > 0 {
                tokio::time::sleep(Duration::from_millis(API_SAMPLE_PACING_MS)).await;
            }
            if let Some((ms, status)) = sample_warm_head_ms(client, API_PROBE_URL).await {
                warm.status_code = Some(status);
                samples.push(ms);
            } else {
                break;
            }
        }
        if !samples.is_empty() {
            tracker.record_bootstrap_samples(Instant::now(), &samples);
        }
    } else if full_burst {
        // Explicit user recalibration on an already-warm stream: collect a fresh 4-sample burst
        let mut samples = Vec::with_capacity(API_FULL_WARM_SAMPLES);
        if let Some((first_ms, status)) = sample_warm_head_ms(client, API_PROBE_URL).await {
            warm.status_code = Some(status);
            if first_ms >= RECONNECT_SUSPECT_FLOOR_MS && tracker.is_suspect_spike(first_ms) {
                // Server had closed idle H2 socket; treat as warmup and re-sample cleanly
                warm.cold_connect_ms = first_ms;
            } else {
                samples.push(first_ms);
            }
        } else {
            return (ApiLatencyMetrics::empty(), None);
        }

        while samples.len() < API_FULL_WARM_SAMPLES {
            if !samples.is_empty() {
                tokio::time::sleep(Duration::from_millis(API_SAMPLE_PACING_MS)).await;
            }
            if let Some((ms, status)) = sample_warm_head_ms(client, API_PROBE_URL).await {
                warm.status_code = Some(status);
                samples.push(ms);
            } else {
                break;
            }
        }
        if !samples.is_empty() {
            tracker.record_bootstrap_samples(Instant::now(), &samples);
        }
    } else {
        // Steady-state real-time live tick: 1 single warm HEAD, instant 1-shot confirm on anomalies
        let Some((first_ms, status)) = sample_warm_head_ms(client, API_PROBE_URL).await else {
            return (ApiLatencyMetrics::empty(), None);
        };
        warm.status_code = Some(status);

        if tracker.needs_confirmation(first_ms) {
            tokio::time::sleep(Duration::from_millis(API_SAMPLE_PACING_MS)).await;
            if let Some((confirm_ms, confirm_status)) =
                sample_warm_head_ms(client, API_PROBE_URL).await
            {
                warm.status_code = Some(confirm_status);
                let discarded_spike =
                    tracker.record_confirmed_pair(Instant::now(), first_ms, confirm_ms);
                if discarded_spike && first_ms >= RECONNECT_SUSPECT_FLOOR_MS {
                    warm.cold_connect_ms = first_ms;
                }
            }
        } else {
            tracker.record_sample(Instant::now(), first_ms);
        }
    }

    let metrics = match tracker.current_metrics() {
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
    };
    (metrics, Some(warm))
}

/// Fast dual-channel gate verification for CLI/Desktop launch (<300ms typical)
pub async fn quick_gate_probe(cfg: &ShieldConfig) -> (ChannelProbe, ChannelProbe, ChannelProbe) {
    let proxy_client = build_proxy_client(cfg, 5);
    let direct_client = build_direct_v4_client(5);

    match (proxy_client, direct_client) {
        (Ok(pc), Ok(dc)) => {
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

pub(crate) fn is_connection_fresh(last_used: Option<Instant>, now: Instant) -> bool {
    last_used
        .map(|ts| now.saturating_duration_since(ts) < WARM_CONN_TTL)
        .unwrap_or(false)
}

pub use crate::probe_pool::ProbePool;

/// Full telemetry network probe for Menu Bar Radar (all channels + calibrated Anthropic API 1-RTT)
pub async fn full_telemetry_probe(cfg: &ShieldConfig) -> NetworkProbeResult {
    let mut pool = ProbePool::new(cfg);
    pool.probe_full(cfg, false).await
}

/// Light one-shot telemetry probe (warmed 3-channel live probe)
pub async fn light_telemetry_probe(cfg: &ShieldConfig) -> NetworkProbeResult {
    let mut pool = ProbePool::new(cfg);
    pool.probe_light(cfg, false).await
}

#[cfg(test)]
mod tests {
    use super::{is_connection_fresh, is_valid_ip_str, parse_cf_trace, ChannelProbe, WARM_CONN_TTL};
    use std::time::{Duration, Instant};

    #[test]
    fn connection_freshness_expires_after_warm_ttl() {
        let t0 = Instant::now();
        assert!(!is_connection_fresh(None, t0));
        assert!(is_connection_fresh(Some(t0), t0 + Duration::from_secs(15)));
        assert!(!is_connection_fresh(Some(t0), t0 + WARM_CONN_TTL));
    }

    #[test]
    fn parse_cf_trace_extracts_fields_and_validates_ip() {
        let trace = parse_cf_trace(
            "ip=45.77.12.34\ncolo=LAX\nloc=US\ntls=TLSv1.3\nhttp=http/2\nwarp=off\n",
        );
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
