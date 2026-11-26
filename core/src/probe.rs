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

fn parse_cf_trace(body: &str) -> (String, Option<String>, Option<String>, Option<String>, Option<String>, Option<String>) {
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
    (ip, colo, loc, tls, http, warp)
}

fn is_valid_ip_str(s: &str) -> bool {
    !s.is_empty() && s.len() <= 45 && !s.contains(char::is_whitespace) && s.parse::<IpAddr>().is_ok()
}

/// Probe Cloudflare trace URLs in priority order:
/// req1 fetches IP/metadata & warms HTTP/2 keep-alive;
/// req2-3 (warmed HEAD on same HTTP/2 stream) measure true calibrated 1-RTT wire latency.
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
                    let (ip, colo, loc, tls, http, warp) = parse_cf_trace(&body);
                    if is_valid_ip_str(&ip) {
                        let mut rtt = None;
                        if measure_rtt {
                            let mut samples = Vec::with_capacity(2);
                            for _ in 0..2 {
                                let t0 = Instant::now();
                                if let Ok(r2) = client.head(trace_url).send().await {
                                    let _ = r2.bytes().await;
                                    samples.push(t0.elapsed().as_millis().max(1) as u64);
                                }
                            }
                            rtt = samples.into_iter().min();
                        }
                        return ChannelProbe {
                            ip,
                            latency_ms: rtt,
                            colo,
                            loc,
                            tls,
                            http,
                            warp,
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

    ChannelProbe {
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

/// Measure realistic Anthropic API 1-RTT latency:
/// 1) Warmup request opens HTTP/2 TLS 1.3 tunnel to api.anthropic.com (records cold_connect_ms)
/// 2) Two back-to-back warmed HEAD requests over the live HTTP/2 stream measure true interactive 1-RTT
/// 3) Reports min(r1, r2) to suppress single-packet proxy micro-stutters + computes wire jitter
pub async fn probe_anthropic_api_latency(client: &Client) -> ApiLatencyMetrics {
    let url = "https://api.anthropic.com/";

    let t_cold = Instant::now();
    let warm_resp = match client.head(url).send().await {
        Ok(r) => r,
        Err(_) => {
            return ApiLatencyMetrics {
                warm_rtt_ms: None,
                cold_connect_ms: None,
                jitter_ms: None,
                status_code: None,
            }
        }
    };
    let cold_ms = t_cold.elapsed().as_millis().max(1) as u64;
    let status = Some(warm_resp.status().as_u16());

    let mut samples: Vec<u64> = Vec::with_capacity(2);
    for _ in 0..2 {
        let t = Instant::now();
        if client.head(url).send().await.is_ok() {
            samples.push(t.elapsed().as_millis().max(1) as u64);
        }
    }

    match samples.as_slice() {
        [a, b] => {
            let best = (*a).min(*b);
            let jitter = (*a).abs_diff(*b);
            ApiLatencyMetrics {
                warm_rtt_ms: Some(best),
                cold_connect_ms: Some(cold_ms),
                jitter_ms: Some(jitter),
                status_code: status,
            }
        }
        [a] => ApiLatencyMetrics {
            warm_rtt_ms: Some(*a),
            cold_connect_ms: Some(cold_ms),
            jitter_ms: Some(0),
            status_code: status,
        },
        _ => ApiLatencyMetrics {
            warm_rtt_ms: None,
            cold_connect_ms: Some(cold_ms),
            jitter_ms: None,
            status_code: status,
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
            let err = ChannelProbe {
                ip: "无法连通".to_string(),
                latency_ms: None,
                colo: None,
                loc: None,
                tls: None,
                http: None,
                warp: None,
                reachable: false,
            };
            (err.clone(), err.clone(), err)
        }
    }
}

/// Full telemetry network probe for Menu Bar Radar (all channels + calibrated Anthropic API 1-RTT in parallel)
pub async fn full_telemetry_probe(cfg: &ShieldConfig) -> NetworkProbeResult {
    let proxy_client_cf = build_proxy_client(cfg, 5);
    let proxy_client_api = build_proxy_client(cfg, 5);
    let direct_client = build_direct_v4_client(5);

    let err_probe = ChannelProbe {
        ip: "无法连通".to_string(),
        latency_ms: None,
        colo: None,
        loc: None,
        tls: None,
        http: None,
        warp: None,
        reachable: false,
    };

    let (claude_edge, tun, api_latency) = match (proxy_client_cf, proxy_client_api, direct_client) {
        (Ok(pc_cf), Ok(pc_api), Ok(dc)) => {
            tokio::join!(
                probe_trace_channel(&pc_cf, "https://claude.ai/cdn-cgi/trace", true),
                probe_trace_channel(&dc, "https://1.1.1.1/cdn-cgi/trace", true),
                probe_anthropic_api_latency(&pc_api)
            )
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
