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
        .pool_max_idle_per_host(4)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Some(Duration::from_secs(30)))
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
        .pool_max_idle_per_host(4)
        .pool_idle_timeout(Duration::from_secs(90))
        .tcp_keepalive(Some(Duration::from_secs(30)))
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
/// Cloudflare / Anthropic edges typically close idle HTTP/2 connections after 30–60s.
/// Only treat a pooled connection as already warm if used within this conservative window.
const WARM_CONN_TTL: Duration = Duration::from_secs(20);
/// If a supposedly warm 1-RTT request exceeds this threshold, assume the server closed the
/// idle socket and forced a fresh TCP+TLS handshake, so perform one follow-up warm sample.
const RECONNECT_SUSPECT_MS: u64 = 550;

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

async fn sample_anthropic_api_warm_rtt(
    client: &Client,
    warm: Option<ApiWarmupState>,
    verify_warm_first: bool,
) -> ApiLatencyMetrics {
    let Some(mut warm) = warm else {
        return ApiLatencyMetrics {
            warm_rtt_ms: None,
            cold_connect_ms: None,
            jitter_ms: None,
            status_code: None,
        };
    };

    let mut samples: Vec<u64> = Vec::with_capacity(API_WARM_SAMPLES);
    if verify_warm_first {
        let t0 = Instant::now();
        if let Ok(r) = client.head(API_PROBE_URL).send().await {
            warm.status_code = Some(r.status().as_u16());
            let _ = r.bytes().await;
            let first_ms = t0.elapsed().as_millis().max(1) as u64;
            if first_ms >= RECONNECT_SUSPECT_MS {
                // Server had closed idle H2 socket; treat this request as fresh warmup
                warm.cold_connect_ms = first_ms;
            } else {
                samples.push(first_ms);
            }
        } else {
            return ApiLatencyMetrics {
                warm_rtt_ms: None,
                cold_connect_ms: None,
                jitter_ms: None,
                status_code: None,
            };
        }
    }

    while samples.len() < API_WARM_SAMPLES {
        if !samples.is_empty() {
            tokio::time::sleep(Duration::from_millis(API_SAMPLE_PACING_MS)).await;
        }
        let t = Instant::now();
        if let Ok(r) = client.head(API_PROBE_URL).send().await {
            let _ = r.bytes().await;
            samples.push(t.elapsed().as_millis().max(1) as u64);
        } else {
            break;
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

/// Single-request trace probe for low-power background keep-alive monitoring.
/// When `assume_warm` is false (connection may have gone idle >20s), the request timing can
/// include a cold TCP+TLS handshake, so `latency_ms` is preserved from `fallback_warm_rtt`
/// instead of reporting a misleading cold-connect spike.
pub async fn probe_trace_channel_single(
    client: &Client,
    primary_url: &str,
    assume_warm: bool,
    fallback_warm_rtt: Option<u64>,
) -> ChannelProbe {
    let trace_urls: [&str; 2] = if primary_url.contains("1.1.1.1") {
        [primary_url, "https://www.cloudflare.com/cdn-cgi/trace"]
    } else {
        [primary_url, "https://1.1.1.1/cdn-cgi/trace"]
    };

    for trace_url in trace_urls {
        let t0 = Instant::now();
        if let Ok(resp) = client.get(trace_url).send().await {
            if resp.status().is_success() {
                if let Ok(body) = resp.text().await {
                    let elapsed = t0.elapsed().as_millis().max(1) as u64;
                    let trace = parse_cf_trace(&body);
                    if is_valid_ip_str(&trace.ip) {
                        let calibrated_rtt = if assume_warm && elapsed < RECONNECT_SUSPECT_MS {
                            Some(elapsed)
                        } else if let Some(prev) = fallback_warm_rtt {
                            Some(prev)
                        } else {
                            // First-ever measurement on a cold socket: take 1 warm follow-up GET
                            let t1 = Instant::now();
                            if let Ok(r2) = client.get(trace_url).send().await {
                                let _ = r2.bytes().await;
                                Some(t1.elapsed().as_millis().max(1) as u64)
                            } else {
                                Some(elapsed)
                            }
                        };
                        return ChannelProbe {
                            ip: trace.ip,
                            latency_ms: calibrated_rtt,
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

    for fallback in ["https://api.ipify.org", "https://ifconfig.me/ip"] {
        let t0 = Instant::now();
        if let Ok(resp) = client.get(fallback).send().await {
            if resp.status().is_success() {
                if let Ok(text) = resp.text().await {
                    let ip = text.trim().to_string();
                    if is_valid_ip_str(&ip) {
                        let elapsed = t0.elapsed().as_millis().max(1) as u64;
                        let rtt = if assume_warm && elapsed < RECONNECT_SUSPECT_MS {
                            Some(elapsed)
                        } else {
                            fallback_warm_rtt.or(Some(elapsed))
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

fn is_connection_fresh(last_used: Option<Instant>, now: Instant) -> bool {
    last_used
        .map(|ts| now.saturating_duration_since(ts) < WARM_CONN_TTL)
        .unwrap_or(false)
}

/// Persistent HTTP/2 + TLS 1.3 connection pool shared across probes in worker / FFI mode.
/// Tracks per-channel warm freshness so cold TCP+TLS handshakes after idle timeouts never
/// pollute calibrated 1-RTT latency readings.
pub struct ProbePool {
    proxy_port: u16,
    proxy_cf: Option<Client>,
    proxy_api: Option<Client>,
    direct_v4: Option<Client>,
    last_cf_used: Option<Instant>,
    last_tun_used: Option<Instant>,
    last_api_used: Option<Instant>,
    last_cf_rtt_ms: Option<u64>,
    last_tun_rtt_ms: Option<u64>,
    last_api_warm: Option<ApiWarmupState>,
    last_api_latency: Option<ApiLatencyMetrics>,
}

impl ProbePool {
    pub fn new(cfg: &ShieldConfig) -> Self {
        let mut pool = Self {
            proxy_port: cfg.proxy_port,
            proxy_cf: None,
            proxy_api: None,
            direct_v4: None,
            last_cf_used: None,
            last_tun_used: None,
            last_api_used: None,
            last_cf_rtt_ms: None,
            last_tun_rtt_ms: None,
            last_api_warm: None,
            last_api_latency: None,
        };
        pool.ensure_clients(cfg, true);
        pool
    }

    pub fn reset(&mut self, cfg: &ShieldConfig) {
        self.ensure_clients(cfg, true);
    }

    fn ensure_clients(&mut self, cfg: &ShieldConfig, force_reset: bool) {
        let port_changed = self.proxy_port != cfg.proxy_port;
        if force_reset || port_changed || self.proxy_cf.is_none() || self.proxy_api.is_none() {
            self.proxy_port = cfg.proxy_port;
            self.proxy_cf = build_proxy_client(cfg, 5).ok();
            self.proxy_api = build_proxy_client(cfg, 5).ok();
            self.last_cf_used = None;
            self.last_api_used = None;
            self.last_api_warm = None;
            if force_reset || port_changed {
                self.last_cf_rtt_ms = None;
                self.last_api_latency = None;
            }
        }
        if force_reset || self.direct_v4.is_none() {
            self.direct_v4 = build_direct_v4_client(5).ok();
            self.last_tun_used = None;
            if force_reset {
                self.last_tun_rtt_ms = None;
            }
        }
    }

    /// Background light telemetry: 2 trace GETs in parallel (zero API RTT burst),
    /// preserving calibrated warm 1-RTT instead of reporting idle cold-handshake spikes.
    pub async fn probe_light(&mut self, cfg: &ShieldConfig, reset_pool: bool) -> NetworkProbeResult {
        self.ensure_clients(cfg, reset_pool);
        let now = Instant::now();
        let cf_warm = is_connection_fresh(self.last_cf_used, now);
        let tun_warm = is_connection_fresh(self.last_tun_used, now);
        let prev_cf_rtt = self.last_cf_rtt_ms;
        let prev_tun_rtt = self.last_tun_rtt_ms;

        let (claude_edge, tun) = match (self.proxy_cf.as_ref(), self.direct_v4.as_ref()) {
            (Some(pc), Some(dc)) => tokio::join!(
                probe_trace_channel_single(pc, "https://claude.ai/cdn-cgi/trace", cf_warm, prev_cf_rtt),
                probe_trace_channel_single(dc, "https://1.1.1.1/cdn-cgi/trace", tun_warm, prev_tun_rtt)
            ),
            _ => (ChannelProbe::unreachable(), ChannelProbe::unreachable()),
        };

        let done = Instant::now();
        if claude_edge.reachable {
            self.last_cf_used = Some(done);
            self.last_cf_rtt_ms = claude_edge.latency_ms;
        } else {
            self.last_cf_used = None;
            self.last_cf_rtt_ms = None;
        }
        if tun.reachable {
            self.last_tun_used = Some(done);
            self.last_tun_rtt_ms = tun.latency_ms;
        } else {
            self.last_tun_used = None;
            self.last_tun_rtt_ms = None;
        }

        let api_latency = if claude_edge.reachable && claude_edge.ip == cfg.expected_ip {
            self.last_api_latency.clone().unwrap_or(ApiLatencyMetrics {
                warm_rtt_ms: None,
                cold_connect_ms: None,
                jitter_ms: None,
                status_code: None,
            })
        } else {
            self.last_api_latency = None;
            self.last_api_warm = None;
            self.last_api_used = None;
            ApiLatencyMetrics {
                warm_rtt_ms: None,
                cold_connect_ms: None,
                jitter_ms: None,
                status_code: None,
            }
        };

        NetworkProbeResult {
            proxy: claude_edge.clone(),
            tun,
            claude_edge,
            api_latency,
        }
    }

    /// Foreground full telemetry: strictly calibrated warm 1-RTT for CF, TUN, and Anthropic API.
    /// Any channel idle >= 20s automatically re-warms before measuring so cold TCP+TLS handshakes
    /// never inflate latency or jitter.
    pub async fn probe_full(&mut self, cfg: &ShieldConfig, reset_pool: bool) -> NetworkProbeResult {
        self.ensure_clients(cfg, reset_pool);
        let err_probe = ChannelProbe::unreachable();
        let now = Instant::now();
        let cf_fresh = is_connection_fresh(self.last_cf_used, now);
        let tun_fresh = is_connection_fresh(self.last_tun_used, now);
        let api_fresh = self.last_api_warm.is_some() && is_connection_fresh(self.last_api_used, now);

        let (claude_edge, tun, api_latency) = match (
            self.proxy_cf.as_ref(),
            self.proxy_api.as_ref(),
            self.direct_v4.as_ref(),
        ) {
            (Some(pc_cf), Some(pc_api), Some(dc)) => {
                let (claude_edge, tun, api_warm) = tokio::join!(
                    async {
                        if cf_fresh {
                            let p = probe_trace_channel_single(pc_cf, "https://claude.ai/cdn-cgi/trace", true, None).await;
                            if p.reachable && p.latency_ms.map(|ms| ms < RECONNECT_SUSPECT_MS).unwrap_or(false) {
                                return p;
                            }
                        }
                        probe_trace_channel(pc_cf, "https://claude.ai/cdn-cgi/trace", true).await
                    },
                    async {
                        if tun_fresh {
                            let p = probe_trace_channel_single(dc, "https://1.1.1.1/cdn-cgi/trace", true, None).await;
                            if p.reachable && p.latency_ms.map(|ms| ms < RECONNECT_SUSPECT_MS).unwrap_or(false) {
                                return p;
                            }
                        }
                        probe_trace_channel(dc, "https://1.1.1.1/cdn-cgi/trace", true).await
                    },
                    async {
                        if api_fresh {
                            self.last_api_warm.as_ref().map(|w| ApiWarmupState {
                                cold_connect_ms: w.cold_connect_ms,
                                status_code: w.status_code,
                            })
                        } else {
                            warmup_anthropic_api(pc_api).await
                        }
                    }
                );

                // Phase 2: sample warmed HTTP/2 API RTT on a quiet proxy tunnel
                let api_latency = sample_anthropic_api_warm_rtt(pc_api, api_warm, api_fresh).await;
                let done = Instant::now();
                if claude_edge.reachable {
                    self.last_cf_used = Some(done);
                    self.last_cf_rtt_ms = claude_edge.latency_ms;
                } else {
                    self.last_cf_used = None;
                    self.last_cf_rtt_ms = None;
                }
                if tun.reachable {
                    self.last_tun_used = Some(done);
                    self.last_tun_rtt_ms = tun.latency_ms;
                } else {
                    self.last_tun_used = None;
                    self.last_tun_rtt_ms = None;
                }
                if api_latency.warm_rtt_ms.is_some() {
                    self.last_api_used = Some(done);
                    self.last_api_warm = Some(ApiWarmupState {
                        cold_connect_ms: api_latency.cold_connect_ms.unwrap_or(0),
                        status_code: api_latency.status_code,
                    });
                    self.last_api_latency = Some(api_latency.clone());
                } else {
                    self.last_api_used = None;
                    self.last_api_warm = None;
                    self.last_api_latency = None;
                }
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

    pub async fn probe_gate(
        &mut self,
        cfg: &ShieldConfig,
        reset_pool: bool,
    ) -> (ChannelProbe, ChannelProbe, ChannelProbe) {
        self.ensure_clients(cfg, reset_pool);
        match (self.proxy_cf.as_ref(), self.direct_v4.as_ref()) {
            (Some(pc), Some(dc)) => {
                let (claude_edge, tun) = tokio::join!(
                    probe_trace_channel(pc, "https://claude.ai/cdn-cgi/trace", false),
                    probe_trace_channel(dc, "https://1.1.1.1/cdn-cgi/trace", false)
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
}

/// Full telemetry network probe for Menu Bar Radar (all channels + calibrated Anthropic API 1-RTT in parallel)
pub async fn full_telemetry_probe(cfg: &ShieldConfig) -> NetworkProbeResult {
    let mut pool = ProbePool::new(cfg);
    pool.probe_full(cfg, false).await
}

/// Light one-shot telemetry probe (2 parallel trace GETs, zero API RTT burst)
pub async fn light_telemetry_probe(cfg: &ShieldConfig) -> NetworkProbeResult {
    let mut pool = ProbePool::new(cfg);
    pool.probe_light(cfg, false).await
}

#[cfg(test)]
mod tests {
    use super::{
        compute_robust_latency, is_connection_fresh, is_valid_ip_str, parse_cf_trace, ChannelProbe,
        WARM_CONN_TTL,
    };
    use std::time::{Duration, Instant};

    #[test]
    fn connection_freshness_expires_after_warm_ttl() {
        let t0 = Instant::now();
        assert!(!is_connection_fresh(None, t0));
        assert!(is_connection_fresh(Some(t0), t0 + Duration::from_secs(5)));
        assert!(!is_connection_fresh(Some(t0), t0 + WARM_CONN_TTL));
    }

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
