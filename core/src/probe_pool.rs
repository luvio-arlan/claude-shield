use crate::config::ShieldConfig;
use crate::latency::ChannelRttTracker;
use crate::probe::{
    build_direct_v4_client, build_proxy_client, is_connection_fresh, probe_trace_channel,
    probe_trace_channel_live, sample_anthropic_api_live, warmup_anthropic_api, ApiLatencyMetrics,
    ApiWarmupState, ChannelProbe, NetworkProbeResult,
};
use crate::purity_score::is_region_supported;
use reqwest::Client;
use std::time::Instant;

/// Returns `true` strictly when proxy + TUN channels have both verified clean against the
/// expected whitelist IP and neither edge reports a banned region.
/// Prevents ever touching `api.anthropic.com` from a drifted, leaking, or banned exit IP.
pub(crate) fn is_safe_to_probe_anthropic_api(
    cfg: &ShieldConfig,
    claude_edge: &ChannelProbe,
    tun: &ChannelProbe,
) -> bool {
    if !claude_edge.reachable || !tun.reachable {
        return false;
    }
    if cfg.is_ip_configured() && (claude_edge.ip != cfg.expected_ip || tun.ip != cfg.expected_ip) {
        return false;
    }
    if let Some(ref loc) = claude_edge.loc {
        if !is_region_supported(loc) {
            return false;
        }
    }
    if let Some(ref loc) = tun.loc {
        if !is_region_supported(loc) {
            return false;
        }
    }
    true
}

/// Persistent HTTP/2 + TLS 1.3 connection pool shared across probes in worker / FFI mode.
/// Keeps all three channels continuously warm via HTTP/2 PING frames and filters single-packet
/// spikes / silent idle reconnects through per-channel rolling `ChannelRttTracker`s.
pub struct ProbePool {
    proxy_port: u16,
    proxy_cf: Option<Client>,
    proxy_api: Option<Client>,
    direct_v4: Option<Client>,
    last_cf_used: Option<Instant>,
    last_tun_used: Option<Instant>,
    last_api_used: Option<Instant>,
    cf_tracker: ChannelRttTracker,
    tun_tracker: ChannelRttTracker,
    api_tracker: ChannelRttTracker,
    last_api_warm: Option<ApiWarmupState>,
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
            cf_tracker: ChannelRttTracker::new(),
            tun_tracker: ChannelRttTracker::new(),
            api_tracker: ChannelRttTracker::new(),
            last_api_warm: None,
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
            self.proxy_cf = build_proxy_client(cfg, 6).ok();
            self.proxy_api = build_proxy_client(cfg, 6).ok();
            self.last_cf_used = None;
            self.last_api_used = None;
            self.last_api_warm = None;
            if force_reset || port_changed {
                self.cf_tracker.clear();
                self.api_tracker.clear();
            }
        }
        if force_reset || self.direct_v4.is_none() {
            self.direct_v4 = build_direct_v4_client(6).ok();
            self.last_tun_used = None;
            if force_reset {
                self.tun_tracker.clear();
            }
        }
    }

    async fn run_telemetry_cycle(
        &mut self,
        cfg: &ShieldConfig,
        reset_pool: bool,
        full_burst: bool,
        skip_api: bool,
    ) -> NetworkProbeResult {
        self.ensure_clients(cfg, reset_pool);
        let now = Instant::now();
        let cf_fresh = is_connection_fresh(self.last_cf_used, now);
        let tun_fresh = is_connection_fresh(self.last_tun_used, now);
        let api_fresh = self.last_api_warm.is_some() && is_connection_fresh(self.last_api_used, now);
        let trace_burst = if full_burst { 2 } else { 1 };
        let cf_tag = format!("proxy:{}", cfg.proxy_port);

        // Phase 1: ONLY verify Proxy/Cloudflare edge + TUN exit IP & region.
        // Never touch api.anthropic.com until Phase 1 confirms a whitelisted, compliant exit IP!
        let (claude_edge, tun) = match (self.proxy_cf.as_ref(), self.direct_v4.as_ref()) {
            (Some(pc_cf), Some(dc)) => {
                let cf_tracker = &mut self.cf_tracker;
                let tun_tracker = &mut self.tun_tracker;

                tokio::join!(
                    probe_trace_channel_live(
                        pc_cf,
                        "https://claude.ai/cdn-cgi/trace",
                        cf_fresh,
                        cf_tracker,
                        &cf_tag,
                        trace_burst,
                    ),
                    probe_trace_channel_live(
                        dc,
                        "https://1.1.1.1/cdn-cgi/trace",
                        tun_fresh,
                        tun_tracker,
                        "tun",
                        trace_burst,
                    )
                )
            }
            _ => (ChannelProbe::unreachable(), ChannelProbe::unreachable()),
        };

        let phase1_done = Instant::now();
        if claude_edge.reachable {
            self.last_cf_used = Some(phase1_done);
        } else {
            self.last_cf_used = None;
            self.cf_tracker.clear();
        }
        if tun.reachable {
            self.last_tun_used = Some(phase1_done);
        } else {
            self.last_tun_used = None;
            self.tun_tracker.clear();
        }

        // Phase 2: strictly post-gate Anthropic API 1-RTT probe.
        // In idle background mode (`skip_api = true`), reuse cached rolling metrics without
        // sending extra requests to api.anthropic.com while still verifying IP/region in Phase 1.
        let api_latency = if is_safe_to_probe_anthropic_api(cfg, &claude_edge, &tun) {
            let api_identity = format!("{}|{}", claude_edge.ip, cfg.proxy_port);
            self.api_tracker.sync_identity(&api_identity);

            if skip_api {
                match self.api_tracker.current_metrics() {
                    Some((warm_rtt_ms, jitter_ms)) => ApiLatencyMetrics {
                        warm_rtt_ms: Some(warm_rtt_ms),
                        cold_connect_ms: self.last_api_warm.as_ref().map(|w| w.cold_connect_ms),
                        jitter_ms: Some(jitter_ms),
                        status_code: self.last_api_warm.as_ref().and_then(|w| w.status_code),
                    },
                    None => ApiLatencyMetrics::empty(),
                }
            } else if let Some(pc_api) = self.proxy_api.as_ref() {
                let api_warm = if api_fresh {
                    self.last_api_warm.as_ref().map(|w| ApiWarmupState {
                        cold_connect_ms: w.cold_connect_ms,
                        status_code: w.status_code,
                    })
                } else {
                    warmup_anthropic_api(pc_api).await
                };

                let (metrics, updated_warm) = sample_anthropic_api_live(
                    pc_api,
                    api_warm,
                    api_fresh,
                    full_burst,
                    &mut self.api_tracker,
                )
                .await;
                if metrics.warm_rtt_ms.is_some() {
                    self.last_api_used = Some(Instant::now());
                    self.last_api_warm = updated_warm;
                } else {
                    self.last_api_used = None;
                    self.last_api_warm = None;
                    self.api_tracker.clear();
                }
                metrics
            } else {
                ApiLatencyMetrics::empty()
            }
        } else {
            self.last_api_used = None;
            self.last_api_warm = None;
            self.api_tracker.clear();
            ApiLatencyMetrics::empty()
        };

        NetworkProbeResult {
            proxy: claude_edge.clone(),
            tun,
            claude_edge,
            api_latency,
        }
    }

    /// Real-time live telemetry tick: 1 warm HTTP/2 RTT per channel with optional `skip_api`
    /// for low-power/idle background ticks.
    pub async fn probe_light_opts(
        &mut self,
        cfg: &ShieldConfig,
        reset_pool: bool,
        skip_api: bool,
    ) -> NetworkProbeResult {
        self.run_telemetry_cycle(cfg, reset_pool, false, skip_api).await
    }

    pub async fn probe_light(&mut self, cfg: &ShieldConfig, reset_pool: bool) -> NetworkProbeResult {
        self.run_telemetry_cycle(cfg, reset_pool, false, false).await
    }

    /// Full multi-sample recalibration burst for manual "重新测速" and CLI one-shot telemetry.
    pub async fn probe_full(&mut self, cfg: &ShieldConfig, reset_pool: bool) -> NetworkProbeResult {
        self.run_telemetry_cycle(cfg, reset_pool, true, false).await
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn sample_channel(ip: &str, loc: Option<&str>, reachable: bool) -> ChannelProbe {
        ChannelProbe {
            ip: ip.to_string(),
            latency_ms: Some(150),
            colo: Some("LAX".to_string()),
            loc: loc.map(String::from),
            tls: Some("TLSv1.3".to_string()),
            http: Some("http/2".to_string()),
            warp: Some("off".to_string()),
            reachable,
        }
    }

    #[test]
    fn api_probe_gate_blocks_drifted_unreachable_or_banned_exits() {
        let mut cfg = ShieldConfig::from_home(PathBuf::from("/tmp/nonexistent-pool-test"));
        cfg.expected_ip = "45.77.12.34".to_string();

        let good = sample_channel("45.77.12.34", Some("US"), true);
        let drifted = sample_channel("1.2.3.4", Some("US"), true);
        let hk = sample_channel("45.77.12.34", Some("HK"), true);
        let down = ChannelProbe::unreachable();

        assert!(is_safe_to_probe_anthropic_api(&cfg, &good, &good));
        assert!(!is_safe_to_probe_anthropic_api(&cfg, &drifted, &good));
        assert!(!is_safe_to_probe_anthropic_api(&cfg, &good, &drifted));
        assert!(!is_safe_to_probe_anthropic_api(&cfg, &hk, &good));
        assert!(!is_safe_to_probe_anthropic_api(&cfg, &good, &hk));
        assert!(!is_safe_to_probe_anthropic_api(&cfg, &good, &down));
    }
}
