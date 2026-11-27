pub mod config;
pub mod detect;
pub mod ffi;
pub mod guard;
pub mod latency;
pub mod patrol;
pub mod pf_guard;
pub mod probe;
pub mod probe_pool;
pub mod proc_audit;
pub mod purity;
pub mod purity_score;
pub mod setup;
pub mod uninstall;
pub mod worker;

use chrono::Local;
use config::{tz_short_and_full, ShieldConfig};
use guard::LocalDefenseAudit;
use probe::{ApiLatencyMetrics, ChannelProbe, NetworkProbeResult};
use purity_score::is_region_supported;
use serde::Serialize;

#[derive(Serialize)]
pub struct TelemetryJson {
    pub expected_ip: String,
    pub proxy_port: u16,
    pub target_tz: String,
    pub region_short: String,
    pub region_full: String,
    pub proxy: ChannelProbe,
    pub tun: ChannelProbe,
    pub claude_edge: ChannelProbe,
    pub api_latency: ApiLatencyMetrics,
    pub defenses: LocalDefenseAudit,
    pub checked_at: String,
}

#[derive(Serialize)]
pub struct GateJson {
    pub ok: bool,
    pub error: Option<String>,
    pub expected_ip: String,
    pub proxy_ip: String,
    pub tun_ip: String,
    pub claude_edge_ip: String,
    pub claude_loc: Option<String>,
    pub claude_colo: Option<String>,
    pub elapsed_ms: u64,
}

pub fn build_telemetry_payload(
    cfg: &ShieldConfig,
    net: NetworkProbeResult,
    defenses: LocalDefenseAudit,
) -> TelemetryJson {
    let (region_short, region_full) = tz_short_and_full(&cfg.target_tz);
    let checked_at = Local::now().format("%H:%M:%S").to_string();

    TelemetryJson {
        expected_ip: cfg.expected_ip.clone(),
        proxy_port: cfg.proxy_port,
        target_tz: cfg.target_tz.clone(),
        region_short,
        region_full,
        proxy: net.proxy,
        tun: net.tun,
        claude_edge: net.claude_edge,
        api_latency: net.api_latency,
        defenses,
        checked_at,
    }
}

pub fn evaluate_gate_with_probes(
    cfg: &ShieldConfig,
    proxy: ChannelProbe,
    tun: ChannelProbe,
    edge: ChannelProbe,
    elapsed_ms: u64,
) -> GateJson {
    let mut error = None;
    if !cfg.is_ip_configured() {
        error = Some("未配置白名单出口 IP (~/.config/claude-guard/expected_ip)。".to_string());
    } else if !proxy.reachable {
        error = Some(format!("本地代理 127.0.0.1:{} 无法连通 claude.ai。", cfg.proxy_port));
    } else if proxy.ip != cfg.expected_ip {
        error = Some(format!(
            "代理/Claude 边缘出口 IP 异常（当前: {}，期望: {}）。",
            proxy.ip, cfg.expected_ip
        ));
    } else if !tun.reachable {
        error = Some("默认路由（TUN）无法连通外网。".to_string());
    } else if tun.ip != cfg.expected_ip {
        error = Some(format!(
            "默认路由（TUN）出口 IP 异常（当前: {}，期望: {}）。",
            tun.ip, cfg.expected_ip
        ));
    } else if let Some(ref loc) = edge.loc {
        if !is_region_supported(loc) {
            error = Some(format!("Claude Cloudflare 边缘识别到封禁地区 ({})，已强制熔断！", loc));
        }
    }
    if error.is_none() {
        if let Some(ref loc) = tun.loc {
            if !is_region_supported(loc) {
                error = Some(format!("TUN 默认路由识别到封禁地区 ({})，已强制熔断！", loc));
            }
        }
    }

    GateJson {
        ok: error.is_none(),
        error,
        expected_ip: cfg.expected_ip.clone(),
        proxy_ip: proxy.ip,
        tun_ip: tun.ip,
        claude_edge_ip: edge.ip,
        claude_loc: edge.loc,
        claude_colo: edge.colo,
        elapsed_ms,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn make_probe(ip: &str, loc: Option<&str>, reachable: bool) -> ChannelProbe {
        ChannelProbe {
            ip: ip.to_string(),
            latency_ms: Some(120),
            colo: Some("LAX".to_string()),
            loc: loc.map(String::from),
            tls: Some("TLSv1.3".to_string()),
            http: Some("http/2".to_string()),
            warp: Some("off".to_string()),
            reachable,
        }
    }

    #[test]
    fn evaluate_gate_blocks_banned_edge_and_tun_regions() {
        let mut cfg = ShieldConfig::from_home(PathBuf::from("/tmp/nonexistent-gate-test"));
        cfg.expected_ip = "45.77.12.34".to_string();

        let ok = evaluate_gate_with_probes(
            &cfg,
            make_probe("45.77.12.34", Some("US"), true),
            make_probe("45.77.12.34", Some("US"), true),
            make_probe("45.77.12.34", Some("US"), true),
            88,
        );
        assert!(ok.ok);

        let hk_edge = evaluate_gate_with_probes(
            &cfg,
            make_probe("45.77.12.34", Some("HK"), true),
            make_probe("45.77.12.34", Some("US"), true),
            make_probe("45.77.12.34", Some("HK"), true),
            90,
        );
        assert!(!hk_edge.ok);
        assert!(hk_edge.error.as_deref().unwrap_or("").contains("HK"));

        let cn_tun = evaluate_gate_with_probes(
            &cfg,
            make_probe("45.77.12.34", Some("US"), true),
            make_probe("45.77.12.34", Some("CN"), true),
            make_probe("45.77.12.34", Some("US"), true),
            92,
        );
        assert!(!cn_tun.ok);
        assert!(cn_tun.error.as_deref().unwrap_or("").contains("CN"));
    }
}
