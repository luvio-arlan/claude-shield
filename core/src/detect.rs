use crate::config::ShieldConfig;
use crate::probe::{build_direct_v4_client, build_proxy_client, probe_trace_channel};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectResult {
    pub proxy_port: u16,
    pub proxy_reachable: bool,
    pub exit_ip: String,
    pub tun_ip: String,
    pub tun_matches: bool,
    pub detected_tz: String,
    pub country_code: String,
    pub city: String,
    pub isp: String,
    pub claude_app_installed: bool,
    pub claude_app_hidden: bool,
    pub claude_cli_path: Option<String>,
    pub already_configured: bool,
}

fn is_port_open(port: u16) -> bool {
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    TcpStream::connect_timeout(&addr, Duration::from_millis(160)).is_ok()
}

pub fn find_real_claude_cli(home: &Path) -> Option<String> {
    let self_wrapper = home.join(".local/bin/claude");
    let guard_bin_dir = home.join(".local/lib/claude-guard-bin");

    if let Ok(path_var) = std::env::var("PATH") {
        for dir in path_var.split(':') {
            if dir.is_empty() {
                continue;
            }
            let dir_path = Path::new(dir);
            if dir_path == guard_bin_dir {
                continue;
            }
            let cand = dir_path.join("claude");
            if cand == self_wrapper {
                continue;
            }
            if is_exec_and_not_shield(&cand) {
                return Some(cand.to_string_lossy().to_string());
            }
        }
    }

    let common = [
        "/opt/homebrew/bin/claude".to_string(),
        "/usr/local/bin/claude".to_string(),
        home.join(".npm-global/bin/claude").to_string_lossy().to_string(),
        home.join(".volta/bin/claude").to_string_lossy().to_string(),
        home.join(".bun/bin/claude").to_string_lossy().to_string(),
        home.join(".claude/local/claude").to_string_lossy().to_string(),
    ];
    for c in &common {
        let p = Path::new(c);
        if is_exec_and_not_shield(p) {
            return Some(c.clone());
        }
    }

    None
}

fn is_exec_and_not_shield(path: &Path) -> bool {
    let is_exec = fs::metadata(path)
        .map(|m| m.is_file() && (m.permissions().mode() & 0o111 != 0))
        .unwrap_or(false);
    if !is_exec {
        return false;
    }
    if let Ok(bytes) = fs::read(path) {
        if bytes.len() < 8192 {
            let text = String::from_utf8_lossy(&bytes);
            if text.contains("claude-shield-core") || text.contains("claude-guard.sh") {
                return false;
            }
        }
    }
    true
}

pub async fn detect_environment(cfg: &ShieldConfig, preferred_port: Option<u16>) -> DetectResult {
    let mut candidates: Vec<u16> = Vec::new();
    if let Some(p) = preferred_port {
        candidates.push(p);
    }
    for p in [cfg.proxy_port, 7897, 7890, 7891, 1087, 1080, 6152, 20171] {
        if !candidates.contains(&p) {
            candidates.push(p);
        }
    }

    let chosen_port = candidates
        .iter()
        .copied()
        .find(|&p| is_port_open(p))
        .unwrap_or_else(|| preferred_port.unwrap_or(cfg.proxy_port));

    let mut probe_cfg = cfg.clone();
    probe_cfg.proxy_port = chosen_port;
    let proxy_client = build_proxy_client(&probe_cfg, 5).ok();
    let direct_client = build_direct_v4_client(5).ok();

    let (proxy_probe, tun_probe) = tokio::join!(
        async {
            match proxy_client.as_ref() {
                Some(c) => probe_trace_channel(c, "https://claude.ai/cdn-cgi/trace", false).await,
                None => crate::probe::ChannelProbe::unreachable(),
            }
        },
        async {
            match direct_client.as_ref() {
                Some(c) => probe_trace_channel(c, "https://1.1.1.1/cdn-cgi/trace", false).await,
                None => crate::probe::ChannelProbe::unreachable(),
            }
        }
    );

    let exit_ip = if proxy_probe.reachable {
        proxy_probe.ip.clone()
    } else if tun_probe.reachable {
        tun_probe.ip.clone()
    } else {
        String::new()
    };

    let tun_ip = if tun_probe.reachable {
        tun_probe.ip.clone()
    } else {
        String::new()
    };

    let mut detected_tz = cfg.target_tz.clone();
    let mut country_code = proxy_probe.loc.clone().unwrap_or_default();
    let mut city = String::new();
    let mut isp = String::new();

    if !exit_ip.is_empty() {
        if let Some(client) = proxy_client.as_ref().or(direct_client.as_ref()) {
            let ip_api_url = format!(
                "http://ip-api.com/json/{}?fields=status,countryCode,city,timezone,isp",
                exit_ip
            );
            if let Ok(resp) = client.get(&ip_api_url).send().await {
                if let Ok(val) = resp.json::<serde_json::Value>().await {
                    if val.get("status").and_then(|s| s.as_str()) == Some("success") {
                        if let Some(tz) = val.get("timezone").and_then(|s| s.as_str()).filter(|s| !s.is_empty()) {
                            detected_tz = tz.to_string();
                        }
                        if let Some(cc) = val.get("countryCode").and_then(|s| s.as_str()).filter(|s| !s.is_empty()) {
                            country_code = cc.to_string();
                        }
                        if let Some(c) = val.get("city").and_then(|s| s.as_str()) {
                            city = c.to_string();
                        }
                        if let Some(i) = val.get("isp").and_then(|s| s.as_str()) {
                            isp = i.to_string();
                        }
                    }
                }
            }
            if city.is_empty() {
                let ipinfo_url = format!("https://ipinfo.io/{}/json", exit_ip);
                if let Ok(resp) = client.get(&ipinfo_url).send().await {
                    if let Ok(val) = resp.json::<serde_json::Value>().await {
                        if let Some(tz) = val.get("timezone").and_then(|s| s.as_str()).filter(|s| !s.is_empty()) {
                            detected_tz = tz.to_string();
                        }
                        if let Some(cc) = val.get("country").and_then(|s| s.as_str()).filter(|s| !s.is_empty()) {
                            country_code = cc.to_string();
                        }
                        if let Some(c) = val.get("city").and_then(|s| s.as_str()) {
                            city = c.to_string();
                        }
                        if let Some(org) = val.get("org").and_then(|s| s.as_str()) {
                            isp = org.to_string();
                        }
                    }
                }
            }
        }
    }

    let orig_in_apps = Path::new("/Applications/Claude.app").exists();
    let orig_in_vault = cfg.home_dir.join(".local/apps/Claude.app").exists();
    let claude_app_installed = orig_in_apps || orig_in_vault;
    let claude_app_hidden = !orig_in_apps && orig_in_vault;

    DetectResult {
        proxy_port: chosen_port,
        proxy_reachable: proxy_probe.reachable,
        exit_ip,
        tun_ip: tun_ip.clone(),
        tun_matches: proxy_probe.reachable && tun_probe.reachable && proxy_probe.ip == tun_ip,
        detected_tz,
        country_code,
        city,
        isp,
        claude_app_installed,
        claude_app_hidden,
        claude_cli_path: find_real_claude_cli(&cfg.home_dir),
        already_configured: cfg.is_ip_configured(),
    }
}
