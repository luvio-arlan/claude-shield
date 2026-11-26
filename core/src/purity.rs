use crate::config::ShieldConfig;
use crate::probe::{build_direct_v4_client, build_direct_v6_client, build_proxy_client, is_valid_ip_str, probe_trace_channel};
use crate::purity_score::{evaluate_purity_score, is_dns_leaked, is_region_supported, timezones_match, PuritySignals};
use chrono::Local;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub severity: String, // "critical" | "warn" | "good"
    pub title: String,
    pub detail: String,
    pub penalty: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProbeInfo {
    pub ip: Option<String>,
    pub geo: Option<String>,
    pub leaked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurityReport {
    pub checked_at: String,
    pub exit_ip: String,
    pub expected_ip: String,
    pub claude_edge_ip: String,
    pub tun_ip: String,
    pub dual_channel_match: bool,
    pub claude_edge_match: bool,
    pub country_code: String,
    pub country: String,
    pub region: String,
    pub city: String,
    pub isp: String,
    pub asn: String,
    pub ip_type: String,
    pub is_residential: bool,
    pub is_hosting: bool,
    pub is_proxy_or_vpn: bool,
    pub is_tor: bool,
    pub is_broadcast: bool,
    pub region_supported: bool,
    pub ip_timezone: Option<String>,
    pub target_timezone: String,
    pub timezone_aligned: bool,
    pub claude_colo: Option<String>,
    pub claude_tls: Option<String>,
    pub claude_warp: Option<String>,
    pub ippure_fraud_score: Option<u64>,
    pub proxycheck_risk: Option<u64>,
    pub combined_fraud_score: Option<u64>,
    pub dns_proxy: DnsProbeInfo,
    pub dns_tun: DnsProbeInfo,
    pub dns_leak: bool,
    pub ipv6_leak: bool,
    pub ipv6_exposed_ip: Option<String>,
    pub purity_score: u8,
    pub grade: String,   // S, A, B, C, F
    pub verdict: String, // Human-readable Chinese summary
    pub factors: Vec<RiskFactor>,
}

async fn fetch_json(client: &Client, url: &str) -> Option<Value> {
    let mut req = client.get(url);
    if url.contains("ipinfo.io") {
        req = req.header("Referer", "https://ipinfo.io/");
    }
    let resp = req.send().await.ok()?;
    if !resp.status().is_success() {
        return None;
    }
    resp.json::<Value>().await.ok()
}

async fn probe_edns(client: &Client) -> DnsProbeInfo {
    if let Some(v) = fetch_json(client, "http://edns.ip-api.com/json").await {
        let ip = v.pointer("/dns/ip").and_then(|x| x.as_str()).map(String::from);
        let geo = v.pointer("/dns/geo").and_then(|x| x.as_str()).map(String::from);
        let leaked = geo.as_deref().map(is_dns_leaked).unwrap_or(false);
        return DnsProbeInfo { ip, geo, leaked };
    }
    DnsProbeInfo {
        ip: None,
        geo: None,
        leaked: false,
    }
}

async fn probe_ipv6_leak() -> (bool, Option<String>) {
    let client = match build_direct_v6_client(2) {
        Ok(c) => c,
        Err(_) => return (false, None),
    };
    if let Ok(resp) = client.get("https://api6.ipify.org").send().await {
        if resp.status().is_success() {
            if let Ok(text) = resp.text().await {
                let ip = text.trim().to_string();
                if ip.contains(':') && is_valid_ip_str(&ip) {
                    return (true, Some(ip));
                }
            }
        }
    }
    (false, None)
}

/// Multi-source ip.net.coffee/claude-grade IP Purity & Environment Leak Audit
pub async fn run_purity_audit(cfg: &ShieldConfig) -> PurityReport {
    let checked_at = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

    let pc = match build_proxy_client(cfg, 6) {
        Ok(c) => c,
        Err(_) => return fallback_error_report(cfg, checked_at),
    };
    let dc = match build_direct_v4_client(6) {
        Ok(c) => c,
        Err(_) => return fallback_error_report(cfg, checked_at),
    };

    let (claude_trace, tun_trace, ippure_val, dns_proxy, dns_tun, (ipv6_leak, ipv6_exposed_ip)) =
        tokio::join!(
            probe_trace_channel(&pc, "https://claude.ai/cdn-cgi/trace", false),
            probe_trace_channel(&dc, "https://1.1.1.1/cdn-cgi/trace", false),
            fetch_json(&pc, "https://my.ippure.com/v1/info"),
            probe_edns(&pc),
            probe_edns(&dc),
            probe_ipv6_leak()
        );

    let exit_ip = if claude_trace.reachable {
        claude_trace.ip.clone()
    } else if let Some(ip) = ippure_val
        .as_ref()
        .and_then(|v| v.get("ip"))
        .and_then(|x| x.as_str())
        .map(str::trim)
        .filter(|ip| is_valid_ip_str(ip))
    {
        ip.to_string()
    } else {
        "无法连通".to_string()
    };

    if exit_ip == "无法连通" {
        return fallback_error_report(cfg, checked_at);
    }

    let proxycheck_url = format!("https://proxycheck.io/v2/{}?vpn=1&asn=1&risk=1", exit_ip);
    let ipapi_url = format!(
        "http://ip-api.com/json/{}?fields=status,country,countryCode,regionName,city,timezone,isp,org,as,asname,mobile,proxy,hosting,query",
        exit_ip
    );
    let ipinfo_url = format!("https://ipinfo.io/widget/demo/{}", exit_ip);

    let (proxycheck_val, ipapi_val, ipinfo_val) = tokio::join!(
        fetch_json(&pc, &proxycheck_url),
        fetch_json(&pc, &ipapi_url),
        fetch_json(&pc, &ipinfo_url)
    );

    let pc_entry = proxycheck_val.as_ref().and_then(|v| v.get(&exit_ip));
    let info_data = ipinfo_val.as_ref().and_then(|v| v.get("data"));

    let country_code = claude_trace
        .loc
        .clone()
        .or_else(|| ipapi_val.as_ref().and_then(|v| v.get("countryCode")).and_then(|x| x.as_str()).map(String::from))
        .or_else(|| ippure_val.as_ref().and_then(|v| v.get("countryCode")).and_then(|x| x.as_str()).map(String::from))
        .or_else(|| pc_entry.and_then(|v| v.get("isocode")).and_then(|x| x.as_str()).map(String::from))
        .unwrap_or_else(|| "??".to_string())
        .to_uppercase();

    let country = ipapi_val
        .as_ref()
        .and_then(|v| v.get("country"))
        .and_then(|x| x.as_str())
        .or_else(|| ippure_val.as_ref().and_then(|v| v.get("country")).and_then(|x| x.as_str()))
        .or_else(|| pc_entry.and_then(|v| v.get("country")).and_then(|x| x.as_str()))
        .unwrap_or("Unknown")
        .to_string();

    let region = ipapi_val
        .as_ref()
        .and_then(|v| v.get("regionName"))
        .and_then(|x| x.as_str())
        .or_else(|| ippure_val.as_ref().and_then(|v| v.get("region")).and_then(|x| x.as_str()))
        .unwrap_or("")
        .to_string();

    let city = ipapi_val
        .as_ref()
        .and_then(|v| v.get("city"))
        .and_then(|x| x.as_str())
        .or_else(|| ippure_val.as_ref().and_then(|v| v.get("city")).and_then(|x| x.as_str()))
        .or_else(|| info_data.and_then(|v| v.get("city")).and_then(|x| x.as_str()))
        .unwrap_or("Unknown")
        .to_string();

    let isp = ipapi_val
        .as_ref()
        .and_then(|v| v.get("isp"))
        .and_then(|x| x.as_str())
        .or_else(|| ippure_val.as_ref().and_then(|v| v.get("asOrganization")).and_then(|x| x.as_str()))
        .or_else(|| pc_entry.and_then(|v| v.get("provider")).and_then(|x| x.as_str()))
        .unwrap_or("Unknown ISP")
        .to_string();

    let asn = pc_entry
        .and_then(|v| v.get("asn"))
        .and_then(|x| x.as_str())
        .map(String::from)
        .or_else(|| {
            info_data
                .and_then(|v| v.pointer("/asn/asn"))
                .and_then(|x| x.as_str())
                .map(String::from)
        })
        .or_else(|| {
            ippure_val
                .as_ref()
                .and_then(|v| v.get("asn"))
                .and_then(|x| x.as_u64())
                .map(|n| format!("AS{}", n))
        })
        .unwrap_or_else(|| "Unknown".to_string());

    let ip_timezone = ipapi_val
        .as_ref()
        .and_then(|v| v.get("timezone"))
        .and_then(|x| x.as_str())
        .or_else(|| ippure_val.as_ref().and_then(|v| v.get("timezone")).and_then(|x| x.as_str()))
        .or_else(|| pc_entry.and_then(|v| v.get("timezone")).and_then(|x| x.as_str()))
        .or_else(|| info_data.and_then(|v| v.get("timezone")).and_then(|x| x.as_str()))
        .map(String::from);

    let ippure_fraud_score = ippure_val
        .as_ref()
        .and_then(|v| v.get("fraudScore"))
        .and_then(|x| x.as_u64());
    let ippure_res = ippure_val
        .as_ref()
        .and_then(|v| v.get("isResidential"))
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let is_broadcast = ippure_val
        .as_ref()
        .and_then(|v| v.get("isBroadcast"))
        .and_then(|x| x.as_bool())
        .unwrap_or(false);

    let proxycheck_risk = pc_entry.and_then(|v| v.get("risk")).and_then(|x| x.as_u64());
    let pc_proxy = pc_entry
        .and_then(|v| v.get("proxy"))
        .and_then(|x| x.as_str())
        .map(|s| s.eq_ignore_ascii_case("yes"))
        .unwrap_or(false);
    let pc_type = pc_entry
        .and_then(|v| v.get("type"))
        .and_then(|x| x.as_str())
        .unwrap_or("");

    let ipapi_hosting = ipapi_val
        .as_ref()
        .and_then(|v| v.get("hosting"))
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let ipapi_proxy = ipapi_val
        .as_ref()
        .and_then(|v| v.get("proxy"))
        .and_then(|x| x.as_bool())
        .unwrap_or(false);

    let info_asn_type = info_data
        .and_then(|v| v.pointer("/asn/type"))
        .and_then(|x| x.as_str())
        .unwrap_or("");
    let info_vpn = info_data
        .and_then(|v| v.pointer("/privacy/vpn"))
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let info_proxy = info_data
        .and_then(|v| v.pointer("/privacy/proxy"))
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let is_tor = info_data
        .and_then(|v| v.pointer("/privacy/tor"))
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let info_hosting = info_data
        .and_then(|v| v.pointer("/privacy/hosting"))
        .and_then(|x| x.as_bool())
        .unwrap_or(false);

    let is_residential = ippure_res
        || pc_type.eq_ignore_ascii_case("Residential")
        || info_asn_type.eq_ignore_ascii_case("isp");
    let is_proxy_or_vpn = pc_proxy || ipapi_proxy || info_vpn || info_proxy;
    let is_hosting = (ipapi_hosting
        || info_hosting
        || info_asn_type.eq_ignore_ascii_case("hosting")
        || pc_type.eq_ignore_ascii_case("Hosting"))
        && !is_residential;

    let ip_type = if is_tor {
        "Tor 节点".to_string()
    } else if is_proxy_or_vpn {
        "代理 / VPN".to_string()
    } else if ippure_res || pc_type.eq_ignore_ascii_case("Residential") {
        if info_asn_type.eq_ignore_ascii_case("isp") {
            "原生家宽 / ISP".to_string()
        } else {
            "住宅 IP".to_string()
        }
    } else if info_asn_type.eq_ignore_ascii_case("isp") {
        "原生 ISP 专线".to_string()
    } else if is_hosting {
        "数据中心 / 机房".to_string()
    } else if info_asn_type.eq_ignore_ascii_case("business") {
        "商业宽带".to_string()
    } else {
        "普通宽带".to_string()
    };

    let combined_fraud_score = match (ippure_fraud_score, proxycheck_risk) {
        (Some(a), Some(b)) => Some(((a as f64 * 0.6) + (b as f64 * 0.4)).round() as u64),
        (Some(a), None) => Some(a),
        (None, Some(b)) => Some(b),
        (None, None) => None,
    };

    let region_supported = is_region_supported(&country_code);
    let dual_channel_match = tun_trace.reachable
        && tun_trace.ip == exit_ip
        && (!cfg.is_ip_configured() || exit_ip == cfg.expected_ip);
    let claude_edge_match = claude_trace.reachable
        && claude_trace.ip == exit_ip
        && (!cfg.is_ip_configured() || claude_trace.ip == cfg.expected_ip);
    let dns_leak = dns_proxy.leaked || dns_tun.leaked;
    let timezone_aligned = timezones_match(ip_timezone.as_deref(), &cfg.target_tz);

    let signals = PuritySignals {
        exit_ip: &exit_ip,
        expected_ip: &cfg.expected_ip,
        claude_edge_ip: &claude_trace.ip,
        tun_ip: &tun_trace.ip,
        country_code: &country_code,
        country: &country,
        city: &city,
        isp: &isp,
        asn: &asn,
        ip_type: &ip_type,
        is_hosting,
        is_proxy_or_vpn,
        is_tor,
        is_broadcast,
        region_supported,
        dual_channel_match,
        claude_edge_match,
        dns_proxy: &dns_proxy,
        dns_tun: &dns_tun,
        dns_leak,
        ipv6_leak,
        ipv6_exposed_ip: ipv6_exposed_ip.as_deref(),
        ippure_fraud_score,
        proxycheck_risk,
        combined_fraud_score,
        ip_timezone: ip_timezone.as_deref(),
        target_timezone: &cfg.target_tz,
        timezone_aligned,
        claude_warp: claude_trace.warp.as_deref(),
    };
    let (final_score, grade, verdict, factors) = evaluate_purity_score(&signals);

    let report = PurityReport {
        checked_at,
        exit_ip,
        expected_ip: cfg.expected_ip.clone(),
        claude_edge_ip: claude_trace.ip,
        tun_ip: tun_trace.ip,
        dual_channel_match,
        claude_edge_match,
        country_code,
        country,
        region,
        city,
        isp,
        asn,
        ip_type,
        is_residential,
        is_hosting,
        is_proxy_or_vpn,
        is_tor,
        is_broadcast,
        region_supported,
        ip_timezone,
        target_timezone: cfg.target_tz.clone(),
        timezone_aligned,
        claude_colo: claude_trace.colo,
        claude_tls: claude_trace.tls,
        claude_warp: claude_trace.warp,
        ippure_fraud_score,
        proxycheck_risk,
        combined_fraud_score,
        dns_proxy,
        dns_tun,
        dns_leak,
        ipv6_leak,
        ipv6_exposed_ip,
        purity_score: final_score,
        grade,
        verdict,
        factors,
    };

    cfg.write_cache_json("last_purity.json", &report);
    report
}

fn fallback_error_report(cfg: &ShieldConfig, checked_at: String) -> PurityReport {
    PurityReport {
        checked_at,
        exit_ip: "无法连通".to_string(),
        expected_ip: cfg.expected_ip.clone(),
        claude_edge_ip: "无法连通".to_string(),
        tun_ip: "无法连通".to_string(),
        dual_channel_match: false,
        claude_edge_match: false,
        country_code: "??".to_string(),
        country: "Unknown".to_string(),
        region: "".to_string(),
        city: "Unknown".to_string(),
        isp: "无法连接代理".to_string(),
        asn: "-".to_string(),
        ip_type: "离线".to_string(),
        is_residential: false,
        is_hosting: false,
        is_proxy_or_vpn: false,
        is_tor: false,
        is_broadcast: false,
        region_supported: false,
        ip_timezone: None,
        target_timezone: cfg.target_tz.clone(),
        timezone_aligned: false,
        claude_colo: None,
        claude_tls: None,
        claude_warp: None,
        ippure_fraud_score: None,
        proxycheck_risk: None,
        combined_fraud_score: None,
        dns_proxy: DnsProbeInfo { ip: None, geo: None, leaked: false },
        dns_tun: DnsProbeInfo { ip: None, geo: None, leaked: false },
        dns_leak: false,
        ipv6_leak: false,
        ipv6_exposed_ip: None,
        purity_score: 0,
        grade: "F".to_string(),
        verdict: "代理或网络不可达 · 已熔断".to_string(),
        factors: vec![RiskFactor {
            severity: "critical".to_string(),
            title: "无法连通本地代理".to_string(),
            detail: format!("请检查代理服务 127.0.0.1:{} 与 TUN 模式是否运行", cfg.proxy_port),
            penalty: -100,
        }],
    }
}
