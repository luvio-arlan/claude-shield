use crate::config::ShieldConfig;
use crate::probe::{build_direct_v4_client, build_direct_v6_client, build_proxy_client, probe_trace_channel};
use chrono::Local;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;

const BLOCKED_CLAUDE_REGIONS: &[&str] = &["CN", "HK", "MO", "RU", "BY", "KP", "IR", "SY", "CU"];

const LEAKED_DNS_KEYWORDS: &[&str] = &[
    "china",
    "hong kong",
    "macao",
    "macau",
    "chinanet",
    "china telecom",
    "china unicom",
    "china mobile",
    "alidns",
    "alibaba",
    "tencent",
    "dnspod",
    "baidu",
    "114dns",
    "cernet",
    "cstnet",
];

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
    pub ip_type: String, // "Residential" | "ISP" | "Business" | "Hosting" | "VPN/Proxy" | "Unknown"
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
    pub grade: String,        // S, A, B, C, F
    pub verdict: String,      // Human-readable Chinese summary
    pub factors: Vec<RiskFactor>,
}

fn is_dns_leaked(geo: &str) -> bool {
    let lower = geo.to_lowercase();
    LEAKED_DNS_KEYWORDS.iter().any(|k| lower.contains(k))
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
    // edns.ip-api.com/json 302 redirects to a random subdomain that identifies the exact recursive DNS resolver
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
                if ip.contains(':') && ip.len() <= 45 {
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

    // Phase 1: Parallel core exit probes + IPPure + DNS leak (Proxy & TUN) + IPv6 leak
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
    } else if let Some(ip) = ippure_val.as_ref().and_then(|v| v.get("ip")).and_then(|x| x.as_str()) {
        ip.to_string()
    } else {
        "无法连通".to_string()
    };

    if exit_ip == "无法连通" {
        return fallback_error_report(cfg, checked_at);
    }

    // Phase 2: Parallel multi-source IP intelligence enrichment for exact exit IP
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

    // Extract normalized intelligence across all 4 sources
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

    // Risk & Classification signals
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
    let is_hosting = (ipapi_hosting || info_hosting || info_asn_type.eq_ignore_ascii_case("hosting") || pc_type.eq_ignore_ascii_case("Hosting"))
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

    let region_supported = !BLOCKED_CLAUDE_REGIONS.contains(&country_code.as_str()) && country_code != "??";
    let dual_channel_match = tun_trace.reachable
        && tun_trace.ip == exit_ip
        && (!cfg.is_ip_configured() || exit_ip == cfg.expected_ip);
    let claude_edge_match = claude_trace.reachable
        && claude_trace.ip == exit_ip
        && (!cfg.is_ip_configured() || claude_trace.ip == cfg.expected_ip);
    let dns_leak = dns_proxy.leaked || dns_tun.leaked;
    let timezone_aligned = ip_timezone
        .as_deref()
        .map(|tz| tz == cfg.target_tz)
        .unwrap_or(true);

    // Score calculation (transparent itemized risk model)
    let mut score: i32 = 100;
    let mut factors: Vec<RiskFactor> = Vec::new();

    if !region_supported {
        score -= 60;
        factors.push(RiskFactor {
            severity: "critical".to_string(),
            title: "不支持地区红线".to_string(),
            detail: format!("当前出口地区 {} 位于 Anthropic 封禁区，严禁访问", country_code),
            penalty: -60,
        });
    } else {
        factors.push(RiskFactor {
            severity: "good".to_string(),
            title: "Claude 合规地区".to_string(),
            detail: format!("{} · {} ({})", country, city, country_code),
            penalty: 0,
        });
    }

    if !dual_channel_match || !claude_edge_match {
        score -= 40;
        factors.push(RiskFactor {
            severity: "critical".to_string(),
            title: "双通道 / Claude 边缘 IP 不一致".to_string(),
            detail: format!(
                "Claude 边缘: {} | TUN: {} | 白名单: {}",
                claude_trace.ip, tun_trace.ip, cfg.expected_ip
            ),
            penalty: -40,
        });
    } else {
        factors.push(RiskFactor {
            severity: "good".to_string(),
            title: "三点出口 100% 一致".to_string(),
            detail: format!("Proxy = TUN = claude.ai ({})", exit_ip),
            penalty: 0,
        });
    }

    if dns_leak {
        score -= 35;
        factors.push(RiskFactor {
            severity: "critical".to_string(),
            title: "检测到 DNS 地区泄露".to_string(),
            detail: format!(
                "Proxy DNS: {} | TUN DNS: {}",
                dns_proxy.geo.as_deref().unwrap_or("未知"),
                dns_tun.geo.as_deref().unwrap_or("未知")
            ),
            penalty: -35,
        });
    } else {
        factors.push(RiskFactor {
            severity: "good".to_string(),
            title: "零 DNS 泄露".to_string(),
            detail: format!(
                "解析出口: {}",
                dns_tun
                    .geo
                    .as_deref()
                    .or(dns_proxy.geo.as_deref())
                    .unwrap_or("海外加密 DNS")
            ),
            penalty: 0,
        });
    }

    if ipv6_leak {
        score -= 25;
        factors.push(RiskFactor {
            severity: "critical".to_string(),
            title: "检测到原生 IPv6 绕过泄露".to_string(),
            detail: format!(
                "直连暴露 IPv6: {}，建议关闭系统或 Clash IPv6",
                ipv6_exposed_ip.as_deref().unwrap_or("unknown")
            ),
            penalty: -25,
        });
    } else {
        factors.push(RiskFactor {
            severity: "good".to_string(),
            title: "零 IPv6 泄露".to_string(),
            detail: "直连 IPv6 通道已完全封闭".to_string(),
            penalty: 0,
        });
    }

    if is_tor {
        score -= 50;
        factors.push(RiskFactor {
            severity: "critical".to_string(),
            title: "Tor 匿名出口".to_string(),
            detail: "Tor 节点将被 Claude 直接拦截或秒封".to_string(),
            penalty: -50,
        });
    } else if is_proxy_or_vpn {
        score -= 25;
        factors.push(RiskFactor {
            severity: "warn".to_string(),
            title: "命中公共代理 / VPN 库".to_string(),
            detail: format!("{} ({}) 被风控库标记为代理/VPN", asn, isp),
            penalty: -25,
        });
    } else if is_hosting {
        score -= 20;
        factors.push(RiskFactor {
            severity: "warn".to_string(),
            title: "数据中心 / 机房 IP".to_string(),
            detail: format!("{} ({}) 属于云机房 ASN，建议升级原生 ISP/住宅 IP", asn, isp),
            penalty: -20,
        });
    } else {
        factors.push(RiskFactor {
            severity: "good".to_string(),
            title: format!("{} · {}", ip_type, asn),
            detail: format!("运营商: {}（非机房/非公开代理）", isp),
            penalty: 0,
        });
    }

    if is_broadcast {
        score -= 8;
        factors.push(RiskFactor {
            severity: "warn".to_string(),
            title: "广播 IP 特征".to_string(),
            detail: "IP 属于跨区广播段，纯净度略低于本地原生 IP".to_string(),
            penalty: -8,
        });
    }

    if let Some(fraud) = combined_fraud_score {
        let pen = ((fraud as f64) * 0.35).round().min(30.0) as i32;
        if pen > 0 {
            score -= pen;
        }
        let sev = if fraud <= 25 {
            "good"
        } else if fraud <= 55 {
            "warn"
        } else {
            "critical"
        };
        factors.push(RiskFactor {
            severity: sev.to_string(),
            title: format!("多源欺诈风险分: {}/100", fraud),
            detail: format!(
                "IPPure: {} | ProxyCheck: {}",
                ippure_fraud_score.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
                proxycheck_risk.map(|v| v.to_string()).unwrap_or_else(|| "-".into())
            ),
            penalty: -pen,
        });
    }

    if !timezone_aligned {
        score -= 10;
        factors.push(RiskFactor {
            severity: "warn".to_string(),
            title: "时区与出口 IP 不一致".to_string(),
            detail: format!(
                "配置时区 {} ≠ 出口 IP 时区 {}",
                cfg.target_tz,
                ip_timezone.as_deref().unwrap_or("未知")
            ),
            penalty: -10,
        });
    } else {
        factors.push(RiskFactor {
            severity: "good".to_string(),
            title: "时区严格对齐".to_string(),
            detail: format!("注入时区 {} 与出口 IP 100% 匹配", cfg.target_tz),
            penalty: 0,
        });
    }

    if let Some(ref w) = claude_trace.warp {
        if w != "off" && !w.is_empty() {
            score -= 10;
            factors.push(RiskFactor {
                severity: "warn".to_string(),
                title: "Cloudflare WARP 出口".to_string(),
                detail: format!("检测到 warp={}，共享出口易触发人机验证", w),
                penalty: -10,
            });
        }
    }

    let final_score = score.clamp(0, 100) as u8;
    let (grade, verdict) = match final_score {
        90..=100 => ("S", "极净原生 · 99% 安全环境"),
        78..=89 => ("A", "优质合规 · 低风控风险"),
        60..=77 => ("B", "中等风险 · 建议排查告警项"),
        40..=59 => ("C", "高危环境 · 建议立即更换节点"),
        _ => ("F", "封号红线 · 严禁启动 Claude"),
    };

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
        grade: grade.to_string(),
        verdict: verdict.to_string(),
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
