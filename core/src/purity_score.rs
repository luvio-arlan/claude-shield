use crate::purity::{DnsProbeInfo, RiskFactor};

pub const BLOCKED_CLAUDE_REGIONS: &[&str] =
    &["CN", "HK", "MO", "RU", "BY", "KP", "IR", "SY", "CU", "VE"];

const LEAKED_DNS_KEYWORDS: &[&str] = &[
    "china",
    "hong kong",
    "macao",
    "macau",
    "chinanet",
    "china telecom",
    "chinatelecom",
    "china unicom",
    "chinaunicom",
    "china mobile",
    "chinamobile",
    "alidns",
    "alibaba",
    "tencent",
    "dnspod",
    "baidu",
    "114dns",
    "cernet",
    "cstnet",
    "cnnic",
    "hkbn",
    "pccw",
    "hkt",
    "ctm",
    "bytedance",
    "huawei cloud",
];

pub(crate) fn is_dns_leaked(geo: &str) -> bool {
    let lower = geo.to_lowercase();
    LEAKED_DNS_KEYWORDS.iter().any(|k| lower.contains(k))
}

pub fn is_region_supported(country_code: &str) -> bool {
    let upper = country_code.trim().to_ascii_uppercase();
    !upper.is_empty() && upper != "??" && !BLOCKED_CLAUDE_REGIONS.contains(&upper.as_str())
}

pub(crate) fn is_dns_verified(dns_proxy: &DnsProbeInfo, dns_tun: &DnsProbeInfo) -> bool {
    dns_proxy.geo.is_some()
        || dns_tun.geo.is_some()
        || dns_proxy.ip.is_some()
        || dns_tun.ip.is_some()
}

pub(crate) fn normalize_timezone(tz: &str) -> &str {
    match tz.trim() {
        "US/Pacific" => "America/Los_Angeles",
        "US/Eastern" => "America/New_York",
        "US/Central" => "America/Chicago",
        "US/Mountain" => "America/Denver",
        "Asia/Calcutta" => "Asia/Kolkata",
        "Asia/Saigon" => "Asia/Ho_Chi_Minh",
        "Asia/Chongqing" | "Asia/Harbin" | "Asia/Urumqi" => "Asia/Shanghai",
        "America/Montreal" => "America/Toronto",
        "Europe/Kiev" => "Europe/Kyiv",
        "Etc/UTC" | "Etc/GMT" => "UTC",
        other => other,
    }
}

pub(crate) fn timezones_match(ip_tz: Option<&str>, target_tz: &str) -> bool {
    ip_tz
        .map(|tz| normalize_timezone(tz) == normalize_timezone(target_tz))
        .unwrap_or(true)
}

pub(crate) struct PuritySignals<'a> {
    pub exit_ip: &'a str,
    pub expected_ip: &'a str,
    pub claude_edge_ip: &'a str,
    pub tun_ip: &'a str,
    pub country_code: &'a str,
    pub country: &'a str,
    pub city: &'a str,
    pub isp: &'a str,
    pub asn: &'a str,
    pub ip_type: &'a str,
    pub is_hosting: bool,
    pub is_proxy_or_vpn: bool,
    pub is_tor: bool,
    pub is_broadcast: bool,
    pub region_supported: bool,
    pub dual_channel_match: bool,
    pub claude_edge_match: bool,
    pub dns_proxy: &'a DnsProbeInfo,
    pub dns_tun: &'a DnsProbeInfo,
    pub dns_leak: bool,
    pub ipv6_leak: bool,
    pub ipv6_exposed_ip: Option<&'a str>,
    pub ippure_fraud_score: Option<u64>,
    pub proxycheck_risk: Option<u64>,
    pub combined_fraud_score: Option<u64>,
    pub ip_timezone: Option<&'a str>,
    pub target_timezone: &'a str,
    pub timezone_aligned: bool,
    pub claude_warp: Option<&'a str>,
}

pub(crate) fn evaluate_purity_score(s: &PuritySignals<'_>) -> (u8, String, String, Vec<RiskFactor>) {
    let mut score: i32 = 100;
    let mut factors: Vec<RiskFactor> = Vec::new();

    if !s.region_supported {
        score -= 60;
        factors.push(RiskFactor {
            severity: "critical".to_string(),
            title: "不支持地区红线".to_string(),
            detail: format!("当前出口地区 {} 位于 Anthropic 封禁区，严禁访问", s.country_code),
            penalty: -60,
        });
    } else {
        factors.push(RiskFactor {
            severity: "good".to_string(),
            title: "Claude 合规地区".to_string(),
            detail: format!("{} · {} ({})", s.country, s.city, s.country_code),
            penalty: 0,
        });
    }

    if !s.dual_channel_match || !s.claude_edge_match {
        score -= 40;
        factors.push(RiskFactor {
            severity: "critical".to_string(),
            title: "双通道 / Claude 边缘 IP 不一致".to_string(),
            detail: format!(
                "Claude 边缘: {} | TUN: {} | 白名单: {}",
                s.claude_edge_ip, s.tun_ip, s.expected_ip
            ),
            penalty: -40,
        });
    } else {
        factors.push(RiskFactor {
            severity: "good".to_string(),
            title: "三点出口 100% 一致".to_string(),
            detail: format!("Proxy = TUN = claude.ai ({})", s.exit_ip),
            penalty: 0,
        });
    }

    let dns_verified = is_dns_verified(s.dns_proxy, s.dns_tun);

    if s.dns_leak {
        score -= 35;
        factors.push(RiskFactor {
            severity: "critical".to_string(),
            title: "检测到 DNS 地区泄露".to_string(),
            detail: format!(
                "Proxy DNS: {} | TUN DNS: {}",
                s.dns_proxy.geo.as_deref().unwrap_or("未知"),
                s.dns_tun.geo.as_deref().unwrap_or("未知")
            ),
            penalty: -35,
        });
    } else if !dns_verified {
        score -= 5;
        factors.push(RiskFactor {
            severity: "warn".to_string(),
            title: "DNS 泄露检测未完成".to_string(),
            detail: "EDNS 探测接口暂不可达，无法确认解析出口，请稍后复测".to_string(),
            penalty: -5,
        });
    } else {
        factors.push(RiskFactor {
            severity: "good".to_string(),
            title: "零 DNS 泄露".to_string(),
            detail: format!(
                "解析出口: {}",
                s.dns_tun
                    .geo
                    .as_deref()
                    .or(s.dns_proxy.geo.as_deref())
                    .or(s.dns_tun.ip.as_deref())
                    .or(s.dns_proxy.ip.as_deref())
                    .unwrap_or("海外加密 DNS")
            ),
            penalty: 0,
        });
    }

    if s.ipv6_leak {
        score -= 25;
        factors.push(RiskFactor {
            severity: "critical".to_string(),
            title: "检测到原生 IPv6 绕过泄露".to_string(),
            detail: format!(
                "直连暴露 IPv6: {}，建议关闭系统或 Clash IPv6",
                s.ipv6_exposed_ip.unwrap_or("unknown")
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

    if s.is_tor {
        score -= 50;
        factors.push(RiskFactor {
            severity: "critical".to_string(),
            title: "Tor 匿名出口".to_string(),
            detail: "Tor 节点将被 Claude 直接拦截或秒封".to_string(),
            penalty: -50,
        });
    } else if s.is_proxy_or_vpn {
        score -= 25;
        factors.push(RiskFactor {
            severity: "warn".to_string(),
            title: "命中公共代理 / VPN 库".to_string(),
            detail: format!("{} ({}) 被风控库标记为代理/VPN", s.asn, s.isp),
            penalty: -25,
        });
    } else if s.is_hosting {
        score -= 20;
        factors.push(RiskFactor {
            severity: "warn".to_string(),
            title: "数据中心 / 机房 IP".to_string(),
            detail: format!("{} ({}) 属于云机房 ASN，建议升级原生 ISP/住宅 IP", s.asn, s.isp),
            penalty: -20,
        });
    } else {
        factors.push(RiskFactor {
            severity: "good".to_string(),
            title: format!("{} · {}", s.ip_type, s.asn),
            detail: format!("运营商: {}（非机房/非公开代理）", s.isp),
            penalty: 0,
        });
    }

    if s.is_broadcast {
        score -= 8;
        factors.push(RiskFactor {
            severity: "warn".to_string(),
            title: "广播 IP 特征".to_string(),
            detail: "IP 属于跨区广播段，纯净度略低于本地原生 IP".to_string(),
            penalty: -8,
        });
    }

    if let Some(fraud) = s.combined_fraud_score {
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
                s.ippure_fraud_score.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
                s.proxycheck_risk.map(|v| v.to_string()).unwrap_or_else(|| "-".into())
            ),
            penalty: -pen,
        });
    }

    if !s.timezone_aligned {
        score -= 10;
        factors.push(RiskFactor {
            severity: "warn".to_string(),
            title: "时区与出口 IP 不一致".to_string(),
            detail: format!(
                "配置时区 {} ≠ 出口 IP 时区 {}",
                s.target_timezone,
                s.ip_timezone.unwrap_or("未知")
            ),
            penalty: -10,
        });
    } else {
        factors.push(RiskFactor {
            severity: "good".to_string(),
            title: "时区严格对齐".to_string(),
            detail: format!("注入时区 {} 与出口 IP 100% 匹配", s.target_timezone),
            penalty: 0,
        });
    }

    if let Some(w) = s.claude_warp {
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

    (final_score, grade.to_string(), verdict.to_string(), factors)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_signals<'a>(dns: &'a DnsProbeInfo) -> PuritySignals<'a> {
        PuritySignals {
            exit_ip: "45.77.12.34",
            expected_ip: "45.77.12.34",
            claude_edge_ip: "45.77.12.34",
            tun_ip: "45.77.12.34",
            country_code: "US",
            country: "United States",
            city: "Los Angeles",
            isp: "AT&T",
            asn: "AS7018",
            ip_type: "原生家宽 / ISP",
            is_hosting: false,
            is_proxy_or_vpn: false,
            is_tor: false,
            is_broadcast: false,
            region_supported: true,
            dual_channel_match: true,
            claude_edge_match: true,
            dns_proxy: dns,
            dns_tun: dns,
            dns_leak: false,
            ipv6_leak: false,
            ipv6_exposed_ip: None,
            ippure_fraud_score: Some(5),
            proxycheck_risk: Some(0),
            combined_fraud_score: Some(3),
            ip_timezone: Some("America/Los_Angeles"),
            target_timezone: "America/Los_Angeles",
            timezone_aligned: true,
            claude_warp: Some("off"),
        }
    }

    #[test]
    fn timezone_aliases_and_dns_keywords_match_accurately() {
        assert!(timezones_match(Some("US/Pacific"), "America/Los_Angeles"));
        assert!(timezones_match(Some("Etc/UTC"), "UTC"));
        assert!(!timezones_match(Some("Asia/Shanghai"), "America/Los_Angeles"));
        assert!(is_dns_leaked("China Telecom Jiangsu"));
        assert!(!is_dns_leaked("Cloudflare, Inc. Los Angeles"));
        assert!(!is_region_supported("CN"));
        assert!(is_region_supported("US"));
    }

    #[test]
    fn purity_scoring_grades_s_a_b_c_f_deterministically() {
        let dns = DnsProbeInfo {
            ip: Some("1.1.1.1".into()),
            geo: Some("Cloudflare".into()),
            leaked: false,
        };
        let clean = base_signals(&dns);
        let (s_score, s_grade, _, _) = evaluate_purity_score(&clean);
        assert_eq!(s_grade, "S");
        assert!(s_score >= 90);

        let mut hosting = base_signals(&dns);
        hosting.is_hosting = true;
        hosting.combined_fraud_score = Some(5);
        let (a_score, a_grade, _, _) = evaluate_purity_score(&hosting);
        assert_eq!(a_grade, "A");
        assert_eq!(a_score, 78);

        let mut medium = base_signals(&dns);
        medium.is_proxy_or_vpn = true;
        medium.timezone_aligned = false;
        let (b_score, b_grade, _, _) = evaluate_purity_score(&medium);
        assert_eq!(b_grade, "B");
        assert!((60..=77).contains(&b_score));

        let mut high = base_signals(&dns);
        high.dns_leak = true;
        high.is_hosting = true;
        let (c_score, c_grade, _, _) = evaluate_purity_score(&high);
        assert_eq!(c_grade, "C");
        assert!((40..=59).contains(&c_score));

        let mut blocked = base_signals(&dns);
        blocked.region_supported = false;
        blocked.dual_channel_match = false;
        let (f_score, f_grade, _, _) = evaluate_purity_score(&blocked);
        assert_eq!(f_grade, "F");
        assert_eq!(f_score, 0);

        let unknown_dns = DnsProbeInfo {
            ip: None,
            geo: None,
            leaked: false,
        };
        let mut unverified = base_signals(&unknown_dns);
        unverified.dns_proxy = &unknown_dns;
        unverified.dns_tun = &unknown_dns;
        let (_, _, _, factors) = evaluate_purity_score(&unverified);
        assert!(factors.iter().any(|f| f.severity == "warn" && f.title.contains("未完成")));
    }
}
