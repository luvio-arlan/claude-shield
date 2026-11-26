use crate::config::ShieldConfig;
use crate::guard::{
    audit_local_defenses, hide_original_claude_app, kill_claude_desktop, kill_pids,
    send_macos_notification, LocalDefenseAudit,
};
use crate::purity::{run_purity_audit, PurityReport};
use chrono::Local;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatrolReport {
    pub timestamp: String,
    pub passed: bool,
    pub purity_score: u8,
    pub grade: String,
    pub alerts: Vec<String>,
    pub auto_healed: Vec<String>,
    pub purity: PurityReport,
    pub defenses: LocalDefenseAudit,
}

/// Daily & On-Demand Deep Security Patrol:
/// - Runs full ip.net.coffee-grade IP purity + DNS/IPv6 leak audit
/// - Auto-hides /Applications/Claude.app if Claude Desktop auto-updater recreated it
/// - Audits Desktop & CLI processes and auto-kills unprotected/drifted sessions if `auto_kill` is true
/// - Persists audit trail to ~/.config/claude-guard/patrol-history.jsonl
/// - Notifies user via macOS Notification Center ONLY when anomalies or auto-heals occur
pub async fn run_daily_patrol(cfg: &ShieldConfig, notify: bool, auto_kill: bool) -> PatrolReport {
    let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let mut alerts: Vec<String> = Vec::new();
    let mut auto_healed: Vec<String> = Vec::new();

    // 1. Check if /Applications/Claude.app reappeared (e.g., after auto-update) and quarantine immediately
    let pre_defenses = audit_local_defenses(cfg);
    if pre_defenses.original_app_exposed {
        let actions = hide_original_claude_app(cfg);
        auto_healed.extend(actions);
    }

    // 2. Run full multi-source IP purity & leak audit
    let purity = run_purity_audit(cfg).await;
    let defenses = audit_local_defenses(cfg);

    // 3. Evaluate anomalies
    if !purity.region_supported {
        alerts.push(format!("出口地区 {} 不受 Claude 支持（封号高危）", purity.country_code));
    }
    if !purity.dual_channel_match || !purity.claude_edge_match {
        alerts.push(format!(
            "出口 IP 漂移或分流不一致（Claude边缘: {} / TUN: {} / 期望: {}）",
            purity.claude_edge_ip, purity.tun_ip, cfg.expected_ip
        ));
    }
    if purity.dns_leak {
        alerts.push("检测到 DNS 泄露至高风险地区运营商".to_string());
    }
    if purity.ipv6_leak {
        alerts.push(format!(
            "检测到原生 IPv6 泄露 ({})",
            purity.ipv6_exposed_ip.as_deref().unwrap_or("unknown")
        ));
    }
    if purity.purity_score < 70 {
        alerts.push(format!(
            "IP 纯净度评分偏低 ({}/100 · {} 级 · {})",
            purity.purity_score, purity.grade, purity.ip_type
        ));
    }
    if !purity.timezone_aligned {
        alerts.push(format!(
            "目标时区 {} 与出口 IP 时区 {} 不一致",
            purity.target_timezone,
            purity.ip_timezone.as_deref().unwrap_or("未知")
        ));
    }
    if !defenses.oauth_locked {
        alerts.push("OAuth 弹窗拦截器未就绪".to_string());
    }
    if !defenses.sandbox_enabled {
        alerts.push("~/.claude/settings.json 的 Seatbelt 沙盒未开启".to_string());
    }
    if defenses.desktop_pid.is_some() && !defenses.desktop_proxy_bound {
        alerts.push("发现未绑定硬代理的 Claude 桌面版进程！".to_string());
        if auto_kill {
            kill_claude_desktop();
            auto_healed.push("已自动急停未受保护的 Claude 桌面版进程".to_string());
        }
    }
    if !defenses.unprotected_cli_pids.is_empty() {
        alerts.push(format!(
            "发现未受代理保护的 Claude Code 终端进程: {:?}",
            defenses.unprotected_cli_pids
        ));
        if auto_kill {
            kill_pids(&defenses.unprotected_cli_pids);
            auto_healed.push("已自动终止未受保护的 Claude Code 进程".to_string());
        }
    }

    // Auto-kill Desktop if IP drifted or unsupported region during patrol
    if auto_kill && defenses.desktop_pid.is_some() && (!purity.dual_channel_match || !purity.region_supported) {
        kill_claude_desktop();
        auto_healed.push("巡检发现 IP 异常，已自动急停 Claude 桌面版防裸连".to_string());
    }

    let passed = alerts.is_empty();

    let report = PatrolReport {
        timestamp,
        passed,
        purity_score: purity.purity_score,
        grade: purity.grade.clone(),
        alerts: alerts.clone(),
        auto_healed: auto_healed.clone(),
        purity,
        defenses,
    };

    cfg.write_cache_json("last_patrol.json", &report);
    cfg.append_jsonl("patrol-history.jsonl", &report);

    if notify && (!alerts.is_empty() || !auto_healed.is_empty()) {
        let summary = if !alerts.is_empty() {
            alerts.join("；")
        } else {
            auto_healed.join("；")
        };
        send_macos_notification(
            if alerts.is_empty() {
                "Claude Shield 自动巡检修复"
            } else {
                "Claude Shield 巡检安全预警"
            },
            &summary,
            if alerts.is_empty() { None } else { Some("Sosumi") },
        );
    }

    report
}
