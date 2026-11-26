use crate::config::ShieldConfig;
use serde::Serialize;
use std::fs;
use std::path::Path;
use std::process::Command;

pub const PF_ANCHOR_NAME: &str = "com.local.claude.shield";
pub const PF_ANCHOR_PATH: &str = "/etc/pf.anchors/com.local.claude.shield";
const PF_CONF_PATH: &str = "/etc/pf.conf";
const BEGIN_MARKER: &str = "# BEGIN claude-shield anchor";
const END_MARKER: &str = "# END claude-shield anchor";

#[derive(Debug, Clone, Serialize)]
pub struct PfGuardStatus {
    pub anchor_name: String,
    pub anchor_file_exists: bool,
    pub pf_conf_hooked: bool,
    pub active_rules_count: usize,
    pub active: bool,
    pub note: String,
}

/// Generate a minimal, self-contained macOS `pf` anti-leak anchor:
/// - Always permits loopback (`lo0`) and local proxy traffic (`127.0.0.1:<proxy_port>`)
/// - Permits TUN interfaces (`utun*`) so Clash/Mihomo TUN routing works normally
/// - Drops outbound IPv6 leaks on non-TUN physical interfaces (preventing native IPv6 exposure)
/// - Drops outbound UDP/443 (QUIC/HTTP3) on non-TUN interfaces so Electron/Chromium cannot
///   silently bypass TCP proxy rules over UDP
pub fn generate_anchor_rules(cfg: &ShieldConfig) -> String {
    format!(
        "# Claude Shield Kernel-Level Anti-Leak PF Anchor ({anchor})\n\
         # Managed by `claude-shield-core pf-guard`. Safe to inspect or remove.\n\
         pass quick on lo0 all\n\
         pass out quick inet proto tcp from 127.0.0.1 to 127.0.0.1 port {port}\n\
         pass quick on utun0 all\n\
         pass quick on utun1 all\n\
         pass quick on utun2 all\n\
         pass quick on utun3 all\n\
         pass quick on utun4 all\n\
         pass quick on utun5 all\n\
         pass quick on utun6 all\n\
         pass quick on utun7 all\n\
         pass quick on utun8 all\n\
         pass quick on utun9 all\n\
         # Block native IPv6 egress leaks on physical interfaces (keep link-local fe80::/10)\n\
         block drop out quick inet6 proto {{ tcp, udp }} from any to !fe80::/10\n\
         # Block QUIC (UDP/443) leaks on physical interfaces so traffic stays on TCP/HTTP2 tunnel\n\
         block drop out quick inet proto udp from any to any port 443\n",
        anchor = PF_ANCHOR_NAME,
        port = cfg.proxy_port
    )
}

pub(crate) fn insert_pf_conf_anchor_block(existing: &str) -> String {
    let cleaned = remove_pf_conf_anchor_block(existing);
    let mut out = cleaned.trim_end().to_string();
    if !out.is_empty() {
        out.push_str("\n\n");
    }
    out.push_str(&format!(
        "{begin}\nanchor \"{anchor}\"\nload anchor \"{anchor}\" from \"{path}\"\n{end}\n",
        begin = BEGIN_MARKER,
        anchor = PF_ANCHOR_NAME,
        path = PF_ANCHOR_PATH,
        end = END_MARKER
    ));
    out
}

pub(crate) fn remove_pf_conf_anchor_block(existing: &str) -> String {
    let mut out = Vec::new();
    let mut skipping = false;
    for line in existing.lines() {
        if line.trim() == BEGIN_MARKER {
            skipping = true;
            continue;
        }
        if line.trim() == END_MARKER {
            skipping = false;
            continue;
        }
        if !skipping {
            out.push(line);
        }
    }
    let mut joined = out.join("\n");
    if !joined.is_empty() {
        joined.push('\n');
    }
    joined
}

pub fn pf_guard_status() -> PfGuardStatus {
    let anchor_file_exists = Path::new(PF_ANCHOR_PATH).exists();
    let pf_conf_hooked = fs::read_to_string(PF_CONF_PATH)
        .map(|s| s.contains(PF_ANCHOR_NAME))
        .unwrap_or(false);

    let active_rules_count = Command::new("/sbin/pfctl")
        .args(["-a", PF_ANCHOR_NAME, "-sr"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter(|l| !l.trim().is_empty())
                .count()
        })
        .unwrap_or(0);

    let active = anchor_file_exists && pf_conf_hooked && active_rules_count > 0;
    let note = if active {
        format!("内核 pf 防泄露锚点已激活（{} 条规则生效）", active_rules_count)
    } else if anchor_file_exists {
        "锚点文件已生成，执行 `sudo claude-shield-core pf-guard enable` 加载至内核".to_string()
    } else {
        "未启用内核 pf 锚点（可选增强：执行 `sudo claude-shield-core pf-guard enable` 开启物理级防 IPv6/QUIC 泄露）".to_string()
    };

    PfGuardStatus {
        anchor_name: PF_ANCHOR_NAME.to_string(),
        anchor_file_exists,
        pf_conf_hooked,
        active_rules_count,
        active,
        note,
    }
}

pub fn enable_pf_guard(cfg: &ShieldConfig) -> Result<String, String> {
    let rules = generate_anchor_rules(cfg);
    fs::write(PF_ANCHOR_PATH, &rules)
        .map_err(|e| format!("无法写入 {}（请使用 sudo 运行）: {}", PF_ANCHOR_PATH, e))?;

    let pf_conf = fs::read_to_string(PF_CONF_PATH)
        .map_err(|e| format!("无法读取 {}: {}", PF_CONF_PATH, e))?;
    let updated_conf = insert_pf_conf_anchor_block(&pf_conf);
    fs::write(PF_CONF_PATH, updated_conf)
        .map_err(|e| format!("无法更新 {}: {}", PF_CONF_PATH, e))?;

    let load = Command::new("/sbin/pfctl")
        .args(["-f", PF_CONF_PATH])
        .output()
        .map_err(|e| format!("调用 pfctl 失败: {}", e))?;
    if !load.status.success() {
        return Err(format!(
            "pfctl 加载配置失败: {}",
            String::from_utf8_lossy(&load.stderr).trim()
        ));
    }

    let _ = Command::new("/sbin/pfctl").arg("-e").output();
    Ok(format!("已启用内核级 pf 防泄露锚点 {}", PF_ANCHOR_NAME))
}

pub fn disable_pf_guard() -> Result<String, String> {
    let _ = Command::new("/sbin/pfctl")
        .args(["-a", PF_ANCHOR_NAME, "-F", "all"])
        .output();

    if Path::new(PF_ANCHOR_PATH).exists() {
        fs::remove_file(PF_ANCHOR_PATH)
            .map_err(|e| format!("无法删除 {}（请使用 sudo 运行）: {}", PF_ANCHOR_PATH, e))?;
    }

    if let Ok(pf_conf) = fs::read_to_string(PF_CONF_PATH) {
        if pf_conf.contains(BEGIN_MARKER) {
            let cleaned = remove_pf_conf_anchor_block(&pf_conf);
            fs::write(PF_CONF_PATH, cleaned)
                .map_err(|e| format!("无法还原 {}: {}", PF_CONF_PATH, e))?;
            let _ = Command::new("/sbin/pfctl").args(["-f", PF_CONF_PATH]).output();
        }
    }

    Ok(format!("已卸载并完全还原内核 pf 锚点 {}", PF_ANCHOR_NAME))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn generate_anchor_rules_blocks_ipv6_and_quic_while_allowing_proxy_and_tun() {
        let cfg = ShieldConfig::from_home(PathBuf::from("/tmp/nonexistent-pf-test"));
        let rules = generate_anchor_rules(&cfg);
        assert!(rules.contains("pass quick on lo0 all"));
        assert!(rules.contains("port 7897"));
        assert!(rules.contains("pass quick on utun0 all"));
        assert!(rules.contains("block drop out quick inet6"));
        assert!(rules.contains("port 443"));
    }

    #[test]
    fn pf_conf_anchor_insert_and_remove_are_idempotent() {
        let base = "scrub-anchor \"com.apple/*\"\nnat-anchor \"com.apple/*\"\n";
        let once = insert_pf_conf_anchor_block(base);
        let twice = insert_pf_conf_anchor_block(&once);
        assert_eq!(once, twice);
        assert!(once.contains(PF_ANCHOR_NAME));
        assert!(once.contains(PF_ANCHOR_PATH));

        let restored = remove_pf_conf_anchor_block(&once);
        assert!(!restored.contains(PF_ANCHOR_NAME));
        assert!(restored.contains("scrub-anchor"));
    }
}
