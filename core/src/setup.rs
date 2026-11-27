use crate::config::ShieldConfig;
use crate::detect::find_real_claude_cli;
use crate::guard::{current_uid, hide_original_claude_app};
use crate::uninstall::remove_launch_agent;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

#[derive(Debug, Clone)]
pub struct SetupOptions {
    pub expected_ip: String,
    pub proxy_port: u16,
    pub target_tz: String,
    pub hide_original: bool,
    pub enable_autostart: bool,
    pub enable_daily_patrol: bool,
    pub app_bundle_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SetupReport {
    pub ok: bool,
    pub actions: Vec<String>,
    pub warnings: Vec<String>,
    pub expected_ip: String,
    pub proxy_port: u16,
    pub target_tz: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub(crate) struct BackupMeta {
    pub had_settings_file: bool,
    pub had_sandbox_enabled: bool,
    pub had_auto_allow_bash: bool,
}

pub fn validate_ip_input(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    let parsed: IpAddr = trimmed
        .parse()
        .map_err(|_| format!("白名单出口 IP 格式无效: {}", trimmed))?;
    Ok(parsed.to_string())
}

pub fn validate_tz_input(raw: &str) -> Result<String, String> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > 64
        || trimmed.starts_with('/')
        || trimmed.contains("..")
        || !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '/' | '+' | '-' | '.'))
    {
        return Err(format!("目标时区格式无效: {}", trimmed));
    }
    Ok(trimmed.to_string())
}

pub(crate) fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn write_executable(path: &Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("无法创建目录 {}: {}", parent.display(), e))?;
    }
    fs::write(path, content).map_err(|e| format!("无法写入 {}: {}", path.display(), e))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("无法设置权限 {}: {}", path.display(), e))?;
    Ok(())
}

pub(crate) fn ensure_shell_path_block(rc_path: &Path) -> Option<String> {
    const START_MARK: &str = "# >>> Claude Shield >>>";
    const END_MARK: &str = "# <<< Claude Shield <<<";
    let block = format!(
        "{}\nexport PATH=\"$HOME/.local/bin:$PATH\"\n{}",
        START_MARK, END_MARK
    );

    let existing = fs::read_to_string(rc_path).unwrap_or_default();
    if existing.contains(START_MARK) && existing.contains(END_MARK) {
        return None;
    }

    let mut updated = existing;
    if !updated.is_empty() && !updated.ends_with('\n') {
        updated.push('\n');
    }
    updated.push('\n');
    updated.push_str(&block);
    updated.push('\n');

    if fs::write(rc_path, updated).is_ok() {
        Some(format!(
            "已将 ~/.local/bin 注入 {}",
            rc_path.file_name().unwrap_or_default().to_string_lossy()
        ))
    } else {
        None
    }
}

fn install_launch_agent(plist_path: &Path, content: &str) -> bool {
    if let Some(parent) = plist_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if fs::write(plist_path, content).is_err() {
        return false;
    }
    let gui = format!("gui/{}", current_uid());
    let p = plist_path.to_string_lossy().to_string();
    let _ = Command::new("/bin/launchctl")
        .args(["bootout", &gui, &p])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    let _ = Command::new("/bin/launchctl")
        .args(["bootstrap", &gui, &p])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    true
}

pub fn run_setup(cfg: &ShieldConfig, opts: &SetupOptions) -> SetupReport {
    let mut actions = Vec::new();
    let mut warnings = Vec::new();

    let clean_ip = match validate_ip_input(&opts.expected_ip) {
        Ok(ip) => ip,
        Err(err) => {
            warnings.push(err);
            return SetupReport {
                ok: false,
                actions,
                warnings,
                expected_ip: opts.expected_ip.trim().to_string(),
                proxy_port: opts.proxy_port,
                target_tz: opts.target_tz.trim().to_string(),
            };
        }
    };
    let clean_tz = match validate_tz_input(&opts.target_tz) {
        Ok(tz) => tz,
        Err(err) => {
            warnings.push(err);
            return SetupReport {
                ok: false,
                actions,
                warnings,
                expected_ip: clean_ip,
                proxy_port: opts.proxy_port,
                target_tz: opts.target_tz.trim().to_string(),
            };
        }
    };

    let home = &cfg.home_dir;
    let config_dir = &cfg.config_dir;
    let backup_dir = config_dir.join("backup");
    let local_bin = home.join(".local/bin");
    let guard_bin = home.join(".local/lib/claude-guard-bin");
    let vault_dir = home.join(".local/apps");
    let claude_dir = home.join(".claude");
    let agents_dir = home.join("Library/LaunchAgents");

    for d in [config_dir, &backup_dir, &local_bin, &guard_bin, &vault_dir, &claude_dir, &agents_dir] {
        let _ = fs::create_dir_all(d);
    }

    let _ = fs::write(config_dir.join("expected_ip"), format!("{}\n", clean_ip));
    let _ = fs::write(config_dir.join("proxy_port"), format!("{}\n", opts.proxy_port));
    let _ = fs::write(config_dir.join("target_tz"), format!("{}\n", clean_tz));
    let _ = fs::write(
        config_dir.join("hide_original"),
        if opts.hide_original { "1\n" } else { "0\n" },
    );
    let _ = fs::write(config_dir.join("setup_complete"), "1\n");
    actions.push(format!(
        "已锁定白名单出口 IP {} · 代理端口 :{} · 时区 {}",
        clean_ip, opts.proxy_port, clean_tz
    ));

    let core_dst = local_bin.join("claude-shield-core");
    if let Ok(cur_exe) = std::env::current_exe() {
        let same_file = fs::canonicalize(&cur_exe).ok() == fs::canonicalize(&core_dst).ok();
        if !same_file {
            // Atomic temp copy + rename so Apple Silicon arm64 CS_BLOB cache is never invalidated in-place
            let core_tmp = local_bin.join(format!(".claude-shield-core.{}.tmp", std::process::id()));
            let copied = fs::copy(&cur_exe, &core_tmp)
                .and_then(|_| fs::set_permissions(&core_tmp, fs::Permissions::from_mode(0o755)))
                .and_then(|_| fs::rename(&core_tmp, &core_dst));
            if copied.is_ok() {
                actions.push("已同步原生 Rust 核心引擎至 ~/.local/bin/claude-shield-core".to_string());
            } else {
                let _ = fs::remove_file(&core_tmp);
                warnings.push("未能复制核心引擎至 ~/.local/bin/claude-shield-core".to_string());
            }
        }
    }

    let shield_cli = "#!/usr/bin/env bash\n# Claude Shield Managed Wrapper\nset -euo pipefail\nexec \"$HOME/.local/bin/claude-shield-core\" \"$@\"\n";
    if let Err(e) = write_executable(&local_bin.join("claude-shield"), shield_cli) {
        warnings.push(e);
    }

    let oauth_script = r#"#!/usr/bin/env bash
# Claude Shield Managed Wrapper
set -euo pipefail
shopt -s nocasematch
for arg in "$@"; do
  if [[ "${arg}" == *"claude.ai"* || "${arg}" == *"anthropic.com"* || "${arg}" == *"claude.com"* ]]; then
    printf '%s' "${arg}" | /usr/bin/pbcopy 2>/dev/null || true
    printf '\n\033[1;33m🔒 [Claude Shield] 已拦截本机默认浏览器弹窗！\033[0m\n' >&2
    printf '\033[0;36m授权链接已自动复制到剪贴板，请粘贴进 AdsPower 指纹浏览器完成授权：\033[0m\n%s\n\n' "${arg}" >&2
    /usr/bin/osascript -e 'display notification "授权链接已自动复制到剪贴板，请粘贴进 AdsPower 指纹浏览器完成授权。" with title "Claude Shield · OAuth 弹窗已拦截"' >/dev/null 2>&1 || true
    exit 0
  fi
done
exec /usr/bin/open "$@"
"#;
    if write_executable(&guard_bin.join("open"), oauth_script).is_ok() {
        actions.push("已部署 OAuth 系统浏览器弹窗拦截器（强制剪贴板转发）".to_string());
    }

    let guard_sh = format!(
        r#"#!/usr/bin/env bash
# Claude Shield Managed Wrapper
set -euo pipefail
EXPECTED_IP="${{EXPECTED_IP:-$(tr -d '[:space:]' < "$HOME/.config/claude-guard/expected_ip" 2>/dev/null || echo "{ip}")}}"
PROXY_PORT="${{PROXY_PORT:-$(tr -d '[:space:]' < "$HOME/.config/claude-guard/proxy_port" 2>/dev/null || echo "{port}")}}"
TARGET_TZ="${{TARGET_TZ:-$(tr -d '[:space:]' < "$HOME/.config/claude-guard/target_tz" 2>/dev/null || echo "{tz}")}}"
PROXY_HTTP="http://127.0.0.1:${{PROXY_PORT}}"
PROXY_SOCKS="socks5h://127.0.0.1:${{PROXY_PORT}}"
check_claude_guard() {{
  if [[ -x "$HOME/.local/bin/claude-shield-core" ]]; then
    "$HOME/.local/bin/claude-shield-core" gate
    return $?
  fi
  echo "CLAUDE_GUARD_ERR:claude-shield-core not found"
  return 1
}}
export_claude_env() {{
  export TZ="${{TARGET_TZ}}"
  export LANG="en_US.UTF-8"
  export LC_ALL="en_US.UTF-8"
  export HTTP_PROXY="${{PROXY_HTTP}}" HTTPS_PROXY="${{PROXY_HTTP}}" ALL_PROXY="${{PROXY_SOCKS}}"
  export http_proxy="${{PROXY_HTTP}}" https_proxy="${{PROXY_HTTP}}" all_proxy="${{PROXY_SOCKS}}"
  export NO_PROXY="localhost,127.0.0.1,::1" no_proxy="localhost,127.0.0.1,::1"
  export NODE_OPTIONS="${{NODE_OPTIONS:+${{NODE_OPTIONS}} }}--dns-result-order=ipv4first"
  export NODE_USE_ENV_PROXY="1"
  export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1"
  export CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY="1"
  export CLAUDE_CODE_ENABLE_TELEMETRY="0"
  export DISABLE_TELEMETRY="1"
  export DISABLE_ERROR_REPORTING="1"
  export DISABLE_BUG_COMMAND="1"
  export DISABLE_AUTOUPDATER="1"
  export OTEL_SDK_DISABLED="1"
  export DO_NOT_TRACK="1"
}}
"#,
        ip = clean_ip,
        port = opts.proxy_port,
        tz = clean_tz
    );
    let _ = write_executable(&local_bin.join("claude-guard.sh"), &guard_sh);

    let real_claude = find_real_claude_cli(home).unwrap_or_else(|| "/usr/local/bin/claude".to_string());
    let cli_wrapper = format!(
        r#"#!/usr/bin/env bash
# Claude Shield Managed Wrapper
set -euo pipefail
REAL_CLAUDE='{real}'
if [[ ! -x "${{REAL_CLAUDE}}" ]]; then
  REAL_CLAUDE="$(which -a claude 2>/dev/null | grep -v "$HOME/.local/bin/claude" | head -n 1 || true)"
fi
if [[ -z "${{REAL_CLAUDE}}" || ! -x "${{REAL_CLAUDE}}" ]]; then
  printf '\033[1;31m[Claude Shield]\033[0m 未检测到 Claude Code CLI，请先安装 @anthropic-ai/claude-code。\n' >&2
  exit 127
fi
exec "$HOME/.local/bin/claude-shield-core" exec-cli "${{REAL_CLAUDE}}" "$@"
"#,
        real = real_claude.replace('\'', "'\\''")
    );
    if write_executable(&local_bin.join("claude"), &cli_wrapper).is_ok() {
        actions.push("已部署 Claude Code CLI 代理门禁与 IPv4-Only/时区/语言硬绑定".to_string());
    }

    let desktop_safe = "#!/usr/bin/env bash\n# Claude Shield Managed Wrapper\nset -euo pipefail\nexec \"$HOME/.local/bin/claude-shield-core\" launch-desktop \"$@\"\n";
    let _ = write_executable(&local_bin.join("claude-desktop-safe"), desktop_safe);

    if let Some(msg) = ensure_shell_path_block(&home.join(".zshrc")) {
        actions.push(msg);
    }
    let bash_profile = home.join(".bash_profile");
    if bash_profile.exists() {
        if let Some(msg) = ensure_shell_path_block(&bash_profile) {
            actions.push(msg);
        }
    }

    let settings_path = claude_dir.join("settings.json");
    let backup_meta_path = backup_dir.join("meta.json");
    let mut settings_val: serde_json::Value = fs::read_to_string(&settings_path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_else(|| serde_json::json!({}));

    if !backup_meta_path.exists() {
        let meta = BackupMeta {
            had_settings_file: settings_path.exists(),
            had_sandbox_enabled: settings_val.pointer("/sandbox/enabled").is_some(),
            had_auto_allow_bash: settings_val.pointer("/sandbox/autoAllowBashIfSandboxed").is_some(),
        };
        if settings_path.exists() {
            let _ = fs::copy(&settings_path, backup_dir.join("settings.json.orig"));
        }
        if let Ok(meta_json) = serde_json::to_string_pretty(&meta) {
            let _ = fs::write(&backup_meta_path, meta_json);
        }
    }

    if let Some(obj) = settings_val.as_object_mut() {
        let sb = obj
            .entry("sandbox")
            .or_insert_with(|| serde_json::json!({}));
        if let Some(sb_obj) = sb.as_object_mut() {
            sb_obj.insert("enabled".to_string(), serde_json::json!(true));
            sb_obj
                .entry("autoAllowBashIfSandboxed")
                .or_insert_with(|| serde_json::json!(true));
        }

        let env = obj.entry("env").or_insert_with(|| serde_json::json!({}));
        if let Some(env_obj) = env.as_object_mut() {
            env_obj.insert("TZ".to_string(), serde_json::json!(clean_tz));
            env_obj.insert("LANG".to_string(), serde_json::json!("en_US.UTF-8"));
            env_obj.insert("LC_ALL".to_string(), serde_json::json!("en_US.UTF-8"));
            env_obj.insert("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC".to_string(), serde_json::json!("1"));
            env_obj.insert("CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY".to_string(), serde_json::json!("1"));
            env_obj.insert("CLAUDE_CODE_ENABLE_TELEMETRY".to_string(), serde_json::json!("0"));
            env_obj.insert("DISABLE_TELEMETRY".to_string(), serde_json::json!("1"));
            env_obj.insert("DISABLE_ERROR_REPORTING".to_string(), serde_json::json!("1"));
            env_obj.insert("DISABLE_BUG_COMMAND".to_string(), serde_json::json!("1"));
            env_obj.insert("DISABLE_AUTOUPDATER".to_string(), serde_json::json!("1"));
            env_obj.insert("OTEL_SDK_DISABLED".to_string(), serde_json::json!("1"));
            env_obj.insert("DO_NOT_TRACK".to_string(), serde_json::json!("1"));
        }
    }
    if let Ok(pretty) = serde_json::to_string_pretty(&settings_val) {
        if fs::write(&settings_path, format!("{}\n", pretty)).is_ok() {
            actions.push(format!(
                "已加固 ~/.claude/settings.json（Seatbelt 沙盒 + TZ={} + en_US.UTF-8 + 全量去遥测）",
                clean_tz
            ));
        }
    }

    let updated_cfg = ShieldConfig::from_home(cfg.home_dir.clone());
    if opts.hide_original {
        let hide_actions = hide_original_claude_app(&updated_cfg);
        if hide_actions.is_empty() {
            if home.join(".local/apps/Claude.app").exists() {
                actions.push("原版 Claude.app 已处于隐藏隔离仓状态".to_string());
            }
        } else {
            actions.extend(hide_actions);
        }
    }

    let radar_plist = agents_dir.join("com.local.claude.shield.radar.plist");
    if opts.enable_autostart {
        let app_exec = format!(
            "{}/Contents/MacOS/ClaudeShield",
            opts.app_bundle_path.trim_end_matches('/')
        );
        let plist_xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.local.claude.shield.radar</string>
  <key>ProgramArguments</key>
  <array>
    <string>{exec}</string>
    <string>--radar-only</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><false/>
  <key>ProcessType</key><string>Interactive</string>
</dict>
</plist>
"#,
            exec = xml_escape(&app_exec)
        );
        if install_launch_agent(&radar_plist, &plist_xml) {
            actions.push("已开启开机自启状态栏雷达 (LaunchAgent)".to_string());
        }
    } else {
        remove_launch_agent(&radar_plist);
    }

    let patrol_plist = agents_dir.join("com.local.claude.shield.patrol.plist");
    if opts.enable_daily_patrol {
        let log_path = config_dir.join("patrol.log").display().to_string();
        let core_path = core_dst.display().to_string();
        let patrol_xml = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.local.claude.shield.patrol</string>
  <key>ProgramArguments</key>
  <array>
    <string>{core}</string>
    <string>patrol</string>
    <string>--notify</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key><integer>9</integer>
    <key>Minute</key><integer>30</integer>
  </dict>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
</dict>
</plist>
"#,
            core = xml_escape(&core_path),
            log = xml_escape(&log_path)
        );
        if install_launch_agent(&patrol_plist, &patrol_xml) {
            actions.push("已开启每日 09:30 自动 IP 纯净度巡检".to_string());
        }
    } else {
        remove_launch_agent(&patrol_plist);
    }

    SetupReport {
        ok: true,
        actions,
        warnings,
        expected_ip: clean_ip,
        proxy_port: opts.proxy_port,
        target_tz: clean_tz,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::uninstall::{remove_shell_path_block, run_uninstall};
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_home(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let dir = std::env::temp_dir().join(format!(
            "claude-shield-setup-{}-{}-{}",
            tag,
            std::process::id(),
            nanos
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create temp home");
        dir
    }

    #[test]
    fn validates_ip_tz_and_xml_escape() {
        assert_eq!(validate_ip_input(" 45.77.12.34 ").as_deref(), Ok("45.77.12.34"));
        assert!(validate_ip_input("45.77.12.34\"; rm -rf /").is_err());
        assert_eq!(validate_tz_input(" America/Los_Angeles ").as_deref(), Ok("America/Los_Angeles"));
        assert!(validate_tz_input("../etc/passwd").is_err());
        assert!(validate_tz_input("Asia/Shanghai$(id)").is_err());
        assert_eq!(xml_escape("/Applications/A & B's.app"), "/Applications/A &amp; B&apos;s.app");
    }

    #[test]
    fn setup_rejects_invalid_ip_without_touching_disk() {
        let home = temp_home("invalid");
        let cfg = ShieldConfig::from_home(home.clone());
        let opts = SetupOptions {
            expected_ip: "not-an-ip".to_string(),
            proxy_port: 7897,
            target_tz: "America/Los_Angeles".to_string(),
            hide_original: false,
            enable_autostart: false,
            enable_daily_patrol: false,
            app_bundle_path: "/Applications/Claude Shield.app".to_string(),
        };
        let report = run_setup(&cfg, &opts);
        assert!(!report.ok);
        assert!(!cfg.config_dir.join("expected_ip").exists());
        let _ = fs::remove_dir_all(&home);
    }

    #[test]
    fn setup_and_uninstall_roundtrip_preserves_user_settings() {
        let home = temp_home("roundtrip");
        let claude_dir = home.join(".claude");
        fs::create_dir_all(&claude_dir).expect("mkdir .claude");
        fs::write(
            claude_dir.join("settings.json"),
            "{\n  \"theme\": \"dark\",\n  \"env\": { \"CUSTOM_VAR\": \"keep\" }\n}\n",
        )
        .expect("write settings");
        fs::write(home.join(".zshrc"), "export FOO=bar\n").expect("write zshrc");

        let cfg = ShieldConfig::from_home(home.clone());
        let opts = SetupOptions {
            expected_ip: "45.77.12.34".to_string(),
            proxy_port: 7897,
            target_tz: "America/Los_Angeles".to_string(),
            hide_original: false,
            enable_autostart: false,
            enable_daily_patrol: false,
            app_bundle_path: "/Applications/Claude Shield.app".to_string(),
        };
        let report = run_setup(&cfg, &opts);
        assert!(report.ok);
        assert_eq!(
            fs::read_to_string(cfg.config_dir.join("hide_original")).expect("read hide"),
            "0\n"
        );
        assert!(home.join(".local/bin/claude").exists());
        assert!(home.join(".local/lib/claude-guard-bin/open").exists());
        assert!(fs::read_to_string(home.join(".zshrc"))
            .expect("read zshrc")
            .contains("# >>> Claude Shield >>>"));

        let u_report = run_uninstall(&cfg, false);
        assert!(u_report.ok);
        assert!(!cfg.config_dir.exists());
        assert!(!home.join(".local/bin/claude").exists());
        let zshrc = fs::read_to_string(home.join(".zshrc")).expect("read zshrc");
        assert!(!zshrc.contains("Claude Shield"));
        assert!(zshrc.contains("export FOO=bar"));

        let settings: serde_json::Value = serde_json::from_str(
            &fs::read_to_string(claude_dir.join("settings.json")).expect("read settings"),
        )
        .expect("parse settings");
        assert_eq!(settings.get("theme").and_then(|v| v.as_str()), Some("dark"));
        assert_eq!(
            settings.pointer("/env/CUSTOM_VAR").and_then(|v| v.as_str()),
            Some("keep")
        );
        assert!(settings.pointer("/env/TZ").is_none());
        assert!(settings.get("sandbox").is_none());

        assert!(!remove_shell_path_block(&home.join(".zshrc")));
        let _ = fs::remove_dir_all(&home);
    }
}
