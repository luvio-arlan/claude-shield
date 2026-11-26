use crate::config::ShieldConfig;
use crate::guard::hide_original_claude_app;
use crate::probe::{build_direct_v4_client, build_proxy_client, probe_trace_channel};
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::{SocketAddr, TcpStream};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UninstallReport {
    pub ok: bool,
    pub restored: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct BackupMeta {
    had_settings_file: bool,
    had_sandbox_enabled: bool,
    had_auto_allow_bash: bool,
}

fn is_port_open(port: u16) -> bool {
    let addr: SocketAddr = ([127, 0, 0, 1], port).into();
    TcpStream::connect_timeout(&addr, Duration::from_millis(160)).is_ok()
}

pub fn find_real_claude_cli(home: &Path) -> Option<String> {
    let self_wrapper = home.join(".local/bin/claude");
    let guard_bin_dir = home.join(".local/lib/claude-guard-bin");

    // 1. Scan PATH entries first
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

    // 2. Common macOS locations (GUI apps often have minimal PATH)
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
            // Fallback to ipinfo.io if timezone still not enriched
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

fn write_executable(path: &Path, content: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("无法创建目录 {}: {}", parent.display(), e))?;
    }
    fs::write(path, content).map_err(|e| format!("无法写入 {}: {}", path.display(), e))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .map_err(|e| format!("无法设置权限 {}: {}", path.display(), e))?;
    Ok(())
}

fn ensure_shell_path_block(rc_path: &Path) -> Option<String> {
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
        Some(format!("已将 ~/.local/bin 注入 {}", rc_path.file_name().unwrap_or_default().to_string_lossy()))
    } else {
        None
    }
}

fn remove_shell_path_block(rc_path: &Path) -> bool {
    const START_MARK: &str = "# >>> Claude Shield >>>";
    const END_MARK: &str = "# <<< Claude Shield <<<";
    let Ok(content) = fs::read_to_string(rc_path) else {
        return false;
    };
    if !content.contains(START_MARK) {
        return false;
    }

    let mut out = Vec::new();
    let mut skipping = false;
    for line in content.lines() {
        if line.trim() == START_MARK {
            skipping = true;
            continue;
        }
        if skipping {
            if line.trim() == END_MARK {
                skipping = false;
            }
            continue;
        }
        out.push(line);
    }

    // Trim extra trailing blank lines left behind
    while out.last().map(|l| l.is_empty()).unwrap_or(false) {
        out.pop();
    }
    let mut final_text = out.join("\n");
    if !final_text.is_empty() {
        final_text.push('\n');
    }
    fs::write(rc_path, final_text).is_ok()
}

fn get_uid() -> String {
    Command::new("/usr/bin/id")
        .arg("-u")
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "501".to_string())
}

fn install_launch_agent(plist_path: &Path, content: &str) -> bool {
    if let Some(parent) = plist_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if fs::write(plist_path, content).is_err() {
        return false;
    }
    let uid = get_uid();
    let gui = format!("gui/{}", uid);
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

fn remove_launch_agent(plist_path: &Path) -> bool {
    if !plist_path.exists() {
        return false;
    }
    let uid = get_uid();
    let gui = format!("gui/{}", uid);
    let p = plist_path.to_string_lossy().to_string();
    let _ = Command::new("/bin/launchctl")
        .args(["bootout", &gui, &p])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
    fs::remove_file(plist_path).is_ok()
}

pub fn run_setup(cfg: &ShieldConfig, opts: &SetupOptions) -> SetupReport {
    let mut actions = Vec::new();
    let mut warnings = Vec::new();

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

    // 1. Write IP / Port / TZ config
    let _ = fs::write(config_dir.join("expected_ip"), format!("{}\n", opts.expected_ip.trim()));
    let _ = fs::write(config_dir.join("proxy_port"), format!("{}\n", opts.proxy_port));
    let _ = fs::write(config_dir.join("target_tz"), format!("{}\n", opts.target_tz.trim()));
    let _ = fs::write(config_dir.join("setup_complete"), "1\n");
    actions.push(format!(
        "已锁定白名单出口 IP {} · 代理端口 :{} · 时区 {}",
        opts.expected_ip.trim(),
        opts.proxy_port,
        opts.target_tz.trim()
    ));

    // 2. Sync Rust core binary to ~/.local/bin/claude-shield-core
    let core_dst = local_bin.join("claude-shield-core");
    if let Ok(cur_exe) = std::env::current_exe() {
        let same_file = fs::canonicalize(&cur_exe).ok() == fs::canonicalize(&core_dst).ok();
        if !same_file {
            if fs::copy(&cur_exe, &core_dst).is_ok() {
                let _ = fs::set_permissions(&core_dst, fs::Permissions::from_mode(0o755));
                actions.push("已同步原生 Rust 核心引擎至 ~/.local/bin/claude-shield-core".to_string());
            } else {
                warnings.push("未能复制核心引擎至 ~/.local/bin/claude-shield-core".to_string());
            }
        }
    }

    // 3. Install claude-shield CLI shortcut
    let shield_cli = "#!/usr/bin/env bash\n# Claude Shield Managed Wrapper\nset -euo pipefail\nexec \"$HOME/.local/bin/claude-shield-core\" \"$@\"\n";
    if let Err(e) = write_executable(&local_bin.join("claude-shield"), shield_cli) {
        warnings.push(e);
    }

    // 4. Install OAuth AdsPower-Only Interceptor
    let oauth_script = r#"#!/usr/bin/env bash
# Claude Shield Managed Wrapper
set -euo pipefail
for arg in "$@"; do
  if [[ "${arg}" == *"claude.ai"* || "${arg}" == *"anthropic.com"* || "${arg}" == *"claude.com"* ]]; then
    printf '%s' "${arg}" | /usr/bin/pbcopy 2>/dev/null || true
    printf '\n\033[1;33m🔒 [Claude Shield] 已拦截本机默认浏览器弹窗！\033[0m\n' >&2
    printf '\033[0;36m授权链接已自动复制到剪贴板，请粘贴进 AdsPower 指纹浏览器完成授权：\033[0m\n%s\n\n' "${arg}" >&2
    exit 0
  fi
done
exec /usr/bin/open "$@"
"#;
    if write_executable(&guard_bin.join("open"), oauth_script).is_ok() {
        actions.push("已部署 OAuth 系统浏览器弹窗拦截器（强制剪贴板转发）".to_string());
    }

    // 5. Install claude-guard.sh (compatibility helper)
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
  export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1"
  export CLAUDE_CODE_ENABLE_TELEMETRY="0"
  export DISABLE_TELEMETRY="1"
  export DISABLE_ERROR_REPORTING="1"
  export DISABLE_BUG_COMMAND="1"
  export DISABLE_AUTOUPDATER="1"
  export OTEL_SDK_DISABLED="1"
  export DO_NOT_TRACK="1"
}}
"#,
        ip = opts.expected_ip.trim(),
        port = opts.proxy_port,
        tz = opts.target_tz.trim()
    );
    let _ = write_executable(&local_bin.join("claude-guard.sh"), &guard_sh);

    // 6. Install Claude Code CLI hard-bound wrapper
    let real_claude = find_real_claude_cli(home).unwrap_or_else(|| "/usr/local/bin/claude".to_string());
    let cli_wrapper = format!(
        r#"#!/usr/bin/env bash
# Claude Shield Managed Wrapper
set -euo pipefail
REAL_CLAUDE="{real}"
if [[ ! -x "${{REAL_CLAUDE}}" ]]; then
  REAL_CLAUDE="$(which -a claude 2>/dev/null | grep -v "$HOME/.local/bin/claude" | head -n 1 || true)"
fi
if [[ -z "${{REAL_CLAUDE}}" || ! -x "${{REAL_CLAUDE}}" ]]; then
  printf '\033[1;31m[Claude Shield]\033[0m 未检测到 Claude Code CLI，请先安装 @anthropic-ai/claude-code。\n' >&2
  exit 127
fi
exec "$HOME/.local/bin/claude-shield-core" exec-cli "${{REAL_CLAUDE}}" "$@"
"#,
        real = real_claude
    );
    if write_executable(&local_bin.join("claude"), &cli_wrapper).is_ok() {
        actions.push("已部署 Claude Code CLI 代理门禁与 IPv4-Only/时区/语言硬绑定".to_string());
    }

    // 7. Install claude-desktop-safe shortcut
    let desktop_safe = "#!/usr/bin/env bash\n# Claude Shield Managed Wrapper\nset -euo pipefail\nexec \"$HOME/.local/bin/claude-shield-core\" launch-desktop \"$@\"\n";
    let _ = write_executable(&local_bin.join("claude-desktop-safe"), desktop_safe);

    // 8. Ensure ~/.local/bin in shell PATH (~/.zshrc and ~/.bash_profile if present)
    if let Some(msg) = ensure_shell_path_block(&home.join(".zshrc")) {
        actions.push(msg);
    }
    let bash_profile = home.join(".bash_profile");
    if bash_profile.exists() {
        if let Some(msg) = ensure_shell_path_block(&bash_profile) {
            actions.push(msg);
        }
    }

    // 9. Harden ~/.claude/settings.json (non-destructive merge + first-time backup)
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
            env_obj.insert("TZ".to_string(), serde_json::json!(opts.target_tz.trim()));
            env_obj.insert("LANG".to_string(), serde_json::json!("en_US.UTF-8"));
            env_obj.insert("LC_ALL".to_string(), serde_json::json!("en_US.UTF-8"));
            env_obj.insert("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC".to_string(), serde_json::json!("1"));
            env_obj.insert("CLAUDE_CODE_ENABLE_TELEMETRY".to_string(), serde_json::json!("0"));
            env_obj.insert("DISABLE_TELEMETRY".to_string(), serde_json::json!("1"));
            env_obj.insert("DISABLE_ERROR_REPORTING".to_string(), serde_json::json!("1"));
            env_obj.insert("DISABLE_BUG_COMMAND".to_string(), serde_json::json!("1"));
            env_obj.insert("DISABLE_AUTOUPDATER".to_string(), serde_json::json!("1"));
        }
    }
    if let Ok(pretty) = serde_json::to_string_pretty(&settings_val) {
        if fs::write(&settings_path, format!("{}\n", pretty)).is_ok() {
            actions.push(format!(
                "已加固 ~/.claude/settings.json（Seatbelt 沙盒 + TZ={} + en_US.UTF-8 + 全量去遥测）",
                opts.target_tz.trim()
            ));
        }
    }

    // 10. Hide original Claude.app if requested
    let updated_cfg = ShieldConfig::load();
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

    // 11. Login Auto-Start Radar LaunchAgent
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
            exec = app_exec
        );
        if install_launch_agent(&radar_plist, &plist_xml) {
            actions.push("已开启开机自启状态栏雷达 (LaunchAgent)".to_string());
        }
    } else {
        remove_launch_agent(&radar_plist);
    }

    // 12. Daily Deep Purity Patrol LaunchAgent
    let patrol_plist = agents_dir.join("com.local.claude.shield.patrol.plist");
    if opts.enable_daily_patrol {
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
            core = core_dst.display(),
            log = config_dir.join("patrol.log").display()
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
        expected_ip: opts.expected_ip.trim().to_string(),
        proxy_port: opts.proxy_port,
        target_tz: opts.target_tz.trim().to_string(),
    }
}

pub fn run_uninstall(cfg: &ShieldConfig, remove_app: bool) -> UninstallReport {
    let mut restored = Vec::new();
    let mut warnings = Vec::new();

    let home = &cfg.home_dir;
    let config_dir = &cfg.config_dir;
    let agents_dir = home.join("Library/LaunchAgents");

    // 1. Remove LaunchAgents (Auto-Start Radar & Daily Patrol)
    let r1 = remove_launch_agent(&agents_dir.join("com.local.claude.shield.radar.plist"));
    let r2 = remove_launch_agent(&agents_dir.join("com.local.claude.shield.patrol.plist"));
    if r1 || r2 {
        restored.push("已关闭并移除开机自启雷达与每日定时巡检任务".to_string());
    }

    // 2. Restore original Claude.app from hidden vault -> /Applications/Claude.app
    let vault_dir = home.join(".local/apps");
    let vault_app = vault_dir.join("Claude.app");
    let apps_dst = PathBuf::from("/Applications/Claude.app");
    let lsreg = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister";

    let _ = Command::new("/usr/bin/chflags")
        .args(["nohidden", vault_dir.to_str().unwrap_or("")])
        .status();

    if vault_app.exists() {
        let _ = Command::new("/usr/bin/chflags")
            .args(["nohidden", vault_app.to_str().unwrap_or("")])
            .status();

        if !apps_dst.exists() {
            let moved = Command::new("/bin/mv")
                .args([vault_app.to_str().unwrap_or(""), "/Applications/Claude.app"])
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if moved {
                let _ = Command::new("/usr/bin/chflags")
                    .args(["nohidden", "/Applications/Claude.app"])
                    .status();
                if Path::new(lsreg).exists() {
                    let _ = Command::new(lsreg)
                        .args(["-f", "/Applications/Claude.app"])
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .status();
                }
                restored.push("已将原版 Claude.app 完整还原至 /Applications 并恢复启动台/Spotlight 图标".to_string());
            } else {
                warnings.push("未能将 ~/.local/apps/Claude.app 移回 /Applications（请检查目录权限）".to_string());
            }
        } else {
            let _ = fs::remove_dir_all(&vault_app);
            if Path::new(lsreg).exists() {
                let _ = Command::new(lsreg)
                    .args(["-f", "/Applications/Claude.app"])
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            restored.push("原版 Claude.app 已位于 /Applications，已清理隔离仓并刷新系统图标索引".to_string());
        }
    }
    let _ = fs::remove_file(vault_dir.join(".metadata_never_index"));
    let _ = fs::remove_dir(&vault_dir); // only removes if empty

    // 3. Surgically restore ~/.claude/settings.json (remove only Claude Shield keys, preserve user's other settings)
    let settings_path = home.join(".claude/settings.json");
    let backup_meta: BackupMeta = fs::read_to_string(config_dir.join("backup/meta.json"))
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();

    if settings_path.exists() {
        if let Ok(raw) = fs::read_to_string(&settings_path) {
            if let Ok(mut val) = serde_json::from_str::<serde_json::Value>(&raw) {
                let mut touched = false;
                if let Some(obj) = val.as_object_mut() {
                    if let Some(env_obj) = obj.get_mut("env").and_then(|e| e.as_object_mut()) {
                        for k in [
                            "TZ",
                            "LANG",
                            "LC_ALL",
                            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
                            "CLAUDE_CODE_ENABLE_TELEMETRY",
                            "DISABLE_TELEMETRY",
                            "DISABLE_ERROR_REPORTING",
                            "DISABLE_BUG_COMMAND",
                            "DISABLE_AUTOUPDATER",
                        ] {
                            if env_obj.remove(k).is_some() {
                                touched = true;
                            }
                        }
                        if env_obj.is_empty() {
                            obj.remove("env");
                        }
                    }

                    if !backup_meta.had_sandbox_enabled {
                        if let Some(sb_obj) = obj.get_mut("sandbox").and_then(|s| s.as_object_mut()) {
                            if sb_obj.remove("enabled").is_some() {
                                touched = true;
                            }
                            if !backup_meta.had_auto_allow_bash {
                                sb_obj.remove("autoAllowBashIfSandboxed");
                            }
                            if sb_obj.is_empty() {
                                obj.remove("sandbox");
                            }
                        }
                    }
                }
                if touched {
                    if let Ok(pretty) = serde_json::to_string_pretty(&val) {
                        let _ = fs::write(&settings_path, format!("{}\n", pretty));
                    }
                    restored.push("已还原 ~/.claude/settings.json（清除时区/语言/去遥测/沙盒注入，保留您原有配置）".to_string());
                }
            }
        }
    }

    // 4. Remove CLI wrappers & OAuth interceptor
    let local_bin = home.join(".local/bin");
    let mut removed_cli = false;

    let claude_wrapper = local_bin.join("claude");
    if claude_wrapper.exists() {
        if let Ok(text) = fs::read_to_string(&claude_wrapper) {
            if text.contains("claude-shield") || text.contains("claude-guard") {
                if fs::remove_file(&claude_wrapper).is_ok() {
                    removed_cli = true;
                }
            }
        }
    }
    for name in ["claude-shield", "claude-shield-core", "claude-guard.sh", "claude-desktop-safe"] {
        let p = local_bin.join(name);
        if p.exists() && fs::remove_file(&p).is_ok() {
            removed_cli = true;
        }
    }
    let guard_bin = home.join(".local/lib/claude-guard-bin");
    if guard_bin.exists() && fs::remove_dir_all(&guard_bin).is_ok() {
        removed_cli = true;
    }
    if removed_cli {
        restored.push("已移除 Claude Code CLI 代理门禁与 OAuth 弹窗拦截器".to_string());
    }

    // 5. Remove Shell PATH block
    let mut cleaned_rc = false;
    if remove_shell_path_block(&home.join(".zshrc")) {
        cleaned_rc = true;
    }
    if remove_shell_path_block(&home.join(".bash_profile")) {
        cleaned_rc = true;
    }
    if cleaned_rc {
        restored.push("已清理 Shell 配置 (~/.zshrc) 中的路径注入块".to_string());
    }

    // 6. Remove ~/.config/claude-guard
    if config_dir.exists() && fs::remove_dir_all(config_dir).is_ok() {
        restored.push("已清理 ~/.config/claude-guard 本地配置与缓存".to_string());
    }

    // 7. Optionally remove /Applications/Claude Shield.app (CLI uninstall mode)
    if remove_app {
        let shield_app = Path::new("/Applications/Claude Shield.app");
        if shield_app.exists() && fs::remove_dir_all(shield_app).is_ok() {
            restored.push("已移除 /Applications/Claude Shield.app".to_string());
        }
    }

    if restored.is_empty() {
        restored.push("本机未发现残留的 Claude Shield 防护配置，系统已处于原始状态".to_string());
    }

    UninstallReport {
        ok: warnings.is_empty(),
        restored,
        warnings,
    }
}
