use crate::config::ShieldConfig;
use crate::proc_audit::inspect_claude_processes;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

struct CachedSettingsFlags {
    path: PathBuf,
    mtime: Option<SystemTime>,
    len: u64,
    sandbox_enabled: bool,
    telemetry_disabled: bool,
}

fn read_settings_flags_cached(settings_path: &Path) -> (bool, bool) {
    static CACHE: OnceLock<Mutex<Option<CachedSettingsFlags>>> = OnceLock::new();
    let meta = fs::metadata(settings_path).ok();
    let mtime = meta.as_ref().and_then(|m| m.modified().ok());
    let len = meta.as_ref().map(|m| m.len()).unwrap_or(0);

    let cache = CACHE.get_or_init(|| Mutex::new(None));
    if let Ok(guard) = cache.lock() {
        if let Some(ref entry) = *guard {
            if entry.path == settings_path && entry.mtime == mtime && entry.len == len {
                return (entry.sandbox_enabled, entry.telemetry_disabled);
            }
        }
    }

    let settings_text = fs::read_to_string(settings_path).unwrap_or_default();
    let settings_json = serde_json::from_str::<serde_json::Value>(&settings_text).ok();
    let sandbox_enabled = settings_json
        .as_ref()
        .and_then(|v| v.pointer("/sandbox/enabled"))
        .and_then(|x| x.as_bool())
        .unwrap_or(false);
    let telemetry_disabled = settings_json
        .as_ref()
        .map(|v| {
            v.pointer("/env/CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC").is_some()
                && v.pointer("/env/DISABLE_TELEMETRY").is_some()
        })
        .unwrap_or_else(|| {
            settings_text.contains("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC")
                && settings_text.contains("DISABLE_TELEMETRY")
        });

    if let Ok(mut guard) = cache.lock() {
        *guard = Some(CachedSettingsFlags {
            path: settings_path.to_path_buf(),
            mtime,
            len,
            sandbox_enabled,
            telemetry_disabled,
        });
    }
    (sandbox_enabled, telemetry_disabled)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalDefenseAudit {
    pub oauth_locked: bool,
    pub original_hidden: bool,
    pub original_app_exposed: bool,
    pub hide_original_enabled: bool,
    pub sandbox_enabled: bool,
    pub telemetry_disabled: bool,
    pub desktop_pid: Option<String>,
    #[serde(default)]
    pub desktop_pids: Vec<String>,
    pub desktop_proxy_bound: bool,
    #[serde(default = "default_true")]
    pub desktop_bypass_locked: bool,
    pub desktop_quic_disabled: bool,
    pub desktop_webrtc_locked: bool,
    #[serde(default)]
    pub active_cli_pids: Vec<String>,
    pub unprotected_cli_pids: Vec<String>,
    pub cli_ready: bool,
    pub login_item_enabled: bool,
    pub daily_patrol_enabled: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaunchDesktopOutcome {
    pub ok: bool,
    pub already_running: bool,
    pub pid: Option<u32>,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KillOutcome {
    pub killed_desktop: usize,
    pub killed_cli: usize,
}

fn is_executable(path: &Path) -> bool {
    fs::metadata(path)
        .map(|m| m.is_file() && (m.permissions().mode() & 0o111 != 0))
        .unwrap_or(false)
}

fn run_capture(bin: &str, args: &[&str]) -> String {
    Command::new(bin)
        .args(args)
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default()
}

pub fn current_uid() -> u32 {
    extern "C" {
        fn getuid() -> u32;
    }
    unsafe { getuid() }
}

pub fn escape_applescript(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "'")
        .replace(['\r', '\n'], " ")
}

fn is_native_versioned_claude_path(comm: &str) -> bool {
    comm.contains("/.local/share/claude/versions/") || comm.contains("/claude/versions/")
}

pub(crate) fn is_candidate_cli_comm(comm: &str) -> bool {
    let base = comm.rsplit('/').next().unwrap_or(comm);
    matches!(base, "claude" | "node" | "bun") || is_native_versioned_claude_path(comm)
}

pub(crate) fn is_genuine_claude_cli_args(comm: &str, args_str: &str) -> bool {
    let base = comm.rsplit('/').next().unwrap_or(comm);
    let is_claude_bin = base == "claude" || is_native_versioned_claude_path(comm);
    let is_node_claude = (base == "node" || base == "bun")
        && (args_str.contains("@anthropic-ai/claude-code") || args_str.contains("/claude-code/"));
    (is_claude_bin || is_node_claude)
        && !args_str.contains("claude-shield")
        && !args_str.contains("ClaudeShield")
        && !args_str.contains("Claude.app")
        && !args_str.contains("claude-guard")
        && !args_str.contains("claude-desktop-safe")
}

pub fn apply_hardened_env(cmd: &mut Command, cfg: &ShieldConfig) {
    let http = cfg.proxy_http_url();
    let socks = cfg.proxy_socks_url();
    let guard_bin = cfg.home_dir.join(".local/lib/claude-guard-bin");
    let guard_bin_str = guard_bin.to_string_lossy().to_string();
    let orig_path = std::env::var("PATH").unwrap_or_default();
    let new_path = if orig_path.split(':').next() == Some(guard_bin_str.as_str()) {
        orig_path
    } else if orig_path.is_empty() {
        guard_bin_str
    } else {
        format!("{}:{}", guard_bin_str, orig_path)
    };

    let existing_node_opts = std::env::var("NODE_OPTIONS").unwrap_or_default();
    let node_opts = if existing_node_opts.contains("--dns-result-order=") {
        existing_node_opts
    } else if existing_node_opts.is_empty() {
        "--dns-result-order=ipv4first".to_string()
    } else {
        format!("{} --dns-result-order=ipv4first", existing_node_opts)
    };

    cmd.env("TZ", &cfg.target_tz)
        .env("LANG", "en_US.UTF-8")
        .env("LC_ALL", "en_US.UTF-8")
        .env("HTTP_PROXY", &http)
        .env("HTTPS_PROXY", &http)
        .env("ALL_PROXY", &socks)
        .env("http_proxy", &http)
        .env("https_proxy", &http)
        .env("all_proxy", &socks)
        .env("NO_PROXY", "localhost,127.0.0.1,::1")
        .env("no_proxy", "localhost,127.0.0.1,::1")
        .env("NODE_OPTIONS", node_opts)
        .env("NODE_USE_ENV_PROXY", "1")
        .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
        .env("CLAUDE_CODE_DISABLE_FEEDBACK_SURVEY", "1")
        .env("CLAUDE_CODE_ENABLE_TELEMETRY", "0")
        .env("DISABLE_TELEMETRY", "1")
        .env("DISABLE_ERROR_REPORTING", "1")
        .env("DISABLE_BUG_COMMAND", "1")
        .env("DISABLE_AUTOUPDATER", "1")
        .env("OTEL_SDK_DISABLED", "1")
        .env("DO_NOT_TRACK", "1")
        .env("PATH", new_path)
        .env("BROWSER", guard_bin.join("open"));
}

pub fn audit_local_defenses(cfg: &ShieldConfig) -> LocalDefenseAudit {
    let oauth_path = cfg.home_dir.join(".local/lib/claude-guard-bin/open");
    let oauth_locked = is_executable(&oauth_path);

    let orig_in_apps = Path::new("/Applications/Claude.app").exists();
    let orig_in_vault = cfg.home_dir.join(".local/apps/Claude.app").exists();
    let original_hidden = !orig_in_apps && orig_in_vault;

    let settings_path = cfg.home_dir.join(".claude/settings.json");
    let (sandbox_enabled, telemetry_disabled) = read_settings_flags_cached(&settings_path);

    let procs = inspect_claude_processes(cfg.proxy_port);

    let cli_ready = is_executable(&cfg.home_dir.join(".local/bin/claude"));
    let login_item_enabled = cfg
        .home_dir
        .join("Library/LaunchAgents/com.local.claude.shield.radar.plist")
        .exists();
    let daily_patrol_enabled = cfg
        .home_dir
        .join("Library/LaunchAgents/com.local.claude.shield.patrol.plist")
        .exists();

    LocalDefenseAudit {
        oauth_locked,
        original_hidden,
        original_app_exposed: orig_in_apps,
        hide_original_enabled: cfg.hide_original,
        sandbox_enabled,
        telemetry_disabled,
        desktop_pid: procs.desktop_pid,
        desktop_pids: procs.desktop_pids,
        desktop_proxy_bound: procs.desktop_proxy_bound,
        desktop_bypass_locked: procs.desktop_bypass_locked,
        desktop_quic_disabled: procs.desktop_quic_disabled,
        desktop_webrtc_locked: procs.desktop_webrtc_locked,
        active_cli_pids: procs.active_cli_pids,
        unprotected_cli_pids: procs.unprotected_cli_pids,
        cli_ready,
        login_item_enabled,
        daily_patrol_enabled,
    }
}

/// Complete original Claude.app hiding & quarantine:
/// 1) Moves /Applications/Claude.app -> ~/.local/apps/Claude.app (preserving Apple code signature)
/// 2) Marks ~/.local/apps and ~/.local/apps/Claude.app as macOS hidden (chflags hidden) + .metadata_never_index
/// 3) Unregisters both /Applications/Claude.app and ~/.local/apps/Claude.app from LaunchServices (Spotlight/Launchpad)
/// 4) Removes any stale Claude.app icon from Dock persistent-apps without disturbing other Dock icons
pub fn hide_original_claude_app(cfg: &ShieldConfig) -> Vec<String> {
    let mut actions = Vec::new();
    let apps_src = Path::new("/Applications/Claude.app");
    let vault_dir = cfg.home_dir.join(".local/apps");
    let vault_app = vault_dir.join("Claude.app");
    let _ = fs::create_dir_all(&vault_dir);

    let was_exposed = apps_src.exists();
    if was_exposed {
        if vault_app.exists() {
            let backup = vault_dir.join("Claude.app.old");
            let _ = fs::remove_dir_all(&backup);
            let _ = fs::rename(&vault_app, &backup);
            if Command::new("/bin/mv")
                .args(["/Applications/Claude.app", vault_app.to_str().unwrap_or("")])
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                let _ = fs::remove_dir_all(&backup);
                actions.push("已将新出现的 /Applications/Claude.app 自动归档至隐藏隔离仓".to_string());
            } else {
                let _ = fs::rename(&backup, &vault_app);
            }
        } else if Command::new("/bin/mv")
            .args(["/Applications/Claude.app", vault_app.to_str().unwrap_or("")])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
        {
            actions.push("已将 /Applications/Claude.app 移入隐藏隔离仓 ~/.local/apps/Claude.app".to_string());
        }
    }

    let _ = fs::write(vault_dir.join(".metadata_never_index"), "");
    let _ = Command::new("/usr/bin/chflags")
        .args(["hidden", vault_dir.to_str().unwrap_or("")])
        .status();
    if vault_app.exists() {
        let _ = Command::new("/usr/bin/chflags")
            .args(["hidden", vault_app.to_str().unwrap_or("")])
            .status();
    }

    let lsreg = "/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister";
    if Path::new(lsreg).exists() {
        if was_exposed || apps_src.exists() {
            let _ = Command::new(lsreg)
                .args(["-u", "/Applications/Claude.app"])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        if vault_app.exists() {
            let _ = Command::new(lsreg)
                .args(["-u", vault_app.to_str().unwrap_or("")])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        if was_exposed {
            actions.push("已从 LaunchServices / Spotlight 注销原版 Claude.app 索引".to_string());
        }
    }

    let dock_plist = cfg.home_dir.join("Library/Preferences/com.apple.dock.plist");
    let dock_may_contain_claude = fs::read(&dock_plist)
        .map(|bytes| bytes.windows(6).any(|w| w == b"Claude"))
        .unwrap_or(false);

    if dock_may_contain_claude {
        let dock_clean_script = r#"
import plistlib, os, subprocess, sys
p = os.path.expanduser("~/Library/Preferences/com.apple.dock.plist")
if not os.path.exists(p): sys.exit(0)
with open(p, "rb") as f: data = plistlib.load(f)
apps = data.get("persistent-apps", [])
new_apps = []
removed = False
for item in apps:
    url = item.get("tile-data", {}).get("file-data", {}).get("_CFURLString", "")
    label = item.get("tile-data", {}).get("file-label", "")
    if label == "Claude" or url.endswith("/Claude.app/") or url.endswith("/Claude.app"):
        removed = True
        continue
    new_apps.append(item)
if removed:
    data["persistent-apps"] = new_apps
    with open(p, "wb") as f: plistlib.dump(data, f)
    subprocess.run(["/usr/bin/killall", "Dock"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("REMOVED_DOCK")
"#;
        let dock_out = run_capture("/usr/bin/python3", &["-c", dock_clean_script]);
        if dock_out.contains("REMOVED_DOCK") {
            actions.push("已从程序坞 (Dock) 移除原版 Claude 图标".to_string());
        }
    }

    actions
}

fn posix_sigkill(pid: i32) -> bool {
    if pid <= 1 || pid == std::process::id() as i32 {
        return false;
    }
    extern "C" {
        fn kill(pid: i32, sig: i32) -> i32;
    }
    const SIGKILL: i32 = 9;
    unsafe { kill(pid, SIGKILL) == 0 }
}

pub fn kill_pids(pids: &[String]) -> usize {
    let mut killed = 0usize;
    for pid_str in pids {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            if posix_sigkill(pid) {
                killed += 1;
            }
        }
    }
    killed
}

pub fn kill_claude_desktop() -> usize {
    let procs = inspect_claude_processes(0);
    let mut killed = kill_pids(&procs.desktop_pids);
    if killed == 0 {
        // Fallback pkill in case a helper/spawned Claude process appeared between scans
        let _ = Command::new("/usr/bin/pkill").args(["-9", "-x", "Claude"]).status();
    } else {
        // Also ensure any Electron helper/renderer child doesn't linger
        let _ = Command::new("/usr/bin/pkill").args(["-9", "-x", "Claude"]).status();
    }
    if killed == 0 && !procs.desktop_pids.is_empty() {
        killed = procs.desktop_pids.len();
    }
    killed
}

pub fn kill_claude_sessions(cfg: &ShieldConfig, include_cli: bool) -> KillOutcome {
    let procs = inspect_claude_processes(cfg.proxy_port);
    let mut killed_desktop = kill_pids(&procs.desktop_pids);
    if !procs.desktop_pids.is_empty() || killed_desktop == 0 {
        let _ = Command::new("/usr/bin/pkill").args(["-9", "-x", "Claude"]).status();
        if killed_desktop == 0 && !procs.desktop_pids.is_empty() {
            killed_desktop = procs.desktop_pids.len();
        }
    }
    let killed_cli = if include_cli {
        kill_pids(&procs.active_cli_pids)
    } else {
        0
    };
    KillOutcome {
        killed_desktop,
        killed_cli,
    }
}

/// Spawn or focus hardened Claude Desktop in-process (zero CLI subprocess fork).
/// Caller is responsible for running gate verification unless `verified_ip` is already approved.
pub fn spawn_hardened_claude_desktop(
    cfg: &ShieldConfig,
    verified_ip: Option<&str>,
) -> LaunchDesktopOutcome {
    if cfg.hide_original && Path::new("/Applications/Claude.app").exists() {
        hide_original_claude_app(cfg);
    }

    let vault_app = cfg.home_dir.join(".local/apps/Claude.app");
    let app_path = if vault_app.exists() {
        vault_app
    } else if Path::new("/Applications/Claude.app").exists() {
        Path::new("/Applications/Claude.app").to_path_buf()
    } else {
        return LaunchDesktopOutcome {
            ok: false,
            already_running: false,
            pid: None,
            message: "未检测到 Claude 桌面版（Claude.app），请先安装 Claude Desktop。".to_string(),
        };
    };

    let defenses = audit_local_defenses(cfg);
    if defenses.desktop_pid.is_some() {
        if defenses.desktop_proxy_bound
            && defenses.desktop_bypass_locked
            && defenses.desktop_quic_disabled
            && defenses.desktop_webrtc_locked
        {
            let _ = Command::new("/usr/bin/open")
                .args(["-a", app_path.to_str().unwrap_or("/Applications/Claude.app")])
                .status();
            return LaunchDesktopOutcome {
                ok: true,
                already_running: true,
                pid: defenses.desktop_pid.and_then(|s| s.parse::<u32>().ok()),
                message: "已将受保护的 Claude 桌面版拉至前台".to_string(),
            };
        }
        kill_claude_desktop();
        std::thread::sleep(std::time::Duration::from_millis(320));
    }

    if let Some(ip) = verified_ip {
        let trimmed = ip.trim();
        if !trimmed.is_empty() && trimmed != "无法连通" && trimmed != "未配置" {
            let _ = fs::create_dir_all(&cfg.config_dir);
            let _ = fs::write(cfg.config_dir.join("last_launch_ip"), format!("{}\n", trimmed));
        }
    }

    let bin = app_path.join("Contents/MacOS/Claude");
    let mut cmd = Command::new(&bin);
    cmd.args([
        &format!("--proxy-server=http://127.0.0.1:{}", cfg.proxy_port),
        "--proxy-bypass-list=<-loopback>",
        "--disable-quic",
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--lang=en-US",
    ]);
    apply_hardened_env(&mut cmd, cfg);
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    match cmd.spawn() {
        Ok(mut child) => {
            let pid = child.id();
            std::thread::sleep(std::time::Duration::from_millis(450));
            if let Ok(Some(status)) = child.try_wait() {
                return LaunchDesktopOutcome {
                    ok: false,
                    already_running: false,
                    pid: None,
                    message: format!("Claude 桌面版异常退出 (code: {:?})", status.code()),
                };
            }
            LaunchDesktopOutcome {
                ok: true,
                already_running: false,
                pid: Some(pid),
                message: "已安全启动 Claude 桌面版".to_string(),
            }
        }
        Err(e) => LaunchDesktopOutcome {
            ok: false,
            already_running: false,
            pid: None,
            message: format!("Claude 桌面版启动失败: {}", e),
        },
    }
}

pub fn send_macos_notification(title: &str, body: &str, sound: Option<&str>) {
    let safe_title = escape_applescript(title);
    let safe_body = escape_applescript(body);
    let script = match sound {
        Some(s) => format!(
            "display notification \"{}\" with title \"{}\" sound name \"{}\"",
            safe_body,
            safe_title,
            escape_applescript(s)
        ),
        None => format!(
            "display notification \"{}\" with title \"{}\"",
            safe_body, safe_title
        ),
    };
    let _ = Command::new("/usr/bin/osascript").args(["-e", &script]).status();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_matching_covers_native_versions_and_excludes_wrappers() {
        assert!(is_candidate_cli_comm("/opt/homebrew/bin/claude"));
        assert!(is_candidate_cli_comm("/usr/local/bin/node"));
        assert!(is_candidate_cli_comm("/Users/u/.local/share/claude/versions/2.1.45"));
        assert!(!is_candidate_cli_comm("/usr/bin/python3"));

        assert!(is_genuine_claude_cli_args("claude", "claude --resume"));
        assert!(is_genuine_claude_cli_args(
            "/Users/u/.local/share/claude/versions/2.1.45",
            "claude --resume"
        ));
        assert!(is_genuine_claude_cli_args(
            "node",
            "node /opt/node_modules/@anthropic-ai/claude-code/cli.js"
        ));
        assert!(!is_genuine_claude_cli_args("claude", "claude-shield-core exec-cli"));
    }

    #[test]
    fn escape_applescript_sanitizes_quotes_and_newlines() {
        assert_eq!(escape_applescript("a\"b\\c\nd\re"), "a'b\\\\c d e");
    }
}
