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
    pub desktop_proxy_bound: bool,
    pub desktop_quic_disabled: bool,
    pub desktop_webrtc_locked: bool,
    pub unprotected_cli_pids: Vec<String>,
    pub cli_ready: bool,
    pub login_item_enabled: bool,
    pub daily_patrol_enabled: bool,
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

pub fn escape_applescript(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "'")
        .replace(['\r', '\n'], " ")
}

pub(crate) fn is_candidate_cli_comm(comm: &str) -> bool {
    let base = comm.rsplit('/').next().unwrap_or(comm);
    matches!(base, "claude" | "node" | "bun")
}

pub(crate) fn is_genuine_claude_cli_args(comm: &str, args_str: &str) -> bool {
    let base = comm.rsplit('/').next().unwrap_or(comm);
    let is_claude_bin = base == "claude";
    let is_node_claude = (base == "node" || base == "bun")
        && (args_str.contains("@anthropic-ai/claude-code") || args_str.contains("/claude-code/"));
    (is_claude_bin || is_node_claude)
        && !args_str.contains("claude-shield")
        && !args_str.contains("ClaudeShield")
        && !args_str.contains("Claude.app")
        && !args_str.contains("claude-guard")
        && !args_str.contains("claude-desktop-safe")
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
        desktop_proxy_bound: procs.desktop_proxy_bound,
        desktop_quic_disabled: procs.desktop_quic_disabled,
        desktop_webrtc_locked: procs.desktop_webrtc_locked,
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

    actions
}

pub fn kill_claude_desktop() {
    let _ = Command::new("/usr/bin/pkill").args(["-9", "-x", "Claude"]).status();
}

pub fn kill_pids(pids: &[String]) {
    for pid in pids {
        let _ = Command::new("/bin/kill").args(["-9", pid]).status();
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
    fn cli_matching_excludes_wrappers() {
        assert!(is_candidate_cli_comm("/opt/homebrew/bin/claude"));
        assert!(is_candidate_cli_comm("/usr/local/bin/node"));
        assert!(!is_candidate_cli_comm("/usr/bin/python3"));

        assert!(is_genuine_claude_cli_args("claude", "claude --resume"));
        assert!(is_genuine_claude_cli_args("node", "node /opt/node_modules/@anthropic-ai/claude-code/cli.js"));
        assert!(!is_genuine_claude_cli_args("claude", "claude-shield-core exec-cli"));
    }

    #[test]
    fn escape_applescript_sanitizes_quotes_and_newlines() {
        assert_eq!(escape_applescript("a\"b\\c\nd\re"), "a'b\\\\c d e");
    }
}
