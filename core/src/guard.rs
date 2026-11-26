use crate::config::ShieldConfig;
use serde::{Deserialize, Serialize};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Stdio};

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

pub(crate) fn escape_applescript(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "'")
        .replace(['\r', '\n'], " ")
}

pub(crate) fn parse_pid_comm_line(line: &str, self_pid: &str) -> Option<(String, String)> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let split_at = trimmed.find(char::is_whitespace)?;
    let pid = trimmed[..split_at].trim();
    if pid.is_empty() || pid == self_pid || !pid.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let comm = trimmed[split_at..].trim();
    if comm.is_empty() {
        return None;
    }
    Some((pid.to_string(), comm.to_string()))
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

pub(crate) fn has_expected_proxy_env(env_out: &str, proxy_port: u16) -> bool {
    let upper = format!("HTTP_PROXY=http://127.0.0.1:{}", proxy_port);
    let lower = format!("http_proxy=http://127.0.0.1:{}", proxy_port);
    env_out.contains(&upper) || env_out.contains(&lower)
}

pub fn audit_local_defenses(cfg: &ShieldConfig) -> LocalDefenseAudit {
    let oauth_path = cfg.home_dir.join(".local/lib/claude-guard-bin/open");
    let oauth_locked = is_executable(&oauth_path);

    let orig_in_apps = Path::new("/Applications/Claude.app").exists();
    let orig_in_vault = cfg.home_dir.join(".local/apps/Claude.app").exists();
    let original_hidden = !orig_in_apps && orig_in_vault;

    let settings_path = cfg.home_dir.join(".claude/settings.json");
    let settings_text = fs::read_to_string(&settings_path).unwrap_or_default();
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

    let pgrep_out = run_capture("/usr/bin/pgrep", &["-x", "Claude"]);
    let desktop_pid = pgrep_out
        .lines()
        .next()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let mut desktop_proxy_bound = true;
    let mut desktop_quic_disabled = true;
    let mut desktop_webrtc_locked = true;

    if let Some(ref pid) = desktop_pid {
        let args_out = run_capture("/bin/ps", &["-p", pid, "-o", "args="]);
        let expected_flag = format!("--proxy-server=http://127.0.0.1:{}", cfg.proxy_port);
        desktop_proxy_bound = args_out.contains(&expected_flag);
        desktop_quic_disabled = args_out.contains("--disable-quic");
        desktop_webrtc_locked =
            args_out.contains("--force-webrtc-ip-handling-policy=disable_non_proxied_udp");
    }

    let unprotected_cli_pids = find_unprotected_claude_cli_pids(cfg);

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
        desktop_pid,
        desktop_proxy_bound,
        desktop_quic_disabled,
        desktop_webrtc_locked,
        unprotected_cli_pids,
        cli_ready,
        login_item_enabled,
        daily_patrol_enabled,
    }
}

fn find_unprotected_claude_cli_pids(cfg: &ShieldConfig) -> Vec<String> {
    // Query only pid + comm first so spaces inside `comm` paths never misalign `args=` splitting.
    let out = run_capture("/bin/ps", &["-ax", "-o", "pid=,comm="]);
    let mut bad = Vec::new();
    let self_pid = std::process::id().to_string();

    for line in out.lines() {
        let Some((pid, comm)) = parse_pid_comm_line(line, &self_pid) else {
            continue;
        };
        if !is_candidate_cli_comm(&comm) {
            continue;
        }
        let args_str = run_capture("/bin/ps", &["-p", &pid, "-o", "args="]);
        if !is_genuine_claude_cli_args(&comm, &args_str) {
            continue;
        }
        let env_out = run_capture("/bin/ps", &["eww", "-p", &pid, "-o", "command="]);
        if !env_out.is_empty() && !has_expected_proxy_env(&env_out, cfg.proxy_port) {
            bad.push(pid);
        }
    }
    bad
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
    fn parse_pid_comm_handles_spaces_in_path() {
        assert_eq!(
            parse_pid_comm_line("  1234 /Applications/My App/claude  ", "999"),
            Some(("1234".to_string(), "/Applications/My App/claude".to_string()))
        );
        assert_eq!(parse_pid_comm_line("999 /usr/local/bin/claude", "999"), None);
        assert_eq!(parse_pid_comm_line("badpid /usr/local/bin/claude", "999"), None);
    }

    #[test]
    fn cli_matching_excludes_wrappers_and_accepts_proxy_env() {
        assert!(is_candidate_cli_comm("/opt/homebrew/bin/claude"));
        assert!(is_candidate_cli_comm("/usr/local/bin/node"));
        assert!(!is_candidate_cli_comm("/usr/bin/python3"));

        assert!(is_genuine_claude_cli_args("claude", "claude --resume"));
        assert!(is_genuine_claude_cli_args("node", "node /opt/node_modules/@anthropic-ai/claude-code/cli.js"));
        assert!(!is_genuine_claude_cli_args("claude", "claude-shield-core exec-cli"));

        assert!(has_expected_proxy_env("PATH=/usr/bin HTTP_PROXY=http://127.0.0.1:7897", 7897));
        assert!(has_expected_proxy_env("http_proxy=http://127.0.0.1:7890", 7890));
        assert!(!has_expected_proxy_env("HTTP_PROXY=http://127.0.0.1:7890", 7897));
    }

    #[test]
    fn escape_applescript_sanitizes_quotes_and_newlines() {
        assert_eq!(escape_applescript("a\"b\\c\nd\re"), "a'b\\\\c d e");
    }
}
