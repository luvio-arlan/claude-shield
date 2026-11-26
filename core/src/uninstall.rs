use crate::config::ShieldConfig;
use crate::setup::BackupMeta;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UninstallReport {
    pub ok: bool,
    pub restored: Vec<String>,
    pub warnings: Vec<String>,
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

pub(crate) fn remove_launch_agent(plist_path: &Path) -> bool {
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

pub(crate) fn remove_shell_path_block(rc_path: &Path) -> bool {
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

    while out.last().map(|l| l.is_empty()).unwrap_or(false) {
        out.pop();
    }
    let mut final_text = out.join("\n");
    if !final_text.is_empty() {
        final_text.push('\n');
    }
    fs::write(rc_path, final_text).is_ok()
}

pub fn run_uninstall(cfg: &ShieldConfig, remove_app: bool) -> UninstallReport {
    let mut restored = Vec::new();
    let mut warnings = Vec::new();

    let home = &cfg.home_dir;
    let config_dir = &cfg.config_dir;
    let agents_dir = home.join("Library/LaunchAgents");

    let r1 = remove_launch_agent(&agents_dir.join("com.local.claude.shield.radar.plist"));
    let r2 = remove_launch_agent(&agents_dir.join("com.local.claude.shield.patrol.plist"));
    if r1 || r2 {
        restored.push("已关闭并移除开机自启雷达与每日定时巡检任务".to_string());
    }

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
    let _ = fs::remove_dir(&vault_dir);

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

    let local_bin = home.join(".local/bin");
    let mut removed_cli = false;

    let claude_wrapper = local_bin.join("claude");
    if claude_wrapper.exists() {
        if let Ok(text) = fs::read_to_string(&claude_wrapper) {
            if (text.contains("claude-shield") || text.contains("claude-guard"))
                && fs::remove_file(&claude_wrapper).is_ok()
            {
                removed_cli = true;
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

    if config_dir.exists() && fs::remove_dir_all(config_dir).is_ok() {
        restored.push("已清理 ~/.config/claude-guard 本地配置与缓存".to_string());
    }

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
