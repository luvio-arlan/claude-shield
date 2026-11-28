use claude_shield_core::config::ShieldConfig;
use claude_shield_core::detect::{
    detect_environment, find_real_claude_cli, is_shield_managed_wrapper,
};
use claude_shield_core::guard::{
    apply_hardened_env, audit_local_defenses, escape_applescript, hide_original_claude_app,
    spawn_hardened_claude_desktop,
};
use claude_shield_core::patrol::{self, run_daily_patrol};
use claude_shield_core::pf_guard::{
    disable_pf_guard, enable_pf_guard, generate_anchor_rules, pf_guard_status,
};
use claude_shield_core::probe::{full_telemetry_probe, light_telemetry_probe, quick_gate_probe};
use claude_shield_core::purity::run_purity_audit;
use claude_shield_core::setup::{run_setup, SetupOptions};
use claude_shield_core::uninstall::run_uninstall;
use claude_shield_core::worker;
use claude_shield_core::{build_telemetry_payload, evaluate_gate_with_probes, GateJson};
use std::env;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::Command;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let subcmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");
    let json_mode = args.iter().any(|a| a == "--json");
    let cfg = ShieldConfig::load();

    match subcmd {
        "worker" => worker::run_worker_loop().await,
        "telemetry" => {
            let light = args.iter().any(|a| a == "--light");
            cmd_telemetry(&cfg, light).await;
        }
        "defenses" => {
            let defenses = audit_local_defenses(&cfg);
            println!("{}", serde_json::to_string(&defenses).unwrap_or_default());
        }
        "pf-guard" => {
            let action = args.get(2).map(|s| s.as_str()).unwrap_or("status");
            cmd_pf_guard(&cfg, action, json_mode);
        }
        "gate" => cmd_gate(&cfg, json_mode).await,
        "purity" => cmd_purity(&cfg, json_mode).await,
        "patrol" => {
            let notify = args.iter().any(|a| a == "--notify");
            let auto_kill = !args.iter().any(|a| a == "--no-kill");
            let report = run_daily_patrol(&cfg, notify, auto_kill).await;
            if json_mode {
                println!("{}", serde_json::to_string(&report).unwrap_or_default());
            } else {
                print_patrol_human(&report);
            }
            if !report.passed {
                std::process::exit(1);
            }
        }
        "hide-original" => {
            let actions = hide_original_claude_app(&cfg);
            if json_mode {
                println!("{}", serde_json::to_string(&actions).unwrap_or_default());
            } else if actions.is_empty() {
                println!("✅ 原版 Claude.app 已处于隐藏隔离状态");
            } else {
                for a in actions {
                    println!("✅ {}", a);
                }
            }
        }
        "exec-cli" => {
            let real_bin = args.get(2).cloned().unwrap_or_else(|| "/usr/local/bin/claude".to_string());
            let pass_args: Vec<String> = args.iter().skip(3).cloned().collect();
            cmd_exec_cli(&cfg, &real_bin, &pass_args).await;
        }
        "launch-desktop" => {
            let force = args.iter().any(|a| a == "--force");
            cmd_launch_desktop(&cfg, force).await;
        }
        "detect" => {
            let preferred_port = arg_value(&args, "--port").and_then(|s| s.parse::<u16>().ok());
            let res = detect_environment(&cfg, preferred_port).await;
            if json_mode {
                println!("{}", serde_json::to_string(&res).unwrap_or_default());
            } else {
                println!(
                    "Proxy :{} ({}) | Exit IP: {} | TUN IP: {} | TZ: {} | City: {}, {}",
                    res.proxy_port,
                    if res.proxy_reachable { "OK" } else { "OFF" },
                    if res.exit_ip.is_empty() { "-" } else { &res.exit_ip },
                    if res.tun_ip.is_empty() { "-" } else { &res.tun_ip },
                    res.detected_tz,
                    res.city,
                    res.country_code
                );
            }
        }
        "setup" => {
            let ip = arg_value(&args, "--ip").unwrap_or_else(|| cfg.expected_ip.clone());
            let port = arg_value(&args, "--port")
                .and_then(|s| s.parse::<u16>().ok())
                .unwrap_or(cfg.proxy_port);
            let tz = arg_value(&args, "--tz").unwrap_or_else(|| cfg.target_tz.clone());
            let hide_original = !args.iter().any(|a| a == "--no-hide");
            let enable_autostart = !args.iter().any(|a| a == "--no-autostart");
            let enable_daily_patrol = !args.iter().any(|a| a == "--no-patrol");
            let app_bundle_path = arg_value(&args, "--app-path")
                .unwrap_or_else(|| "/Applications/Claude Shield.app".to_string());
            let opts = SetupOptions {
                expected_ip: ip,
                proxy_port: port,
                target_tz: tz,
                hide_original,
                enable_autostart,
                enable_daily_patrol,
                app_bundle_path,
            };
            let report = run_setup(&cfg, &opts);
            if json_mode {
                println!("{}", serde_json::to_string(&report).unwrap_or_default());
            } else if report.ok {
                println!("🛡️  Claude Shield 一键部署完成");
                for a in &report.actions {
                    println!("  ✅ {}", a);
                }
                for w in &report.warnings {
                    println!("  ⚠️  {}", w);
                }
            } else {
                for w in &report.warnings {
                    eprintln!("  ❌ {}", w);
                }
                std::process::exit(1);
            }
        }
        "uninstall" => {
            let remove_app = args.iter().any(|a| a == "--remove-app");
            let report = run_uninstall(&cfg, remove_app);
            if json_mode {
                println!("{}", serde_json::to_string(&report).unwrap_or_default());
            } else {
                println!("♻️  Claude Shield 已一键卸载并还原系统环境");
                for r in &report.restored {
                    println!("  ✅ {}", r);
                }
                for w in &report.warnings {
                    println!("  ⚠️  {}", w);
                }
            }
        }
        _ => {
            println!("Claude Shield Core v{} (Native Rust Engine)", env!("CARGO_PKG_VERSION"));
            println!("Usage: claude-shield-core <worker|telemetry|defenses|pf-guard|gate|purity|patrol|hide-original|detect|setup|uninstall|exec-cli|launch-desktop> [--json]");
        }
    }
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}

fn cmd_pf_guard(cfg: &ShieldConfig, action: &str, json_mode: bool) {
    match action {
        "generate" => {
            print!("{}", generate_anchor_rules(cfg));
        }
        "enable" => match enable_pf_guard(cfg) {
            Ok(msg) => {
                if json_mode {
                    println!("{}", serde_json::json!({ "ok": true, "message": msg }));
                } else {
                    println!("✅ {}", msg);
                }
            }
            Err(err) => {
                if json_mode {
                    println!("{}", serde_json::json!({ "ok": false, "error": err }));
                } else {
                    eprintln!("❌ {}", err);
                }
                std::process::exit(1);
            }
        },
        "disable" => match disable_pf_guard() {
            Ok(msg) => {
                if json_mode {
                    println!("{}", serde_json::json!({ "ok": true, "message": msg }));
                } else {
                    println!("✅ {}", msg);
                }
            }
            Err(err) => {
                if json_mode {
                    println!("{}", serde_json::json!({ "ok": false, "error": err }));
                } else {
                    eprintln!("❌ {}", err);
                }
                std::process::exit(1);
            }
        },
        _ => {
            let status = pf_guard_status();
            if json_mode {
                println!("{}", serde_json::to_string(&status).unwrap_or_default());
            } else {
                println!(
                    "PF Anchor {} — {} ({})",
                    status.anchor_name,
                    if status.active { "ACTIVE ✅" } else { "INACTIVE" },
                    status.note
                );
            }
        }
    }
}

async fn cmd_telemetry(cfg: &ShieldConfig, light: bool) {
    let net = if light {
        light_telemetry_probe(cfg).await
    } else {
        full_telemetry_probe(cfg).await
    };
    let defenses = audit_local_defenses(cfg);
    let payload = build_telemetry_payload(cfg, net, defenses);

    cfg.write_cache_json("last_telemetry.json", &payload);
    println!("{}", serde_json::to_string(&payload).unwrap_or_default());
}

async fn evaluate_gate(cfg: &ShieldConfig) -> GateJson {
    let t0 = std::time::Instant::now();
    let (proxy, tun, edge) = quick_gate_probe(cfg).await;
    let elapsed_ms = t0.elapsed().as_millis() as u64;
    evaluate_gate_with_probes(cfg, proxy, tun, edge, elapsed_ms)
}

async fn cmd_gate(cfg: &ShieldConfig, json_mode: bool) {
    let res = evaluate_gate(cfg).await;
    if json_mode {
        println!("{}", serde_json::to_string(&res).unwrap_or_default());
    } else if let Some(ref err) = res.error {
        println!("CLAUDE_GUARD_ERR:{}", err);
    } else {
        println!(
            "OK ip={} loc={} colo={} ms={}",
            res.proxy_ip,
            res.claude_loc.as_deref().unwrap_or("?"),
            res.claude_colo.as_deref().unwrap_or("?"),
            res.elapsed_ms
        );
    }
    if !res.ok {
        std::process::exit(1);
    }
}

async fn cmd_purity(cfg: &ShieldConfig, json_mode: bool) {
    let report = run_purity_audit(cfg).await;
    if json_mode {
        println!("{}", serde_json::to_string(&report).unwrap_or_default());
        return;
    }

    let grade_color = match report.grade.as_str() {
        "S" | "A" => "\x1b[1;32m",
        "B" => "\x1b[1;33m",
        _ => "\x1b[1;31m",
    };
    println!("\n\x1b[1m🛡️  Claude Shield IP 纯净度深度体检 (ip.net.coffee 级)\x1b[0m");
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    println!(
        "综合评分: {}{}/100 ({} 级)\x1b[0m  —  {}",
        grade_color, report.purity_score, report.grade, report.verdict
    );
    println!(
        "出口 IP : {}  |  类型: {}  |  ASN: {}",
        report.exit_ip, report.ip_type, report.asn
    );
    println!(
        "地理位置: {} · {} ({})  |  运营商: {}",
        report.country, report.city, report.country_code, report.isp
    );
    println!(
        "Claude边: {} (colo={} | {} | warp={})",
        report.claude_edge_ip,
        report.claude_colo.as_deref().unwrap_or("-"),
        report.claude_tls.as_deref().unwrap_or("-"),
        report.claude_warp.as_deref().unwrap_or("-")
    );
    let dns_status_str = if report.dns_leak {
        "\x1b[31m存在泄露!\x1b[0m"
    } else if !report.dns_verified() {
        "\x1b[33m检测未完成(待复测)\x1b[0m"
    } else {
        "\x1b[32m安全\x1b[0m"
    };
    println!(
        "DNS 检测: {}  |  IPv6 泄露: {}  |  时区对齐: {}",
        dns_status_str,
        if report.ipv6_leak { "\x1b[31m存在泄露!\x1b[0m" } else { "\x1b[32m安全\x1b[0m" },
        if report.timezone_aligned { "\x1b[32m已对齐\x1b[0m" } else { "\x1b[33m不一致\x1b[0m" }
    );
    println!("──────────────────────────────────────────────────");
    for f in &report.factors {
        let icon = match f.severity.as_str() {
            "good" => "✅",
            "warn" => "⚠️ ",
            _ => "🚨",
        };
        let pen = if f.penalty < 0 {
            format!(" ({})", f.penalty)
        } else {
            String::new()
        };
        println!("{} {}{}: {}", icon, f.title, pen, f.detail);
    }
    println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n");
}

fn print_patrol_human(report: &patrol::PatrolReport) {
    println!(
        "🛡️  Claude Shield Patrol [{}] — {} (Purity: {}/100 {})",
        report.timestamp,
        if report.passed { "PASS ✅" } else { "ALERT 🚨" },
        report.purity_score,
        report.grade
    );
    for h in &report.auto_healed {
        println!("  🔧 Auto-Healed: {}", h);
    }
    for a in &report.alerts {
        println!("  ⚠️  Alert: {}", a);
    }
}

async fn cmd_exec_cli(cfg: &ShieldConfig, real_bin: &str, pass_args: &[String]) {
    let gate = evaluate_gate(cfg).await;
    if !gate.ok {
        eprintln!(
            "\x1b[1;31m[Claude Shield 熔断拦截]\x1b[0m {}",
            gate.error.unwrap_or_else(|| "IP 校验失败".into())
        );
        std::process::exit(1);
    }

    // Prevent wrapper self-recursion if PATH resolution ever points back to ~/.local/bin/claude
    let wrapper_self = cfg.home_dir.join(".local/bin/claude");
    let target_path = Path::new(real_bin);
    let points_to_self = is_shield_managed_wrapper(target_path)
        || (std::fs::canonicalize(target_path).ok() == std::fs::canonicalize(&wrapper_self).ok()
            && wrapper_self.exists());
    let resolved_bin = if points_to_self {
        match find_real_claude_cli(&cfg.home_dir) {
            Some(found) => found,
            None => {
                eprintln!(
                    "\x1b[1;31m[Claude Shield]\x1b[0m 检测到 CLI 包装器指向自身且未找到真实 claude 二进制，已中止防死循环。"
                );
                std::process::exit(127);
            }
        }
    } else {
        real_bin.to_string()
    };

    eprintln!(
        "\x1b[0;32m[Claude Shield v{}]\x1b[0m ✅ IP={} ({}) | TZ={} | Proxy=127.0.0.1:{} | Gate={}ms | IPv4-Only",
        env!("CARGO_PKG_VERSION"),
        gate.proxy_ip,
        gate.claude_colo.as_deref().unwrap_or("CF"),
        cfg.target_tz,
        cfg.proxy_port,
        gate.elapsed_ms
    );

    let mut cmd = Command::new(&resolved_bin);
    cmd.args(pass_args);
    apply_hardened_env(&mut cmd, cfg);

    let err = cmd.exec();
    eprintln!("\x1b[1;31m[Claude Shield]\x1b[0m 无法执行 {}: {}", resolved_bin, err);
    std::process::exit(127);
}

async fn cmd_launch_desktop(cfg: &ShieldConfig, force: bool) {
    let mut verified_ip: Option<String> = None;
    if !force {
        let gate = evaluate_gate(cfg).await;
        if !gate.ok {
            let clean = escape_applescript(&gate.error.unwrap_or_else(|| "出口 IP 校验未通过".into()));
            let _ = Command::new("/usr/bin/osascript")
                .args([
                    "-e",
                    &format!(
                        "display dialog \"⚠️ Claude Shield 熔断拦截\\n\\n{}\" buttons {{\"知道了\"}} default button 1 with icon stop with title \"Claude Shield\"",
                        clean
                    ),
                ])
                .status();
            std::process::exit(1);
        }
        if !gate.proxy_ip.is_empty() && gate.proxy_ip != "无法连通" {
            verified_ip = Some(gate.proxy_ip);
        }
    }

    let outcome = spawn_hardened_claude_desktop(cfg, verified_ip.as_deref());
    if !outcome.ok {
        let safe_msg = escape_applescript(&outcome.message);
        let icon = if outcome.message.contains("未检测到 Claude 桌面版") {
            "note"
        } else {
            "stop"
        };
        let _ = Command::new("/usr/bin/osascript")
            .args([
                "-e",
                &format!(
                    "display dialog \"⚠️ {}\" buttons {{\"知道了\"}} default button 1 with icon {} with title \"Claude Shield\"",
                    safe_msg, icon
                ),
            ])
            .status();
        if icon == "stop" {
            std::process::exit(1);
        }
    }
}
