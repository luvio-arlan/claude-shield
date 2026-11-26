mod config;
mod detect;
mod guard;
mod patrol;
mod probe;
mod purity;
mod purity_score;
mod setup;
mod uninstall;

use chrono::Local;
use config::{tz_short_and_full, ShieldConfig};
use detect::detect_environment;
use guard::{audit_local_defenses, escape_applescript, hide_original_claude_app, kill_claude_desktop, LocalDefenseAudit};
use patrol::run_daily_patrol;
use probe::{full_telemetry_probe, quick_gate_probe, ApiLatencyMetrics, ChannelProbe};
use purity::run_purity_audit;
use serde::Serialize;
use setup::{run_setup, SetupOptions};
use std::env;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use uninstall::run_uninstall;

#[derive(Serialize)]
struct TelemetryJson {
    expected_ip: String,
    proxy_port: u16,
    target_tz: String,
    region_short: String,
    region_full: String,
    proxy: ChannelProbe,
    tun: ChannelProbe,
    claude_edge: ChannelProbe,
    api_latency: ApiLatencyMetrics,
    defenses: LocalDefenseAudit,
    checked_at: String,
}

#[derive(Serialize)]
struct GateJson {
    ok: bool,
    error: Option<String>,
    expected_ip: String,
    proxy_ip: String,
    tun_ip: String,
    claude_edge_ip: String,
    claude_loc: Option<String>,
    claude_colo: Option<String>,
    elapsed_ms: u64,
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();
    let subcmd = args.get(1).map(|s| s.as_str()).unwrap_or("help");
    let json_mode = args.iter().any(|a| a == "--json");
    let cfg = ShieldConfig::load();

    match subcmd {
        "telemetry" => cmd_telemetry(&cfg).await,
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
            println!("Usage: claude-shield-core <telemetry|gate|purity|patrol|hide-original|detect|setup|uninstall|exec-cli|launch-desktop> [--json]");
        }
    }
}

fn arg_value(args: &[String], flag: &str) -> Option<String> {
    args.windows(2).find(|w| w[0] == flag).map(|w| w[1].clone())
}

async fn cmd_telemetry(cfg: &ShieldConfig) {
    let (net, defenses) = tokio::join!(
        full_telemetry_probe(cfg),
        tokio::task::spawn_blocking({
            let c = cfg.clone();
            move || audit_local_defenses(&c)
        })
    );
    let defenses = defenses.unwrap_or_else(|_| audit_local_defenses(cfg));
    let (region_short, region_full) = tz_short_and_full(&cfg.target_tz);
    let checked_at = Local::now().format("%H:%M:%S").to_string();

    let payload = TelemetryJson {
        expected_ip: cfg.expected_ip.clone(),
        proxy_port: cfg.proxy_port,
        target_tz: cfg.target_tz.clone(),
        region_short,
        region_full,
        proxy: net.proxy,
        tun: net.tun,
        claude_edge: net.claude_edge,
        api_latency: net.api_latency,
        defenses,
        checked_at,
    };

    cfg.write_cache_json("last_telemetry.json", &payload);
    println!("{}", serde_json::to_string(&payload).unwrap_or_default());
}

async fn evaluate_gate(cfg: &ShieldConfig) -> GateJson {
    let t0 = std::time::Instant::now();
    let (proxy, tun, edge) = quick_gate_probe(cfg).await;
    let elapsed_ms = t0.elapsed().as_millis() as u64;

    let mut error = None;
    if !cfg.is_ip_configured() {
        error = Some("未配置白名单出口 IP (~/.config/claude-guard/expected_ip)。".to_string());
    } else if !proxy.reachable {
        error = Some(format!("本地代理 127.0.0.1:{} 无法连通 claude.ai。", cfg.proxy_port));
    } else if proxy.ip != cfg.expected_ip {
        error = Some(format!(
            "代理/Claude 边缘出口 IP 异常（当前: {}，期望: {}）。",
            proxy.ip, cfg.expected_ip
        ));
    } else if !tun.reachable {
        error = Some("默认路由（TUN）无法连通外网。".to_string());
    } else if tun.ip != cfg.expected_ip {
        error = Some(format!(
            "默认路由（TUN）出口 IP 异常（当前: {}，期望: {}）。",
            tun.ip, cfg.expected_ip
        ));
    } else if let Some(ref loc) = edge.loc {
        if matches!(loc.as_str(), "CN" | "HK" | "MO" | "RU" | "BY" | "KP" | "IR" | "SY" | "CU") {
            error = Some(format!("Claude Cloudflare 边缘识别到封禁地区 ({})，已强制熔断！", loc));
        }
    }

    GateJson {
        ok: error.is_none(),
        error,
        expected_ip: cfg.expected_ip.clone(),
        proxy_ip: proxy.ip,
        tun_ip: tun.ip,
        claude_edge_ip: edge.ip,
        claude_loc: edge.loc,
        claude_colo: edge.colo,
        elapsed_ms,
    }
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
    println!(
        "DNS 检测: {}  |  IPv6 泄露: {}  |  时区对齐: {}",
        if report.dns_leak { "\x1b[31m存在泄露!\x1b[0m" } else { "\x1b[32m安全\x1b[0m" },
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

fn apply_hardened_env(cmd: &mut Command, cfg: &ShieldConfig) {
    let http = cfg.proxy_http_url();
    let socks = cfg.proxy_socks_url();
    let guard_bin = cfg.home_dir.join(".local/lib/claude-guard-bin");
    let orig_path = env::var("PATH").unwrap_or_default();
    let new_path = format!("{}:{}", guard_bin.display(), orig_path);

    let existing_node_opts = env::var("NODE_OPTIONS").unwrap_or_default();
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
        .env("CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC", "1")
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

async fn cmd_exec_cli(cfg: &ShieldConfig, real_bin: &str, pass_args: &[String]) {
    let gate = evaluate_gate(cfg).await;
    if !gate.ok {
        eprintln!(
            "\x1b[1;31m[Claude Shield 熔断拦截]\x1b[0m {}",
            gate.error.unwrap_or_else(|| "IP 校验失败".into())
        );
        std::process::exit(1);
    }

    eprintln!(
        "\x1b[0;32m[Claude Shield v{}]\x1b[0m ✅ IP={} ({}) | TZ={} | Proxy=127.0.0.1:{} | Gate={}ms | IPv4-Only",
        env!("CARGO_PKG_VERSION"),
        gate.proxy_ip,
        gate.claude_colo.as_deref().unwrap_or("CF"),
        cfg.target_tz,
        cfg.proxy_port,
        gate.elapsed_ms
    );

    let mut cmd = Command::new(real_bin);
    cmd.args(pass_args);
    apply_hardened_env(&mut cmd, cfg);

    let err = cmd.exec();
    eprintln!("\x1b[1;31m[Claude Shield]\x1b[0m 无法执行 {}: {}", real_bin, err);
    std::process::exit(127);
}

async fn cmd_launch_desktop(cfg: &ShieldConfig, force: bool) {
    if cfg.hide_original && Path::new("/Applications/Claude.app").exists() {
        hide_original_claude_app(cfg);
    }

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

    let vault_app = cfg.home_dir.join(".local/apps/Claude.app");
    let app_path = if vault_app.exists() {
        vault_app
    } else if Path::new("/Applications/Claude.app").exists() {
        Path::new("/Applications/Claude.app").to_path_buf()
    } else {
        let _ = Command::new("/usr/bin/osascript")
            .args([
                "-e",
                "display dialog \"未检测到 Claude 桌面版（Claude.app），请先安装 Claude Desktop。\" buttons {\"知道了\"} default button 1 with icon note with title \"Claude Shield\"",
            ])
            .status();
        std::process::exit(0);
    };

    let defenses = audit_local_defenses(cfg);
    if defenses.desktop_pid.is_some() {
        if defenses.desktop_proxy_bound && defenses.desktop_quic_disabled && defenses.desktop_webrtc_locked {
            let _ = Command::new("/usr/bin/open")
                .args(["-a", app_path.to_str().unwrap_or("/Applications/Claude.app")])
                .status();
            return;
        } else {
            kill_claude_desktop();
            tokio::time::sleep(std::time::Duration::from_millis(350)).await;
        }
    }

    if let Some(ip) = verified_ip {
        let _ = std::fs::create_dir_all(&cfg.config_dir);
        let _ = std::fs::write(cfg.config_dir.join("last_launch_ip"), format!("{}\n", ip));
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
            tokio::time::sleep(std::time::Duration::from_millis(600)).await;
            if let Ok(Some(status)) = child.try_wait() {
                let _ = Command::new("/usr/bin/osascript")
                    .args([
                        "-e",
                        &format!(
                            "display dialog \"⚠️ Claude 桌面版异常退出 (code: {:?})\" buttons {{\"知道了\"}} default button 1 with icon stop with title \"Claude Shield\"",
                            status.code()
                        ),
                    ])
                    .status();
                std::process::exit(1);
            }
        }
        Err(e) => {
            let safe_err = escape_applescript(&e.to_string());
            let _ = Command::new("/usr/bin/osascript")
                .args([
                    "-e",
                    &format!(
                        "display dialog \"⚠️ Claude 桌面版启动失败: {}\" buttons {{\"知道了\"}} default button 1 with icon stop with title \"Claude Shield\"",
                        safe_err
                    ),
                ])
                .status();
            std::process::exit(1);
        }
    }
}
