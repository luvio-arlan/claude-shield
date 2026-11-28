#!/usr/bin/env python3
"""AI-Native Garden Guardrails for Claude Shield (L2/L3 Deterministic Checks).

Every recurring macOS/SwiftUI/Rust regression and cross-language contract is encoded
here as an error-driven check so agents catch violations locally and in CI.
"""

from __future__ import annotations

import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP_SOURCES_DIR = ROOT / "app" / "Sources"
MODELS_SWIFT = APP_SOURCES_DIR / "Models.swift"
UPDATER_SWIFT = APP_SOURCES_DIR / "Updater.swift"
CARGO_TOML = ROOT / "core" / "Cargo.toml"
BUILD_SH = ROOT / "scripts" / "build-release.sh"
CHECK_SH = ROOT / "scripts" / "check.sh"
INSTALL_SH = ROOT / "scripts" / "install.sh"

# Zero ratchet debt: every source file in app/Sources/*.swift and core/src/*.rs must stay <= 800 lines.
LINE_RATCHET: dict[str, int] = {}
DEFAULT_MAX_LINES = 800


def fail(code: str, message: str, fix: str) -> str:
    return f"[{code}] {message}\n  -> Fix: {fix}"


def swift_files() -> list[pathlib.Path]:
    return sorted(APP_SOURCES_DIR.glob("*.swift"))


def rust_files() -> list[pathlib.Path]:
    return sorted((ROOT / "core" / "src").glob("*.rs"))


def check_swift_guardrails(errors: list[str]) -> None:
    files = swift_files()
    if not files:
        errors.append(fail("SWIFT_SOURCES_MISSING", "No Swift files found in app/Sources/.", "Keep modular Swift sources in app/Sources/*.swift."))
        return

    all_swift = "\n".join(p.read_text(encoding="utf-8") for p in files)

    dashboard_texts = [
        (p.name, p.read_text(encoding="utf-8"))
        for p in files
        if p.name.startswith("Dashboard") and p.name != "DashboardState.swift"
    ]
    for name, body in dashboard_texts:
        if ".onTapGesture" in body:
            errors.append(
                fail(
                    "NO_ROOT_TAP_GESTURE_ON_WINDOW",
                    f"Found .onTapGesture inside {name}.",
                    "Remove .onTapGesture so AppKit's isMovableByWindowBackground = true can drag the window smoothly.",
                )
            )
        micro_fonts = re.findall(r"\.font\(\.system\(size:\s*([0-9]+(?:\.[0-9]+)?)", body)
        too_small = [s for s in micro_fonts if float(s) < 10.0]
        if too_small:
            errors.append(
                fail(
                    "NO_MICRO_FONT_IN_CONSOLE",
                    f"Found sub-10pt micro-fonts in {name}: {sorted(set(too_small))}.",
                    "Keep all Console typography >= 10pt (>= 11pt for captions/metadata, >= 13.5pt for nav/values).",
                )
            )

    if "cacheDisplay(in:" in all_swift:
        errors.append(
            fail(
                "NO_SYNC_BITMAP_CAPTURE",
                "Found synchronous NSView.cacheDisplay(in:to:) in app/Sources/.",
                "Animate the GPU-composited NSWindow directly instead of capturing Retina bitmaps on the main thread.",
            )
        )

    for p in files:
        text = p.read_text(encoding="utf-8")
        if ".repeatForever(" in text and ("disablesAnimations = true" not in text or ".onDisappear" not in text):
            errors.append(
                fail(
                    "NO_UNGATED_REPEAT_FOREVER",
                    f"Found ungated `.repeatForever(` animation in app/Sources/{p.name}.",
                    "Gate repeating SwiftUI animations on view visibility and cancel via `disablesAnimations = true` in `.onDisappear` so hidden windows consume 0% CPU.",
                )
            )
        if re.search(r"withAnimation\s*\([^)]*\.repeatForever\(", text):
            errors.append(
                fail(
                    "NO_EXPLICIT_WITH_ANIMATION_REPEAT_FOREVER",
                    f"Found `withAnimation(...repeatForever(` in app/Sources/{p.name}.",
                    "Never pass `.repeatForever` to explicit `withAnimation` (it leaks infinite repeating transactions into sibling layout/position updates); use `PulsingOpacityView` or value-scoped `.animation(..., value:)` on an isolated leaf view.",
                )
            )
        for pat in ("fatalError(", "try!", " as! "):
            if pat in text:
                errors.append(
                    fail(
                        "NO_SWIFT_FORCE_UNWRAP_DANGEROUS",
                        f"Found unsafe `{pat.strip()}` in app/Sources/{p.name}.",
                        "Handle errors explicitly or return a safe fallback instead of crashing the resident menu bar app.",
                    )
                )

    app_delegate_path = APP_SOURCES_DIR / "AppDelegate.swift"
    if app_delegate_path.exists():
        delegate_text = app_delegate_path.read_text(encoding="utf-8")
        if "hostingController = nil" not in delegate_text:
            errors.append(
                fail(
                    "POPOVER_TEARDOWN_ON_CLOSE",
                    "AppDelegate.swift does not release `hostingController = nil` when the popover closes.",
                    "Tear down the hidden SwiftUI NSHostingController in popoverDidClose to eliminate idle CPU and memory footprint.",
                )
            )
        launch_block = re.search(
            r"func applicationDidFinishLaunching\(.*?\n    \}",
            delegate_text,
            re.S,
        )
        if launch_block and "ensurePopover()" in launch_block.group(0):
            errors.append(
                fail(
                    "NO_PREWARM_HIDDEN_POPOVER",
                    "Found `ensurePopover()` pre-warming inside applicationDidFinishLaunching.",
                    "Lazily construct NSPopover on user click so `--radar-only` launches with zero hidden SwiftUI view trees.",
                )
            )

    if UPDATER_SWIFT.exists():
        updater_text = UPDATER_SWIFT.read_text(encoding="utf-8")
        if re.search(r"try\?\s*await\s+fetchDataWithFallback\(\s*url:\s*sumURL", updater_text):
            errors.append(
                fail(
                    "UPDATER_FAIL_CLOSED_CHECKSUM",
                    "Found `try? await fetchDataWithFallback(url: sumURL ...)` in app/Sources/Updater.swift.",
                    "Fail closed (`try await` + throw UpdateError.checksumVerificationFailed) when SHA256SUMS.txt cannot be verified.",
                )
            )
        if re.search(r"\bif\s+let\s+sumURL\s*=\s*info\.checksumURL\b", updater_text) or "missingChecksumAsset" not in updater_text:
            errors.append(
                fail(
                    "UPDATER_REQUIRE_CHECKSUM",
                    "app/Sources/Updater.swift allows skipping SHA-256 verification when checksumURL is absent.",
                    "Use `guard let sumURL = info.checksumURL else { throw UpdateError.missingChecksumAsset }` so updates always fail closed.",
                )
            )

    vm_path = APP_SOURCES_DIR / "ShieldViewModel.swift"
    if vm_path.exists():
        vm_text = vm_path.read_text(encoding="utf-8")
        screen_sleep_match = re.search(r"screensDidSleepNotification.*?workspaceObservers\s*=", vm_text, re.S)
        if screen_sleep_match and "isSystemAsleep = true" in screen_sleep_match.group(0):
            errors.append(
                fail(
                    "NO_SCREEN_SLEEP_BLINDING",
                    "screensDidSleepNotification sets `isSystemAsleep = true` in ShieldViewModel.swift.",
                    "Track screen lock/dim via `isScreenOff` and reserve `isSystemAsleep` strictly for `willSleepNotification` so background Claude sessions stay guarded while the display is off.",
                )
            )
        if "pathDebounceTask?.cancel()" not in vm_text:
            errors.append(
                fail(
                    "DEBOUNCED_PATH_MONITOR_REFRESH",
                    "NWPathMonitor updates in ShieldViewModel.swift are not debounced via a cancellable `pathDebounceTask`.",
                    "Cancel and reschedule `pathDebounceTask` on pathUpdateHandler changes so Wi-Fi/TUN flaps never trigger redundant pool resets.",
                )
            )

    actions_path = APP_SOURCES_DIR / "ShieldViewModelActions.swift"
    if actions_path.exists():
        actions_text = actions_path.read_text(encoding="utf-8")
        if "_ = RustCoreBridge.killPIDs(" in actions_text:
            errors.append(
                fail(
                    "NO_BLIND_CLI_KILL_NOTIFICATION",
                    "app/Sources/ShieldViewModelActions.swift discards `RustCoreBridge.killPIDs(...)` return count before notifying.",
                    "Confirm the killed count (`killed > 0`) after re-verifying unprotected PIDs so already-exited transient processes never trigger false breach alerts.",
                )
            )

    for ui_name in ("DashboardPuritySection.swift", "PopoverSections.swift"):
        ui_path = APP_SOURCES_DIR / ui_name
        if ui_path.exists():
            ui_text = ui_path.read_text(encoding="utf-8")
            if re.search(r"dns_leak\s*\?[^:\n]+:\s*\"零泄露\"", ui_text) or "p.dnsStatus" not in ui_text:
                errors.append(
                    fail(
                        "NO_BINARY_DNS_LEAK_UI",
                        f"app/Sources/{ui_name} uses a binary dns_leak check instead of 3-state `p.dnsStatus`.",
                        "Render DNS status via `p.dnsStatus` (`.clean` / `.unverified` / `.leaked`) so an incomplete EDNS probe never shows green \"零泄露\".",
                    )
                )
            if ui_name == "PopoverSections.swift" and "p.factors.prefix(" in ui_text:
                errors.append(
                    fail(
                        "NO_TRUNCATED_PURITY_FACTORS",
                        "app/Sources/PopoverSections.swift hard-truncates audit factors via `p.factors.prefix(...)`.",
                        "Render all `p.factors` inside a bounded `ScrollView` so warnings at index 6+ (e.g. timezone/WARP) are never silently hidden.",
                    )
                )

    required_patterns = [
        ("NSPopoverDelegate", "POPOVER_ANTI_FLICKER", "AppDelegate must conform to NSPopoverDelegate and track lastPopoverClosedAt."),
        ("lastPopoverClosedAt", "POPOVER_ANTI_FLICKER", "Track popoverDidClose timestamp and guard togglePopover."),
        ("sendAction(on: [.leftMouseDown])", "STATUS_BUTTON_RESPONSIVENESS", "Trigger statusItem.button on .leftMouseDown for zero-lag clicks."),
        ("setDockVisible(true)", "CONSOLE_DOCK_INTEGRATION", "Show Claude Shield in the Dock (.regular) when the Console opens."),
        ("setDockVisible(false)", "MENUBAR_RESIDENT_ACCESSORY", "Return to .accessory when the Console hides to the menu bar."),
        ("sizingOptions = .preferredContentSize", "POPOVER_NATIVE_SIZING", "Use NSHostingController.sizingOptions = .preferredContentSize."),
        ("pop.behavior = .applicationDefined", "POPOVER_NO_TRANSIENT_RACE", "Use .applicationDefined with explicit event monitors instead of .transient."),
    ]
    for needle, code, fix in required_patterns:
        if needle not in all_swift:
            errors.append(fail(code, f"Missing required macOS invariant `{needle}` in app/Sources/.", fix))


    if not (APP_SOURCES_DIR / "ClaudeShieldCore.h").exists():
        errors.append(
            fail(
                "SINGLE_PROCESS_FFI_HEADER",
                "Missing app/Sources/ClaudeShieldCore.h C-ABI bridging header.",
                "Keep ClaudeShieldCore.h so ClaudeShield static-links libclaude_shield_core.a in a single process.",
            )
        )
    for sh_path in (BUILD_SH, INSTALL_SH):
        if "libclaude_shield_core.a" not in sh_path.read_text(encoding="utf-8"):
            errors.append(
                fail(
                    "SINGLE_PROCESS_FFI_LINK",
                    f"{sh_path.relative_to(ROOT)} does not static-link libclaude_shield_core.a.",
                    "Link core/target/release/libclaude_shield_core.a into ClaudeShield to maintain single-process architecture.",
                )
            )


def check_rust_guardrails(errors: list[str]) -> None:
    main_rs = ROOT / "core" / "src" / "main.rs"
    if main_rs.exists() and 'flavor = "current_thread"' not in main_rs.read_text(encoding="utf-8"):
        errors.append(
            fail(
                "SINGLE_THREAD_TOKIO_CORE",
                "core/src/main.rs does not configure single-threaded Tokio (`flavor = \"current_thread\"`).",
                "Use `#[tokio::main(flavor = \"current_thread\")]` to avoid spawning idle multi-thread worker pools in a lightweight daemon.",
            )
        )
    probe_rs = ROOT / "core" / "src" / "probe.rs"
    if probe_rs.exists():
        probe_text = probe_rs.read_text(encoding="utf-8")
        if "http2_keep_alive_interval" not in probe_text or "http2_keep_alive_while_idle(true)" not in probe_text:
            errors.append(
                fail(
                    "HTTP2_KEEPALIVE_REQUIRED",
                    "core/src/probe.rs does not enable HTTP/2 keep-alive PING frames while idle.",
                    "Configure `.http2_keep_alive_interval(...)` and `.http2_keep_alive_while_idle(true)` so pooled sockets never silently drop and spike latency.",
                )
            )
    probe_pool_rs = ROOT / "core" / "src" / "probe_pool.rs"
    if probe_pool_rs.exists():
        pool_text = probe_pool_rs.read_text(encoding="utf-8")
        cycle_parts = pool_text.split("fn run_telemetry_cycle", 1)
        cycle_body = cycle_parts[1] if len(cycle_parts) == 2 else pool_text
        gate_idx = cycle_body.find("is_safe_to_probe_anthropic_api(")
        warmup_idx = cycle_body.find("warmup_anthropic_api(")
        if gate_idx == -1 or (warmup_idx != -1 and warmup_idx < gate_idx):
            errors.append(
                fail(
                    "NO_PRE_GATE_API_WARMUP",
                    "core/src/probe_pool.rs calls `warmup_anthropic_api` before verifying `is_safe_to_probe_anthropic_api` in `run_telemetry_cycle`.",
                    "Never connect to api.anthropic.com until Phase 1 verifies whitelisted Proxy + TUN exit IP and compliant region.",
                )
            )
    purity_rs = ROOT / "core" / "src" / "purity.rs"
    if purity_rs.exists():
        purity_text = purity_rs.read_text(encoding="utf-8")
        if re.search(r"http://\{[a-zA-Z0-9_]+:016x\}\.edns\.ip-api\.com", purity_text):
            errors.append(
                fail(
                    "EDNS_NONCE_MUST_BE_32_CHARS",
                    "core/src/purity.rs formats a 16-char `:016x` subdomain for `edns.ip-api.com` (which always returns HTTP 404).",
                    "Generate a 32-char lowercase hex nonce (`http://{hi:016x}{lo:016x}.edns.ip-api.com/json`) so EDNS resolves in 1 hop.",
                )
            )
    proc_audit_rs = ROOT / "core" / "src" / "proc_audit.rs"
    if proc_audit_rs.exists():
        proc_text = proc_audit_rs.read_text(encoding="utf-8")
        if "thread_local!" in proc_text and "PROCARGS_SCRATCH" in proc_text:
            errors.append(
                fail(
                    "NO_PER_THREAD_PROCARGS_SCRATCH",
                    "core/src/proc_audit.rs stores large PROCARGS_SCRATCH buffers in `thread_local!`.",
                    "Share a single `OnceLock<Mutex<Vec<u8>>>` scratch buffer so arbitrary Swift GCD threads do not pin N×512KB dirty pages.",
                )
            )
    guard_rs = ROOT / "core" / "src" / "guard.rs"
    if guard_rs.exists():
        guard_text = guard_rs.read_text(encoding="utf-8")
        if 'args_str.contains("@anthropic-ai/claude-code")' in guard_text:
            errors.append(
                fail(
                    "NO_SUBSTRING_NODE_CLI_MATCH",
                    "core/src/guard.rs matches Node/Bun Claude Code CLI via raw substring scan across joined arguments.",
                    "Inspect the parsed JS runtime entrypoint script path so npm/pnpm/MCP processes referencing claude-code are never falsely killed.",
                )
            )
        if "is_embedded_multicall_applet_argv0(" not in guard_text:
            errors.append(
                fail(
                    "NO_MULTICALL_APPLET_CLI_FALSE_POSITIVE",
                    "core/src/guard.rs does not filter Claude Code embedded multicall ARGV0 utility applets (ugrep/bfs/rg).",
                    "Check `is_embedded_multicall_applet_argv0(args)` inside `is_genuine_claude_cli_args` so sandboxed grep/find/rg invocations of the claude binary are never falsely killed.",
                )
            )
    for path in rust_files():
        rel = path.relative_to(ROOT).as_posix()
        text = path.read_text(encoding="utf-8")
        prod_text = text.split("#[cfg(test)]", 1)[0]
        for idx, line in enumerate(prod_text.splitlines(), start=1):
            if ".unwrap()" in line or ".expect(" in line:
                errors.append(
                    fail(
                        "NO_RUST_UNWRAP_IN_PROD",
                        f"Found `.unwrap()` / `.expect(` in production Rust code at {rel}:{idx}.",
                        "Use `unwrap_or` / `unwrap_or_else` / `?` / explicit error handling outside #[cfg(test)].",
                    )
                )


def parse_rust_struct_fields(rust_src: str, struct_name: str) -> list[str]:
    m = re.search(rf"(?:pub\s+)?struct\s+{re.escape(struct_name)}\b[^{{]*\{{(.*?)\n\}}", rust_src, re.S)
    if not m:
        return []
    return re.findall(r"^\s*(?:pub(?:\([^)]*\))?\s+)?([a-zA-Z_][a-zA-Z0-9_]*)\s*:", m.group(1), re.M)


def parse_swift_struct_fields(swift_src: str, struct_name: str) -> list[str]:
    m = re.search(rf"(?:public\s+|private\s+|internal\s+)?struct\s+{re.escape(struct_name)}\b[^{{]*\{{(.*?)\n\}}", swift_src, re.S)
    if not m:
        return []
    return re.findall(r"^\s*(?:let|var)\s+([a-zA-Z_][a-zA-Z0-9_]*)\s*:[^\n{=]+$", m.group(1), re.M)


def check_rust_swift_dto_parity(errors: list[str]) -> None:
    if not MODELS_SWIFT.exists():
        errors.append(fail("SWIFT_MODELS_MISSING", "Missing app/Sources/Models.swift.", "Define all Swift DTO models in app/Sources/Models.swift."))
        return
    swift_models = MODELS_SWIFT.read_text(encoding="utf-8")
    all_rust = "\n".join(p.read_text(encoding="utf-8") for p in rust_files())

    dto_pairs = [
        ("ChannelProbe", "ChannelProbeModel"),
        ("ApiLatencyMetrics", "ApiLatencyModel"),
        ("LocalDefenseAudit", "LocalDefenseModel"),
        ("LaunchDesktopOutcome", "LaunchDesktopOutcomeModel"),
        ("KillOutcome", "KillOutcomeModel"),
        ("TelemetryJson", "TelemetrySnapshot"),
        ("RiskFactor", "RiskFactorModel"),
        ("DnsProbeInfo", "DnsProbeModel"),
        ("PurityReport", "PurityReport"),
        ("PatrolReport", "PatrolReportModel"),
        ("DetectResult", "DetectResultModel"),
        ("SetupReport", "SetupReportModel"),
        ("UninstallReport", "UninstallReportModel"),
        ("GateJson", "GateResultModel"),
    ]
    for rust_name, swift_name in dto_pairs:
        r_fields = set(parse_rust_struct_fields(all_rust, rust_name))
        s_fields = set(parse_swift_struct_fields(swift_models, swift_name))
        if not r_fields or not s_fields:
            errors.append(
                fail(
                    "RUST_SWIFT_DTO_PARITY",
                    f"Could not locate DTO pair Rust `{rust_name}` ({len(r_fields)} fields) / Swift `{swift_name}` ({len(s_fields)} fields).",
                    "Keep Rust Serialize structs and Swift Codable structs cleanly declared for contract verification.",
                )
            )
            continue
        missing_in_swift = sorted(r_fields - s_fields)
        extra_in_swift = sorted(s_fields - r_fields)
        if missing_in_swift or extra_in_swift:
            errors.append(
                fail(
                    "RUST_SWIFT_DTO_PARITY",
                    f"DTO drift between Rust `{rust_name}` and Swift `{swift_name}`: missing_in_swift={missing_in_swift}, extra_in_swift={extra_in_swift}.",
                    "Update both Rust struct fields and app/Sources/Models.swift together to maintain 1:1 JSON contract parity.",
                )
            )


def check_version_parity(errors: list[str]) -> None:
    cargo_match = re.search(r'^version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"', CARGO_TOML.read_text(encoding="utf-8"), re.M)
    if not cargo_match:
        errors.append(fail("VERSION_PARITY", "Could not parse version from core/Cargo.toml.", "Set `version = \"x.y.z\"` in core/Cargo.toml."))
        return
    ver = cargo_match.group(1)
    major_minor = ".".join(ver.split(".")[:2])

    if UPDATER_SWIFT.exists():
        u_text = UPDATER_SWIFT.read_text(encoding="utf-8")
        if f'return "{ver}"' not in u_text:
            errors.append(
                fail(
                    "VERSION_PARITY",
                    f"Fallback version in app/Sources/Updater.swift does not match core/Cargo.toml (`{ver}`).",
                    f'Update `AppReleaseConfig.currentVersion` fallback in app/Sources/Updater.swift to `return "{ver}"`.',
                )
            )

    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    if f"Claude-Shield-v{ver}-macOS-arm64.dmg" not in readme:
        errors.append(
            fail(
                "VERSION_PARITY",
                f"README.md download filename does not reference `Claude-Shield-v{ver}-macOS-arm64.dmg`.",
                f"Update README.md release references to v{ver} / v{major_minor}.",
            )
        )

    skill = (ROOT / "SKILL.md").read_text(encoding="utf-8")
    if f"v{major_minor}" not in skill:
        errors.append(
            fail(
                "VERSION_PARITY",
                f"SKILL.md does not reference `v{major_minor}`.",
                f"Update SKILL.md version header/description to v{major_minor}.",
            )
        )


def check_framework_sync(errors: list[str]) -> None:
    fw_re = re.compile(r"-framework\s+([A-Za-z0-9_]+)")
    build_fws = set(fw_re.findall(BUILD_SH.read_text(encoding="utf-8")))
    check_fws = set(fw_re.findall(CHECK_SH.read_text(encoding="utf-8")))
    install_fws = set(fw_re.findall(INSTALL_SH.read_text(encoding="utf-8")))
    if not (build_fws == check_fws == install_fws):
        errors.append(
            fail(
                "FRAMEWORK_SYNC",
                f"Framework mismatch: build-release.sh={sorted(build_fws)} vs check.sh={sorted(check_fws)} vs install.sh={sorted(install_fws)}.",
                "Keep identical -framework flags in scripts/build-release.sh, scripts/check.sh, and scripts/install.sh.",
            )
        )


def check_shell_and_single_rule_entry(errors: list[str]) -> None:
    for sh in sorted((ROOT / "scripts").glob("*.sh")):
        proc = subprocess.run(["bash", "-n", str(sh)], capture_output=True, text=True)
        if proc.returncode != 0:
            errors.append(
                fail(
                    "SHELL_SYNTAX",
                    f"Syntax error in {sh.relative_to(ROOT)}: {proc.stderr.strip()}",
                    "Fix bash syntax errors before committing.",
                )
            )

    if not (ROOT / "AGENTS.md").exists():
        errors.append(fail("SINGLE_AI_RULE_ENTRY", "Missing AGENTS.md at repo root.", "Maintain AGENTS.md as the single AI rule entry."))
    for forbidden in (ROOT / "CLAUDE.md", ROOT / ".cursorrules", ROOT / ".cursor" / "rules"):
        if forbidden.exists():
            errors.append(
                fail(
                    "SINGLE_AI_RULE_ENTRY",
                    f"Found duplicate rule file/dir `{forbidden.relative_to(ROOT)}`.",
                    "Keep AGENTS.md as the sole AI rule entry and remove duplicate rule files.",
                )
            )


def check_line_ratchet_and_markers(errors: list[str]) -> None:
    markers = "|".join(m.upper() for m in ("todo", "fixme", "hack", "xxx"))
    todo_re = re.compile(rf"\b({markers})\b")
    for path in [*swift_files(), *rust_files()]:
        rel = path.relative_to(ROOT).as_posix()
        lines = path.read_text(encoding="utf-8").splitlines()
        limit = LINE_RATCHET.get(rel, DEFAULT_MAX_LINES)
        if len(lines) > limit:
            errors.append(
                fail(
                    "FILE_LINE_RATCHET",
                    f"{rel} has {len(lines)} lines (ceiling: {limit}).",
                    "Split cohesive modules into dedicated files instead of growing monolithic files.",
                )
            )
        for idx, line in enumerate(lines, start=1):
            if todo_re.search(line):
                errors.append(
                    fail(
                        "NO_STALE_MARKER",
                        f"Found stale marker at {rel}:{idx}: {line.strip()}",
                        "Resolve the item or open a tracked issue instead of leaving stale markers in source.",
                    )
                )


def main() -> int:
    errors: list[str] = []
    check_swift_guardrails(errors)
    check_rust_guardrails(errors)
    check_rust_swift_dto_parity(errors)
    check_version_parity(errors)
    check_framework_sync(errors)
    check_shell_and_single_rule_entry(errors)
    check_line_ratchet_and_markers(errors)

    if errors:
        print("❌ Garden Guardrails failed:\n", file=sys.stderr)
        for err in errors:
            print(err, file=sys.stderr)
        return 1

    print("✅ Garden Guardrails passed (Swift/Rust invariants, DTO parity, version parity, framework sync, shell syntax, <=800L, clean markers).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
