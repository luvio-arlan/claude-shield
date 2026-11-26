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
        for pat in ("fatalError(", "try!", " as! "):
            if pat in text:
                errors.append(
                    fail(
                        "NO_SWIFT_FORCE_UNWRAP_DANGEROUS",
                        f"Found unsafe `{pat.strip()}` in app/Sources/{p.name}.",
                        "Handle errors explicitly or return a safe fallback instead of crashing the resident menu bar app.",
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


def check_rust_guardrails(errors: list[str]) -> None:
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
