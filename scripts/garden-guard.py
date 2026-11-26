#!/usr/bin/env python3
"""AI-Native Garden Guardrails for Claude Shield (L2/L3 Deterministic Checks).

Every recurring macOS/SwiftUI/Rust regression is encoded here as an error-driven
check so agents and contributors catch violations locally and in CI before merge.
"""

from __future__ import annotations

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
APP_SWIFT = ROOT / "app" / "ClaudeShieldApp.swift"
BUILD_SH = ROOT / "scripts" / "build-release.sh"
CHECK_SH = ROOT / "scripts" / "check.sh"
INSTALL_SH = ROOT / "scripts" / "install.sh"

# Ratchet caps for existing large files: new files must stay <= 800 lines;
# existing files cannot silently grow past their ratchet ceiling without refactoring.
LINE_RATCHET: dict[str, int] = {
    "app/ClaudeShieldApp.swift": 6350,
    "core/src/setup.rs": 900,
}
DEFAULT_MAX_LINES = 800


def fail(code: str, message: str, fix: str) -> str:
    return f"[{code}] {message}\n  -> Fix: {fix}"


def check_swift_guardrails(errors: list[str]) -> None:
    text = APP_SWIFT.read_text(encoding="utf-8")

    # 1. Never attach .onTapGesture to the root of ShieldDashboardView (breaks window drag)
    dash_match = re.search(
        r"private struct ShieldDashboardView: View \{.*?\nprivate final class ShieldDashboardWindow:",
        text,
        re.S,
    )
    if not dash_match:
        errors.append(
            fail(
                "SWIFT_DASHBOARD_MISSING",
                "Could not locate ShieldDashboardView block in app/ClaudeShieldApp.swift.",
                "Keep ShieldDashboardView and ShieldDashboardWindow cleanly separated.",
            )
        )
    elif ".onTapGesture" in dash_match.group(0):
        errors.append(
            fail(
                "NO_ROOT_TAP_GESTURE_ON_WINDOW",
                "Found .onTapGesture inside ShieldDashboardView.",
                "Remove .onTapGesture so AppKit's isMovableByWindowBackground = true can drag the window smoothly.",
            )
        )
    if dash_match:
        micro_fonts = re.findall(r"\.font\(\.system\(size:\s*([0-9]+(?:\.[0-9]+)?)", dash_match.group(0))
        too_small = [s for s in micro_fonts if float(s) < 10.0]
        if too_small:
            errors.append(
                fail(
                    "NO_MICRO_FONT_IN_CONSOLE",
                    f"Found sub-10pt micro-fonts in ShieldDashboardView: {sorted(set(too_small))}.",
                    "Keep all Console typography >= 10pt (>= 11pt for captions/metadata, >= 13.5pt for nav/values) for macOS readability.",
                )
            )

    # 2. Enforce Popover + Console mutual exclusion and anti-flicker transient guard
    required_patterns = [
        (
            "NSPopoverDelegate",
            "POPOVER_ANTI_FLICKER",
            "AppDelegate must conform to NSPopoverDelegate and track lastPopoverClosedAt to prevent transient click flicker.",
        ),
        (
            "lastPopoverClosedAt",
            "POPOVER_ANTI_FLICKER",
            "Track popoverDidClose timestamp and guard togglePopover within 0.16s to eliminate flicker.",
        ),
        (
            "sendAction(on: [.leftMouseDown])",
            "STATUS_BUTTON_RESPONSIVENESS",
            "Trigger statusItem.button on .leftMouseDown for zero-lag clicks and clean transient toggle.",
        ),
        (
            "setDockVisible(true)",
            "CONSOLE_DOCK_INTEGRATION",
            "Show Claude Shield in the Dock (.regular) when the Console opens so native Dock minimize/reopen works like mainstream macOS apps.",
        ),
        (
            "setDockVisible(false)",
            "MENUBAR_RESIDENT_ACCESSORY",
            "Return to .accessory when the Console hides to the menu bar so the app stays resident without lingering in the Dock.",
        ),
        (
            "sizingOptions = .preferredContentSize",
            "POPOVER_NATIVE_SIZING",
            "Use NSHostingController.sizingOptions = .preferredContentSize on macOS 13+ so the popover footer never clips.",
        ),
        (
            "pop.behavior = .applicationDefined",
            "POPOVER_NO_TRANSIENT_RACE",
            "Use .applicationDefined with explicit event monitors instead of .transient to prevent NSStatusBarButton click flicker and missed opens.",
        ),
    ]
    if "cacheDisplay(in:" in text:
        errors.append(
            fail(
                "NO_SYNC_BITMAP_CAPTURE",
                "Found synchronous NSView.cacheDisplay(in:to:) in app/ClaudeShieldApp.swift.",
                "Animate the GPU-composited NSWindow directly instead of capturing Retina bitmaps on the main thread.",
            )
        )
    for needle, code, fix in required_patterns:
        if needle not in text:
            errors.append(fail(code, f"Missing required macOS invariant `{needle}` in app/ClaudeShieldApp.swift.", fix))


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


def check_line_ratchet_and_markers(errors: list[str]) -> None:
    markers = "|".join(m.upper() for m in ("todo", "fixme", "hack", "xxx"))
    todo_re = re.compile(rf"\b({markers})\b")
    scan_paths = [
        *sorted((ROOT / "app").glob("*.swift")),
        *sorted((ROOT / "core" / "src").glob("*.rs")),
    ]
    for path in scan_paths:
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
    check_framework_sync(errors)
    check_line_ratchet_and_markers(errors)

    if errors:
        print("❌ Garden Guardrails failed:\n", file=sys.stderr)
        for err in errors:
            print(err, file=sys.stderr)
        return 1

    print("✅ Garden Guardrails passed (Swift invariants, framework sync, line ratchet, clean markers).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
