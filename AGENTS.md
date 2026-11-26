# Claude Shield — Repository Guide for AI Agents

## 1. Architecture Map

- `core/` — Native Rust core engine (`claude-shield-core`): proxy/TUN/Cloudflare dual-channel telemetry, multi-source IP purity audit, DNS/IPv6 leak detection, daily patrol, Seatbelt/OAuth/hide-original setup & uninstall.
- `app/ClaudeShieldApp.swift` — Native macOS 13+ SwiftUI + AppKit client: Menu Bar quick radar (`ShieldPopoverView`) + draggable/resizable Studio Console (`ShieldDashboardView` / `ShieldDashboardWindowController`) with CoreAnimation genie-suction transitions + pre-launch risk guard (`LaunchGuardView`).
- `scripts/check.sh` — **Single source of truth** quality gate (used locally and in `.github/workflows/ci.yml`).
- `scripts/garden-guard.py` — Deterministic L2 guardrails enforcing macOS window/popover invariants, framework sync, and file-size ratchets.
- `scripts/build-release.sh` — Builds release Rust binary, compiles & signs `Claude Shield.app`, and packages DMG/ZIP.

## 2. Verification Gate (Mandatory Before Finishing)

Always run the single repository quality gate after edits:

```bash
./scripts/check.sh
```

Never bypass or weaken checks in `scripts/check.sh` or `scripts/garden-guard.py`. When fixing a recurring UI or platform bug, encode a deterministic check in `scripts/garden-guard.py` instead of adding prose here.

## 3. UI Design Tokens & Alignment Contract

- **Aesthetic**: Warm Anthropic Editorial (low visual weight, eye-comfortable).
  - Light canvas `#F7F5F0`, sidebar `#EFECE6` (`232pt`), card `#FFFFFF`, border `black.opacity(0.058)`.
  - Dark canvas `#181717`, sidebar `#1E1D1C`, card `#252423`, border `white.opacity(0.075)`.
  - Brand Soft Terracotta (`#CC6945` / `#DB7A57`), Sage Emerald (`#1C8763` / `#42C794`).
- **Swiss Grid Reference Lines & Typography Floor (Console)**:
  - **H1 (`y: 34..78`, height `44pt`)**: Left brand badge (`Claude Shield`, `15.5pt`) and right section title (`20pt`) + action pills share the exact same vertical baseline.
  - **H2 (`y: 94`)**: Top of first sidebar nav item aligns flush with top of first main-canvas card.
  - **Default Window Frame**: `980 × 752` (minimum `820 × 580`), unified `14pt` grid gutter / `18pt` section rhythm and concentric radii (`16 / 13 / 12 / 10 / 9`), sized so Settings bottom actions and Radar quick actions both sit cleanly above the fold without dead bottom void.
  - **Typography Floor**: Never use sub-`10pt` micro-fonts in Console (`>= 10.5pt` for badges, `>= 11pt` for captions/metadata, `13.5pt` for sidebar nav & metric values, `16.5pt` for primary IPs). Enforced by `scripts/garden-guard.py`.
- **Menu Bar & Console Lifecycle (Mainstream macOS App Model)**:
  - Default startup (`--radar-only`) is Menu Bar resident (`.accessory`), rendering disk-cached state in `<5ms` before async probes.
  - Opening the app icon or Console switches to `.regular` so Claude Shield appears in the Dock; clicking the yellow `-` button performs native macOS Dock minimization, and clicking the Dock icon restores/focuses the Console.
  - Closing (`×` / `⌘W`) or clicking `收至状态栏` fades the Console out (GPU alpha, never synchronous `cacheDisplay` bitmap capture) and returns to `.accessory` Menu Bar resident mode.
  - **Zero-Flicker Popover Contract**: Use `NSPopover.behavior = .applicationDefined` with explicit global/local click + `Esc` monitors (ignoring `statusItem.button?.window?.frame`), call `NSApp.activate(ignoringOtherApps: true)` *before* `pop.show(...)`, and call `makeKey()` on the popover window. Clicking the status bar icon opens the popover immediately without closing the Console or thrashing Dock activation policy.

## 4. Local Install & Live Reload

```bash
swiftc -O -target "$(uname -m)-apple-macos13.0" \
  -framework Cocoa -framework SwiftUI -framework Network -framework QuartzCore \
  app/ClaudeShieldApp.swift -o "/Applications/Claude Shield.app/Contents/MacOS/ClaudeShield" \
  && codesign --force --deep --sign - "/Applications/Claude Shield.app" \
  && (pkill -x ClaudeShield || true) && sleep 0.4 \
  && open -a "/Applications/Claude Shield.app" --args --radar-only
```
