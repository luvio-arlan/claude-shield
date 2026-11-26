# Claude Shield — Repository Guide for AI Agents

## 1. Architecture Map

- `core/src/` — Modular Native Rust engine (`claude-shield-core`), every module `<= 800` lines:
  - `main.rs`, `config.rs`, `probe.rs`, `guard.rs`, `purity.rs`, `purity_score.rs`, `patrol.rs`, `detect.rs`, `setup.rs`, `uninstall.rs`.
- `app/Sources/` — Modular macOS 13+ SwiftUI + AppKit client, every file `<= 800` lines:
  - `Models.swift`, `RustCoreBridge.swift`, `Updater.swift`, `ShieldViewModel.swift`, `ThemeAndComponents.swift`, `PopoverView.swift`, `PopoverSections.swift`, `LaunchGuardView.swift`, `DashboardState.swift`, `DashboardView.swift`, `DashboardRadarSection.swift`, `DashboardPuritySection.swift`, `DashboardSettingsSection.swift`, `AppDelegate.swift`, `main.swift`.
- `scripts/check.sh` — **Single source of truth** quality gate (local + `.github/workflows/ci.yml`).
- `scripts/garden-guard.py` — L2/L3 deterministic guardrails: Swift/Rust invariants, Rust↔Swift DTO parity, version parity, framework sync, shell syntax, and zero-ratchet `<= 800`-line enforcement.
- `scripts/build-release.sh` — Builds release Rust binary, compiles & signs `Claude Shield.app`, and packages DMG/ZIP (version derived from `core/Cargo.toml`).

## 2. Verification Gate (Mandatory Before Finishing)

```bash
./scripts/check.sh
```

Never bypass or weaken `scripts/check.sh` or `scripts/garden-guard.py`. When fixing a recurring bug, encode a deterministic check in `scripts/garden-guard.py` instead of adding prose here.

## 3. UI Design Tokens & Lifecycle Contract

- **Aesthetic**: Warm Anthropic Editorial (`#F7F5F0` / `#EFECE6` light, `#181717` / `#1E1D1C` dark; `#CC6945` / `#DB7A57` Soft Terracotta, `#1C8763` / `#42C794` Sage Emerald).
- **Console Grid**: Window `980 × 752` (min `820 × 580`), sidebar `232pt`, H1 (`y: 34..78`, height `44pt`), H2 (`y: 94`), unified `14pt` gutter / `18pt` rhythm, concentric radii (`16 / 13 / 12 / 10 / 9`).
- **Lifecycle**: `--radar-only` starts `.accessory` (`<5ms` cached render); opening Console switches to `.regular` (Dock minimize/reopen); closing returns to `.accessory`.

## 4. Local Install & Live Reload

```bash
swiftc -O -target "$(uname -m)-apple-macos13.0" \
  -framework Cocoa -framework SwiftUI -framework Network -framework QuartzCore \
  app/Sources/*.swift -o "/Applications/Claude Shield.app/Contents/MacOS/ClaudeShield" \
  && codesign --force --deep --sign - "/Applications/Claude Shield.app" \
  && (pkill -x ClaudeShield || true) && sleep 0.4 \
  && open -a "/Applications/Claude Shield.app" --args --radar-only
```
