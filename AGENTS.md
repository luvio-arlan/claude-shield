# Claude Shield — Repository Guide for AI Agents

## 1. Architecture Map

- `core/src/` — Modular Native Rust engine (`claude_shield_core` staticlib + `claude-shield-core` CLI), every module `<= 800` lines:
  - `lib.rs`, `main.rs`, `ffi.rs`, `config.rs`, `probe.rs`, `probe_pool.rs`, `latency.rs`, `proc_audit.rs`, `worker.rs`, `guard.rs`, `pf_guard.rs`, `purity.rs`, `purity_score.rs`, `patrol.rs`, `detect.rs`, `setup.rs`, `uninstall.rs`.
- `app/Sources/` — Modular macOS 13+ SwiftUI + AppKit single-process client (static-linking `libclaude_shield_core.a` via `ClaudeShieldCore.h`), every file `<= 800` lines:
  - `ClaudeShieldCore.h`, `Models.swift`, `CoreWorkerClient.swift`, `KernelWatchers.swift`, `RustCoreBridge.swift`, `Updater.swift`, `ShieldViewModel.swift`, `ShieldViewModelActions.swift`, `ThemeAndComponents.swift`, `PopoverView.swift`, `PopoverSections.swift`, `LaunchGuardView.swift`, `DashboardState.swift`, `DashboardView.swift`, `DashboardRadarSection.swift`, `DashboardPuritySection.swift`, `DashboardSettingsSection.swift`, `AppDelegate.swift`, `main.swift`.
- `scripts/check.sh` — **Single source of truth** quality gate (local + `.github/workflows/ci.yml`).
- `scripts/garden-guard.py` — L2/L3 deterministic guardrails: Swift/Rust invariants, Rust↔Swift DTO parity, version parity, framework sync, shell syntax, and zero-ratchet `<= 800`-line enforcement.
- `scripts/build-release.sh` — Builds release Rust binary, compiles & signs `Claude Shield.app`, and packages DMG/ZIP (version derived from `core/Cargo.toml`).

## 2. Verification Gate (Mandatory Before Finishing)

```bash
./scripts/check.sh
```

Never bypass or weaken `scripts/check.sh` or `scripts/garden-guard.py`. When fixing a recurring bug, encode a deterministic check in `scripts/garden-guard.py` instead of adding prose here.

## 3. UI Design Tokens & Lifecycle Contract

- **Aesthetic**: Ivory Porcelain & Brushed Titanium (`#F5F6F2` / `#ECEEE9` light, `#141619` / `#191C20` dark; Machined Space Titanium / Luminous Ivory Titanium CTAs; `#119665` / `#38D59A` Apple Jade Emerald; centralized in `app/Sources/ShieldPalette.swift`).
- **Console Grid**: Window `980 × 752` (min `820 × 580`), sidebar `232pt`, H1 (`y: 34..78`, height `44pt`), H2 (`y: 94`), unified `14pt` gutter / `18pt` rhythm, concentric radii (`16 / 13 / 12 / 10 / 9`).
- **Lifecycle**: `--radar-only` starts `.accessory` (`<5ms` cached render); opening Console switches to `.regular` (Dock minimize/reopen); closing returns to `.accessory`.

## 4. Local Install & Live Reload

```bash
(cd core && cargo build --release --quiet) \
  && swiftc -O -target "$(uname -m)-apple-macos13.0" \
  -import-objc-header app/Sources/ClaudeShieldCore.h \
  -framework Cocoa -framework SwiftUI -framework Network -framework QuartzCore \
  -framework Security -framework SystemConfiguration \
  app/Sources/*.swift core/target/release/libclaude_shield_core.a \
  -o "/Applications/Claude Shield.app/Contents/MacOS/ClaudeShield" \
  && codesign --force --deep --sign - "/Applications/Claude Shield.app" \
  && (pkill -x ClaudeShield || true) && sleep 0.4 \
  && open -a "/Applications/Claude Shield.app" --args --radar-only
```
