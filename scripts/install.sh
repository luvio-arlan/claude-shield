#!/usr/bin/env bash
# Claude Shield — Unified macOS Protection Suite Installer (Rust Core + SwiftUI Radar)
# Delegates all wrapper/settings/LaunchAgent setup to `claude-shield-core setup` (Single Source of Truth).
set -euo pipefail

EXPECTED_IP=""
PROXY_PORT="7897"
TARGET_TZ="America/Los_Angeles"
ENABLE_AUTOSTART="1"
ENABLE_DAILY_PATROL="1"
HIDE_ORIGINAL="1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VERSION="$(awk -F'"' '/^version = / { print $2; exit }' "${REPO_ROOT}/core/Cargo.toml")"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ip) EXPECTED_IP="$2"; shift 2 ;;
    --port) PROXY_PORT="$2"; shift 2 ;;
    --tz) TARGET_TZ="$2"; shift 2 ;;
    --no-autostart) ENABLE_AUTOSTART="0"; shift ;;
    --no-patrol) ENABLE_DAILY_PATROL="0"; shift ;;
    --no-hide) HIDE_ORIGINAL="0"; shift ;;
    -h|--help)
      echo "Usage: $0 --ip <DEDICATED_IP> [--port 7897] [--tz America/Los_Angeles] [--no-autostart] [--no-patrol] [--no-hide]"
      exit 0
      ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "${EXPECTED_IP}" ]]; then
  if [[ -f "$HOME/.config/claude-guard/expected_ip" ]]; then
    EXPECTED_IP="$(tr -d '[:space:]' < "$HOME/.config/claude-guard/expected_ip")"
  else
    echo "Error: --ip <DEDICATED_IP> is required." >&2
    exit 1
  fi
fi

mkdir -p "$HOME/.local/bin"

# 1. Build Native Rust Core Engine (claude-shield-core)
CORE_BIN="$HOME/.local/bin/claude-shield-core"
if command -v cargo >/dev/null 2>&1 && [[ -f "${REPO_ROOT}/core/Cargo.toml" ]]; then
  echo "🦀 Building native Rust core engine v${VERSION} (claude-shield-core)..."
  (cd "${REPO_ROOT}/core" && MACOSX_DEPLOYMENT_TARGET=13.0 cargo build --release --quiet)
  cp "${REPO_ROOT}/core/target/release/claude-shield-core" "${CORE_BIN}"
  chmod +x "${CORE_BIN}"
  echo "✅ Built native Rust core: ${CORE_BIN}"
elif [[ ! -x "${CORE_BIN}" ]]; then
  echo "❌ Neither cargo nor an existing ${CORE_BIN} was found. Install Rust via 'brew install rust' or use the .dmg installer." >&2
  exit 1
fi

build_icns() {
  local src_png="$1" out_icns="$2"
  local tmp_dir iconset
  tmp_dir="$(mktemp -d)"
  iconset="${tmp_dir}/AppIcon.iconset"
  mkdir -p "${iconset}"
  for sz in 16 32 128 256 512; do
    sips -z "${sz}" "${sz}" "${src_png}" --out "${iconset}/icon_${sz}x${sz}.png" >/dev/null 2>&1
    local sz2=$((sz * 2))
    sips -z "${sz2}" "${sz2}" "${src_png}" --out "${iconset}/icon_${sz}x${sz}@2x.png" >/dev/null 2>&1
  done
  iconutil -c icns "${iconset}" -o "${out_icns}"
  rm -rf "${tmp_dir}"
}

# Remove legacy split apps if present
pkill -x "ClaudeGuard" 2>/dev/null || true
pkill -x "ClaudeShield" 2>/dev/null || true
rm -rf "/Applications/Claude Safe.app" "/Applications/Claude Guard.app"

# 2. Build Unified Native SwiftUI App + Embed Rust Core Binary
SHIELD_APP="/Applications/Claude Shield.app"
if command -v swiftc >/dev/null 2>&1 && compgen -G "${REPO_ROOT}/app/Sources/*.swift" >/dev/null; then
  rm -rf "${SHIELD_APP}"
  mkdir -p "${SHIELD_APP}/Contents/MacOS" "${SHIELD_APP}/Contents/Resources"

  echo "🦅 Compiling native SwiftUI radar app + static-linking Rust FFI (/Applications/Claude Shield.app)..."
  swiftc -O -target "$(uname -m)-apple-macos13.0" \
    -import-objc-header "${REPO_ROOT}/app/Sources/ClaudeShieldCore.h" \
    -framework Cocoa -framework SwiftUI -framework Network -framework QuartzCore \
    -framework Security -framework SystemConfiguration \
    "${REPO_ROOT}/app/Sources/"*.swift \
    "${REPO_ROOT}/core/target/release/libclaude_shield_core.a" \
    -o "${SHIELD_APP}/Contents/MacOS/ClaudeShield"

  cp "${CORE_BIN}" "${SHIELD_APP}/Contents/MacOS/claude-shield-core"
  chmod +x "${SHIELD_APP}/Contents/MacOS/claude-shield-core"

  ICON_NAME=""
  if [[ -f "${REPO_ROOT}/assets/icon.png" ]] && command -v iconutil >/dev/null 2>&1 && command -v sips >/dev/null 2>&1; then
    build_icns "${REPO_ROOT}/assets/icon.png" "${SHIELD_APP}/Contents/Resources/app.icns"
    ICON_NAME="app.icns"
  else
    FALLBACK_ICON="$(ls "$HOME/.local/apps/Claude.app/Contents/Resources/"*.icns /Applications/Claude.app/Contents/Resources/*.icns 2>/dev/null | head -n 1 || true)"
    if [[ -n "${FALLBACK_ICON}" ]]; then
      cp "${FALLBACK_ICON}" "${SHIELD_APP}/Contents/Resources/app.icns"
      ICON_NAME="app.icns"
    fi
  fi
  if [[ -f "${REPO_ROOT}/assets/claude-spark-template.png" ]]; then
    cp "${REPO_ROOT}/assets/claude-spark-template.png" "${SHIELD_APP}/Contents/Resources/claude-spark-template.png"
  fi

  cat > "${SHIELD_APP}/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>ClaudeShield</string>
  <key>CFBundleIdentifier</key><string>com.local.claude.shield</string>
  <key>CFBundleName</key><string>Claude Shield</string>
  <key>CFBundleDisplayName</key><string>Claude Shield</string>
  <key>CFBundleVersion</key><string>${VERSION}</string>
  <key>CFBundleShortVersionString</key><string>${VERSION}</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleIconFile</key><string>${ICON_NAME}</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>LSUIElement</key><true/>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
EOF
  codesign --force --deep --sign - "${SHIELD_APP}" >/dev/null 2>&1 || true
  /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "${SHIELD_APP}" >/dev/null 2>&1 || true
  echo "✅ Built ${SHIELD_APP} v${VERSION} (Rust Core + SwiftUI Studio Console & Radar)"
fi

# 3. Delegate all local hardening, wrappers, settings.json & LaunchAgents to Rust Core (Single Source of Truth)
SETUP_ARGS=(
  --ip "${EXPECTED_IP}"
  --port "${PROXY_PORT}"
  --tz "${TARGET_TZ}"
  --app-path "${SHIELD_APP}"
)
[[ "${HIDE_ORIGINAL}" == "0" ]] && SETUP_ARGS+=(--no-hide)
[[ "${ENABLE_AUTOSTART}" == "0" ]] && SETUP_ARGS+=(--no-autostart)
[[ "${ENABLE_DAILY_PATROL}" == "0" ]] && SETUP_ARGS+=(--no-patrol)

"${CORE_BIN}" setup "${SETUP_ARGS[@]}"

echo ""
echo "🎉 Claude Shield v${VERSION} installed successfully!"
echo "👉 Run 'claude-shield purity' for an ip.net.coffee-grade purity audit in terminal."
echo "👉 Open /Applications/Claude Shield.app from Spotlight/Launchpad to launch Claude & radar."
