#!/usr/bin/env bash
# Claude Shield v3.2 — Standalone macOS .app + .dmg + .zip Release Packager
set -euo pipefail

VERSION="${1:-3.2.0}"
ARCH="$(uname -m)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
DIST_DIR="${REPO_ROOT}/dist"
APP_NAME="Claude Shield.app"
APP_DIR="${DIST_DIR}/${APP_NAME}"
DMG_STAGING="${DIST_DIR}/dmg-staging"
DMG_OUT="${DIST_DIR}/Claude-Shield-v${VERSION}-macOS-${ARCH}.dmg"
ZIP_OUT="${DIST_DIR}/Claude-Shield-v${VERSION}-macOS-${ARCH}.zip"

rm -rf "${DIST_DIR}"
mkdir -p "${APP_DIR}/Contents/MacOS" "${APP_DIR}/Contents/Resources" "${DMG_STAGING}"

echo "🦀 [1/5] Building native Rust core engine (release, LTO + strip)..."
(cd "${REPO_ROOT}/core" && cargo build --release --quiet)
cp "${REPO_ROOT}/core/target/release/claude-shield-core" "${APP_DIR}/Contents/MacOS/claude-shield-core"
chmod +x "${APP_DIR}/Contents/MacOS/claude-shield-core"

echo "🦅 [2/5] Compiling native SwiftUI App (macOS 13.0+ ${ARCH})..."
swiftc -O -target "${ARCH}-apple-macos13.0" \
  -framework Cocoa -framework SwiftUI -framework Network -framework QuartzCore \
  "${REPO_ROOT}/app/ClaudeShieldApp.swift" \
  -o "${APP_DIR}/Contents/MacOS/ClaudeShield"
chmod +x "${APP_DIR}/Contents/MacOS/ClaudeShield"

echo "🎨 [3/5] Generating Retina .icns & bundling resources..."
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

build_icns "${REPO_ROOT}/assets/icon.png" "${APP_DIR}/Contents/Resources/app.icns"
if [[ -f "${REPO_ROOT}/assets/claude-spark-template.png" ]]; then
  cp "${REPO_ROOT}/assets/claude-spark-template.png" "${APP_DIR}/Contents/Resources/claude-spark-template.png"
fi

cat > "${APP_DIR}/Contents/Info.plist" <<EOF
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
  <key>CFBundleIconFile</key><string>app.icns</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
  <key>LSUIElement</key><true/>
  <key>NSHighResolutionCapable</key><true/>
</dict>
</plist>
EOF

echo "🔏 [4/5] Ad-hoc code signing bundle..."
codesign --force --deep --sign - "${APP_DIR}"

echo "📦 [5/5] Creating DMG & ZIP release artifacts..."
cp -R "${APP_DIR}" "${DMG_STAGING}/${APP_NAME}"
ln -s /Applications "${DMG_STAGING}/Applications"

hdiutil create \
  -volname "Claude Shield v${VERSION}" \
  -srcfolder "${DMG_STAGING}" \
  -ov -format UDZO \
  -imagekey zlib-level=9 \
  "${DMG_OUT}" >/dev/null

(cd "${DIST_DIR}" && ditto -c -k --sequesterRsrc --keepParent "${APP_NAME}" "${ZIP_OUT}")
(cd "${DIST_DIR}" && shasum -a 256 "$(basename "${DMG_OUT}")" "$(basename "${ZIP_OUT}")" > SHA256SUMS.txt)

rm -rf "${DMG_STAGING}"
echo "✅ Release artifacts ready in ${DIST_DIR}:"
ls -lh "${DMG_OUT}" "${ZIP_OUT}" "${DIST_DIR}/SHA256SUMS.txt"
