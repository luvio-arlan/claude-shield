#!/usr/bin/env bash
# Claude Shield v3.0 — Unified macOS Protection Suite Installer (Rust Core + SwiftUI Radar)
# Installs:
#   1. Native Rust Core Engine (~/.local/bin/claude-shield-core & bundled in App)
#   2. Dual-channel + claude.ai Edge IP Fail-Closed Gate (~/.local/bin/claude-guard.sh)
#   3. Hard-bound Claude Code CLI wrapper (~/.local/bin/claude + claude-shield CLI)
#   4. OAuth AdsPower-Only Interceptor (~/.local/lib/claude-guard-bin/open)
#   5. Complete Original Claude.app Auto-Hiding (Vault + chflags hidden + lsregister -u + Dock cleanup)
#   6. macOS Seatbelt Sandbox + Zero-Telemetry + IPv4-First (~/.claude/settings.json)
#   7. All-in-One Native App: /Applications/Claude Shield.app (Safe Launcher + Radar + Purity Audit)
#   8. Login Auto-Start Radar & Daily Deep Purity Patrol LaunchAgents
set -euo pipefail

EXPECTED_IP=""
PROXY_PORT="7897"
TARGET_TZ="America/Los_Angeles"
ENABLE_AUTOSTART="1"
ENABLE_DAILY_PATROL="1"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ip) EXPECTED_IP="$2"; shift 2 ;;
    --port) PROXY_PORT="$2"; shift 2 ;;
    --tz) TARGET_TZ="$2"; shift 2 ;;
    --no-autostart) ENABLE_AUTOSTART="0"; shift ;;
    --no-patrol) ENABLE_DAILY_PATROL="0"; shift ;;
    -h|--help)
      echo "Usage: $0 --ip <DEDICATED_IP> [--port 7897] [--tz America/Los_Angeles] [--no-autostart] [--no-patrol]"
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

REAL_CLAUDE="$(which -a claude 2>/dev/null | grep -v "$HOME/.local/bin/claude" | head -n 1 || true)"
[[ -z "${REAL_CLAUDE}" ]] && REAL_CLAUDE="/usr/local/bin/claude"

mkdir -p "$HOME/.config/claude-guard" "$HOME/.local/bin" "$HOME/.local/lib/claude-guard-bin" "$HOME/.local/apps" "$HOME/.claude" "$HOME/Library/LaunchAgents"
printf '%s\n' "${EXPECTED_IP}" > "$HOME/.config/claude-guard/expected_ip"
printf '%s\n' "${PROXY_PORT}" > "$HOME/.config/claude-guard/proxy_port"
printf '%s\n' "${TARGET_TZ}" > "$HOME/.config/claude-guard/target_tz"
touch "$HOME/.local/apps/.metadata_never_index"

# 1. Build Native Rust Core Engine (claude-shield-core)
CORE_BIN="$HOME/.local/bin/claude-shield-core"
if command -v cargo >/dev/null 2>&1 && [[ -f "${REPO_ROOT}/core/Cargo.toml" ]]; then
  echo "🦀 Building native Rust core engine (claude-shield-core)..."
  (cd "${REPO_ROOT}/core" && cargo build --release --quiet)
  cp "${REPO_ROOT}/core/target/release/claude-shield-core" "${CORE_BIN}"
  chmod +x "${CORE_BIN}"
  echo "✅ Built native Rust core: ${CORE_BIN}"
elif [[ -x "${CORE_BIN}" ]]; then
  echo "ℹ️  Using existing Rust core binary: ${CORE_BIN}"
else
  echo "⚠️  Rust (cargo) not found. Install via 'brew install rust' to enable native Rust core speed & purity engine." >&2
fi

# 2. Complete Original Claude.app Auto-Hiding (Vault + Finder hidden + LaunchServices unregister + Dock cleanup)
if [[ -x "${CORE_BIN}" ]]; then
  "${CORE_BIN}" hide-original
else
  if [[ -d "/Applications/Claude.app" && ! -d "$HOME/.local/apps/Claude.app" ]]; then
    mv "/Applications/Claude.app" "$HOME/.local/apps/Claude.app"
  fi
  chflags hidden "$HOME/.local/apps" 2>/dev/null || true
  [[ -d "$HOME/.local/apps/Claude.app" ]] && chflags hidden "$HOME/.local/apps/Claude.app" 2>/dev/null || true
  LSREG="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
  [[ -x "${LSREG}" ]] && "${LSREG}" -u "/Applications/Claude.app" "$HOME/.local/apps/Claude.app" >/dev/null 2>&1 || true
fi

# 3. Install claude-guard.sh (Rust-accelerated with bash fallback for full compatibility)
cat > "$HOME/.local/bin/claude-guard.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail

EXPECTED_IP_FILE="\${HOME}/.config/claude-guard/expected_ip"
PROXY_PORT_FILE="\${HOME}/.config/claude-guard/proxy_port"
TARGET_TZ_FILE="\${HOME}/.config/claude-guard/target_tz"

EXPECTED_IP="\${EXPECTED_IP:-\$(tr -d '[:space:]' < "\${EXPECTED_IP_FILE}" 2>/dev/null || echo "${EXPECTED_IP}")}"
PROXY_PORT="\${PROXY_PORT:-\$(tr -d '[:space:]' < "\${PROXY_PORT_FILE}" 2>/dev/null || echo "${PROXY_PORT}")}"
TARGET_TZ="\${TARGET_TZ:-\$(tr -d '[:space:]' < "\${TARGET_TZ_FILE}" 2>/dev/null || echo "${TARGET_TZ}")}"

PROXY_HTTP="http://127.0.0.1:\${PROXY_PORT}"
PROXY_SOCKS="socks5h://127.0.0.1:\${PROXY_PORT}"

fetch_ip() {
  local mode="\$1" ip="" body=""
  if [[ "\${mode}" == "proxy" ]]; then
    body="\$(curl -4 -fsS --max-time 4 -x "\${PROXY_HTTP}" "https://claude.ai/cdn-cgi/trace" 2>/dev/null || true)"
  else
    body="\$(curl -4 -fsS --max-time 4 --noproxy '*' "https://1.1.1.1/cdn-cgi/trace" 2>/dev/null || true)"
  fi
  ip="\$(printf '%s\n' "\${body}" | sed -n 's/^ip=//p' | tr -d '[:space:]')"
  [[ -n "\${ip}" ]] && { echo "\${ip}"; return 0; }

  for url in "https://api.ipify.org" "https://ifconfig.me/ip"; do
    if [[ "\${mode}" == "proxy" ]]; then
      ip="\$(curl -4 -fsS --max-time 4 -x "\${PROXY_HTTP}" "\${url}" 2>/dev/null | tr -d '[:space:]' || true)"
    else
      ip="\$(curl -4 -fsS --max-time 4 --noproxy '*' "\${url}" 2>/dev/null | tr -d '[:space:]' || true)"
    fi
    [[ -n "\${ip}" ]] && { echo "\${ip}"; return 0; }
  done
  return 1
}

check_claude_guard() {
  # If user didn't override EXPECTED_IP inline and Rust core is available, use native Rust gate
  local file_ip
  file_ip="\$(tr -d '[:space:]' < "\${EXPECTED_IP_FILE}" 2>/dev/null || true)"
  if [[ "\${EXPECTED_IP}" == "\${file_ip}" && -x "\${HOME}/.local/bin/claude-shield-core" ]]; then
    local out
    if ! out="\$("\${HOME}/.local/bin/claude-shield-core" gate)"; then
      echo "\${out}"
      return 1
    fi
    return 0
  fi

  local tmp_proxy tmp_tun proxy_ip tun_ip
  tmp_proxy="\$(mktemp)"
  tmp_tun="\$(mktemp)"
  (fetch_ip proxy || true) > "\${tmp_proxy}" &
  local pid_p=\$!
  (fetch_ip tun || true) > "\${tmp_tun}" &
  local pid_t=\$!
  wait "\${pid_p}" "\${pid_t}" 2>/dev/null || true
  proxy_ip="\$(cat "\${tmp_proxy}" 2>/dev/null || true)"
  tun_ip="\$(cat "\${tmp_tun}" 2>/dev/null || true)"
  rm -f "\${tmp_proxy}" "\${tmp_tun}"

  [[ -z "\${proxy_ip}" ]] && { echo "CLAUDE_GUARD_ERR:本地代理 127.0.0.1:\${PROXY_PORT} 无法连通。"; return 1; }
  [[ "\${proxy_ip}" != "\${EXPECTED_IP}" ]] && { echo "CLAUDE_GUARD_ERR:代理出口 IP 异常（当前: \${proxy_ip}，期望: \${EXPECTED_IP}）。"; return 1; }
  [[ -z "\${tun_ip}" ]] && { echo "CLAUDE_GUARD_ERR:默认路由（TUN）无法连通外网。"; return 1; }
  [[ "\${tun_ip}" != "\${EXPECTED_IP}" ]] && { echo "CLAUDE_GUARD_ERR:默认路由（TUN）出口 IP 异常（当前: \${tun_ip}，期望: \${EXPECTED_IP}）。"; return 1; }
  return 0
}

export_claude_env() {
  export TZ="\${TARGET_TZ}"
  export LANG="en_US.UTF-8"
  export LC_ALL="en_US.UTF-8"
  export HTTP_PROXY="\${PROXY_HTTP}" HTTPS_PROXY="\${PROXY_HTTP}" ALL_PROXY="\${PROXY_SOCKS}"
  export http_proxy="\${PROXY_HTTP}" https_proxy="\${PROXY_HTTP}" all_proxy="\${PROXY_SOCKS}"
  export NO_PROXY="localhost,127.0.0.1,::1" no_proxy="localhost,127.0.0.1,::1"
  export NODE_OPTIONS="\${NODE_OPTIONS:+\${NODE_OPTIONS} }--dns-result-order=ipv4first"
  export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1"
  export CLAUDE_CODE_ENABLE_TELEMETRY="0"
  export DISABLE_TELEMETRY="1"
  export DISABLE_ERROR_REPORTING="1"
  export DISABLE_BUG_COMMAND="1"
  export DISABLE_AUTOUPDATER="1"
  export OTEL_SDK_DISABLED="1"
  export DO_NOT_TRACK="1"
}
EOF

# 4. OAuth AdsPower-Only Interceptor (covers claude.ai, anthropic.com, claude.com)
cat > "$HOME/.local/lib/claude-guard-bin/open" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
for arg in "$@"; do
  if [[ "${arg}" == *"claude.ai"* || "${arg}" == *"anthropic.com"* || "${arg}" == *"claude.com"* ]]; then
    printf '%s' "${arg}" | /usr/bin/pbcopy 2>/dev/null || true
    printf '\n\033[1;33m🔒 [Claude Shield] 已拦截本机默认浏览器弹窗！\033[0m\n' >&2
    printf '\033[0;36m授权链接已自动复制到剪贴板，请粘贴进 AdsPower 指纹浏览器完成授权：\033[0m\n%s\n\n' "${arg}" >&2
    exit 0
  fi
done
exec /usr/bin/open "$@"
EOF

# 5. Ultra-Fast Rust-backed Claude Code CLI Wrapper (~/.local/bin/claude)
cat > "$HOME/.local/bin/claude" <<EOF
#!/usr/bin/env bash
set -euo pipefail
if [[ -x "\${HOME}/.local/bin/claude-shield-core" ]]; then
  exec "\${HOME}/.local/bin/claude-shield-core" exec-cli "${REAL_CLAUDE}" "\$@"
fi
source "\${HOME}/.local/bin/claude-guard.sh"
if ! err_msg="\$(check_claude_guard)"; then
  printf '\033[1;31m[Claude Shield 熔断拦截]\033[0m %s\n' "\${err_msg#CLAUDE_GUARD_ERR:}" >&2
  exit 1
fi
export_claude_env
export PATH="\${HOME}/.local/lib/claude-guard-bin:\${PATH}"
export BROWSER="\${HOME}/.local/lib/claude-guard-bin/open"
printf '\033[0;32m[Claude Shield]\033[0m ✅ IP=%s | TZ=%s | Proxy=127.0.0.1:%s | OAuth=AdsPower-Only\n' "\${EXPECTED_IP}" "\${TARGET_TZ}" "\${PROXY_PORT}" >&2
exec "${REAL_CLAUDE}" "\$@"
EOF

# 6. Convenient CLI Utility: claude-shield (purity / patrol / gate / hide-original)
cat > "$HOME/.local/bin/claude-shield" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
exec "$HOME/.local/bin/claude-shield-core" "$@"
EOF

# 7. Hardened Desktop Safe Launcher (~/.local/bin/claude-desktop-safe)
cat > "$HOME/.local/bin/claude-desktop-safe" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ -x "${HOME}/.local/bin/claude-shield-core" ]]; then
  exec "${HOME}/.local/bin/claude-shield-core" launch-desktop
fi
source "${HOME}/.local/bin/claude-guard.sh"
if ! err_msg="$(check_claude_guard)"; then
  clean_msg="${err_msg#CLAUDE_GUARD_ERR:}"
  /usr/bin/osascript -e "display dialog \"⚠️ Claude Shield 熔断拦截\\n\\n${clean_msg}\" buttons {\"知道了\"} default button 1 with icon stop with title \"Claude Shield\"" >/dev/null 2>&1 || true
  exit 1
fi
export_claude_env
CLAUDE_APP="${HOME}/.local/apps/Claude.app"
[[ ! -d "${CLAUDE_APP}" ]] && CLAUDE_APP="/Applications/Claude.app"
nohup "${CLAUDE_APP}/Contents/MacOS/Claude" \
  --proxy-server="http://127.0.0.1:${PROXY_PORT}" \
  --proxy-bypass-list="<-loopback>" \
  --disable-quic \
  --force-webrtc-ip-handling-policy=disable_non_proxied_udp \
  --lang="en-US" >/dev/null 2>&1 &
disown || true
EOF

chmod +x "$HOME/.local/bin/claude-guard.sh" \
  "$HOME/.local/lib/claude-guard-bin/open" \
  "$HOME/.local/bin/claude" \
  "$HOME/.local/bin/claude-shield" \
  "$HOME/.local/bin/claude-desktop-safe"

# Helper: build multi-resolution macOS .icns from assets/icon.png
build_icns() {
  local src_png="$1" out_icns="$2"
  local tmp_dir
  tmp_dir="$(mktemp -d)"
  local iconset="${tmp_dir}/AppIcon.iconset"
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

# 8. Build Unified Native SwiftUI App + Embed Rust Core Binary
if command -v swiftc >/dev/null 2>&1 && [[ -f "${REPO_ROOT}/app/ClaudeShieldApp.swift" ]]; then
  SHIELD_APP="/Applications/Claude Shield.app"
  rm -rf "${SHIELD_APP}"
  mkdir -p "${SHIELD_APP}/Contents/MacOS" "${SHIELD_APP}/Contents/Resources"

  echo "🦅 Compiling native SwiftUI radar app (/Applications/Claude Shield.app)..."
  swiftc -O -framework Cocoa -framework SwiftUI -framework Network \
    "${REPO_ROOT}/app/ClaudeShieldApp.swift" \
    -o "${SHIELD_APP}/Contents/MacOS/ClaudeShield"

  if [[ -x "${CORE_BIN}" ]]; then
    cp "${CORE_BIN}" "${SHIELD_APP}/Contents/MacOS/claude-shield-core"
    chmod +x "${SHIELD_APP}/Contents/MacOS/claude-shield-core"
  fi

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

  cat > "${SHIELD_APP}/Contents/Info.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleExecutable</key><string>ClaudeShield</string>
  <key>CFBundleIdentifier</key><string>com.local.claude.shield</string>
  <key>CFBundleName</key><string>Claude Shield</string>
  <key>CFBundleDisplayName</key><string>Claude Shield</string>
  <key>CFBundleVersion</key><string>3.0</string>
  <key>CFBundleShortVersionString</key><string>3.0</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleIconFile</key><string>${ICON_NAME}</string>
  <key>LSUIElement</key><true/>
</dict>
</plist>
EOF
  /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "${SHIELD_APP}" >/dev/null 2>&1 || true
  echo "✅ Built /Applications/Claude Shield.app v3.0 (Rust Core + SwiftUI Radar + Purity Audit)"
fi

# 9. Harden ~/.claude/settings.json (merge non-destructively via Python so user preferences are preserved)
/usr/bin/python3 - "${TARGET_TZ}" <<'PYEOF'
import json, os, sys
tz = sys.argv[1]
path = os.path.expanduser("~/.claude/settings.json")
data = {}
if os.path.exists(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        data = {}

sb = data.setdefault("sandbox", {})
sb["enabled"] = True
sb.setdefault("autoAllowBashIfSandboxed", True)

env = data.setdefault("env", {})
env["TZ"] = tz
env["LANG"] = "en_US.UTF-8"
env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
env["CLAUDE_CODE_ENABLE_TELEMETRY"] = "0"
env["DISABLE_TELEMETRY"] = "1"
env["DISABLE_ERROR_REPORTING"] = "1"
env["DISABLE_BUG_COMMAND"] = "1"
env["DISABLE_AUTOUPDATER"] = "1"

with open(path, "w", encoding="utf-8") as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
    f.write("\n")
PYEOF

# 10. Install LaunchAgents: Login Auto-Start Radar & Daily Deep Purity Patrol
USER_UID="$(id -u)"
RADAR_PLIST="$HOME/Library/LaunchAgents/com.local.claude.shield.radar.plist"
PATROL_PLIST="$HOME/Library/LaunchAgents/com.local.claude.shield.patrol.plist"

if [[ "${ENABLE_AUTOSTART}" == "1" ]]; then
  cat > "${RADAR_PLIST}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.local.claude.shield.radar</string>
  <key>ProgramArguments</key>
  <array>
    <string>/Applications/Claude Shield.app/Contents/MacOS/ClaudeShield</string>
    <string>--radar-only</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><false/>
  <key>ProcessType</key><string>Interactive</string>
</dict>
</plist>
EOF
  launchctl bootout "gui/${USER_UID}" "${RADAR_PLIST}" 2>/dev/null || true
  launchctl bootstrap "gui/${USER_UID}" "${RADAR_PLIST}" 2>/dev/null || true
  echo "✅ Enabled Login Auto-Start Radar (com.local.claude.shield.radar)"
fi

if [[ "${ENABLE_DAILY_PATROL}" == "1" && -x "${CORE_BIN}" ]]; then
  cat > "${PATROL_PLIST}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.local.claude.shield.patrol</string>
  <key>ProgramArguments</key>
  <array>
    <string>${CORE_BIN}</string>
    <string>patrol</string>
    <string>--notify</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>StartCalendarInterval</key>
  <dict>
    <key>Hour</key><integer>9</integer>
    <key>Minute</key><integer>30</integer>
  </dict>
  <key>StandardOutPath</key><string>${HOME}/.config/claude-guard/patrol.log</string>
  <key>StandardErrorPath</key><string>${HOME}/.config/claude-guard/patrol.log</string>
</dict>
</plist>
EOF
  launchctl bootout "gui/${USER_UID}" "${PATROL_PLIST}" 2>/dev/null || true
  launchctl bootstrap "gui/${USER_UID}" "${PATROL_PLIST}" 2>/dev/null || true
  echo "✅ Enabled Daily Security & Purity Patrol (com.local.claude.shield.patrol · 09:30 + login)"
fi

echo ""
echo "🎉 Claude Shield v3.0 installed successfully!"
echo "👉 Run 'claude-shield purity' for an ip.net.coffee-grade purity audit in terminal."
echo "👉 Open /Applications/Claude Shield.app from Spotlight/Launchpad to launch Claude & radar."
