#!/usr/bin/env bash
# Claude Shield — Unified macOS Protection Suite Installer
# Installs:
#   1. Dual-channel IP Fail-Closed Gate (~/.local/bin/claude-guard.sh)
#   2. Hard-bound Claude Code CLI wrapper (~/.local/bin/claude)
#   3. OAuth AdsPower-Only Interceptor (~/.local/lib/claude-guard-bin/open)
#   4. Original Claude.app Vault Isolation (~/.local/apps/Claude.app)
#   5. macOS Seatbelt Sandbox + Anti-Telemetry (~/.claude/settings.json)
#   6. All-in-One Native App: /Applications/Claude Shield.app (Safe Launcher + Menu Bar Radar)
set -euo pipefail

EXPECTED_IP=""
PROXY_PORT="7897"
TARGET_TZ="America/Los_Angeles"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ip) EXPECTED_IP="$2"; shift 2 ;;
    --port) PROXY_PORT="$2"; shift 2 ;;
    --tz) TARGET_TZ="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 --ip <DEDICATED_IP> [--port 7897] [--tz America/Los_Angeles]"
      exit 0
      ;;
    *) echo "Unknown arg: $1" >&2; exit 1 ;;
  esac
done

if [[ -z "${EXPECTED_IP}" ]]; then
  echo "Error: --ip <DEDICATED_IP> is required." >&2
  exit 1
fi

REAL_CLAUDE="$(which -a claude 2>/dev/null | grep -v "$HOME/.local/bin/claude" | head -n 1 || true)"
[[ -z "${REAL_CLAUDE}" ]] && REAL_CLAUDE="/usr/local/bin/claude"

mkdir -p "$HOME/.config/claude-guard" "$HOME/.local/bin" "$HOME/.local/lib/claude-guard-bin" "$HOME/.local/apps" "$HOME/.claude"
printf '%s\n' "${EXPECTED_IP}" > "$HOME/.config/claude-guard/expected_ip"
printf '%s\n' "${PROXY_PORT}" > "$HOME/.config/claude-guard/proxy_port"
printf '%s\n' "${TARGET_TZ}" > "$HOME/.config/claude-guard/target_tz"
touch "$HOME/.local/apps/.metadata_never_index"

# Hide original Claude.app into vault to prevent accidental misclick (preserves Apple code signature)
if [[ -d "/Applications/Claude.app" && ! -d "$HOME/.local/apps/Claude.app" ]]; then
  mv "/Applications/Claude.app" "$HOME/.local/apps/Claude.app"
fi

cat > "$HOME/.local/bin/claude-guard.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail

EXPECTED_IP_FILE="\${HOME}/.config/claude-guard/expected_ip"
PROXY_PORT_FILE="\${HOME}/.config/claude-guard/proxy_port"
TARGET_TZ_FILE="\${HOME}/.config/claude-guard/target_tz"

EXPECTED_IP="\$(tr -d '[:space:]' < "\${EXPECTED_IP_FILE}" 2>/dev/null || echo "${EXPECTED_IP}")"
PROXY_PORT="\$(tr -d '[:space:]' < "\${PROXY_PORT_FILE}" 2>/dev/null || echo "${PROXY_PORT}")"
TARGET_TZ="\$(tr -d '[:space:]' < "\${TARGET_TZ_FILE}" 2>/dev/null || echo "${TARGET_TZ}")"

PROXY_HTTP="http://127.0.0.1:\${PROXY_PORT}"
PROXY_SOCKS="socks5h://127.0.0.1:\${PROXY_PORT}"

fetch_ip() {
  local mode="\$1" ip="" body=""
  if [[ "\${mode}" == "proxy" ]]; then
    body="\$(curl -fsS --max-time 4 -x "\${PROXY_HTTP}" "https://1.1.1.1/cdn-cgi/trace" 2>/dev/null || true)"
  else
    body="\$(curl -fsS --max-time 4 --noproxy '*' "https://1.1.1.1/cdn-cgi/trace" 2>/dev/null || true)"
  fi
  ip="\$(printf '%s\n' "\${body}" | sed -n 's/^ip=//p' | tr -d '[:space:]')"
  [[ -n "\${ip}" ]] && { echo "\${ip}"; return 0; }

  for url in "https://api.ipify.org" "https://ifconfig.me/ip"; do
    if [[ "\${mode}" == "proxy" ]]; then
      ip="\$(curl -fsS --max-time 4 -x "\${PROXY_HTTP}" "\${url}" 2>/dev/null | tr -d '[:space:]' || true)"
    else
      ip="\$(curl -fsS --max-time 4 --noproxy '*' "\${url}" 2>/dev/null | tr -d '[:space:]' || true)"
    fi
    [[ -n "\${ip}" ]] && { echo "\${ip}"; return 0; }
  done
  return 1
}

check_claude_guard() {
  local proxy_ip tun_ip
  proxy_ip="\$(fetch_ip proxy || true)"
  tun_ip="\$(fetch_ip tun || true)"
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
  export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC="1"
  export DISABLE_TELEMETRY="1"
  export DISABLE_ERROR_REPORTING="1"
}
EOF

cat > "$HOME/.local/lib/claude-guard-bin/open" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
for arg in "$@"; do
  if [[ "${arg}" == *"claude.ai"* || "${arg}" == *"anthropic.com"* ]]; then
    printf '%s' "${arg}" | /usr/bin/pbcopy 2>/dev/null || true
    printf '\n\033[1;33m🔒 [Claude Shield] 已拦截本机默认浏览器弹窗！\033[0m\n' >&2
    printf '\033[0;36m授权链接已自动复制到剪贴板，请粘贴进指纹浏览器完成授权：\033[0m\n%s\n\n' "${arg}" >&2
    exit 0
  fi
done
exec /usr/bin/open "$@"
EOF

cat > "$HOME/.local/bin/claude" <<EOF
#!/usr/bin/env bash
set -euo pipefail
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

cat > "$HOME/.local/bin/claude-desktop-safe" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
source "${HOME}/.local/bin/claude-guard.sh"
if ! err_msg="$(check_claude_guard)"; then
  clean_msg="${err_msg#CLAUDE_GUARD_ERR:}"
  /usr/bin/osascript -e "display dialog \"⚠️ Claude Shield 熔断拦截\\n\\n${clean_msg}\" buttons {\"知道了\"} default button 1 with icon stop with title \"Claude Shield\"" >/dev/null 2>&1 || true
  exit 1
fi
export_claude_env
CLAUDE_APP="${HOME}/.local/apps/Claude.app"
[[ ! -d "${CLAUDE_APP}" ]] && CLAUDE_APP="/Applications/Claude.app"
if [[ ! -d "${CLAUDE_APP}" ]]; then
  /usr/bin/osascript -e 'display dialog "未检测到 Claude 桌面版（Claude.app），请先安装 Claude Desktop。" buttons {"知道了"} default button 1 with icon note with title "Claude Shield"' >/dev/null 2>&1 || true
  exit 0
fi
pgrep -x "Claude" >/dev/null 2>&1 && { open -a "${CLAUDE_APP}"; exit 0; }
nohup "${CLAUDE_APP}/Contents/MacOS/Claude" \
  --proxy-server="http://127.0.0.1:${PROXY_PORT}" \
  --proxy-bypass-list="<-loopback>" \
  --lang="en-US" >/dev/null 2>&1 &
disown || true
EOF

chmod +x "$HOME/.local/bin/claude-guard.sh" "$HOME/.local/lib/claude-guard-bin/open" "$HOME/.local/bin/claude" "$HOME/.local/bin/claude-desktop-safe"

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

# Build unified All-in-One native Swift app: /Applications/Claude Shield.app
if command -v swiftc >/dev/null 2>&1 && [[ -f "${REPO_ROOT}/app/ClaudeShieldApp.swift" ]]; then
  SHIELD_APP="/Applications/Claude Shield.app"
  rm -rf "${SHIELD_APP}"
  mkdir -p "${SHIELD_APP}/Contents/MacOS" "${SHIELD_APP}/Contents/Resources"

  swiftc -O -framework Cocoa -framework SwiftUI \
    "${REPO_ROOT}/app/ClaudeShieldApp.swift" \
    -o "${SHIELD_APP}/Contents/MacOS/ClaudeShield"

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
  <key>CFBundleVersion</key><string>2.1</string>
  <key>CFBundleShortVersionString</key><string>2.1</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleIconFile</key><string>${ICON_NAME}</string>
  <key>LSUIElement</key><true/>
</dict>
</plist>
EOF
  # Refresh LaunchServices icon cache
  /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "${SHIELD_APP}" >/dev/null 2>&1 || true
  echo "✅ Built /Applications/Claude Shield.app (All-in-One Safe Launcher + Menu Bar Radar)"
fi

if [[ ! -f "$HOME/.claude/settings.json" ]]; then
  cat > "$HOME/.claude/settings.json" <<EOF
{
  "sandbox": { "enabled": true, "autoAllowBashIfSandboxed": true },
  "env": {
    "TZ": "${TARGET_TZ}",
    "LANG": "en_US.UTF-8",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    "DISABLE_TELEMETRY": "1",
    "DISABLE_ERROR_REPORTING": "1"
  }
}
EOF
fi

echo "✅ Claude Shield installed! Ensure \$HOME/.local/bin is first in your PATH."
echo "👉 Open /Applications/Claude Shield.app from Spotlight/Launchpad to safely launch Claude & start the menu bar radar."
