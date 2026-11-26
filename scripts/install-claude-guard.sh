#!/usr/bin/env bash
# Install Claude Safe Cage (macOS Native Kill-Switch for Claude Code & Claude Desktop)
set -euo pipefail

EXPECTED_IP=""
PROXY_PORT="7897"
TARGET_TZ="America/Los_Angeles"

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
if [[ -z "${REAL_CLAUDE}" ]]; then
  echo "Warning: claude CLI not found in PATH yet; you can edit REAL_CLAUDE in ~/.local/bin/claude later." >&2
  REAL_CLAUDE="/usr/local/bin/claude"
fi

mkdir -p "$HOME/.config/claude-guard" "$HOME/.local/bin" "$HOME/.local/lib/claude-guard-bin" "$HOME/.claude"
printf '%s\n' "${EXPECTED_IP}" > "$HOME/.config/claude-guard/expected_ip"

cat > "$HOME/.local/bin/claude-guard.sh" <<EOF
#!/usr/bin/env bash
set -euo pipefail

EXPECTED_IP_FILE="\${HOME}/.config/claude-guard/expected_ip"
EXPECTED_IP="\$(tr -d '[:space:]' < "\${EXPECTED_IP_FILE}" 2>/dev/null || echo "${EXPECTED_IP}")"
PROXY_HTTP="http://127.0.0.1:${PROXY_PORT}"
PROXY_SOCKS="socks5h://127.0.0.1:${PROXY_PORT}"
TARGET_TZ="${TARGET_TZ}"

fetch_ip() {
  local mode="\$1" ip=""
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
  [[ -z "\${proxy_ip}" ]] && { echo "CLAUDE_GUARD_ERR:本地代理 127.0.0.1:${PROXY_PORT} 无法连通。"; return 1; }
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
    printf '\n\033[1;33m🔒 [Claude Guard] 已拦截本机默认浏览器弹窗！\033[0m\n' >&2
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
  printf '\033[1;31m[Claude Guard 熔断拦截]\033[0m %s\n' "\${err_msg#CLAUDE_GUARD_ERR:}" >&2
  exit 1
fi
export_claude_env
export PATH="\${HOME}/.local/lib/claude-guard-bin:\${PATH}"
export BROWSER="\${HOME}/.local/lib/claude-guard-bin/open"
printf '\033[0;32m[Claude Guard]\033[0m ✅ IP=%s | TZ=%s | Proxy=127.0.0.1:${PROXY_PORT} | OAuth=AdsPower-Only\n' "\${EXPECTED_IP}" "\${TARGET_TZ}" >&2
exec "${REAL_CLAUDE}" "\$@"
EOF

cat > "$HOME/.local/bin/claude-desktop-safe" <<EOF
#!/usr/bin/env bash
set -euo pipefail
source "\${HOME}/.local/bin/claude-guard.sh"
if ! err_msg="\$(check_claude_guard)"; then
  clean_msg="\${err_msg#CLAUDE_GUARD_ERR:}"
  /usr/bin/osascript -e "display dialog \"⚠️ Claude Guard 熔断拦截\\n\\n\${clean_msg}\" buttons {\"知道了\"} default button 1 with icon stop with title \"Claude Safe\"" >/dev/null 2>&1 || true
  exit 1
fi
export_claude_env
pgrep -x "Claude" >/dev/null 2>&1 && { open -a "/Applications/Claude.app"; exit 0; }
nohup /Applications/Claude.app/Contents/MacOS/Claude \
  --proxy-server="http://127.0.0.1:${PROXY_PORT}" \
  --proxy-bypass-list="<-loopback>" \
  --lang="en-US" >/dev/null 2>&1 &
disown || true
EOF

chmod +x "$HOME/.local/bin/claude-guard.sh" "$HOME/.local/lib/claude-guard-bin/open" "$HOME/.local/bin/claude" "$HOME/.local/bin/claude-desktop-safe"

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

echo "✅ Claude Safe Cage installed! Ensure \$HOME/.local/bin is first in your PATH."
