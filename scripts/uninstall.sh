#!/usr/bin/env bash
# Claude Shield — One-Click Uninstall & Full System Restore
set -euo pipefail

pkill -x "ClaudeShield" 2>/dev/null || true

CORE_BIN=""
if [[ -x "/Applications/Claude Shield.app/Contents/MacOS/claude-shield-core" ]]; then
  CORE_BIN="/Applications/Claude Shield.app/Contents/MacOS/claude-shield-core"
elif [[ -x "$HOME/.local/bin/claude-shield-core" ]]; then
  CORE_BIN="$HOME/.local/bin/claude-shield-core"
fi

if [[ -n "${CORE_BIN}" ]]; then
  "${CORE_BIN}" uninstall --remove-app
else
  echo "⚠️  未找到 claude-shield-core，正在执行兜底还原..."
  USER_UID="$(id -u)"
  for plist in "$HOME/Library/LaunchAgents/com.local.claude.shield.radar.plist" "$HOME/Library/LaunchAgents/com.local.claude.shield.patrol.plist"; do
    if [[ -f "${plist}" ]]; then
      launchctl bootout "gui/${USER_UID}" "${plist}" 2>/dev/null || true
      rm -f "${plist}"
    fi
  done
  if [[ -d "$HOME/.local/apps/Claude.app" && ! -d "/Applications/Claude.app" ]]; then
    chflags nohidden "$HOME/.local/apps" "$HOME/.local/apps/Claude.app" 2>/dev/null || true
    mv "$HOME/.local/apps/Claude.app" "/Applications/Claude.app"
    /System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "/Applications/Claude.app" >/dev/null 2>&1 || true
    echo "✅ 已还原原版 /Applications/Claude.app"
  fi
  rm -rf "$HOME/.local/lib/claude-guard-bin" "$HOME/.config/claude-guard" "/Applications/Claude Shield.app"
  rm -f "$HOME/.local/bin/claude-shield" "$HOME/.local/bin/claude-shield-core" "$HOME/.local/bin/claude-guard.sh" "$HOME/.local/bin/claude-desktop-safe"
  echo "✅ Claude Shield 已卸载并还原"
fi
