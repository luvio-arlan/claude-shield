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
  if [[ -f "$HOME/.local/bin/claude" ]] && grep -qE "claude-shield|claude-guard" "$HOME/.local/bin/claude" 2>/dev/null; then
    rm -f "$HOME/.local/bin/claude"
  fi
  for rc in "$HOME/.zshrc" "$HOME/.bash_profile"; do
    if [[ -f "${rc}" ]] && grep -q "# >>> Claude Shield >>>" "${rc}" 2>/dev/null; then
      /usr/bin/python3 - "${rc}" <<'PYEOF'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
lines = p.read_text(encoding="utf-8", errors="ignore").splitlines()
out, skip = [], False
for line in lines:
    if line.strip() == "# >>> Claude Shield >>>":
        skip = True
        continue
    if skip:
        if line.strip() == "# <<< Claude Shield <<<":
            skip = False
        continue
    out.append(line)
while out and not out[-1]:
    out.pop()
p.write_text(("\n".join(out) + "\n") if out else "", encoding="utf-8")
PYEOF
    fi
  done
  rm -rf "$HOME/.local/lib/claude-guard-bin" "$HOME/.config/claude-guard" "/Applications/Claude Shield.app"
  rm -f "$HOME/.local/bin/claude-shield" "$HOME/.local/bin/claude-shield-core" "$HOME/.local/bin/claude-guard.sh" "$HOME/.local/bin/claude-desktop-safe"
  echo "✅ Claude Shield 已卸载并还原"
fi
