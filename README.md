# Claude Safe Cage Skill

> **0 虚拟机内存损耗**的 macOS 原生 Claude 防封铁笼：集 **双通道 IP 门禁锁 + 桌面版防误触隐藏 + OAuth 强制拦截 + 原生 Swift 状态栏实时雷达** 于一体。

## 为什么做这个项目？

用虚拟机套娃（Lima/Docker）跑 Claude Code 常驻吃掉 2–4GB 内存、拖慢大型前端项目读写，还调不动 macOS 原生工具链；而直接裸跑又怕哪天忘开代理、切错节点、或者手滑点开桌面版瞬间裸连封号。

**Claude Safe Cage** 用纯 macOS 原生机制实现了 **6 道防线**（全套内存占用 <15MB）：

1. **双通道 IP 门禁锁（Kill-Switch）**：启动前 0.5 秒同时校验本地代理端口和默认路由（TUN）出口 IP，不等于白名单独享 IP 直接红字/弹窗熔断。
2. **运行中硬代理绑定（Fail-Closed）**：CLI 与桌面版（Electron `--proxy-server`）锁死本地代理端口，中途代理崩了立刻断网，绝不回退物理网卡裸连。
3. **原版防误触隐藏 + 零跳动安全壳**：自动把原版 `Claude.app` 移入隐藏隔离仓（禁止 Spotlight 索引、保留官方签名），`/Applications` 只留 `LSUIElement=true` 零跳动的 `Claude Safe.app`。
4. **OAuth 强制拦截（AdsPower-Only）**：拦截 `claude.ai` / `anthropic.com` 系统浏览器弹窗，自动复制授权链接到剪贴板，强制走指纹浏览器完成闭环。
5. **进程级时区 & 语言伪装 + 官方 Seatbelt 沙盒**：强制注入 `TZ=America/Los_Angeles`、`en-US`（不动 Mac 系统时钟），开启 `~/.claude/settings.json` 沙盒与去遥测。
6. **商业级原生 SwiftUI 状态栏雷达（`Claude Guard.app` v2.0）**：随 `Claude Safe.app` 打开自动常驻顶部状态栏，毛玻璃 Popover 面板实时显示双通道 IP + 毫秒级测速延迟、6 项防线评分矩阵、进程 PID、**IP 漂移自动急停（Fail-Closed Auto-Kill）开关**、一键聚焦/紧急急停与诊断报告复制。

## 一键部署

```bash
git clone https://github.com/luvio-arlan/claude-safe-cage-skill.git
cd claude-safe-cage-skill

bash scripts/install-claude-guard.sh \
  --ip "<YOUR_DEDICATED_IP>" \
  --port "7897" \
  --tz "America/Los_Angeles"
```

也可直接作为 Agent Skill 安装到 `~/.gemini/config/skills/claude-safe-cage/` 或 `~/.claude/skills/claude-safe-cage/`。

## 完整手册

详细 AdsPower 指纹配置表、缓存清理与验真命令请查看 [SKILL.md](./SKILL.md)。

## License

MIT
