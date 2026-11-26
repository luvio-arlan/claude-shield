<p align="center">
  <img src="./assets/icon.png" width="128" height="128" alt="Claude Shield Icon" />
</p>

<h1 align="center">Claude Shield</h1>

<p align="center">
  <strong>macOS 原生轻量级 Claude 防封安全套件（0 虚拟机损耗 · 启动器与状态栏雷达二合一）</strong>
</p>

<p align="center">
  双通道 IP 门禁锁 · 运行中硬代理绑定 · 原版隐藏防误触 · OAuth 指纹浏览器拦截 · Seatbelt 沙盒 · 原生 SwiftUI 状态栏雷达
</p>

---

## 为什么做 Claude Shield？

用虚拟机套娃（Lima / Docker）跑 Claude Code 动辄常驻 2–4GB 内存、拖慢大型项目 I/O，还调不动 macOS 原生工具链；而直接裸跑又最怕某天忘开代理、节点悄悄漂移、或手滑点开原版桌面端瞬间裸连触发风控。

**Claude Shield** 100% 基于 macOS 原生机制构建，整套常驻内存 **< 20MB**，将 **安全启动器** 与 **顶部状态栏实时监控雷达** 合二为一成单个原生 App（`Claude Shield.app`），同时守护 **网页端（AdsPower）+ 终端（Claude Code）+ 桌面端（Claude Desktop）**。

> **核心特性：退出状态栏监控，底层防护依然全程在线。**
> 关闭菜单栏雷达仅退出监控界面——已启动的桌面版硬代理绑定、Claude Code CLI 双通道 IP 门禁、OAuth 弹窗拦截、原版隐藏隔离仓以及 macOS Seatbelt 沙盒全部独立生效，永不失效。

---

## 六道原生防线

| 防线 | 机制 | 解决什么痛点 |
| :--- | :--- | :--- |
| **① 双通道 IP 门禁锁（Kill-Switch）** | 启动前并行校验本地代理端口（如 `:7897`）与系统默认路由（TUN）出口 IP，必须严格等于白名单独享 IP | 忘开代理、TUN 异常退出或误切机场节点导致裸连 |
| **② 运行中硬代理绑定 + 零泄漏网络隔离** | CLI 注入 `HTTP/HTTPS/ALL_PROXY`；桌面版注入 `--proxy-server` + `--disable-quic`（防 UDP/QUIC 绕过）+ `--force-webrtc-ip-handling-policy=disable_non_proxied_udp`（配合 TUN + Fake-IP 封死 DNS 泄漏） | 运行中途代理崩溃回退直连，或 Electron 通过 QUIC/WebRTC 悄悄漏出真实 IP |
| **③ 二合一原生 App + 原版防误触隐藏** | 自动将原版 `Claude.app` 移入隐藏仓 `~/.local/apps/`（禁 Spotlight 索引、保留官方签名）；`/Applications` 仅保留零跳动的 `Claude Shield.app` | 手滑点开原版客户端裸连，或在应用栏里出现两个割裂的图标 |
| **④ OAuth 强制拦截（AdsPower-Only）** | 拦截 `open` / `$BROWSER` 对 `claude.ai` 与 `anthropic.com` 的拉起，自动复制授权链接到剪贴板 | 首次登录/续期时误弹宿主机浏览器导致环境关联 |
| **⑤ 进程级时区/语言对齐 + Seatbelt 沙盒** | 动态注入目标时区与 `en-US`（不改动系统时钟），开启 `~/.claude/settings.json` 官方沙盒并禁用遥测 | IP 地区与客户端时区冲突、Agent 越权读写或多余遥测外联 |
| **⑥ 商业级 SwiftUI 状态栏雷达** | 原生毛玻璃 Popover（明暗模式自适应），每 15 秒并行探测双通道 IP、**真实 Anthropic API 1-RTT 延迟**（双步 HTTP/2 Keep-Alive 去握手误差）与**运行中进程代理绑定审计**，内置零误杀 **IP 漂移自动急停** | 后台节点漂移或误启未绑定代理进程时肉眼无感知，或冷建连测速虚高 |

---

## 一键安装

> 前置要求：macOS 13+、Xcode Command Line Tools（`swiftc`），以及 Clash Verge Rev / Mihomo 等支持本地代理端口 + TUN 模式的客户端。

```bash
git clone https://github.com/luvio-arlan/claude-shield.git
cd claude-shield

bash scripts/install.sh \
  --ip "<YOUR_DEDICATED_IP>" \
  --port "7897" \
  --tz "America/Los_Angeles"
```

安装完成后会自动生成/配置：
- `/Applications/Claude Shield.app` — **二合一原生 App**（从 Spotlight / Launchpad 打开即验真并安全启动 Claude 桌面版，同时常驻顶部状态栏雷达；再次点击直接聚焦/拉起桌面版）
- `~/.config/claude-guard/` — 白名单 IP（`expected_ip`）、代理端口（`proxy_port`）、目标时区（`target_tz`），换节点只需修改对应文件
- `~/.local/bin/claude` — Claude Code CLI 安全门禁包装器（请确保 `$HOME/.local/bin` 位于 `PATH` 最前）
- `~/.local/lib/claude-guard-bin/open` — OAuth 系统浏览器弹窗拦截器
- `~/.local/apps/Claude.app` — 原版桌面端隐藏隔离仓
- `~/.claude/settings.json` — 官方 macOS Seatbelt 沙盒与去遥测配置

> 也兼容作为 AI Agent Skill 使用：直接将本仓库放入 `~/.gemini/config/skills/claude-shield/` 或 `~/.claude/skills/claude-shield/`，详见 [SKILL.md](./SKILL.md)。

---

## 日常使用与验真

1. **桌面端**：直接打开 `Claude Shield`（Spotlight / Launchpad），自动验真双通道 IP 并安全拉起 Claude 桌面版；点击顶部菜单栏 `🟢 LA 220ms` 可随时查看 6 层防线矩阵、切换 IP 漂移自动急停或复制诊断快照。
2. **终端 CLI**：正常执行 `claude`，启动前自动执行双通道 IP 门禁，通过后显示绿标并放行；首次授权执行 `claude auth login --claudeai`，链接会自动复制到剪贴板，粘贴进 AdsPower 指纹浏览器完成授权即可。
3. **仅启动状态栏雷达（不自动拉起桌面版）**：
   ```bash
   open -g -a "/Applications/Claude Shield.app" --args --radar-only
   ```
4. **验证 Fail-Closed 熔断是否生效**：
   ```bash
   bash -c 'source "$HOME/.local/bin/claude-guard.sh"; EXPECTED_IP="1.2.3.4"; check_claude_guard'
   ```
   返回 `CLAUDE_GUARD_ERR:...` 且退出码非 0 即说明熔断正常。

---

## 完整防封配置手册（含 AdsPower 指纹规范）

完整的 AdsPower 指纹 7 项配置、旧环境缓存清理与排障指南请查阅 [SKILL.md](./SKILL.md)。

## License

MIT
