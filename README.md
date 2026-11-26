<p align="center">
  <img src="./assets/icon.png" width="128" height="128" alt="Claude Shield Icon" />
</p>

<h1 align="center">Claude Shield v3.0</h1>

<p align="center">
  <strong>macOS 原生轻量级 Claude 防封安全套件（Rust 核心引擎 · SwiftUI 商业级状态栏雷达 · 0 虚拟机损耗）</strong>
</p>

<p align="center">
  Rust 极速三点门禁 · ip.net.coffee 级多源 IP 纯净度体检 · 真实 API 1-RTT 延迟校准 · 原版图标彻底隐藏 · 开机自启 + 每日巡检 · 唤醒/断网瞬间急停
</p>

---

## 为什么升级到 v3.0（Rust Core + SwiftUI）？

用虚拟机套娃（Lima / Docker）跑 Claude Code 动辄常驻 2–4GB 内存、拖慢 I/O；而直接裸跑又面临 **IP 漂移、DNS/IPv6 泄露、Mac 睡眠唤醒瞬间走物理网卡、Claude 自动更新重新生成原版图标、机房 IP 欺诈分飙升** 等隐蔽封号陷阱。

**Claude Shield v3.0** 将底层网络探针、门禁校验、多源纯净度引擎与进程审计全部使用 **原生 Rust (`claude-shield-core`)** 重写，并与 **原生 SwiftUI 状态栏雷达 (`Claude Shield.app`)** 深度整合：

- **极速零损耗**：单二进制 Rust 核心（LTO + Strip 优化），无 Bash/curl 频繁 Fork 开销，常驻内存 **< 20MB**，App 启动读取本地缓存 **< 50ms 瞬开**。
- **真实延迟校准**：采用 **HTTP/2 Keep-Alive 预热 + 双连发取最优值** 直测 `api.anthropic.com`，剔除冷 TCP/TLS 握手虚高误差并计算抖动（`API 185ms ±4`）。
- **内置 `ip.net.coffee/claude` 级纯净度体检**：并发融合 **Claude Cloudflare Edge (`claude.ai/cdn-cgi/trace`) + IPPure + ProxyCheck + IP-API + IPInfo + 双通道 EDNS DNS 泄露检测 + IPv6 泄露探测 + 时区一致性审计**，实时输出 `0-100` 纯净度评分与 `S/A/B/C/F` 风险评级。
- **全天候零暴露保护**：安装后自动彻底隐藏原版 `Claude.app`（迁移隐藏仓 + `chflags hidden` + `lsregister -u` 注销 Spotlight/Launchpad + 清理 Dock），支持 **开机自启雷达 + 每日自动巡检**，并在 **Mac 唤醒 / Wi-Fi 切换 / 进程未受保护** 时瞬间执行 Fail-Closed 自动急停。

> **核心原则：退出状态栏监控，底层防护依然全程在线。**
> 关闭菜单栏雷达仅退出 UI——已启动的桌面版硬代理绑定、Rust CLI 门禁、OAuth 弹窗拦截、原版隐藏隔离仓、Seatbelt 沙盒以及 LaunchAgent 每日巡检全部独立生效。

---

## 九道原生防封防线

| 防线 | 机制 | 解决什么痛点 |
| :--- | :--- | :--- |
| **① 三点出口 IP 门禁锁（Rust 极速校验）** | 启动前并行校验 **本地代理 → `claude.ai/cdn-cgi/trace` 边缘出口** 与 **系统默认路由（TUN）出口**，严格匹配白名单且阻断 CN/HK/MO 等封禁地区 | 忘开代理、TUN 异常退出、分流规则错乱导致 `claude.ai` 走错节点 |
| **② 运行中硬代理 + 零泄露隔离** | CLI 注入 `HTTP/HTTPS/ALL_PROXY` + `NODE_OPTIONS="--dns-result-order=ipv4first"`（封死 Node IPv6 泄露）；桌面版注入 `--proxy-server` + `--disable-quic` + `--force-webrtc-ip-handling-policy=disable_non_proxied_udp` | 运行中途代理崩溃回退直连，或 Electron/Node 通过 QUIC/WebRTC/IPv6 泄露真实 IP |
| **③ `ip.net.coffee` 级多源 IP 纯净度引擎** | 并行探测 IPPure 欺诈分、ProxyCheck 风险与住宅属性、IP-API/IPInfo 机房与隐私标记、Proxy & TUN 双通道 EDNS DNS 泄露、原生 IPv6 泄露与时区偏移 | 误用被污染机房 IP、隐藏 DNS 泄露或节点突然掉纯度却毫不知情 |
| **④ 原版图标彻底隐藏 + 自动回血隔离** | 安装时自动将 `/Applications/Claude.app` 移入 `~/.local/apps/`，叠加 `.metadata_never_index` + `chflags hidden` + `lsregister -u` + 自动清理 Dock；巡检若发现自动更新重新生成原版图标则立即重新隔离 | 手滑点开原版客户端瞬间裸连，或自动更新后在启动台重新冒出双图标 |
| **⑤ OAuth 强制拦截（AdsPower-Only）** | 拦截 `open` / `$BROWSER` 对 `claude.ai`、`anthropic.com`、`claude.com` 的系统浏览器拉起，自动复制授权链接到剪贴板 | 登录/续期时误弹宿主机浏览器造成跨号指纹关联 |
| **⑥ 睡眠唤醒 & 网络切换瞬间急停** | 原生接入 macOS `NSWorkspace.didWakeNotification` 与 `NWPathMonitor`，电脑休眠唤醒或切网瞬间立即复检，发现 IP 漂移或未受保护进程（含桌面版 & 裸奔 CLI）0 秒急停 | MacBook 合盖唤醒瞬间 Clash 尚未接管导致后台桌面版裸连物理网卡 |
| **⑦ 进程级时区/语言对齐 + 零遥测沙盒** | 自动核对 `target_tz` 与出口 IP 真实时区，注入 `TZ` / `en_US.UTF-8`，开启 Seatbelt 沙盒并关闭所有非必要遥测与后台自动更新（`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`、`DISABLE_AUTOUPDATER=1`） | IP 与时区打架、多余遥测外联或后台未走代理更新 |
| **⑧ 开机自启雷达 + 每日安全巡检** | 注册轻量 macOS LaunchAgents：登录静默启动状态栏雷达（面板可一键开关），每日定时自动执行深度纯净度体检与防线自愈，仅在发现风险时推送原生通知 | 重启电脑忘开监控，或节点长期运行后纯净度悄悄劣化 |
| **⑨ 商业级双页签 SwiftUI 状态栏雷达** | 明暗自适应毛玻璃 Popover（实时雷达 / 纯净度体检双页签），支持 **API 真实 1-RTT 延迟与抖动**、纯净度得分环、一键巡检、一键 2x Retina 诊断截图 | 状态不透明、冷建连测速虚高、排障麻烦 |

---

## 一键安装

> 前置要求：macOS 13+、Xcode Command Line Tools（`swiftc`）、Rust 工具链（`brew install rust`，用于编译原生 Rust 核心引擎），以及 Clash Verge Rev / Mihomo 等支持本地代理端口 + TUN 模式的客户端。

```bash
git clone https://github.com/luvio-arlan/claude-shield.git
cd claude-shield

bash scripts/install.sh \
  --ip "<YOUR_DEDICATED_IP>" \
  --port "7897" \
  --tz "America/Los_Angeles"
```

可选参数：
- `--no-autostart`：跳过配置开机自启状态栏雷达（安装后也可在菜单栏面板随时开关）
- `--no-patrol`：跳过配置每日定时自动巡检

安装完成后会自动生成/配置：
- `~/.local/bin/claude-shield-core` — **原生 Rust 防封核心引擎**（同时打包进 `/Applications/Claude Shield.app`）
- `~/.local/bin/claude-shield` — 终端诊断命令（支持 `purity` / `patrol` / `gate` / `hide-original`）
- `/Applications/Claude Shield.app` — **二合一原生 App**（安全启动器 + 状态栏实时雷达 + 纯净度体检）
- `~/.local/bin/claude` — Rust 加速的 Claude Code CLI 安全门禁包装器（确保 `$HOME/.local/bin` 位于 `PATH` 最前）
- `~/.local/lib/claude-guard-bin/open` — OAuth 系统浏览器弹窗拦截器
- `~/.local/apps/Claude.app` — 原版桌面端隐藏隔离仓（已设 `hidden` 并注销 Spotlight/Launchpad）
- `~/Library/LaunchAgents/com.local.claude.shield.{radar,patrol}.plist` — 开机自启雷达 & 每日巡检守护
- `~/.claude/settings.json` — 官方 macOS Seatbelt 沙盒与全量去遥测配置

> 也兼容作为 AI Agent Skill 使用：直接同步至 `~/.gemini/config/skills/claude-shield/` 或 `~/.claude/skills/claude-shield/`，详见 [SKILL.md](./SKILL.md)。

---

## 日常使用与命令

1. **桌面端**：从 Spotlight / Launchpad 打开 `Claude Shield`，Rust 核心毫秒级验真并安全拉起桌面版；点击菜单栏 `🟢 LA 185ms · S` 可切换 **「实时雷达」** 与 **「纯净度体检」** 面板。
2. **终端纯净度深度体检（`ip.net.coffee` 级）**：
   ```bash
   claude-shield purity
   ```
3. **立即执行全链路巡检（含自动隐藏暴露的原版 App）**：
   ```bash
   claude-shield patrol
   ```
4. **终端 Claude Code**：直接运行 `claude`，自动经由 Rust 核心极速验真并注入全套防封与 IPv4-Only 环境。
5. **仅启动状态栏雷达（不拉起桌面版）**：
   ```bash
   open -g -a "/Applications/Claude Shield.app" --args --radar-only
   ```
6. **验证 Fail-Closed 熔断是否生效**：
   ```bash
   bash -c 'source "$HOME/.local/bin/claude-guard.sh"; EXPECTED_IP="1.2.3.4"; check_claude_guard'
   ```
   返回 `CLAUDE_GUARD_ERR:...` 且退出码非 0 即说明熔断生效。

---

## 完整防封配置手册（含 AdsPower 指纹规范）

完整的 AdsPower 指纹 7 项配置、Clash TUN + Fake-IP 防 DNS/IPv6 泄露规范与排障指南请查阅 [SKILL.md](./SKILL.md)。

## License

MIT
