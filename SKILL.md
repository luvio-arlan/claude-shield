---
name: claude-shield
description: >-
  macOS 原生轻量级 Claude Shield v3.0 防封安全套件（Rust 核心引擎 + SwiftUI 状态栏雷达，零虚拟机损耗）全套配置指南与自动化部署工作流。
  覆盖 AdsPower 指纹浏览器隔离、Clash Verge Rev (TUN + Fake-IP + 防 DNS/IPv6 泄露) 三点 IP 门禁锁、
  ip.net.coffee 级多源 IP 纯净度体检、Claude Code CLI 与 Claude Desktop 硬代理绑定、原版图标彻底隐藏防误触、
  开机自启雷达、每日安全巡检、睡眠唤醒瞬间急停、OAuth 强制拦截以及官方 macOS Seatbelt 沙盒。
  当用户需要配置 Claude Code / Claude 桌面版防封号、隔离多环境、检测 IP 纯净度或防止误裸连国内 IP 时激活。
---

# Claude Shield v3.0 — macOS 原生轻量防封安全套件（Rust + SwiftUI）

一套 **0 虚拟机内存损耗、Rust 极速内核、100% 原生速度** 的 macOS 防封隔离架构，同时守护 **网页端（AdsPower）+ 终端（Claude Code）+ 桌面端（Claude Desktop）** 三端闭环，内置 **`ip.net.coffee/claude` 级多源 IP 纯净度引擎**、**开机自启雷达** 与 **每日安全巡检**。

> **重要设计原则**：退出 `Claude Shield` 状态栏监控 **不会** 撤除任何底层防护——已启动的桌面版硬代理绑定、Rust CLI 门禁、OAuth 弹窗拦截、原版隐藏隔离仓、Seatbelt 沙盒与每日定时巡检全部独立生效。

## 9 道原生防线

| 防线 | 作用 | 防范风险 |
| :--- | :--- | :--- |
| **① 三点 IP 门禁锁（Rust 极速引擎）** | 并行校验代理访问 `claude.ai/cdn-cgi/trace` 与默认路由（TUN）出口 IP，严格匹配白名单且阻断 CN/HK/MO 等封禁区 | 忘开代理、TUN 退出、Clash 分流错乱导致 `claude.ai` 走错节点 |
| **② 运行中硬绑定代理 + IPv4/UDP 封闭** | CLI 注入代理与 `NODE_OPTIONS="--dns-result-order=ipv4first"`；桌面版注入 `--proxy-server`、`--disable-quic`、`--force-webrtc-ip-handling-policy=disable_non_proxied_udp` | 运行中代理崩溃回退直连，或 QUIC/WebRTC/IPv6 泄露真实 IP |
| **③ `ip.net.coffee` 级多源纯净度体检** | 融合 Claude Edge + IPPure + ProxyCheck + IP-API + IPInfo + Proxy/TUN 双通道 EDNS DNS 泄露 + IPv6 泄露 + 时区对齐，输出 0–100 评分与 S/A/B/C/F 评级 | 节点被标机房/代理、欺诈分飙升、隐藏 DNS/IPv6 泄露 |
| **④ 原版图标彻底隐藏 + 自动回血** | 自动迁移 `/Applications/Claude.app` → `~/.local/apps/`，叠加 `chflags hidden` + `.metadata_never_index` + `lsregister -u` 注销索引 + 自动清理 Dock；巡检发现自动更新复原原版图标即自动重隐 | 手滑点开原版客户端裸连，或自动更新后出现双图标 |
| **⑤ OAuth 强制拦截（仅限指纹浏览器）** | 拦截 `open` / `$BROWSER` 对 `claude.ai`、`anthropic.com`、`claude.com` 的调用，自动复制链接到剪贴板并拒绝拉起宿主机浏览器 | 登录/续期时误弹宿主机浏览器导致关联风控 |
| **⑥ 唤醒 & 切网瞬间急停（Fail-Closed）** | 监听 macOS `didWakeNotification` 与 `NWPathMonitor`，休眠唤醒或切网瞬间立即复检；发现 IP 漂移或未受保护进程（含桌面版与裸奔 CLI）0 秒自动急停 | MacBook 合盖唤醒瞬间代理尚未接管导致后台裸连 |
| **⑦ 进程级时区/语言对齐 + 零遥测沙盒** | 核对 `target_tz` 与出口 IP 真实时区，注入 `TZ`、`en_US.UTF-8`，开启 `~/.claude/settings.json` Seatbelt 沙盒并关闭所有遥测与后台自动更新 | IP 与客户端时区打架、Agent 越权或多余遥测外联 |
| **⑧ 开机自启雷达 + 每日巡检守护** | 自动部署 LaunchAgents：登录静默启动状态栏雷达（UI 内可一键开关）+ 每日定时纯净度与防线巡检（异常时推送 macOS 通知） | 重启忘开防护或节点纯净度悄悄退化 |
| **⑨ 双页签商业级 SwiftUI 雷达（v3.0）** | 启动读取缓存 <50ms 瞬开，支持「实时雷达 / 纯净度体检」双页签、校准后的 Anthropic API 真实 1-RTT 延迟（含抖动）与 2x Retina 诊断截图 | 冷建连测速虚高、纯净度不可视 |

---

## 一、AdsPower 指纹浏览器配置规范（一环境一号）

1. **新建独立环境**（切勿复用或“复制”曾触发 KYC/风控的旧环境）：
   - **内核**：SunBrowser（最新或次新 Chrome 稳定版）
   - **操作系统**：**macOS**（与真实 Mac 宿主机一致，切忌伪装 Windows）
2. **代理信息**：
   - **代理方式**：自定义 → **Socks5** → `127.0.0.1:7897`（或直连独享代理）
   - 点 **「检查代理」** 确认出口 IP 与地区 100% 匹配目标独享 IP
3. **指纹配置（关键 7 项）**：
   - **WebRTC**：`替换`（严禁选“真实”）
   - **时区 / 地理位置 / 语言**：全部勾选 `基于 IP 生成`（地理位置选 `询问`）
   - **Canvas / WebGL 图像 / AudioContext**：全部选 **`噪音（Noise）`**（严禁选“真实”，防止撞宿主机硬件指纹）
   - **端口扫描保护**：`启用`
4. **Clash Verge Rev 防泄露关键项**：
   - 开启 **TUN 模式**（`stack: gvisor` 或 `system`，开启 `dns-hijack`）
   - 关闭 **IPv6**（`ipv6: false`），杜绝原生 IPv6 绕过
   - `dns.enhanced-mode: fake-ip`，且 Anthropic/Claude 域名强制走海外加密 DoH/DoT（严禁国内 DNS 解析）

---

## 二、一键部署全套防封套件（Rust Core + SwiftUI App）

```bash
bash scripts/install.sh \
  --ip "<YOUR_DEDICATED_IP>" \
  --port "7897" \
  --tz "America/Los_Angeles"
```

安装完成后会生成：
- `~/.local/bin/claude-shield-core` & `~/.local/bin/claude-shield`：原生 Rust 防封核心与 CLI 体检命令
- `~/.config/claude-guard/`：`expected_ip`、`proxy_port`、`target_tz`、巡检日志 `patrol-history.jsonl`
- `~/.local/bin/claude-guard.sh`：Rust 加速的双通道验真与环境注入库
- `~/.local/lib/claude-guard-bin/open`：OAuth 弹窗拦截器
- `~/.local/bin/claude`：Rust 极速启动的 Claude Code 安全包装器
- `/Applications/Claude Shield.app`：二合一原生 App（原版已彻底隐藏至 `~/.local/apps/Claude.app` 并注销 Spotlight/Launchpad）
- `~/Library/LaunchAgents/com.local.claude.shield.{radar,patrol}.plist`：开机自启与每日巡检
- `~/.claude/settings.json`：官方 macOS Seatbelt 沙盒与去遥测配置

---

## 三、日常检查与铁律

1. **深度纯净度体检**：运行 `claude-shield purity`（或在菜单栏点击「纯净度体检」），确保评分 ≥ 80（A/S 级）、DNS/IPv6 零泄露、时区 100% 对齐。
2. **终端授权**：运行 `claude auth login --claudeai`，拦截器自动复制链接，粘贴进 **AdsPower 专属窗口**点授权。
3. **桌面版授权**：通过 `Claude Shield.app` 启动，**选「Continue with email」邮箱验证码登录**，切勿点 Google 登录拉起宿主机默认浏览器。
4. **验证 Fail-Closed 熔断**：
   ```bash
   bash -c 'source "$HOME/.local/bin/claude-guard.sh"; EXPECTED_IP="1.2.3.4"; check_claude_guard'
   ```
   返回 `CLAUDE_GUARD_ERR:...` 且退出码非 0 即说明熔断生效。
