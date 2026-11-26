---
name: claude-shield
description: >-
  macOS 原生轻量级 Claude Shield 防封安全套件（零虚拟机损耗）全套配置指南与自动化部署工作流。
  覆盖 AdsPower 指纹浏览器隔离、Clash Verge Rev (TUN + Fake-IP) 双通道 IP 门禁锁、
  Claude Code CLI 与 Claude Desktop 桌面版硬代理绑定、原版防误触隐藏、
  二合一原生 SwiftUI App（安全启动器 + 顶部状态栏实时雷达，退出监控后底层防护持续生效）、
  OAuth 强制拦截（仅限指纹浏览器授权）以及官方 macOS Seatbelt 沙盒。
  当用户需要配置 Claude Code / Claude 桌面版防封号、隔离多环境、防止误裸连国内 IP 时激活。
---

# Claude Shield — macOS 原生轻量防封安全套件

一套 **0 虚拟机内存损耗、100% 原生速度** 的 macOS 防封隔离架构，同时守护 **网页端（AdsPower）+ 终端（Claude Code）+ 桌面端（Claude Desktop）** 三端闭环，并将 **安全启动器与状态栏雷达合二为一** 为 `/Applications/Claude Shield.app`。

> **重要设计原则**：退出 `Claude Shield` 状态栏监控 **不会** 撤除任何底层防护——已启动的桌面版硬代理绑定、CLI 双通道 IP 门禁、OAuth 弹窗拦截、原版隐藏仓与 Seatbelt 沙盒全部独立生效。

## 6 道原生防线

| 防线 | 作用 | 防范风险 |
| :--- | :--- | :--- |
| **① 双通道 IP 门禁锁（Kill-Switch）** | 启动前并行校验本地代理端口与默认路由（TUN）出口 IP，必须严格等于白名单独享 IP | 忘开代理、TUN 异常退出、误切机场节点导致裸连封号 |
| **② 运行中硬绑定代理（Fail-Closed）** | CLI 注入 `HTTP/HTTPS/ALL_PROXY`；桌面版注入 Electron `--proxy-server` + `--proxy-bypass-list="<-loopback>"` | 运行中途代理崩溃后悄悄回退直连物理网卡 |
| **③ 原版防误触隔离 + 二合一原生 App** | 将原版 `Claude.app` 移入 `~/.local/apps/`（加 `.metadata_never_index` 禁止 Spotlight 索引，保留官方签名），`/Applications/` 仅保留单一 `Claude Shield.app` | 手滑点到原版桌面客户端瞬间裸连 |
| **④ OAuth 强制拦截（仅限指纹浏览器）** | 拦截 `open` / `$BROWSER` 对 `claude.ai` 与 `anthropic.com` 的调用，自动复制链接到剪贴板并拒绝拉起宿主机 Chrome/Safari | 首次登录或续期时误弹宿主机浏览器导致关联风控 |
| **⑤ 进程级时区/语言对齐 + Seatbelt 沙盒** | 动态注入目标时区（`~/.config/claude-guard/target_tz`）、`LANG=en_US.UTF-8`、`--lang=en-US`（不动系统时钟），开启 `~/.claude/settings.json` 官方沙盒与去遥测 | IP 与客户端时区打架、Agent 越权读写或多余遥测外联 |
| **⑥ 原生 SwiftUI 状态栏雷达（`Claude Shield.app` v2.1）** | 明暗自适应毛玻璃 Popover（<20MB 内存），每 15 秒并行巡检双通道 IP + 真实 1-RTT 延迟 + 6 层防线矩阵，内置 **IP 漂移自动急停（Auto-Kill）**、一键聚焦与诊断复制 | 后台节点悄悄漂移时肉眼无感知，或巡检异常未及时阻断 |

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
4. **删除旧环境后彻底清本地缓存**：
   ```bash
   ls -la "$HOME/Library/Application Support/adspower_global/cwd_global/source/cache"
   # 删除已废弃旧环境对应的缓存目录，并清空 AdsPower 回收站
   ```

---

## 二、一键部署全套防封套件（CLI + 二合一原生 App）

```bash
bash scripts/install.sh \
  --ip "<YOUR_DEDICATED_IP>" \
  --port "7897" \
  --tz "America/Los_Angeles"
```

安装完成后会生成：
- `~/.config/claude-guard/expected_ip`：白名单出口 IP（换 IP 只改这一行）
- `~/.config/claude-guard/proxy_port`：本地代理端口（默认 `7897`）
- `~/.config/claude-guard/target_tz`：目标时区（默认 `America/Los_Angeles`）
- `~/.local/bin/claude-guard.sh`：双通道 IP 验真与环境注入库
- `~/.local/lib/claude-guard-bin/open`：OAuth 弹窗拦截器
- `~/.local/bin/claude`：Claude Code 安全包装器
- `/Applications/Claude Shield.app`：二合一原生 App（安全启动器 + 状态栏实时监控雷达；原版已隐藏至 `~/.local/apps/Claude.app`，并自动清理旧版 `Claude Safe.app` / `Claude Guard.app`）
- `~/.claude/settings.json`：官方 macOS 沙盒与去遥测配置

---

## 三、首次授权与日常铁律

1. **终端授权**：运行 `claude auth login --claudeai`，拦截器自动拦截默认浏览器并复制链接，粘贴进 **AdsPower 专属窗口**点授权，再把授权码回填终端。
2. **桌面版授权**：通过 `Claude Shield.app` 启动，**选「Continue with email」邮箱验证码登录**（去 AdsPower 的 Gmail 收验证码），切勿点「Continue with Google」拉起宿主机默认浏览器。
3. **验证 Fail-Closed 熔断**：
   ```bash
   bash -c 'source "$HOME/.local/bin/claude-guard.sh"; EXPECTED_IP="1.2.3.4"; check_claude_guard'
   ```
   返回 `CLAUDE_GUARD_ERR:...` 且退出码非 0 即说明熔断生效。
