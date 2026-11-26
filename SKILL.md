---
name: claude-safe-cage
description: >-
  macOS 原生轻量级 Claude 防封铁笼（零虚拟机损耗）全套配置指南与自动化部署工作流。
  覆盖 AdsPower 指纹浏览器隔离、Clash Verge Rev (TUN + Fake-IP) 双通道 IP 门禁锁、
  Claude Code CLI 与 Claude Desktop 桌面版硬代理绑定、原版防误触隐藏、
  macOS 顶部状态栏实时环境雷达（Swift 原生 App）、OAuth 强制拦截（仅限指纹浏览器授权）
  以及官方 macOS Seatbelt 沙盒。
  当用户需要配置 Claude Code / Claude 桌面版防封号、隔离多环境、防止误裸连国内 IP 时激活。
---

# Claude Safe Cage — macOS 原生轻量防封铁笼（终极版）

一套 **0 虚拟机内存损耗、100% 原生速度** 的 macOS 防封隔离架构，同时守护 **网页端（AdsPower）+ 终端（Claude Code）+ 桌面端（Claude Desktop）** 三端闭环，并附带 **macOS 顶部状态栏实时监控雷达 App**。

## 6 道原生硬件级防线

| 防线 | 作用 | 防范风险 |
| :--- | :--- | :--- |
| **① 双通道 IP 门禁锁（Kill-Switch）** | 启动前 0.5 秒同时校验本地代理端口与默认路由（TUN）出口 IP，必须严格等于白名单独享 IP | 忘开代理、TUN 异常退出、误切机场节点导致裸连封号 |
| **② 运行中硬绑定代理（Fail-Closed）** | CLI 注入 `HTTP/HTTPS/ALL_PROXY`；桌面版注入 Electron `--proxy-server` + `--proxy-bypass-list="<-loopback>"` | 运行中途代理崩溃后悄悄回退直连物理网卡 |
| **③ 原版防误触隔离 + 无跳动安全壳** | 将原版 `Claude.app` 移入 `~/.local/apps/`（加 `.metadata_never_index` 禁止 Spotlight 索引，保留官方签名），`/Applications/` 仅保留 `LSUIElement=true` 零跳动 `Claude Safe.app` | 手滑点到原版桌面客户端瞬间裸连 |
| **④ OAuth 强制拦截（仅限指纹浏览器）** | 拦截 `open` / `$BROWSER` 对 `claude.ai` 与 `anthropic.com` 的调用，自动复制链接到剪贴板并拒绝拉起宿主机 Chrome/Safari | 首次登录或续期时误弹宿主机浏览器导致关联风控 |
| **⑤ 进程级时区/语言对齐 + Seatbelt 沙盒** | 注入 `TZ=America/Los_Angeles`、`LANG=en_US.UTF-8`、`--lang=en-US`（不动系统时钟），开启 `~/.claude/settings.json` 官方沙盒与去遥测 | IP 与客户端时区打架、Agent 越权读写或多余遥测外联 |
| **⑥ 状态栏实时雷达（`Claude Guard.app`）** | 原生 Swift 编译（<15MB 内存），每 15 秒自动巡检双通道 IP、OAuth 锁、原版隔离与沙盒状态，正常显示 `🟢 LA Safe`，异常秒变 `🔴 IP 异常!` | 后台节点悄悄漂移时肉眼无感知 |

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

## 二、一键部署全套防封铁笼（CLI + 桌面版 + 状态栏雷达）

```bash
bash scripts/install-claude-guard.sh \
  --ip "<YOUR_DEDICATED_IP>" \
  --port "7897" \
  --tz "America/Los_Angeles"
```

安装完成后会生成：
- `~/.config/claude-guard/expected_ip`：白名单出口 IP（换 IP 只改这一行）
- `~/.local/bin/claude-guard.sh`：双通道 IP 验真与环境注入库
- `~/.local/lib/claude-guard-bin/open`：OAuth 弹窗拦截器
- `~/.local/bin/claude`：Claude Code 安全包装器
- `/Applications/Claude Safe.app`：零跳动桌面版安全入口（原版已隐藏至 `~/.local/apps/Claude.app`）
- `/Applications/Claude Guard.app`：原生 Swift 状态栏实时监控雷达 App
- `~/.claude/settings.json`：官方 macOS 沙盒与去遥测配置

---

## 三、首次授权与日常铁律

1. **终端授权**：运行 `claude auth login --claudeai`，拦截器自动拦截默认浏览器并复制链接，粘贴进 **AdsPower 专属窗口**点授权，再把授权码回填终端。
2. **桌面版授权**：通过 `Claude Safe.app` 启动，**选「Continue with email」邮箱验证码登录**（去 AdsPower 的 Gmail 收验证码），切勿点「Continue with Google」拉起宿主机默认浏览器。
3. **验证 Fail-Closed 熔断**：
   ```bash
   bash -c 'source "$HOME/.local/bin/claude-guard.sh"; EXPECTED_IP="1.2.3.4"; check_claude_guard'
   ```
   返回 `CLAUDE_GUARD_ERR:...` 且退出码非 0 即说明熔断生效。
