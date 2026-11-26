---
name: claude-safe-cage
description: >-
  macOS 原生轻量级 Claude 防封铁笼（零虚拟机损耗）全套配置指南与自动化部署工作流。
  覆盖 AdsPower 指纹浏览器隔离、Clash Verge Rev (TUN + Fake-IP) 双通道 IP 门禁锁、
  Claude Code CLI 与 Claude Desktop 桌面版硬代理绑定、洛杉矶/美国时区语言注入、
  OAuth 强制拦截（仅限指纹浏览器授权）以及官方 macOS Seatbelt 沙盒。
  当用户需要配置 Claude Code / Claude 桌面版防封号、隔离多环境、防止误裸连国内 IP 时激活。
---

# Claude Safe Cage — macOS 原生轻量防封铁笼

一套 **0 内存损耗、100% 原生速度** 的 macOS 防封隔离架构，替代重型虚拟机套娃方案，同时保护 **网页端（AdsPower）+ 终端（Claude Code）+ 桌面端（Claude Desktop）** 三端闭环。

## 核心防护架构（5 道防线）

| 防线 | 作用 | 防范风险 |
| :--- | :--- | :--- |
| **① 双通道 IP 门禁锁（Kill-Switch）** | 启动前 0.5 秒同时校验本地代理端口与默认路由（TUN）出口 IP，必须严格等于指定的独享住宅/双 ISP IP | 忘开代理、TUN 异常退出、误切其他地区机场节点导致的裸连封号 |
| **② 运行中硬绑定代理（Fail-Closed）** | CLI 注入 `HTTP/HTTPS/ALL_PROXY`；桌面版注入 Electron `--proxy-server` 与 `--proxy-bypass-list="<-loopback>"` | 运行中途代理崩溃后悄悄回退直连本地物理网卡 |
| **③ OAuth 强制拦截（仅限指纹浏览器）** | 拦截 `open` / `$BROWSER` 对 `claude.ai` 与 `anthropic.com` 的调用，自动复制链接到剪贴板并拒绝拉起宿主机默认 Chrome/Safari | 首次登录或 Token 续期时误弹宿主机浏览器导致关联风控 |
| **④ 进程级时区与语言对齐** | 强制注入 `TZ=<TARGET_TZ>`（如 `America/Los_Angeles`）与 `LANG=en_US.UTF-8`、`--lang=en-US`，不动系统全局时钟 | IP 在美国但客户端上报 `Asia/Shanghai` + `zh-CN` |
| **⑤ 官方 macOS Seatbelt 沙盒 + 关遥测** | 在 `~/.claude/settings.json` 启用 `sandbox.enabled: true` 并关闭非必要遥测与错误上报 | Agent 越权读取敏感文件 + 多余第三方遥测域名探针走错分流规则 |

---

## 一、AdsPower 指纹浏览器配置规范（一环境一号）

1. **新建独立环境**（切勿复用或“复制”曾触发 KYC/风控的旧环境）：
   - **内核**：SunBrowser（最新或次新 Chrome 稳定版）
   - **操作系统**：**macOS**（与真实 Mac 宿主机一致，切忌伪装 Windows）
2. **代理信息**：
   - **代理方式**：自定义
   - **代理类型**：`Socks5`
   - **主机 / 端口**：本机代理端口（如 Clash Verge Rev 默认 `127.0.0.1:7897`）或直连独享代理
   - 点 **「检查代理」** 确认出口 IP 与地区 100% 匹配目标独享 IP
3. **指纹配置（关键 7 项）**：
   - **WebRTC**：`替换`（严禁选“真实”）
   - **时区 / 地理位置 / 语言**：全部勾选 `基于 IP 生成`（地理位置选 `询问`）
   - **Canvas / WebGL 图像 / AudioContext**：全部选 **`噪音（Noise）`**（严禁选“真实”，防止撞宿主机硬件指纹）
   - **端口扫描保护**：`启用`
4. **登号前验真**：先访问 `https://iphey.com` 与 `https://browserleaks.com/webrtc`，确认 IP、时区、语言、WebRTC 无泄露后再登录账号。
5. **删除旧环境后彻底清本地缓存**：
   ```bash
   ls -la "$HOME/Library/Application Support/adspower_global/cwd_global/source/cache"
   # 删除已废弃旧环境对应的缓存目录，并清空 AdsPower 回收站
   ```

---

## 二、一键部署本机防封铁笼（CLI + 桌面版）

运行随附安装脚本（传入你的独享 IP、本地代理端口与目标时区）：

```bash
bash scripts/install-claude-guard.sh \
  --ip "<YOUR_DEDICATED_IP>" \
  --port "7897" \
  --tz "America/Los_Angeles"
```

安装完成后会生成：
- `~/.config/claude-guard/expected_ip`：白名单出口 IP（更换独享 IP 时只需改这一行）
- `~/.local/bin/claude-guard.sh`：双通道 IP 验真与环境变量注入库
- `~/.local/lib/claude-guard-bin/open`：OAuth 弹窗拦截器（阻止拉起宿主机默认浏览器）
- `~/.local/bin/claude`：Claude Code 安全包装器（优先级高于原版 `claude`）
- `~/.local/bin/claude-desktop-safe` 与 `/Applications/Claude Safe.app`：带弹窗拦截与硬代理锁的桌面版启动器
- `~/.claude/settings.json`：官方 macOS 沙盒与去遥测配置

---

## 三、首次授权与日常使用铁律

1. **永远通过 `claude`（已接管）启动终端，通过 `/Applications/Claude Safe.app`（或 `claude-desktop`）启动桌面版**；把原版 `Claude.app` 从 Dock 移除。
2. **所有 OAuth 授权链接**会被自动拦截并复制到剪贴板，直接粘贴进 **AdsPower 专属窗口**点确认即可完成三端闭环。
3. **验证 Fail-Closed 熔断**：
   ```bash
   bash -c 'source "$HOME/.local/bin/claude-guard.sh"; EXPECTED_IP="1.2.3.4"; check_claude_guard'
   ```
   返回 `CLAUDE_GUARD_ERR:...` 且退出码非 0 即说明熔断生效。
4. **日常习惯**：一环境一号、不频繁清 AdsPower Cookie、不切换不同国家节点、登录与支付避免连续失败重试。
