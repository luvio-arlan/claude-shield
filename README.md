# Claude Safe Cage Skill

> macOS 原生轻量级 Claude 防封铁笼（0 虚拟机内存损耗）—— 一键守护 **AdsPower + Claude Code CLI + Claude Desktop** 三端 IP/时区/指纹闭环。

## 为什么不用虚拟机套娃？

如果你在 Mac 上只维护 1–2 个主力 Claude 账号，跑 Lima/Docker 虚拟机不仅常驻吃掉 2–4GB 内存、拖慢大型项目读写，还无法调用 Xcode 等原生环境。

本 Skill 提供一套 **5 道原生硬件级防线**：
1. **双通道 IP 门禁锁（Kill-Switch）**：启动前同时校验本地代理端口和默认路由（TUN）出口 IP，必须严格匹配你的独享 IP，否则红字/弹窗熔断拒绝启动。
2. **运行中硬代理绑定（Fail-Closed）**：CLI 与桌面版（Electron `--proxy-server`）均锁死本地代理端口，代理意外退出时直接断网，绝不回退直连物理网卡。
3. **OAuth 强制拦截（仅限指纹浏览器）**：自动拦截 `claude.ai` / `anthropic.com` 的系统浏览器弹窗，将授权链接复制到剪贴板，强制走 AdsPower 完成闭环授权。
4. **进程级时区 & 语言伪装**：自动注入目标时区（如 `America/Los_Angeles`）与 `en_US.UTF-8`，不影响 macOS 系统时钟。
5. **官方 macOS Seatbelt 沙盒 + 关闭遥测**：写入 `~/.claude/settings.json` 限制越权访问并减少非必要外联。

## 快速安装

```bash
git clone https://github.com/luvio-arlan/claude-safe-cage-skill.git
cd claude-safe-cage-skill

bash scripts/install-claude-guard.sh \
  --ip "<YOUR_DEDICATED_IP>" \
  --port "7897" \
  --tz "America/Los_Angeles"
```

也可以直接将本仓库作为 Agent Skill 安装到 `~/.gemini/config/skills/claude-safe-cage/` 或 `~/.claude/skills/claude-safe-cage/`。

## 完整手册

详细配置规范（含 AdsPower 指纹参数对照表与验真清单）请查看 [SKILL.md](./SKILL.md)。

## 免责声明

本工具仅用于网络代理稳定性校验、进程级环境隔离与本地隐私安全防护。请遵守相关服务条款。
