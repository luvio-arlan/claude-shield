import Cocoa
import SwiftUI

// MARK: - Popover Telemetry, Defense Matrix, Purity & Diagnostic Share Card

extension ShieldPopoverView {
    var networkTelemetryRow: some View {
        HStack(spacing: 8) {
            tunnelCard(
                title: "Claude 边缘 :\(vm.snapshot.proxy_port)",
                ip: vm.snapshot.proxy.ip,
                subtitle: vm.snapshot.claude_edge.colo.map { "CF \($0) · \(vm.snapshot.claude_edge.loc ?? "")" },
                latency: vm.snapshot.proxy.latency_ms,
                ok: vm.snapshot.proxyOK,
                icon: "arrow.triangle.branch"
            )
            tunnelCard(
                title: "TUN 默认路由",
                ip: vm.snapshot.tun.ip,
                subtitle: vm.snapshot.tun.colo.map { "CF \($0) · \(vm.snapshot.tun.loc ?? "")" },
                latency: vm.snapshot.tun.latency_ms,
                ok: vm.snapshot.tunOK,
                icon: "shield.lefthalf.filled"
            )
        }
    }

    private func tunnelCard(title: String, ip: String, subtitle: String?, latency: Int?, ok: Bool, icon: String) -> some View {
        let dotColor: Color = ok ? safeGreen : dangerRed
        return VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 5) {
                Circle().fill(dotColor).frame(width: 7, height: 7)
                Text(title)
                    .font(.system(size: 10.5, weight: .semibold))
                    .foregroundColor(labelColor)
                    .lineLimit(1)
                Spacer(minLength: 3)
                if let ms = latency {
                    let lc = latencyColor(ms)
                    Text(verbatim: "\(ms)ms")
                        .font(.system(size: 9.5, weight: .bold, design: .monospaced))
                        .foregroundColor(lc)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(Capsule().fill(lc.opacity(isDark ? 0.18 : 0.10)))
                }
            }

            HStack(spacing: 5) {
                Image(systemName: icon)
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundColor(dotColor)
                Text(ip)
                    .font(.system(size: 12, weight: .semibold, design: .monospaced))
                    .foregroundColor(.primary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
            }

            if let sub = subtitle {
                Text(sub)
                    .font(.system(size: 9.5, weight: .medium, design: .monospaced))
                    .foregroundColor(labelColor)
                    .lineLimit(1)
            }
        }
        .padding(.horizontal, 11)
        .padding(.vertical, 9.5)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 13, style: .continuous).fill(cardSurface))
        .overlay(RoundedRectangle(cornerRadius: 13, style: .continuous).strokeBorder(palette.cardSpecularBorder, lineWidth: 0.85))
        .shadow(color: cardShadow, radius: 7, y: 2)
    }

    var defenseMatrixGrid: some View {
        let d = vm.snapshot.defenses
        return VStack(spacing: 7) {
            HStack(spacing: 8) {
                let tzOK = vm.purity?.timezone_aligned ?? true
                metricTile(
                    icon: "globe.americas.fill",
                    title: "时区与语言",
                    value: "\(vm.snapshot.region_short) · en-US",
                    ok: tzOK
                )
                metricTile(
                    icon: "lock.shield.fill",
                    title: "OAuth 门禁",
                    value: d.oauth_locked ? "AdsPower-Only" : "未锁定",
                    ok: d.oauth_locked
                )
            }
            HStack(spacing: 8) {
                metricTile(
                    icon: "eye.slash.fill",
                    title: "原版隐藏仓",
                    value: d.original_hidden ? "已隐藏防误触" : (d.original_app_exposed ? "暴露在应用栏!" : "未安装原版"),
                    ok: d.original_hidden || !d.original_app_exposed
                )
                metricTile(
                    icon: "cube.transparent.fill",
                    title: "沙盒与去遥测",
                    value: (d.sandbox_enabled && d.telemetry_disabled) ? "Seatbelt + 静音" : "部分未启",
                    ok: d.sandbox_enabled && d.telemetry_disabled
                )
            }
            HStack(spacing: 8) {
                metricTile(
                    icon: "desktopcomputer",
                    title: "桌面版进程",
                    value: d.desktop_pid.map { vm.snapshot.desktopUnprotected ? "未绑定代理 · #\($0)" : "硬代理 · #\($0)" } ?? "待机未启动",
                    ok: !vm.snapshot.desktopUnprotected,
                    dim: !vm.snapshot.desktopRunning
                )
                metricTile(
                    icon: "terminal.fill",
                    title: "Claude Code",
                    value: vm.snapshot.hasUnprotectedCLI
                        ? "发现未保护进程!"
                        : (vm.snapshot.hasActiveCLI
                            ? "守护中 · \(d.activeCLIPIDs.count) 进程"
                            : (d.cli_ready ? "Rust 门禁就绪" : "待初始化")),
                    ok: d.cli_ready && !vm.snapshot.hasUnprotectedCLI
                )
            }
        }
    }

    private func metricTile(icon: String, title: String, value: String, ok: Bool, dim: Bool = false) -> some View {
        let tint: Color = dim ? labelColor : (ok ? safeGreen : warnAmber)
        return HStack(spacing: 8.5) {
            ZStack {
                RoundedRectangle(cornerRadius: 8, style: .continuous)
                    .fill(tint.opacity(isDark ? 0.14 : 0.085))
                    .frame(width: 27, height: 27)
                Image(systemName: icon)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundColor(tint)
            }

            VStack(alignment: .leading, spacing: 1.5) {
                Text(title)
                    .font(.system(size: 10, weight: .medium))
                    .foregroundColor(labelColor)
                Text(value)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(dim ? labelColor : inkPrimary)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 9.5)
        .padding(.vertical, 7.5)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 11, style: .continuous).fill(cardSurface))
        .overlay(RoundedRectangle(cornerRadius: 11, style: .continuous).strokeBorder(palette.cardSpecularBorder, lineWidth: 0.75))
        .shadow(color: cardShadow, radius: 5, y: 1.5)
    }

    var togglesPanel: some View {
        VStack(spacing: 6) {
            compactToggleRow(
                icon: "bolt.shield.fill",
                title: "IP 漂移 & 唤醒自动急停",
                subtitle: "断网/切节点/唤醒瞬间自动终止裸连进程",
                isOn: vm.autoKillOnBreach
            ) {
                withAnimation(.spring(response: 0.24, dampingFraction: 0.78)) {
                    vm.autoKillOnBreach.toggle()
                }
            }

            compactToggleRow(
                icon: "sunrise.fill",
                title: "开机自启 & 每日自动体检",
                subtitle: vm.snapshot.defenses.daily_patrol_enabled ? "登录静默启动雷达 · 每日后台自动复检防线" : "登录静默启动状态栏保护雷达",
                isOn: vm.loginAutoStart
            ) {
                withAnimation(.spring(response: 0.24, dampingFraction: 0.78)) {
                    vm.setLoginAutoStart(!vm.loginAutoStart)
                }
            }
        }
    }

    private func compactToggleRow(
        icon: String,
        title: String,
        subtitle: String,
        isOn: Bool,
        action: @escaping () -> Void
    ) -> some View {
        let activeTint = safeGreen
        return HStack(spacing: 8) {
            ZStack {
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill((isOn ? activeTint : labelColor).opacity(isDark ? 0.20 : 0.13))
                    .frame(width: 24, height: 24)
                Image(systemName: icon)
                    .font(.system(size: 11.5, weight: .semibold))
                    .foregroundColor(isOn ? activeTint : labelColor)
            }
            VStack(alignment: .leading, spacing: 1.5) {
                Text(title)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(.primary)
                Text(subtitle)
                    .font(.system(size: 9.5, weight: .medium))
                    .foregroundColor(labelColor)
                    .lineLimit(1)
            }
            Spacer(minLength: 6)

            Button(action: action) {
                ZStack(alignment: isOn ? .trailing : .leading) {
                    Capsule()
                        .fill(isOn ? activeTint : (isDark ? Color.white.opacity(0.18) : Color.black.opacity(0.16)))
                        .frame(width: 34, height: 19)
                    Circle()
                        .fill(Color.white)
                        .frame(width: 15, height: 15)
                        .shadow(color: Color.black.opacity(0.22), radius: 2, y: 1)
                        .padding(2)
                }
                .contentShape(Capsule())
            }
            .buttonStyle(SnappyButtonStyle(scale: 0.94, pressedOpacity: 0.95))
        }
        .padding(.horizontal, 11)
        .padding(.vertical, 8)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(cardSurface))
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(isOn ? activeTint.opacity(isDark ? 0.24 : 0.16) : cardBorder, lineWidth: 0.8)
        )
        .shadow(color: cardShadow, radius: 5, y: 1.5)
    }

    var purityPanel: some View {
        VStack(spacing: 8.5) {
            if let p = vm.purity {
                let pc = purityColor(p.purity_score)
                HStack(spacing: 12) {
                    ZStack {
                        Circle()
                            .stroke(pc.opacity(0.18), lineWidth: 5.5)
                            .frame(width: 56, height: 56)
                        Circle()
                            .trim(from: 0, to: CGFloat(max(0, min(100, p.purity_score))) / 100.0)
                            .stroke(pc, style: StrokeStyle(lineWidth: 5.5, lineCap: .round))
                            .rotationEffect(.degrees(-90))
                            .frame(width: 56, height: 56)
                            .animation(.spring(response: 0.45, dampingFraction: 0.82), value: p.purity_score)
                        VStack(spacing: 0) {
                            Text("\(p.purity_score)")
                                .font(.system(size: 16, weight: .bold, design: .rounded))
                                .foregroundColor(pc)
                            Text("\(p.grade)级")
                                .font(.system(size: 9, weight: .heavy))
                                .foregroundColor(labelColor)
                        }
                    }

                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 5) {
                            Text(p.ip_type)
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.primary)
                            Text(p.country_code)
                                .font(.system(size: 9.5, weight: .bold, design: .monospaced))
                                .foregroundColor(p.region_supported ? safeGreen : dangerRed)
                                .padding(.horizontal, 5)
                                .padding(.vertical, 1)
                                .background(Capsule().fill((p.region_supported ? safeGreen : dangerRed).opacity(0.16)))
                        }
                        Text(p.verdict)
                            .font(.system(size: 10.5, weight: .semibold))
                            .foregroundColor(pc)
                        Text("\(p.asn) · \(p.isp)")
                            .font(.system(size: 10, weight: .medium))
                            .foregroundColor(labelColor)
                            .lineLimit(1)
                        Text("\(p.country) · \(p.city)  |  欺诈分: \(p.combined_fraud_score.map(String.init) ?? "-")")
                            .font(.system(size: 9.5, weight: .medium, design: .monospaced))
                            .foregroundColor(labelColor)
                            .lineLimit(1)
                    }
                    Spacer(minLength: 0)
                }
                .padding(10)
                .background(RoundedRectangle(cornerRadius: 11, style: .continuous).fill(cardSurface))
                .overlay(RoundedRectangle(cornerRadius: 11, style: .continuous).strokeBorder(pc.opacity(0.32), lineWidth: 0.9))

                HStack(spacing: 6) {
                    leakPill(title: "Claude边", value: p.claude_edge_match ? (p.claude_colo ?? "一致") : "异常", ok: p.claude_edge_match)
                    leakPill(title: "DNS", value: p.dns_leak ? "泄露!" : "零泄露", ok: !p.dns_leak)
                    leakPill(title: "IPv6", value: p.ipv6_leak ? "泄露!" : "已封闭", ok: !p.ipv6_leak)
                    leakPill(title: "时区", value: p.timezone_aligned ? "已对齐" : "偏移!", ok: p.timezone_aligned)
                }

                VStack(spacing: 4.5) {
                    ForEach(p.factors.prefix(6)) { f in
                        HStack(alignment: .top, spacing: 7) {
                            Image(systemName: f.severity == "good" ? "checkmark.circle.fill" : (f.severity == "warn" ? "exclamationmark.triangle.fill" : "xmark.octagon.fill"))
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundColor(f.severity == "good" ? safeGreen : (f.severity == "warn" ? warnAmber : dangerRed))
                                .padding(.top, 1)
                            VStack(alignment: .leading, spacing: 1) {
                                HStack {
                                    Text(f.title)
                                        .font(.system(size: 10.5, weight: .semibold))
                                        .foregroundColor(.primary)
                                    Spacer()
                                    if f.penalty < 0 {
                                        Text("\(f.penalty)")
                                            .font(.system(size: 9.5, weight: .bold, design: .monospaced))
                                            .foregroundColor(f.severity == "warn" ? warnAmber : dangerRed)
                                    }
                                }
                                Text(f.detail)
                                    .font(.system(size: 9.5, weight: .medium))
                                    .foregroundColor(labelColor)
                                    .lineLimit(2)
                            }
                        }
                        .padding(.horizontal, 9)
                        .padding(.vertical, 5)
                        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(cardSurface))
                        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.6))
                    }
                }
            } else {
                VStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("正在执行多源 IP 纯净度与 DNS/IPv6 泄露体检...")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(labelColor)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 28)
                .background(RoundedRectangle(cornerRadius: 11, style: .continuous).fill(cardSurface))
            }

            Spacer(minLength: 0)

            HStack(spacing: 8) {
                secondaryActionButton(
                    icon: "sparkle.magnifyingglass",
                    title: vm.isAuditing ? "全面体检中..." : "重新全面体检",
                    isLoading: vm.isAuditing,
                    help: "复测多源 IP 纯净度、DNS/IPv6 泄露，并自动巡检修复本地防线"
                ) {
                    vm.runFullCheckup()
                }
                if vm.snapshot.defenses.original_app_exposed {
                    secondaryActionButton(
                        icon: "eye.slash.fill",
                        title: "隐藏原版",
                        tint: warnAmber,
                        help: "立即隐藏暴露在 /Applications 的原版 Claude.app"
                    ) {
                        vm.hideOriginalAppNow()
                    }
                }
            }
        }
    }

    private func leakPill(title: String, value: String, ok: Bool) -> some View {
        let color = ok ? safeGreen : dangerRed
        return VStack(spacing: 2) {
            Text(title)
                .font(.system(size: 9.5, weight: .medium))
                .foregroundColor(labelColor)
            Text(value)
                .font(.system(size: 10.5, weight: .bold, design: .monospaced))
                .foregroundColor(color)
                .lineLimit(1)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 6)
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(color.opacity(isDark ? 0.13 : 0.08)))
        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(color.opacity(0.28), lineWidth: 0.7))
    }

    var actionButtonsBar: some View {
        VStack(spacing: 7.5) {
            PrimaryLaunchButton(
                desktopRunning: vm.snapshot.desktopRunning,
                isSafe: vm.snapshot.isSafe,
                isLoading: vm.isCheckingLaunch,
                isDark: isDark
            ) {
                vm.launchClaudeSafe()
            }

            HStack(spacing: 8) {
                secondaryActionButton(
                    icon: "arrow.clockwise",
                    title: vm.isRefreshing ? "测速中" : "重新测速",
                    tint: titaniumAccent,
                    isLoading: vm.isRefreshing,
                    help: "使用 Rust 内核重新测量三点出口 IP 与 Anthropic API 真实 1-RTT"
                ) {
                    vm.refresh(force: true, mode: .full, userInitiated: true)
                }

                if vm.snapshot.anyClaudeRunning {
                    secondaryActionButton(
                        icon: "stop.circle.fill",
                        title: "急停",
                        tint: dangerRed,
                        isDestructive: true,
                        help: "立即强制终止运行中的 Claude 桌面版与 CLI 进程"
                    ) {
                        vm.emergencyKillClaude(includeCLI: true)
                    }
                }
            }
        }
    }

    private func secondaryActionButton(
        icon: String,
        title: String,
        tint: Color = .primary,
        isLoading: Bool = false,
        isDestructive: Bool = false,
        help: String,
        action: @escaping () -> Void
    ) -> some View {
        HoverableActionButton(
            icon: icon,
            title: title,
            tint: tint,
            isLoading: isLoading,
            isDestructive: isDestructive,
            isDark: isDark,
            cardSurface: cardSurface,
            cardBorder: cardBorder,
            cardShadow: cardShadow,
            dangerRed: dangerRed,
            helpText: help,
            action: action
        )
    }
}
