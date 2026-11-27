import Cocoa
import SwiftUI

// MARK: - Studio Console Section 1: 实时雷达

extension ShieldDashboardView {
    func radarSectionContent(useThreeMatrixCols: Bool) -> some View {
        let twoEqualCols = [
            GridItem(.flexible(), spacing: 14),
            GridItem(.flexible(), spacing: 14)
        ]
        let matrixCols = Array(
            repeating: GridItem(.flexible(), spacing: 14),
            count: useThreeMatrixCols ? 3 : 2
        )

        return VStack(alignment: .leading, spacing: 18) {
            HStack(spacing: 16) {
                ShieldStatusBadge(
                    isSafe: vm.snapshot.isSafe,
                    accentColor: accentColor,
                    isDark: isDark,
                    isActive: vm.isDashboardVisible
                )

                VStack(alignment: .leading, spacing: 5) {
                    HStack(spacing: 8.5) {
                        Text(vm.snapshot.isSafe ? "SHIELD ARMED" : "IP 异常预警")
                            .font(.system(size: 18.5, weight: .bold, design: .rounded))
                            .foregroundColor(inkPrimary)

                        Text(vm.snapshot.isSafe ? "Rust 内核锁死" : "熔断就绪")
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundColor(accentColor)
                            .padding(.horizontal, 9)
                            .padding(.vertical, 3)
                            .background(Capsule().fill(accentColor.opacity(isDark ? 0.18 : 0.10)))
                    }

                    HStack(spacing: 8.5) {
                        Text(vm.snapshot.expected_ip)
                            .font(.system(size: 14, weight: .semibold, design: .monospaced))
                            .foregroundColor(inkPrimary.opacity(0.86))

                        if let apiMs = vm.snapshot.api_latency.warm_rtt_ms {
                            let jitter = vm.snapshot.api_latency.jitter_ms
                            let jitterText = jitter.map { " ±\($0)" } ?? ""
                            let apiColor = apiLatencyColor(apiMs, jitter: jitter)
                            Text(verbatim: "API \(apiMs)ms\(jitterText)")
                                .font(.system(size: 12, weight: .semibold, design: .monospaced))
                                .foregroundColor(apiColor)
                                .padding(.horizontal, 8.5)
                                .padding(.vertical, 2.5)
                                .background(Capsule().fill(apiColor.opacity(isDark ? 0.16 : 0.09)))
                        } else if let colo = vm.snapshot.claude_edge.colo {
                            Text("CF \(colo)")
                                .font(.system(size: 12, weight: .medium, design: .monospaced))
                                .foregroundColor(labelColor)
                        }
                    }
                }

                Spacer(minLength: 10)

                if let p = vm.purity {
                    let pc = purityColor(p.purity_score)
                    Button(action: {
                        withAnimation(.spring(response: 0.26, dampingFraction: 0.86)) {
                            nav.selectedSection = .purity
                        }
                    }) {
                        VStack(alignment: .trailing, spacing: 3) {
                            HStack(spacing: 6) {
                                Text("\(p.purity_score)")
                                    .font(.system(size: 24, weight: .bold, design: .rounded))
                                    .foregroundColor(pc)
                                Text(p.grade)
                                    .font(.system(size: 11.5, weight: .heavy, design: .rounded))
                                    .foregroundColor(.white)
                                    .padding(.horizontal, 6.5)
                                    .padding(.vertical, 2)
                                    .background(RoundedRectangle(cornerRadius: 5.5, style: .continuous).fill(pc))
                            }
                            Text("IP 纯净度 · 查看详情")
                                .font(.system(size: 11, weight: .medium))
                                .foregroundColor(labelColor)
                        }
                        .padding(.horizontal, 15)
                        .padding(.vertical, 10)
                        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(pc.opacity(isDark ? 0.12 : 0.065)))
                    }
                    .buttonStyle(SnappyButtonStyle(scale: 0.97))
                } else {
                    VStack(alignment: .trailing, spacing: 3) {
                        Text("\(vm.snapshot.defenseScore)/8")
                            .font(.system(size: 22, weight: .bold, design: .rounded))
                            .foregroundColor(accentColor)
                        Text("防线激活")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundColor(labelColor)
                    }
                }
            }
            .padding(.horizontal, 22)
            .padding(.vertical, 20)
            .background(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(cardSurface)
                    .overlay(
                        RoundedRectangle(cornerRadius: 16, style: .continuous)
                            .fill(
                                LinearGradient(
                                    colors: [accentColor.opacity(isDark ? 0.11 : 0.055), Color.clear],
                                    startPoint: .topLeading,
                                    endPoint: .bottomTrailing
                                )
                            )
                    )
            )
            .overlay(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .strokeBorder(accentColor.opacity(isDark ? 0.24 : 0.18), lineWidth: 0.85)
            )
            .shadow(color: cardShadow, radius: 8, y: 2)

            LazyVGrid(columns: twoEqualCols, spacing: 14) {
                dashboardTunnelCard(
                    title: "Claude 边缘通道 :\(vm.snapshot.proxy_port)",
                    ip: vm.snapshot.proxy.ip,
                    subtitle: vm.snapshot.claude_edge.colo.map { "Cloudflare \($0) · \(vm.snapshot.claude_edge.loc ?? "")" } ?? "边缘节点探测中",
                    latency: vm.snapshot.proxy.latency_ms,
                    ok: vm.snapshot.proxyOK,
                    icon: "arrow.triangle.branch"
                )
                dashboardTunnelCard(
                    title: "TUN 系统默认路由",
                    ip: vm.snapshot.tun.ip,
                    subtitle: vm.snapshot.tun.colo.map { "Cloudflare \($0) · \(vm.snapshot.tun.loc ?? "")" } ?? "系统路由探测中",
                    latency: vm.snapshot.tun.latency_ms,
                    ok: vm.snapshot.tunOK,
                    icon: "shield.lefthalf.filled"
                )
            }

            VStack(alignment: .leading, spacing: 11) {
                HStack(alignment: .firstTextBaseline) {
                    Text("本地防线状态")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundColor(labelColor)
                    Spacer()
                    Text("\(vm.snapshot.defenseScore)/8 项已激活")
                        .font(.system(size: 11.5, weight: .semibold, design: .monospaced))
                        .foregroundColor(vm.snapshot.isSafe ? safeGreen : warnAmber)
                }

                let d = vm.snapshot.defenses
                let tzOK = vm.purity?.timezone_aligned ?? true
                LazyVGrid(columns: matrixCols, spacing: 14) {
                    dashboardMetricTile(
                        icon: "globe.americas.fill",
                        title: "时区与语言",
                        value: "\(vm.snapshot.region_short) · en-US",
                        ok: tzOK
                    )
                    dashboardMetricTile(
                        icon: "lock.shield.fill",
                        title: "OAuth 门禁",
                        value: d.oauth_locked ? "AdsPower-Only" : "未锁定",
                        ok: d.oauth_locked
                    )
                    dashboardMetricTile(
                        icon: "eye.slash.fill",
                        title: "原版隐藏仓",
                        value: d.original_hidden ? "已隐藏防误触" : (d.original_app_exposed ? "暴露在应用栏!" : "未安装原版"),
                        ok: d.original_hidden || !d.original_app_exposed
                    )
                    dashboardMetricTile(
                        icon: "cube.transparent.fill",
                        title: "沙盒与去遥测",
                        value: (d.sandbox_enabled && d.telemetry_disabled) ? "Seatbelt + 静音" : "部分未启",
                        ok: d.sandbox_enabled && d.telemetry_disabled
                    )
                    dashboardMetricTile(
                        icon: "desktopcomputer",
                        title: "桌面版进程",
                        value: d.desktop_pid.map { vm.snapshot.desktopUnprotected ? "未绑定 · #\($0)" : "硬代理 · #\($0)" } ?? "待机未启动",
                        ok: !vm.snapshot.desktopUnprotected,
                        dim: !vm.snapshot.desktopRunning
                    )
                    dashboardMetricTile(
                        icon: "terminal.fill",
                        title: "Claude Code",
                        value: vm.snapshot.hasUnprotectedCLI
                            ? "未保护进程!"
                            : (vm.snapshot.hasActiveCLI
                                ? "守护中 · \(d.activeCLIPIDs.count) 进程"
                                : (d.cli_ready ? "Rust 门禁就绪" : "待初始化")),
                        ok: d.cli_ready && !vm.snapshot.hasUnprotectedCLI
                    )
                }
            }

            LazyVGrid(columns: twoEqualCols, spacing: 14) {
                dashboardToggleCard(
                    icon: "bolt.shield.fill",
                    title: "IP 漂移 & 唤醒急停",
                    subtitle: "断网、切节点或唤醒瞬间自动熔断",
                    isOn: vm.autoKillOnBreach
                ) {
                    withAnimation(.spring(response: 0.24, dampingFraction: 0.80)) {
                        vm.autoKillOnBreach.toggle()
                    }
                }

                dashboardToggleCard(
                    icon: "sunrise.fill",
                    title: "开机自启 & 每日体检",
                    subtitle: vm.snapshot.defenses.daily_patrol_enabled ? "登录静默守护 · 每日自动复检防线" : "登录静默启动状态栏保护雷达",
                    isOn: vm.loginAutoStart
                ) {
                    withAnimation(.spring(response: 0.24, dampingFraction: 0.80)) {
                        vm.setLoginAutoStart(!vm.loginAutoStart)
                    }
                }
            }

            if vm.snapshot.anyClaudeRunning {
                dashboardActionTile(
                    icon: "stop.circle.fill",
                    title: vm.snapshot.hasActiveCLI ? "急停全部 Claude 进程（桌面版 + CLI）" : "急停 Claude 桌面版",
                    isLoading: false,
                    tint: dangerRed,
                    isDestructive: true
                ) {
                    vm.emergencyKillClaude(includeCLI: true)
                }
            }
        }
    }

    private func dashboardActionTile(
        icon: String,
        title: String,
        isLoading: Bool,
        tint: Color,
        isDestructive: Bool = false,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            HStack(spacing: 7) {
                if isLoading {
                    ProgressView().controlSize(.mini).scaleEffect(0.8)
                } else {
                    Image(systemName: icon)
                        .font(.system(size: 13, weight: .medium))
                        .foregroundColor(isDestructive ? dangerRed : labelColor)
                }
                Text(title)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(isDestructive ? dangerRed : tint.opacity(0.88))
                    .lineLimit(1)
            }
            .frame(maxWidth: .infinity)
            .frame(height: 44)
            .background(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(isDestructive ? dangerRed.opacity(isDark ? 0.14 : 0.08) : cardSurface)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .strokeBorder(isDestructive ? dangerRed.opacity(0.28) : cardBorder, lineWidth: 0.75)
            )
            .shadow(color: cardShadow, radius: 5, y: 1.5)
        }
        .buttonStyle(SnappyButtonStyle(scale: 0.98))
    }

    private func dashboardTunnelCard(title: String, ip: String, subtitle: String, latency: Int?, ok: Bool, icon: String) -> some View {
        let dotColor = ok ? safeGreen : dangerRed
        return VStack(alignment: .leading, spacing: 9) {
            HStack(spacing: 6.5) {
                Circle().fill(dotColor).frame(width: 7.5, height: 7.5)
                Text(title)
                    .font(.system(size: 12.5, weight: .medium))
                    .foregroundColor(labelColor)
                    .lineLimit(1)
                Spacer(minLength: 4)
                if let ms = latency {
                    let lc = latencyColor(ms)
                    Text(verbatim: "\(ms)ms")
                        .font(.system(size: 11, weight: .semibold, design: .monospaced))
                        .foregroundColor(lc)
                        .padding(.horizontal, 7.5)
                        .padding(.vertical, 2.5)
                        .background(Capsule().fill(lc.opacity(isDark ? 0.16 : 0.09)))
                }
            }

            HStack(spacing: 7) {
                Image(systemName: icon)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(dotColor)
                Text(ip)
                    .font(.system(size: 16.5, weight: .bold, design: .monospaced))
                    .foregroundColor(inkPrimary)
                    .textSelection(.enabled)
            }

            Text(subtitle)
                .font(.system(size: 11.5, weight: .medium, design: .monospaced))
                .foregroundColor(subtleLabelColor)
                .lineLimit(1)
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(cardSurface))
        .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(palette.cardSpecularBorder, lineWidth: 0.85))
        .shadow(color: cardShadow, radius: 8, y: 2.5)
    }

    private func dashboardMetricTile(icon: String, title: String, value: String, ok: Bool, dim: Bool = false) -> some View {
        let tint: Color = dim ? subtleLabelColor : (ok ? safeGreen : warnAmber)
        return HStack(spacing: 11) {
            ZStack {
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(tint.opacity(isDark ? 0.15 : 0.09))
                    .frame(width: 36, height: 36)
                Image(systemName: icon)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundColor(tint)
            }
            VStack(alignment: .leading, spacing: 2.5) {
                Text(title)
                    .font(.system(size: 11.5, weight: .medium))
                    .foregroundColor(labelColor)
                    .lineLimit(1)
                Text(value)
                    .font(.system(size: 13.5, weight: .semibold))
                    .foregroundColor(dim ? labelColor : inkPrimary)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(cardSurface))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(palette.cardSpecularBorder, lineWidth: 0.8))
        .shadow(color: cardShadow, radius: 6, y: 2)
    }

    private func dashboardToggleCard(icon: String, title: String, subtitle: String, isOn: Bool, action: @escaping () -> Void) -> some View {
        let activeTint = safeGreen
        return HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill((isOn ? activeTint : subtleLabelColor).opacity(isDark ? 0.15 : 0.09))
                    .frame(width: 36, height: 36)
                Image(systemName: icon)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundColor(isOn ? activeTint : subtleLabelColor)
            }

            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.system(size: 13.5, weight: .semibold))
                    .foregroundColor(inkPrimary)
                    .lineLimit(1)
                Text(subtitle)
                    .font(.system(size: 11.5, weight: .regular))
                    .foregroundColor(labelColor)
                    .lineLimit(1)
            }

            Spacer(minLength: 8)

            Button(action: action) {
                ZStack(alignment: isOn ? .trailing : .leading) {
                    Capsule()
                        .fill(isOn ? activeTint.opacity(0.90) : (isDark ? Color.white.opacity(0.16) : Color.black.opacity(0.14)))
                        .frame(width: 38, height: 21)
                    Circle()
                        .fill(Color.white)
                        .frame(width: 17, height: 17)
                        .shadow(color: Color.black.opacity(0.16), radius: 1.5, y: 0.5)
                        .padding(2)
                }
                .contentShape(Capsule())
            }
            .buttonStyle(SnappyButtonStyle(scale: 0.94, pressedOpacity: 0.95))
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 15)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(cardSurface))
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(isOn ? activeTint.opacity(isDark ? 0.22 : 0.16) : cardBorder, lineWidth: 0.75)
        )
        .shadow(color: cardShadow, radius: 4, y: 1.5)
    }
}
