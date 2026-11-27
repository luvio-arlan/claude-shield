import Cocoa
import SwiftUI

// MARK: - SwiftUI Menu Bar Popover Shell

struct ShieldPopoverView: View {
    @ObservedObject var vm: ShieldViewModel
    @Environment(\.colorScheme) var colorScheme
    @Namespace private var tabNamespace

    var isDark: Bool { colorScheme == .dark }
    var palette: ShieldPalette { ShieldPalette(isDark: isDark) }

    var safeGreen: Color { palette.safeGreen }
    var dangerRed: Color { palette.dangerRed }
    var warnAmber: Color { palette.warnAmber }
    var titaniumAccent: Color { palette.titaniumAccent }
    var inkPrimary: Color { palette.inkPrimary }

    var accentColor: Color {
        vm.snapshot.isSafe ? safeGreen : dangerRed
    }

    var cardSurface: Color { palette.popoverCardSurface }
    var cardBorder: Color { palette.cardBorder }
    var cardShadow: Color { palette.cardShadow }
    var labelColor: Color { palette.labelColor }

    func purityColor(_ score: Int) -> Color {
        ShieldMetricsStyle.purityColor(score, safe: safeGreen, warn: warnAmber, danger: dangerRed)
    }

    func latencyColor(_ ms: Int) -> Color {
        ShieldMetricsStyle.latencyColor(ms, safe: safeGreen, warn: warnAmber, danger: dangerRed)
    }

    func apiLatencyColor(_ ms: Int, jitter: Int?) -> Color {
        ShieldMetricsStyle.apiLatencyColor(ms, jitter: jitter, safe: safeGreen, warn: warnAmber, danger: dangerRed)
    }

    private func selectTab(_ tab: ShieldTab) {
        guard vm.selectedTab != tab else { return }
        withAnimation(.spring(response: 0.26, dampingFraction: 0.86)) {
            vm.selectedTab = tab
        }
        if tab == .purity && vm.purity == nil {
            vm.refreshPurity(silent: true)
        }
    }

    var body: some View {
        ZStack(alignment: .bottom) {
            VStack(spacing: 10) {
                headerCard
                    .padding(.horizontal, 14)

                if vm.shouldShowPopoverUpdateBanner, let info = vm.availableUpdate {
                    updateBannerCard(info)
                        .padding(.horizontal, 14)
                        .transition(.move(edge: .top).combined(with: .opacity))
                }

                segmentedTabBar
                    .padding(.horizontal, 14)

                tabContentDeck

                footerBar
                    .padding(.horizontal, 14)
            }
            .padding(.vertical, 14)

            if let toast = vm.toastMessage {
                Text(toast)
                    .font(.system(size: 11.5, weight: .medium))
                    .foregroundColor(.white)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(Capsule().fill(Color.black.opacity(0.86)))
                    .shadow(color: .black.opacity(0.25), radius: 6, y: 2)
                    .padding(.bottom, 10)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .frame(width: 400)
        .fixedSize(horizontal: false, vertical: true)
        .background(
            ZStack(alignment: .top) {
                VisualEffectView(material: .popover, blendingMode: .behindWindow)
                palette.popoverGlassWash
                palette.topAtmosphereGlow(isSafe: vm.snapshot.isSafe)
                    .frame(height: 150)
                    .allowsHitTesting(false)
            }
        )
    }

    @ViewBuilder
    private var tabContentDeck: some View {
        let isRadar = vm.selectedTab == .radar
        MatchedHeightTabStack {
            radarTabContent
                .padding(.horizontal, 14)
                .padding(.vertical, 2)
                .opacity(isRadar ? 1 : 0)
                .offset(x: isRadar ? 0 : -16)
                .allowsHitTesting(isRadar)
                .accessibilityHidden(!isRadar)

            purityPanel
                .padding(.horizontal, 14)
                .padding(.vertical, 2)
                .opacity(isRadar ? 0 : 1)
                .offset(x: isRadar ? 16 : 0)
                .allowsHitTesting(!isRadar)
                .accessibilityHidden(isRadar)
        }
        .clipped()
        .padding(.vertical, -2)
    }

    private var radarTabContent: some View {
        VStack(spacing: 10) {
            networkTelemetryRow
            defenseMatrixGrid
            togglesPanel
            Spacer(minLength: 0)
            actionButtonsBar
        }
    }

    var headerCard: some View {
        HStack(spacing: 11) {
            ShieldStatusBadge(
                isSafe: vm.snapshot.isSafe,
                accentColor: accentColor,
                isDark: isDark,
                isActive: vm.isPopoverVisible
            )

            VStack(alignment: .leading, spacing: 3.5) {
                HStack(spacing: 6) {
                    Text(vm.snapshot.isSafe ? "SHIELD ARMED" : "IP 异常预警")
                        .font(.system(size: 14, weight: .bold, design: .rounded))
                        .foregroundColor(inkPrimary)

                    Text(vm.snapshot.isSafe ? "Rust 内核锁死" : "熔断就绪")
                        .font(.system(size: 9.5, weight: .semibold))
                        .foregroundColor(accentColor)
                        .padding(.horizontal, 6.5)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(accentColor.opacity(isDark ? 0.18 : 0.10)))
                        .overlay(Capsule().strokeBorder(accentColor.opacity(isDark ? 0.30 : 0.20), lineWidth: 0.6))
                }

                HStack(spacing: 5) {
                    Text(vm.snapshot.expected_ip)
                        .font(.system(size: 11.5, weight: .semibold, design: .monospaced))
                        .foregroundColor(inkPrimary.opacity(0.82))
                    if let apiMs = vm.snapshot.api_latency.warm_rtt_ms {
                        let jitter = vm.snapshot.api_latency.jitter_ms
                        let jitterText = jitter.map { " ±\($0)" } ?? ""
                        Text(verbatim: "· API \(apiMs)ms\(jitterText)")
                            .font(.system(size: 10.5, weight: .semibold, design: .monospaced))
                            .foregroundColor(apiLatencyColor(apiMs, jitter: jitter))
                            .lineLimit(1)
                    } else if let colo = vm.snapshot.claude_edge.colo {
                        Text("· CF \(colo)")
                            .font(.system(size: 10.5, weight: .medium))
                            .foregroundColor(labelColor)
                    }
                }
            }

            Spacer(minLength: 4)

            if let p = vm.purity {
                let pc = purityColor(p.purity_score)
                Button(action: {
                    selectTab(vm.selectedTab == .radar ? .purity : .radar)
                }) {
                    VStack(alignment: .trailing, spacing: 2) {
                        HStack(spacing: 3.5) {
                            Text("\(p.purity_score)")
                                .font(.system(size: 15.5, weight: .bold, design: .rounded))
                                .foregroundColor(pc)
                            Text(p.grade)
                                .font(.system(size: 9.5, weight: .heavy, design: .rounded))
                                .foregroundColor(.white)
                                .padding(.horizontal, 4.5)
                                .padding(.vertical, 1)
                                .background(RoundedRectangle(cornerRadius: 4.5, style: .continuous).fill(pc))
                        }
                        Text("IP 纯净度")
                            .font(.system(size: 9.5, weight: .medium))
                            .foregroundColor(labelColor)
                    }
                    .padding(.horizontal, 8)
                    .padding(.vertical, 5)
                    .background(
                        RoundedRectangle(cornerRadius: 9, style: .continuous)
                            .fill(pc.opacity(isDark ? 0.13 : 0.08))
                    )
                    .contentShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
                }
                .buttonStyle(SnappyButtonStyle(scale: 0.95))
                .help("点击切换 IP 纯净度深度体检面板")
            } else {
                VStack(alignment: .trailing, spacing: 1) {
                    Text("\(vm.snapshot.defenseScore)/8")
                        .font(.system(size: 16, weight: .bold, design: .rounded))
                        .foregroundColor(accentColor)
                    Text("防线激活")
                        .font(.system(size: 9.5, weight: .medium))
                        .foregroundColor(labelColor)
                }
            }
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 11)
        .background(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .fill(cardSurface)
                .overlay(
                    RoundedRectangle(cornerRadius: 14, style: .continuous)
                        .fill(
                            LinearGradient(
                                colors: [accentColor.opacity(isDark ? 0.12 : 0.06), Color.clear],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            )
                        )
                )
        )
        .overlay(
            RoundedRectangle(cornerRadius: 14, style: .continuous)
                .strokeBorder(accentColor.opacity(isDark ? 0.28 : 0.22), lineWidth: 0.85)
        )
        .shadow(color: cardShadow, radius: 8, y: 2.5)
    }

    private func updateBannerCard(_ info: AppUpdateInfo) -> some View {
        let accent = titaniumAccent
        return VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 8) {
                ZStack {
                    RoundedRectangle(cornerRadius: 8, style: .continuous)
                        .fill(accent.opacity(isDark ? 0.20 : 0.12))
                        .frame(width: 24, height: 24)
                    Image(systemName: "arrow.down.circle.fill")
                        .font(.system(size: 12.5, weight: .semibold))
                        .foregroundColor(accent)
                }

                VStack(alignment: .leading, spacing: 1.5) {
                    HStack(spacing: 5) {
                        Text("发现新版本 \(info.tagName)")
                            .font(.system(size: 11.5, weight: .bold))
                            .foregroundColor(inkPrimary)
                        Text("GitHub")
                            .font(.system(size: 9, weight: .semibold, design: .monospaced))
                            .foregroundColor(accent)
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1)
                            .background(Capsule().fill(accent.opacity(isDark ? 0.18 : 0.10)))
                    }
                    Group {
                        switch vm.updatePhase {
                        case .downloading(_, let progress):
                            Text("正在下载安装包… \(Int(progress * 100))%")
                        case .installing(_, let stage):
                            Text(stage)
                        default:
                            Text(info.notesSummary)
                        }
                    }
                    .font(.system(size: 9.5, weight: .medium))
                    .foregroundColor(labelColor)
                    .lineLimit(1)
                }

                Spacer(minLength: 4)

                if vm.updatePhase.isBusy {
                    ProgressView()
                        .controlSize(.mini)
                        .scaleEffect(0.85)
                } else {
                    Button(action: { vm.performUpdate(info) }) {
                        Text(info.zipDownloadURL != nil ? "立即更新" : "前往下载")
                            .font(.system(size: 10.5, weight: .semibold))
                            .foregroundColor(palette.primaryCTAForeground)
                            .padding(.horizontal, 9)
                            .padding(.vertical, 4.5)
                            .background(Capsule().fill(palette.primaryCTAGradient))
                    }
                    .buttonStyle(SnappyButtonStyle(scale: 0.95))

                    Button(action: { vm.dismissUpdateBanner(info.version) }) {
                        Image(systemName: "xmark")
                            .font(.system(size: 9.5, weight: .semibold))
                            .foregroundColor(labelColor)
                            .frame(width: 20, height: 20)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(SnappyButtonStyle(scale: 0.92))
                    .help("暂不提示此版本")
                }
            }

            if case .downloading(_, let progress) = vm.updatePhase {
                GeometryReader { geo in
                    ZStack(alignment: .leading) {
                        Capsule()
                            .fill(accent.opacity(isDark ? 0.20 : 0.14))
                            .frame(height: 4)
                        Capsule()
                            .fill(accent)
                            .frame(width: max(8, geo.size.width * CGFloat(progress)), height: 4)
                            .animation(.easeOut(duration: 0.18), value: progress)
                    }
                }
                .frame(height: 4)
            }
        }
        .padding(.horizontal, 11)
        .padding(.vertical, 8.5)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(cardSurface)
                .overlay(
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .fill(accent.opacity(isDark ? 0.08 : 0.045))
                )
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(accent.opacity(isDark ? 0.30 : 0.22), lineWidth: 0.85)
        )
    }

    private var segmentedTabBar: some View {
        HStack(spacing: 4) {
            ForEach(ShieldTab.allCases, id: \.self) { tab in
                SegmentedTabItemButton(
                    tab: tab,
                    active: vm.selectedTab == tab,
                    purityScore: vm.purity?.purity_score,
                    scoreColor: purityColor(vm.purity?.purity_score ?? 100),
                    isDark: isDark,
                    namespace: tabNamespace
                ) {
                    selectTab(tab)
                }
            }
        }
        .padding(3.5)
        .background(RoundedRectangle(cornerRadius: 11, style: .continuous).fill(palette.recessedTray))
        .overlay(RoundedRectangle(cornerRadius: 11, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.65))
    }

    private var footerBar: some View {
        HStack(spacing: 8) {
            Text("\(AppReleaseConfig.shortDisplayVersion) · 更新 \(vm.snapshot.checked_at)")
                .font(.system(size: 10, weight: .medium, design: .monospaced))
                .foregroundColor(palette.subtleLabelColor)
                .lineLimit(1)
            Spacer(minLength: 4)
            Button(action: {
                let target: ShieldDashboardSection = vm.selectedTab == .purity ? .purity : .radar
                vm.openDashboard(section: target, isFirstRun: false)
            }) {
                HStack(spacing: 4.5) {
                    ZStack(alignment: .topTrailing) {
                        Image(systemName: "macwindow")
                            .font(.system(size: 10, weight: .semibold))
                        if vm.availableUpdate != nil {
                            Circle()
                                .fill(safeGreen)
                                .frame(width: 5, height: 5)
                                .offset(x: 2.5, y: -2)
                        }
                    }
                    Text("控制台")
                        .font(.system(size: 10.5, weight: .semibold))
                }
                .foregroundColor(titaniumAccent)
                .padding(.horizontal, 10)
                .padding(.vertical, 4)
                .background(
                    Capsule().fill(palette.jadePillFill)
                )
                .overlay(
                    Capsule().strokeBorder(palette.jadePillBorder, lineWidth: 0.7)
                )
            }
            .buttonStyle(SnappyButtonStyle(scale: 0.95))
            .help("打开独立控制台窗口（含实时雷达、纯净度体检与防护设置）")
        }
        .padding(.top, 2)
    }
}
