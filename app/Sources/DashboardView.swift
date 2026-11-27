import SwiftUI

// MARK: - Studio Console Shell (Sidebar + Main Canvas Chrome)

struct ShieldDashboardView: View {
    @ObservedObject var nav: ShieldDashboardNavState
    @ObservedObject var state: SetupWizardState
    @ObservedObject var vm: ShieldViewModel
    let onHideToMenuBar: () -> Void
    let onLaunchClaude: () -> Void
    let onUninstall: () -> Void
    let onApplied: () -> Void

    @Environment(\.colorScheme) private var colorScheme
    @Namespace private var navNamespace
    @StateObject var detectHover = LocalState(false)
    @StateObject var uninstallHover = LocalState(false)
    @StateObject var saveHover = LocalState(false)
    @StateObject var updateHover = LocalState(false)
    @StateObject private var hideBarHover = LocalState(false)
    @StateObject private var launchHover = LocalState(false)

    var isDark: Bool { colorScheme == .dark }
    var palette: ShieldPalette { ShieldPalette(isDark: isDark) }

    var canvasBg: Color { palette.canvasBg }
    var sidebarBg: Color { palette.sidebarBg }
    var titaniumAccent: Color { palette.titaniumAccent }
    var safeGreen: Color { palette.safeGreen }
    var dangerRed: Color { palette.dangerRed }
    var warnAmber: Color { palette.warnAmber }
    var accentColor: Color {
        vm.snapshot.isSafe ? safeGreen : dangerRed
    }
    var cardSurface: Color { palette.cardSurface }
    var cardBorder: Color { palette.cardBorder }
    var cardShadow: Color { palette.cardShadow }
    var dividerColor: Color { palette.dividerColor }
    var inkPrimary: Color { palette.inkPrimary }
    var labelColor: Color { palette.labelColor }
    var subtleLabelColor: Color { palette.subtleLabelColor }

    func purityColor(_ score: Int) -> Color {
        ShieldMetricsStyle.purityColor(score, safe: safeGreen, warn: warnAmber, danger: dangerRed)
    }

    func latencyColor(_ ms: Int) -> Color {
        ShieldMetricsStyle.latencyColor(ms, safe: safeGreen, warn: warnAmber, danger: dangerRed)
    }

    func apiLatencyColor(_ ms: Int, jitter: Int?) -> Color {
        ShieldMetricsStyle.apiLatencyColor(ms, jitter: jitter, safe: safeGreen, warn: warnAmber, danger: dangerRed)
    }

    var body: some View {
        HStack(spacing: 0) {
            sidebarColumn
                .frame(width: 232)

            Rectangle()
                .fill(dividerColor)
                .frame(width: 1)

            mainCanvasColumn
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .background(canvasBg.ignoresSafeArea())
        .frame(minWidth: 820, maxWidth: .infinity, minHeight: 580, maxHeight: .infinity)
        .onAppear {
            if state.isFirstRun || state.expectedIP.isEmpty {
                state.runAutoDetect()
            }
            if nav.selectedSection == .purity && vm.purity == nil {
                vm.refreshPurity(silent: true)
            }
        }
        .onChange(of: nav.selectedSection) { newSection in
            if newSection == .purity && vm.purity == nil {
                vm.refreshPurity(silent: true)
            }
            if newSection == .settings && (state.isFirstRun || state.expectedIP.isEmpty) {
                state.runAutoDetect()
            }
        }
    }

    // MARK: - Sidebar

    private var sidebarColumn: some View {
        ZStack {
            sidebarBg.ignoresSafeArea()

            VStack(alignment: .leading, spacing: 16) {
                // Brand Identity — aligned on H1 baseline (y: 34..78, height 44) with right topBarHeader
                HStack(spacing: 11) {
                    ShieldStatusBadge(
                        isSafe: vm.snapshot.isSafe || state.setupReport != nil,
                        accentColor: vm.snapshot.isSafe ? safeGreen : (state.isFirstRun ? titaniumAccent : dangerRed),
                        isDark: isDark,
                        isActive: vm.isDashboardVisible
                    )
                    .scaleEffect(0.92)
                    .frame(width: 42, height: 42)

                    VStack(alignment: .leading, spacing: 3) {
                        Text("Claude Shield")
                            .font(.system(size: 15.5, weight: .bold, design: .rounded))
                            .foregroundColor(inkPrimary)
                        HStack(spacing: 5.5) {
                            Text(AppReleaseConfig.shortDisplayVersion)
                                .font(.system(size: 10.5, weight: .semibold, design: .monospaced))
                                .foregroundColor(titaniumAccent)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 1.5)
                                .background(Capsule().fill(titaniumAccent.opacity(isDark ? 0.18 : 0.10)))
                            Text("Console")
                                .font(.system(size: 10.5, weight: .medium, design: .rounded))
                                .foregroundColor(subtleLabelColor)
                        }
                    }
                    Spacer(minLength: 0)
                }
                .frame(height: 44)
                .padding(.top, 34)
                .padding(.horizontal, 16)

                // Navigation Items — starts on H2 baseline (y: 94) matching right content top
                VStack(spacing: 6) {
                    ForEach(ShieldDashboardSection.allCases) { section in
                        sidebarNavButton(section)
                    }
                }
                .padding(.horizontal, 12)

                Spacer(minLength: 10)

                VStack(alignment: .leading, spacing: 11) {
                    Rectangle()
                        .fill(dividerColor)
                        .frame(height: 1)

                    VStack(alignment: .leading, spacing: 4.5) {
                        HStack(spacing: 6) {
                            PulsingOpacityView(
                                isActive: vm.isDashboardVisible,
                                duration: 2.2,
                                minOpacity: 0.42,
                                maxOpacity: 1.0
                            ) {
                                Circle()
                                    .fill(accentColor)
                            }
                            .frame(width: 7, height: 7)

                            Text(vm.snapshot.isSafe ? "静谧守护中" : "防线需关注")
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundColor(accentColor)

                            Spacer(minLength: 4)

                            Text("\(vm.snapshot.defenseScore)/8")
                                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                                .foregroundColor(subtleLabelColor)
                        }

                        HStack(spacing: 6) {
                            Text(vm.snapshot.expected_ip)
                                .font(.system(size: 12.5, weight: .semibold, design: .monospaced))
                                .foregroundColor(inkPrimary.opacity(0.84))
                                .lineLimit(1)
                                .minimumScaleFactor(0.85)

                            Spacer(minLength: 4)

                            Text(vm.snapshot.region_short)
                                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                                .foregroundColor(subtleLabelColor)
                        }
                    }
                    .padding(.horizontal, 4)

                    Button(action: onLaunchClaude) {
                        HStack(spacing: 6.5) {
                            if vm.isCheckingLaunch {
                                ProgressView()
                                    .controlSize(.mini)
                                    .scaleEffect(0.78)
                            } else {
                                Image(systemName: vm.snapshot.desktopRunning ? "macwindow.on.rectangle" : "play.fill")
                                    .font(.system(size: 11, weight: .semibold))
                                    .foregroundColor(accentColor)
                            }
                            Text(
                                vm.isCheckingLaunch
                                    ? "安全校验中..."
                                    : (vm.snapshot.desktopRunning ? "切回 Claude 桌面版" : "安全启动 Claude")
                            )
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundColor(inkPrimary)
                            .lineLimit(1)
                        }
                        .frame(maxWidth: .infinity)
                        .frame(height: 36)
                        .background(
                            RoundedRectangle(cornerRadius: 10, style: .continuous)
                                .fill(
                                    launchHover.value
                                        ? (isDark ? Color(red: 0.175, green: 0.190, blue: 0.215) : Color.white)
                                        : cardSurface
                                )
                        )
                        .overlay(
                            RoundedRectangle(cornerRadius: 10, style: .continuous)
                                .strokeBorder(
                                    launchHover.value
                                        ? AnyShapeStyle(accentColor.opacity(isDark ? 0.36 : 0.28))
                                        : AnyShapeStyle(palette.cardSpecularBorder),
                                    lineWidth: 0.8
                                )
                        )
                        .shadow(
                            color: launchHover.value ? accentColor.opacity(isDark ? 0.14 : 0.09) : cardShadow,
                            radius: launchHover.value ? 7 : 5,
                            y: 1.5
                        )
                    }
                    .buttonStyle(SnappyButtonStyle(scale: 0.98))
                    .animation(.easeOut(duration: 0.14), value: launchHover.value)
                    .onHover { launchHover.value = $0 }
                    .disabled(vm.isCheckingLaunch)
                }
                .padding(.horizontal, 14)
                .padding(.bottom, 18)
            }
        }
    }

    private func sidebarNavButton(_ section: ShieldDashboardSection) -> some View {
        let active = nav.selectedSection == section
        return Button(action: {
            withAnimation(.spring(response: 0.26, dampingFraction: 0.86)) {
                nav.selectedSection = section
            }
        }) {
            HStack(spacing: 10.5) {
                RoundedRectangle(cornerRadius: 2, style: .continuous)
                    .fill(active ? titaniumAccent : Color.clear)
                    .frame(width: 3, height: 22)

                Image(systemName: section.icon)
                    .font(.system(size: 15, weight: active ? .semibold : .medium))
                    .foregroundColor(active ? titaniumAccent : labelColor)
                    .frame(width: 22, alignment: .center)

                VStack(alignment: .leading, spacing: 2) {
                    Text(section.title)
                        .font(.system(size: 13.5, weight: active ? .semibold : .medium))
                        .foregroundColor(active ? inkPrimary : inkPrimary.opacity(0.76))
                    Text(section.caption)
                        .font(.system(size: 11, weight: .regular))
                        .foregroundColor(subtleLabelColor)
                        .lineLimit(1)
                }

                Spacer(minLength: 4)

                if section == .purity, let p = vm.purity {
                    let pc = purityColor(p.purity_score)
                    Text("\(p.purity_score)")
                        .font(.system(size: 11, weight: .bold, design: .monospaced))
                        .foregroundColor(pc)
                        .padding(.horizontal, 6.5)
                        .padding(.vertical, 2.5)
                        .background(Capsule().fill(pc.opacity(isDark ? 0.18 : 0.10)))
                } else if section == .settings, vm.availableUpdate != nil {
                    Circle()
                        .fill(titaniumAccent)
                        .frame(width: 7, height: 7)
                }
            }
            .padding(.leading, 7)
            .padding(.trailing, 11)
            .padding(.vertical, 10.5)
            .contentShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            .background(
                ZStack {
                    if active {
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .fill(cardSurface)
                            .overlay(
                                RoundedRectangle(cornerRadius: 10, style: .continuous)
                                    .strokeBorder(palette.cardSpecularBorder, lineWidth: 0.75)
                            )
                            .shadow(color: cardShadow, radius: 6, y: 2)
                            .matchedGeometryEffect(id: "dashboardNavPill", in: navNamespace)
                    }
                }
            )
        }
        .buttonStyle(.plain)
    }

    // MARK: - Main Canvas

    private var mainCanvasColumn: some View {
        ZStack(alignment: .bottom) {
            canvasBg.ignoresSafeArea()

            VStack(spacing: 0) {
                palette.topAtmosphereGlow(isSafe: vm.snapshot.isSafe)
                    .frame(height: 160)
                Spacer()
            }
            .allowsHitTesting(false)
            .ignoresSafeArea()

            VStack(spacing: 0) {
                topBarHeader

                GeometryReader { geo in
                    let contentWidth = max(480, geo.size.width - 48)
                    let useThreeMatrixCols = contentWidth >= 560

                    ScrollView(.vertical, showsIndicators: false) {
                        VStack(alignment: .leading, spacing: 14) {
                            if shouldShowSettingsUpdateCard && nav.selectedSection != .settings {
                                settingsUpdateCard
                            }

                            switch nav.selectedSection {
                            case .radar:
                                radarSectionContent(useThreeMatrixCols: useThreeMatrixCols)
                            case .purity:
                                puritySectionContent(wide: useThreeMatrixCols)
                            case .settings:
                                settingsSectionContent(onApplied: onApplied, onHideToMenuBar: onHideToMenuBar, onLaunchClaude: onLaunchClaude, onUninstall: onUninstall)
                            }
                        }
                        .padding(.horizontal, 24)
                        .padding(.top, 0)
                        .padding(.bottom, 18)
                        .frame(maxWidth: 1040, alignment: .leading)
                        .frame(maxWidth: .infinity, alignment: .center)
                    }
                }
            }

            if let toast = vm.toastMessage {
                Text(toast)
                    .font(.system(size: 11.5, weight: .semibold))
                    .foregroundColor(.white)
                    .padding(.horizontal, 15)
                    .padding(.vertical, 7.5)
                    .background(Capsule().fill(Color.black.opacity(0.84)))
                    .shadow(color: .black.opacity(0.20), radius: 8, y: 3)
                    .padding(.bottom, 16)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
    }

    private var topBarHeader: some View {
        HStack(alignment: .center, spacing: 12) {
            HStack(spacing: 8) {
                Text(state.isFirstRun && nav.selectedSection == .settings ? "欢迎使用 Claude Shield" : nav.selectedSection.title)
                    .font(.system(size: 20, weight: .bold, design: .rounded))
                    .foregroundColor(inkPrimary)

                if !vm.snapshot.isSafe {
                    Text("异常警戒")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(dangerRed)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(Capsule().fill(dangerRed.opacity(isDark ? 0.18 : 0.10)))
                }

                if nav.selectedSection == .settings && !state.isFirstRun {
                    updateCheckPill
                }
            }

            Spacer(minLength: 12)

            HStack(spacing: 8) {
                Button(action: { vm.refresh(force: true, mode: .full, userInitiated: true) }) {
                    HStack(spacing: 5.5) {
                        if vm.isRefreshing {
                            ProgressView().controlSize(.mini).scaleEffect(0.76)
                        } else {
                            Image(systemName: "arrow.clockwise")
                                .font(.system(size: 11, weight: .semibold))
                        }
                        Text(vm.isRefreshing ? "测速中" : "重新测速")
                            .font(.system(size: 12, weight: .medium))
                    }
                    .foregroundColor(inkPrimary.opacity(0.82))
                    .padding(.horizontal, 12)
                    .frame(height: 32)
                    .background(Capsule().fill(cardSurface))
                    .overlay(Capsule().strokeBorder(cardBorder, lineWidth: 0.75))
                }
                .buttonStyle(SnappyButtonStyle(scale: 0.96))
                .help("重新探测双通道出口 IP 与 Anthropic API 延迟")

                Button(action: onHideToMenuBar) {
                    HStack(spacing: 5.5) {
                        Image(systemName: "menubar.arrow.up.rectangle")
                            .font(.system(size: 11.5, weight: .medium))
                        Text("收至状态栏")
                            .font(.system(size: 12, weight: .medium))
                    }
                    .foregroundColor(hideBarHover.value ? titaniumAccent : inkPrimary.opacity(0.82))
                    .padding(.horizontal, 12.5)
                    .frame(height: 32)
                    .background(
                        Capsule().fill(
                            hideBarHover.value
                                ? titaniumAccent.opacity(isDark ? 0.16 : 0.09)
                                : cardSurface
                        )
                    )
                    .overlay(
                        Capsule().strokeBorder(
                            hideBarHover.value ? titaniumAccent.opacity(0.32) : cardBorder,
                            lineWidth: 0.75
                        )
                    )
                }
                .buttonStyle(SnappyButtonStyle(scale: 0.96))
                .animation(.easeOut(duration: 0.12), value: hideBarHover.value)
                .onHover { hideBarHover.value = $0 }
                .help("隐藏控制台至顶部状态栏继续守护（⌘W）")
            }
        }
        .frame(height: 44)
        .padding(.horizontal, 24)
        .padding(.top, 34)
        .padding(.bottom, 16)
    }

    private var updateCheckPill: some View {
        Button(action: {
            if let info = vm.availableUpdate, !vm.updatePhase.isBusy {
                vm.performUpdate(info)
            } else {
                vm.checkForUpdates(manual: true)
            }
        }) {
            HStack(spacing: 4) {
                if vm.updatePhase.isBusy {
                    ProgressView().controlSize(.mini).scaleEffect(0.72)
                } else if case .upToDate = vm.updatePhase {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 10, weight: .semibold))
                } else if vm.availableUpdate != nil {
                    Image(systemName: "arrow.down.circle.fill")
                        .font(.system(size: 10, weight: .semibold))
                } else {
                    Image(systemName: "arrow.triangle.2.circlepath")
                        .font(.system(size: 10, weight: .semibold))
                }
                Text(updatePillLabel)
                    .font(.system(size: 10.5, weight: .semibold))
            }
            .foregroundColor(updatePillForeground)
            .padding(.horizontal, 8.5)
            .padding(.vertical, 3)
            .background(Capsule().fill(updatePillBackground))
        }
        .buttonStyle(SnappyButtonStyle(scale: 0.96))
        .animation(.easeOut(duration: 0.12), value: updateHover.value)
        .onHover { updateHover.value = $0 }
        .disabled(vm.updatePhase.isBusy)
        .help("从 GitHub Releases 检查并安装最新版本")
    }
}
