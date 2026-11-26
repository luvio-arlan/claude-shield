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
    @StateObject private var pulseDot = LocalState(false)

    var isDark: Bool { colorScheme == .dark }

    var canvasBg: Color {
        isDark ? Color(red: 0.095, green: 0.093, blue: 0.090) : Color(red: 0.969, green: 0.961, blue: 0.945)
    }
    var sidebarBg: Color {
        isDark ? Color(red: 0.118, green: 0.115, blue: 0.111) : Color(red: 0.941, green: 0.931, blue: 0.912)
    }
    var brandTerracotta: Color {
        isDark ? Color(red: 0.86, green: 0.48, blue: 0.34) : Color(red: 0.80, green: 0.41, blue: 0.27)
    }
    var safeGreen: Color {
        isDark ? Color(red: 0.26, green: 0.78, blue: 0.58) : Color(red: 0.11, green: 0.53, blue: 0.39)
    }
    var dangerRed: Color {
        isDark ? Color(red: 0.94, green: 0.42, blue: 0.44) : Color(red: 0.80, green: 0.22, blue: 0.22)
    }
    var warnAmber: Color {
        isDark ? Color(red: 0.94, green: 0.70, blue: 0.28) : Color(red: 0.75, green: 0.44, blue: 0.08)
    }
    var accentColor: Color {
        vm.snapshot.isSafe ? safeGreen : dangerRed
    }
    var cardSurface: Color {
        isDark ? Color(red: 0.145, green: 0.142, blue: 0.137) : Color.white
    }
    var cardBorder: Color {
        isDark ? Color.white.opacity(0.075) : Color.black.opacity(0.058)
    }
    var cardShadow: Color {
        isDark ? Color.black.opacity(0.22) : Color.black.opacity(0.032)
    }
    var dividerColor: Color {
        isDark ? Color.white.opacity(0.065) : Color.black.opacity(0.055)
    }
    var inkPrimary: Color {
        isDark ? Color(red: 0.94, green: 0.93, blue: 0.91) : Color(red: 0.15, green: 0.145, blue: 0.135)
    }
    var labelColor: Color {
        isDark ? Color.white.opacity(0.56) : Color(red: 0.44, green: 0.42, blue: 0.39)
    }
    var subtleLabelColor: Color {
        isDark ? Color.white.opacity(0.40) : Color(red: 0.58, green: 0.55, blue: 0.51)
    }
    var brandGradient: LinearGradient {
        LinearGradient(
            colors: [
                Color(red: 0.83, green: 0.44, blue: 0.30),
                Color(red: 0.74, green: 0.35, blue: 0.22)
            ],
            startPoint: .top,
            endPoint: .bottom
        )
    }

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
            withAnimation(.easeInOut(duration: 2.2).repeatForever(autoreverses: true)) {
                pulseDot.value = true
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
                        accentColor: vm.snapshot.isSafe ? safeGreen : (state.isFirstRun ? brandTerracotta : dangerRed),
                        isDark: isDark
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
                                .foregroundColor(brandTerracotta)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 1.5)
                                .background(Capsule().fill(brandTerracotta.opacity(isDark ? 0.18 : 0.10)))
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

                VStack(alignment: .leading, spacing: 0) {
                    VStack(alignment: .leading, spacing: 6.5) {
                        HStack(spacing: 6.5) {
                            Circle()
                                .fill(accentColor)
                                .frame(width: 7.5, height: 7.5)
                                .opacity(pulseDot.value ? 1.0 : 0.42)
                            Text(vm.snapshot.isSafe ? "静谧守护中" : "防线需关注")
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundColor(accentColor)
                            Spacer()
                            Text("\(vm.snapshot.defenseScore)/8")
                                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                                .foregroundColor(subtleLabelColor)
                        }

                        Text(vm.snapshot.expected_ip)
                            .font(.system(size: 13, weight: .bold, design: .monospaced))
                            .foregroundColor(inkPrimary.opacity(0.88))
                            .lineLimit(1)

                        Text("\(vm.snapshot.region_short) · 更新 \(vm.snapshot.checked_at)")
                            .font(.system(size: 11, weight: .medium, design: .monospaced))
                            .foregroundColor(subtleLabelColor)
                            .lineLimit(1)
                    }
                    .padding(14)

                    Divider().overlay(dividerColor).padding(.horizontal, 10)

                    Button(action: onLaunchClaude) {
                        HStack(spacing: 6.5) {
                            if vm.isCheckingLaunch {
                                ProgressView()
                                    .controlSize(.mini)
                                    .scaleEffect(0.78)
                            } else {
                                Image(systemName: vm.snapshot.desktopRunning ? "macwindow.on.rectangle" : "play.fill")
                                    .font(.system(size: 11, weight: .semibold))
                            }
                            Text(
                                vm.isCheckingLaunch
                                    ? "安全校验中..."
                                    : (vm.snapshot.desktopRunning ? "切回 Claude 桌面版" : "安全启动 Claude")
                            )
                            .font(.system(size: 13, weight: .semibold))
                            .lineLimit(1)
                        }
                        .frame(maxWidth: .infinity)
                        .frame(height: 38)
                        .foregroundColor(brandTerracotta)
                        .background(
                            RoundedRectangle(cornerRadius: 9, style: .continuous)
                                .fill(
                                    brandTerracotta.opacity(
                                        launchHover.value
                                            ? (isDark ? 0.22 : 0.14)
                                            : (isDark ? 0.14 : 0.085)
                                    )
                                )
                        )
                    }
                    .buttonStyle(SnappyButtonStyle(scale: 0.98))
                    .onHover { h in withAnimation(.easeOut(duration: 0.12)) { launchHover.value = h } }
                    .disabled(vm.isCheckingLaunch)
                    .padding(9)
                }
                .background(
                    RoundedRectangle(cornerRadius: 13, style: .continuous)
                        .fill(cardSurface.opacity(isDark ? 0.86 : 0.90))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 13, style: .continuous)
                        .strokeBorder(cardBorder, lineWidth: 0.75)
                )
                .shadow(color: cardShadow, radius: 5, y: 1.5)
                .padding(.horizontal, 12)
                .padding(.bottom, 20)
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
                    .fill(active ? brandTerracotta : Color.clear)
                    .frame(width: 3, height: 22)

                Image(systemName: section.icon)
                    .font(.system(size: 15, weight: active ? .semibold : .medium))
                    .foregroundColor(active ? brandTerracotta : labelColor)
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
                        .fill(brandTerracotta)
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
                                    .strokeBorder(cardBorder, lineWidth: 0.7)
                            )
                            .shadow(color: cardShadow, radius: 5, y: 1.5)
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
                LinearGradient(
                    colors: [
                        (vm.snapshot.isSafe ? safeGreen : brandTerracotta).opacity(isDark ? 0.08 : 0.045),
                        Color.clear
                    ],
                    startPoint: .top,
                    endPoint: .bottom
                )
                .frame(height: 140)
                Spacer()
            }
            .allowsHitTesting(false)
            .ignoresSafeArea()

            GeometryReader { geo in
                let contentWidth = max(480, geo.size.width - 48)
                let useThreeMatrixCols = contentWidth >= 560

                VStack(spacing: 0) {
                    topBarHeader

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
                Button(action: { vm.refresh(force: true) }) {
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
                    .foregroundColor(hideBarHover.value ? brandTerracotta : inkPrimary.opacity(0.82))
                    .padding(.horizontal, 12.5)
                    .frame(height: 32)
                    .background(
                        Capsule().fill(
                            hideBarHover.value
                                ? brandTerracotta.opacity(isDark ? 0.16 : 0.09)
                                : cardSurface
                        )
                    )
                    .overlay(
                        Capsule().strokeBorder(
                            hideBarHover.value ? brandTerracotta.opacity(0.32) : cardBorder,
                            lineWidth: 0.75
                        )
                    )
                }
                .buttonStyle(SnappyButtonStyle(scale: 0.96))
                .onHover { h in withAnimation(.easeOut(duration: 0.12)) { hideBarHover.value = h } }
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
        .onHover { h in withAnimation(.easeOut(duration: 0.12)) { updateHover.value = h } }
        .disabled(vm.updatePhase.isBusy)
        .help("从 GitHub Releases 检查并安装最新版本")
    }
}
