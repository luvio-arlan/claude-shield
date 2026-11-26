import SwiftUI

// MARK: - Studio Console Section 3: 防护设置

extension ShieldDashboardView {
    private var tzPresets: [(String, String)] {
        [
            ("洛杉矶", "America/Los_Angeles"),
            ("纽约", "America/New_York"),
            ("东京", "Asia/Tokyo"),
            ("新加坡", "Asia/Singapore"),
            ("伦敦", "Europe/London"),
            ("法兰克福", "Europe/Berlin")
        ]
    }

    private var builtinTags: [String] {
        ["CLI 门禁", "OAuth 拦截", "Seatbelt 沙盒", "零遥测", "IPv4-First"]
    }

    func settingsSectionContent(
        onApplied: @escaping () -> Void,
        onHideToMenuBar: @escaping () -> Void,
        onLaunchClaude: @escaping () -> Void,
        onUninstall: @escaping () -> Void
    ) -> some View {
        VStack(alignment: .leading, spacing: 18) {
            if !state.isFirstRun, shouldShowSettingsUpdateCard {
                settingsUpdateCard
            }

            if let report = state.setupReport {
                completionCard(
                    report,
                    onHideToMenuBar: onHideToMenuBar,
                    onLaunchClaude: onLaunchClaude
                )
            } else {
                networkConfigCard
                optionsCard

                if let err = state.errorMessage {
                    HStack(spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.system(size: 13))
                            .foregroundColor(warnAmber)
                        Text(err)
                            .font(.system(size: 12.5, weight: .medium))
                            .foregroundColor(.primary.opacity(0.9))
                            .fixedSize(horizontal: false, vertical: true)
                        Spacer(minLength: 0)
                    }
                    .padding(.horizontal, 14)
                    .padding(.vertical, 11)
                    .background(RoundedRectangle(cornerRadius: 11, style: .continuous).fill(warnAmber.opacity(isDark ? 0.15 : 0.10)))
                    .overlay(RoundedRectangle(cornerRadius: 11, style: .continuous).strokeBorder(warnAmber.opacity(0.32), lineWidth: 0.8))
                }

                bottomActionRow(onApplied: onApplied, onUninstall: onUninstall)
            }
        }
    }

    var shouldShowSettingsUpdateCard: Bool {
        switch vm.updatePhase {
        case .available, .downloading, .installing, .failed:
            return true
        default:
            return false
        }
    }

    @ViewBuilder
    var settingsUpdateCard: some View {
        if let info = vm.updatePhase.info {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 10) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 9, style: .continuous)
                            .fill(brandTerracotta.opacity(isDark ? 0.20 : 0.12))
                            .frame(width: 34, height: 34)
                        Image(systemName: "arrow.down.circle.fill")
                            .font(.system(size: 16, weight: .semibold))
                            .foregroundColor(brandTerracotta)
                    }

                    VStack(alignment: .leading, spacing: 2.5) {
                        HStack(spacing: 6) {
                            Text("发现新版本 \(info.tagName)")
                                .font(.system(size: 13.5, weight: .bold))
                                .foregroundColor(.primary)
                            Text("当前 \(AppReleaseConfig.shortDisplayVersion)")
                                .font(.system(size: 10.5, weight: .medium, design: .monospaced))
                                .foregroundColor(labelColor)
                        }
                        Group {
                            switch vm.updatePhase {
                            case .downloading(_, let p):
                                Text("正在从 GitHub Release 下载更新包… \(Int(p * 100))%")
                            case .installing(_, let stage):
                                Text(stage)
                            default:
                                Text(info.notesSummary)
                            }
                        }
                        .font(.system(size: 11.5, weight: .regular))
                        .foregroundColor(labelColor)
                        .lineLimit(2)
                    }

                    Spacer(minLength: 8)

                    if vm.updatePhase.isBusy {
                        ProgressView().controlSize(.small)
                    } else {
                        HStack(spacing: 7) {
                            Button(action: { vm.openReleasePage(info.htmlURL) }) {
                                Text("查看日志")
                                    .font(.system(size: 11.5, weight: .semibold))
                                    .foregroundColor(labelColor)
                                    .padding(.horizontal, 10)
                                    .padding(.vertical, 6)
                                    .background(Capsule().fill(isDark ? Color.white.opacity(0.08) : Color.black.opacity(0.05)))
                            }
                            .buttonStyle(SnappyButtonStyle(scale: 0.96))

                            Button(action: { vm.performUpdate(info) }) {
                                HStack(spacing: 4) {
                                    Image(systemName: info.zipDownloadURL != nil ? "arrow.down.to.line" : "safari")
                                        .font(.system(size: 11, weight: .semibold))
                                    Text(info.zipDownloadURL != nil ? "立即更新" : "前往下载")
                                        .font(.system(size: 12, weight: .semibold))
                                }
                                .foregroundColor(.white)
                                .padding(.horizontal, 12)
                                .padding(.vertical, 6)
                                .background(Capsule().fill(brandGradient))
                            }
                            .buttonStyle(SnappyButtonStyle(scale: 0.96))
                        }
                    }
                }

                if case .downloading(_, let progress) = vm.updatePhase {
                    GeometryReader { geo in
                        ZStack(alignment: .leading) {
                            Capsule()
                                .fill(brandTerracotta.opacity(isDark ? 0.20 : 0.14))
                                .frame(height: 5)
                            Capsule()
                                .fill(brandGradient)
                                .frame(width: max(10, geo.size.width * CGFloat(progress)), height: 5)
                                .animation(.easeOut(duration: 0.18), value: progress)
                        }
                    }
                    .frame(height: 5)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 13)
            .background(
                RoundedRectangle(cornerRadius: 13, style: .continuous)
                    .fill(brandTerracotta.opacity(isDark ? 0.12 : 0.07))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 13, style: .continuous)
                    .strokeBorder(brandTerracotta.opacity(isDark ? 0.35 : 0.26), lineWidth: 0.9)
            )
        } else if case .failed(let msg) = vm.updatePhase {
            HStack(spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 13))
                    .foregroundColor(warnAmber)
                Text(msg)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(.primary.opacity(0.88))
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 6)
                Button("重试") { vm.checkForUpdates(manual: true) }
                    .buttonStyle(SnappyButtonStyle(scale: 0.96))
                    .font(.system(size: 11.5, weight: .semibold))
                    .foregroundColor(brandTerracotta)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4.5)
                    .background(Capsule().fill(brandTerracotta.opacity(isDark ? 0.18 : 0.11)))
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .background(RoundedRectangle(cornerRadius: 11, style: .continuous).fill(warnAmber.opacity(isDark ? 0.14 : 0.09)))
            .overlay(RoundedRectangle(cornerRadius: 11, style: .continuous).strokeBorder(warnAmber.opacity(0.30), lineWidth: 0.8))
        }
    }

    var updatePillLabel: String {
        switch vm.updatePhase {
        case .checking: return "检查中"
        case .upToDate: return "已是最新"
        case .available(let info): return "升级 \(info.tagName)"
        case .downloading(_, let p): return "下载 \(Int(p * 100))%"
        case .installing: return "安装中"
        case .idle, .failed: return "检查更新"
        }
    }

    var updatePillForeground: Color {
        switch vm.updatePhase {
        case .upToDate: return safeGreen
        case .available, .downloading, .installing: return brandTerracotta
        default: return updateHover.value ? .primary : labelColor
        }
    }

    var updatePillBackground: Color {
        switch vm.updatePhase {
        case .upToDate:
            return safeGreen.opacity(isDark ? 0.18 : 0.11)
        case .available, .downloading, .installing:
            return brandTerracotta.opacity(updateHover.value ? (isDark ? 0.28 : 0.18) : (isDark ? 0.20 : 0.12))
        default:
            return updateHover.value
                ? (isDark ? Color.white.opacity(0.12) : Color.black.opacity(0.08))
                : (isDark ? Color.white.opacity(0.07) : Color.black.opacity(0.045))
        }
    }

    private var networkConfigCard: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .center) {
                HStack(spacing: 7) {
                    Image(systemName: "network.badge.shield.half.filled")
                        .font(.system(size: 14.5, weight: .semibold))
                        .foregroundColor(brandTerracotta)
                    Text("网络与地区")
                        .font(.system(size: 14.5, weight: .bold))
                        .foregroundColor(.primary)
                }

                Spacer()

                Button(action: { state.runAutoDetect() }) {
                    HStack(spacing: 5) {
                        if state.isDetecting {
                            ProgressView().controlSize(.mini).scaleEffect(0.8)
                        } else {
                            Image(systemName: "wand.and.stars")
                                .font(.system(size: 11.5, weight: .semibold))
                        }
                        Text(state.isDetecting ? "正在探测..." : "自动识别节点")
                            .font(.system(size: 12, weight: .semibold))
                    }
                    .foregroundColor(brandTerracotta)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(
                        Capsule().fill(
                            brandTerracotta.opacity(detectHover.value ? (isDark ? 0.26 : 0.17) : (isDark ? 0.16 : 0.10))
                        )
                    )
                }
                .buttonStyle(SnappyButtonStyle())
                .onHover { h in withAnimation(.easeOut(duration: 0.12)) { detectHover.value = h } }
                .disabled(state.isDetecting)
            }

            if let info = state.detectedInfo, !info.exit_ip.isEmpty {
                HStack(spacing: 8) {
                    Circle()
                        .fill(info.tun_matches ? safeGreen : warnAmber)
                        .frame(width: 7.5, height: 7.5)
                    Text("\(info.country_code.isEmpty ? "US" : info.country_code)\(info.city.isEmpty ? "" : " · \(info.city)")\(info.isp.isEmpty ? "" : " · \(info.isp)")")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(.primary.opacity(0.84))
                        .lineLimit(1)
                    Spacer()
                    Text(info.tun_matches ? "Proxy & TUN 一致" : "请确认已开启 TUN")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(info.tun_matches ? safeGreen : warnAmber)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8.5)
                .background(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill((info.tun_matches ? safeGreen : warnAmber).opacity(isDark ? 0.12 : 0.08))
                )
            }

            HStack(spacing: 14) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("白名单出口 IP")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(labelColor)
                    StyledSettingsInput(placeholder: "例如 45.77.12.34", text: $state.expectedIP, isDark: isDark)
                }

                VStack(alignment: .leading, spacing: 6) {
                    Text("本地代理端口")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(labelColor)
                    StyledSettingsInput(placeholder: "7897", text: $state.proxyPortText, isDark: isDark)
                        .frame(width: 140)
                }
            }

            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text("目标时区 (TZ)")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(labelColor)
                    Spacer()
                    Text("语言自动锁定 en_US.UTF-8")
                        .font(.system(size: 11, weight: .medium, design: .monospaced))
                        .foregroundColor(safeGreen)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 2.5)
                        .background(Capsule().fill(safeGreen.opacity(isDark ? 0.14 : 0.09)))
                }

                StyledSettingsInput(placeholder: "America/Los_Angeles", text: $state.targetTZ, isDark: isDark)

                HStack(spacing: 7) {
                    ForEach(tzPresets, id: \.1) { label, tz in
                        let selected = state.targetTZ == tz
                        Button(label) {
                            withAnimation(.easeOut(duration: 0.15)) {
                                state.targetTZ = tz
                            }
                        }
                        .buttonStyle(SnappyButtonStyle(scale: 0.96))
                        .font(.system(size: 11.5, weight: selected ? .semibold : .medium))
                        .foregroundColor(selected ? .white : .primary.opacity(0.78))
                        .padding(.horizontal, 11)
                        .padding(.vertical, 5)
                        .background(
                            Capsule().fill(
                                selected
                                    ? AnyShapeStyle(brandGradient)
                                    : AnyShapeStyle(isDark ? Color.white.opacity(0.07) : Color.black.opacity(0.045))
                            )
                        )
                    }
                    Spacer(minLength: 0)
                }
                .padding(.top, 2)
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 15, style: .continuous).fill(cardSurface))
        .overlay(RoundedRectangle(cornerRadius: 15, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.85))
        .shadow(color: cardShadow, radius: 5, y: 2)
    }

    private func policyRow(
        icon: String,
        title: String,
        subtitle: String,
        isOn: Binding<Bool>
    ) -> some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(brandTerracotta.opacity(isDark ? 0.16 : 0.10))
                    .frame(width: 34, height: 34)
                Image(systemName: icon)
                    .font(.system(size: 14.5, weight: .semibold))
                    .foregroundColor(brandTerracotta)
            }

            VStack(alignment: .leading, spacing: 2.5) {
                Text(title)
                    .font(.system(size: 13.5, weight: .semibold))
                    .foregroundColor(.primary)
                Text(subtitle)
                    .font(.system(size: 11.5, weight: .regular))
                    .foregroundColor(labelColor)
                    .lineLimit(1)
            }

            Spacer(minLength: 12)

            Toggle("", isOn: isOn)
                .labelsHidden()
                .toggleStyle(.switch)
                .tint(brandTerracotta)
                .controlSize(.regular)
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var optionsCard: some View {
        VStack(spacing: 0) {
            policyRow(
                icon: "eye.slash.fill",
                title: "隐藏原版 Claude.app 图标",
                subtitle: "移入隔离仓防误点裸连，卸载时一键无损还原",
                isOn: $state.hideOriginal
            )

            Divider().overlay(dividerColor).padding(.leading, 66)

            policyRow(
                icon: "bolt.shield.fill",
                title: "开机自启状态栏雷达",
                subtitle: "登录 macOS 后自动守护休眠唤醒与网络切换",
                isOn: $state.enableAutostart
            )

            Divider().overlay(dividerColor).padding(.leading, 66)

            policyRow(
                icon: "sparkle.magnifyingglass",
                title: "每日 09:30 自动纯净度巡检",
                subtitle: "静默检测 DNS/IPv6 泄露，异常时主动提醒",
                isOn: $state.enableDailyPatrol
            )

            Divider().overlay(dividerColor)

            VStack(alignment: .leading, spacing: 9) {
                HStack(spacing: 6) {
                    Image(systemName: "checkmark.shield.fill")
                        .font(.system(size: 11.5, weight: .semibold))
                        .foregroundColor(safeGreen)
                    Text("默认内置防线")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundColor(labelColor)
                    Spacer()
                    Text("已自动启用 · \(builtinTags.count) 项")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(safeGreen)
                }

                HStack(spacing: 8) {
                    ForEach(builtinTags, id: \.self) { tag in
                        HStack(spacing: 4) {
                            Image(systemName: "checkmark.circle.fill")
                                .font(.system(size: 10.5))
                                .foregroundColor(safeGreen)
                            Text(tag)
                                .font(.system(size: 11.5, weight: .medium))
                                .foregroundColor(.primary.opacity(0.84))
                                .lineLimit(1)
                                .fixedSize(horizontal: true, vertical: false)
                        }
                        .padding(.horizontal, 9.5)
                        .padding(.vertical, 5)
                        .background(
                            Capsule().fill(safeGreen.opacity(isDark ? 0.13 : 0.085))
                        )
                        .overlay(
                            Capsule().strokeBorder(safeGreen.opacity(isDark ? 0.22 : 0.14), lineWidth: 0.6)
                        )
                    }
                    Spacer(minLength: 0)
                }
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 14)
        }
        .frame(maxWidth: .infinity)
        .background(RoundedRectangle(cornerRadius: 15, style: .continuous).fill(cardSurface))
        .overlay(RoundedRectangle(cornerRadius: 15, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.85))
        .shadow(color: cardShadow, radius: 5, y: 2)
    }

    private func bottomActionRow(onApplied: @escaping () -> Void, onUninstall: @escaping () -> Void) -> some View {
        HStack(spacing: 12) {
            if !state.isFirstRun {
                Button(action: onUninstall) {
                    HStack(spacing: 5.5) {
                        Image(systemName: "arrow.uturn.backward.circle")
                            .font(.system(size: 12.5, weight: .medium))
                        Text("卸载并还原")
                            .font(.system(size: 12.5, weight: .semibold))
                    }
                    .foregroundColor(dangerRed.opacity(0.90))
                    .padding(.horizontal, 15)
                    .frame(height: 38)
                    .background(
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .fill(dangerRed.opacity(uninstallHover.value ? (isDark ? 0.18 : 0.11) : (isDark ? 0.10 : 0.06)))
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .strokeBorder(dangerRed.opacity(uninstallHover.value ? 0.36 : 0.18), lineWidth: 0.75)
                    )
                }
                .buttonStyle(SnappyButtonStyle())
                .onHover { h in withAnimation(.easeOut(duration: 0.12)) { uninstallHover.value = h } }
            }

            Spacer(minLength: 12)

            Button(action: {
                state.applySetup(onSuccess: onApplied)
            }) {
                HStack(spacing: 6.5) {
                    if state.isApplying {
                        ProgressView().controlSize(.small).scaleEffect(0.8)
                    } else {
                        Image(systemName: "checkmark.shield.fill")
                            .font(.system(size: 13, weight: .semibold))
                    }
                    Text(state.isApplying ? "正在部署防线..." : (state.isFirstRun ? "一键部署全套防封防护" : "保存并应用防护"))
                        .font(.system(size: 13, weight: .semibold))
                }
                .padding(.horizontal, 24)
                .frame(height: 38)
                .foregroundColor(.white)
                .background(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill(brandGradient)
                        .brightness(saveHover.value ? 0.04 : 0)
                )
                .shadow(color: brandTerracotta.opacity(saveHover.value ? 0.28 : 0.16), radius: 6, y: 2)
            }
            .buttonStyle(SnappyButtonStyle(scale: 0.98))
            .onHover { h in withAnimation(.easeOut(duration: 0.12)) { saveHover.value = h } }
            .disabled(state.isApplying)
        }
        .padding(.top, 2)
    }

    private func completionCard(
        _ report: SetupReportModel,
        onHideToMenuBar: @escaping () -> Void,
        onLaunchClaude: @escaping () -> Void
    ) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                ZStack {
                    Circle()
                        .fill(safeGreen.opacity(isDark ? 0.18 : 0.12))
                        .frame(width: 44, height: 44)
                    Image(systemName: "checkmark.seal.fill")
                        .font(.system(size: 22))
                        .foregroundColor(safeGreen)
                }
                VStack(alignment: .leading, spacing: 3) {
                    Text("全套本地防封防线已就绪")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundColor(.primary)
                    Text("\(report.expected_ip) · 端口 \(report.proxy_port) · \(report.target_tz) · en_US.UTF-8")
                        .font(.system(size: 12, weight: .medium, design: .monospaced))
                        .foregroundColor(labelColor)
                }
            }

            VStack(alignment: .leading, spacing: 9) {
                ForEach(report.actions, id: \.self) { item in
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.system(size: 13))
                            .foregroundColor(safeGreen)
                            .padding(.top, 1.5)
                        Text(item)
                            .font(.system(size: 13, weight: .medium))
                            .foregroundColor(.primary.opacity(0.9))
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(cardSurface))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.85))

            HStack(spacing: 12) {
                Button("返回实时雷达") {
                    state.setupReport = nil
                    withAnimation(.spring(response: 0.28, dampingFraction: 0.84)) {
                        nav.selectedSection = .radar
                    }
                }
                .buttonStyle(SnappyButtonStyle())
                .font(.system(size: 13.5, weight: .semibold))
                .foregroundColor(.primary)
                .padding(.horizontal, 22)
                .frame(height: 44)
                .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(cardSurface))
                .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.9))

                Button("收起到状态栏") {
                    state.setupReport = nil
                    onHideToMenuBar()
                }
                .buttonStyle(SnappyButtonStyle())
                .font(.system(size: 13.5, weight: .semibold))
                .foregroundColor(labelColor)
                .padding(.horizontal, 18)
                .frame(height: 44)
                .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(cardSurface))
                .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.9))

                Button(action: {
                    state.setupReport = nil
                    onHideToMenuBar()
                    onLaunchClaude()
                }) {
                    HStack(spacing: 7) {
                        Image(systemName: "play.fill").font(.system(size: 12.5))
                        Text("立即安全启动 Claude").font(.system(size: 14.5, weight: .semibold))
                    }
                    .frame(maxWidth: .infinity)
                    .frame(height: 44)
                    .foregroundColor(.white)
                    .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(brandGradient))
                    .shadow(color: Color(red: 0.75, green: 0.31, blue: 0.18).opacity(0.28), radius: 8, y: 3)
                }
                .buttonStyle(SnappyButtonStyle(scale: 0.985))
            }
        }
    }
}
