import Cocoa
import SwiftUI

// MARK: - Launch Guard Interception Modal (IP Change / Low Purity)

@MainActor
final class LaunchGuardState: ObservableObject {
    @Published var context: LaunchGuardContext
    @Published var isRechecking: Bool = false
    @Published var passedAndLaunching: Bool = false

    init(context: LaunchGuardContext) {
        self.context = context
    }
}

struct LaunchGuardView: View {
    @ObservedObject var state: LaunchGuardState
    let onCancel: () -> Void
    let onRecheck: () -> Void
    let onForceLaunch: () -> Void

    @Environment(\.colorScheme) private var colorScheme
    @StateObject private var forceHover = LocalState(false)
    @StateObject private var cancelHover = LocalState(false)
    @StateObject private var recheckHover = LocalState(false)

    private var isDark: Bool { colorScheme == .dark }
    private var palette: ShieldPalette { ShieldPalette(isDark: isDark) }
    private var ctx: LaunchGuardContext { state.context }

    private var safeGreen: Color { palette.safeGreen }
    private var dangerRed: Color { palette.dangerRed }
    private var warnAmber: Color { palette.warnAmber }
    private var accentColor: Color {
        if state.passedAndLaunching { return safeGreen }
        return ctx.isCritical ? dangerRed : warnAmber
    }
    private var cardSurface: Color { palette.popoverCardSurface }
    private var cardBorder: Color { palette.cardBorder }
    private var labelColor: Color { palette.labelColor }

    private func purityColor(_ score: Int) -> Color {
        ShieldMetricsStyle.purityColor(score, safe: safeGreen, warn: warnAmber, danger: dangerRed)
    }

    var body: some View {
        ZStack(alignment: .top) {
            VisualEffectView(material: .hudWindow, blendingMode: .behindWindow)

            LinearGradient(
                colors: [
                    accentColor.opacity(isDark ? 0.22 : 0.13),
                    accentColor.opacity(0.0)
                ],
                startPoint: .top,
                endPoint: .bottom
            )
            .frame(height: 110)
            .allowsHitTesting(false)

            VStack(spacing: 12) {
                headerSection

                if ctx.ipChangedFromLast || !ctx.gateOK {
                    ipComparisonCard
                }

                if let p = ctx.purity {
                    puritySummaryCard(p)
                }

                footerActionBar
            }
            .padding(18)
        }
        .frame(width: 432)
        .fixedSize(horizontal: false, vertical: true)
        .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .strokeBorder(
                    LinearGradient(
                        colors: [
                            accentColor.opacity(isDark ? 0.55 : 0.38),
                            isDark ? Color.white.opacity(0.14) : Color.black.opacity(0.10)
                        ],
                        startPoint: .top,
                        endPoint: .bottom
                    ),
                    lineWidth: 1
                )
        )
        .shadow(color: Color.black.opacity(isDark ? 0.55 : 0.22), radius: 24, y: 12)
    }

    private var headerSection: some View {
        HStack(alignment: .top, spacing: 12) {
            ShieldStatusBadge(
                isSafe: state.passedAndLaunching,
                accentColor: accentColor,
                isDark: isDark
            )

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 7) {
                    Text(state.passedAndLaunching ? "安全校验已通过" : ctx.headline)
                        .font(.system(size: 15, weight: .bold, design: .rounded))
                        .foregroundColor(.primary)

                    Text(state.passedAndLaunching ? "正在启动" : ctx.badgeText)
                        .font(.system(size: 9.5, weight: .bold))
                        .foregroundColor(accentColor)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 2.5)
                        .background(Capsule().fill(accentColor.opacity(isDark ? 0.22 : 0.13)))
                        .overlay(Capsule().strokeBorder(accentColor.opacity(0.35), lineWidth: 0.6))
                }

                Text(state.passedAndLaunching ? "出口 IP 与纯净度均满足安全标准，正在安全拉起 Claude 桌面版..." : ctx.subtitle)
                    .font(.system(size: 11.5, weight: .medium))
                    .foregroundColor(labelColor)
                    .fixedSize(horizontal: false, vertical: true)
                    .lineSpacing(2)
            }

            Spacer(minLength: 4)

            Button(action: onCancel) {
                Image(systemName: "xmark")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundColor(labelColor)
                    .frame(width: 22, height: 22)
                    .background(Circle().fill(isDark ? Color.white.opacity(0.08) : Color.black.opacity(0.06)))
            }
            .buttonStyle(SnappyButtonStyle(scale: 0.92))
            .help("关闭并取消启动 (Esc)")
        }
    }

    private var ipComparisonCard: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(spacing: 6) {
                Image(systemName: "network.badge.shield.half.filled")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(accentColor)
                Text(ctx.ipChangedFromLast ? "出口 IP 变化对比" : "出口通道一致性异常")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(.primary.opacity(0.88))
                Spacer()
                if let p = ctx.purity, p.country_code != "??" {
                    Text("\(p.country_code) · \(p.city)")
                        .font(.system(size: 10, weight: .semibold, design: .monospaced))
                        .foregroundColor(labelColor)
                } else if let loc = ctx.claudeLoc {
                    Text("CF Edge: \(loc)")
                        .font(.system(size: 10, weight: .semibold, design: .monospaced))
                        .foregroundColor(labelColor)
                }
            }

            if ctx.ipChangedFromLast, let lastIP = ctx.lastLaunchIP {
                HStack(spacing: 8) {
                    ipChip(title: "上次启动 IP", value: lastIP, tint: labelColor, highlighted: false)
                    Image(systemName: "arrow.right")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(accentColor)
                    ipChip(title: "当前出口 IP", value: ctx.currentIP, tint: accentColor, highlighted: true)
                }
            }

            if !ctx.gateOK {
                HStack(spacing: 6) {
                    miniChannelBadge(label: "白名单", value: ctx.expectedIP, ok: true)
                    miniChannelBadge(label: "Proxy", value: ctx.currentIP, ok: ctx.currentIP == ctx.expectedIP)
                    miniChannelBadge(label: "TUN", value: ctx.tunIP, ok: ctx.tunIP == ctx.expectedIP)
                }
            }
        }
        .padding(11)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(cardSurface))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.8))
    }

    private func ipChip(title: String, value: String, tint: Color, highlighted: Bool) -> some View {
        VStack(alignment: .leading, spacing: 2.5) {
            Text(title)
                .font(.system(size: 9.5, weight: .medium))
                .foregroundColor(labelColor)
            Text(value)
                .font(.system(size: 11.5, weight: .bold, design: .monospaced))
                .foregroundColor(highlighted ? tint : .primary.opacity(0.88))
                .lineLimit(1)
                .minimumScaleFactor(0.8)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 9)
        .padding(.vertical, 7)
        .background(
            RoundedRectangle(cornerRadius: 9, style: .continuous)
                .fill(highlighted ? tint.opacity(isDark ? 0.16 : 0.10) : (isDark ? Color.white.opacity(0.04) : Color.black.opacity(0.035)))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 9, style: .continuous)
                .strokeBorder(highlighted ? tint.opacity(0.38) : cardBorder, lineWidth: 0.7)
        )
    }

    private func miniChannelBadge(label: String, value: String, ok: Bool) -> some View {
        let color = ok ? safeGreen : dangerRed
        return VStack(alignment: .leading, spacing: 1.5) {
            HStack(spacing: 3.5) {
                Circle().fill(color).frame(width: 5, height: 5)
                Text(label)
                    .font(.system(size: 9, weight: .semibold))
                    .foregroundColor(labelColor)
            }
            Text(value)
                .font(.system(size: 10, weight: .semibold, design: .monospaced))
                .foregroundColor(ok ? .primary.opacity(0.85) : dangerRed)
                .lineLimit(1)
                .minimumScaleFactor(0.75)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 7)
        .padding(.vertical, 5.5)
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(color.opacity(isDark ? 0.10 : 0.06)))
        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(color.opacity(0.24), lineWidth: 0.6))
    }

    private func puritySummaryCard(_ p: PurityReport) -> some View {
        let pc = purityColor(p.purity_score)
        let riskFactors = p.factors
            .filter { $0.severity != "good" }
            .sorted { $0.penalty < $1.penalty }
            .prefix(3)

        return VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 12) {
                ZStack {
                    Circle()
                        .stroke(pc.opacity(isDark ? 0.22 : 0.16), lineWidth: 5)
                    Circle()
                        .trim(from: 0, to: CGFloat(max(0, min(100, p.purity_score))) / 100.0)
                        .stroke(pc, style: StrokeStyle(lineWidth: 5, lineCap: .round))
                        .rotationEffect(.degrees(-90))
                        .animation(.spring(response: 0.5, dampingFraction: 0.8), value: p.purity_score)
                    VStack(spacing: -1) {
                        Text("\(p.purity_score)")
                            .font(.system(size: 15, weight: .heavy, design: .rounded))
                            .foregroundColor(pc)
                        Text("\(p.grade) 级")
                            .font(.system(size: 8.5, weight: .bold))
                            .foregroundColor(labelColor)
                    }
                }
                .frame(width: 48, height: 48)

                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 6) {
                        Text("IP 纯净度评估")
                            .font(.system(size: 11.5, weight: .bold))
                            .foregroundColor(.primary)
                        Text("安全线 ≥ \(ctx.threshold) 分")
                            .font(.system(size: 9.5, weight: .semibold, design: .monospaced))
                            .foregroundColor(p.purity_score >= ctx.threshold ? safeGreen : pc)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 1.5)
                            .background(Capsule().fill((p.purity_score >= ctx.threshold ? safeGreen : pc).opacity(isDark ? 0.18 : 0.11)))
                    }
                    Text(p.verdict)
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.primary.opacity(0.84))
                        .lineLimit(1)
                    Text("\(p.ip_type) · \(p.asn) · \(p.isp)")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundColor(labelColor)
                        .lineLimit(1)
                }
                Spacer(minLength: 0)
            }

            if !riskFactors.isEmpty {
                Divider().opacity(0.45)
                VStack(spacing: 6) {
                    ForEach(Array(riskFactors)) { f in
                        let fc = f.severity == "critical" ? dangerRed : warnAmber
                        HStack(alignment: .top, spacing: 7) {
                            Image(systemName: f.severity == "critical" ? "exclamationmark.octagon.fill" : "exclamationmark.triangle.fill")
                                .font(.system(size: 10.5, weight: .semibold))
                                .foregroundColor(fc)
                                .padding(.top, 1.5)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(f.title)
                                    .font(.system(size: 10.5, weight: .semibold))
                                    .foregroundColor(.primary.opacity(0.92))
                                Text(f.detail)
                                    .font(.system(size: 9.5, weight: .regular))
                                    .foregroundColor(labelColor)
                                    .lineLimit(2)
                            }
                            Spacer(minLength: 4)
                            if f.penalty < 0 {
                                Text("\(f.penalty)")
                                    .font(.system(size: 9.5, weight: .bold, design: .monospaced))
                                    .foregroundColor(fc)
                                    .padding(.horizontal, 5)
                                    .padding(.vertical, 1.5)
                                    .background(RoundedRectangle(cornerRadius: 4, style: .continuous).fill(fc.opacity(isDark ? 0.18 : 0.11)))
                            }
                        }
                    }
                }
            }
        }
        .padding(11)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(cardSurface))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.8))
    }

    private var footerActionBar: some View {
        HStack(spacing: 8) {
            Button(action: onRecheck) {
                HStack(spacing: 5) {
                    if state.isRechecking {
                        ProgressView()
                            .controlSize(.mini)
                            .scaleEffect(0.8)
                            .frame(width: 11, height: 11)
                    } else {
                        Image(systemName: "arrow.clockwise")
                            .font(.system(size: 11, weight: .semibold))
                    }
                    Text(state.isRechecking ? "检测中" : "重新检测")
                        .font(.system(size: 11.5, weight: .semibold))
                }
                .foregroundColor(.primary.opacity(0.86))
                .padding(.horizontal, 11)
                .padding(.vertical, 8)
                .background(
                    RoundedRectangle(cornerRadius: 9, style: .continuous)
                        .fill(recheckHover.value ? (isDark ? Color.white.opacity(0.13) : Color.white.opacity(0.95)) : cardSurface)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 9, style: .continuous)
                        .strokeBorder(cardBorder, lineWidth: 0.8)
                )
            }
            .buttonStyle(SnappyButtonStyle())
            .disabled(state.isRechecking || state.passedAndLaunching)
            .onHover { hovering in
                withAnimation(.easeOut(duration: 0.12)) { recheckHover.value = hovering }
            }
            .help("在 Clash 切换节点后点击重新核验")

            Spacer(minLength: 4)

            Button(action: onCancel) {
                Text("取消启动")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundColor(.primary)
                    .padding(.horizontal, 15)
                    .padding(.vertical, 8)
                    .background(
                        RoundedRectangle(cornerRadius: 9, style: .continuous)
                            .fill(cancelHover.value ? (isDark ? Color.white.opacity(0.16) : Color.white) : (isDark ? Color.white.opacity(0.10) : Color.white.opacity(0.88)))
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 9, style: .continuous)
                            .strokeBorder(isDark ? Color.white.opacity(0.20) : Color.black.opacity(0.14), lineWidth: 0.8)
                    )
            }
            .buttonStyle(SnappyButtonStyle())
            .keyboardShortcut(.cancelAction)
            .disabled(state.passedAndLaunching)
            .onHover { hovering in
                withAnimation(.easeOut(duration: 0.12)) { cancelHover.value = hovering }
            }

            Button(action: onForceLaunch) {
                HStack(spacing: 5) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 11, weight: .semibold))
                    Text("强制启动")
                        .font(.system(size: 12, weight: .bold))
                }
                .foregroundColor(.white)
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
                .background(
                    RoundedRectangle(cornerRadius: 9, style: .continuous)
                        .fill(
                            LinearGradient(
                                colors: ctx.isCritical
                                    ? [Color(red: 0.88, green: 0.24, blue: 0.24), Color(red: 0.72, green: 0.14, blue: 0.16)]
                                    : [Color(red: 0.88, green: 0.52, blue: 0.14), Color(red: 0.76, green: 0.36, blue: 0.08)],
                                startPoint: .top,
                                endPoint: .bottom
                            )
                        )
                        .brightness(forceHover.value ? 0.05 : 0)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 9, style: .continuous)
                        .strokeBorder(Color.white.opacity(forceHover.value ? 0.32 : 0.18), lineWidth: 0.7)
                )
                .shadow(color: accentColor.opacity(forceHover.value ? 0.38 : 0.25), radius: forceHover.value ? 6 : 3, y: 2)
            }
            .buttonStyle(SnappyButtonStyle())
            .disabled(state.isRechecking || state.passedAndLaunching)
            .onHover { hovering in
                withAnimation(.easeOut(duration: 0.12)) { forceHover.value = hovering }
            }
            .help("忽略本次风险拦截，仍使用硬代理与防泄露参数强行启动 Claude 桌面版")
        }
        .padding(.top, 2)
    }
}

final class LaunchGuardPanel: NSPanel {
    var onEscape: (() -> Void)?
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { true }
    override func cancelOperation(_ sender: Any?) {
        onEscape?()
    }
}

@MainActor
final class LaunchGuardWindowController {
    private var panel: LaunchGuardPanel?
    private var state: LaunchGuardState?

    func show(
        context: LaunchGuardContext,
        viewModel: ShieldViewModel
    ) {
        dismiss()

        let guardState = LaunchGuardState(context: context)
        self.state = guardState

        let view = LaunchGuardView(
            state: guardState,
            onCancel: { [weak self] in
                self?.dismiss()
            },
            onRecheck: { [weak self, weak viewModel, weak guardState] in
                guard let self = self, let vm = viewModel, let st = guardState, !st.isRechecking else { return }
                st.isRechecking = true
                Task { @MainActor in
                    let fresh = await vm.evaluateLaunchGuardContext()
                    st.isRechecking = false
                    st.context = fresh
                    if let p = fresh.purity {
                        vm.purity = p
                        vm.onStatusChange?(vm.snapshot, p)
                    }
                    let stillRisky = !fresh.gateOK || fresh.ipChangedFromLast || fresh.purityBelowThreshold
                    if !stillRisky {
                        st.passedAndLaunching = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 0.65) {
                            self.dismiss()
                            vm.executeDesktopLaunch(force: false, recordIP: fresh.currentIP, gateAlreadyPassed: true)
                        }
                    } else {
                        self.resizeAndCenter()
                    }
                }
            },
            onForceLaunch: { [weak self, weak viewModel, weak guardState] in
                let ip = guardState?.context.currentIP
                self?.dismiss()
                viewModel?.executeDesktopLaunch(force: true, recordIP: ip)
            }
        )

        let hc = NSHostingController(rootView: view)
        let panel = LaunchGuardPanel(
            contentRect: NSRect(x: 0, y: 0, width: 432, height: 340),
            styleMask: [.borderless, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        panel.contentViewController = hc
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.level = .floating
        panel.isMovableByWindowBackground = true
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.hidesOnDeactivate = false
        panel.onEscape = { [weak self] in self?.dismiss() }

        self.panel = panel
        resizeAndCenter()
        panel.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func resizeAndCenter() {
        guard let panel = panel, let contentView = panel.contentView else { return }
        contentView.layoutSubtreeIfNeeded()
        let fitting = contentView.fittingSize
        if fitting.width > 0 && fitting.height > 0 {
            panel.setContentSize(NSSize(width: 432, height: ceil(fitting.height)))
        }
        if let screen = NSScreen.main ?? NSScreen.screens.first {
            let vf = screen.visibleFrame
            let sz = panel.frame.size
            let origin = NSPoint(
                x: vf.midX - sz.width / 2.0,
                y: vf.midY - sz.height / 2.0 + 24
            )
            panel.setFrameOrigin(origin)
        } else {
            panel.center()
        }
    }

    func dismiss() {
        panel?.orderOut(nil)
        panel?.close()
        panel = nil
        state = nil
    }
}
