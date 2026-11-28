import Cocoa
import SwiftUI
import Network
import QuartzCore

// MARK: - Console Setup State & NSWindow Lifecycle Controller

@MainActor
final class SetupWizardState: ObservableObject {
    @Published var isFirstRun: Bool
    @Published var isDetecting: Bool = false
    @Published var isApplying: Bool = false
    @Published var expectedIP: String = ""
    @Published var proxyPortText: String = "7897"
    @Published var targetTZ: String = "America/Los_Angeles"
    @Published var hideOriginal: Bool = true
    @Published var enableAutostart: Bool = true
    @Published var enableDailyPatrol: Bool = true
    @Published var detectedInfo: DetectResultModel?
    @Published var setupReport: SetupReportModel?
    @Published var errorMessage: String?

    private var lastSyncedIP: String
    private var lastSyncedPort: String
    private var lastSyncedTZ: String

    init(isFirstRun: Bool, currentSnapshot: TelemetrySnapshot) {
        self.isFirstRun = isFirstRun
        let initIP = (currentSnapshot.expected_ip != "未配置" && currentSnapshot.expected_ip != "检测中...")
            ? currentSnapshot.expected_ip
            : ""
        let initPort = String(currentSnapshot.proxy_port)
        let initTZ = currentSnapshot.target_tz
        self.expectedIP = initIP
        self.proxyPortText = initPort
        self.targetTZ = initTZ
        self.lastSyncedIP = initIP
        self.lastSyncedPort = initPort
        self.lastSyncedTZ = initTZ
        self.hideOriginal = isFirstRun ? true : currentSnapshot.defenses.hideOriginalPreference
        self.enableAutostart = isFirstRun ? true : currentSnapshot.defenses.login_item_enabled
        self.enableDailyPatrol = isFirstRun ? true : currentSnapshot.defenses.daily_patrol_enabled
    }

    func syncFromSnapshot(_ snapshot: TelemetrySnapshot) {
        guard !isApplying && !isDetecting else { return }
        if !isFirstRun {
            if snapshot.expected_ip != "未配置" && snapshot.expected_ip != "检测中..." {
                if expectedIP.isEmpty || expectedIP == lastSyncedIP {
                    expectedIP = snapshot.expected_ip
                }
                lastSyncedIP = snapshot.expected_ip
            }
            let snapPort = String(snapshot.proxy_port)
            if proxyPortText == lastSyncedPort {
                proxyPortText = snapPort
            }
            lastSyncedPort = snapPort
            if targetTZ == lastSyncedTZ {
                targetTZ = snapshot.target_tz
            }
            lastSyncedTZ = snapshot.target_tz
            hideOriginal = snapshot.defenses.hideOriginalPreference
            enableAutostart = snapshot.defenses.login_item_enabled
            enableDailyPatrol = snapshot.defenses.daily_patrol_enabled
        }
    }

    private static func isValidIPAddress(_ ip: String) -> Bool {
        IPv4Address(ip) != nil || IPv6Address(ip) != nil
    }

    func runAutoDetect() {
        guard !isDetecting else { return }
        isDetecting = true
        errorMessage = nil
        let preferredPort = Int(proxyPortText.trimmingCharacters(in: .whitespacesAndNewlines))
        Task.detached(priority: .userInitiated) {
            let res = RustCoreBridge.detectEnvironment(port: preferredPort)
            await MainActor.run {
                self.isDetecting = false
                guard let res = res else {
                    self.errorMessage = "无法调用 Rust 核心探测网络环境，请检查代理软件是否已启动。"
                    return
                }
                self.detectedInfo = res
                self.proxyPortText = String(res.proxy_port)
                if !res.exit_ip.isEmpty {
                    self.expectedIP = res.exit_ip
                }
                if !res.detected_tz.isEmpty {
                    self.targetTZ = res.detected_tz
                }
                if !res.proxy_reachable {
                    self.errorMessage = "未检测到可用的本地代理（已扫描 7897/7890/6152 等端口），请先开启 Clash Verge Rev / Mihomo 后点击「重新探测」。"
                }
            }
        }
    }

    func applySetup(onSuccess: @escaping () -> Void) {
        let ip = expectedIP.trimmingCharacters(in: .whitespacesAndNewlines)
        let tz = targetTZ.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !ip.isEmpty, ip != "未配置", Self.isValidIPAddress(ip) else {
            errorMessage = "请输入合法的 IPv4 或 IPv6 白名单出口地址（例如 45.77.12.34）。"
            return
        }
        guard let port = Int(proxyPortText.trimmingCharacters(in: .whitespacesAndNewlines)), port > 0, port <= 65535 else {
            errorMessage = "请输入有效的本地代理端口（如 7897 或 7890）。"
            return
        }
        guard !tz.isEmpty else {
            errorMessage = "请选择或填写与出口 IP 匹配的目标时区（如 America/Los_Angeles）。"
            return
        }

        isApplying = true
        errorMessage = nil
        let appPath = Bundle.main.bundleURL.pathExtension == "app"
            ? Bundle.main.bundleURL.path
            : "/Applications/Claude Shield.app"
        let hideOrig = hideOriginal
        let autoStart = enableAutostart
        let patrol = enableDailyPatrol

        Task.detached(priority: .userInitiated) {
            let report = RustCoreBridge.runSetup(
                ip: ip,
                port: port,
                tz: tz,
                hideOriginal: hideOrig,
                autostart: autoStart,
                patrol: patrol,
                appPath: appPath
            )
            await MainActor.run {
                self.isApplying = false
                if let report = report, report.ok {
                    self.setupReport = report
                    onSuccess()
                } else {
                    self.errorMessage = report?.warnings.first ?? "本地防护部署失败，请确认应用具有读写用户目录权限。"
                }
            }
        }
    }
}

enum ShieldDashboardSection: String, CaseIterable, Identifiable {
    case radar
    case purity
    case settings

    var id: String { rawValue }

    var title: String {
        switch self {
        case .radar: return "实时雷达"
        case .purity: return "纯净度体检"
        case .settings: return "防护设置"
        }
    }

    var icon: String {
        switch self {
        case .radar: return "shield.lefthalf.filled"
        case .purity: return "sparkle.magnifyingglass"
        case .settings: return "slider.horizontal.3"
        }
    }

    var caption: String {
        switch self {
        case .radar: return "网络态势与防线矩阵"
        case .purity: return "IP 纯净度与防泄露"
        case .settings: return "白名单、时区与策略"
        }
    }
}

@MainActor
final class ShieldDashboardNavState: ObservableObject {
    @Published var selectedSection: ShieldDashboardSection = .radar
}

final class ShieldDashboardWindow: NSWindow {
    var suppressAutoFocusUntil: Date?
    override var canBecomeKey: Bool { true }
    override var canBecomeMain: Bool { true }
    override func makeFirstResponder(_ responder: NSResponder?) -> Bool {
        if let until = suppressAutoFocusUntil, Date() < until,
           let r = responder, r is NSTextView || r is NSTextField {
            return super.makeFirstResponder(nil)
        }
        return super.makeFirstResponder(responder)
    }
}

@MainActor
final class ShieldDashboardWindowController: NSObject, NSWindowDelegate {
    private var window: ShieldDashboardWindow?
    private var navState = ShieldDashboardNavState()
    private var wizardState: SetupWizardState?
    private weak var boundViewModel: ShieldViewModel?
    private var isHiding = false
    private var savedWindowFrame: NSRect?

    var currentSection: ShieldDashboardSection {
        navState.selectedSection
    }

    private func setDockVisible(_ visible: Bool) {
        let target: NSApplication.ActivationPolicy = visible ? .regular : .accessory
        if NSApp.activationPolicy() != target {
            NSApp.setActivationPolicy(target)
        }
    }

    func show(viewModel: ShieldViewModel, section: ShieldDashboardSection = .radar, isFirstRun: Bool = false) {
        navState.selectedSection = section
        isHiding = false
        setDockVisible(true)
        viewModel.setDashboardVisible(true)

        if let existing = window, boundViewModel === viewModel {
            if isFirstRun {
                wizardState?.isFirstRun = true
                wizardState?.setupReport = nil
            }
            wizardState?.syncFromSnapshot(viewModel.snapshot)
            existing.suppressAutoFocusUntil = Date().addingTimeInterval(0.18)
            if existing.isMiniaturized {
                existing.deminiaturize(nil)
                existing.makeKeyAndOrderFront(nil)
                NSApp.activate(ignoringOtherApps: true)
            } else if existing.isVisible {
                existing.alphaValue = 1.0
                existing.makeKeyAndOrderFront(nil)
                NSApp.activate(ignoringOtherApps: true)
            } else {
                presentSmoothly(existing)
            }
            return
        }

        let state = SetupWizardState(isFirstRun: isFirstRun, currentSnapshot: viewModel.snapshot)
        self.wizardState = state
        self.boundViewModel = viewModel

        let rootView = ShieldDashboardView(
            nav: navState,
            state: state,
            vm: viewModel,
            onHideToMenuBar: { [weak self] in
                self?.hideToMenuBar(animated: true)
            },
            onLaunchClaude: {
                viewModel.launchClaudeSafe()
            },
            onUninstall: { [weak self] in
                self?.hideToMenuBar(animated: false)
                viewModel.confirmAndUninstall()
            },
            onApplied: {
                viewModel.refresh(force: true, mode: .full, resetPool: true)
                viewModel.refreshPurity(silent: true)
            }
        )

        let hc = NSHostingController(rootView: rootView)
        hc.sizingOptions = []

        let initialFrame: NSRect
        if let restored = savedWindowFrame {
            initialFrame = restored
        } else if let screen = NSScreen.main ?? NSScreen.screens.first {
            let vf = screen.visibleFrame
            let w = min(980, vf.width - 64)
            let h = min(752, vf.height - 48)
            initialFrame = NSRect(
                x: vf.midX - w / 2.0,
                y: vf.midY - h / 2.0 + 12,
                width: w,
                height: h
            )
        } else {
            initialFrame = NSRect(x: 0, y: 0, width: 980, height: 752)
        }

        let win = ShieldDashboardWindow(
            contentRect: initialFrame,
            styleMask: [.titled, .closable, .miniaturizable, .resizable, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        win.title = "Claude Shield"
        win.titleVisibility = .hidden
        win.titlebarAppearsTransparent = true
        win.isMovableByWindowBackground = true
        win.isReleasedWhenClosed = false
        win.minSize = NSSize(width: 820, height: 580)
        win.level = .normal
        win.collectionBehavior = [.fullScreenPrimary, .managed]
        win.contentViewController = hc
        win.delegate = self
        win.suppressAutoFocusUntil = Date().addingTimeInterval(0.24)
        win.setFrame(initialFrame, display: false)
        if savedWindowFrame == nil && NSScreen.main == nil && NSScreen.screens.isEmpty {
            win.center()
        }
        win.contentView?.layoutSubtreeIfNeeded()

        self.window = win
        presentSmoothly(win)
    }

    private func releaseHiddenWindow(_ win: ShieldDashboardWindow) {
        savedWindowFrame = win.frame
        win.orderOut(nil)
        win.alphaValue = 1.0
        win.delegate = nil
        win.contentViewController = nil
        if self.window === win {
            self.window = nil
        }
        self.wizardState = nil
        boundViewModel?.setDashboardVisible(false)
        setDockVisible(false)
    }

    func hideToMenuBar(animated: Bool = true, completion: (() -> Void)? = nil) {
        guard let win = window, win.isVisible || win.isMiniaturized else {
            boundViewModel?.setDashboardVisible(false)
            setDockVisible(false)
            completion?()
            return
        }
        if win.isMiniaturized || !animated {
            isHiding = false
            releaseHiddenWindow(win)
            completion?()
            return
        }

        isHiding = true
        NSAnimationContext.runAnimationGroup({ ctx in
            ctx.duration = 0.14
            ctx.timingFunction = CAMediaTimingFunction(controlPoints: 0.4, 0.0, 1.0, 1.0)
            win.animator().alphaValue = 0.0
        }, completionHandler: { [weak self, weak win] in
            Task { @MainActor [weak self, weak win] in
                guard let self, let win else {
                    completion?()
                    return
                }
                guard self.isHiding else {
                    win.alphaValue = 1.0
                    completion?()
                    return
                }
                self.isHiding = false
                self.releaseHiddenWindow(win)
                completion?()
            }
        })
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        hideToMenuBar(animated: true)
        return false
    }

    func windowDidMiniaturize(_ notification: Notification) {
        boundViewModel?.setDashboardVisible(false)
    }

    func windowDidDeminiaturize(_ notification: Notification) {
        guard let win = window else { return }
        boundViewModel?.setDashboardVisible(true)
        win.alphaValue = 1.0
        win.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func presentSmoothly(_ win: ShieldDashboardWindow) {
        win.alphaValue = 0.0
        win.makeKeyAndOrderFront(nil)
        _ = win.makeFirstResponder(nil)
        NSApp.activate(ignoringOtherApps: true)

        NSAnimationContext.runAnimationGroup({ ctx in
            ctx.duration = 0.16
            ctx.timingFunction = CAMediaTimingFunction(controlPoints: 0.16, 1.0, 0.30, 1.0)
            win.animator().alphaValue = 1.0
        }, completionHandler: { [weak win] in
            Task { @MainActor [weak win] in
                win?.alphaValue = 1.0
            }
        })
    }
}
