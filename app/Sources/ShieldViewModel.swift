import Cocoa
import SwiftUI
import Combine
import Network

// MARK: - ViewModel

enum ShieldTab: String, CaseIterable {
    case radar = "实时雷达"
    case purity = "纯净度体检"
}

@MainActor
final class ShieldViewModel: ObservableObject {
    @Published var snapshot: TelemetrySnapshot
    @Published var purity: PurityReport?
    @Published var selectedTab: ShieldTab = .radar
    @Published var isRefreshing: Bool = false
    @Published var isAuditing: Bool = false
    @Published var isCheckingLaunch: Bool = false
    @Published var autoKillOnBreach: Bool {
        didSet { UserDefaults.standard.set(autoKillOnBreach, forKey: "autoKillOnBreach") }
    }
    @Published var loginAutoStart: Bool = false
    @Published var toastMessage: String?
    @Published var updatePhase: AppUpdatePhase = .idle
    @Published private(set) var isPopoverVisible: Bool = false
    @Published private(set) var isDashboardVisible: Bool = false
    @Published var dismissedUpdateVersion: String? {
        didSet {
            if let v = dismissedUpdateVersion {
                UserDefaults.standard.set(v, forKey: "dismissedUpdateVersion")
            } else {
                UserDefaults.standard.removeObject(forKey: "dismissedUpdateVersion")
            }
        }
    }

    var availableUpdate: AppUpdateInfo? { updatePhase.info }
    var shouldShowPopoverUpdateBanner: Bool {
        guard let info = availableUpdate else { return false }
        if updatePhase.isBusy { return true }
        return dismissedUpdateVersion != info.version
    }

    var onStatusChange: ((TelemetrySnapshot, PurityReport?) -> Void)?
    var onRequestClosePopover: (() -> Void)?
    var onShowLaunchGuard: ((LaunchGuardContext) -> Void)?
    var onShowDashboard: ((ShieldDashboardSection, Bool) -> Void)?

    private var timer: Timer?
    private var purityTimer: Timer?
    private var updateTimer: Timer?
    private var pathMonitor: NWPathMonitor?
    private var workspaceObservers: [NSObjectProtocol] = []
    private var lastPathSignature: String?
    private var consecutiveUnreachableCount = 0
    private var lastRefreshAt: Date?
    private var lastFullRefreshAt: Date?
    private var currentTimerInterval: TimeInterval?
    private var isSystemAsleep: Bool = false
    private var isAuditingDefenses: Bool = false

    var isUIVisible: Bool { isPopoverVisible || isDashboardVisible }

    init() {
        self.autoKillOnBreach = UserDefaults.standard.object(forKey: "autoKillOnBreach") as? Bool ?? true
        self.dismissedUpdateVersion = UserDefaults.standard.string(forKey: "dismissedUpdateVersion")
        let cachedSnap = RustCoreBridge.loadCachedTelemetry() ?? .initial
        self.snapshot = cachedSnap
        self.purity = RustCoreBridge.loadCachedPurity()
        self.loginAutoStart = cachedSnap.defenses.login_item_enabled
    }

    deinit {
        timer?.invalidate()
        purityTimer?.invalidate()
        updateTimer?.invalidate()
        pathMonitor?.cancel()
        for observer in workspaceObservers {
            NSWorkspace.shared.notificationCenter.removeObserver(observer)
        }
    }

    func setPopoverVisible(_ visible: Bool) {
        guard isPopoverVisible != visible else { return }
        isPopoverVisible = visible
        rescheduleTimer()
        if visible {
            let needsFull = lastFullRefreshAt.map { Date().timeIntervalSince($0) >= 4.0 } ?? true
            if needsFull {
                refresh(force: true, mode: .full)
            }
        }
    }

    func setDashboardVisible(_ visible: Bool) {
        guard isDashboardVisible != visible else { return }
        isDashboardVisible = visible
        rescheduleTimer()
        if visible {
            let needsFull = lastFullRefreshAt.map { Date().timeIntervalSince($0) >= 4.0 } ?? true
            if needsFull {
                refresh(force: true, mode: .full)
            }
        }
    }

    private func desiredTimerInterval() -> TimeInterval? {
        if isSystemAsleep {
            return nil
        }
        if isUIVisible {
            return 15.0
        }
        if snapshot.desktopRunning || !snapshot.isSafe {
            return 25.0
        }
        return 60.0
    }

    private func rescheduleTimer() {
        let target = desiredTimerInterval()
        if target == currentTimerInterval {
            return
        }
        timer?.invalidate()
        timer = nil
        currentTimerInterval = target

        guard let interval = target else { return }
        let newTimer = Timer.scheduledTimer(withTimeInterval: interval, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self = self, !self.isSystemAsleep else { return }
                let mode: TelemetryProbeMode = self.isUIVisible ? .full : .light
                self.refresh(force: false, mode: mode)
            }
        }
        newTimer.tolerance = interval * 0.2
        timer = newTimer
    }

    nonisolated private static func isClaudeDesktopNotification(_ notification: Notification) -> Bool {
        guard let app = notification.userInfo?[NSWorkspace.applicationUserInfoKey] as? NSRunningApplication else {
            return false
        }
        if app.bundleIdentifier == "com.anthropic.claudefordesktop" { return true }
        if app.bundleURL?.lastPathComponent == "Claude.app" { return true }
        if app.executableURL?.lastPathComponent == "Claude" { return true }
        return app.localizedName == "Claude"
    }

    func startMonitoring(initialFullProbe: Bool = false) {
        refresh(force: true, mode: initialFullProbe ? .full : .light)
        rescheduleTimer()

        DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) { [weak self] in
            guard let self = self else { return }
            if self.purity == nil {
                self.refreshPurity(silent: true)
            }
        }
        purityTimer?.invalidate()
        let pTimer = Timer.scheduledTimer(withTimeInterval: 14400.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self = self, !self.isSystemAsleep else { return }
                self.runFullCheckup(silent: true)
            }
        }
        pTimer.tolerance = 600.0
        purityTimer = pTimer

        DispatchQueue.main.asyncAfter(deadline: .now() + 8.0) { [weak self] in
            self?.checkForUpdates(manual: false)
        }
        updateTimer?.invalidate()
        let uTimer = Timer.scheduledTimer(withTimeInterval: 21600.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                guard let self = self, !self.isSystemAsleep else { return }
                self.checkForUpdates(manual: false)
            }
        }
        uTimer.tolerance = 900.0
        updateTimer = uTimer

        let wsCenter = NSWorkspace.shared.notificationCenter
        for existing in workspaceObservers {
            wsCenter.removeObserver(existing)
        }
        workspaceObservers.removeAll()

        let launchObs = wsCenter.addObserver(
            forName: NSWorkspace.didLaunchApplicationNotification,
            object: nil,
            queue: .main
        ) { [weak self] note in
            guard Self.isClaudeDesktopNotification(note) else { return }
            Task { @MainActor in
                self?.auditDefensesImmediately()
            }
        }

        let terminateObs = wsCenter.addObserver(
            forName: NSWorkspace.didTerminateApplicationNotification,
            object: nil,
            queue: .main
        ) { [weak self] note in
            guard Self.isClaudeDesktopNotification(note) else { return }
            Task { @MainActor in
                self?.auditDefensesImmediately()
            }
        }

        let sleepHandler: @Sendable (Notification) -> Void = { [weak self] _ in
            Task { @MainActor in
                self?.isSystemAsleep = true
                self?.rescheduleTimer()
            }
        }
        let willSleepObs = wsCenter.addObserver(
            forName: NSWorkspace.willSleepNotification,
            object: nil,
            queue: .main,
            using: sleepHandler
        )
        let screenSleepObs = wsCenter.addObserver(
            forName: NSWorkspace.screensDidSleepNotification,
            object: nil,
            queue: .main,
            using: sleepHandler
        )

        let wakeHandler: @Sendable (Notification) -> Void = { [weak self] _ in
            Task { @MainActor in
                guard let self = self else { return }
                let wasAsleep = self.isSystemAsleep
                self.isSystemAsleep = false
                self.consecutiveUnreachableCount = 0
                self.rescheduleTimer()
                let mode: TelemetryProbeMode = self.isUIVisible ? .full : .light
                self.refresh(force: true, mode: mode, resetPool: true)
                if wasAsleep {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) { [weak self] in
                        guard let self = self, !self.isSystemAsleep else { return }
                        self.refresh(force: true, mode: self.isUIVisible ? .full : .light)
                    }
                }
            }
        }
        let didWakeObs = wsCenter.addObserver(
            forName: NSWorkspace.didWakeNotification,
            object: nil,
            queue: .main,
            using: wakeHandler
        )
        let screenWakeObs = wsCenter.addObserver(
            forName: NSWorkspace.screensDidWakeNotification,
            object: nil,
            queue: .main,
            using: wakeHandler
        )

        workspaceObservers = [
            launchObs,
            terminateObs,
            willSleepObs,
            screenSleepObs,
            didWakeObs,
            screenWakeObs
        ]

        pathMonitor?.cancel()
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            let interfaces = path.availableInterfaces.map(\.name).sorted().joined(separator: ",")
            let sig = "\(path.status)|\(interfaces)|\(path.isExpensive)|\(path.isConstrained)"
            Task { @MainActor in
                guard let self = self else { return }
                let changed = self.lastPathSignature != nil && self.lastPathSignature != sig
                self.lastPathSignature = sig
                if changed && !self.isSystemAsleep {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) { [weak self] in
                        guard let self = self, !self.isSystemAsleep else { return }
                        let mode: TelemetryProbeMode = self.isUIVisible ? .full : .light
                        self.refresh(force: true, mode: mode, resetPool: true)
                    }
                }
            }
        }
        monitor.start(queue: DispatchQueue.global(qos: .utility))
        self.pathMonitor = monitor
    }

    func auditDefensesImmediately() {
        guard !isAuditingDefenses else { return }
        isAuditingDefenses = true
        Task.detached(priority: .userInitiated) {
            let defenses = RustCoreBridge.fetchLocalDefenses()
            await MainActor.run {
                self.isAuditingDefenses = false
                guard let defenses = defenses else { return }
                let updated = self.snapshot.replacingDefenses(defenses)
                self.snapshot = updated
                self.loginAutoStart = defenses.login_item_enabled
                self.onStatusChange?(updated, self.purity)
                self.rescheduleTimer()

                if defenses.original_app_exposed && defenses.hideOriginalPreference {
                    Task.detached(priority: .utility) {
                        _ = RustCoreBridge.hideOriginalApp()
                    }
                }

                if self.autoKillOnBreach {
                    if updated.desktopUnprotected {
                        self.emergencyKillClaude(reason: "检测到未绑定硬代理或未禁 QUIC/WebRTC 的 Claude 桌面版进程（#\(defenses.desktop_pid ?? "?")），已即时熔断急停防裸连！")
                    } else if updated.hasUnprotectedCLI {
                        self.killUnprotectedCLI(pids: defenses.unprotected_cli_pids)
                    }
                }
            }
        }
    }

    func refresh(force: Bool = false, mode: TelemetryProbeMode? = nil, resetPool: Bool = false) {
        guard !isRefreshing else { return }
        let resolvedMode: TelemetryProbeMode = mode ?? ((isUIVisible || force) ? .full : .light)
        if !force, let last = lastRefreshAt, Date().timeIntervalSince(last) < 4.0 {
            return
        }
        lastRefreshAt = Date()
        if resolvedMode == .full {
            lastFullRefreshAt = Date()
        }
        isRefreshing = true
        let priority: TaskPriority = isUIVisible || force ? .userInitiated : .utility
        Task.detached(priority: priority) {
            let result = RustCoreBridge.fetchTelemetry(mode: resolvedMode, resetPool: resetPool)
            await MainActor.run {
                self.isRefreshing = false
                guard let result = result else { return }
                self.snapshot = result
                self.loginAutoStart = result.defenses.login_item_enabled
                self.onStatusChange?(result, self.purity)
                self.rescheduleTimer()

                if result.defenses.original_app_exposed && result.defenses.hideOriginalPreference {
                    Task.detached(priority: .utility) {
                        _ = RustCoreBridge.hideOriginalApp()
                    }
                }

                if result.isSafe {
                    self.consecutiveUnreachableCount = 0
                    return
                }

                if self.autoKillOnBreach {
                    if result.desktopUnprotected {
                        self.emergencyKillClaude(reason: "检测到未绑定硬代理或未禁 QUIC/WebRTC 的 Claude 桌面版进程（#\(result.defenses.desktop_pid ?? "?")），已自动急停防裸连！")
                    } else if result.hasUnprotectedCLI {
                        self.killUnprotectedCLI(pids: result.defenses.unprotected_cli_pids)
                    } else if result.desktopRunning && result.isConfirmedIPDrift {
                        self.emergencyKillClaude(reason: "检测到出口 IP 漂移（Claude 边缘: \(result.proxy.ip) / TUN: \(result.tun.ip)），已自动急停 Claude 桌面版！")
                    } else if result.desktopRunning {
                        self.consecutiveUnreachableCount += 1
                        if self.consecutiveUnreachableCount >= 2 {
                            self.consecutiveUnreachableCount = 0
                            self.emergencyKillClaude(reason: "连续检测到代理/TUN 通道中断，已自动急停 Claude 桌面版（Fail-Closed）！")
                        } else {
                            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) {
                                self.refresh(force: true, mode: .light, resetPool: true)
                            }
                        }
                    }
                }
            }
        }
    }

    func refreshPurity(silent: Bool = false) {
        guard !isAuditing else { return }
        isAuditing = true
        Task.detached(priority: silent ? .utility : .userInitiated) {
            let report = RustCoreBridge.fetchPurity()
            await MainActor.run {
                self.isAuditing = false
                if let report = report {
                    self.purity = report
                    self.onStatusChange?(self.snapshot, report)
                    if !silent {
                        self.showToast("全面体检完成：\(report.purity_score) 分（\(report.grade) 级）")
                    }
                } else if !silent {
                    self.showToast("全面体检失败，请检查代理连通性")
                }
            }
        }
    }

    func runFullCheckup(silent: Bool = false) {
        guard !isAuditing else { return }
        isAuditing = true
        let autoKill = autoKillOnBreach
        Task.detached(priority: silent ? .utility : .userInitiated) {
            let report = RustCoreBridge.runPatrol(notify: silent, autoKill: autoKill)
            await MainActor.run {
                self.isAuditing = false
                if let report = report {
                    self.purity = report.purity
                    self.onStatusChange?(self.snapshot, report.purity)
                    self.refresh(force: true)
                    if !silent {
                        if report.passed {
                            if !report.auto_healed.isEmpty {
                                self.showToast("全面体检通过（已自动修复 \(report.auto_healed.count) 项）· \(report.purity_score) 分")
                            } else {
                                self.showToast("全面体检通过 · 纯净度 \(report.purity_score) 分（\(report.grade) 级）")
                            }
                        } else {
                            self.showToast("体检发现 \(report.alerts.count) 项异常，请查看纯净度详情")
                        }
                    }
                } else if !silent {
                    self.showToast("全面体检失败，请检查代理连通性")
                }
            }
        }
    }

    func hideOriginalAppNow() {
        Task.detached(priority: .userInitiated) {
            let actions = RustCoreBridge.hideOriginalApp()
            await MainActor.run {
                self.showToast(actions.isEmpty ? "原版 Claude.app 已处于隐藏状态" : "已自动隐藏原版 Claude.app 图标")
                self.refresh(force: true)
            }
        }
    }

    func setLoginAutoStart(_ enabled: Bool) {
        let actual = RustCoreBridge.toggleLaunchAgent(enabled: enabled)
        loginAutoStart = actual
        showToast(actual ? "已开启开机自启保护雷达" : "已关闭开机自启雷达")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { [weak self] in
            self?.refresh(force: true)
        }
    }

    private func findRunningClaudeApp() -> NSRunningApplication? {
        if let pidStr = snapshot.defenses.desktop_pid, let pid = Int32(pidStr),
           let app = NSRunningApplication(processIdentifier: pid), !app.isTerminated {
            return app
        }
        if let byBundle = NSRunningApplication.runningApplications(withBundleIdentifier: "com.anthropic.claudefordesktop")
            .first(where: { !$0.isTerminated }) {
            return byBundle
        }
        return NSWorkspace.shared.runningApplications.first { app in
            guard !app.isTerminated else { return false }
            if app.bundleURL?.lastPathComponent == "Claude.app" { return true }
            if app.executableURL?.lastPathComponent == "Claude" { return true }
            return app.localizedName == "Claude"
        }
    }

    @discardableResult
    func focusClaudeDesktop() -> Bool {
        guard let runningApp = findRunningClaudeApp() else { return false }
        onRequestClosePopover?()

        runningApp.unhide()
        if #available(macOS 14.0, *) {
            NSApp.yieldActivation(to: runningApp)
            runningApp.activate()
        } else {
            runningApp.activate(options: [.activateIgnoringOtherApps, .activateAllWindows])
        }

        if let appURL = runningApp.bundleURL ?? RustCoreBridge.claudeDesktopAppURL() {
            let config = NSWorkspace.OpenConfiguration()
            config.activates = true
            config.createsNewApplicationInstance = false
            NSWorkspace.shared.openApplication(at: appURL, configuration: config) { _, _ in }
        }
        return true
    }

    func evaluateLaunchGuardContext() async -> LaunchGuardContext {
        let cachedPurity = self.purity ?? RustCoreBridge.loadCachedPurity()
        let fallbackExpected = self.snapshot.expected_ip

        return await Task.detached(priority: .userInitiated) {
            let gate = RustCoreBridge.fetchGate()
            let currentIP: String = {
                if let g = gate, !g.proxy_ip.isEmpty, g.proxy_ip != "无法连通" {
                    return g.proxy_ip
                }
                if let g = gate, !g.claude_edge_ip.isEmpty, g.claude_edge_ip != "无法连通" {
                    return g.claude_edge_ip
                }
                return "无法连通"
            }()

            let lastIP = RustCoreBridge.loadLastLaunchIP()
            let expectedIP = gate?.expected_ip ?? fallbackExpected
            let tunIP = gate?.tun_ip ?? "无法连通"
            let gateOK = gate?.ok ?? false
            let gateError = gate?.error ?? (gate == nil ? "无法调用 Rust 安全内核进行门禁校验。" : nil)

            var purityReport = cachedPurity
            let needsFreshPurity = (purityReport == nil || purityReport?.exit_ip != currentIP) && currentIP != "无法连通"
            if needsFreshPurity {
                if let fresh = RustCoreBridge.fetchPurity() {
                    purityReport = fresh
                }
            }

            let threshold = LaunchGuardContext.safePurityThreshold
            let ipChanged: Bool = {
                guard let last = lastIP, !last.isEmpty else { return false }
                guard currentIP != "无法连通", !currentIP.isEmpty else { return true }
                return currentIP != last
            }()
            let purityLow: Bool = {
                if let p = purityReport {
                    return p.purity_score < threshold
                }
                return currentIP == "无法连通"
            }()

            return LaunchGuardContext(
                currentIP: currentIP,
                lastLaunchIP: lastIP,
                expectedIP: expectedIP,
                tunIP: tunIP,
                gateOK: gateOK,
                gateError: gateError,
                claudeLoc: gate?.claude_loc ?? purityReport?.country_code,
                purity: purityReport,
                ipChangedFromLast: ipChanged,
                purityBelowThreshold: purityLow,
                threshold: threshold
            )
        }.value
    }

    func launchClaudeSafe() {
        if findRunningClaudeApp() != nil && !snapshot.desktopUnprotected {
            if focusClaudeDesktop() {
                showToast("已将 Claude 桌面版拉至前台")
                return
            }
        }

        guard !isCheckingLaunch else { return }
        isCheckingLaunch = true
        showToast("正在核验出口 IP 与纯净度...")

        Task { @MainActor in
            let ctx = await evaluateLaunchGuardContext()
            self.isCheckingLaunch = false

            if let p = ctx.purity {
                self.purity = p
                self.onStatusChange?(self.snapshot, p)
            }

            let shouldIntercept = !ctx.gateOK || ctx.ipChangedFromLast || ctx.purityBelowThreshold
            if shouldIntercept {
                self.onRequestClosePopover?()
                self.onShowLaunchGuard?(ctx)
            } else {
                self.executeDesktopLaunch(force: false, recordIP: ctx.currentIP)
            }
        }
    }

    func executeDesktopLaunch(force: Bool, recordIP: String?) {
        onRequestClosePopover?()
        if let ip = recordIP {
            RustCoreBridge.saveLastLaunchIP(ip)
        }

        let bin = RustCoreBridge.coreBinaryPath
        let task = Process()
        if FileManager.default.isExecutableFile(atPath: bin) {
            task.executableURL = URL(fileURLWithPath: bin)
            task.arguments = force ? ["launch-desktop", "--force"] : ["launch-desktop"]
        } else {
            let script = FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent(".local/bin/claude-desktop-safe").path
            task.executableURL = URL(fileURLWithPath: "/bin/bash")
            task.arguments = [script]
        }
        try? task.run()
        showToast(force ? "已强制安全启动 Claude 桌面版" : "验真通过，正在启动 Claude 桌面版...")

        DispatchQueue.main.asyncAfter(deadline: .now() + 1.4) { [weak self] in
            self?.focusClaudeDesktop()
            self?.refresh(force: true)
        }
    }

    private func killUnprotectedCLI(pids: [String]) {
        for pid in pids {
            let t = Process()
            t.executableURL = URL(fileURLWithPath: "/bin/kill")
            t.arguments = ["-9", pid]
            try? t.run()
        }
        let alert = Process()
        alert.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
        alert.arguments = ["-e", "display notification \"发现未走安全门禁的 Claude Code 进程，已自动终止防裸连！\" with title \"Claude Shield 熔断急停\" sound name \"Sosumi\""]
        try? alert.run()
        showToast("已终止未受保护的 CLI 进程")
    }

    func emergencyKillClaude(reason: String? = nil) {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        task.arguments = ["-9", "-x", "Claude"]
        try? task.run()
        task.waitUntilExit()

        if let reason = reason {
            let safe = reason
                .replacingOccurrences(of: "\\", with: "\\\\")
                .replacingOccurrences(of: "\"", with: "'")
                .replacingOccurrences(of: "\r", with: " ")
                .replacingOccurrences(of: "\n", with: " ")
            let alert = Process()
            alert.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            alert.arguments = ["-e", "display notification \"\(safe)\" with title \"Claude Shield 熔断急停\" sound name \"Sosumi\""]
            try? alert.run()
        }
        showToast("已执行紧急急停（Claude 进程已终止）")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) { [weak self] in
            self?.refresh(force: true)
        }
    }

    func showToast(_ msg: String) {
        withAnimation(.easeInOut(duration: 0.2)) {
            toastMessage = msg
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) { [weak self] in
            withAnimation(.easeInOut(duration: 0.2)) {
                if self?.toastMessage == msg {
                    self?.toastMessage = nil
                }
            }
        }
    }
}
