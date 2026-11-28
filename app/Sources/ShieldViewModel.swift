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
    private var powerObserver: NSObjectProtocol?
    private var vnodeWatchers: [VnodeWatcher] = []
    private let mihomoMonitor = MihomoEventMonitor()
    private var lastPathSignature: String?
    private var lastConfigFilesStamp: String?
    private var consecutiveUnreachableCount = 0
    private var lastRefreshAt: Date?
    private var lastFullRefreshAt: Date?
    private var currentTimerInterval: TimeInterval?
    private var isSystemAsleep: Bool = false
    private var isScreenOff: Bool = false
    private var isLowPowerMode: Bool = ProcessInfo.processInfo.isLowPowerModeEnabled
    private var isAuditingDefenses: Bool = false
    private var isHidingOriginalApp: Bool = false
    private var isProbeInFlight: Bool = false
    var inFlightKillCLIPIDs: Set<String> = []
    private var pathDebounceTask: Task<Void, Never>?
    private var toastDismissTask: Task<Void, Never>?
    private var pendingRefresh: (mode: TelemetryProbeMode, resetPool: Bool, userInitiated: Bool)?

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
        pathDebounceTask?.cancel()
        toastDismissTask?.cancel()
        pathMonitor?.cancel()
        mihomoMonitor.stop()
        for w in vnodeWatchers { w.stop() }
        for observer in workspaceObservers {
            NSWorkspace.shared.notificationCenter.removeObserver(observer)
        }
        if let pObs = powerObserver {
            NotificationCenter.default.removeObserver(pObs)
        }
    }

    func setPopoverVisible(_ visible: Bool) {
        guard isPopoverVisible != visible else { return }
        isPopoverVisible = visible
        rescheduleTimer()
        if visible {
            let needsLive = lastRefreshAt.map { Date().timeIntervalSince($0) >= 2.2 } ?? true
            if needsLive || snapshot.api_latency.warm_rtt_ms == nil {
                refresh(force: true, mode: .light, userInitiated: false)
            }
        }
    }

    func setDashboardVisible(_ visible: Bool) {
        guard isDashboardVisible != visible else { return }
        isDashboardVisible = visible
        rescheduleTimer()
        if visible {
            let needsLive = lastRefreshAt.map { Date().timeIntervalSince($0) >= 2.2 } ?? true
            if needsLive || snapshot.api_latency.warm_rtt_ms == nil {
                refresh(force: true, mode: .light, userInitiated: false)
            }
        }
    }

    private func desiredTimerInterval() -> TimeInterval? {
        if isSystemAsleep {
            return nil
        }
        if isUIVisible {
            return 3.0
        }
        if !snapshot.isSafe {
            return 4.0
        }
        if snapshot.anyClaudeRunning {
            return (isLowPowerMode || isScreenOff) ? 10.0 : 4.0
        }
        return (isLowPowerMode || isScreenOff) ? 25.0 : 15.0
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
                self.refresh(force: false, mode: .light, userInitiated: false)
            }
        }
        newTimer.tolerance = min(interval * 0.15, 2.0)
        timer = newTimer
    }

    nonisolated private static func captureConfigFilesStamp(configDir: String) -> String {
        let fm = FileManager.default
        let names = ["expected_ip", "proxy_port", "target_tz", "hide_original"]
        return names.map { name in
            let path = "\(configDir)/\(name)"
            guard let attrs = try? fm.attributesOfItem(atPath: path) else { return "\(name):-" }
            let size = (attrs[.size] as? NSNumber)?.int64Value ?? 0
            let mtime = (attrs[.modificationDate] as? Date)?.timeIntervalSince1970 ?? 0
            return "\(name):\(size):\(Int64(mtime * 1000))"
        }.joined(separator: "|")
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

        // True system sleep pauses active network polling; screen sleep / lock NEVER blinds watchers or auto-kill!
        let willSleepObs = wsCenter.addObserver(
            forName: NSWorkspace.willSleepNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                self.isSystemAsleep = true
                self.mihomoMonitor.setPaused(true)
                self.rescheduleTimer()
            }
        }

        let didWakeObs = wsCenter.addObserver(
            forName: NSWorkspace.didWakeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                let wasAsleep = self.isSystemAsleep
                self.isSystemAsleep = false
                self.isScreenOff = false
                self.consecutiveUnreachableCount = 0
                self.mihomoMonitor.setPaused(false)
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

        let screenSleepObs = wsCenter.addObserver(
            forName: NSWorkspace.screensDidSleepNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                self.isScreenOff = true
                self.rescheduleTimer()
            }
        }

        let screenWakeObs = wsCenter.addObserver(
            forName: NSWorkspace.screensDidWakeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                guard let self else { return }
                self.isScreenOff = false
                self.rescheduleTimer()
                guard !self.isSystemAsleep else { return }
                let isStale = self.lastRefreshAt.map { Date().timeIntervalSince($0) >= 3.0 } ?? true
                if isStale {
                    self.refresh(force: true, mode: .light)
                }
            }
        }

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
                    self.pathDebounceTask?.cancel()
                    self.pathDebounceTask = Task { @MainActor [weak self] in
                        try? await Task.sleep(nanoseconds: 800_000_000)
                        guard !Task.isCancelled, let self = self, !self.isSystemAsleep else { return }
                        let mode: TelemetryProbeMode = self.isUIVisible ? .full : .light
                        self.refresh(force: true, mode: mode, resetPool: true)
                    }
                }
            }
        }
        monitor.start(queue: DispatchQueue.global(qos: .background))
        self.pathMonitor = monitor

        // Low Power Mode adaptive throttling
        if let existingPower = powerObserver {
            NotificationCenter.default.removeObserver(existingPower)
        }
        powerObserver = NotificationCenter.default.addObserver(
            forName: .NSProcessInfoPowerStateDidChange,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                guard let self = self else { return }
                self.isLowPowerMode = ProcessInfo.processInfo.isLowPowerModeEnabled
                self.rescheduleTimer()
            }
        }

        // Kernel kqueue VNODE watchers (0% idle CPU, Apple Silicon E-Core queue)
        for w in vnodeWatchers { w.stop() }
        vnodeWatchers.removeAll()
        let homePath = FileManager.default.homeDirectoryForCurrentUser.path
        let appsWatcher = VnodeWatcher(path: "/Applications", debounceInterval: 0.40) { [weak self] in
            Task { @MainActor in
                guard let self = self, !self.isSystemAsleep else { return }
                if FileManager.default.fileExists(atPath: "/Applications/Claude.app") {
                    self.auditDefensesImmediately()
                }
            }
        }
        if appsWatcher.start() { vnodeWatchers.append(appsWatcher) }

        let configDir = "\(homePath)/.config/claude-guard"
        if FileManager.default.fileExists(atPath: configDir) {
            self.lastConfigFilesStamp = Self.captureConfigFilesStamp(configDir: configDir)
            let cfgWatcher = VnodeWatcher(path: configDir, debounceInterval: 0.50) { [weak self] in
                let newStamp = Self.captureConfigFilesStamp(configDir: configDir)
                Task { @MainActor in
                    guard let self = self, !self.isSystemAsleep else { return }
                    // Ignore internal cache writes (last_telemetry.json / last_purity.json)
                    guard newStamp != self.lastConfigFilesStamp else { return }
                    self.lastConfigFilesStamp = newStamp
                    self.refresh(force: true, mode: .light, resetPool: true)
                }
            }
            if cfgWatcher.start() { vnodeWatchers.append(cfgWatcher) }
        }

        let claudeDir = "\(homePath)/.claude"
        if FileManager.default.fileExists(atPath: claudeDir) {
            let settingsWatcher = VnodeWatcher(path: claudeDir, debounceInterval: 0.50) { [weak self] in
                Task { @MainActor in
                    guard let self = self, !self.isSystemAsleep else { return }
                    self.auditDefensesImmediately()
                }
            }
            if settingsWatcher.start() { vnodeWatchers.append(settingsWatcher) }
        }

        // Dual-layer Clash Verge Rev / Mihomo real-time proxy switch & TUN monitor
        mihomoMonitor.start { [weak self] _ in
            Task { @MainActor in
                guard let self = self, !self.isSystemAsleep else { return }
                let mode: TelemetryProbeMode = self.isUIVisible ? .full : .light
                self.refresh(force: true, mode: mode, resetPool: true)
            }
        }
        rescheduleTimer()
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
                    self.triggerAutoHideOriginalAppIfNeeded()
                }

                if self.autoKillOnBreach {
                    if updated.desktopUnprotected {
                        self.emergencyKillClaude(
                            includeCLI: false,
                            reason: "检测到未绑定硬代理或未禁 Bypass/QUIC/WebRTC 的 Claude 桌面版进程（#\(defenses.desktop_pid ?? "?")），已即时熔断急停防裸连！"
                        )
                    }
                    if updated.hasUnprotectedCLI {
                        self.killUnprotectedCLI(
                            pids: defenses.unprotected_cli_pids,
                            details: defenses.unprotectedCLIDetails
                        )
                    }
                }
            }
        }
    }

    func refresh(
        force: Bool = false,
        mode: TelemetryProbeMode? = nil,
        resetPool: Bool = false,
        userInitiated: Bool = false
    ) {
        let resolvedMode: TelemetryProbeMode = mode ?? (userInitiated ? .full : .light)
        if isProbeInFlight {
            if force || userInitiated {
                let mergedMode: TelemetryProbeMode =
                    (pendingRefresh?.mode == .full || resolvedMode == .full) ? .full : .light
                let mergedReset = (pendingRefresh?.resetPool ?? false) || resetPool
                let mergedUser = (pendingRefresh?.userInitiated ?? false) || userInitiated
                pendingRefresh = (mergedMode, mergedReset, mergedUser)
                if mergedUser {
                    isRefreshing = true
                }
            }
            return
        }
        if !force, !userInitiated, let last = lastRefreshAt, Date().timeIntervalSince(last) < 1.8 {
            return
        }
        lastRefreshAt = Date()
        if resolvedMode == .full {
            lastFullRefreshAt = Date()
        }
        isProbeInFlight = true
        if userInitiated {
            isRefreshing = true
        }
        let skipApi = !isUIVisible
            && !userInitiated
            && resolvedMode == .light
            && !resetPool
            && !snapshot.anyClaudeRunning
            && snapshot.isSafe
            && snapshot.api_latency.warm_rtt_ms != nil
        let priority: TaskPriority = (isUIVisible || force || userInitiated) ? .userInitiated : .utility
        Task.detached(priority: priority) {
            let result = RustCoreBridge.fetchTelemetry(mode: resolvedMode, resetPool: resetPool, skipApi: skipApi)
            await MainActor.run {
                self.isProbeInFlight = false
                if let next = self.pendingRefresh {
                    self.pendingRefresh = nil
                    if !next.userInitiated {
                        self.isRefreshing = false
                    }
                    self.applyTelemetryResult(result)
                    self.refresh(
                        force: true,
                        mode: next.mode,
                        resetPool: next.resetPool,
                        userInitiated: next.userInitiated
                    )
                    return
                }
                self.isRefreshing = false
                self.applyTelemetryResult(result)
            }
        }
    }

    private func applyTelemetryResult(_ result: TelemetrySnapshot?) {
        guard let result = result else { return }
        self.snapshot = result
        self.loginAutoStart = result.defenses.login_item_enabled
        self.onStatusChange?(result, self.purity)
        self.rescheduleTimer()

        if result.defenses.original_app_exposed && result.defenses.hideOriginalPreference {
            triggerAutoHideOriginalAppIfNeeded()
        }

        if result.isSafe {
            self.consecutiveUnreachableCount = 0
            return
        }

        if self.autoKillOnBreach {
            var killedAllSessions = false
            if result.anyClaudeRunning && result.isConfirmedNetworkBreach {
                let reason: String
                if result.regionBanned {
                    let loc = result.claude_edge.loc ?? result.tun.loc ?? "高危地区"
                    reason = "检测到封禁出口地区（\(loc)），已自动急停所有 Claude 桌面版与终端进程！"
                } else {
                    reason = "检测到出口 IP 漂移（Claude 边缘: \(result.proxy.ip) / TUN: \(result.tun.ip)），已自动急停所有 Claude 桌面版与终端进程！"
                }
                self.emergencyKillClaude(includeCLI: true, reason: reason)
                killedAllSessions = true
            } else {
                if result.desktopUnprotected {
                    self.emergencyKillClaude(
                        includeCLI: false,
                        reason: "检测到未绑定硬代理或未禁 Bypass/QUIC/WebRTC 的 Claude 桌面版进程（#\(result.defenses.desktop_pid ?? "?")），已自动急停防裸连！"
                    )
                }
                if result.hasUnprotectedCLI {
                    self.killUnprotectedCLI(
                        pids: result.defenses.unprotected_cli_pids,
                        details: result.defenses.unprotectedCLIDetails
                    )
                }
            }

            if !killedAllSessions && result.anyClaudeRunning && (!result.proxyOK || !result.tunOK) {
                self.consecutiveUnreachableCount += 1
                if self.consecutiveUnreachableCount >= 2 {
                    self.consecutiveUnreachableCount = 0
                    self.emergencyKillClaude(
                        includeCLI: true,
                        reason: "连续检测到代理/TUN 通道中断，已自动急停所有 Claude 桌面版与终端进程（Fail-Closed）！"
                    )
                } else {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak self] in
                        guard let self = self, !self.isSystemAsleep else { return }
                        self.refresh(force: true, mode: .light, resetPool: true)
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
                    let updatedSnap = self.snapshot.replacingDefenses(report.defenses)
                    self.snapshot = updatedSnap
                    self.loginAutoStart = report.defenses.login_item_enabled
                    self.purity = report.purity
                    self.onStatusChange?(updatedSnap, report.purity)
                    self.rescheduleTimer()
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

    private func triggerAutoHideOriginalAppIfNeeded() {
        guard !isHidingOriginalApp else { return }
        isHidingOriginalApp = true
        Task.detached(priority: .utility) {
            _ = RustCoreBridge.hideOriginalApp()
            await MainActor.run {
                self.isHidingOriginalApp = false
            }
        }
    }

    func showToast(_ msg: String) {
        toastDismissTask?.cancel()
        withAnimation(.easeInOut(duration: 0.2)) {
            toastMessage = msg
        }
        toastDismissTask = Task { @MainActor [weak self] in
            try? await Task.sleep(nanoseconds: 2_500_000_000)
            guard !Task.isCancelled, let self = self else { return }
            withAnimation(.easeInOut(duration: 0.2)) {
                if self.toastMessage == msg {
                    self.toastMessage = nil
                }
            }
        }
    }
}
