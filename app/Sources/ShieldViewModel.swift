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
    private var wakeObserver: NSObjectProtocol?
    private var lastNetworkStatus: NWPath.Status?
    private var consecutiveUnreachableCount = 0
    private var lastRefreshAt: Date?

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
        if let observer = wakeObserver {
            NSWorkspace.shared.notificationCenter.removeObserver(observer)
        }
    }

    func startMonitoring() {
        refresh(force: true)

        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 15.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh(force: false) }
        }

        DispatchQueue.main.asyncAfter(deadline: .now() + 1.8) { [weak self] in
            self?.refreshPurity(silent: true)
        }
        purityTimer?.invalidate()
        purityTimer = Timer.scheduledTimer(withTimeInterval: 14400.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.runFullCheckup(silent: true) }
        }

        DispatchQueue.main.asyncAfter(deadline: .now() + 5.0) { [weak self] in
            self?.checkForUpdates(manual: false)
        }
        updateTimer?.invalidate()
        updateTimer = Timer.scheduledTimer(withTimeInterval: 21600.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.checkForUpdates(manual: false) }
        }

        if let existingObserver = wakeObserver {
            NSWorkspace.shared.notificationCenter.removeObserver(existingObserver)
        }
        wakeObserver = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.consecutiveUnreachableCount = 0
                self?.refresh(force: true)
                DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) {
                    self?.refresh(force: true)
                }
            }
        }

        pathMonitor?.cancel()
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            Task { @MainActor in
                guard let self = self else { return }
                let changed = self.lastNetworkStatus != nil && self.lastNetworkStatus != path.status
                self.lastNetworkStatus = path.status
                if changed {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
                        self.refresh(force: true)
                    }
                }
            }
        }
        monitor.start(queue: DispatchQueue.global(qos: .utility))
        self.pathMonitor = monitor
    }

    func refresh(force: Bool = false) {
        guard !isRefreshing else { return }
        if !force, let last = lastRefreshAt, Date().timeIntervalSince(last) < 4.0 {
            return
        }
        lastRefreshAt = Date()
        isRefreshing = true
        Task.detached(priority: .userInitiated) {
            let result = RustCoreBridge.fetchTelemetry()
            await MainActor.run {
                self.isRefreshing = false
                guard let result = result else { return }
                self.snapshot = result
                self.loginAutoStart = result.defenses.login_item_enabled
                self.onStatusChange?(result, self.purity)

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
                                self.refresh(force: true)
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

    func copyDiagnosticScreenshot(_ pngData: Data?) {
        guard let pngData = pngData, let image = NSImage(data: pngData) else {
            showToast("截图生成失败，请重试")
            return
        }
        let pb = NSPasteboard.general
        pb.clearContents()
        let item = NSPasteboardItem()
        item.setData(pngData, forType: .png)
        if let tiff = image.tiffRepresentation {
            item.setData(tiff, forType: .tiff)
        }
        pb.writeObjects([item])
        showToast("2x 高清诊断截图已复制，可直接 ⌘V 粘贴")
    }

    func openSetupWizard(isFirstRun: Bool = false) {
        openDashboard(section: .settings, isFirstRun: isFirstRun)
    }

    func openDashboard(section: ShieldDashboardSection = .radar, isFirstRun: Bool = false) {
        onRequestClosePopover?()
        onShowDashboard?(section, isFirstRun)
    }

    func checkForUpdates(manual: Bool = false) {
        guard !updatePhase.isBusy else { return }
        if manual {
            updatePhase = .checking
        }
        let proxyPort = snapshot.proxy_port
        Task.detached(priority: manual ? .userInitiated : .utility) {
            do {
                let info = try await GitHubUpdater.checkLatestRelease(proxyPort: proxyPort)
                await MainActor.run {
                    if let info = info {
                        if manual {
                            self.dismissedUpdateVersion = nil
                        }
                        self.updatePhase = .available(info)
                        self.onStatusChange?(self.snapshot, self.purity)
                        if manual {
                            self.showToast("发现新版本 \(info.tagName)，可一键更新")
                        }
                    } else if manual {
                        self.updatePhase = .upToDate(AppReleaseConfig.shortDisplayVersion)
                        self.showToast("当前已是最新版本 \(AppReleaseConfig.shortDisplayVersion)")
                    }
                }
            } catch {
                await MainActor.run {
                    if manual {
                        let msg = (error as? LocalizedError)?.errorDescription ?? "检查更新失败，请确认网络连接"
                        self.updatePhase = .failed(msg)
                        self.showToast(msg)
                    }
                }
            }
        }
    }

    func performUpdate(_ info: AppUpdateInfo) {
        guard !updatePhase.isBusy else { return }
        if info.zipDownloadURL == nil {
            NSWorkspace.shared.open(info.htmlURL)
            return
        }
        let proxyPort = snapshot.proxy_port
        updatePhase = .downloading(info, 0.0)
        Task.detached(priority: .userInitiated) {
            do {
                try await GitHubUpdater.downloadAndInstall(
                    info: info,
                    proxyPort: proxyPort,
                    onProgress: { progress in
                        Task { @MainActor in
                            self.updatePhase = .downloading(info, progress)
                        }
                    },
                    onStage: { stage in
                        Task { @MainActor in
                            self.updatePhase = .installing(info, stage)
                        }
                    }
                )
                await MainActor.run {
                    NSApp.terminate(nil)
                }
            } catch {
                await MainActor.run {
                    let msg = (error as? LocalizedError)?.errorDescription ?? "更新失败：\(error.localizedDescription)"
                    self.updatePhase = .failed(msg)
                    self.showToast(msg)
                }
            }
        }
    }

    func dismissUpdateBanner(_ version: String) {
        dismissedUpdateVersion = version
        onStatusChange?(snapshot, purity)
    }

    func openReleasePage(_ url: URL) {
        NSWorkspace.shared.open(url)
    }

    func confirmAndUninstall() {
        onRequestClosePopover?()
        NSApp.activate(ignoringOtherApps: true)

        let confirm = NSAlert()
        confirm.alertStyle = .warning
        confirm.messageText = "确认一键卸载并还原系统环境？"
        confirm.informativeText = """
        Claude Shield 将为您完整还原以下所有本地修改：

        • 将隐藏隔离仓中的原版 Claude.app 还原至 /Applications，并恢复启动台 / Spotlight 图标
        • 移除 Claude Code CLI 代理门禁与 OAuth 系统浏览器弹窗拦截器
        • 还原 ~/.claude/settings.json 中的时区 / 语言 / 遥测 / 沙盒注入项（保留您原有配置）
        • 关闭并清理开机自启雷达与每日自动巡检任务
        • 清理 ~/.config/claude-guard 本地配置与缓存，并将 Claude Shield.app 移至废纸篓
        """
        confirm.addButton(withTitle: "一键卸载并还原")
        confirm.addButton(withTitle: "取消")
        if let firstBtn = confirm.buttons.first {
            firstBtn.hasDestructiveAction = true
        }

        guard confirm.runModal() == .alertFirstButtonReturn else { return }

        Task.detached(priority: .userInitiated) {
            let report = RustCoreBridge.runUninstall()
            var trashedApp = false
            let bundleURL = Bundle.main.bundleURL
            if bundleURL.pathExtension == "app" && FileManager.default.fileExists(atPath: bundleURL.path) {
                do {
                    try FileManager.default.trashItem(at: bundleURL, resultingItemURL: nil)
                    trashedApp = true
                } catch {
                    trashedApp = false
                }
            }

            let didTrashApp = trashedApp
            await MainActor.run {
                var items = report?.restored ?? ["已清理 Claude Shield 本地防护配置"]
                if didTrashApp {
                    items.append("已将 Claude Shield.app 移至废纸篓")
                }
                let listText = items.map { "✅ \($0)" }.joined(separator: "\n")
                let warnText: String
                if let warns = report?.warnings, !warns.isEmpty {
                    warnText = "\n\n注意：\n" + warns.map { "⚠️ \($0)" }.joined(separator: "\n")
                } else {
                    warnText = ""
                }

                let done = NSAlert()
                done.alertStyle = .informational
                done.messageText = "Claude Shield 已卸载并完全还原"
                done.informativeText = "\(listText)\(warnText)\n\n您的原版 Claude 应用、终端命令与系统环境均已恢复至安装前状态。"
                done.addButton(withTitle: "知道了")
                NSApp.activate(ignoringOtherApps: true)
                done.runModal()
                NSApplication.shared.terminate(nil)
            }
        }
    }

    private func showToast(_ msg: String) {
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
