import Cocoa
import SwiftUI

// MARK: - ShieldViewModel Secondary Actions (Navigation, Updates & Uninstall)

extension ShieldViewModel {
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

    func dismissUpdateError() {
        if case .failed = updatePhase {
            updatePhase = .idle
        }
    }

    func openReleasePage(_ url: URL) {
        NSWorkspace.shared.open(url)
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
        loginAutoStart = enabled
        Task.detached(priority: .userInitiated) {
            let actual = RustCoreBridge.toggleLaunchAgent(enabled: enabled)
            await MainActor.run {
                self.loginAutoStart = actual
                self.showToast(actual ? "已开启开机自启保护雷达" : "已关闭开机自启雷达")
            }
            try? await Task.sleep(nanoseconds: 400_000_000)
            await MainActor.run {
                self.refresh(force: true)
            }
        }
    }

    func findRunningClaudeApp() -> NSRunningApplication? {
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
        // Only short-circuit to focusing an existing Desktop window when current telemetry is verified safe
        if findRunningClaudeApp() != nil,
           snapshot.expected_ip != "检测中...",
           snapshot.isSafe,
           !snapshot.desktopUnprotected {
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
                // Gate just passed on warm pool -> skip redundant cold gate re-probe
                self.executeDesktopLaunch(force: false, recordIP: ctx.currentIP, gateAlreadyPassed: true)
            }
        }
    }

    func executeDesktopLaunch(force: Bool, recordIP: String?, gateAlreadyPassed: Bool = false) {
        onRequestClosePopover?()
        if let ip = recordIP {
            RustCoreBridge.saveLastLaunchIP(ip)
        }

        let skipGate = force || gateAlreadyPassed
        showToast(force ? "已强制安全启动 Claude 桌面版" : "验真通过，正在启动 Claude 桌面版...")

        Task.detached(priority: .userInitiated) {
            let outcome = RustCoreBridge.launchDesktop(skipGate: skipGate, verifiedIP: recordIP)
            await MainActor.run {
                if let outcome = outcome {
                    if !outcome.ok {
                        self.showToast(outcome.message)
                    } else if outcome.already_running {
                        self.focusClaudeDesktop()
                    }
                } else {
                    // Fallback to CLI helper only if in-process FFI returned nil
                    let bin = RustCoreBridge.coreBinaryPath
                    let task = Process()
                    if FileManager.default.isExecutableFile(atPath: bin) {
                        task.executableURL = URL(fileURLWithPath: bin)
                        task.arguments = skipGate ? ["launch-desktop", "--force"] : ["launch-desktop"]
                    } else {
                        let script = FileManager.default.homeDirectoryForCurrentUser
                            .appendingPathComponent(".local/bin/claude-desktop-safe").path
                        task.executableURL = URL(fileURLWithPath: "/bin/bash")
                        task.arguments = [script]
                    }
                    try? task.run()
                }
            }
            try? await Task.sleep(nanoseconds: 1_000_000_000)
            await MainActor.run {
                self.focusClaudeDesktop()
                self.refresh(force: true)
            }
        }
    }

    nonisolated private static func postSystemNotificationAsync(title: String, body: String, sound: String? = "Sosumi") {
        let safeTitle = title
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "'")
            .replacingOccurrences(of: "\r", with: " ")
            .replacingOccurrences(of: "\n", with: " ")
        let safeBody = body
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "'")
            .replacingOccurrences(of: "\r", with: " ")
            .replacingOccurrences(of: "\n", with: " ")
        let script: String
        if let sound = sound {
            script = "display notification \"\(safeBody)\" with title \"\(safeTitle)\" sound name \"\(sound)\""
        } else {
            script = "display notification \"\(safeBody)\" with title \"\(safeTitle)\""
        }
        Task.detached(priority: .utility) {
            let alert = Process()
            alert.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            alert.arguments = ["-e", script]
            try? alert.run()
            alert.waitUntilExit()
        }
    }

    func killUnprotectedCLI(pids: [String], details: [String] = []) {
        let candidatePIDs = pids.filter { !inFlightKillCLIPIDs.contains($0) }
        guard !candidatePIDs.isEmpty else { return }
        inFlightKillCLIPIDs.formUnion(candidatePIDs)

        Task.detached(priority: .userInitiated) {
            // Brief 120ms re-verification eliminates fork/execve races and transient probes
            // before sending SIGKILL or surfacing a breach alert.
            try? await Task.sleep(nanoseconds: 120_000_000)
            let freshDefenses = RustCoreBridge.fetchLocalDefenses()
            let freshSet = Set(freshDefenses?.unprotected_cli_pids ?? [])
            let confirmedPIDs = candidatePIDs.filter { freshSet.contains($0) }
            guard !confirmedPIDs.isEmpty else {
                await MainActor.run {
                    self.inFlightKillCLIPIDs.subtract(candidatePIDs)
                }
                return
            }

            let confirmedDetails = freshDefenses?.unprotectedCLIDetails.filter { detail in
                confirmedPIDs.contains { pid in detail.hasPrefix("#\(pid) ") }
            } ?? details
            let killed = RustCoreBridge.killPIDs(confirmedPIDs)

            if killed > 0 {
                let targetSummary = confirmedDetails.isEmpty
                    ? confirmedPIDs.map { "#\($0)" }.joined(separator: "、")
                    : confirmedDetails.joined(separator: "；")
                Self.postSystemNotificationAsync(
                    title: "Claude Shield 熔断急停",
                    body: "发现未走安全门禁的 Claude Code 进程（\(targetSummary)），已自动终止防裸连！"
                )
                await MainActor.run {
                    self.showToast("已终止 \(killed) 个未受保护的 CLI 进程（\(targetSummary)）")
                }
            }

            try? await Task.sleep(nanoseconds: 600_000_000)
            await MainActor.run {
                self.inFlightKillCLIPIDs.subtract(candidatePIDs)
                self.auditDefensesImmediately()
            }
        }
    }

    func emergencyKillClaude(includeCLI: Bool = true, reason: String? = nil) {
        Task.detached(priority: .userInitiated) {
            let outcome = RustCoreBridge.killClaude(includeCLI: includeCLI)
            let totalKilled = (outcome?.killed_desktop ?? 0) + (outcome?.killed_cli ?? 0)
            if let reason = reason, totalKilled > 0 {
                Self.postSystemNotificationAsync(title: "Claude Shield 熔断急停", body: reason)
            }
            await MainActor.run {
                if let out = outcome, out.killed_cli > 0 {
                    self.showToast("已执行紧急急停（已终止桌面版与 \(out.killed_cli) 个 CLI 进程）")
                } else {
                    self.showToast("已执行紧急急停（Claude 进程已终止）")
                }
            }
            try? await Task.sleep(nanoseconds: 600_000_000)
            await MainActor.run {
                self.refresh(force: true)
            }
        }
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
}
