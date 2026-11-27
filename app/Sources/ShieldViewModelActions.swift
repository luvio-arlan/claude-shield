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
}
