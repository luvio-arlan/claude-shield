import Cocoa
import SwiftUI

// MARK: - AppDelegate (Unified Safe Launcher + Menu Bar Radar)

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSPopoverDelegate {
    private static let reopenNotification = Notification.Name("com.local.claude.shield.launchDesktop")
    private static let statusTitleAttrs: [NSAttributedString.Key: Any] = [
        .font: NSFont.monospacedDigitSystemFont(ofSize: 12.5, weight: .medium),
        .baselineOffset: 0.2
    ]

    private var statusItem: NSStatusItem!
    private var popover: NSPopover?
    private var hostingController: NSHostingController<ShieldPopoverView>?
    private let viewModel = ShieldViewModel()
    private let launchGuardController = LaunchGuardWindowController()
    private let dashboardController = ShieldDashboardWindowController()
    private var hasCompletedInitialLaunch = false
    private var lastPopoverClosedAt: Date = .distantPast
    private var popoverGlobalMonitor: Any?
    private var popoverLocalMonitor: Any?
    private var lastStatusState: MenuBarShieldState?
    private var lastStatusText: String?
    private var lastStatusBaseKey: String?
    private var lastStatusLatencyMs: Int?

    func applicationDidFinishLaunching(_ notification: Notification) {
        let radarOnly = CommandLine.arguments.contains("--radar-only")

        if let icnsURL = Bundle.main.url(forResource: "app", withExtension: "icns"),
           let icon = NSImage(contentsOf: icnsURL) {
            NSApp.applicationIconImage = icon
        }

        if let bundleID = Bundle.main.bundleIdentifier {
            let others = NSRunningApplication.runningApplications(withBundleIdentifier: bundleID)
                .filter { $0.processIdentifier != ProcessInfo.processInfo.processIdentifier }
            if !others.isEmpty {
                if !radarOnly {
                    DistributedNotificationCenter.default().post(name: Self.reopenNotification, object: nil)
                }
                NSApp.terminate(nil)
                return
            }
        }

        DistributedNotificationCenter.default().addObserver(
            self,
            selector: #selector(handleExternalLaunchRequest),
            name: Self.reopenNotification,
            object: nil
        )

        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            button.imagePosition = .imageLeading
            button.action = #selector(togglePopover(_:))
            button.target = self
            button.sendAction(on: [.leftMouseDown])
            applyStatusButtonFromSnapshot(viewModel.snapshot, purity: viewModel.purity)
        }

        viewModel.onStatusChange = { [weak self] snap, purity in
            guard let self = self else { return }
            self.applyStatusButtonFromSnapshot(snap, purity: purity)
        }

        viewModel.onRequestClosePopover = { [weak self] in
            if self?.popover?.isShown == true {
                self?.popover?.performClose(nil)
            }
        }

        viewModel.onShowLaunchGuard = { [weak self] context in
            guard let self = self else { return }
            self.launchGuardController.show(context: context, viewModel: self.viewModel)
        }

        viewModel.onShowDashboard = { [weak self] section, isFirstRun in
            guard let self = self else { return }
            if self.popover?.isShown == true { self.popover?.performClose(nil) }
            self.dashboardController.show(viewModel: self.viewModel, section: section, isFirstRun: isFirstRun)
        }

        let willShowConsole = RustCoreBridge.needsInitialSetup || !radarOnly
        viewModel.startMonitoring(initialFullProbe: willShowConsole)
        hasCompletedInitialLaunch = true

        if RustCoreBridge.needsInitialSetup {
            dashboardController.show(viewModel: viewModel, section: .settings, isFirstRun: true)
        } else if !radarOnly {
            dashboardController.show(viewModel: viewModel, section: .radar, isFirstRun: false)
        }
    }

    func applicationWillTerminate(_ notification: Notification) {
        CoreWorkerClient.shared.shutdown()
    }

    private func ensurePopover() -> NSPopover {
        if let existing = popover {
            return existing
        }
        let hc = NSHostingController(rootView: ShieldPopoverView(vm: viewModel))
        hc.sizingOptions = .preferredContentSize
        self.hostingController = hc

        let pop = NSPopover()
        pop.behavior = .applicationDefined
        pop.animates = true
        pop.delegate = self
        pop.contentViewController = hc
        self.popover = pop
        return pop
    }

    private func applyStatusButtonFromSnapshot(_ snap: TelemetrySnapshot, purity: PurityReport?) {
        if snap.expected_ip == "检测中..." {
            updateStatusButton(state: .loading, text: "Shield", baseKey: "loading", latencyMs: nil)
            return
        }
        if snap.isSafe {
            let bestMs = snap.api_latency.warm_rtt_ms ?? snap.proxy.latency_ms
            let msText = bestMs.map { " \($0)ms" } ?? ""
            let gradeText = purity.map { " · \($0.grade)" } ?? ""
            let baseKey = "\(snap.region_short)\(gradeText)"
            updateStatusButton(state: .armed, text: "\(snap.region_short)\(msText)\(gradeText)", baseKey: baseKey, latencyMs: bestMs)
        } else if snap.regionBanned {
            updateStatusButton(state: .alert, text: "地区封禁!", baseKey: "alert-region", latencyMs: nil)
        } else if snap.desktopUnprotected || snap.hasUnprotectedCLI {
            updateStatusButton(state: .alert, text: "进程未受保护!", baseKey: "alert-proc", latencyMs: nil)
        } else {
            updateStatusButton(state: .alert, text: "IP 异常!", baseKey: "alert-ip", latencyMs: nil)
        }
    }

    func popoverDidClose(_ notification: Notification) {
        teardownPopoverMonitors()
        lastPopoverClosedAt = Date()
        viewModel.setPopoverVisible(false)
        // Release hidden SwiftUI view tree so closed menu bar radar uses zero background CPU/GPU
        popover?.contentViewController = nil
        hostingController = nil
        popover = nil
    }

    private func installPopoverMonitors() {
        teardownPopoverMonitors()

        popoverGlobalMonitor = NSEvent.addGlobalMonitorForEvents(
            matching: [.leftMouseDown, .rightMouseDown]
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self, let pop = self.popover, pop.isShown else { return }
                if let btnFrame = self.statusItem.button?.window?.frame,
                   btnFrame.contains(NSEvent.mouseLocation) {
                    return
                }
                pop.performClose(nil)
            }
        }

        popoverLocalMonitor = NSEvent.addLocalMonitorForEvents(
            matching: [.leftMouseDown, .rightMouseDown, .keyDown]
        ) { [weak self] event in
            guard let self, let pop = self.popover, pop.isShown else { return event }
            if event.type == .keyDown {
                if event.keyCode == 53 {
                    pop.performClose(nil)
                    return nil
                }
                return event
            }
            let popWindow = pop.contentViewController?.view.window
            let btnWindow = self.statusItem.button?.window
            if event.window !== popWindow && event.window !== btnWindow {
                pop.performClose(nil)
            }
            return event
        }
    }

    private func teardownPopoverMonitors() {
        if let global = popoverGlobalMonitor {
            NSEvent.removeMonitor(global)
            popoverGlobalMonitor = nil
        }
        if let local = popoverLocalMonitor {
            NSEvent.removeMonitor(local)
            popoverLocalMonitor = nil
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if hasCompletedInitialLaunch {
            dashboardController.show(viewModel: viewModel, section: dashboardController.currentSection, isFirstRun: false)
        }
        return true
    }

    @objc private func handleExternalLaunchRequest() {
        dashboardController.show(viewModel: viewModel, section: dashboardController.currentSection, isFirstRun: false)
    }

    private func updateStatusButton(state: MenuBarShieldState, text: String, baseKey: String, latencyMs: Int?) {
        if lastStatusState == state && lastStatusText == text {
            return
        }
        // Hysteresis in background mode: skip tiny <3ms noise redraws while keeping live accuracy
        if !viewModel.isUIVisible,
           state == .armed,
           lastStatusState == .armed,
           lastStatusBaseKey == baseKey,
           let prevMs = lastStatusLatencyMs,
           let nextMs = latencyMs,
           abs(nextMs - prevMs) < 3 {
            return
        }
        guard let button = statusItem.button else { return }
        let stateChanged = lastStatusState != state
        lastStatusState = state
        lastStatusText = text
        lastStatusBaseKey = baseKey
        lastStatusLatencyMs = latencyMs
        if stateChanged || button.image == nil {
            button.image = ShieldBrandGraphics.makeMenuBarIcon(state: state)
        }
        button.attributedTitle = NSAttributedString(string: " \(text)", attributes: Self.statusTitleAttrs)
    }

    private func showPopoverNow() {
        guard let button = statusItem.button else { return }
        let pop = ensurePopover()
        viewModel.setPopoverVisible(true)
        NSApp.activate(ignoringOtherApps: true)
        pop.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        pop.contentViewController?.view.window?.makeKey()
        installPopoverMonitors()
    }

    @objc private func togglePopover(_ sender: AnyObject?) {
        if let pop = popover, pop.isShown {
            pop.performClose(sender)
            return
        }
        if Date().timeIntervalSince(lastPopoverClosedAt) < 0.06 {
            return
        }
        showPopoverNow()
    }
}
