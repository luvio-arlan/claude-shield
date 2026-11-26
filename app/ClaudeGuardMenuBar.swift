import Cocoa
import SwiftUI
import Combine

// MARK: - Data Model

struct TelemetrySnapshot: Sendable {
    let expectedIP: String
    let proxyPort: String
    let proxyIP: String
    let proxyLatencyMs: Int?
    let tunIP: String
    let tunLatencyMs: Int?
    let oauthLocked: Bool
    let originalHidden: Bool
    let sandboxEnabled: Bool
    let desktopPID: String?
    let cliLoggedIn: Bool
    let checkedAt: String

    var proxyOK: Bool { !expectedIP.isEmpty && proxyIP == expectedIP }
    var tunOK: Bool { !expectedIP.isEmpty && tunIP == expectedIP }
    var isSafe: Bool { proxyOK && tunOK }
    var desktopRunning: Bool { desktopPID != nil }
    var defenseScore: Int {
        var s = 0
        if proxyOK { s += 1 }
        if tunOK { s += 1 }
        if oauthLocked { s += 1 }
        if originalHidden { s += 1 }
        if sandboxEnabled { s += 1 }
        if cliLoggedIn || desktopRunning { s += 1 }
        return s
    }

    static let initial = TelemetrySnapshot(
        expectedIP: "检测中...",
        proxyPort: "7897",
        proxyIP: "...",
        proxyLatencyMs: nil,
        tunIP: "...",
        tunLatencyMs: nil,
        oauthLocked: false,
        originalHidden: false,
        sandboxEnabled: false,
        desktopPID: nil,
        cliLoggedIn: false,
        checkedAt: "--:--:--"
    )
}

// MARK: - Shell Telemetry Probe (Off-Main)

private enum TelemetryProbe {
    static func run(_ path: String, _ args: [String]) -> (output: String, ms: Int) {
        let start = CFAbsoluteTimeGetCurrent()
        let task = Process()
        task.executableURL = URL(fileURLWithPath: path)
        task.arguments = args
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice
        do {
            try task.run()
            task.waitUntilExit()
            let elapsed = Int((CFAbsoluteTimeGetCurrent() - start) * 1000)
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            let str = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            return (str, elapsed)
        } catch {
            return ("", 0)
        }
    }

    static func fetchIP(viaProxy: Bool, port: String) -> (ip: String, ms: Int?) {
        let urls = ["https://api.ipify.org", "https://ifconfig.me/ip"]
        for url in urls {
            let args: [String] = viaProxy
                ? ["-fsS", "--max-time", "4", "-x", "http://127.0.0.1:\(port)", url]
                : ["-fsS", "--max-time", "4", "--noproxy", "*", url]
            let res = run("/usr/bin/curl", args)
            if !res.output.isEmpty && res.output.count <= 45 {
                return (res.output, res.ms)
            }
        }
        return ("无法连通", nil)
    }

    static func collect() -> TelemetrySnapshot {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let fm = FileManager.default

        let ipFile = home.appendingPathComponent(".config/claude-guard/expected_ip")
        let expectedIP = (try? String(contentsOf: ipFile, encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? "未配置"

        let portFile = home.appendingPathComponent(".config/claude-guard/proxy_port")
        let rawPort = (try? String(contentsOf: portFile, encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let proxyPort = rawPort.isEmpty ? "7897" : rawPort

        let proxyRes = fetchIP(viaProxy: true, port: proxyPort)
        let tunRes = fetchIP(viaProxy: false, port: proxyPort)

        let oauthPath = home.appendingPathComponent(".local/lib/claude-guard-bin/open").path
        let oauthLocked = fm.isExecutableFile(atPath: oauthPath)

        let origInApps = fm.fileExists(atPath: "/Applications/Claude.app")
        let origInVault = fm.fileExists(atPath: home.appendingPathComponent(".local/apps/Claude.app").path)
        let originalHidden = !origInApps && origInVault

        let settingsPath = home.appendingPathComponent(".claude/settings.json").path
        let settingsText = (try? String(contentsOfFile: settingsPath, encoding: .utf8)) ?? ""
        let sandboxEnabled = settingsText.contains("\"enabled\": true") || settingsText.contains("\"enabled\":true")

        let pgrepRes = run("/usr/bin/pgrep", ["-x", "Claude"])
        let desktopPID = pgrepRes.output.split(separator: "\n").first.map(String.init)

        let claudeDirExists = fm.fileExists(atPath: home.appendingPathComponent(".claude.json").path)
            || fm.fileExists(atPath: home.appendingPathComponent(".claude/settings.json").path)

        let df = DateFormatter()
        df.dateFormat = "HH:mm:ss"

        return TelemetrySnapshot(
            expectedIP: expectedIP,
            proxyPort: proxyPort,
            proxyIP: proxyRes.ip,
            proxyLatencyMs: proxyRes.ms,
            tunIP: tunRes.ip,
            tunLatencyMs: tunRes.ms,
            oauthLocked: oauthLocked,
            originalHidden: originalHidden,
            sandboxEnabled: sandboxEnabled,
            desktopPID: desktopPID,
            cliLoggedIn: claudeDirExists,
            checkedAt: df.string(from: Date())
        )
    }
}

// MARK: - ViewModel

@MainActor
final class GuardViewModel: ObservableObject {
    @Published var snapshot: TelemetrySnapshot = .initial
    @Published var isRefreshing: Bool = false
    @Published var pulse: Bool = false
    @Published var autoKillOnBreach: Bool {
        didSet { UserDefaults.standard.set(autoKillOnBreach, forKey: "autoKillOnBreach") }
    }
    @Published var toastMessage: String?

    var onStatusChange: ((TelemetrySnapshot) -> Void)?
    private var timer: Timer?

    init() {
        self.autoKillOnBreach = UserDefaults.standard.object(forKey: "autoKillOnBreach") as? Bool ?? true
    }

    func startPolling() {
        refresh()
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 15.0, repeats: true) { [weak self] _ in
            Task { @MainActor in
                self?.refresh()
            }
        }
    }

    func refresh() {
        guard !isRefreshing else { return }
        isRefreshing = true
        Task.detached(priority: .utility) {
            let result = TelemetryProbe.collect()
            await MainActor.run {
                self.snapshot = result
                self.isRefreshing = false
                self.onStatusChange?(result)

                // Fail-closed emergency auto-kill if IP drifts while Claude Desktop is running
                if self.autoKillOnBreach && !result.isSafe && result.desktopRunning {
                    self.emergencyKillClaude(reason: "检测到出口 IP 漂移（代理: \(result.proxyIP) / TUN: \(result.tunIP)），已自动急停 Claude 桌面版以防裸连！")
                }
            }
        }
    }

    func launchClaudeSafe() {
        let script = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".local/bin/claude-desktop-safe").path
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/bash")
        task.arguments = [script]
        try? task.run()
        showToast(snapshot.desktopRunning ? "已切换至 Claude 桌面版" : "正在验真并启动 Claude Safe...")
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) { [weak self] in
            self?.refresh()
        }
    }

    func emergencyKillClaude(reason: String? = nil) {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
        task.arguments = ["-9", "-x", "Claude"]
        try? task.run()
        task.waitUntilExit()

        if let reason = reason {
            let alert = Process()
            alert.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            alert.arguments = ["-e", "display notification \"\(reason)\" with title \"Claude Guard 熔断急停\" sound name \"Sosumi\""]
            try? alert.run()
        }
        showToast("已执行紧急急停（Claude 进程已终止）")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) { [weak self] in
            self?.refresh()
        }
    }

    func copyDiagnostics() {
        let s = snapshot
        let report = """
        [Claude Safe Cage Telemetry · \(s.checkedAt)]
        Status: \(s.isSafe ? "ARMED (SAFE)" : "BREACH WARNING")
        Whitelist IP: \(s.expectedIP)
        Proxy (127.0.0.1:\(s.proxyPort)): \(s.proxyIP) (\(s.proxyLatencyMs.map { "\($0)ms" } ?? "N/A"))
        TUN Route: \(s.tunIP) (\(s.tunLatencyMs.map { "\($0)ms" } ?? "N/A"))
        OAuth Lock: \(s.oauthLocked ? "AdsPower-Only" : "Unlocked")
        Original App Vault: \(s.originalHidden ? "Hidden" : "Exposed")
        macOS Seatbelt Sandbox: \(s.sandboxEnabled ? "Enabled" : "Disabled")
        Desktop Process: \(s.desktopPID.map { "Running (PID \($0))" } ?? "Idle")
        """
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(report, forType: .string)
        showToast("诊断快照已复制到剪贴板")
    }

    func quitApp() {
        NSApplication.shared.terminate(nil)
    }

    private func showToast(_ msg: String) {
        withAnimation(.easeInOut(duration: 0.2)) {
            toastMessage = msg
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.4) { [weak self] in
            withAnimation(.easeInOut(duration: 0.2)) {
                if self?.toastMessage == msg {
                    self?.toastMessage = nil
                }
            }
        }
    }
}

// MARK: - SwiftUI Commercial UI

struct GuardPopoverView: View {
    @ObservedObject var vm: GuardViewModel

    private var accentColor: Color {
        vm.snapshot.isSafe ? Color(red: 0.16, green: 0.82, blue: 0.49) : Color(red: 0.96, green: 0.29, blue: 0.34)
    }

    var body: some View {
        ZStack(alignment: .bottom) {
            VStack(spacing: 12) {
                headerCard
                networkTelemetryRow
                defenseMatrixGrid
                protectionToggleBar
                actionButtonsBar
                footerBar
            }
            .padding(14)

            if let toast = vm.toastMessage {
                Text(toast)
                    .font(.system(size: 11, weight: .medium))
                    .foregroundColor(.white)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(Capsule().fill(Color.black.opacity(0.82)))
                    .shadow(color: .black.opacity(0.25), radius: 6, y: 2)
                    .padding(.bottom, 10)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .frame(width: 368)
        .background(VisualEffectView(material: .popover, blendingMode: .behindWindow))
        .onAppear {
            withAnimation(.easeInOut(duration: 1.8).repeatForever(autoreverses: true)) {
                vm.pulse = true
            }
        }
    }

    // 1. Hero Status Card
    private var headerCard: some View {
        HStack(spacing: 12) {
            ZStack {
                Circle()
                    .fill(accentColor.opacity(vm.pulse ? 0.24 : 0.10))
                    .frame(width: 44, height: 44)
                Circle()
                    .fill(accentColor.opacity(0.18))
                    .frame(width: 34, height: 34)
                Image(systemName: vm.snapshot.isSafe ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                    .font(.system(size: 18, weight: .semibold))
                    .foregroundColor(accentColor)
            }

            VStack(alignment: .leading, spacing: 3) {
                HStack(spacing: 6) {
                    Text(vm.snapshot.isSafe ? "CAGE ARMED" : "IP 异常预警")
                        .font(.system(size: 14, weight: .bold, design: .rounded))
                        .foregroundColor(.primary)

                    Text(vm.snapshot.isSafe ? "全链路锁死" : "熔断就绪")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundColor(accentColor)
                        .padding(.horizontal, 6)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(accentColor.opacity(0.14)))
                }

                HStack(spacing: 6) {
                    Image(systemName: "network")
                        .font(.system(size: 10))
                        .foregroundColor(.secondary)
                    Text(vm.snapshot.expectedIP)
                        .font(.system(size: 11.5, weight: .medium, design: .monospaced))
                        .foregroundColor(.secondary)
                    Text("· Los Angeles")
                        .font(.system(size: 11))
                        .foregroundColor(.secondary.opacity(0.85))
                }
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 2) {
                Text("\(vm.snapshot.defenseScore)/6")
                    .font(.system(size: 15, weight: .bold, design: .rounded))
                    .foregroundColor(accentColor)
                Text("防线激活")
                    .font(.system(size: 9.5))
                    .foregroundColor(.secondary)
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(
                    LinearGradient(
                        colors: [accentColor.opacity(0.12), Color.primary.opacity(0.03)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(accentColor.opacity(0.32), lineWidth: 1)
        )
    }

    // 2. Dual-Channel Network Telemetry
    private var networkTelemetryRow: some View {
        HStack(spacing: 8) {
            tunnelCard(
                title: "代理端口 :\(vm.snapshot.proxyPort)",
                ip: vm.snapshot.proxyIP,
                latency: vm.snapshot.proxyLatencyMs,
                ok: vm.snapshot.proxyOK,
                icon: "arrow.triangle.branch"
            )
            tunnelCard(
                title: "系统路由 (TUN)",
                ip: vm.snapshot.tunIP,
                latency: vm.snapshot.tunLatencyMs,
                ok: vm.snapshot.tunOK,
                icon: "shield.lefthalf.filled"
            )
        }
    }

    private func tunnelCard(title: String, ip: String, latency: Int?, ok: Bool, icon: String) -> some View {
        let dotColor: Color = ok ? Color(red: 0.16, green: 0.82, blue: 0.49) : Color(red: 0.96, green: 0.29, blue: 0.34)
        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 5) {
                Circle()
                    .fill(dotColor)
                    .frame(width: 7, height: 7)
                Text(title)
                    .font(.system(size: 10.5, weight: .medium))
                    .foregroundColor(.secondary)
                Spacer()
                if let ms = latency {
                    Text("\(ms)ms")
                        .font(.system(size: 9.5, weight: .semibold, design: .monospaced))
                        .foregroundColor(ms < 500 ? .secondary : .orange)
                }
            }

            HStack(spacing: 4) {
                Image(systemName: icon)
                    .font(.system(size: 10))
                    .foregroundColor(dotColor.opacity(0.9))
                Text(ip)
                    .font(.system(size: 11.5, weight: .semibold, design: .monospaced))
                    .foregroundColor(.primary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
            }
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Color.primary.opacity(0.045)))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(Color.primary.opacity(0.08), lineWidth: 0.8))
    }

    // 3. 6-Layer Defense Matrix
    private var defenseMatrixGrid: some View {
        let cols = [GridItem(.flexible(), spacing: 8), GridItem(.flexible(), spacing: 8)]
        return LazyVGrid(columns: cols, spacing: 8) {
            metricTile(icon: "globe.americas.fill", title: "时区与语言", value: "LA · en-US", ok: true)
            metricTile(icon: "lock.shield.fill", title: "OAuth 门禁", value: vm.snapshot.oauthLocked ? "AdsPower-Only" : "未锁定", ok: vm.snapshot.oauthLocked)
            metricTile(icon: "eye.slash.fill", title: "原版隐藏仓", value: vm.snapshot.originalHidden ? "已隔离防误触" : "暴露在应用栏", ok: vm.snapshot.originalHidden)
            metricTile(icon: "cube.transparent.fill", title: "macOS 沙盒", value: vm.snapshot.sandboxEnabled ? "Seatbelt 已启" : "未启用", ok: vm.snapshot.sandboxEnabled)
            metricTile(icon: "desktopcomputer", title: "桌面版进程", value: vm.snapshot.desktopPID.map { "受保护 · #\($0)" } ?? "待机未启动", ok: true, dim: !vm.snapshot.desktopRunning)
            metricTile(icon: "terminal.fill", title: "Claude Code", value: vm.snapshot.cliLoggedIn ? "CLI 防护就绪" : "待初始化", ok: vm.snapshot.cliLoggedIn)
        }
    }

    private func metricTile(icon: String, title: String, value: String, ok: Bool, dim: Bool = false) -> some View {
        let tint: Color = dim ? .secondary : (ok ? Color(red: 0.16, green: 0.82, blue: 0.49) : .orange)
        return HStack(spacing: 8) {
            Image(systemName: icon)
                .font(.system(size: 13))
                .foregroundColor(tint)
                .frame(width: 20)

            VStack(alignment: .leading, spacing: 1.5) {
                Text(title)
                    .font(.system(size: 10))
                    .foregroundColor(.secondary)
                Text(value)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(dim ? .secondary : .primary)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 9)
        .padding(.vertical, 7)
        .background(RoundedRectangle(cornerRadius: 9, style: .continuous).fill(Color.primary.opacity(0.035)))
        .overlay(RoundedRectangle(cornerRadius: 9, style: .continuous).strokeBorder(Color.primary.opacity(0.06), lineWidth: 0.6))
    }

    // 4. Fail-Closed Auto-Kill Toggle
    private var protectionToggleBar: some View {
        HStack(spacing: 8) {
            Image(systemName: "bolt.shield.fill")
                .font(.system(size: 13))
                .foregroundColor(vm.autoKillOnBreach ? .orange : .secondary)
            VStack(alignment: .leading, spacing: 1) {
                Text("IP 漂移自动急停（Fail-Closed）")
                    .font(.system(size: 11.5, weight: .semibold))
                Text("巡检发现节点异常时自动终止桌面版防裸连")
                    .font(.system(size: 9.5))
                    .foregroundColor(.secondary)
            }
            Spacer()
            Toggle("", isOn: $vm.autoKillOnBreach)
                .toggleStyle(.switch)
                .controlSize(.mini)
                .labelsHidden()
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(Color.primary.opacity(0.04)))
    }

    // 5. Primary & Secondary Actions
    private var actionButtonsBar: some View {
        HStack(spacing: 8) {
            Button(action: { vm.launchClaudeSafe() }) {
                HStack(spacing: 6) {
                    Image(systemName: vm.snapshot.desktopRunning ? "macwindow.on.rectangle" : "play.fill")
                        .font(.system(size: 11, weight: .semibold))
                    Text(vm.snapshot.desktopRunning ? "聚焦 Claude 桌面版" : "安全启动 Claude 桌面版")
                        .font(.system(size: 12, weight: .semibold))
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 8)
                .foregroundColor(.white)
                .background(
                    RoundedRectangle(cornerRadius: 9, style: .continuous)
                        .fill(vm.snapshot.isSafe ? Color.accentColor : Color.gray)
                )
            }
            .buttonStyle(.plain)

            iconActionButton(icon: vm.isRefreshing ? "hourglass" : "arrow.clockwise", help: "立即重新测速检测") {
                vm.refresh()
            }

            iconActionButton(icon: "doc.on.doc", help: "复制诊断报告") {
                vm.copyDiagnostics()
            }

            if vm.snapshot.desktopRunning {
                iconActionButton(icon: "stop.circle.fill", help: "紧急停止 Claude 桌面版", tint: Color(red: 0.96, green: 0.29, blue: 0.34)) {
                    vm.emergencyKillClaude()
                }
            }
        }
    }

    private func iconActionButton(icon: String, help: String, tint: Color = .primary, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: icon)
                .font(.system(size: 12.5, weight: .medium))
                .foregroundColor(tint)
                .frame(width: 34, height: 32)
                .background(RoundedRectangle(cornerRadius: 9, style: .continuous).fill(Color.primary.opacity(0.06)))
                .overlay(RoundedRectangle(cornerRadius: 9, style: .continuous).strokeBorder(Color.primary.opacity(0.09), lineWidth: 0.7))
        }
        .buttonStyle(.plain)
        .help(help)
    }

    // 6. Footer
    private var footerBar: some View {
        HStack {
            Text("Claude Safe Cage v2.0 · 巡检 \(vm.snapshot.checkedAt)")
                .font(.system(size: 10, design: .monospaced))
                .foregroundColor(.secondary.opacity(0.85))
            Spacer()
            Button("退出") { vm.quitApp() }
                .buttonStyle(.plain)
                .font(.system(size: 10.5, weight: .medium))
                .foregroundColor(.secondary)
        }
        .padding(.top, 2)
    }
}

struct VisualEffectView: NSViewRepresentable {
    let material: NSVisualEffectView.Material
    let blendingMode: NSVisualEffectView.BlendingMode

    func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.material = material
        view.blendingMode = blendingMode
        view.state = .active
        return view
    }

    func updateNSView(_ nsView: NSVisualEffectView, context: Context) {
        nsView.material = material
        nsView.blendingMode = blendingMode
    }
}

// MARK: - AppDelegate (NSPopover Menu Bar Host)

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem!
    private var popover: NSPopover!
    private let viewModel = GuardViewModel()

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let button = statusItem.button {
            button.title = "🟡 Guard"
            button.action = #selector(togglePopover(_:))
            button.target = self
        }

        let popover = NSPopover()
        popover.behavior = .transient
        popover.animates = true
        popover.contentViewController = NSHostingController(rootView: GuardPopoverView(vm: viewModel))
        self.popover = popover

        viewModel.onStatusChange = { [weak self] snap in
            guard let button = self?.statusItem.button else { return }
            if snap.isSafe {
                let msText = snap.proxyLatencyMs.map { " \($0)ms" } ?? ""
                button.title = "🟢 LA Safe\(msText)"
            } else {
                button.title = "🔴 IP 异常!"
            }
        }

        viewModel.startPolling()
    }

    @objc private func togglePopover(_ sender: AnyObject?) {
        guard let button = statusItem.button else { return }
        if popover.isShown {
            popover.performClose(sender)
        } else {
            viewModel.refresh()
            popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
            NSApp.activate(ignoringOtherApps: true)
        }
    }
}

MainActor.assumeIsolated {
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    let delegate = AppDelegate()
    app.delegate = delegate
    app.run()
}
