import Cocoa
import SwiftUI
import Combine
import Network

// MARK: - Rust Core Data Models

struct ChannelProbeModel: Codable, Sendable {
    let ip: String
    let latency_ms: Int?
    let colo: String?
    let loc: String?
    let tls: String?
    let http: String?
    let warp: String?
    let reachable: Bool
}

struct ApiLatencyModel: Codable, Sendable {
    let warm_rtt_ms: Int?
    let cold_connect_ms: Int?
    let jitter_ms: Int?
    let status_code: Int?
}

struct LocalDefenseModel: Codable, Sendable {
    let oauth_locked: Bool
    let original_hidden: Bool
    let original_app_exposed: Bool
    let sandbox_enabled: Bool
    let telemetry_disabled: Bool
    let desktop_pid: String?
    let desktop_proxy_bound: Bool
    let desktop_quic_disabled: Bool
    let desktop_webrtc_locked: Bool
    let unprotected_cli_pids: [String]
    let cli_ready: Bool
    let login_item_enabled: Bool
    let daily_patrol_enabled: Bool
}

struct TelemetrySnapshot: Codable, Sendable {
    let expected_ip: String
    let proxy_port: Int
    let target_tz: String
    let region_short: String
    let region_full: String
    let proxy: ChannelProbeModel
    let tun: ChannelProbeModel
    let claude_edge: ChannelProbeModel
    let api_latency: ApiLatencyModel
    let defenses: LocalDefenseModel
    let checked_at: String

    var proxyOK: Bool { !expected_ip.isEmpty && expected_ip != "未配置" && proxy.reachable && proxy.ip == expected_ip }
    var tunOK: Bool { !expected_ip.isEmpty && expected_ip != "未配置" && tun.reachable && tun.ip == expected_ip }
    var desktopRunning: Bool { defenses.desktop_pid != nil }
    var desktopUnprotected: Bool { desktopRunning && (!defenses.desktop_proxy_bound || !defenses.desktop_quic_disabled) }
    var hasUnprotectedCLI: Bool { !defenses.unprotected_cli_pids.isEmpty }

    var isConfirmedIPDrift: Bool {
        guard !expected_ip.isEmpty && expected_ip != "未配置" else { return false }
        let proxyDrifted = proxy.reachable && proxy.ip != expected_ip
        let tunDrifted = tun.reachable && tun.ip != expected_ip
        return proxyDrifted || tunDrifted
    }

    var isSafe: Bool { proxyOK && tunOK && !desktopUnprotected && !hasUnprotectedCLI }

    var defenseScore: Int {
        var s = 0
        if proxyOK { s += 1 }
        if tunOK { s += 1 }
        if defenses.oauth_locked { s += 1 }
        if defenses.original_hidden { s += 1 }
        if defenses.sandbox_enabled && defenses.telemetry_disabled { s += 1 }
        if !desktopUnprotected && !hasUnprotectedCLI && (defenses.cli_ready || desktopRunning) { s += 1 }
        if defenses.login_item_enabled { s += 1 }
        if defenses.daily_patrol_enabled { s += 1 }
        return s
    }

    static let initial = TelemetrySnapshot(
        expected_ip: "检测中...",
        proxy_port: 7897,
        target_tz: "America/Los_Angeles",
        region_short: "LA",
        region_full: "Los Angeles",
        proxy: ChannelProbeModel(ip: "...", latency_ms: nil, colo: nil, loc: nil, tls: nil, http: nil, warp: nil, reachable: false),
        tun: ChannelProbeModel(ip: "...", latency_ms: nil, colo: nil, loc: nil, tls: nil, http: nil, warp: nil, reachable: false),
        claude_edge: ChannelProbeModel(ip: "...", latency_ms: nil, colo: nil, loc: nil, tls: nil, http: nil, warp: nil, reachable: false),
        api_latency: ApiLatencyModel(warm_rtt_ms: nil, cold_connect_ms: nil, jitter_ms: nil, status_code: nil),
        defenses: LocalDefenseModel(
            oauth_locked: false,
            original_hidden: false,
            original_app_exposed: false,
            sandbox_enabled: false,
            telemetry_disabled: false,
            desktop_pid: nil,
            desktop_proxy_bound: true,
            desktop_quic_disabled: true,
            desktop_webrtc_locked: true,
            unprotected_cli_pids: [],
            cli_ready: false,
            login_item_enabled: false,
            daily_patrol_enabled: false
        ),
        checked_at: "--:--:--"
    )
}

struct RiskFactorModel: Codable, Sendable, Identifiable {
    var id: String { "\(title)-\(detail)" }
    let severity: String
    let title: String
    let detail: String
    let penalty: Int
}

struct DnsProbeModel: Codable, Sendable {
    let ip: String?
    let geo: String?
    let leaked: Bool
}

struct PurityReport: Codable, Sendable {
    let checked_at: String
    let exit_ip: String
    let expected_ip: String
    let claude_edge_ip: String
    let tun_ip: String
    let dual_channel_match: Bool
    let claude_edge_match: Bool
    let country_code: String
    let country: String
    let region: String
    let city: String
    let isp: String
    let asn: String
    let ip_type: String
    let is_residential: Bool
    let is_hosting: Bool
    let is_proxy_or_vpn: Bool
    let is_tor: Bool
    let is_broadcast: Bool
    let region_supported: Bool
    let ip_timezone: String?
    let target_timezone: String
    let timezone_aligned: Bool
    let claude_colo: String?
    let claude_tls: String?
    let claude_warp: String?
    let ippure_fraud_score: Int?
    let proxycheck_risk: Int?
    let combined_fraud_score: Int?
    let dns_proxy: DnsProbeModel
    let dns_tun: DnsProbeModel
    let dns_leak: Bool
    let ipv6_leak: Bool
    let ipv6_exposed_ip: String?
    let purity_score: Int
    let grade: String
    let verdict: String
    let factors: [RiskFactorModel]
}

struct PatrolReportModel: Codable, Sendable {
    let timestamp: String
    let passed: Bool
    let purity_score: Int
    let grade: String
    let alerts: [String]
    let auto_healed: [String]
    let purity: PurityReport
    let defenses: LocalDefenseModel
}

// MARK: - Rust Core Bridge (Single-Binary Zero-Fork-Overhead Engine)

private enum RustCoreBridge {
    static var coreBinaryPath: String {
        if let bundled = Bundle.main.executableURL?
            .deletingLastPathComponent()
            .appendingPathComponent("claude-shield-core").path,
           FileManager.default.isExecutableFile(atPath: bundled) {
            return bundled
        }
        let localBin = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".local/bin/claude-shield-core").path
        return localBin
    }

    static var cacheDir: URL {
        FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".config/claude-guard")
    }

    static func loadCachedTelemetry() -> TelemetrySnapshot? {
        let url = cacheDir.appendingPathComponent("last_telemetry.json")
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(TelemetrySnapshot.self, from: data)
    }

    static func loadCachedPurity() -> PurityReport? {
        let url = cacheDir.appendingPathComponent("last_purity.json")
        guard let data = try? Data(contentsOf: url) else { return nil }
        return try? JSONDecoder().decode(PurityReport.self, from: data)
    }

    static func runCore(_ args: [String]) -> Data? {
        let bin = coreBinaryPath
        guard FileManager.default.isExecutableFile(atPath: bin) else { return nil }
        let task = Process()
        task.executableURL = URL(fileURLWithPath: bin)
        task.arguments = args
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice
        do {
            try task.run()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            task.waitUntilExit()
            return data.isEmpty ? nil : data
        } catch {
            return nil
        }
    }

    static func fetchTelemetry() -> TelemetrySnapshot? {
        guard let data = runCore(["telemetry"]) else { return nil }
        return try? JSONDecoder().decode(TelemetrySnapshot.self, from: data)
    }

    static func fetchPurity() -> PurityReport? {
        guard let data = runCore(["purity", "--json"]) else { return nil }
        return try? JSONDecoder().decode(PurityReport.self, from: data)
    }

    static func runPatrol(notify: Bool, autoKill: Bool) -> PatrolReportModel? {
        var args = ["patrol", "--json"]
        if notify { args.append("--notify") }
        if !autoKill { args.append("--no-kill") }
        guard let data = runCore(args) else { return nil }
        return try? JSONDecoder().decode(PatrolReportModel.self, from: data)
    }

    static func hideOriginalApp() -> [String] {
        guard let data = runCore(["hide-original", "--json"]),
              let items = try? JSONDecoder().decode([String].self, from: data) else {
            return []
        }
        return items
    }

    static func toggleLaunchAgent(enabled: Bool) -> Bool {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let agentsDir = home.appendingPathComponent("Library/LaunchAgents")
        let plistURL = agentsDir.appendingPathComponent("com.local.claude.shield.radar.plist")
        let uid = getuid()

        if enabled {
            try? FileManager.default.createDirectory(at: agentsDir, withIntermediateDirectories: true)
            let plist = """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
              <key>Label</key><string>com.local.claude.shield.radar</string>
              <key>ProgramArguments</key>
              <array>
                <string>/Applications/Claude Shield.app/Contents/MacOS/ClaudeShield</string>
                <string>--radar-only</string>
              </array>
              <key>RunAtLoad</key><true/>
              <key>KeepAlive</key><false/>
              <key>ProcessType</key><string>Interactive</string>
            </dict>
            </plist>
            """
            do {
                try plist.write(to: plistURL, atomically: true, encoding: .utf8)
                let boot = Process()
                boot.executableURL = URL(fileURLWithPath: "/bin/launchctl")
                boot.arguments = ["bootstrap", "gui/\(uid)", plistURL.path]
                try? boot.run()
                boot.waitUntilExit()
                return true
            } catch {
                return false
            }
        } else {
            let bootout = Process()
            bootout.executableURL = URL(fileURLWithPath: "/bin/launchctl")
            bootout.arguments = ["bootout", "gui/\(uid)", plistURL.path]
            try? bootout.run()
            bootout.waitUntilExit()
            try? FileManager.default.removeItem(at: plistURL)
            return false
        }
    }
}

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
    @Published var isCheckingPurity: Bool = false
    @Published var isPatrolling: Bool = false
    @Published var pulse: Bool = false
    @Published var autoKillOnBreach: Bool {
        didSet { UserDefaults.standard.set(autoKillOnBreach, forKey: "autoKillOnBreach") }
    }
    @Published var loginAutoStart: Bool = false
    @Published var toastMessage: String?

    var onStatusChange: ((TelemetrySnapshot, PurityReport?) -> Void)?
    private var timer: Timer?
    private var purityTimer: Timer?
    private var pathMonitor: NWPathMonitor?
    private var lastNetworkStatus: NWPath.Status?
    private var consecutiveUnreachableCount = 0

    init() {
        self.autoKillOnBreach = UserDefaults.standard.object(forKey: "autoKillOnBreach") as? Bool ?? true
        // Instant startup: hydrate cached state in <5ms before first network probe completes
        let cachedSnap = RustCoreBridge.loadCachedTelemetry() ?? .initial
        self.snapshot = cachedSnap
        self.purity = RustCoreBridge.loadCachedPurity()
        self.loginAutoStart = cachedSnap.defenses.login_item_enabled
    }

    func startMonitoring() {
        refresh()

        // 15s lightweight Rust telemetry polling
        timer?.invalidate()
        timer = Timer.scheduledTimer(withTimeInterval: 15.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.refresh() }
        }

        // Delayed initial purity check (1.8s after launch for zero startup lag) + every 4h automatic re-audit
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.8) { [weak self] in
            self?.refreshPurity(silent: true)
        }
        purityTimer?.invalidate()
        purityTimer = Timer.scheduledTimer(withTimeInterval: 14400.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.runPatrolNow(silent: true) }
        }

        // Real-time macOS Sleep/Wake instant drift guard
        NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification,
            object: nil,
            queue: .main
        ) { [weak self] _ in
            Task { @MainActor in
                self?.consecutiveUnreachableCount = 0
                self?.refresh()
                DispatchQueue.main.asyncAfter(deadline: .now() + 3.0) {
                    self?.refresh()
                }
            }
        }

        // Real-time Network Interface / VPN Path Monitor (instant reaction to Wi-Fi/TUN switches)
        let monitor = NWPathMonitor()
        monitor.pathUpdateHandler = { [weak self] path in
            Task { @MainActor in
                guard let self = self else { return }
                let changed = self.lastNetworkStatus != nil && self.lastNetworkStatus != path.status
                self.lastNetworkStatus = path.status
                if changed {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
                        self.refresh()
                    }
                }
            }
        }
        monitor.start(queue: DispatchQueue.global(qos: .utility))
        self.pathMonitor = monitor
    }

    func refresh() {
        guard !isRefreshing else { return }
        isRefreshing = true
        Task.detached(priority: .userInitiated) {
            let result = RustCoreBridge.fetchTelemetry()
            await MainActor.run {
                self.isRefreshing = false
                guard let result = result else { return }
                self.snapshot = result
                self.loginAutoStart = result.defenses.login_item_enabled
                self.onStatusChange?(result, self.purity)

                // Auto-heal if /Applications/Claude.app reappeared (e.g. after auto-update)
                if result.defenses.original_app_exposed {
                    Task.detached(priority: .utility) {
                        _ = RustCoreBridge.hideOriginalApp()
                    }
                }

                if result.isSafe {
                    self.consecutiveUnreachableCount = 0
                    return
                }

                // Smart Fail-Closed Auto-Kill (Desktop + unprotected CLI)
                if self.autoKillOnBreach {
                    if result.desktopUnprotected {
                        self.emergencyKillClaude(reason: "检测到未绑定硬代理或未禁 QUIC 的 Claude 桌面版进程（#\(result.defenses.desktop_pid ?? "?")），已自动急停防裸连！")
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
                                self.refresh()
                            }
                        }
                    }
                }
            }
        }
    }

    func refreshPurity(silent: Bool = false) {
        guard !isCheckingPurity else { return }
        isCheckingPurity = true
        Task.detached(priority: .userInitiated) {
            let report = RustCoreBridge.fetchPurity()
            await MainActor.run {
                self.isCheckingPurity = false
                if let report = report {
                    self.purity = report
                    self.onStatusChange?(self.snapshot, report)
                    if !silent {
                        self.showToast("纯净度体检完成：\(report.purity_score) 分（\(report.grade) 级）")
                    }
                } else if !silent {
                    self.showToast("纯净度体检失败，请检查代理连通性")
                }
            }
        }
    }

    func runPatrolNow(silent: Bool = false) {
        guard !isPatrolling else { return }
        isPatrolling = true
        let autoKill = autoKillOnBreach
        Task.detached(priority: .utility) {
            let report = RustCoreBridge.runPatrol(notify: silent, autoKill: autoKill)
            await MainActor.run {
                self.isPatrolling = false
                if let report = report {
                    self.purity = report.purity
                    self.refresh()
                    if !silent {
                        if report.passed {
                            self.showToast("全链路巡检通过 · 纯净度 \(report.purity_score)/100 (\(report.grade))")
                        } else {
                            self.showToast("巡检发现 \(report.alerts.count) 项异常，请查看纯净度面板")
                        }
                    }
                }
            }
        }
    }

    func hideOriginalAppNow() {
        Task.detached(priority: .userInitiated) {
            let actions = RustCoreBridge.hideOriginalApp()
            await MainActor.run {
                self.showToast(actions.isEmpty ? "原版 Claude.app 已处于隐藏状态" : "已自动隐藏原版 Claude.app 图标")
                self.refresh()
            }
        }
    }

    func setLoginAutoStart(_ enabled: Bool) {
        let actual = RustCoreBridge.toggleLaunchAgent(enabled: enabled)
        loginAutoStart = actual
        showToast(actual ? "已开启开机自启保护雷达" : "已关闭开机自启雷达")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.4) { [weak self] in
            self?.refresh()
        }
    }

    func launchClaudeSafe() {
        let bin = RustCoreBridge.coreBinaryPath
        let task = Process()
        if FileManager.default.isExecutableFile(atPath: bin) {
            task.executableURL = URL(fileURLWithPath: bin)
            task.arguments = ["launch-desktop"]
        } else {
            let script = FileManager.default.homeDirectoryForCurrentUser
                .appendingPathComponent(".local/bin/claude-desktop-safe").path
            task.executableURL = URL(fileURLWithPath: "/bin/bash")
            task.arguments = [script]
        }
        try? task.run()
        showToast(snapshot.desktopRunning ? "已切换至 Claude 桌面版" : "正在 Rust 极速验真并启动 Claude...")
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.8) { [weak self] in
            self?.refresh()
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
            let safe = reason.replacingOccurrences(of: "\"", with: "'")
            let alert = Process()
            alert.executableURL = URL(fileURLWithPath: "/usr/bin/osascript")
            alert.arguments = ["-e", "display notification \"\(safe)\" with title \"Claude Shield 熔断急停\" sound name \"Sosumi\""]
            try? alert.run()
        }
        showToast("已执行紧急急停（Claude 进程已终止）")
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) { [weak self] in
            self?.refresh()
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

    func quitMonitorOnly() {
        NSApplication.shared.terminate(nil)
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

// MARK: - SwiftUI Commercial UI v3.0

struct ShieldPopoverView: View {
    @ObservedObject var vm: ShieldViewModel
    @Environment(\.colorScheme) private var colorScheme

    private var isDark: Bool { colorScheme == .dark }

    private var safeGreen: Color {
        isDark ? Color(red: 0.22, green: 0.84, blue: 0.60) : Color(red: 0.04, green: 0.54, blue: 0.36)
    }

    private var dangerRed: Color {
        isDark ? Color(red: 0.98, green: 0.42, blue: 0.44) : Color(red: 0.84, green: 0.16, blue: 0.16)
    }

    private var warnAmber: Color {
        isDark ? Color(red: 0.98, green: 0.72, blue: 0.24) : Color(red: 0.76, green: 0.38, blue: 0.04)
    }

    private var accentColor: Color {
        vm.snapshot.isSafe ? safeGreen : dangerRed
    }

    private var cardSurface: Color {
        isDark ? Color.white.opacity(0.075) : Color.white.opacity(0.80)
    }

    private var cardBorder: Color {
        isDark ? Color.white.opacity(0.11) : Color.black.opacity(0.08)
    }

    private var cardShadow: Color {
        isDark ? Color.clear : Color.black.opacity(0.05)
    }

    private var labelColor: Color {
        isDark ? Color.white.opacity(0.65) : Color.black.opacity(0.58)
    }

    private var brandGradient: LinearGradient {
        LinearGradient(
            colors: [
                Color(red: 0.86, green: 0.43, blue: 0.27),
                Color(red: 0.75, green: 0.31, blue: 0.18)
            ],
            startPoint: .top,
            endPoint: .bottom
        )
    }

    private func purityColor(_ score: Int) -> Color {
        if score >= 80 { return safeGreen }
        if score >= 60 { return warnAmber }
        return dangerRed
    }

    private func latencyColor(_ ms: Int) -> Color {
        if ms < 300 { return safeGreen }
        if ms < 600 { return warnAmber }
        return dangerRed
    }

    var body: some View {
        ZStack(alignment: .bottom) {
            VStack(spacing: 10) {
                headerCard
                segmentedTabBar

                if vm.selectedTab == .radar {
                    networkTelemetryRow
                    defenseMatrixGrid
                    togglesPanel
                    actionButtonsBar
                } else {
                    purityPanel
                }

                footerBar
            }
            .padding(14)

            if let toast = vm.toastMessage {
                Text(toast)
                    .font(.system(size: 11.5, weight: .medium))
                    .foregroundColor(.white)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(Capsule().fill(Color.black.opacity(0.86)))
                    .shadow(color: .black.opacity(0.25), radius: 6, y: 2)
                    .padding(.bottom, 10)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
        .frame(width: 400)
        .fixedSize(horizontal: false, vertical: true)
        .background(VisualEffectView(material: .popover, blendingMode: .behindWindow))
        .onAppear {
            withAnimation(.easeInOut(duration: 1.8).repeatForever(autoreverses: true)) {
                vm.pulse = true
            }
        }
    }

    // 1. Hero Status Card
    private var headerCard: some View {
        HStack(spacing: 11) {
            ZStack {
                Circle()
                    .fill(accentColor.opacity(vm.pulse ? (isDark ? 0.26 : 0.18) : (isDark ? 0.12 : 0.08)))
                    .frame(width: 44, height: 44)
                Circle()
                    .fill(
                        LinearGradient(
                            colors: [accentColor.opacity(0.95), accentColor.opacity(0.75)],
                            startPoint: .topLeading,
                            endPoint: .bottomTrailing
                        )
                    )
                    .frame(width: 34, height: 34)
                    .shadow(color: accentColor.opacity(0.32), radius: 5, y: 2)
                Image(systemName: vm.snapshot.isSafe ? "checkmark.shield.fill" : "exclamationmark.shield.fill")
                    .font(.system(size: 16, weight: .semibold))
                    .foregroundColor(.white)
            }

            VStack(alignment: .leading, spacing: 3.5) {
                HStack(spacing: 6) {
                    Text(vm.snapshot.isSafe ? "SHIELD ARMED" : "IP 异常预警")
                        .font(.system(size: 14, weight: .bold, design: .rounded))
                        .foregroundColor(.primary)

                    Text(vm.snapshot.isSafe ? "Rust 内核锁死" : "熔断就绪")
                        .font(.system(size: 9.5, weight: .semibold))
                        .foregroundColor(accentColor)
                        .padding(.horizontal, 6.5)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(accentColor.opacity(isDark ? 0.22 : 0.12)))
                        .overlay(Capsule().strokeBorder(accentColor.opacity(isDark ? 0.35 : 0.28), lineWidth: 0.6))
                }

                HStack(spacing: 5) {
                    Text(vm.snapshot.expected_ip)
                        .font(.system(size: 11.5, weight: .semibold, design: .monospaced))
                        .foregroundColor(.primary.opacity(0.86))
                    if let apiMs = vm.snapshot.api_latency.warm_rtt_ms {
                        let jitterText = vm.snapshot.api_latency.jitter_ms.map { " ±\($0)" } ?? ""
                        Text(verbatim: "· API \(apiMs)ms\(jitterText)")
                            .font(.system(size: 10.5, weight: .semibold, design: .monospaced))
                            .foregroundColor(latencyColor(apiMs))
                            .lineLimit(1)
                    } else if let colo = vm.snapshot.claude_edge.colo {
                        Text("· CF \(colo)")
                            .font(.system(size: 10.5, weight: .medium))
                            .foregroundColor(labelColor)
                    }
                }
            }

            Spacer(minLength: 4)

            if let p = vm.purity {
                let pc = purityColor(p.purity_score)
                Button(action: {
                    withAnimation(.easeInOut(duration: 0.18)) {
                        vm.selectedTab = vm.selectedTab == .radar ? .purity : .radar
                    }
                }) {
                    VStack(alignment: .trailing, spacing: 1) {
                        HStack(spacing: 3) {
                            Text("\(p.purity_score)")
                                .font(.system(size: 16, weight: .bold, design: .rounded))
                                .foregroundColor(pc)
                            Text(p.grade)
                                .font(.system(size: 10, weight: .heavy, design: .rounded))
                                .foregroundColor(.white)
                                .padding(.horizontal, 4.5)
                                .padding(.vertical, 1)
                                .background(RoundedRectangle(cornerRadius: 4, style: .continuous).fill(pc))
                        }
                        Text("IP 纯净度")
                            .font(.system(size: 9.5, weight: .medium))
                            .foregroundColor(labelColor)
                    }
                }
                .buttonStyle(.plain)
                .help("点击切换 IP 纯净度深度体检面板")
            } else {
                VStack(alignment: .trailing, spacing: 1) {
                    Text("\(vm.snapshot.defenseScore)/8")
                        .font(.system(size: 16, weight: .bold, design: .rounded))
                        .foregroundColor(accentColor)
                    Text("防线激活")
                        .font(.system(size: 9.5, weight: .medium))
                        .foregroundColor(labelColor)
                }
            }
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .fill(cardSurface)
                .overlay(
                    RoundedRectangle(cornerRadius: 12, style: .continuous)
                        .fill(
                            LinearGradient(
                                colors: [accentColor.opacity(isDark ? 0.16 : 0.09), Color.clear],
                                startPoint: .topLeading,
                                endPoint: .bottomTrailing
                            )
                        )
                )
        )
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(accentColor.opacity(isDark ? 0.38 : 0.30), lineWidth: 1)
        )
        .shadow(color: cardShadow, radius: 4, y: 1.5)
    }

    // 2. Segmented Tab Bar
    private var segmentedTabBar: some View {
        HStack(spacing: 4) {
            ForEach(ShieldTab.allCases, id: \.self) { tab in
                let active = vm.selectedTab == tab
                Button(action: {
                    withAnimation(.easeInOut(duration: 0.16)) {
                        vm.selectedTab = tab
                    }
                    if tab == .purity && vm.purity == nil {
                        vm.refreshPurity()
                    }
                }) {
                    HStack(spacing: 5) {
                        Image(systemName: tab == .radar ? "shield.checkered" : "sparkle.magnifyingglass")
                            .font(.system(size: 11, weight: .semibold))
                        Text(tab.rawValue)
                            .font(.system(size: 11.5, weight: .semibold))
                        if tab == .purity, let p = vm.purity {
                            Text("\(p.purity_score)分")
                                .font(.system(size: 9.5, weight: .bold, design: .monospaced))
                                .foregroundColor(active ? .white.opacity(0.95) : purityColor(p.purity_score))
                                .padding(.horizontal, 4.5)
                                .padding(.vertical, 1)
                                .background(Capsule().fill(active ? Color.white.opacity(0.22) : purityColor(p.purity_score).opacity(0.15)))
                        }
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 6)
                    .foregroundColor(active ? .white : .primary.opacity(0.75))
                    .background(
                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .fill(active ? AnyShapeStyle(brandGradient) : AnyShapeStyle(Color.clear))
                    )
                }
                .buttonStyle(.plain)
            }
        }
        .padding(3)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(cardSurface))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.7))
    }

    // 3. Dual-Channel + Claude Edge Telemetry
    private var networkTelemetryRow: some View {
        HStack(spacing: 8) {
            tunnelCard(
                title: "Claude 边缘 :\(vm.snapshot.proxy_port)",
                ip: vm.snapshot.proxy.ip,
                subtitle: vm.snapshot.claude_edge.colo.map { "CF \($0) · \(vm.snapshot.claude_edge.loc ?? "")" },
                latency: vm.snapshot.proxy.latency_ms,
                ok: vm.snapshot.proxyOK,
                icon: "arrow.triangle.branch"
            )
            tunnelCard(
                title: "TUN 默认路由",
                ip: vm.snapshot.tun.ip,
                subtitle: vm.snapshot.tun.colo.map { "CF \($0) · \(vm.snapshot.tun.loc ?? "")" },
                latency: vm.snapshot.tun.latency_ms,
                ok: vm.snapshot.tunOK,
                icon: "shield.lefthalf.filled"
            )
        }
    }

    private func tunnelCard(title: String, ip: String, subtitle: String?, latency: Int?, ok: Bool, icon: String) -> some View {
        let dotColor: Color = ok ? safeGreen : dangerRed
        return VStack(alignment: .leading, spacing: 5) {
            HStack(spacing: 5) {
                Circle().fill(dotColor).frame(width: 7, height: 7)
                Text(title)
                    .font(.system(size: 10.5, weight: .semibold))
                    .foregroundColor(labelColor)
                    .lineLimit(1)
                Spacer(minLength: 3)
                if let ms = latency {
                    let lc = latencyColor(ms)
                    Text(verbatim: "\(ms)ms")
                        .font(.system(size: 9.5, weight: .bold, design: .monospaced))
                        .foregroundColor(lc)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1)
                        .background(Capsule().fill(lc.opacity(isDark ? 0.18 : 0.10)))
                }
            }

            HStack(spacing: 5) {
                Image(systemName: icon)
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundColor(dotColor)
                Text(ip)
                    .font(.system(size: 12, weight: .semibold, design: .monospaced))
                    .foregroundColor(.primary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
            }

            if let sub = subtitle {
                Text(sub)
                    .font(.system(size: 9.5, weight: .medium, design: .monospaced))
                    .foregroundColor(labelColor)
                    .lineLimit(1)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8.5)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(cardSurface))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.8))
        .shadow(color: cardShadow, radius: 3, y: 1)
    }

    // 4. Hardened Defense Matrix (3x2)
    private var defenseMatrixGrid: some View {
        let d = vm.snapshot.defenses
        return VStack(spacing: 7) {
            HStack(spacing: 8) {
                let tzOK = vm.purity?.timezone_aligned ?? true
                metricTile(
                    icon: "globe.americas.fill",
                    title: "时区与语言",
                    value: "\(vm.snapshot.region_short) · en-US",
                    ok: tzOK
                )
                metricTile(
                    icon: "lock.shield.fill",
                    title: "OAuth 门禁",
                    value: d.oauth_locked ? "AdsPower-Only" : "未锁定",
                    ok: d.oauth_locked
                )
            }
            HStack(spacing: 8) {
                metricTile(
                    icon: "eye.slash.fill",
                    title: "原版隐藏仓",
                    value: d.original_hidden ? "已隐藏防误触" : (d.original_app_exposed ? "暴露在应用栏!" : "未安装原版"),
                    ok: d.original_hidden || !d.original_app_exposed
                )
                metricTile(
                    icon: "cube.transparent.fill",
                    title: "沙盒与去遥测",
                    value: (d.sandbox_enabled && d.telemetry_disabled) ? "Seatbelt + 静音" : "部分未启",
                    ok: d.sandbox_enabled && d.telemetry_disabled
                )
            }
            HStack(spacing: 8) {
                metricTile(
                    icon: "desktopcomputer",
                    title: "桌面版进程",
                    value: d.desktop_pid.map { vm.snapshot.desktopUnprotected ? "未绑定代理 · #\($0)" : "硬代理 · #\($0)" } ?? "待机未启动",
                    ok: !vm.snapshot.desktopUnprotected,
                    dim: !vm.snapshot.desktopRunning
                )
                metricTile(
                    icon: "terminal.fill",
                    title: "Claude Code",
                    value: vm.snapshot.hasUnprotectedCLI ? "发现未保护进程!" : (d.cli_ready ? "Rust 门禁就绪" : "待初始化"),
                    ok: d.cli_ready && !vm.snapshot.hasUnprotectedCLI
                )
            }
        }
    }

    private func metricTile(icon: String, title: String, value: String, ok: Bool, dim: Bool = false) -> some View {
        let tint: Color = dim ? labelColor : (ok ? safeGreen : warnAmber)
        return HStack(spacing: 8) {
            ZStack {
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill(tint.opacity(isDark ? 0.16 : 0.11))
                    .frame(width: 26, height: 26)
                Image(systemName: icon)
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundColor(tint)
            }

            VStack(alignment: .leading, spacing: 1.5) {
                Text(title)
                    .font(.system(size: 10, weight: .medium))
                    .foregroundColor(labelColor)
                Text(value)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(dim ? labelColor : .primary)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 9)
        .padding(.vertical, 7)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(cardSurface))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.7))
        .shadow(color: cardShadow, radius: 2.5, y: 1)
    }

    // 5. Protection Toggles (Auto-Kill + Login Auto-Start)
    private var togglesPanel: some View {
        VStack(spacing: 6) {
            compactToggleRow(
                icon: "bolt.shield.fill",
                title: "IP 漂移 & 唤醒自动急停",
                subtitle: "断网/切节点/唤醒瞬间自动终止裸连进程",
                isOn: vm.autoKillOnBreach
            ) {
                withAnimation(.spring(response: 0.24, dampingFraction: 0.78)) {
                    vm.autoKillOnBreach.toggle()
                }
            }

            compactToggleRow(
                icon: "sunrise.fill",
                title: "开机自启 & 每日巡检守护",
                subtitle: vm.snapshot.defenses.daily_patrol_enabled ? "登录静默启动雷达 · 每日自动纯净度体检" : "登录静默启动状态栏保护雷达",
                isOn: vm.loginAutoStart
            ) {
                withAnimation(.spring(response: 0.24, dampingFraction: 0.78)) {
                    vm.setLoginAutoStart(!vm.loginAutoStart)
                }
            }
        }
    }

    private func compactToggleRow(
        icon: String,
        title: String,
        subtitle: String,
        isOn: Bool,
        action: @escaping () -> Void
    ) -> some View {
        let activeTint = safeGreen
        return HStack(spacing: 8) {
            ZStack {
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill((isOn ? activeTint : labelColor).opacity(isDark ? 0.20 : 0.13))
                    .frame(width: 24, height: 24)
                Image(systemName: icon)
                    .font(.system(size: 11.5, weight: .semibold))
                    .foregroundColor(isOn ? activeTint : labelColor)
            }
            VStack(alignment: .leading, spacing: 1.5) {
                Text(title)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(.primary)
                Text(subtitle)
                    .font(.system(size: 9.5, weight: .medium))
                    .foregroundColor(labelColor)
                    .lineLimit(1)
            }
            Spacer(minLength: 6)

            Button(action: action) {
                ZStack(alignment: isOn ? .trailing : .leading) {
                    Capsule()
                        .fill(isOn ? activeTint : (isDark ? Color.white.opacity(0.18) : Color.black.opacity(0.16)))
                        .frame(width: 34, height: 19)
                    Circle()
                        .fill(Color.white)
                        .frame(width: 15, height: 15)
                        .shadow(color: Color.black.opacity(0.22), radius: 2, y: 1)
                        .padding(2)
                }
            }
            .buttonStyle(.plain)
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 7)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(cardSurface))
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(isOn ? activeTint.opacity(isDark ? 0.30 : 0.24) : cardBorder, lineWidth: 0.8)
        )
    }

    // 6. Purity Tab (ip.net.coffee/claude Grade Multi-Source Audit)
    private var purityPanel: some View {
        VStack(spacing: 9) {
            if let p = vm.purity {
                let pc = purityColor(p.purity_score)
                // Score Gauge & IP Meta
                HStack(spacing: 12) {
                    ZStack {
                        Circle()
                            .stroke(pc.opacity(0.18), lineWidth: 5.5)
                            .frame(width: 56, height: 56)
                        Circle()
                            .trim(from: 0, to: CGFloat(max(0, min(100, p.purity_score))) / 100.0)
                            .stroke(pc, style: StrokeStyle(lineWidth: 5.5, lineCap: .round))
                            .rotationEffect(.degrees(-90))
                            .frame(width: 56, height: 56)
                        VStack(spacing: 0) {
                            Text("\(p.purity_score)")
                                .font(.system(size: 16, weight: .bold, design: .rounded))
                                .foregroundColor(pc)
                            Text("\(p.grade)级")
                                .font(.system(size: 9, weight: .heavy))
                                .foregroundColor(labelColor)
                        }
                    }

                    VStack(alignment: .leading, spacing: 3) {
                        HStack(spacing: 5) {
                            Text(p.ip_type)
                                .font(.system(size: 12, weight: .bold))
                                .foregroundColor(.primary)
                            Text(p.country_code)
                                .font(.system(size: 9.5, weight: .bold, design: .monospaced))
                                .foregroundColor(p.region_supported ? safeGreen : dangerRed)
                                .padding(.horizontal, 5)
                                .padding(.vertical, 1)
                                .background(Capsule().fill((p.region_supported ? safeGreen : dangerRed).opacity(0.16)))
                        }
                        Text(p.verdict)
                            .font(.system(size: 10.5, weight: .semibold))
                            .foregroundColor(pc)
                        Text("\(p.asn) · \(p.isp)")
                            .font(.system(size: 10, weight: .medium))
                            .foregroundColor(labelColor)
                            .lineLimit(1)
                        Text("\(p.country) · \(p.city)  |  欺诈分: \(p.combined_fraud_score.map(String.init) ?? "-")")
                            .font(.system(size: 9.5, weight: .medium, design: .monospaced))
                            .foregroundColor(labelColor)
                            .lineLimit(1)
                    }
                    Spacer(minLength: 0)
                }
                .padding(10)
                .background(RoundedRectangle(cornerRadius: 11, style: .continuous).fill(cardSurface))
                .overlay(RoundedRectangle(cornerRadius: 11, style: .continuous).strokeBorder(pc.opacity(0.32), lineWidth: 0.9))

                // 4-Way Leak Guard Strip
                HStack(spacing: 6) {
                    leakPill(title: "Claude边", value: p.claude_edge_match ? (p.claude_colo ?? "一致") : "异常", ok: p.claude_edge_match)
                    leakPill(title: "DNS", value: p.dns_leak ? "泄露!" : "零泄露", ok: !p.dns_leak)
                    leakPill(title: "IPv6", value: p.ipv6_leak ? "泄露!" : "已封闭", ok: !p.ipv6_leak)
                    leakPill(title: "时区", value: p.timezone_aligned ? "已对齐" : "偏移!", ok: p.timezone_aligned)
                }

                // Itemized Risk Factors
                VStack(spacing: 5) {
                    ForEach(p.factors.prefix(6)) { f in
                        HStack(alignment: .top, spacing: 7) {
                            Image(systemName: f.severity == "good" ? "checkmark.circle.fill" : (f.severity == "warn" ? "exclamationmark.triangle.fill" : "xmark.octagon.fill"))
                                .font(.system(size: 11, weight: .semibold))
                                .foregroundColor(f.severity == "good" ? safeGreen : (f.severity == "warn" ? warnAmber : dangerRed))
                                .padding(.top, 1)
                            VStack(alignment: .leading, spacing: 1) {
                                HStack {
                                    Text(f.title)
                                        .font(.system(size: 10.5, weight: .semibold))
                                        .foregroundColor(.primary)
                                    Spacer()
                                    if f.penalty < 0 {
                                        Text("\(f.penalty)")
                                            .font(.system(size: 9.5, weight: .bold, design: .monospaced))
                                            .foregroundColor(f.severity == "warn" ? warnAmber : dangerRed)
                                    }
                                }
                                Text(f.detail)
                                    .font(.system(size: 9.5, weight: .medium))
                                    .foregroundColor(labelColor)
                                    .lineLimit(2)
                            }
                        }
                        .padding(.horizontal, 9)
                        .padding(.vertical, 5.5)
                        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(cardSurface))
                        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.6))
                    }
                }
            } else {
                VStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("正在执行多源 IP 纯净度与 DNS/IPv6 泄露体检...")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(labelColor)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 28)
                .background(RoundedRectangle(cornerRadius: 11, style: .continuous).fill(cardSurface))
            }

            HStack(spacing: 8) {
                secondaryActionButton(
                    icon: "sparkle.magnifyingglass",
                    title: vm.isCheckingPurity ? "体检中..." : "深度复测纯净度",
                    isLoading: vm.isCheckingPurity,
                    help: "调用多源 IP 情报库 + claude.ai 边缘 + DNS/IPv6 泄露全量复测"
                ) {
                    vm.refreshPurity()
                }
                secondaryActionButton(
                    icon: "checkmark.shield",
                    title: vm.isPatrolling ? "巡检中..." : "立即执行巡检",
                    isLoading: vm.isPatrolling,
                    help: "执行每日级全链路巡检并自动修复暴露的原版 App"
                ) {
                    vm.runPatrolNow()
                }
                if vm.snapshot.defenses.original_app_exposed {
                    secondaryActionButton(
                        icon: "eye.slash.fill",
                        title: "隐藏原版",
                        tint: warnAmber,
                        help: "立即隐藏暴露在 /Applications 的原版 Claude.app"
                    ) {
                        vm.hideOriginalAppNow()
                    }
                }
            }
        }
    }

    private func leakPill(title: String, value: String, ok: Bool) -> some View {
        let color = ok ? safeGreen : dangerRed
        return VStack(spacing: 2) {
            Text(title)
                .font(.system(size: 9.5, weight: .medium))
                .foregroundColor(labelColor)
            Text(value)
                .font(.system(size: 10.5, weight: .bold, design: .monospaced))
                .foregroundColor(color)
                .lineLimit(1)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 6)
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(color.opacity(isDark ? 0.13 : 0.08)))
        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(color.opacity(0.28), lineWidth: 0.7))
    }

    // 7. Primary & Secondary Actions
    private var actionButtonsBar: some View {
        VStack(spacing: 7) {
            Button(action: { vm.launchClaudeSafe() }) {
                HStack(spacing: 6) {
                    Image(systemName: vm.snapshot.desktopRunning ? "macwindow.on.rectangle" : "play.fill")
                        .font(.system(size: 11.5, weight: .semibold))
                    Text(vm.snapshot.desktopRunning ? "聚焦 Claude 桌面版" : "安全启动 Claude 桌面版")
                        .font(.system(size: 12.5, weight: .semibold))
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 9)
                .foregroundColor(.white)
                .background(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill(vm.snapshot.isSafe ? AnyShapeStyle(brandGradient) : AnyShapeStyle(Color.gray.opacity(0.65)))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .strokeBorder(Color.white.opacity(0.18), lineWidth: 0.7)
                )
                .shadow(color: vm.snapshot.isSafe ? Color(red: 0.75, green: 0.31, blue: 0.18).opacity(0.28) : .clear, radius: 4, y: 2)
            }
            .buttonStyle(.plain)

            HStack(spacing: 7) {
                secondaryActionButton(
                    icon: "arrow.clockwise",
                    title: vm.isRefreshing ? "测速中" : "重新测速",
                    isLoading: vm.isRefreshing,
                    help: "使用 Rust 内核重新测量三点出口 IP 与 Anthropic API 真实 1-RTT"
                ) {
                    vm.refresh()
                }

                secondaryActionButton(
                    icon: "checkmark.shield",
                    title: vm.isPatrolling ? "巡检中" : "立即巡检",
                    isLoading: vm.isPatrolling,
                    help: "执行全链路安全与纯净度巡检"
                ) {
                    vm.runPatrolNow()
                }

                secondaryActionButton(
                    icon: "camera.viewfinder",
                    title: "截图诊断",
                    help: "生成 2x Retina 诊断卡片并复制到剪贴板"
                ) {
                    copySnapshotImage()
                }

                if vm.snapshot.desktopRunning {
                    secondaryActionButton(
                        icon: "stop.circle.fill",
                        title: "急停",
                        tint: dangerRed,
                        isDestructive: true,
                        help: "立即强制终止 Claude 桌面版进程"
                    ) {
                        vm.emergencyKillClaude()
                    }
                }
            }
        }
    }

    private func secondaryActionButton(
        icon: String,
        title: String,
        tint: Color = .primary,
        isLoading: Bool = false,
        isDestructive: Bool = false,
        help: String,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            HStack(spacing: 4) {
                if isLoading {
                    ProgressView()
                        .controlSize(.mini)
                        .scaleEffect(0.82)
                        .frame(width: 11, height: 11)
                } else {
                    Image(systemName: icon)
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(tint)
                }
                Text(title)
                    .font(.system(size: 10.5, weight: .semibold))
                    .foregroundColor(isDestructive ? dangerRed : .primary)
                    .lineLimit(1)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 7)
            .background(
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(isDestructive ? dangerRed.opacity(isDark ? 0.16 : 0.09) : cardSurface)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .strokeBorder(isDestructive ? dangerRed.opacity(isDark ? 0.35 : 0.25) : cardBorder, lineWidth: 0.8)
            )
            .shadow(color: cardShadow, radius: 2, y: 1)
        }
        .buttonStyle(.plain)
        .disabled(isLoading)
        .help(help)
    }

    // 8. Footer
    private var footerBar: some View {
        HStack {
            Text("Claude Shield v3.0 Rust · 巡检 \(vm.snapshot.checked_at)")
                .font(.system(size: 10, weight: .medium, design: .monospaced))
                .foregroundColor(labelColor)
            Spacer()
            Button("退出监控") { vm.quitMonitorOnly() }
                .buttonStyle(.plain)
                .font(.system(size: 10.5, weight: .semibold))
                .foregroundColor(labelColor)
                .help("仅关闭状态栏雷达，Rust CLI 门禁、每日巡检与沙盒防护持续生效")
        }
        .padding(.top, 1)
    }

    // Exportable 2x Retina Diagnostic Card
    private var diagnosticShareCard: some View {
        VStack(spacing: 10) {
            headerCard
            networkTelemetryRow
            if let p = vm.purity {
                HStack(spacing: 6) {
                    leakPill(title: "纯净度", value: "\(p.purity_score) (\(p.grade))", ok: p.purity_score >= 78)
                    leakPill(title: "IP属性", value: p.ip_type, ok: !p.is_hosting && !p.is_proxy_or_vpn)
                    leakPill(title: "DNS", value: p.dns_leak ? "泄露" : "安全", ok: !p.dns_leak)
                    leakPill(title: "IPv6", value: p.ipv6_leak ? "泄露" : "封闭", ok: !p.ipv6_leak)
                }
            }
            defenseMatrixGrid
            HStack {
                Text("Claude Shield v3.0 Rust · \(vm.snapshot.checked_at)")
                    .font(.system(size: 10, weight: .medium, design: .monospaced))
                    .foregroundColor(labelColor)
                Spacer()
                Text(vm.autoKillOnBreach ? "Fail-Closed + 唤醒防护已启" : "Fail-Closed 未启")
                    .font(.system(size: 9.5, weight: .semibold))
                    .foregroundColor(vm.autoKillOnBreach ? safeGreen : labelColor)
            }
        }
        .padding(16)
        .frame(width: 404)
        .background(
            RoundedRectangle(cornerRadius: 16, style: .continuous)
                .fill(
                    LinearGradient(
                        colors: isDark
                            ? [Color(red: 0.13, green: 0.14, blue: 0.16), Color(red: 0.10, green: 0.11, blue: 0.13)]
                            : [Color(red: 0.96, green: 0.96, blue: 0.95), Color(red: 0.92, green: 0.93, blue: 0.92)],
                        startPoint: .topLeading,
                        endPoint: .bottomTrailing
                    )
                )
        )
        .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(cardBorder, lineWidth: 1))
        .environment(\.colorScheme, colorScheme)
    }

    private func copySnapshotImage() {
        if #available(macOS 13.0, *) {
            let renderer = ImageRenderer(content: diagnosticShareCard)
            renderer.scale = 2.0
            if let cgImage = renderer.cgImage {
                let rep = NSBitmapImageRep(cgImage: cgImage)
                let png = rep.representation(using: .png, properties: [:])
                vm.copyDiagnosticScreenshot(png)
                return
            }
        }
        vm.copyDiagnosticScreenshot(nil)
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

// MARK: - AppDelegate (Unified Safe Launcher + Menu Bar Radar)

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    private static let reopenNotification = Notification.Name("com.local.claude.shield.launchDesktop")

    private var statusItem: NSStatusItem!
    private var popover: NSPopover!
    private var hostingController: NSHostingController<ShieldPopoverView>!
    private let viewModel = ShieldViewModel()
    private var hasCompletedInitialLaunch = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        let radarOnly = CommandLine.arguments.contains("--radar-only")

        // Single-instance guard
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
            button.title = "🟡 Shield"
            button.action = #selector(togglePopover(_:))
            button.target = self
        }

        let hc = NSHostingController(rootView: ShieldPopoverView(vm: viewModel))
        if #available(macOS 13.0, *) {
            hc.sizingOptions = .preferredContentSize
        }
        self.hostingController = hc

        let popover = NSPopover()
        popover.behavior = .transient
        popover.animates = true
        popover.contentViewController = hc
        self.popover = popover
        updatePopoverSize()

        viewModel.onStatusChange = { [weak self] snap, purity in
            guard let self = self, let button = self.statusItem.button else { return }
            if snap.isSafe {
                let bestMs = snap.api_latency.warm_rtt_ms ?? snap.proxy.latency_ms
                let msText = bestMs.map { " \($0)ms" } ?? ""
                let gradeText = purity.map { " · \($0.grade)" } ?? ""
                button.title = "🟢 \(snap.region_short)\(msText)\(gradeText)"
            } else {
                if snap.desktopUnprotected || snap.hasUnprotectedCLI {
                    button.title = "🔴 进程未受保护!"
                } else {
                    button.title = "🔴 IP 异常!"
                }
            }
            if self.popover.isShown {
                self.updatePopoverSize()
            }
        }

        viewModel.startMonitoring()
        hasCompletedInitialLaunch = true

        if !radarOnly {
            viewModel.launchClaudeSafe()
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if hasCompletedInitialLaunch {
            viewModel.launchClaudeSafe()
        }
        return false
    }

    @objc private func handleExternalLaunchRequest() {
        viewModel.launchClaudeSafe()
    }

    private func updatePopoverSize() {
        hostingController.view.layoutSubtreeIfNeeded()
        let fitting = hostingController.view.fittingSize
        if fitting.width > 0 && fitting.height > 0 {
            popover.contentSize = NSSize(width: 400, height: ceil(fitting.height))
        }
    }

    @objc private func togglePopover(_ sender: AnyObject?) {
        guard let button = statusItem.button else { return }
        if popover.isShown {
            popover.performClose(sender)
        } else {
            updatePopoverSize()
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
