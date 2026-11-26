import Cocoa
import SwiftUI
import Combine

// MARK: - Region Helper

private func tzDisplayNames(for tz: String) -> (short: String, full: String) {
    let cityRaw = tz.split(separator: "/").last.map(String.init) ?? tz
    let full = cityRaw.replacingOccurrences(of: "_", with: " ")
    let shortMap: [String: String] = [
        "Los Angeles": "LA",
        "New York": "NY",
        "San Francisco": "SF",
        "Chicago": "CHI",
        "Singapore": "SG",
        "Hong Kong": "HK",
        "Tokyo": "TYO",
        "London": "LDN",
        "Frankfurt": "FRA",
        "Amsterdam": "AMS",
        "Seattle": "SEA",
        "Dallas": "DAL",
        "Phoenix": "PHX",
        "Denver": "DEN"
    ]
    let short = shortMap[full] ?? String(full.prefix(6))
    return (short, full)
}

// MARK: - Data Model

struct TelemetrySnapshot: Sendable {
    let expectedIP: String
    let proxyPort: String
    let targetTZ: String
    let proxyIP: String
    let proxyLatencyMs: Int?
    let proxyColo: String?
    let tunIP: String
    let tunLatencyMs: Int?
    let apiLatencyMs: Int?
    let oauthLocked: Bool
    let originalHidden: Bool
    let sandboxEnabled: Bool
    let desktopPID: String?
    let desktopProxyBound: Bool
    let cliReady: Bool
    let checkedAt: String

    var regionShort: String { tzDisplayNames(for: targetTZ).short }
    var regionFull: String { tzDisplayNames(for: targetTZ).full }

    var proxyOK: Bool { !expectedIP.isEmpty && expectedIP != "未配置" && proxyIP == expectedIP }
    var tunOK: Bool { !expectedIP.isEmpty && expectedIP != "未配置" && tunIP == expectedIP }
    var desktopRunning: Bool { desktopPID != nil }
    var desktopUnprotected: Bool { desktopRunning && !desktopProxyBound }

    /// True if either channel returned a real IP that does NOT match expectedIP (definite node drift / leak)
    var isConfirmedIPDrift: Bool {
        guard !expectedIP.isEmpty && expectedIP != "未配置" else { return false }
        let proxyDrifted = !proxyIP.isEmpty && proxyIP != "..." && proxyIP != "无法连通" && proxyIP != expectedIP
        let tunDrifted = !tunIP.isEmpty && tunIP != "..." && tunIP != "无法连通" && tunIP != expectedIP
        return proxyDrifted || tunDrifted
    }

    var isSafe: Bool { proxyOK && tunOK && !desktopUnprotected }
    var defenseScore: Int {
        var s = 0
        if proxyOK { s += 1 }
        if tunOK { s += 1 }
        if oauthLocked { s += 1 }
        if originalHidden { s += 1 }
        if sandboxEnabled { s += 1 }
        if !desktopUnprotected && (cliReady || desktopRunning) { s += 1 }
        return s
    }

    static let initial = TelemetrySnapshot(
        expectedIP: "检测中...",
        proxyPort: "7897",
        targetTZ: "America/Los_Angeles",
        proxyIP: "...",
        proxyLatencyMs: nil,
        proxyColo: nil,
        tunIP: "...",
        tunLatencyMs: nil,
        apiLatencyMs: nil,
        oauthLocked: false,
        originalHidden: false,
        sandboxEnabled: false,
        desktopPID: nil,
        desktopProxyBound: true,
        cliReady: false,
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

    /// Fresh-route IP check + 2nd keep-alive HTTP/2 request for exact 1-RTT wire latency (zero TLS/handshake inflation, zero stale-socket blindness)
    static func fetchIPAndExactRTT(viaProxy: Bool, port: String) -> (ip: String, ms: Int?, colo: String?) {
        let proxyArgs: [String] = viaProxy ? ["-x", "http://127.0.0.1:\(port)"] : ["--noproxy", "*"]

        // Primary: Cloudflare trace (2-step keep-alive on a fresh connection: req1 verifies fresh route IP + colo, req2 measures pure 1-RTT)
        let traceArgs = ["-4", "-fsS", "--http2", "--max-time", "4"] + proxyArgs + [
            "https://1.1.1.1/cdn-cgi/trace",
            "--next",
            "-4", "-fsS", "--http2", "--max-time", "3", "-I", "-o", "/dev/null",
            "-w", "\n__EXACT_RTT__:%{time_starttransfer}"
        ] + proxyArgs + ["https://1.1.1.1/cdn-cgi/trace"]

        let traceRes = run("/usr/bin/curl", traceArgs)
        if !traceRes.output.isEmpty {
            let parts = traceRes.output.components(separatedBy: "\n__EXACT_RTT__:")
            let body = parts.first ?? ""
            let ip = body
                .split(separator: "\n")
                .first(where: { $0.hasPrefix("ip=") })
                .map { String($0.dropFirst(3)).trimmingCharacters(in: .whitespacesAndNewlines) } ?? ""
            let colo = body
                .split(separator: "\n")
                .first(where: { $0.hasPrefix("colo=") })
                .map { String($0.dropFirst(5)).trimmingCharacters(in: .whitespacesAndNewlines) }

            if !ip.isEmpty, ip.count <= 45, !ip.contains(" ") {
                var rttMs: Int? = nil
                if parts.count > 1, let sec = Double(parts[1].trimmingCharacters(in: .whitespacesAndNewlines)), sec > 0 {
                    rttMs = max(1, Int((sec * 1000.0).rounded()))
                }
                return (ip, rttMs, colo)
            }
        }

        // Fallbacks: api.ipify.org, ifconfig.me
        for url in ["https://api.ipify.org", "https://ifconfig.me/ip"] {
            let args = ["-4", "-fsS", "--max-time", "4", "-w", "\n__TIMING__:%{time_appconnect} %{time_starttransfer} %{time_total}"] + proxyArgs + [url]
            let res = run("/usr/bin/curl", args)
            guard !res.output.isEmpty else { continue }
            let parts = res.output.components(separatedBy: "\n__TIMING__:")
            let ip = parts.first?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            guard !ip.isEmpty, ip.count <= 45, !ip.contains(" ") else { continue }
            var rttMs: Int? = nil
            if parts.count > 1 {
                let nums = parts[1].trimmingCharacters(in: .whitespacesAndNewlines).split(separator: " ").compactMap { Double($0) }
                if nums.count == 3 {
                    let delta = (nums[0] > 0 && nums[1] > nums[0]) ? (nums[1] - nums[0]) : nums[2]
                    if delta > 0 { rttMs = max(1, Int((delta * 1000.0).rounded())) }
                }
            }
            return (ip, rttMs, nil)
        }
        return ("无法连通", nil, nil)
    }

    /// Measure exact 1-RTT wire latency directly to Anthropic API (api.anthropic.com) via 2-step HTTP/2 keep-alive
    static func fetchAnthropicAPIRTT(port: String) -> Int? {
        let proxyArgs = ["-x", "http://127.0.0.1:\(port)"]
        let args = ["-4", "-sS", "--http2", "--max-time", "4", "-I", "-o", "/dev/null"] + proxyArgs + [
            "https://api.anthropic.com",
            "--next",
            "-4", "-sS", "--http2", "--max-time", "3", "-I", "-o", "/dev/null",
            "-w", "%{time_starttransfer}"
        ] + proxyArgs + ["https://api.anthropic.com"]

        let res = run("/usr/bin/curl", args)
        if let sec = Double(res.output), sec > 0 {
            return max(1, Int((sec * 1000.0).rounded()))
        }
        return nil
    }

    static func collect() -> TelemetrySnapshot {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let fm = FileManager.default
        let cfgDir = home.appendingPathComponent(".config/claude-guard")

        let expectedIP = (try? String(contentsOf: cfgDir.appendingPathComponent("expected_ip"), encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? "未配置"

        let rawPort = (try? String(contentsOf: cfgDir.appendingPathComponent("proxy_port"), encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let proxyPort = rawPort.isEmpty ? "7897" : rawPort

        let rawTZ = (try? String(contentsOf: cfgDir.appendingPathComponent("target_tz"), encoding: .utf8))?
            .trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        let targetTZ = rawTZ.isEmpty ? "America/Los_Angeles" : rawTZ

        // Run Proxy IP+RTT, TUN IP+RTT, and real Anthropic API 1-RTT in parallel
        let group = DispatchGroup()
        var proxyRes: (ip: String, ms: Int?, colo: String?) = ("无法连通", nil, nil)
        var tunRes: (ip: String, ms: Int?, colo: String?) = ("无法连通", nil, nil)
        var apiRtt: Int? = nil

        group.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            proxyRes = fetchIPAndExactRTT(viaProxy: true, port: proxyPort)
            group.leave()
        }
        group.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            tunRes = fetchIPAndExactRTT(viaProxy: false, port: proxyPort)
            group.leave()
        }
        group.enter()
        DispatchQueue.global(qos: .userInitiated).async {
            apiRtt = fetchAnthropicAPIRTT(port: proxyPort)
            group.leave()
        }
        group.wait()

        let oauthPath = home.appendingPathComponent(".local/lib/claude-guard-bin/open").path
        let oauthLocked = fm.isExecutableFile(atPath: oauthPath)

        let origInApps = fm.fileExists(atPath: "/Applications/Claude.app")
        let origInVault = fm.fileExists(atPath: home.appendingPathComponent(".local/apps/Claude.app").path)
        let originalHidden = !origInApps && origInVault

        let settingsPath = home.appendingPathComponent(".claude/settings.json").path
        let settingsText = (try? String(contentsOfFile: settingsPath, encoding: .utf8)) ?? ""
        let sandboxEnabled = settingsText.contains("\"enabled\": true") || settingsText.contains("\"enabled\":true")

        // Process-level proxy-binding audit for running Claude Desktop
        let pgrepRes = run("/usr/bin/pgrep", ["-x", "Claude"])
        let desktopPID = pgrepRes.output.split(separator: "\n").first.map(String.init)
        var desktopProxyBound = true
        if let pid = desktopPID {
            let psRes = run("/bin/ps", ["-p", pid, "-o", "args="])
            desktopProxyBound = psRes.output.contains("--proxy-server=http://127.0.0.1:\(proxyPort)")
        }

        let cliReady = fm.isExecutableFile(atPath: home.appendingPathComponent(".local/bin/claude").path)

        let df = DateFormatter()
        df.dateFormat = "HH:mm:ss"

        return TelemetrySnapshot(
            expectedIP: expectedIP,
            proxyPort: proxyPort,
            targetTZ: targetTZ,
            proxyIP: proxyRes.ip,
            proxyLatencyMs: proxyRes.ms,
            proxyColo: proxyRes.colo,
            tunIP: tunRes.ip,
            tunLatencyMs: tunRes.ms,
            apiLatencyMs: apiRtt,
            oauthLocked: oauthLocked,
            originalHidden: originalHidden,
            sandboxEnabled: sandboxEnabled,
            desktopPID: desktopPID,
            desktopProxyBound: desktopProxyBound,
            cliReady: cliReady,
            checkedAt: df.string(from: Date())
        )
    }
}

// MARK: - ViewModel

@MainActor
final class ShieldViewModel: ObservableObject {
    @Published var snapshot: TelemetrySnapshot = .initial
    @Published var isRefreshing: Bool = false
    @Published var pulse: Bool = false
    @Published var autoKillOnBreach: Bool {
        didSet { UserDefaults.standard.set(autoKillOnBreach, forKey: "autoKillOnBreach") }
    }
    @Published var toastMessage: String?

    var onStatusChange: ((TelemetrySnapshot) -> Void)?
    private var timer: Timer?
    private var consecutiveUnreachableCount = 0

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

                if result.isSafe {
                    self.consecutiveUnreachableCount = 0
                    return
                }

                // Smart Fail-Closed Auto-Kill:
                // 1) Definite IP drift or unprotected Claude process -> instant 0s kill
                // 2) Transient unreachable/timeout -> 1 immediate fast re-check before killing (zero false positives)
                if self.autoKillOnBreach && result.desktopRunning {
                    if result.desktopUnprotected {
                        self.emergencyKillClaude(reason: "检测到未绑定硬代理的 Claude 桌面版进程（#\(result.desktopPID ?? "?")），已自动急停防裸连！")
                    } else if result.isConfirmedIPDrift {
                        self.emergencyKillClaude(reason: "检测到出口 IP 漂移（代理: \(result.proxyIP) / TUN: \(result.tunIP)），已自动急停 Claude 桌面版以防裸连！")
                    } else {
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

    func launchClaudeSafe() {
        let script = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".local/bin/claude-desktop-safe").path
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/bash")
        task.arguments = [script]
        try? task.run()
        showToast(snapshot.desktopRunning ? "已切换至 Claude 桌面版" : "正在验真并启动 Claude 桌面版...")
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
            alert.arguments = ["-e", "display notification \"\(reason)\" with title \"Claude Shield 熔断急停\" sound name \"Sosumi\""]
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
        [Claude Shield v2.2 Telemetry · \(s.checkedAt)]
        Status: \(s.isSafe ? "ARMED (SAFE)" : "BREACH WARNING")
        Whitelist IP: \(s.expectedIP) (\(s.targetTZ)\(s.proxyColo.map { " · \($0)" } ?? ""))
        Anthropic API 1-RTT: \(s.apiLatencyMs.map { "\($0)ms" } ?? "N/A")
        Proxy (127.0.0.1:\(s.proxyPort)): \(s.proxyIP) (\(s.proxyLatencyMs.map { "\($0)ms" } ?? "N/A"))
        TUN Route: \(s.tunIP) (\(s.tunLatencyMs.map { "\($0)ms" } ?? "N/A"))
        OAuth Lock: \(s.oauthLocked ? "AdsPower-Only" : "Unlocked")
        Original App Vault: \(s.originalHidden ? "Hidden" : "Exposed")
        macOS Seatbelt Sandbox: \(s.sandboxEnabled ? "Enabled" : "Disabled")
        Desktop Process: \(s.desktopPID.map { s.desktopProxyBound ? "Protected (PID \($0))" : "UNPROTECTED (PID \($0))" } ?? "Idle")
        CLI Guard: \(s.cliReady ? "Armed" : "Not Installed")
        """
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(report, forType: .string)
        showToast("诊断快照已复制到剪贴板")
    }

    func quitMonitorOnly() {
        // Quitting the menu bar radar never disables hard-bound proxy, CLI gate, OAuth lock, or Seatbelt sandbox.
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
        isDark ? Color.white.opacity(0.075) : Color.white.opacity(0.78)
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

    var body: some View {
        ZStack(alignment: .bottom) {
            VStack(spacing: 11) {
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
        .frame(width: 384)
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
        HStack(spacing: 12) {
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

                    Text(vm.snapshot.isSafe ? "全链路锁死" : "熔断就绪")
                        .font(.system(size: 10, weight: .semibold))
                        .foregroundColor(accentColor)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 2)
                        .background(Capsule().fill(accentColor.opacity(isDark ? 0.22 : 0.12)))
                        .overlay(Capsule().strokeBorder(accentColor.opacity(isDark ? 0.35 : 0.28), lineWidth: 0.6))
                }

                HStack(spacing: 5) {
                    Image(systemName: "network")
                        .font(.system(size: 10.5, weight: .medium))
                        .foregroundColor(labelColor)
                    Text(vm.snapshot.expectedIP)
                        .font(.system(size: 11.5, weight: .semibold, design: .monospaced))
                        .foregroundColor(.primary.opacity(0.84))
                    if let apiMs = vm.snapshot.apiLatencyMs {
                        Text(verbatim: "· API \(apiMs)ms")
                            .font(.system(size: 10.5, weight: .semibold, design: .monospaced))
                            .foregroundColor(latencyColor(apiMs))
                            .lineLimit(1)
                    } else {
                        Text("· \(vm.snapshot.proxyColo ?? vm.snapshot.regionFull)")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundColor(labelColor)
                            .lineLimit(1)
                    }
                }
            }

            Spacer(minLength: 4)

            VStack(alignment: .trailing, spacing: 1) {
                Text("\(vm.snapshot.defenseScore)/6")
                    .font(.system(size: 16, weight: .bold, design: .rounded))
                    .foregroundColor(accentColor)
                Text("防线激活")
                    .font(.system(size: 10, weight: .medium))
                    .foregroundColor(labelColor)
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

    // 2. Dual-Channel Network Telemetry
    private var networkTelemetryRow: some View {
        HStack(spacing: 8) {
            tunnelCard(
                title: "代理 :\(vm.snapshot.proxyPort)",
                ip: vm.snapshot.proxyIP,
                latency: vm.snapshot.proxyLatencyMs,
                ok: vm.snapshot.proxyOK,
                icon: "arrow.triangle.branch"
            )
            tunnelCard(
                title: "TUN 路由",
                ip: vm.snapshot.tunIP,
                latency: vm.snapshot.tunLatencyMs,
                ok: vm.snapshot.tunOK,
                icon: "shield.lefthalf.filled"
            )
        }
    }

    private func latencyColor(_ ms: Int) -> Color {
        if ms < 350 { return safeGreen }
        if ms < 700 { return warnAmber }
        return dangerRed
    }

    private func tunnelCard(title: String, ip: String, latency: Int?, ok: Bool, icon: String) -> some View {
        let dotColor: Color = ok ? safeGreen : dangerRed
        return VStack(alignment: .leading, spacing: 6) {
            HStack(spacing: 5) {
                Circle()
                    .fill(dotColor)
                    .frame(width: 7, height: 7)
                Text(title)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(labelColor)
                    .lineLimit(1)
                    .fixedSize(horizontal: true, vertical: false)
                Spacer(minLength: 4)
                if let ms = latency {
                    let lc = latencyColor(ms)
                    Text(verbatim: "\(ms)ms")
                        .font(.system(size: 10, weight: .bold, design: .monospaced))
                        .foregroundColor(lc)
                        .padding(.horizontal, 5)
                        .padding(.vertical, 1.5)
                        .background(Capsule().fill(lc.opacity(isDark ? 0.18 : 0.10)))
                        .lineLimit(1)
                        .fixedSize(horizontal: true, vertical: false)
                }
            }

            HStack(spacing: 5) {
                Image(systemName: icon)
                    .font(.system(size: 10.5, weight: .semibold))
                    .foregroundColor(dotColor)
                Text(ip)
                    .font(.system(size: 12, weight: .semibold, design: .monospaced))
                    .foregroundColor(.primary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
            }
        }
        .padding(.horizontal, 11)
        .padding(.vertical, 9.5)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(cardSurface))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.8))
        .shadow(color: cardShadow, radius: 3, y: 1)
    }

    // 3. 6-Layer Defense Matrix (deterministic 3x2 grid to avoid NSPopover LazyVGrid height clipping)
    private var defenseMatrixGrid: some View {
        VStack(spacing: 8) {
            HStack(spacing: 8) {
                metricTile(icon: "globe.americas.fill", title: "时区与语言", value: "\(vm.snapshot.regionShort) · en-US", ok: true)
                metricTile(icon: "lock.shield.fill", title: "OAuth 门禁", value: vm.snapshot.oauthLocked ? "AdsPower-Only" : "未锁定", ok: vm.snapshot.oauthLocked)
            }
            HStack(spacing: 8) {
                metricTile(icon: "eye.slash.fill", title: "原版隐藏仓", value: vm.snapshot.originalHidden ? "已隔离防误触" : "暴露在应用栏", ok: vm.snapshot.originalHidden)
                metricTile(icon: "cube.transparent.fill", title: "macOS 沙盒", value: vm.snapshot.sandboxEnabled ? "Seatbelt 已启" : "未启用", ok: vm.snapshot.sandboxEnabled)
            }
            HStack(spacing: 8) {
                metricTile(
                    icon: "desktopcomputer",
                    title: "桌面版进程",
                    value: vm.snapshot.desktopPID.map { vm.snapshot.desktopProxyBound ? "受保护 · #\($0)" : "未绑定代理 · #\($0)" } ?? "待机未启动",
                    ok: !vm.snapshot.desktopUnprotected,
                    dim: !vm.snapshot.desktopRunning
                )
                metricTile(icon: "terminal.fill", title: "Claude Code", value: vm.snapshot.cliReady ? "CLI 防护就绪" : "待初始化", ok: vm.snapshot.cliReady)
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
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundColor(tint)
            }

            VStack(alignment: .leading, spacing: 1.5) {
                Text(title)
                    .font(.system(size: 10.5, weight: .medium))
                    .foregroundColor(labelColor)
                Text(value)
                    .font(.system(size: 11.5, weight: .semibold))
                    .foregroundColor(dim ? labelColor : .primary)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 9)
        .padding(.vertical, 7.5)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(cardSurface))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.7))
        .shadow(color: cardShadow, radius: 2.5, y: 1)
    }

    // 4. Fail-Closed Auto-Kill Toggle
    private var protectionToggleBar: some View {
        HStack(spacing: 9) {
            ZStack {
                RoundedRectangle(cornerRadius: 7, style: .continuous)
                    .fill((vm.autoKillOnBreach ? warnAmber : labelColor).opacity(isDark ? 0.18 : 0.12))
                    .frame(width: 26, height: 26)
                Image(systemName: "bolt.shield.fill")
                    .font(.system(size: 12.5, weight: .semibold))
                    .foregroundColor(vm.autoKillOnBreach ? warnAmber : labelColor)
            }
            VStack(alignment: .leading, spacing: 1.5) {
                Text("IP 漂移自动急停（Fail-Closed）")
                    .font(.system(size: 11.5, weight: .semibold))
                    .foregroundColor(.primary)
                Text("巡检发现节点异常时自动终止桌面版防裸连")
                    .font(.system(size: 10, weight: .medium))
                    .foregroundColor(labelColor)
            }
            Spacer()
            Toggle("", isOn: $vm.autoKillOnBreach)
                .toggleStyle(.switch)
                .controlSize(.mini)
                .labelsHidden()
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8.5)
        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(cardSurface))
        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.7))
        .shadow(color: cardShadow, radius: 2.5, y: 1)
    }

    // 5. Primary & Secondary Actions (2-row labeled layout for clarity)
    private var actionButtonsBar: some View {
        VStack(spacing: 8) {
            Button(action: { vm.launchClaudeSafe() }) {
                HStack(spacing: 6) {
                    Image(systemName: vm.snapshot.desktopRunning ? "macwindow.on.rectangle" : "play.fill")
                        .font(.system(size: 11.5, weight: .semibold))
                    Text(vm.snapshot.desktopRunning ? "聚焦 Claude 桌面版" : "安全启动 Claude 桌面版")
                        .font(.system(size: 12.5, weight: .semibold))
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 9.5)
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

            HStack(spacing: 8) {
                secondaryActionButton(
                    icon: "arrow.clockwise",
                    title: vm.isRefreshing ? "检测中" : "重新测速",
                    isLoading: vm.isRefreshing,
                    help: "立即重新校验双通道 IP 与 Anthropic API 延迟"
                ) {
                    vm.refresh()
                }

                secondaryActionButton(
                    icon: "doc.on.doc",
                    title: "复制诊断",
                    help: "复制完整环境与网络诊断报告到剪贴板"
                ) {
                    vm.copyDiagnostics()
                }

                if vm.snapshot.desktopRunning {
                    secondaryActionButton(
                        icon: "stop.circle.fill",
                        title: "紧急急停",
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
            HStack(spacing: 5) {
                if isLoading {
                    ProgressView()
                        .controlSize(.mini)
                        .scaleEffect(0.85)
                        .frame(width: 12, height: 12)
                } else {
                    Image(systemName: icon)
                        .font(.system(size: 11.5, weight: .semibold))
                        .foregroundColor(tint)
                }
                Text(title)
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(isDestructive ? dangerRed : .primary)
                    .lineLimit(1)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 7.5)
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

    // 6. Footer
    private var footerBar: some View {
        HStack {
            Text("Claude Shield v2.2 · 巡检 \(vm.snapshot.checkedAt)")
                .font(.system(size: 10.5, weight: .medium, design: .monospaced))
                .foregroundColor(labelColor)
            Spacer()
            Button("退出监控") { vm.quitMonitorOnly() }
                .buttonStyle(.plain)
                .font(.system(size: 11, weight: .semibold))
                .foregroundColor(labelColor)
                .help("仅关闭状态栏雷达，已启动的代理硬绑定、CLI 门禁与沙盒防护持续生效")
        }
        .padding(.top, 1)
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

        // Single-instance guard: if Claude Shield is already running, ask it to launch/focus Claude Desktop and exit
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

        viewModel.onStatusChange = { [weak self] snap in
            guard let self = self, let button = self.statusItem.button else { return }
            if snap.isSafe {
                let bestMs = snap.apiLatencyMs ?? snap.proxyLatencyMs
                let msText = bestMs.map { " \($0)ms" } ?? ""
                button.title = "🟢 \(snap.regionShort)\(msText)"
            } else {
                button.title = snap.desktopUnprotected ? "🔴 进程未受保护!" : "🔴 IP 异常!"
            }
            if self.popover.isShown {
                self.updatePopoverSize()
            }
        }

        viewModel.startPolling()
        hasCompletedInitialLaunch = true

        // Unified Launcher behavior: clicking Claude Shield.app from Launchpad/Spotlight launches/focuses Claude Desktop
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
            popover.contentSize = NSSize(width: 384, height: ceil(fitting.height))
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
