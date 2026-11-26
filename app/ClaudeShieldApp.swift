import Cocoa
import SwiftUI
import Combine
import Network
import CryptoKit
import QuartzCore

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

struct DetectResultModel: Codable, Sendable {
    let proxy_port: Int
    let proxy_reachable: Bool
    let exit_ip: String
    let tun_ip: String
    let tun_matches: Bool
    let detected_tz: String
    let country_code: String
    let city: String
    let isp: String
    let claude_app_installed: Bool
    let claude_app_hidden: Bool
    let claude_cli_path: String?
    let already_configured: Bool
}

struct SetupReportModel: Codable, Sendable {
    let ok: Bool
    let actions: [String]
    let warnings: [String]
    let expected_ip: String
    let proxy_port: Int
    let target_tz: String
}

struct UninstallReportModel: Codable, Sendable {
    let ok: Bool
    let restored: [String]
    let warnings: [String]
}

struct GateResultModel: Codable, Sendable {
    let ok: Bool
    let error: String?
    let expected_ip: String
    let proxy_ip: String
    let tun_ip: String
    let claude_edge_ip: String
    let claude_loc: String?
    let claude_colo: String?
    let elapsed_ms: Int
}

struct LaunchGuardContext: Sendable {
    static let safePurityThreshold = 78 // A-grade safety floor (S: 90-100, A: 78-89)

    let currentIP: String
    let lastLaunchIP: String?
    let expectedIP: String
    let tunIP: String
    let gateOK: Bool
    let gateError: String?
    let claudeLoc: String?
    let purity: PurityReport?
    let ipChangedFromLast: Bool
    let purityBelowThreshold: Bool
    let threshold: Int

    var isCritical: Bool {
        if !gateOK { return true }
        if let p = purity {
            if !p.region_supported || p.dns_leak || p.purity_score < 60 { return true }
        }
        if currentIP == "无法连通" || currentIP.isEmpty { return true }
        return false
    }

    var badgeText: String {
        if !gateOK && purityBelowThreshold { return "多重高危拦截" }
        if !gateOK { return "出口通道异常" }
        if ipChangedFromLast && purityBelowThreshold { return "IP 变更 · 低纯净度" }
        if ipChangedFromLast { return "出口 IP 变更" }
        return "纯净度低于安全线"
    }

    var headline: String {
        isCritical ? "高危风险 · 启动已拦截" : "安全预警 · 启动已暂停"
    }

    var subtitle: String {
        if !gateOK {
            return gateError ?? "出口 IP 与白名单或双通道不一致，直接启动可能触发风控。"
        }
        if ipChangedFromLast && purityBelowThreshold {
            return "检测到出口 IP 与上次启动不一致，且当前纯净度低于 \(threshold) 分安全线。"
        }
        if ipChangedFromLast {
            return "当前出口 IP 与上次启动记录不同，频繁切换 IP 可能增加账号风控概率。"
        }
        return "当前出口 IP 纯净度未达到 \(threshold) 分（A 级）安全阈值，建议更换节点后再启动。"
    }
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

    static func fetchGate() -> GateResultModel? {
        guard let data = runCore(["gate", "--json"]) else { return nil }
        return try? JSONDecoder().decode(GateResultModel.self, from: data)
    }

    static func loadLastLaunchIP() -> String? {
        let url = cacheDir.appendingPathComponent("last_launch_ip")
        guard let raw = try? String(contentsOf: url, encoding: .utf8) else { return nil }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty ? nil : trimmed
    }

    static func saveLastLaunchIP(_ ip: String) {
        let trimmed = ip.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed != "无法连通", trimmed != "未配置", trimmed != "..." else { return }
        try? FileManager.default.createDirectory(at: cacheDir, withIntermediateDirectories: true)
        let url = cacheDir.appendingPathComponent("last_launch_ip")
        try? (trimmed + "\n").write(to: url, atomically: true, encoding: .utf8)
    }

    static func claudeDesktopAppURL() -> URL? {
        let vault = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".local/apps/Claude.app")
        if FileManager.default.fileExists(atPath: vault.path) {
            return vault
        }
        let apps = URL(fileURLWithPath: "/Applications/Claude.app")
        if FileManager.default.fileExists(atPath: apps.path) {
            return apps
        }
        return nil
    }

    static func hideOriginalApp() -> [String] {
        guard let data = runCore(["hide-original", "--json"]),
              let items = try? JSONDecoder().decode([String].self, from: data) else {
            return []
        }
        return items
    }

    static var needsInitialSetup: Bool {
        let ipURL = cacheDir.appendingPathComponent("expected_ip")
        guard let raw = try? String(contentsOf: ipURL, encoding: .utf8) else { return true }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        return trimmed.isEmpty || trimmed == "未配置"
    }

    static func detectEnvironment(port: Int? = nil) -> DetectResultModel? {
        var args = ["detect", "--json"]
        if let port = port {
            args.append(contentsOf: ["--port", String(port)])
        }
        guard let data = runCore(args) else { return nil }
        return try? JSONDecoder().decode(DetectResultModel.self, from: data)
    }

    static func runSetup(
        ip: String,
        port: Int,
        tz: String,
        hideOriginal: Bool,
        autostart: Bool,
        patrol: Bool,
        appPath: String
    ) -> SetupReportModel? {
        var args = [
            "setup", "--json",
            "--ip", ip.trimmingCharacters(in: .whitespacesAndNewlines),
            "--port", String(port),
            "--tz", tz.trimmingCharacters(in: .whitespacesAndNewlines),
            "--app-path", appPath
        ]
        if !hideOriginal { args.append("--no-hide") }
        if !autostart { args.append("--no-autostart") }
        if !patrol { args.append("--no-patrol") }
        guard let data = runCore(args) else { return nil }
        return try? JSONDecoder().decode(SetupReportModel.self, from: data)
    }

    static func runUninstall() -> UninstallReportModel? {
        guard let data = runCore(["uninstall", "--json"]) else { return nil }
        return try? JSONDecoder().decode(UninstallReportModel.self, from: data)
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
                let bootout = Process()
                bootout.executableURL = URL(fileURLWithPath: "/bin/launchctl")
                bootout.arguments = ["bootout", "gui/\(uid)", plistURL.path]
                try? bootout.run()
                bootout.waitUntilExit()
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

// MARK: - GitHub Auto-Updater (Zero-Dependency, Proxy-Aware, SHA-256 Verified)

private enum AppReleaseConfig {
    static let githubRepo = "luvio-arlan/claude-shield"

    static var currentVersion: String {
        if let v = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String,
           !v.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return v.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return "3.2.0"
    }

    static var shortDisplayVersion: String {
        "v\(currentVersion)"
    }

    static var currentArch: String {
        #if arch(arm64)
        return "arm64"
        #else
        return "x86_64"
        #endif
    }

    static func normalizedVersion(_ raw: String) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        let withoutV = trimmed.hasPrefix("v") || trimmed.hasPrefix("V") ? String(trimmed.dropFirst()) : trimmed
        return withoutV.split(separator: "-", maxSplits: 1).first.map(String.init) ?? withoutV
    }

    static func isVersion(_ remote: String, newerThan local: String) -> Bool {
        let rParts = normalizedVersion(remote).split(separator: ".").map { Int($0) ?? 0 }
        let lParts = normalizedVersion(local).split(separator: ".").map { Int($0) ?? 0 }
        let count = max(rParts.count, lParts.count)
        for i in 0..<count {
            let rv = i < rParts.count ? rParts[i] : 0
            let lv = i < lParts.count ? lParts[i] : 0
            if rv != lv { return rv > lv }
        }
        return false
    }
}

struct GitHubReleaseAsset: Codable, Sendable {
    let name: String
    let browser_download_url: String
    let size: Int
}

struct GitHubRelease: Codable, Sendable {
    let tag_name: String
    let name: String?
    let body: String?
    let html_url: String
    let published_at: String?
    let draft: Bool?
    let prerelease: Bool?
    let assets: [GitHubReleaseAsset]
}

struct AppUpdateInfo: Equatable, Sendable {
    let version: String
    let tagName: String
    let title: String
    let notesSummary: String
    let htmlURL: URL
    let zipDownloadURL: URL?
    let zipAssetName: String?
    let zipSize: Int
    let checksumURL: URL?
}

enum AppUpdatePhase: Equatable {
    case idle
    case checking
    case upToDate(String)
    case available(AppUpdateInfo)
    case downloading(AppUpdateInfo, Double)
    case installing(AppUpdateInfo, String)
    case failed(String)

    var info: AppUpdateInfo? {
        switch self {
        case .available(let i), .downloading(let i, _), .installing(let i, _):
            return i
        default:
            return nil
        }
    }

    var isBusy: Bool {
        switch self {
        case .checking, .downloading, .installing:
            return true
        default:
            return false
        }
    }
}

private final class DownloadProgressBridge: NSObject, URLSessionDownloadDelegate, @unchecked Sendable {
    private let onProgress: @Sendable (Double) -> Void
    private var continuation: CheckedContinuation<URL, Error>?
    private var finished = false

    init(onProgress: @escaping @Sendable (Double) -> Void) {
        self.onProgress = onProgress
    }

    func download(url: URL, session: URLSession) async throws -> URL {
        try await withCheckedThrowingContinuation { cont in
            self.continuation = cont
            var req = URLRequest(url: url)
            req.setValue("Claude-Shield/\(AppReleaseConfig.currentVersion)", forHTTPHeaderField: "User-Agent")
            let task = session.downloadTask(with: req)
            task.resume()
        }
    }

    func urlSession(
        _ session: URLSession,
        downloadTask: URLSessionDownloadTask,
        didWriteData bytesWritten: Int64,
        totalBytesWritten: Int64,
        totalBytesExpectedToWrite: Int64
    ) {
        guard totalBytesExpectedToWrite > 0 else { return }
        let ratio = min(1.0, max(0.0, Double(totalBytesWritten) / Double(totalBytesExpectedToWrite)))
        onProgress(ratio)
    }

    func urlSession(_ session: URLSession, downloadTask: URLSessionDownloadTask, didFinishDownloadingTo location: URL) {
        guard !finished else { return }
        finished = true
        let tempCopy = FileManager.default.temporaryDirectory
            .appendingPathComponent("claude-shield-dl-\(UUID().uuidString).zip")
        do {
            try? FileManager.default.removeItem(at: tempCopy)
            try FileManager.default.moveItem(at: location, to: tempCopy)
            continuation?.resume(returning: tempCopy)
        } catch {
            continuation?.resume(throwing: error)
        }
        continuation = nil
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        guard let error = error, !finished else { return }
        finished = true
        continuation?.resume(throwing: error)
        continuation = nil
    }
}

private enum GitHubUpdater {
    enum UpdateError: LocalizedError {
        case invalidURL
        case httpStatus(Int)
        case noZipAsset
        case checksumMismatch
        case extractFailed
        case appNotFoundInArchive

        var errorDescription: String? {
            switch self {
            case .invalidURL: return "更新地址无效"
            case .httpStatus(let code): return "GitHub 接口返回异常（HTTP \(code)）"
            case .noZipAsset: return "该版本未附带 macOS ZIP 安装包，请前往 GitHub 手动下载"
            case .checksumMismatch: return "安装包 SHA-256 校验失败，已中止更新以保障安全"
            case .extractFailed: return "解压更新包失败，请重试或前往 GitHub 手动下载"
            case .appNotFoundInArchive: return "更新包中未找到 Claude Shield.app"
            }
        }
    }

    private static func makeSession(proxyPort: Int?, timeout: TimeInterval, delegate: URLSessionDelegate? = nil) -> URLSession {
        let cfg = URLSessionConfiguration.ephemeral
        cfg.timeoutIntervalForRequest = timeout
        cfg.timeoutIntervalForResource = max(timeout, 180)
        cfg.requestCachePolicy = .reloadIgnoringLocalCacheData
        if let port = proxyPort, port > 0 {
            cfg.connectionProxyDictionary = [
                kCFNetworkProxiesHTTPEnable as String: 1,
                kCFNetworkProxiesHTTPProxy as String: "127.0.0.1",
                kCFNetworkProxiesHTTPPort as String: port,
                kCFNetworkProxiesHTTPSEnable as String: 1,
                kCFNetworkProxiesHTTPSProxy as String: "127.0.0.1",
                kCFNetworkProxiesHTTPSPort as String: port
            ]
        }
        return URLSession(configuration: cfg, delegate: delegate, delegateQueue: nil)
    }

    private static func fetchDataWithFallback(url: URL, accept: String?, proxyPort: Int) async throws -> (Data, HTTPURLResponse) {
        var req = URLRequest(url: url)
        req.setValue("Claude-Shield/\(AppReleaseConfig.currentVersion)", forHTTPHeaderField: "User-Agent")
        if let accept = accept {
            req.setValue(accept, forHTTPHeaderField: "Accept")
        }

        func attempt(port: Int?) async throws -> (Data, HTTPURLResponse) {
            let session = makeSession(proxyPort: port, timeout: 12)
            defer { session.finishTasksAndInvalidate() }
            let (data, resp) = try await session.data(for: req)
            guard let http = resp as? HTTPURLResponse else {
                throw UpdateError.httpStatus(0)
            }
            return (data, http)
        }

        do {
            return try await attempt(port: nil)
        } catch {
            if proxyPort > 0 {
                return try await attempt(port: proxyPort)
            }
            throw error
        }
    }

    private static func summarizeNotes(_ raw: String?) -> String {
        guard let raw = raw, !raw.isEmpty else {
            return "包含最新安全防护优化与体验改进"
        }
        let lines = raw
            .components(separatedBy: .newlines)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && !$0.hasPrefix("#") && !$0.hasPrefix("---") }
            .map { line -> String in
                var s = line
                for prefix in ["- ", "* ", "• "] {
                    if s.hasPrefix(prefix) { s = String(s.dropFirst(prefix.count)) }
                }
                return s.replacingOccurrences(of: "**", with: "")
            }
        let joined = lines.prefix(2).joined(separator: " · ")
        if joined.isEmpty { return "包含最新安全防护优化与体验改进" }
        return joined.count > 96 ? String(joined.prefix(94)) + "…" : joined
    }

    static func checkLatestRelease(proxyPort: Int) async throws -> AppUpdateInfo? {
        guard let url = URL(string: "https://api.github.com/repos/\(AppReleaseConfig.githubRepo)/releases/latest") else {
            throw UpdateError.invalidURL
        }
        let (data, http) = try await fetchDataWithFallback(
            url: url,
            accept: "application/vnd.github+json",
            proxyPort: proxyPort
        )
        if http.statusCode == 404 {
            return nil
        }
        guard (200...299).contains(http.statusCode) else {
            throw UpdateError.httpStatus(http.statusCode)
        }

        let release = try JSONDecoder().decode(GitHubRelease.self, from: data)
        if release.draft == true || release.prerelease == true {
            return nil
        }
        guard AppReleaseConfig.isVersion(release.tag_name, newerThan: AppReleaseConfig.currentVersion) else {
            return nil
        }

        let arch = AppReleaseConfig.currentArch.lowercased()
        let zipAssets = release.assets.filter { $0.name.lowercased().hasSuffix(".zip") }
        let matchedZip = zipAssets.first(where: { $0.name.lowercased().contains(arch) })
            ?? zipAssets.first(where: { $0.name.lowercased().contains("universal") || $0.name.lowercased().contains("macos") })
            ?? zipAssets.first
        let checksumAsset = release.assets.first(where: { $0.name.uppercased().contains("SHA256") })

        guard let htmlURL = URL(string: release.html_url) else {
            throw UpdateError.invalidURL
        }

        return AppUpdateInfo(
            version: AppReleaseConfig.normalizedVersion(release.tag_name),
            tagName: release.tag_name,
            title: (release.name?.isEmpty == false ? release.name! : release.tag_name),
            notesSummary: summarizeNotes(release.body),
            htmlURL: htmlURL,
            zipDownloadURL: matchedZip.flatMap { URL(string: $0.browser_download_url) },
            zipAssetName: matchedZip?.name,
            zipSize: matchedZip?.size ?? 0,
            checksumURL: checksumAsset.flatMap { URL(string: $0.browser_download_url) }
        )
    }

    static func downloadAndInstall(
        info: AppUpdateInfo,
        proxyPort: Int,
        onProgress: @escaping @Sendable (Double) -> Void,
        onStage: @escaping @Sendable (String) -> Void
    ) async throws {
        guard let zipURL = info.zipDownloadURL else {
            throw UpdateError.noZipAsset
        }

        func downloadOnce(port: Int?) async throws -> URL {
            let bridge = DownloadProgressBridge(onProgress: onProgress)
            let session = makeSession(proxyPort: port, timeout: 30, delegate: bridge)
            defer { session.finishTasksAndInvalidate() }
            return try await bridge.download(url: zipURL, session: session)
        }

        let downloadedTemp: URL
        do {
            downloadedTemp = try await downloadOnce(port: nil)
        } catch {
            if proxyPort > 0 {
                onProgress(0)
                downloadedTemp = try await downloadOnce(port: proxyPort)
            } else {
                throw error
            }
        }

        let fm = FileManager.default
        let cacheRoot = fm.urls(for: .cachesDirectory, in: .userDomainMask).first ?? fm.temporaryDirectory
        let stagingDir = cacheRoot
            .appendingPathComponent("ClaudeShieldUpdate", isDirectory: true)
            .appendingPathComponent(info.version, isDirectory: true)
        try? fm.removeItem(at: stagingDir)
        try fm.createDirectory(at: stagingDir, withIntermediateDirectories: true)

        let zipPath = stagingDir.appendingPathComponent(info.zipAssetName ?? "update.zip")
        try? fm.removeItem(at: zipPath)
        try fm.moveItem(at: downloadedTemp, to: zipPath)

        // Verify SHA-256 checksum if release published SHA256SUMS.txt
        if let sumURL = info.checksumURL, let assetName = info.zipAssetName {
            onStage("正在校验 SHA-256 签名...")
            if let (sumData, http) = try? await fetchDataWithFallback(url: sumURL, accept: nil, proxyPort: proxyPort),
               (200...299).contains(http.statusCode),
               let sumText = String(data: sumData, encoding: .utf8) {
                let expectedHash = sumText
                    .components(separatedBy: .newlines)
                    .compactMap { line -> String? in
                        let parts = line.split(whereSeparator: { $0.isWhitespace })
                        guard parts.count >= 2 else { return nil }
                        let name = String(parts[1]).replacingOccurrences(of: "*", with: "")
                        return name == assetName ? String(parts[0]).lowercased() : nil
                    }
                    .first
                if let expected = expectedHash {
                    let fileData = try Data(contentsOf: zipPath)
                    let digest = SHA256.hash(data: fileData).map { String(format: "%02x", $0) }.joined()
                    guard digest == expected else {
                        throw UpdateError.checksumMismatch
                    }
                }
            }
        }

        onStage("正在解压新版本...")
        let extractDir = stagingDir.appendingPathComponent("extracted", isDirectory: true)
        try fm.createDirectory(at: extractDir, withIntermediateDirectories: true)

        let unzip = Process()
        unzip.executableURL = URL(fileURLWithPath: "/usr/bin/ditto")
        unzip.arguments = ["-x", "-k", zipPath.path, extractDir.path]
        try unzip.run()
        unzip.waitUntilExit()
        guard unzip.terminationStatus == 0 else {
            throw UpdateError.extractFailed
        }

        let newAppURL = extractDir.appendingPathComponent("Claude Shield.app")
        let candidateApp: URL
        if fm.fileExists(atPath: newAppURL.path) {
            candidateApp = newAppURL
        } else if let found = (try? fm.contentsOfDirectory(at: extractDir, includingPropertiesForKeys: nil))?
            .first(where: { $0.pathExtension == "app" }) {
            candidateApp = found
        } else {
            throw UpdateError.appNotFoundInArchive
        }

        guard fm.isExecutableFile(atPath: candidateApp.appendingPathComponent("Contents/MacOS/ClaudeShield").path) else {
            throw UpdateError.appNotFoundInArchive
        }

        // Clear quarantine attribute before swapping
        let xattr = Process()
        xattr.executableURL = URL(fileURLWithPath: "/usr/bin/xattr")
        xattr.arguments = ["-cr", candidateApp.path]
        try? xattr.run()
        xattr.waitUntilExit()

        onStage("正在替换应用并重启...")

        let targetAppPath: String = {
            if Bundle.main.bundleURL.pathExtension == "app" {
                return Bundle.main.bundleURL.path
            }
            return "/Applications/Claude Shield.app"
        }()

        let pid = ProcessInfo.processInfo.processIdentifier
        let scriptURL = stagingDir.appendingPathComponent("apply-update.sh")
        let script = """
        #!/usr/bin/env bash
        set -euo pipefail
        OLD_PID="$1"
        NEW_APP="$2"
        TARGET_APP="$3"
        STAGING_DIR="$4"

        for _ in $(seq 1 60); do
          if ! kill -0 "${OLD_PID}" 2>/dev/null; then
            break
          fi
          sleep 0.1
        done

        BACKUP_APP="${TARGET_APP}.bak.$$"
        replace_direct() {
          if [[ -d "${TARGET_APP}" ]]; then
            mv "${TARGET_APP}" "${BACKUP_APP}"
          fi
          if mv "${NEW_APP}" "${TARGET_APP}"; then
            rm -rf "${BACKUP_APP}"
            return 0
          else
            [[ -d "${BACKUP_APP}" ]] && mv "${BACKUP_APP}" "${TARGET_APP}" || true
            return 1
          fi
        }

        if ! replace_direct 2>/dev/null; then
          /usr/bin/osascript -e "do shell script \\"rm -rf '${TARGET_APP}' && mv '${NEW_APP}' '${TARGET_APP}'\\" with administrator privileges"
        fi

        /usr/bin/xattr -cr "${TARGET_APP}" 2>/dev/null || true
        if [[ -x "${TARGET_APP}/Contents/MacOS/claude-shield-core" && -d "${HOME}/.local/bin" ]]; then
          cp "${TARGET_APP}/Contents/MacOS/claude-shield-core" "${HOME}/.local/bin/claude-shield-core" 2>/dev/null || true
          chmod +x "${HOME}/.local/bin/claude-shield-core" 2>/dev/null || true
        fi
        LSREG="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
        [[ -x "${LSREG}" ]] && "${LSREG}" -f "${TARGET_APP}" >/dev/null 2>&1 || true

        rm -rf "${STAGING_DIR}"
        open -n "${TARGET_APP}" --args --radar-only
        """
        try script.write(to: scriptURL, atomically: true, encoding: .utf8)
        try fm.setAttributes([.posixPermissions: 0o755], ofItemAtPath: scriptURL.path)

        let helper = Process()
        helper.executableURL = URL(fileURLWithPath: "/bin/bash")
        helper.arguments = [scriptURL.path, String(pid), candidateApp.path, targetAppPath, stagingDir.path]
        helper.standardOutput = FileHandle.nullDevice
        helper.standardError = FileHandle.nullDevice
        try helper.run()
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
    var onShowSetupWizard: ((Bool) -> Void)?
    var onShowDashboard: ((ShieldDashboardSection, Bool) -> Void)?
    private var timer: Timer?
    private var purityTimer: Timer?
    private var updateTimer: Timer?
    private var pathMonitor: NWPathMonitor?
    private var lastNetworkStatus: NWPath.Status?
    private var consecutiveUnreachableCount = 0
    private var lastRefreshAt: Date?

    init() {
        self.autoKillOnBreach = UserDefaults.standard.object(forKey: "autoKillOnBreach") as? Bool ?? true
        self.dismissedUpdateVersion = UserDefaults.standard.string(forKey: "dismissedUpdateVersion")
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
            Task { @MainActor in self?.runFullCheckup(silent: true) }
        }

        // Silent GitHub release auto-update check (5s after launch + every 6h)
        DispatchQueue.main.asyncAfter(deadline: .now() + 5.0) { [weak self] in
            self?.checkForUpdates(manual: false)
        }
        updateTimer?.invalidate()
        updateTimer = Timer.scheduledTimer(withTimeInterval: 21600.0, repeats: true) { [weak self] _ in
            Task { @MainActor in self?.checkForUpdates(manual: false) }
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
                    self.refresh()
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

    /// Reliably brings Claude Desktop to the active desktop: closes popover, unhides, activates,
    /// switches macOS Spaces, and reopens/unminimizes its Electron window if closed or in the Dock.
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

        // Send macOS reopen event to the existing app bundle so minimized/closed Electron windows
        // come back to the desktop and macOS switches Spaces if Claude is on another desktop.
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
        // If Claude Desktop is already running and hardened, immediately pull it to the desktop!
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
            let safe = reason
                .replacingOccurrences(of: "\\", with: "\\\\")
                .replacingOccurrences(of: "\"", with: "'")
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

    func openSetupWizard(isFirstRun: Bool = false) {
        openDashboard(section: .settings, isFirstRun: isFirstRun)
    }

    func openDashboard(section: ShieldDashboardSection = .radar, isFirstRun: Bool = false) {
        onRequestClosePopover?()
        if let onShowDashboard = onShowDashboard {
            onShowDashboard(section, isFirstRun)
        } else {
            onShowSetupWizard?(isFirstRun)
        }
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

// MARK: - Smooth Interaction Primitives

private final class LocalState<Value>: ObservableObject {
    @Published var value: Value
    init(_ initial: Value) { self.value = initial }
}

private struct SnappyButtonStyle: ButtonStyle {
    var scale: CGFloat = 0.97
    var pressedOpacity: Double = 0.88

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? scale : 1.0)
            .opacity(configuration.isPressed ? pressedOpacity : 1.0)
            .animation(.easeOut(duration: 0.08), value: configuration.isPressed)
    }
}

private enum MenuBarShieldState {
    case loading
    case armed
    case alert
}

private enum ShieldBrandGraphics {
    private static let sparkTemplateCG: CGImage? = {
        let candidates: [URL?] = [
            Bundle.main.url(forResource: "claude-spark-template", withExtension: "png"),
            URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
                .appendingPathComponent("assets/claude-spark-template.png"),
        ]
        for url in candidates.compactMap({ $0 }) {
            if let img = NSImage(contentsOf: url),
               let cg = img.cgImage(forProposedRect: nil, context: nil, hints: nil) {
                return cg
            }
        }
        return nil
    }()

    /// Taut modern security shield path in CoreGraphics bottom-left coordinate space (0.82 W:H).
    static func tautShieldPath(cx: CGFloat, cy: CGFloat, w: CGFloat, h: CGFloat) -> CGPath {
        let hw = w / 2.0
        let hh = h / 2.0
        func pt(_ nx: CGFloat, _ ny: CGFloat) -> CGPoint {
            CGPoint(x: cx + nx * hw, y: cy + ny * hh)
        }

        let p = CGMutablePath()
        p.move(to: pt(0.0, 0.99))
        p.addCurve(to: pt(0.89, 0.84), control1: pt(0.28, 0.99), control2: pt(0.64, 0.93))
        p.addCurve(to: pt(0.99, 0.70), control1: pt(0.96, 0.81), control2: pt(0.99, 0.77))
        p.addCurve(to: pt(0.90, 0.02), control1: pt(0.99, 0.44), control2: pt(0.97, 0.22))
        p.addCurve(to: pt(0.07, -0.96), control1: pt(0.80, -0.44), control2: pt(0.45, -0.80))
        p.addCurve(to: pt(-0.07, -0.96), control1: pt(0.025, -0.995), control2: pt(-0.025, -0.995))
        p.addCurve(to: pt(-0.90, 0.02), control1: pt(-0.45, -0.80), control2: pt(-0.80, -0.44))
        p.addCurve(to: pt(-0.99, 0.70), control1: pt(-0.97, 0.22), control2: pt(-0.99, 0.44))
        p.addCurve(to: pt(-0.89, 0.84), control1: pt(-0.99, 0.77), control2: pt(-0.96, 0.81))
        p.addCurve(to: pt(0.0, 0.99), control1: pt(-0.64, 0.93), control2: pt(-0.28, 0.99))
        p.closeSubpath()
        return p
    }

    /// Draws the signature 45-degree interlocking twin-wing shield ring.
    static func drawTwinWingShield(
        in ctx: CGContext,
        cx: CGFloat,
        cy: CGFloat,
        cutCenterY: CGFloat,
        outerW: CGFloat,
        outerH: CGFloat,
        ringThicknessX: CGFloat,
        ringThicknessY: CGFloat,
        gapWidth: CGFloat,
        upperLeftColor: CGColor,
        lowerRightColor: CGColor
    ) {
        let outerShield = tautShieldPath(cx: cx, cy: cy, w: outerW, h: outerH)
        let innerShield = tautShieldPath(
            cx: cx,
            cy: cy + outerH * 0.004,
            w: max(1, outerW - ringThicknessX * 2),
            h: max(1, outerH - ringThicknessY * 2)
        )

        let ring = CGMutablePath()
        ring.addPath(outerShield)
        ring.addPath(innerShield)

        let shift = (gapWidth / 2.0) * sqrt(2.0)
        let span = max(outerW, outerH) * 2.5

        ctx.saveGState()
        ctx.addPath(ring)
        ctx.clip(using: .evenOdd)
        let ulPoly = CGMutablePath()
        ulPoly.move(to: CGPoint(x: cx - span, y: cutCenterY - span + shift))
        ulPoly.addLine(to: CGPoint(x: cx + span, y: cutCenterY + span + shift))
        ulPoly.addLine(to: CGPoint(x: cx + span, y: cutCenterY + span * 2.5))
        ulPoly.addLine(to: CGPoint(x: cx - span, y: cutCenterY + span * 2.5))
        ulPoly.closeSubpath()
        ctx.addPath(ulPoly)
        ctx.setFillColor(upperLeftColor)
        ctx.fillPath()
        ctx.restoreGState()

        ctx.saveGState()
        ctx.addPath(ring)
        ctx.clip(using: .evenOdd)
        let lrPoly = CGMutablePath()
        lrPoly.move(to: CGPoint(x: cx - span, y: cutCenterY - span - shift))
        lrPoly.addLine(to: CGPoint(x: cx + span, y: cutCenterY + span - shift))
        lrPoly.addLine(to: CGPoint(x: cx + span, y: cutCenterY - span * 2.5))
        lrPoly.addLine(to: CGPoint(x: cx - span, y: cutCenterY - span * 2.5))
        lrPoly.closeSubpath()
        ctx.addPath(lrPoly)
        ctx.setFillColor(lowerRightColor)
        ctx.fillPath()
        ctx.restoreGState()
    }

    /// Draws the authentic official Claude spark mask tinted with `tint` (or a clean 8-ray fallback).
    static func drawClaudeSpark(in ctx: CGContext, rect: CGRect, tint: CGColor) {
        if let sparkCG = sparkTemplateCG {
            ctx.saveGState()
            ctx.interpolationQuality = .high
            ctx.clip(to: rect, mask: sparkCG)
            ctx.setFillColor(tint)
            ctx.fill(rect)
            ctx.restoreGState()
            return
        }

        // Vector fallback when running standalone without bundle resources
        let cx = rect.midX
        let cy = rect.midY
        let r = min(rect.width, rect.height) * 0.46
        ctx.saveGState()
        ctx.setStrokeColor(tint)
        ctx.setLineWidth(max(1.2, r * 0.22))
        ctx.setLineCap(.round)
        for i in 0..<8 {
            let a = CGFloat(i) * (.pi / 4.0)
            let len = (i % 2 == 0) ? r : r * 0.84
            ctx.move(to: CGPoint(x: cx, y: cy))
            ctx.addLine(to: CGPoint(x: cx + cos(a) * len, y: cy + sin(a) * len))
        }
        ctx.strokePath()
        ctx.restoreGState()
    }

    /// Native adaptive Retina macOS menu bar icon: 45-degree twin-wing shield + official Claude spark + jewel status beacon.
    static func makeMenuBarIcon(state: MenuBarShieldState) -> NSImage {
        let size = NSSize(width: 18, height: 18)
        let image = NSImage(size: size, flipped: false) { rect in
            guard let ctx = NSGraphicsContext.current?.cgContext else { return false }
            ctx.setAllowsAntialiasing(true)
            ctx.setShouldAntialias(true)

            let primaryColor: NSColor
            let secondaryColor: NSColor
            let sparkColor: NSColor
            let dotColor: NSColor

            switch state {
            case .armed:
                primaryColor = NSColor.labelColor
                secondaryColor = NSColor.labelColor.withAlphaComponent(0.72)
                sparkColor = NSColor.labelColor
                dotColor = NSColor(srgbRed: 0.13, green: 0.77, blue: 0.42, alpha: 1.0)
            case .loading:
                primaryColor = NSColor.labelColor.withAlphaComponent(0.88)
                secondaryColor = NSColor.labelColor.withAlphaComponent(0.58)
                sparkColor = NSColor.labelColor.withAlphaComponent(0.85)
                dotColor = NSColor(srgbRed: 0.96, green: 0.65, blue: 0.14, alpha: 1.0)
            case .alert:
                let alertRed = NSColor(srgbRed: 0.95, green: 0.29, blue: 0.29, alpha: 1.0)
                primaryColor = alertRed
                secondaryColor = alertRed.withAlphaComponent(0.76)
                sparkColor = alertRed
                dotColor = alertRed
            }

            let cx = rect.midX - 0.5
            let cy = rect.midY
            let cutY = cy + 0.8

            ctx.beginTransparencyLayer(auxiliaryInfo: nil)

            drawTwinWingShield(
                in: ctx,
                cx: cx,
                cy: cy,
                cutCenterY: cutY,
                outerW: 13.4,
                outerH: 15.8,
                ringThicknessX: 1.95,
                ringThicknessY: 2.15,
                gapWidth: 1.15,
                upperLeftColor: primaryColor.cgColor,
                lowerRightColor: secondaryColor.cgColor
            )

            if state == .alert {
                // Crisp exclamation mark inside shield for unmistakable alert readability at 18pt
                ctx.saveGState()
                ctx.setFillColor(sparkColor.cgColor)
                let bar = CGRect(x: cx - 0.85, y: cutY - 0.6, width: 1.7, height: 4.5)
                ctx.addPath(CGPath(roundedRect: bar, cornerWidth: 0.85, cornerHeight: 0.85, transform: nil))
                ctx.fillPath()
                ctx.fillEllipse(in: CGRect(x: cx - 0.9, y: cutY - 3.1, width: 1.8, height: 1.8))
                ctx.restoreGState()
            } else {
                let sparkSize: CGFloat = 6.8
                let sparkRect = CGRect(x: cx - sparkSize / 2.0, y: cutY - sparkSize / 2.0, width: sparkSize, height: sparkSize)
                drawClaudeSpark(in: ctx, rect: sparkRect, tint: sparkColor.cgColor)
            }

            // Negative-space cutout halo + jewel status dot at bottom-right
            let dotCenter = CGPoint(x: rect.maxX - 3.3, y: rect.minY + 3.4)
            let haloR: CGFloat = 3.55
            ctx.saveGState()
            ctx.setBlendMode(.clear)
            ctx.fillEllipse(in: CGRect(x: dotCenter.x - haloR, y: dotCenter.y - haloR, width: haloR * 2, height: haloR * 2))
            ctx.restoreGState()

            ctx.endTransparencyLayer()

            let dotR: CGFloat = 2.45
            ctx.saveGState()
            ctx.setFillColor(dotColor.cgColor)
            ctx.fillEllipse(in: CGRect(x: dotCenter.x - dotR, y: dotCenter.y - dotR, width: dotR * 2, height: dotR * 2))
            ctx.restoreGState()

            return true
        }
        image.isTemplate = false
        return image
    }

    /// 3x Retina popover hero emblem matching Option 3B (twin-wing shield + authentic official Claude spark).
    static func makePopoverBadgeEmblem(isSafe: Bool, isDark: Bool) -> NSImage {
        let ptSize: CGFloat = 38
        let scale: CGFloat = 3
        let pxSize = Int(ptSize * scale)
        let cs = CGColorSpace(name: CGColorSpace.sRGB)!
        let ctx = CGContext(
            data: nil,
            width: pxSize,
            height: pxSize,
            bitsPerComponent: 8,
            bytesPerRow: 0,
            space: cs,
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
        )!
        ctx.interpolationQuality = .high
        ctx.setAllowsAntialiasing(true)
        ctx.setShouldAntialias(true)
        ctx.scaleBy(x: scale, y: scale)

        let cx = ptSize / 2.0
        let cy = ptSize / 2.0 - 0.3
        let sparkCy = cy + 1.5

        let ulColor: CGColor
        let lrColor: CGColor
        let sparkTint: CGColor

        if isSafe {
            ulColor = isDark
                ? CGColor(srgbRed: 0.95, green: 0.93, blue: 0.89, alpha: 1.0)
                : CGColor(srgbRed: 0.114, green: 0.110, blue: 0.102, alpha: 1.0)
            lrColor = isDark
                ? CGColor(srgbRed: 0.72, green: 0.69, blue: 0.65, alpha: 1.0)
                : CGColor(srgbRed: 0.239, green: 0.227, blue: 0.212, alpha: 1.0)
            sparkTint = CGColor(srgbRed: 0.851, green: 0.463, blue: 0.333, alpha: 1.0) // Official Claude Terracotta #D97655
        } else {
            ulColor = isDark
                ? CGColor(srgbRed: 0.98, green: 0.42, blue: 0.44, alpha: 1.0)
                : CGColor(srgbRed: 0.84, green: 0.16, blue: 0.16, alpha: 1.0)
            lrColor = isDark
                ? CGColor(srgbRed: 0.82, green: 0.26, blue: 0.28, alpha: 1.0)
                : CGColor(srgbRed: 0.68, green: 0.12, blue: 0.12, alpha: 1.0)
            sparkTint = ulColor
        }

        drawTwinWingShield(
            in: ctx,
            cx: cx,
            cy: cy,
            cutCenterY: sparkCy,
            outerW: 23.2,
            outerH: 27.6,
            ringThicknessX: 2.7,
            ringThicknessY: 3.1,
            gapWidth: 1.45,
            upperLeftColor: ulColor,
            lowerRightColor: lrColor
        )

        if isSafe {
            let sparkSize: CGFloat = 11.8
            let sparkRect = CGRect(x: cx - sparkSize / 2.0, y: sparkCy - sparkSize / 2.0, width: sparkSize, height: sparkSize)
            drawClaudeSpark(in: ctx, rect: sparkRect, tint: sparkTint)
        } else {
            ctx.saveGState()
            ctx.setFillColor(sparkTint)
            let bar = CGRect(x: cx - 1.25, y: sparkCy - 1.0, width: 2.5, height: 6.4)
            ctx.addPath(CGPath(roundedRect: bar, cornerWidth: 1.25, cornerHeight: 1.25, transform: nil))
            ctx.fillPath()
            ctx.fillEllipse(in: CGRect(x: cx - 1.35, y: sparkCy - 4.4, width: 2.7, height: 2.7))
            ctx.restoreGState()
        }

        let img = NSImage(cgImage: ctx.makeImage()!, size: NSSize(width: ptSize, height: ptSize))
        return img
    }
}

private struct ShieldStatusBadge: View {
    let isSafe: Bool
    let accentColor: Color
    let isDark: Bool
    @StateObject private var pulseState = LocalState(false)

    var body: some View {
        let ringOpacity = pulseState.value ? (isDark ? 0.24 : 0.16) : (isDark ? 0.09 : 0.06)
        let tileBgTop = isDark
            ? Color(red: 0.17, green: 0.165, blue: 0.16)
            : Color(red: 0.97, green: 0.953, blue: 0.925)
        let tileBgBot = isDark
            ? Color(red: 0.125, green: 0.12, blue: 0.115)
            : Color(red: 0.925, green: 0.894, blue: 0.843)
        let tileBorder = isSafe
            ? (isDark ? Color.white.opacity(0.14) : Color.black.opacity(0.09))
            : accentColor.opacity(isDark ? 0.55 : 0.45)

        ZStack {
            RoundedRectangle(cornerRadius: 13.5, style: .continuous)
                .fill(accentColor.opacity(ringOpacity))
                .frame(width: 46, height: 46)

            RoundedRectangle(cornerRadius: 10.5, style: .continuous)
                .fill(
                    LinearGradient(
                        colors: [tileBgTop, tileBgBot],
                        startPoint: .top,
                        endPoint: .bottom
                    )
                )
                .frame(width: 38, height: 38)
                .overlay(
                    RoundedRectangle(cornerRadius: 10.5, style: .continuous)
                        .strokeBorder(tileBorder, lineWidth: 0.9)
                )
                .shadow(color: Color.black.opacity(isDark ? 0.30 : 0.09), radius: 4, y: 1.5)

            Image(nsImage: ShieldBrandGraphics.makePopoverBadgeEmblem(isSafe: isSafe, isDark: isDark))
                .resizable()
                .interpolation(.high)
                .frame(width: 38, height: 38)

            // Live armed / alert micro-beacon at bottom-right
            Circle()
                .fill(accentColor)
                .frame(width: 8.5, height: 8.5)
                .overlay(
                    Circle()
                        .strokeBorder(isDark ? Color(red: 0.13, green: 0.14, blue: 0.15) : Color(red: 0.96, green: 0.96, blue: 0.95), lineWidth: 1.8)
                )
                .shadow(color: accentColor.opacity(0.45), radius: 2.5, y: 0.5)
                .offset(x: 15.5, y: 15.5)
        }
        .onAppear {
            withAnimation(.easeInOut(duration: 1.9).repeatForever(autoreverses: true)) {
                pulseState.value = true
            }
        }
    }
}

private struct HoverableActionButton: View {
    let icon: String
    let title: String
    var tint: Color = .primary
    var isLoading: Bool = false
    var isDestructive: Bool = false
    let isDark: Bool
    let cardSurface: Color
    let cardBorder: Color
    let cardShadow: Color
    let dangerRed: Color
    let helpText: String
    let action: () -> Void

    @StateObject private var hoverState = LocalState(false)

    private var fillColor: Color {
        let hovered = hoverState.value
        if isDestructive {
            return dangerRed.opacity(hovered ? (isDark ? 0.24 : 0.14) : (isDark ? 0.16 : 0.09))
        }
        if hovered {
            return isDark ? Color.white.opacity(0.12) : Color.white.opacity(0.95)
        }
        return cardSurface
    }

    private var borderColor: Color {
        let hovered = hoverState.value
        if isDestructive {
            return dangerRed.opacity(hovered ? 0.45 : (isDark ? 0.35 : 0.25))
        }
        if hovered {
            return isDark ? Color.white.opacity(0.20) : Color.black.opacity(0.14)
        }
        return cardBorder
    }

    var body: some View {
        Button(action: action) {
            HStack(spacing: 5) {
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
            .padding(.vertical, 7.5)
            .background(
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(fillColor)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .strokeBorder(borderColor, lineWidth: 0.8)
            )
            .shadow(color: cardShadow, radius: 2, y: 1)
            .contentShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
        }
        .buttonStyle(SnappyButtonStyle())
        .onHover { hovering in
            withAnimation(.easeOut(duration: 0.12)) {
                hoverState.value = hovering
            }
        }
        .disabled(isLoading)
        .help(helpText)
    }
}

@available(macOS 13.0, *)
private struct MatchedHeightTabStack: Layout {
    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? 400
        let childProposal = ProposedViewSize(width: width, height: nil)
        let maxHeight = subviews.map { $0.sizeThatFits(childProposal).height }.max() ?? 0
        return CGSize(width: width, height: maxHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let exactProposal = ProposedViewSize(width: bounds.width, height: bounds.height)
        for subview in subviews {
            subview.place(at: bounds.origin, anchor: .topLeading, proposal: exactProposal)
        }
    }
}

private struct SegmentedTabItemButton: View {
    let tab: ShieldTab
    let active: Bool
    let purityScore: Int?
    let scoreColor: Color
    let isDark: Bool
    let brandGradient: LinearGradient
    let namespace: Namespace.ID
    let action: () -> Void

    @StateObject private var hoverState = LocalState(false)

    var body: some View {
        let hovered = hoverState.value && !active
        let textColor: Color = active ? .white : .primary.opacity(hovered ? 0.92 : 0.72)
        let hoverFill: Color = isDark ? Color.white.opacity(0.06) : Color.black.opacity(0.045)

        Button(action: action) {
            HStack(spacing: 5) {
                Image(systemName: tab == .radar ? "shield.checkered" : "sparkle.magnifyingglass")
                    .font(.system(size: 11, weight: .semibold))
                Text(tab.rawValue)
                    .font(.system(size: 11.5, weight: .semibold))
                if tab == .purity, let score = purityScore {
                    Text("\(score)分")
                        .font(.system(size: 9.5, weight: .bold, design: .monospaced))
                        .foregroundColor(active ? .white.opacity(0.95) : scoreColor)
                        .padding(.horizontal, 4.5)
                        .padding(.vertical, 1)
                        .background(Capsule().fill(active ? Color.white.opacity(0.22) : scoreColor.opacity(0.15)))
                }
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 6.5)
            .foregroundColor(textColor)
            .background(
                ZStack {
                    if active {
                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .fill(brandGradient)
                            .shadow(color: Color(red: 0.75, green: 0.31, blue: 0.18).opacity(0.24), radius: 3, y: 1)
                            .matchedGeometryEffect(id: "activeTabPill", in: namespace)
                    } else if hovered {
                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .fill(hoverFill)
                    }
                }
            )
            .contentShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        }
        .buttonStyle(SnappyButtonStyle(scale: 0.985, pressedOpacity: 0.92))
        .onHover { hovering in
            withAnimation(.easeOut(duration: 0.12)) {
                hoverState.value = hovering
            }
        }
    }
}

private struct PrimaryLaunchButton: View {
    let desktopRunning: Bool
    let isSafe: Bool
    var isLoading: Bool = false
    let brandGradient: LinearGradient
    let action: () -> Void

    @StateObject private var hoverState = LocalState(false)

    var body: some View {
        let hovered = hoverState.value
        Button(action: action) {
            HStack(spacing: 6) {
                if isLoading {
                    ProgressView()
                        .controlSize(.small)
                        .scaleEffect(0.72)
                        .frame(width: 13, height: 13)
                } else {
                    Image(systemName: desktopRunning ? "macwindow.on.rectangle" : "play.fill")
                        .font(.system(size: 11.5, weight: .semibold))
                }
                Text(isLoading ? "正在核验出口 IP 与纯净度..." : (desktopRunning ? "聚焦 Claude 桌面版" : "安全启动 Claude 桌面版"))
                    .font(.system(size: 12.5, weight: .semibold))
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 9)
            .foregroundColor(.white)
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(isSafe ? AnyShapeStyle(brandGradient) : AnyShapeStyle(Color.gray.opacity(0.65)))
                    .brightness(hovered ? 0.04 : 0)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .strokeBorder(Color.white.opacity(hovered ? 0.28 : 0.18), lineWidth: 0.7)
            )
            .shadow(color: isSafe ? Color(red: 0.75, green: 0.31, blue: 0.18).opacity(hovered ? 0.36 : 0.28) : .clear, radius: hovered ? 6 : 4, y: 2)
            .contentShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
        }
        .buttonStyle(SnappyButtonStyle(scale: 0.98, pressedOpacity: 0.92))
        .disabled(isLoading)
        .onHover { hovering in
            withAnimation(.easeOut(duration: 0.12)) {
                hoverState.value = hovering
            }
        }
    }
}

// MARK: - SwiftUI Commercial UI v3.0

struct ShieldPopoverView: View {
    @ObservedObject var vm: ShieldViewModel
    @Environment(\.colorScheme) private var colorScheme
    @Namespace private var tabNamespace

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

    private func selectTab(_ tab: ShieldTab) {
        guard vm.selectedTab != tab else { return }
        withAnimation(.spring(response: 0.26, dampingFraction: 0.86)) {
            vm.selectedTab = tab
        }
        if tab == .purity && vm.purity == nil {
            vm.refreshPurity(silent: true)
        }
    }

    var body: some View {
        ZStack(alignment: .bottom) {
            VStack(spacing: 10) {
                headerCard
                    .padding(.horizontal, 14)

                if vm.shouldShowPopoverUpdateBanner, let info = vm.availableUpdate {
                    updateBannerCard(info)
                        .padding(.horizontal, 14)
                        .transition(.move(edge: .top).combined(with: .opacity))
                }

                segmentedTabBar
                    .padding(.horizontal, 14)

                tabContentDeck

                footerBar
                    .padding(.horizontal, 14)
            }
            .padding(.vertical, 14)

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
    }

    @ViewBuilder
    private var tabContentDeck: some View {
        let isRadar = vm.selectedTab == .radar
        let content = Group {
            radarTabContent
                .padding(.horizontal, 14)
                .padding(.vertical, 2)
                .opacity(isRadar ? 1 : 0)
                .offset(x: isRadar ? 0 : -16)
                .allowsHitTesting(isRadar)
                .accessibilityHidden(!isRadar)

            purityPanel
                .padding(.horizontal, 14)
                .padding(.vertical, 2)
                .opacity(isRadar ? 0 : 1)
                .offset(x: isRadar ? 16 : 0)
                .allowsHitTesting(!isRadar)
                .accessibilityHidden(isRadar)
        }

        if #available(macOS 13.0, *) {
            MatchedHeightTabStack {
                content
            }
            .clipped()
            .padding(.vertical, -2)
        } else {
            ZStack(alignment: .top) {
                content
            }
            .clipped()
            .padding(.vertical, -2)
        }
    }

    private var radarTabContent: some View {
        VStack(spacing: 10) {
            networkTelemetryRow
            defenseMatrixGrid
            togglesPanel
            Spacer(minLength: 0)
            actionButtonsBar
        }
    }

    // 1. Hero Status Card
    private var headerCard: some View {
        HStack(spacing: 11) {
            ShieldStatusBadge(isSafe: vm.snapshot.isSafe, accentColor: accentColor, isDark: isDark)

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
                    selectTab(vm.selectedTab == .radar ? .purity : .radar)
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
                    .contentShape(Rectangle())
                }
                .buttonStyle(SnappyButtonStyle(scale: 0.95))
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

    // 1.5 Auto-Update Banner (GitHub Releases)
    private func updateBannerCard(_ info: AppUpdateInfo) -> some View {
        let brandTerracotta = Color(red: 0.85, green: 0.43, blue: 0.27)
        return VStack(alignment: .leading, spacing: 7) {
            HStack(spacing: 8) {
                ZStack {
                    RoundedRectangle(cornerRadius: 7, style: .continuous)
                        .fill(brandTerracotta.opacity(isDark ? 0.22 : 0.13))
                        .frame(width: 24, height: 24)
                    Image(systemName: "arrow.down.circle.fill")
                        .font(.system(size: 12.5, weight: .semibold))
                        .foregroundColor(brandTerracotta)
                }

                VStack(alignment: .leading, spacing: 1.5) {
                    HStack(spacing: 5) {
                        Text("发现新版本 \(info.tagName)")
                            .font(.system(size: 11.5, weight: .bold))
                            .foregroundColor(.primary)
                        Text("GitHub")
                            .font(.system(size: 9, weight: .semibold, design: .monospaced))
                            .foregroundColor(brandTerracotta)
                            .padding(.horizontal, 5)
                            .padding(.vertical, 1)
                            .background(Capsule().fill(brandTerracotta.opacity(isDark ? 0.20 : 0.12)))
                    }
                    Group {
                        switch vm.updatePhase {
                        case .downloading(_, let progress):
                            Text("正在下载安装包… \(Int(progress * 100))%")
                        case .installing(_, let stage):
                            Text(stage)
                        default:
                            Text(info.notesSummary)
                        }
                    }
                    .font(.system(size: 9.5, weight: .medium))
                    .foregroundColor(labelColor)
                    .lineLimit(1)
                }

                Spacer(minLength: 4)

                if vm.updatePhase.isBusy {
                    ProgressView()
                        .controlSize(.mini)
                        .scaleEffect(0.85)
                } else {
                    Button(action: { vm.performUpdate(info) }) {
                        Text(info.zipDownloadURL != nil ? "立即更新" : "前往下载")
                            .font(.system(size: 10.5, weight: .semibold))
                            .foregroundColor(.white)
                            .padding(.horizontal, 9)
                            .padding(.vertical, 4.5)
                            .background(Capsule().fill(brandGradient))
                    }
                    .buttonStyle(SnappyButtonStyle(scale: 0.95))

                    Button(action: { vm.dismissUpdateBanner(info.version) }) {
                        Image(systemName: "xmark")
                            .font(.system(size: 9.5, weight: .semibold))
                            .foregroundColor(labelColor)
                            .frame(width: 20, height: 20)
                            .contentShape(Rectangle())
                    }
                    .buttonStyle(SnappyButtonStyle(scale: 0.92))
                    .help("暂不提示此版本")
                }
            }

            if case .downloading(_, let progress) = vm.updatePhase {
                GeometryReader { geo in
                    ZStack(alignment: .leading) {
                        Capsule()
                            .fill(brandTerracotta.opacity(isDark ? 0.20 : 0.14))
                            .frame(height: 4)
                        Capsule()
                            .fill(brandGradient)
                            .frame(width: max(8, geo.size.width * CGFloat(progress)), height: 4)
                            .animation(.easeOut(duration: 0.18), value: progress)
                    }
                }
                .frame(height: 4)
            }
        }
        .padding(.horizontal, 10)
        .padding(.vertical, 8)
        .background(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(cardSurface)
                .overlay(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill(brandTerracotta.opacity(isDark ? 0.08 : 0.05))
                )
        )
        .overlay(
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .strokeBorder(brandTerracotta.opacity(isDark ? 0.36 : 0.28), lineWidth: 0.85)
        )
    }

    // 2. Segmented Tab Bar (Spring Sliding Pill)
    private var segmentedTabBar: some View {
        HStack(spacing: 4) {
            ForEach(ShieldTab.allCases, id: \.self) { tab in
                SegmentedTabItemButton(
                    tab: tab,
                    active: vm.selectedTab == tab,
                    purityScore: vm.purity?.purity_score,
                    scoreColor: purityColor(vm.purity?.purity_score ?? 100),
                    isDark: isDark,
                    brandGradient: brandGradient,
                    namespace: tabNamespace
                ) {
                    selectTab(tab)
                }
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
                title: "开机自启 & 每日自动体检",
                subtitle: vm.snapshot.defenses.daily_patrol_enabled ? "登录静默启动雷达 · 每日后台自动复检防线" : "登录静默启动状态栏保护雷达",
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
                .contentShape(Capsule())
            }
            .buttonStyle(SnappyButtonStyle(scale: 0.94, pressedOpacity: 0.95))
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
        VStack(spacing: 8.5) {
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
                            .animation(.spring(response: 0.45, dampingFraction: 0.82), value: p.purity_score)
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
                VStack(spacing: 4.5) {
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
                        .padding(.vertical, 5)
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

            Spacer(minLength: 0)

            HStack(spacing: 8) {
                secondaryActionButton(
                    icon: "sparkle.magnifyingglass",
                    title: vm.isAuditing ? "全面体检中..." : "重新全面体检",
                    isLoading: vm.isAuditing,
                    help: "复测多源 IP 纯净度、DNS/IPv6 泄露，并自动巡检修复本地防线"
                ) {
                    vm.runFullCheckup()
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
            PrimaryLaunchButton(
                desktopRunning: vm.snapshot.desktopRunning,
                isSafe: vm.snapshot.isSafe,
                isLoading: vm.isCheckingLaunch,
                brandGradient: brandGradient
            ) {
                vm.launchClaudeSafe()
            }

            HStack(spacing: 7) {
                secondaryActionButton(
                    icon: "arrow.clockwise",
                    title: vm.isRefreshing ? "测速中" : "重新测速",
                    isLoading: vm.isRefreshing,
                    help: "使用 Rust 内核重新测量三点出口 IP 与 Anthropic API 真实 1-RTT"
                ) {
                    vm.refresh(force: true)
                }

                secondaryActionButton(
                    icon: "sparkle.magnifyingglass",
                    title: vm.isAuditing ? "体检中" : "全面体检",
                    isLoading: vm.isAuditing,
                    help: "执行 IP 纯净度、DNS/IPv6 泄露与本地防线全量体检（含自动修复）"
                ) {
                    vm.runFullCheckup()
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
        HoverableActionButton(
            icon: icon,
            title: title,
            tint: tint,
            isLoading: isLoading,
            isDestructive: isDestructive,
            isDark: isDark,
            cardSurface: cardSurface,
            cardBorder: cardBorder,
            cardShadow: cardShadow,
            dangerRed: dangerRed,
            helpText: help,
            action: action
        )
    }

    // 8. Footer
    private var footerBar: some View {
        HStack(spacing: 8) {
            Text("\(AppReleaseConfig.shortDisplayVersion) · 更新 \(vm.snapshot.checked_at)")
                .font(.system(size: 10, weight: .medium, design: .monospaced))
                .foregroundColor(labelColor)
                .lineLimit(1)
            Spacer(minLength: 4)
            Button(action: {
                let target: ShieldDashboardSection = vm.selectedTab == .purity ? .purity : .radar
                vm.openDashboard(section: target, isFirstRun: false)
            }) {
                HStack(spacing: 4) {
                    Image(systemName: "macwindow")
                        .font(.system(size: 9.5, weight: .semibold))
                    Text("控制台")
                        .font(.system(size: 10.5, weight: .semibold))
                }
                .foregroundColor(Color(red: 0.80, green: 0.41, blue: 0.27))
                .padding(.horizontal, 8)
                .padding(.vertical, 3)
                .background(
                    Capsule().fill(Color(red: 0.80, green: 0.41, blue: 0.27).opacity(isDark ? 0.18 : 0.10))
                )
            }
            .buttonStyle(SnappyButtonStyle(scale: 0.95))
            .help("打开独立控制台窗口（支持拖动、缩放与收至状态栏）")

            Button(action: { vm.openSetupWizard(isFirstRun: false) }) {
                HStack(spacing: 4) {
                    ZStack(alignment: .topTrailing) {
                        Image(systemName: "gearshape.fill")
                            .font(.system(size: 10, weight: .semibold))
                        if vm.availableUpdate != nil {
                            Circle()
                                .fill(Color(red: 0.80, green: 0.41, blue: 0.27))
                                .frame(width: 5.5, height: 5.5)
                                .offset(x: 2.5, y: -2)
                        }
                    }
                    Text("防护设置")
                        .font(.system(size: 10.5, weight: .semibold))
                }
                .foregroundColor(labelColor)
            }
            .buttonStyle(SnappyButtonStyle(scale: 0.95))
            .help("打开控制台防护设置：管理出口 IP 白名单、时区对齐、自动更新与卸载还原")
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
                Text("Claude Shield \(AppReleaseConfig.shortDisplayVersion) Rust · \(vm.snapshot.checked_at)")
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

// MARK: - Launch Guard Interception Modal (IP Change / Low Purity)

@MainActor
private final class LaunchGuardState: ObservableObject {
    @Published var context: LaunchGuardContext
    @Published var isRechecking: Bool = false
    @Published var passedAndLaunching: Bool = false

    init(context: LaunchGuardContext) {
        self.context = context
    }
}

private struct LaunchGuardView: View {
    @ObservedObject var state: LaunchGuardState
    let onCancel: () -> Void
    let onRecheck: () -> Void
    let onForceLaunch: () -> Void

    @Environment(\.colorScheme) private var colorScheme
    @StateObject private var forceHover = LocalState(false)
    @StateObject private var cancelHover = LocalState(false)
    @StateObject private var recheckHover = LocalState(false)

    private var isDark: Bool { colorScheme == .dark }
    private var ctx: LaunchGuardContext { state.context }

    private var safeGreen: Color {
        isDark ? Color(red: 0.22, green: 0.84, blue: 0.60) : Color(red: 0.04, green: 0.54, blue: 0.36)
    }
    private var dangerRed: Color {
        isDark ? Color(red: 0.98, green: 0.40, blue: 0.42) : Color(red: 0.84, green: 0.16, blue: 0.16)
    }
    private var warnAmber: Color {
        isDark ? Color(red: 0.98, green: 0.72, blue: 0.24) : Color(red: 0.78, green: 0.42, blue: 0.04)
    }
    private var accentColor: Color {
        if state.passedAndLaunching { return safeGreen }
        return ctx.isCritical ? dangerRed : warnAmber
    }
    private var cardSurface: Color {
        isDark ? Color.white.opacity(0.065) : Color.white.opacity(0.76)
    }
    private var cardBorder: Color {
        isDark ? Color.white.opacity(0.11) : Color.black.opacity(0.08)
    }
    private var labelColor: Color {
        isDark ? Color.white.opacity(0.62) : Color.black.opacity(0.56)
    }

    private func purityColor(_ score: Int) -> Color {
        if score >= ctx.threshold { return safeGreen }
        if score >= 60 { return warnAmber }
        return dangerRed
    }

    var body: some View {
        ZStack(alignment: .top) {
            VisualEffectView(material: .hudWindow, blendingMode: .behindWindow)

            // Subtle ambient top glow matching severity
            LinearGradient(
                colors: [
                    accentColor.opacity(isDark ? 0.22 : 0.13),
                    accentColor.opacity(0.0)
                ],
                startPoint: .top,
                endPoint: .bottom
            )
            .frame(height: 110)
            .allowsHitTesting(false)

            VStack(spacing: 12) {
                headerSection

                if ctx.ipChangedFromLast || !ctx.gateOK {
                    ipComparisonCard
                }

                if let p = ctx.purity {
                    puritySummaryCard(p)
                }

                footerActionBar
            }
            .padding(18)
        }
        .frame(width: 432)
        .fixedSize(horizontal: false, vertical: true)
        .clipShape(RoundedRectangle(cornerRadius: 18, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 18, style: .continuous)
                .strokeBorder(
                    LinearGradient(
                        colors: [
                            accentColor.opacity(isDark ? 0.55 : 0.38),
                            isDark ? Color.white.opacity(0.14) : Color.black.opacity(0.10)
                        ],
                        startPoint: .top,
                        endPoint: .bottom
                    ),
                    lineWidth: 1
                )
        )
        .shadow(color: Color.black.opacity(isDark ? 0.55 : 0.22), radius: 24, y: 12)
    }

    private var headerSection: some View {
        HStack(alignment: .top, spacing: 12) {
            ShieldStatusBadge(
                isSafe: state.passedAndLaunching,
                accentColor: accentColor,
                isDark: isDark
            )

            VStack(alignment: .leading, spacing: 4) {
                HStack(spacing: 7) {
                    Text(state.passedAndLaunching ? "安全校验已通过" : ctx.headline)
                        .font(.system(size: 15, weight: .bold, design: .rounded))
                        .foregroundColor(.primary)

                    Text(state.passedAndLaunching ? "正在启动" : ctx.badgeText)
                        .font(.system(size: 9.5, weight: .bold))
                        .foregroundColor(accentColor)
                        .padding(.horizontal, 7)
                        .padding(.vertical, 2.5)
                        .background(Capsule().fill(accentColor.opacity(isDark ? 0.22 : 0.13)))
                        .overlay(Capsule().strokeBorder(accentColor.opacity(0.35), lineWidth: 0.6))
                }

                Text(state.passedAndLaunching ? "出口 IP 与纯净度均满足安全标准，正在安全拉起 Claude 桌面版..." : ctx.subtitle)
                    .font(.system(size: 11.5, weight: .medium))
                    .foregroundColor(labelColor)
                    .fixedSize(horizontal: false, vertical: true)
                    .lineSpacing(2)
            }

            Spacer(minLength: 4)

            Button(action: onCancel) {
                Image(systemName: "xmark")
                    .font(.system(size: 10, weight: .bold))
                    .foregroundColor(labelColor)
                    .frame(width: 22, height: 22)
                    .background(Circle().fill(isDark ? Color.white.opacity(0.08) : Color.black.opacity(0.06)))
            }
            .buttonStyle(SnappyButtonStyle(scale: 0.92))
            .help("关闭并取消启动 (Esc)")
        }
    }

    private var ipComparisonCard: some View {
        VStack(alignment: .leading, spacing: 9) {
            HStack(spacing: 6) {
                Image(systemName: "network.badge.shield.half.filled")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(accentColor)
                Text(ctx.ipChangedFromLast ? "出口 IP 变化对比" : "出口通道一致性异常")
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(.primary.opacity(0.88))
                Spacer()
                if let p = ctx.purity, p.country_code != "??" {
                    Text("\(p.country_code) · \(p.city)")
                        .font(.system(size: 10, weight: .semibold, design: .monospaced))
                        .foregroundColor(labelColor)
                } else if let loc = ctx.claudeLoc {
                    Text("CF Edge: \(loc)")
                        .font(.system(size: 10, weight: .semibold, design: .monospaced))
                        .foregroundColor(labelColor)
                }
            }

            if ctx.ipChangedFromLast, let lastIP = ctx.lastLaunchIP {
                HStack(spacing: 8) {
                    ipChip(title: "上次启动 IP", value: lastIP, tint: labelColor, highlighted: false)
                    Image(systemName: "arrow.right")
                        .font(.system(size: 11, weight: .bold))
                        .foregroundColor(accentColor)
                    ipChip(title: "当前出口 IP", value: ctx.currentIP, tint: accentColor, highlighted: true)
                }
            }

            if !ctx.gateOK {
                HStack(spacing: 6) {
                    miniChannelBadge(label: "白名单", value: ctx.expectedIP, ok: true)
                    miniChannelBadge(label: "Proxy", value: ctx.currentIP, ok: ctx.currentIP == ctx.expectedIP)
                    miniChannelBadge(label: "TUN", value: ctx.tunIP, ok: ctx.tunIP == ctx.expectedIP)
                }
            }
        }
        .padding(11)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(cardSurface))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.8))
    }

    private func ipChip(title: String, value: String, tint: Color, highlighted: Bool) -> some View {
        VStack(alignment: .leading, spacing: 2.5) {
            Text(title)
                .font(.system(size: 9.5, weight: .medium))
                .foregroundColor(labelColor)
            Text(value)
                .font(.system(size: 11.5, weight: .bold, design: .monospaced))
                .foregroundColor(highlighted ? tint : .primary.opacity(0.88))
                .lineLimit(1)
                .minimumScaleFactor(0.8)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 9)
        .padding(.vertical, 7)
        .background(
            RoundedRectangle(cornerRadius: 9, style: .continuous)
                .fill(highlighted ? tint.opacity(isDark ? 0.16 : 0.10) : (isDark ? Color.white.opacity(0.04) : Color.black.opacity(0.035)))
        )
        .overlay(
            RoundedRectangle(cornerRadius: 9, style: .continuous)
                .strokeBorder(highlighted ? tint.opacity(0.38) : cardBorder, lineWidth: 0.7)
        )
    }

    private func miniChannelBadge(label: String, value: String, ok: Bool) -> some View {
        let color = ok ? safeGreen : dangerRed
        return VStack(alignment: .leading, spacing: 1.5) {
            HStack(spacing: 3.5) {
                Circle().fill(color).frame(width: 5, height: 5)
                Text(label)
                    .font(.system(size: 9, weight: .semibold))
                    .foregroundColor(labelColor)
            }
            Text(value)
                .font(.system(size: 10, weight: .semibold, design: .monospaced))
                .foregroundColor(ok ? .primary.opacity(0.85) : dangerRed)
                .lineLimit(1)
                .minimumScaleFactor(0.75)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .padding(.horizontal, 7)
        .padding(.vertical, 5.5)
        .background(RoundedRectangle(cornerRadius: 8, style: .continuous).fill(color.opacity(isDark ? 0.10 : 0.06)))
        .overlay(RoundedRectangle(cornerRadius: 8, style: .continuous).strokeBorder(color.opacity(0.24), lineWidth: 0.6))
    }

    private func puritySummaryCard(_ p: PurityReport) -> some View {
        let pc = purityColor(p.purity_score)
        let riskFactors = p.factors
            .filter { $0.severity != "good" }
            .sorted { $0.penalty < $1.penalty }
            .prefix(3)

        return VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 12) {
                ZStack {
                    Circle()
                        .stroke(pc.opacity(isDark ? 0.22 : 0.16), lineWidth: 5)
                    Circle()
                        .trim(from: 0, to: CGFloat(max(0, min(100, p.purity_score))) / 100.0)
                        .stroke(pc, style: StrokeStyle(lineWidth: 5, lineCap: .round))
                        .rotationEffect(.degrees(-90))
                        .animation(.spring(response: 0.5, dampingFraction: 0.8), value: p.purity_score)
                    VStack(spacing: -1) {
                        Text("\(p.purity_score)")
                            .font(.system(size: 15, weight: .heavy, design: .rounded))
                            .foregroundColor(pc)
                        Text("\(p.grade) 级")
                            .font(.system(size: 8.5, weight: .bold))
                            .foregroundColor(labelColor)
                    }
                }
                .frame(width: 48, height: 48)

                VStack(alignment: .leading, spacing: 3) {
                    HStack(spacing: 6) {
                        Text("IP 纯净度评估")
                            .font(.system(size: 11.5, weight: .bold))
                            .foregroundColor(.primary)
                        Text("安全线 ≥ \(ctx.threshold) 分")
                            .font(.system(size: 9.5, weight: .semibold, design: .monospaced))
                            .foregroundColor(p.purity_score >= ctx.threshold ? safeGreen : pc)
                            .padding(.horizontal, 6)
                            .padding(.vertical, 1.5)
                            .background(Capsule().fill((p.purity_score >= ctx.threshold ? safeGreen : pc).opacity(isDark ? 0.18 : 0.11)))
                    }
                    Text(p.verdict)
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(.primary.opacity(0.84))
                        .lineLimit(1)
                    Text("\(p.ip_type) · \(p.asn) · \(p.isp)")
                        .font(.system(size: 10, weight: .medium))
                        .foregroundColor(labelColor)
                        .lineLimit(1)
                }
                Spacer(minLength: 0)
            }

            if !riskFactors.isEmpty {
                Divider().opacity(0.45)
                VStack(spacing: 6) {
                    ForEach(Array(riskFactors)) { f in
                        let fc = f.severity == "critical" ? dangerRed : warnAmber
                        HStack(alignment: .top, spacing: 7) {
                            Image(systemName: f.severity == "critical" ? "exclamationmark.octagon.fill" : "exclamationmark.triangle.fill")
                                .font(.system(size: 10.5, weight: .semibold))
                                .foregroundColor(fc)
                                .padding(.top, 1.5)
                            VStack(alignment: .leading, spacing: 1) {
                                Text(f.title)
                                    .font(.system(size: 10.5, weight: .semibold))
                                    .foregroundColor(.primary.opacity(0.92))
                                Text(f.detail)
                                    .font(.system(size: 9.5, weight: .regular))
                                    .foregroundColor(labelColor)
                                    .lineLimit(2)
                            }
                            Spacer(minLength: 4)
                            if f.penalty < 0 {
                                Text("\(f.penalty)")
                                    .font(.system(size: 9.5, weight: .bold, design: .monospaced))
                                    .foregroundColor(fc)
                                    .padding(.horizontal, 5)
                                    .padding(.vertical, 1.5)
                                    .background(RoundedRectangle(cornerRadius: 4, style: .continuous).fill(fc.opacity(isDark ? 0.18 : 0.11)))
                            }
                        }
                    }
                }
            }
        }
        .padding(11)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(cardSurface))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.8))
    }

    private var footerActionBar: some View {
        HStack(spacing: 8) {
            // Re-check after switching Clash node
            Button(action: onRecheck) {
                HStack(spacing: 5) {
                    if state.isRechecking {
                        ProgressView()
                            .controlSize(.mini)
                            .scaleEffect(0.8)
                            .frame(width: 11, height: 11)
                    } else {
                        Image(systemName: "arrow.clockwise")
                            .font(.system(size: 11, weight: .semibold))
                    }
                    Text(state.isRechecking ? "检测中" : "重新检测")
                        .font(.system(size: 11.5, weight: .semibold))
                }
                .foregroundColor(.primary.opacity(0.86))
                .padding(.horizontal, 11)
                .padding(.vertical, 8)
                .background(
                    RoundedRectangle(cornerRadius: 9, style: .continuous)
                        .fill(recheckHover.value ? (isDark ? Color.white.opacity(0.13) : Color.white.opacity(0.95)) : cardSurface)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 9, style: .continuous)
                        .strokeBorder(cardBorder, lineWidth: 0.8)
                )
            }
            .buttonStyle(SnappyButtonStyle())
            .disabled(state.isRechecking || state.passedAndLaunching)
            .onHover { hovering in
                withAnimation(.easeOut(duration: 0.12)) { recheckHover.value = hovering }
            }
            .help("在 Clash 切换节点后点击重新核验")

            Spacer(minLength: 4)

            // Safe default action: Cancel Launch
            Button(action: onCancel) {
                Text("取消启动")
                    .font(.system(size: 12, weight: .semibold))
                    .foregroundColor(.primary)
                    .padding(.horizontal, 15)
                    .padding(.vertical, 8)
                    .background(
                        RoundedRectangle(cornerRadius: 9, style: .continuous)
                            .fill(cancelHover.value ? (isDark ? Color.white.opacity(0.16) : Color.white) : (isDark ? Color.white.opacity(0.10) : Color.white.opacity(0.88)))
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 9, style: .continuous)
                            .strokeBorder(isDark ? Color.white.opacity(0.20) : Color.black.opacity(0.14), lineWidth: 0.8)
                    )
            }
            .buttonStyle(SnappyButtonStyle())
            .keyboardShortcut(.cancelAction)
            .disabled(state.passedAndLaunching)
            .onHover { hovering in
                withAnimation(.easeOut(duration: 0.12)) { cancelHover.value = hovering }
            }

            // Explicit Force Launch button
            Button(action: onForceLaunch) {
                HStack(spacing: 5) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 11, weight: .semibold))
                    Text("强制启动")
                        .font(.system(size: 12, weight: .bold))
                }
                .foregroundColor(.white)
                .padding(.horizontal, 14)
                .padding(.vertical, 8)
                .background(
                    RoundedRectangle(cornerRadius: 9, style: .continuous)
                        .fill(
                            LinearGradient(
                                colors: ctx.isCritical
                                    ? [Color(red: 0.88, green: 0.24, blue: 0.24), Color(red: 0.72, green: 0.14, blue: 0.16)]
                                    : [Color(red: 0.88, green: 0.52, blue: 0.14), Color(red: 0.76, green: 0.36, blue: 0.08)],
                                startPoint: .top,
                                endPoint: .bottom
                            )
                        )
                        .brightness(forceHover.value ? 0.05 : 0)
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 9, style: .continuous)
                        .strokeBorder(Color.white.opacity(forceHover.value ? 0.32 : 0.18), lineWidth: 0.7)
                )
                .shadow(color: accentColor.opacity(forceHover.value ? 0.38 : 0.25), radius: forceHover.value ? 6 : 3, y: 2)
            }
            .buttonStyle(SnappyButtonStyle())
            .disabled(state.isRechecking || state.passedAndLaunching)
            .onHover { hovering in
                withAnimation(.easeOut(duration: 0.12)) { forceHover.value = hovering }
            }
            .help("忽略本次风险拦截，仍使用硬代理与防泄露参数强行启动 Claude 桌面版")
        }
        .padding(.top, 2)
    }
}

private final class LaunchGuardPanel: NSPanel {
    var onEscape: (() -> Void)?
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
    override func cancelOperation(_ sender: Any?) {
        onEscape?()
    }
}

@MainActor
private final class LaunchGuardWindowController {
    private var panel: LaunchGuardPanel?
    private var state: LaunchGuardState?

    func show(
        context: LaunchGuardContext,
        viewModel: ShieldViewModel
    ) {
        dismiss()

        let guardState = LaunchGuardState(context: context)
        self.state = guardState

        let view = LaunchGuardView(
            state: guardState,
            onCancel: { [weak self] in
                self?.dismiss()
            },
            onRecheck: { [weak self, weak viewModel, weak guardState] in
                guard let self = self, let vm = viewModel, let st = guardState, !st.isRechecking else { return }
                st.isRechecking = true
                Task { @MainActor in
                    let fresh = await vm.evaluateLaunchGuardContext()
                    st.isRechecking = false
                    st.context = fresh
                    if let p = fresh.purity {
                        vm.purity = p
                        vm.onStatusChange?(vm.snapshot, p)
                    }
                    let stillRisky = !fresh.gateOK || fresh.ipChangedFromLast || fresh.purityBelowThreshold
                    if !stillRisky {
                        st.passedAndLaunching = true
                        DispatchQueue.main.asyncAfter(deadline: .now() + 0.65) {
                            self.dismiss()
                            vm.executeDesktopLaunch(force: false, recordIP: fresh.currentIP)
                        }
                    } else {
                        self.resizeAndCenter()
                    }
                }
            },
            onForceLaunch: { [weak self, weak viewModel, weak guardState] in
                let ip = guardState?.context.currentIP
                self?.dismiss()
                viewModel?.executeDesktopLaunch(force: true, recordIP: ip)
            }
        )

        let hc = NSHostingController(rootView: view)
        let panel = LaunchGuardPanel(
            contentRect: NSRect(x: 0, y: 0, width: 432, height: 340),
            styleMask: [.borderless, .fullSizeContentView],
            backing: .buffered,
            defer: false
        )
        panel.contentViewController = hc
        panel.isOpaque = false
        panel.backgroundColor = .clear
        panel.hasShadow = true
        panel.level = .floating
        panel.isMovableByWindowBackground = true
        panel.collectionBehavior = [.canJoinAllSpaces, .fullScreenAuxiliary]
        panel.hidesOnDeactivate = false
        panel.onEscape = { [weak self] in self?.dismiss() }

        self.panel = panel
        resizeAndCenter()
        panel.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    private func resizeAndCenter() {
        guard let panel = panel, let contentView = panel.contentView else { return }
        contentView.layoutSubtreeIfNeeded()
        let fitting = contentView.fittingSize
        if fitting.width > 0 && fitting.height > 0 {
            panel.setContentSize(NSSize(width: 432, height: ceil(fitting.height)))
        }
        if let screen = NSScreen.main ?? NSScreen.screens.first {
            let vf = screen.visibleFrame
            let sz = panel.frame.size
            let origin = NSPoint(
                x: vf.midX - sz.width / 2.0,
                y: vf.midY - sz.height / 2.0 + 24
            )
            panel.setFrameOrigin(origin)
        } else {
            panel.center()
        }
    }

    func dismiss() {
        panel?.orderOut(nil)
        panel?.close()
        panel = nil
        state = nil
    }
}

// MARK: - First-Run Onboarding & Protection Setup Window (Zero-CLI One-Click Setup + Uninstall)

@MainActor
private final class SetupWizardState: ObservableObject {
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

    init(isFirstRun: Bool, currentSnapshot: TelemetrySnapshot) {
        self.isFirstRun = isFirstRun
        if currentSnapshot.expected_ip != "未配置" && currentSnapshot.expected_ip != "检测中..." {
            self.expectedIP = currentSnapshot.expected_ip
        }
        self.proxyPortText = String(currentSnapshot.proxy_port)
        self.targetTZ = currentSnapshot.target_tz
        self.enableAutostart = isFirstRun ? true : currentSnapshot.defenses.login_item_enabled
        self.enableDailyPatrol = isFirstRun ? true : currentSnapshot.defenses.daily_patrol_enabled
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
        guard !ip.isEmpty, ip != "未配置" else {
            errorMessage = "请先填写或自动识别您的专属白名单出口 IP。"
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
                    self.errorMessage = "本地防护部署失败，请确认应用具有读写用户目录权限。"
                }
            }
        }
    }
}

private struct StyledSettingsInput: View {
    let placeholder: String
    @Binding var text: String
    let isDark: Bool
    var isMonospaced: Bool = true
    @FocusState private var isFocused: Bool

    var body: some View {
        let accent = Color(red: 0.85, green: 0.43, blue: 0.27)
        TextField(placeholder, text: $text)
            .textFieldStyle(.plain)
            .focused($isFocused)
            .font(.system(size: 13.5, weight: .medium, design: isMonospaced ? .monospaced : .default))
            .foregroundColor(.primary)
            .padding(.horizontal, 12)
            .frame(height: 38)
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(isDark ? Color.black.opacity(0.28) : Color.white.opacity(0.92))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .strokeBorder(
                        isFocused ? accent.opacity(0.85) : (isDark ? Color.white.opacity(0.13) : Color.black.opacity(0.11)),
                        lineWidth: isFocused ? 1.5 : 0.9
                    )
            )
            .shadow(color: isFocused ? accent.opacity(0.16) : .clear, radius: 4, y: 0)
            .animation(.easeOut(duration: 0.14), value: isFocused)
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
private final class ShieldDashboardNavState: ObservableObject {
    @Published var selectedSection: ShieldDashboardSection = .radar
}

private struct ShieldDashboardView: View {
    @ObservedObject var nav: ShieldDashboardNavState
    @ObservedObject var state: SetupWizardState
    @ObservedObject var vm: ShieldViewModel
    let onHideToMenuBar: () -> Void
    let onLaunchClaude: () -> Void
    let onUninstall: () -> Void
    let onApplied: () -> Void

    @Environment(\.colorScheme) private var colorScheme
    @Namespace private var navNamespace
    @StateObject private var detectHover = LocalState(false)
    @StateObject private var uninstallHover = LocalState(false)
    @StateObject private var saveHover = LocalState(false)
    @StateObject private var updateHover = LocalState(false)
    @StateObject private var hideBarHover = LocalState(false)
    @StateObject private var launchHover = LocalState(false)
    @StateObject private var pulseDot = LocalState(false)

    private var isDark: Bool { colorScheme == .dark }

    // Serene, eye-comfortable Anthropic Editorial palette (low visual weight)
    private var canvasBg: Color {
        isDark ? Color(red: 0.095, green: 0.093, blue: 0.090) : Color(red: 0.969, green: 0.961, blue: 0.945)
    }
    private var sidebarBg: Color {
        isDark ? Color(red: 0.118, green: 0.115, blue: 0.111) : Color(red: 0.941, green: 0.931, blue: 0.912)
    }
    private var brandTerracotta: Color {
        isDark ? Color(red: 0.86, green: 0.48, blue: 0.34) : Color(red: 0.80, green: 0.41, blue: 0.27)
    }
    private var safeGreen: Color {
        isDark ? Color(red: 0.26, green: 0.78, blue: 0.58) : Color(red: 0.11, green: 0.53, blue: 0.39)
    }
    private var dangerRed: Color {
        isDark ? Color(red: 0.94, green: 0.42, blue: 0.44) : Color(red: 0.80, green: 0.22, blue: 0.22)
    }
    private var warnAmber: Color {
        isDark ? Color(red: 0.94, green: 0.70, blue: 0.28) : Color(red: 0.75, green: 0.44, blue: 0.08)
    }
    private var accentColor: Color {
        vm.snapshot.isSafe ? safeGreen : dangerRed
    }
    private var cardSurface: Color {
        isDark ? Color(red: 0.145, green: 0.142, blue: 0.137) : Color.white
    }
    private var cardBorder: Color {
        isDark ? Color.white.opacity(0.075) : Color.black.opacity(0.058)
    }
    private var cardShadow: Color {
        isDark ? Color.black.opacity(0.22) : Color.black.opacity(0.032)
    }
    private var dividerColor: Color {
        isDark ? Color.white.opacity(0.065) : Color.black.opacity(0.055)
    }
    private var inkPrimary: Color {
        isDark ? Color(red: 0.94, green: 0.93, blue: 0.91) : Color(red: 0.15, green: 0.145, blue: 0.135)
    }
    private var labelColor: Color {
        isDark ? Color.white.opacity(0.56) : Color(red: 0.44, green: 0.42, blue: 0.39)
    }
    private var subtleLabelColor: Color {
        isDark ? Color.white.opacity(0.40) : Color(red: 0.58, green: 0.55, blue: 0.51)
    }
    private var brandGradient: LinearGradient {
        LinearGradient(
            colors: [
                Color(red: 0.83, green: 0.44, blue: 0.30),
                Color(red: 0.74, green: 0.35, blue: 0.22)
            ],
            startPoint: .top,
            endPoint: .bottom
        )
    }

    private let tzPresets: [(String, String)] = [
        ("洛杉矶", "America/Los_Angeles"),
        ("纽约", "America/New_York"),
        ("东京", "Asia/Tokyo"),
        ("新加坡", "Asia/Singapore"),
        ("伦敦", "Europe/London"),
        ("法兰克福", "Europe/Berlin")
    ]

    private let builtinTags: [String] = [
        "CLI 门禁", "OAuth 拦截", "Seatbelt 沙盒", "零遥测", "IPv4-First"
    ]

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

    // Header stays crisp and minimal (no verbose greeting/description subtitles)

    var body: some View {
        HStack(spacing: 0) {
            sidebarColumn
                .frame(width: 232)

            Rectangle()
                .fill(dividerColor)
                .frame(width: 1)

            mainCanvasColumn
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .background(canvasBg.ignoresSafeArea())
        .frame(minWidth: 820, maxWidth: .infinity, minHeight: 580, maxHeight: .infinity)
        .onAppear {
            if state.isFirstRun || state.expectedIP.isEmpty {
                state.runAutoDetect()
            }
            if nav.selectedSection == .purity && vm.purity == nil {
                vm.refreshPurity(silent: true)
            }
            withAnimation(.easeInOut(duration: 2.2).repeatForever(autoreverses: true)) {
                pulseDot.value = true
            }
        }
        .onChange(of: nav.selectedSection) { newSection in
            if newSection == .purity && vm.purity == nil {
                vm.refreshPurity(silent: true)
            }
            if newSection == .settings && (state.isFirstRun || state.expectedIP.isEmpty) {
                state.runAutoDetect()
            }
        }
    }

    // MARK: - Sidebar (Light & Calm)

    private var sidebarColumn: some View {
        ZStack {
            sidebarBg.ignoresSafeArea()

            VStack(alignment: .leading, spacing: 16) {
                // Brand Identity — strictly aligned on H1 baseline (y: 34..78, height 44) with right topBarHeader
                HStack(spacing: 11) {
                    ShieldStatusBadge(
                        isSafe: vm.snapshot.isSafe || state.setupReport != nil,
                        accentColor: vm.snapshot.isSafe ? safeGreen : (state.isFirstRun ? brandTerracotta : dangerRed),
                        isDark: isDark
                    )
                    .scaleEffect(0.92)
                    .frame(width: 42, height: 42)

                    VStack(alignment: .leading, spacing: 3) {
                        Text("Claude Shield")
                            .font(.system(size: 15.5, weight: .bold, design: .rounded))
                            .foregroundColor(inkPrimary)
                        HStack(spacing: 5.5) {
                            Text(AppReleaseConfig.shortDisplayVersion)
                                .font(.system(size: 10.5, weight: .semibold, design: .monospaced))
                                .foregroundColor(brandTerracotta)
                                .padding(.horizontal, 6)
                                .padding(.vertical, 1.5)
                                .background(Capsule().fill(brandTerracotta.opacity(isDark ? 0.18 : 0.10)))
                            Text("Console")
                                .font(.system(size: 10.5, weight: .medium, design: .rounded))
                                .foregroundColor(subtleLabelColor)
                        }
                    }
                    Spacer(minLength: 0)
                }
                .frame(height: 44)
                .padding(.top, 34)
                .padding(.horizontal, 16)

                // Navigation Items — starts on exact H2 baseline (y: 94) matching right content top
                VStack(spacing: 6) {
                    ForEach(ShieldDashboardSection.allCases) { section in
                        sidebarNavButton(section)
                    }
                }
                .padding(.horizontal, 12)

                Spacer(minLength: 10)

                // Unified, Airy Bottom Guard Dock (eliminates heavy brick button)
                VStack(alignment: .leading, spacing: 0) {
                    VStack(alignment: .leading, spacing: 6.5) {
                        HStack(spacing: 6.5) {
                            Circle()
                                .fill(accentColor)
                                .frame(width: 7.5, height: 7.5)
                                .opacity(pulseDot.value ? 1.0 : 0.42)
                            Text(vm.snapshot.isSafe ? "静谧守护中" : "防线需关注")
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundColor(accentColor)
                            Spacer()
                            Text("\(vm.snapshot.defenseScore)/8")
                                .font(.system(size: 11, weight: .semibold, design: .monospaced))
                                .foregroundColor(subtleLabelColor)
                        }

                        Text(vm.snapshot.expected_ip)
                            .font(.system(size: 13, weight: .bold, design: .monospaced))
                            .foregroundColor(inkPrimary.opacity(0.88))
                            .lineLimit(1)

                        Text("\(vm.snapshot.region_short) · 更新 \(vm.snapshot.checked_at)")
                            .font(.system(size: 11, weight: .medium, design: .monospaced))
                            .foregroundColor(subtleLabelColor)
                            .lineLimit(1)
                    }
                    .padding(14)

                    Divider().overlay(dividerColor).padding(.horizontal, 10)

                    Button(action: onLaunchClaude) {
                        HStack(spacing: 6.5) {
                            if vm.isCheckingLaunch {
                                ProgressView()
                                    .controlSize(.mini)
                                    .scaleEffect(0.78)
                            } else {
                                Image(systemName: vm.snapshot.desktopRunning ? "macwindow.on.rectangle" : "play.fill")
                                    .font(.system(size: 11, weight: .semibold))
                            }
                            Text(
                                vm.isCheckingLaunch
                                    ? "安全校验中..."
                                    : (vm.snapshot.desktopRunning ? "切回 Claude 桌面版" : "安全启动 Claude")
                            )
                            .font(.system(size: 13, weight: .semibold))
                            .lineLimit(1)
                        }
                        .frame(maxWidth: .infinity)
                        .frame(height: 38)
                        .foregroundColor(brandTerracotta)
                        .background(
                            RoundedRectangle(cornerRadius: 9, style: .continuous)
                                .fill(
                                    brandTerracotta.opacity(
                                        launchHover.value
                                            ? (isDark ? 0.22 : 0.14)
                                            : (isDark ? 0.14 : 0.085)
                                    )
                                )
                        )
                    }
                    .buttonStyle(SnappyButtonStyle(scale: 0.98))
                    .onHover { h in withAnimation(.easeOut(duration: 0.12)) { launchHover.value = h } }
                    .disabled(vm.isCheckingLaunch)
                    .padding(9)
                }
                .background(
                    RoundedRectangle(cornerRadius: 13, style: .continuous)
                        .fill(cardSurface.opacity(isDark ? 0.86 : 0.90))
                )
                .overlay(
                    RoundedRectangle(cornerRadius: 13, style: .continuous)
                        .strokeBorder(cardBorder, lineWidth: 0.75)
                )
                .shadow(color: cardShadow, radius: 5, y: 1.5)
                .padding(.horizontal, 12)
                .padding(.bottom, 20)
            }
        }
    }

    private func sidebarNavButton(_ section: ShieldDashboardSection) -> some View {
        let active = nav.selectedSection == section
        return Button(action: {
            withAnimation(.spring(response: 0.26, dampingFraction: 0.86)) {
                nav.selectedSection = section
            }
        }) {
            HStack(spacing: 10.5) {
                RoundedRectangle(cornerRadius: 2, style: .continuous)
                    .fill(active ? brandTerracotta : Color.clear)
                    .frame(width: 3, height: 22)

                Image(systemName: section.icon)
                    .font(.system(size: 15, weight: active ? .semibold : .medium))
                    .foregroundColor(active ? brandTerracotta : labelColor)
                    .frame(width: 22, alignment: .center)

                VStack(alignment: .leading, spacing: 2) {
                    Text(section.title)
                        .font(.system(size: 13.5, weight: active ? .semibold : .medium))
                        .foregroundColor(active ? inkPrimary : inkPrimary.opacity(0.76))
                    Text(section.caption)
                        .font(.system(size: 11, weight: .regular))
                        .foregroundColor(subtleLabelColor)
                        .lineLimit(1)
                }

                Spacer(minLength: 4)

                if section == .purity, let p = vm.purity {
                    let pc = purityColor(p.purity_score)
                    Text("\(p.purity_score)")
                        .font(.system(size: 11, weight: .bold, design: .monospaced))
                        .foregroundColor(pc)
                        .padding(.horizontal, 6.5)
                        .padding(.vertical, 2.5)
                        .background(Capsule().fill(pc.opacity(isDark ? 0.18 : 0.10)))
                } else if section == .settings, vm.availableUpdate != nil {
                    Circle()
                        .fill(brandTerracotta)
                        .frame(width: 7, height: 7)
                }
            }
            .padding(.leading, 7)
            .padding(.trailing, 11)
            .padding(.vertical, 10.5)
            .contentShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
            .background(
                ZStack {
                    if active {
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .fill(cardSurface)
                            .overlay(
                                RoundedRectangle(cornerRadius: 10, style: .continuous)
                                    .strokeBorder(cardBorder, lineWidth: 0.7)
                            )
                            .shadow(color: cardShadow, radius: 5, y: 1.5)
                            .matchedGeometryEffect(id: "dashboardNavPill", in: navNamespace)
                    }
                }
            )
        }
        .buttonStyle(.plain)
    }

    // MARK: - Main Canvas (Airy, Balanced, Zero Clutter)

    private var mainCanvasColumn: some View {
        ZStack(alignment: .bottom) {
            canvasBg.ignoresSafeArea()

            // Whisper-soft ambient top wash
            VStack(spacing: 0) {
                LinearGradient(
                    colors: [
                        (vm.snapshot.isSafe ? safeGreen : brandTerracotta).opacity(isDark ? 0.08 : 0.045),
                        Color.clear
                    ],
                    startPoint: .top,
                    endPoint: .bottom
                )
                .frame(height: 140)
                Spacer()
            }
            .allowsHitTesting(false)
            .ignoresSafeArea()

            GeometryReader { geo in
                let contentWidth = max(480, geo.size.width - 48)
                let useThreeMatrixCols = contentWidth >= 560

                VStack(spacing: 0) {
                    topBarHeader

                    ScrollView(.vertical, showsIndicators: false) {
                        VStack(alignment: .leading, spacing: 14) {
                            if shouldShowSettingsUpdateCard && nav.selectedSection != .settings {
                                settingsUpdateCard
                            }

                            switch nav.selectedSection {
                            case .radar:
                                radarSectionContent(useThreeMatrixCols: useThreeMatrixCols)
                            case .purity:
                                puritySectionContent(wide: useThreeMatrixCols)
                            case .settings:
                                settingsSectionContent
                            }
                        }
                        .padding(.horizontal, 24)
                        .padding(.top, 0)
                        .padding(.bottom, 18)
                        .frame(maxWidth: 1040, alignment: .leading)
                        .frame(maxWidth: .infinity, alignment: .center)
                    }
                }
            }

            if let toast = vm.toastMessage {
                Text(toast)
                    .font(.system(size: 11.5, weight: .semibold))
                    .foregroundColor(.white)
                    .padding(.horizontal, 15)
                    .padding(.vertical, 7.5)
                    .background(Capsule().fill(Color.black.opacity(0.84)))
                    .shadow(color: .black.opacity(0.20), radius: 8, y: 3)
                    .padding(.bottom, 16)
                    .transition(.move(edge: .bottom).combined(with: .opacity))
            }
        }
    }

    private var topBarHeader: some View {
        // Strictly aligned on H1 baseline (y: 34..78, height 44) + 16pt gap to H2 (y: 94)
        HStack(alignment: .center, spacing: 12) {
            HStack(spacing: 8) {
                Text(state.isFirstRun && nav.selectedSection == .settings ? "欢迎使用 Claude Shield" : nav.selectedSection.title)
                    .font(.system(size: 20, weight: .bold, design: .rounded))
                    .foregroundColor(inkPrimary)

                if !vm.snapshot.isSafe {
                    Text("异常警戒")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(dangerRed)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 3)
                        .background(Capsule().fill(dangerRed.opacity(isDark ? 0.18 : 0.10)))
                }

                if nav.selectedSection == .settings && !state.isFirstRun {
                    updateCheckPill
                }
            }

            Spacer(minLength: 12)

            HStack(spacing: 8) {
                Button(action: { vm.refresh(force: true) }) {
                    HStack(spacing: 5.5) {
                        if vm.isRefreshing {
                            ProgressView().controlSize(.mini).scaleEffect(0.76)
                        } else {
                            Image(systemName: "arrow.clockwise")
                                .font(.system(size: 11, weight: .semibold))
                        }
                        Text(vm.isRefreshing ? "测速中" : "重新测速")
                            .font(.system(size: 12, weight: .medium))
                    }
                    .foregroundColor(inkPrimary.opacity(0.82))
                    .padding(.horizontal, 12)
                    .frame(height: 32)
                    .background(Capsule().fill(cardSurface))
                    .overlay(Capsule().strokeBorder(cardBorder, lineWidth: 0.75))
                }
                .buttonStyle(SnappyButtonStyle(scale: 0.96))
                .help("重新探测双通道出口 IP 与 Anthropic API 延迟")

                Button(action: onHideToMenuBar) {
                    HStack(spacing: 5.5) {
                        Image(systemName: "menubar.arrow.up.rectangle")
                            .font(.system(size: 11.5, weight: .medium))
                        Text("收至状态栏")
                            .font(.system(size: 12, weight: .medium))
                    }
                    .foregroundColor(hideBarHover.value ? brandTerracotta : inkPrimary.opacity(0.82))
                    .padding(.horizontal, 12.5)
                    .frame(height: 32)
                    .background(
                        Capsule().fill(
                            hideBarHover.value
                                ? brandTerracotta.opacity(isDark ? 0.16 : 0.09)
                                : cardSurface
                        )
                    )
                    .overlay(
                        Capsule().strokeBorder(
                            hideBarHover.value ? brandTerracotta.opacity(0.32) : cardBorder,
                            lineWidth: 0.75
                        )
                    )
                }
                .buttonStyle(SnappyButtonStyle(scale: 0.96))
                .onHover { h in withAnimation(.easeOut(duration: 0.12)) { hideBarHover.value = h } }
                .help("隐藏控制台至顶部状态栏继续守护（⌘W）")
            }
        }
        .frame(height: 44)
        .padding(.horizontal, 24)
        .padding(.top, 34)
        .padding(.bottom, 16)
    }

    private var updateCheckPill: some View {
        Button(action: {
            if let info = vm.availableUpdate, !vm.updatePhase.isBusy {
                vm.performUpdate(info)
            } else {
                vm.checkForUpdates(manual: true)
            }
        }) {
            HStack(spacing: 4) {
                if vm.updatePhase.isBusy {
                    ProgressView().controlSize(.mini).scaleEffect(0.72)
                } else if case .upToDate = vm.updatePhase {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 10, weight: .semibold))
                } else if vm.availableUpdate != nil {
                    Image(systemName: "arrow.down.circle.fill")
                        .font(.system(size: 10, weight: .semibold))
                } else {
                    Image(systemName: "arrow.triangle.2.circlepath")
                        .font(.system(size: 10, weight: .semibold))
                }
                Text(updatePillLabel)
                    .font(.system(size: 10.5, weight: .semibold))
            }
            .foregroundColor(updatePillForeground)
            .padding(.horizontal, 8.5)
            .padding(.vertical, 3)
            .background(Capsule().fill(updatePillBackground))
        }
        .buttonStyle(SnappyButtonStyle(scale: 0.96))
        .onHover { h in withAnimation(.easeOut(duration: 0.12)) { updateHover.value = h } }
        .disabled(vm.updatePhase.isBusy)
        .help("从 GitHub Releases 检查并安装最新版本")
    }

    // MARK: - Section 1: 实时雷达 (Precision Grid, Even Weight)

    private func radarSectionContent(useThreeMatrixCols: Bool) -> some View {
        let twoEqualCols = [
            GridItem(.flexible(), spacing: 14),
            GridItem(.flexible(), spacing: 14)
        ]
        let matrixCols = Array(
            repeating: GridItem(.flexible(), spacing: 14),
            count: useThreeMatrixCols ? 3 : 2
        )

        return VStack(alignment: .leading, spacing: 18) {
            // 1. Hero Status Banner (16pt outer radius)
            HStack(spacing: 16) {
                ShieldStatusBadge(isSafe: vm.snapshot.isSafe, accentColor: accentColor, isDark: isDark)

                VStack(alignment: .leading, spacing: 5) {
                    HStack(spacing: 8.5) {
                        Text(vm.snapshot.isSafe ? "SHIELD ARMED" : "IP 异常预警")
                            .font(.system(size: 18.5, weight: .bold, design: .rounded))
                            .foregroundColor(inkPrimary)

                        Text(vm.snapshot.isSafe ? "Rust 内核锁死" : "熔断就绪")
                            .font(.system(size: 11, weight: .semibold))
                            .foregroundColor(accentColor)
                            .padding(.horizontal, 9)
                            .padding(.vertical, 3)
                            .background(Capsule().fill(accentColor.opacity(isDark ? 0.18 : 0.10)))
                    }

                    HStack(spacing: 8.5) {
                        Text(vm.snapshot.expected_ip)
                            .font(.system(size: 14, weight: .semibold, design: .monospaced))
                            .foregroundColor(inkPrimary.opacity(0.86))

                        if let apiMs = vm.snapshot.api_latency.warm_rtt_ms {
                            let jitterText = vm.snapshot.api_latency.jitter_ms.map { " ±\($0)" } ?? ""
                            Text(verbatim: "API \(apiMs)ms\(jitterText)")
                                .font(.system(size: 12, weight: .semibold, design: .monospaced))
                                .foregroundColor(latencyColor(apiMs))
                                .padding(.horizontal, 8.5)
                                .padding(.vertical, 2.5)
                                .background(Capsule().fill(latencyColor(apiMs).opacity(isDark ? 0.16 : 0.09)))
                        } else if let colo = vm.snapshot.claude_edge.colo {
                            Text("CF \(colo)")
                                .font(.system(size: 12, weight: .medium, design: .monospaced))
                                .foregroundColor(labelColor)
                        }
                    }
                }

                Spacer(minLength: 10)

                if let p = vm.purity {
                    let pc = purityColor(p.purity_score)
                    Button(action: {
                        withAnimation(.spring(response: 0.26, dampingFraction: 0.86)) {
                            nav.selectedSection = .purity
                        }
                    }) {
                        VStack(alignment: .trailing, spacing: 3) {
                            HStack(spacing: 6) {
                                Text("\(p.purity_score)")
                                    .font(.system(size: 24, weight: .bold, design: .rounded))
                                    .foregroundColor(pc)
                                Text(p.grade)
                                    .font(.system(size: 11.5, weight: .heavy, design: .rounded))
                                    .foregroundColor(.white)
                                    .padding(.horizontal, 6.5)
                                    .padding(.vertical, 2)
                                    .background(RoundedRectangle(cornerRadius: 5.5, style: .continuous).fill(pc))
                            }
                            Text("IP 纯净度 · 查看详情")
                                .font(.system(size: 11, weight: .medium))
                                .foregroundColor(labelColor)
                        }
                        .padding(.horizontal, 15)
                        .padding(.vertical, 10)
                        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(pc.opacity(isDark ? 0.12 : 0.065)))
                    }
                    .buttonStyle(SnappyButtonStyle(scale: 0.97))
                } else {
                    VStack(alignment: .trailing, spacing: 3) {
                        Text("\(vm.snapshot.defenseScore)/8")
                            .font(.system(size: 22, weight: .bold, design: .rounded))
                            .foregroundColor(accentColor)
                        Text("防线激活")
                            .font(.system(size: 11, weight: .medium))
                            .foregroundColor(labelColor)
                    }
                }
            }
            .padding(.horizontal, 22)
            .padding(.vertical, 20)
            .background(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .fill(cardSurface)
                    .overlay(
                        RoundedRectangle(cornerRadius: 16, style: .continuous)
                            .fill(
                                LinearGradient(
                                    colors: [accentColor.opacity(isDark ? 0.11 : 0.055), Color.clear],
                                    startPoint: .topLeading,
                                    endPoint: .bottomTrailing
                                )
                            )
                    )
            )
            .overlay(
                RoundedRectangle(cornerRadius: 16, style: .continuous)
                    .strokeBorder(accentColor.opacity(isDark ? 0.24 : 0.18), lineWidth: 0.85)
            )
            .shadow(color: cardShadow, radius: 8, y: 2)

            // 2. Dual Channel Telemetry (Strict equal-width 2 columns)
            LazyVGrid(columns: twoEqualCols, spacing: 14) {
                dashboardTunnelCard(
                    title: "Claude 边缘通道 :\(vm.snapshot.proxy_port)",
                    ip: vm.snapshot.proxy.ip,
                    subtitle: vm.snapshot.claude_edge.colo.map { "Cloudflare \($0) · \(vm.snapshot.claude_edge.loc ?? "")" } ?? "边缘节点探测中",
                    latency: vm.snapshot.proxy.latency_ms,
                    ok: vm.snapshot.proxyOK,
                    icon: "arrow.triangle.branch"
                )
                dashboardTunnelCard(
                    title: "TUN 系统默认路由",
                    ip: vm.snapshot.tun.ip,
                    subtitle: vm.snapshot.tun.colo.map { "Cloudflare \($0) · \(vm.snapshot.tun.loc ?? "")" } ?? "系统路由探测中",
                    latency: vm.snapshot.tun.latency_ms,
                    ok: vm.snapshot.tunOK,
                    icon: "shield.lefthalf.filled"
                )
            }

            // 3. 6-Dimension Defense Matrix (Exact 3x2 or 2x3 aligned grid)
            VStack(alignment: .leading, spacing: 11) {
                HStack(alignment: .firstTextBaseline) {
                    Text("本地防线状态")
                        .font(.system(size: 13, weight: .semibold))
                        .foregroundColor(labelColor)
                    Spacer()
                    Text("\(vm.snapshot.defenseScore)/8 项已激活")
                        .font(.system(size: 11.5, weight: .semibold, design: .monospaced))
                        .foregroundColor(vm.snapshot.isSafe ? safeGreen : warnAmber)
                }

                let d = vm.snapshot.defenses
                let tzOK = vm.purity?.timezone_aligned ?? true
                LazyVGrid(columns: matrixCols, spacing: 14) {
                    dashboardMetricTile(
                        icon: "globe.americas.fill",
                        title: "时区与语言",
                        value: "\(vm.snapshot.region_short) · en-US",
                        ok: tzOK
                    )
                    dashboardMetricTile(
                        icon: "lock.shield.fill",
                        title: "OAuth 门禁",
                        value: d.oauth_locked ? "AdsPower-Only" : "未锁定",
                        ok: d.oauth_locked
                    )
                    dashboardMetricTile(
                        icon: "eye.slash.fill",
                        title: "原版隐藏仓",
                        value: d.original_hidden ? "已隐藏防误触" : (d.original_app_exposed ? "暴露在应用栏!" : "未安装原版"),
                        ok: d.original_hidden || !d.original_app_exposed
                    )
                    dashboardMetricTile(
                        icon: "cube.transparent.fill",
                        title: "沙盒与去遥测",
                        value: (d.sandbox_enabled && d.telemetry_disabled) ? "Seatbelt + 静音" : "部分未启",
                        ok: d.sandbox_enabled && d.telemetry_disabled
                    )
                    dashboardMetricTile(
                        icon: "desktopcomputer",
                        title: "桌面版进程",
                        value: d.desktop_pid.map { vm.snapshot.desktopUnprotected ? "未绑定 · #\($0)" : "硬代理 · #\($0)" } ?? "待机未启动",
                        ok: !vm.snapshot.desktopUnprotected,
                        dim: !vm.snapshot.desktopRunning
                    )
                    dashboardMetricTile(
                        icon: "terminal.fill",
                        title: "Claude Code",
                        value: vm.snapshot.hasUnprotectedCLI ? "未保护进程!" : (d.cli_ready ? "Rust 门禁就绪" : "待初始化"),
                        ok: d.cli_ready && !vm.snapshot.hasUnprotectedCLI
                    )
                }
            }

            // 4. Protection Toggles (Strict equal-width & equal-height 2 columns)
            LazyVGrid(columns: twoEqualCols, spacing: 14) {
                dashboardToggleCard(
                    icon: "bolt.shield.fill",
                    title: "IP 漂移 & 唤醒急停",
                    subtitle: "断网、切节点或唤醒瞬间自动熔断",
                    isOn: vm.autoKillOnBreach
                ) {
                    withAnimation(.spring(response: 0.24, dampingFraction: 0.80)) {
                        vm.autoKillOnBreach.toggle()
                    }
                }

                dashboardToggleCard(
                    icon: "sunrise.fill",
                    title: "开机自启 & 每日体检",
                    subtitle: vm.snapshot.defenses.daily_patrol_enabled ? "登录静默守护 · 每日自动复检防线" : "登录静默启动状态栏保护雷达",
                    isOn: vm.loginAutoStart
                ) {
                    withAnimation(.spring(response: 0.24, dampingFraction: 0.80)) {
                        vm.setLoginAutoStart(!vm.loginAutoStart)
                    }
                }
            }

            // 5. Full-Width Balanced Quick Actions Bar (Flush left & right edges!)
            HStack(spacing: 14) {
                dashboardActionTile(
                    icon: "sparkle.magnifyingglass",
                    title: vm.isAuditing ? "全面体检中..." : "全面体检",
                    isLoading: vm.isAuditing,
                    tint: inkPrimary
                ) {
                    vm.runFullCheckup()
                }

                dashboardActionTile(
                    icon: "camera.viewfinder",
                    title: "截图诊断",
                    isLoading: false,
                    tint: inkPrimary
                ) {
                    copyDashboardSnapshotImage()
                }

                dashboardActionTile(
                    icon: "slider.horizontal.3",
                    title: "防护设置",
                    isLoading: false,
                    tint: inkPrimary
                ) {
                    withAnimation(.spring(response: 0.26, dampingFraction: 0.86)) {
                        nav.selectedSection = .settings
                    }
                }

                if vm.snapshot.desktopRunning {
                    dashboardActionTile(
                        icon: "stop.circle.fill",
                        title: "急停 Claude",
                        isLoading: false,
                        tint: dangerRed,
                        isDestructive: true
                    ) {
                        vm.emergencyKillClaude()
                    }
                }
            }
        }
    }

    private func dashboardActionTile(
        icon: String,
        title: String,
        isLoading: Bool,
        tint: Color,
        isDestructive: Bool = false,
        action: @escaping () -> Void
    ) -> some View {
        Button(action: action) {
            HStack(spacing: 7) {
                if isLoading {
                    ProgressView().controlSize(.mini).scaleEffect(0.8)
                } else {
                    Image(systemName: icon)
                        .font(.system(size: 13, weight: .medium))
                        .foregroundColor(isDestructive ? dangerRed : labelColor)
                }
                Text(title)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(isDestructive ? dangerRed : tint.opacity(0.88))
                    .lineLimit(1)
            }
            .frame(maxWidth: .infinity)
            .frame(height: 44)
            .background(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .fill(isDestructive ? dangerRed.opacity(isDark ? 0.14 : 0.08) : cardSurface)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 12, style: .continuous)
                    .strokeBorder(isDestructive ? dangerRed.opacity(0.28) : cardBorder, lineWidth: 0.75)
            )
            .shadow(color: cardShadow, radius: 4, y: 1.5)
        }
        .buttonStyle(SnappyButtonStyle(scale: 0.98))
    }

    private func copyDashboardSnapshotImage() {
        let card = VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 10) {
                ShieldStatusBadge(isSafe: vm.snapshot.isSafe, accentColor: accentColor, isDark: isDark)
                VStack(alignment: .leading, spacing: 3) {
                    Text(vm.snapshot.isSafe ? "SHIELD ARMED" : "IP 异常预警")
                        .font(.system(size: 14, weight: .bold, design: .rounded))
                    Text("\(vm.snapshot.expected_ip) · \(vm.snapshot.region_short)")
                        .font(.system(size: 11.5, weight: .semibold, design: .monospaced))
                        .foregroundColor(labelColor)
                }
                Spacer()
                if let p = vm.purity {
                    Text("\(p.purity_score) \(p.grade)")
                        .font(.system(size: 15, weight: .bold, design: .rounded))
                        .foregroundColor(purityColor(p.purity_score))
                }
            }
            HStack(spacing: 8) {
                dashboardTunnelCard(
                    title: "Claude 边缘 :\(vm.snapshot.proxy_port)",
                    ip: vm.snapshot.proxy.ip,
                    subtitle: vm.snapshot.claude_edge.colo.map { "CF \($0) · \(vm.snapshot.claude_edge.loc ?? "")" } ?? "-",
                    latency: vm.snapshot.proxy.latency_ms,
                    ok: vm.snapshot.proxyOK,
                    icon: "arrow.triangle.branch"
                )
                dashboardTunnelCard(
                    title: "TUN 默认路由",
                    ip: vm.snapshot.tun.ip,
                    subtitle: vm.snapshot.tun.colo.map { "CF \($0) · \(vm.snapshot.tun.loc ?? "")" } ?? "-",
                    latency: vm.snapshot.tun.latency_ms,
                    ok: vm.snapshot.tunOK,
                    icon: "shield.lefthalf.filled"
                )
            }
            HStack {
                Text("Claude Shield \(AppReleaseConfig.shortDisplayVersion) · \(vm.snapshot.checked_at)")
                    .font(.system(size: 10, weight: .medium, design: .monospaced))
                    .foregroundColor(labelColor)
                Spacer()
                Text("防线 \(vm.snapshot.defenseScore)/8")
                    .font(.system(size: 10, weight: .semibold))
                    .foregroundColor(safeGreen)
            }
        }
        .padding(16)
        .frame(width: 440)
        .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(canvasBg))
        .environment(\.colorScheme, colorScheme)

        if #available(macOS 13.0, *) {
            let renderer = ImageRenderer(content: card)
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

    private func dashboardTunnelCard(title: String, ip: String, subtitle: String, latency: Int?, ok: Bool, icon: String) -> some View {
        let dotColor = ok ? safeGreen : dangerRed
        return VStack(alignment: .leading, spacing: 9) {
            HStack(spacing: 6.5) {
                Circle().fill(dotColor).frame(width: 7.5, height: 7.5)
                Text(title)
                    .font(.system(size: 12.5, weight: .medium))
                    .foregroundColor(labelColor)
                    .lineLimit(1)
                Spacer(minLength: 4)
                if let ms = latency {
                    let lc = latencyColor(ms)
                    Text(verbatim: "\(ms)ms")
                        .font(.system(size: 11, weight: .semibold, design: .monospaced))
                        .foregroundColor(lc)
                        .padding(.horizontal, 7.5)
                        .padding(.vertical, 2.5)
                        .background(Capsule().fill(lc.opacity(isDark ? 0.16 : 0.09)))
                }
            }

            HStack(spacing: 7) {
                Image(systemName: icon)
                    .font(.system(size: 13, weight: .semibold))
                    .foregroundColor(dotColor)
                Text(ip)
                    .font(.system(size: 16.5, weight: .bold, design: .monospaced))
                    .foregroundColor(inkPrimary)
                    .textSelection(.enabled)
            }

            Text(subtitle)
                .font(.system(size: 11.5, weight: .medium, design: .monospaced))
                .foregroundColor(subtleLabelColor)
                .lineLimit(1)
        }
        .padding(.horizontal, 18)
        .padding(.vertical, 16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 13, style: .continuous).fill(cardSurface))
        .overlay(RoundedRectangle(cornerRadius: 13, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.75))
        .shadow(color: cardShadow, radius: 6, y: 2)
    }

    private func dashboardMetricTile(icon: String, title: String, value: String, ok: Bool, dim: Bool = false) -> some View {
        let tint: Color = dim ? subtleLabelColor : (ok ? safeGreen : warnAmber)
        return HStack(spacing: 11) {
            ZStack {
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(tint.opacity(isDark ? 0.15 : 0.09))
                    .frame(width: 36, height: 36)
                Image(systemName: icon)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundColor(tint)
            }
            VStack(alignment: .leading, spacing: 2.5) {
                Text(title)
                    .font(.system(size: 11.5, weight: .medium))
                    .foregroundColor(labelColor)
                    .lineLimit(1)
                Text(value)
                    .font(.system(size: 13.5, weight: .semibold))
                    .foregroundColor(dim ? labelColor : inkPrimary)
                    .lineLimit(1)
            }
            Spacer(minLength: 0)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 14)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(cardSurface))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.75))
        .shadow(color: cardShadow, radius: 4, y: 1.5)
    }

    private func dashboardToggleCard(icon: String, title: String, subtitle: String, isOn: Bool, action: @escaping () -> Void) -> some View {
        let activeTint = safeGreen
        return HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill((isOn ? activeTint : subtleLabelColor).opacity(isDark ? 0.15 : 0.09))
                    .frame(width: 36, height: 36)
                Image(systemName: icon)
                    .font(.system(size: 15, weight: .semibold))
                    .foregroundColor(isOn ? activeTint : subtleLabelColor)
            }

            VStack(alignment: .leading, spacing: 3) {
                Text(title)
                    .font(.system(size: 13.5, weight: .semibold))
                    .foregroundColor(inkPrimary)
                    .lineLimit(1)
                Text(subtitle)
                    .font(.system(size: 11.5, weight: .regular))
                    .foregroundColor(labelColor)
                    .lineLimit(1)
            }

            Spacer(minLength: 8)

            Button(action: action) {
                ZStack(alignment: isOn ? .trailing : .leading) {
                    Capsule()
                        .fill(isOn ? activeTint.opacity(0.90) : (isDark ? Color.white.opacity(0.16) : Color.black.opacity(0.14)))
                        .frame(width: 38, height: 21)
                    Circle()
                        .fill(Color.white)
                        .frame(width: 17, height: 17)
                        .shadow(color: Color.black.opacity(0.16), radius: 1.5, y: 0.5)
                        .padding(2)
                }
                .contentShape(Capsule())
            }
            .buttonStyle(SnappyButtonStyle(scale: 0.94, pressedOpacity: 0.95))
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 15)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(cardSurface))
        .overlay(
            RoundedRectangle(cornerRadius: 12, style: .continuous)
                .strokeBorder(isOn ? activeTint.opacity(isDark ? 0.22 : 0.16) : cardBorder, lineWidth: 0.75)
        )
        .shadow(color: cardShadow, radius: 4, y: 1.5)
    }

    // MARK: - Section 2: 纯净度体检

    private func puritySectionContent(wide: Bool) -> some View {
        let fourCols = Array(repeating: GridItem(.flexible(), spacing: 12), count: wide ? 4 : 2)
        return VStack(alignment: .leading, spacing: 14) {
            if let p = vm.purity {
                let pc = purityColor(p.purity_score)
                // Hero Purity Gauge Card
                HStack(spacing: 18) {
                    ZStack {
                        Circle()
                            .stroke(pc.opacity(0.15), lineWidth: 6.5)
                            .frame(width: 78, height: 78)
                        Circle()
                            .trim(from: 0, to: CGFloat(max(0, min(100, p.purity_score))) / 100.0)
                            .stroke(pc, style: StrokeStyle(lineWidth: 6.5, lineCap: .round))
                            .rotationEffect(.degrees(-90))
                            .frame(width: 78, height: 78)
                            .animation(.spring(response: 0.5, dampingFraction: 0.82), value: p.purity_score)
                        VStack(spacing: 1) {
                            Text("\(p.purity_score)")
                                .font(.system(size: 22, weight: .bold, design: .rounded))
                                .foregroundColor(pc)
                            Text("\(p.grade) 级")
                                .font(.system(size: 10, weight: .bold))
                                .foregroundColor(labelColor)
                        }
                    }

                    VStack(alignment: .leading, spacing: 4.5) {
                        HStack(spacing: 7) {
                            Text(p.ip_type)
                                .font(.system(size: 15.5, weight: .bold))
                                .foregroundColor(inkPrimary)
                            Text(p.country_code)
                                .font(.system(size: 10.5, weight: .bold, design: .monospaced))
                                .foregroundColor(p.region_supported ? safeGreen : dangerRed)
                                .padding(.horizontal, 6.5)
                                .padding(.vertical, 2)
                                .background(Capsule().fill((p.region_supported ? safeGreen : dangerRed).opacity(0.12)))
                            Text("欺诈分 \(p.combined_fraud_score.map(String.init) ?? "-")")
                                .font(.system(size: 10.5, weight: .medium, design: .monospaced))
                                .foregroundColor(labelColor)
                                .padding(.horizontal, 7)
                                .padding(.vertical, 2)
                                .background(Capsule().fill(isDark ? Color.white.opacity(0.07) : Color.black.opacity(0.045)))
                        }

                        Text(p.verdict)
                            .font(.system(size: 13, weight: .semibold))
                            .foregroundColor(pc)

                        Text("\(p.exit_ip)  ·  \(p.asn) · \(p.isp)")
                            .font(.system(size: 11.5, weight: .medium, design: .monospaced))
                            .foregroundColor(inkPrimary.opacity(0.80))
                            .lineLimit(1)

                        Text("\(p.country) · \(p.city)  ·  检测时间 \(p.checked_at)")
                            .font(.system(size: 11, weight: .regular))
                            .foregroundColor(subtleLabelColor)
                    }

                    Spacer(minLength: 10)

                    Button(action: { vm.runFullCheckup() }) {
                        HStack(spacing: 5.5) {
                            if vm.isAuditing {
                                ProgressView().controlSize(.mini).scaleEffect(0.76)
                            } else {
                                Image(systemName: "sparkle.magnifyingglass")
                                    .font(.system(size: 11.5, weight: .semibold))
                            }
                            Text(vm.isAuditing ? "体检中..." : "重新体检")
                                .font(.system(size: 12, weight: .semibold))
                        }
                        .foregroundColor(.white)
                        .padding(.horizontal, 13)
                        .frame(height: 34)
                        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(brandGradient))
                        .shadow(color: brandTerracotta.opacity(0.18), radius: 5, y: 2)
                    }
                    .buttonStyle(SnappyButtonStyle(scale: 0.97))
                    .disabled(vm.isAuditing)
                }
                .padding(18)
                .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(cardSurface))
                .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(pc.opacity(0.22), lineWidth: 0.85))
                .shadow(color: cardShadow, radius: 6, y: 2)

                // 4-Way Leak Guard Strip (Exact 4 equal columns)
                LazyVGrid(columns: fourCols, spacing: 12) {
                    dashboardLeakCard(title: "Claude 边缘", value: p.claude_edge_match ? (p.claude_colo ?? "一致") : "异常", ok: p.claude_edge_match)
                    dashboardLeakCard(title: "DNS 通道", value: p.dns_leak ? "检测到泄露!" : "零泄露", ok: !p.dns_leak)
                    dashboardLeakCard(title: "IPv6 隔离", value: p.ipv6_leak ? "检测到泄露!" : "已封闭", ok: !p.ipv6_leak)
                    dashboardLeakCard(title: "时区对齐", value: p.timezone_aligned ? "完全对齐" : "存在偏移!", ok: p.timezone_aligned)
                }

                // Full Itemized Audit Factors (Clean Apple-style Grouped Card — zero orphan gap!)
                VStack(alignment: .leading, spacing: 9) {
                    HStack {
                        Text("风险与纯净度审计明细")
                            .font(.system(size: 12.5, weight: .semibold))
                            .foregroundColor(labelColor)
                        Spacer()
                        Text("共 \(p.factors.count) 项")
                            .font(.system(size: 10.5, weight: .medium, design: .monospaced))
                            .foregroundColor(subtleLabelColor)
                    }

                    VStack(spacing: 0) {
                        ForEach(Array(p.factors.enumerated()), id: \.element.id) { idx, f in
                            HStack(alignment: .center, spacing: 11) {
                                Image(systemName: f.severity == "good" ? "checkmark.circle.fill" : (f.severity == "warn" ? "exclamationmark.triangle.fill" : "xmark.octagon.fill"))
                                    .font(.system(size: 13.5, weight: .semibold))
                                    .foregroundColor(f.severity == "good" ? safeGreen : (f.severity == "warn" ? warnAmber : dangerRed))
                                    .frame(width: 18)

                                Text(f.title)
                                    .font(.system(size: 12.5, weight: .semibold))
                                    .foregroundColor(inkPrimary)
                                    .frame(width: 168, alignment: .leading)
                                    .lineLimit(1)

                                Text(f.detail)
                                    .font(.system(size: 11.5, weight: .regular))
                                    .foregroundColor(labelColor)
                                    .lineLimit(1)
                                    .truncationMode(.tail)

                                Spacer(minLength: 8)

                                if f.penalty < 0 {
                                    Text("\(f.penalty)")
                                        .font(.system(size: 10.5, weight: .bold, design: .monospaced))
                                        .foregroundColor(f.severity == "warn" ? warnAmber : dangerRed)
                                        .padding(.horizontal, 7)
                                        .padding(.vertical, 2)
                                        .background(Capsule().fill((f.severity == "warn" ? warnAmber : dangerRed).opacity(0.12)))
                                } else {
                                    Text("通过")
                                        .font(.system(size: 10, weight: .medium))
                                        .foregroundColor(safeGreen.opacity(0.85))
                                        .padding(.horizontal, 7)
                                        .padding(.vertical, 2)
                                        .background(Capsule().fill(safeGreen.opacity(isDark ? 0.14 : 0.08)))
                                }
                            }
                            .padding(.horizontal, 16)
                            .padding(.vertical, 10.5)

                            if idx < p.factors.count - 1 {
                                Divider().overlay(dividerColor).padding(.leading, 45)
                            }
                        }
                    }
                    .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(cardSurface))
                    .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.75))
                    .shadow(color: cardShadow, radius: 5, y: 1.5)
                }
            } else {
                VStack(spacing: 12) {
                    ProgressView().controlSize(.regular)
                    Text("正在执行多源 IP 纯净度与 DNS/IPv6 泄露体检...")
                        .font(.system(size: 12.5, weight: .medium))
                        .foregroundColor(labelColor)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 64)
                .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(cardSurface))
                .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.75))
            }
        }
    }

    private func dashboardLeakCard(title: String, value: String, ok: Bool) -> some View {
        let color = ok ? safeGreen : dangerRed
        return VStack(alignment: .leading, spacing: 5) {
            HStack {
                Text(title)
                    .font(.system(size: 10.5, weight: .medium))
                    .foregroundColor(labelColor)
                Spacer()
                Image(systemName: ok ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                    .font(.system(size: 11.5))
                    .foregroundColor(color)
            }
            Text(value)
                .font(.system(size: 13.5, weight: .bold, design: .monospaced))
                .foregroundColor(color)
                .lineLimit(1)
        }
        .padding(.horizontal, 13)
        .padding(.vertical, 11)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(cardSurface))
        .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(color.opacity(isDark ? 0.24 : 0.18), lineWidth: 0.75))
        .shadow(color: cardShadow, radius: 4, y: 1.5)
    }

    // MARK: - Section 3: 防护设置

    private var settingsSectionContent: some View {
        VStack(alignment: .leading, spacing: 18) {
            if !state.isFirstRun, shouldShowSettingsUpdateCard {
                settingsUpdateCard
            }

            if let report = state.setupReport {
                completionCard(report)
            } else {
                networkConfigCard
                optionsCard

                if let err = state.errorMessage {
                    HStack(spacing: 8) {
                        Image(systemName: "exclamationmark.triangle.fill")
                            .font(.system(size: 13))
                            .foregroundColor(warnAmber)
                        Text(err)
                            .font(.system(size: 12.5, weight: .medium))
                            .foregroundColor(.primary.opacity(0.9))
                            .fixedSize(horizontal: false, vertical: true)
                        Spacer(minLength: 0)
                    }
                    .padding(.horizontal, 14)
                    .padding(.vertical, 11)
                    .background(RoundedRectangle(cornerRadius: 11, style: .continuous).fill(warnAmber.opacity(isDark ? 0.15 : 0.10)))
                    .overlay(RoundedRectangle(cornerRadius: 11, style: .continuous).strokeBorder(warnAmber.opacity(0.32), lineWidth: 0.8))
                }

                bottomActionRow
            }
        }
    }

    private var shouldShowSettingsUpdateCard: Bool {
        switch vm.updatePhase {
        case .available, .downloading, .installing, .failed:
            return true
        default:
            return false
        }
    }

    @ViewBuilder
    private var settingsUpdateCard: some View {
        if let info = vm.updatePhase.info {
            VStack(alignment: .leading, spacing: 10) {
                HStack(spacing: 10) {
                    ZStack {
                        RoundedRectangle(cornerRadius: 9, style: .continuous)
                            .fill(brandTerracotta.opacity(isDark ? 0.20 : 0.12))
                            .frame(width: 34, height: 34)
                        Image(systemName: "arrow.down.circle.fill")
                            .font(.system(size: 16, weight: .semibold))
                            .foregroundColor(brandTerracotta)
                    }

                    VStack(alignment: .leading, spacing: 2.5) {
                        HStack(spacing: 6) {
                            Text("发现新版本 \(info.tagName)")
                                .font(.system(size: 13.5, weight: .bold))
                                .foregroundColor(.primary)
                            Text("当前 \(AppReleaseConfig.shortDisplayVersion)")
                                .font(.system(size: 10.5, weight: .medium, design: .monospaced))
                                .foregroundColor(labelColor)
                        }
                        Group {
                            switch vm.updatePhase {
                            case .downloading(_, let p):
                                Text("正在从 GitHub Release 下载更新包… \(Int(p * 100))%")
                            case .installing(_, let stage):
                                Text(stage)
                            default:
                                Text(info.notesSummary)
                            }
                        }
                        .font(.system(size: 11.5, weight: .regular))
                        .foregroundColor(labelColor)
                        .lineLimit(2)
                    }

                    Spacer(minLength: 8)

                    if vm.updatePhase.isBusy {
                        ProgressView().controlSize(.small)
                    } else {
                        HStack(spacing: 7) {
                            Button(action: { vm.openReleasePage(info.htmlURL) }) {
                                Text("查看日志")
                                    .font(.system(size: 11.5, weight: .semibold))
                                    .foregroundColor(labelColor)
                                    .padding(.horizontal, 10)
                                    .padding(.vertical, 6)
                                    .background(Capsule().fill(isDark ? Color.white.opacity(0.08) : Color.black.opacity(0.05)))
                            }
                            .buttonStyle(SnappyButtonStyle(scale: 0.96))

                            Button(action: { vm.performUpdate(info) }) {
                                HStack(spacing: 4) {
                                    Image(systemName: info.zipDownloadURL != nil ? "arrow.down.to.line" : "safari")
                                        .font(.system(size: 11, weight: .semibold))
                                    Text(info.zipDownloadURL != nil ? "立即更新" : "前往下载")
                                        .font(.system(size: 12, weight: .semibold))
                                }
                                .foregroundColor(.white)
                                .padding(.horizontal, 12)
                                .padding(.vertical, 6)
                                .background(Capsule().fill(brandGradient))
                            }
                            .buttonStyle(SnappyButtonStyle(scale: 0.96))
                        }
                    }
                }

                if case .downloading(_, let progress) = vm.updatePhase {
                    GeometryReader { geo in
                        ZStack(alignment: .leading) {
                            Capsule()
                                .fill(brandTerracotta.opacity(isDark ? 0.20 : 0.14))
                                .frame(height: 5)
                            Capsule()
                                .fill(brandGradient)
                                .frame(width: max(10, geo.size.width * CGFloat(progress)), height: 5)
                                .animation(.easeOut(duration: 0.18), value: progress)
                        }
                    }
                    .frame(height: 5)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 13)
            .background(
                RoundedRectangle(cornerRadius: 13, style: .continuous)
                    .fill(brandTerracotta.opacity(isDark ? 0.12 : 0.07))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 13, style: .continuous)
                    .strokeBorder(brandTerracotta.opacity(isDark ? 0.35 : 0.26), lineWidth: 0.9)
            )
        } else if case .failed(let msg) = vm.updatePhase {
            HStack(spacing: 8) {
                Image(systemName: "exclamationmark.triangle.fill")
                    .font(.system(size: 13))
                    .foregroundColor(warnAmber)
                Text(msg)
                    .font(.system(size: 12, weight: .medium))
                    .foregroundColor(.primary.opacity(0.88))
                    .fixedSize(horizontal: false, vertical: true)
                Spacer(minLength: 6)
                Button("重试") { vm.checkForUpdates(manual: true) }
                    .buttonStyle(SnappyButtonStyle(scale: 0.96))
                    .font(.system(size: 11.5, weight: .semibold))
                    .foregroundColor(brandTerracotta)
                    .padding(.horizontal, 10)
                    .padding(.vertical, 4.5)
                    .background(Capsule().fill(brandTerracotta.opacity(isDark ? 0.18 : 0.11)))
            }
            .padding(.horizontal, 14)
            .padding(.vertical, 10)
            .background(RoundedRectangle(cornerRadius: 11, style: .continuous).fill(warnAmber.opacity(isDark ? 0.14 : 0.09)))
            .overlay(RoundedRectangle(cornerRadius: 11, style: .continuous).strokeBorder(warnAmber.opacity(0.30), lineWidth: 0.8))
        }
    }

    private var updatePillLabel: String {
        switch vm.updatePhase {
        case .checking: return "检查中"
        case .upToDate: return "已是最新"
        case .available(let info): return "升级 \(info.tagName)"
        case .downloading(_, let p): return "下载 \(Int(p * 100))%"
        case .installing: return "安装中"
        case .idle, .failed: return "检查更新"
        }
    }

    private var updatePillForeground: Color {
        switch vm.updatePhase {
        case .upToDate: return safeGreen
        case .available, .downloading, .installing: return brandTerracotta
        default: return updateHover.value ? .primary : labelColor
        }
    }

    private var updatePillBackground: Color {
        switch vm.updatePhase {
        case .upToDate:
            return safeGreen.opacity(isDark ? 0.18 : 0.11)
        case .available, .downloading, .installing:
            return brandTerracotta.opacity(updateHover.value ? (isDark ? 0.28 : 0.18) : (isDark ? 0.20 : 0.12))
        default:
            return updateHover.value
                ? (isDark ? Color.white.opacity(0.12) : Color.black.opacity(0.08))
                : (isDark ? Color.white.opacity(0.07) : Color.black.opacity(0.045))
        }
    }

    private var networkConfigCard: some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(alignment: .center) {
                HStack(spacing: 7) {
                    Image(systemName: "network.badge.shield.half.filled")
                        .font(.system(size: 14.5, weight: .semibold))
                        .foregroundColor(brandTerracotta)
                    Text("网络与地区")
                        .font(.system(size: 14.5, weight: .bold))
                        .foregroundColor(.primary)
                }

                Spacer()

                Button(action: { state.runAutoDetect() }) {
                    HStack(spacing: 5) {
                        if state.isDetecting {
                            ProgressView().controlSize(.mini).scaleEffect(0.8)
                        } else {
                            Image(systemName: "wand.and.stars")
                                .font(.system(size: 11.5, weight: .semibold))
                        }
                        Text(state.isDetecting ? "正在探测..." : "自动识别节点")
                            .font(.system(size: 12, weight: .semibold))
                    }
                    .foregroundColor(brandTerracotta)
                    .padding(.horizontal, 12)
                    .padding(.vertical, 6)
                    .background(
                        Capsule().fill(
                            brandTerracotta.opacity(detectHover.value ? (isDark ? 0.26 : 0.17) : (isDark ? 0.16 : 0.10))
                        )
                    )
                }
                .buttonStyle(SnappyButtonStyle())
                .onHover { h in withAnimation(.easeOut(duration: 0.12)) { detectHover.value = h } }
                .disabled(state.isDetecting)
            }

            if let info = state.detectedInfo, !info.exit_ip.isEmpty {
                HStack(spacing: 8) {
                    Circle()
                        .fill(info.tun_matches ? safeGreen : warnAmber)
                        .frame(width: 7.5, height: 7.5)
                    Text("\(info.country_code.isEmpty ? "US" : info.country_code)\(info.city.isEmpty ? "" : " · \(info.city)")\(info.isp.isEmpty ? "" : " · \(info.isp)")")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(.primary.opacity(0.84))
                        .lineLimit(1)
                    Spacer()
                    Text(info.tun_matches ? "Proxy & TUN 一致" : "请确认已开启 TUN")
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(info.tun_matches ? safeGreen : warnAmber)
                }
                .padding(.horizontal, 12)
                .padding(.vertical, 8.5)
                .background(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill((info.tun_matches ? safeGreen : warnAmber).opacity(isDark ? 0.12 : 0.08))
                )
            }

            HStack(spacing: 14) {
                VStack(alignment: .leading, spacing: 6) {
                    Text("白名单出口 IP")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(labelColor)
                    StyledSettingsInput(placeholder: "例如 45.77.12.34", text: $state.expectedIP, isDark: isDark)
                }

                VStack(alignment: .leading, spacing: 6) {
                    Text("本地代理端口")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(labelColor)
                    StyledSettingsInput(placeholder: "7897", text: $state.proxyPortText, isDark: isDark)
                        .frame(width: 140)
                }
            }

            VStack(alignment: .leading, spacing: 8) {
                HStack {
                    Text("目标时区 (TZ)")
                        .font(.system(size: 12, weight: .medium))
                        .foregroundColor(labelColor)
                    Spacer()
                    Text("语言自动锁定 en_US.UTF-8")
                        .font(.system(size: 11, weight: .medium, design: .monospaced))
                        .foregroundColor(safeGreen)
                        .padding(.horizontal, 8)
                        .padding(.vertical, 2.5)
                        .background(Capsule().fill(safeGreen.opacity(isDark ? 0.14 : 0.09)))
                }

                StyledSettingsInput(placeholder: "America/Los_Angeles", text: $state.targetTZ, isDark: isDark)

                HStack(spacing: 7) {
                    ForEach(tzPresets, id: \.1) { label, tz in
                        let selected = state.targetTZ == tz
                        Button(label) {
                            withAnimation(.easeOut(duration: 0.15)) {
                                state.targetTZ = tz
                            }
                        }
                        .buttonStyle(SnappyButtonStyle(scale: 0.96))
                        .font(.system(size: 11.5, weight: selected ? .semibold : .medium))
                        .foregroundColor(selected ? .white : .primary.opacity(0.78))
                        .padding(.horizontal, 11)
                        .padding(.vertical, 5)
                        .background(
                            Capsule().fill(
                                selected
                                    ? AnyShapeStyle(brandGradient)
                                    : AnyShapeStyle(isDark ? Color.white.opacity(0.07) : Color.black.opacity(0.045))
                            )
                        )
                    }
                    Spacer(minLength: 0)
                }
                .padding(.top, 2)
            }
        }
        .padding(20)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 15, style: .continuous).fill(cardSurface))
        .overlay(RoundedRectangle(cornerRadius: 15, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.85))
        .shadow(color: cardShadow, radius: 5, y: 2)
    }

    private func policyRow(
        icon: String,
        title: String,
        subtitle: String,
        isOn: Binding<Bool>
    ) -> some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(brandTerracotta.opacity(isDark ? 0.16 : 0.10))
                    .frame(width: 34, height: 34)
                Image(systemName: icon)
                    .font(.system(size: 14.5, weight: .semibold))
                    .foregroundColor(brandTerracotta)
            }

            VStack(alignment: .leading, spacing: 2.5) {
                Text(title)
                    .font(.system(size: 13.5, weight: .semibold))
                    .foregroundColor(.primary)
                Text(subtitle)
                    .font(.system(size: 11.5, weight: .regular))
                    .foregroundColor(labelColor)
                    .lineLimit(1)
            }

            Spacer(minLength: 12)

            Toggle("", isOn: isOn)
                .labelsHidden()
                .toggleStyle(.switch)
                .tint(brandTerracotta)
                .controlSize(.regular)
        }
        .padding(.horizontal, 20)
        .padding(.vertical, 14)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var optionsCard: some View {
        VStack(spacing: 0) {
            policyRow(
                icon: "eye.slash.fill",
                title: "隐藏原版 Claude.app 图标",
                subtitle: "移入隔离仓防误点裸连，卸载时一键无损还原",
                isOn: $state.hideOriginal
            )

            Divider().overlay(dividerColor).padding(.leading, 66)

            policyRow(
                icon: "bolt.shield.fill",
                title: "开机自启状态栏雷达",
                subtitle: "登录 macOS 后自动守护休眠唤醒与网络切换",
                isOn: $state.enableAutostart
            )

            Divider().overlay(dividerColor).padding(.leading, 66)

            policyRow(
                icon: "sparkle.magnifyingglass",
                title: "每日 09:30 自动纯净度巡检",
                subtitle: "静默检测 DNS/IPv6 泄露，异常时主动提醒",
                isOn: $state.enableDailyPatrol
            )

            Divider().overlay(dividerColor)

            VStack(alignment: .leading, spacing: 9) {
                HStack(spacing: 6) {
                    Image(systemName: "checkmark.shield.fill")
                        .font(.system(size: 11.5, weight: .semibold))
                        .foregroundColor(safeGreen)
                    Text("默认内置防线")
                        .font(.system(size: 12, weight: .semibold))
                        .foregroundColor(labelColor)
                    Spacer()
                    Text("已自动启用 · \(builtinTags.count) 项")
                        .font(.system(size: 11, weight: .medium))
                        .foregroundColor(safeGreen)
                }

                HStack(spacing: 8) {
                    ForEach(builtinTags, id: \.self) { tag in
                        HStack(spacing: 4) {
                            Image(systemName: "checkmark.circle.fill")
                                .font(.system(size: 10.5))
                                .foregroundColor(safeGreen)
                            Text(tag)
                                .font(.system(size: 11.5, weight: .medium))
                                .foregroundColor(.primary.opacity(0.84))
                                .lineLimit(1)
                                .fixedSize(horizontal: true, vertical: false)
                        }
                        .padding(.horizontal, 9.5)
                        .padding(.vertical, 5)
                        .background(
                            Capsule().fill(safeGreen.opacity(isDark ? 0.13 : 0.085))
                        )
                        .overlay(
                            Capsule().strokeBorder(safeGreen.opacity(isDark ? 0.22 : 0.14), lineWidth: 0.6)
                        )
                    }
                    Spacer(minLength: 0)
                }
            }
            .padding(.horizontal, 20)
            .padding(.vertical, 14)
        }
        .frame(maxWidth: .infinity)
        .background(RoundedRectangle(cornerRadius: 15, style: .continuous).fill(cardSurface))
        .overlay(RoundedRectangle(cornerRadius: 15, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.85))
        .shadow(color: cardShadow, radius: 5, y: 2)
    }

    private var bottomActionRow: some View {
        HStack(spacing: 12) {
            if !state.isFirstRun {
                Button(action: onUninstall) {
                    HStack(spacing: 5.5) {
                        Image(systemName: "arrow.uturn.backward.circle")
                            .font(.system(size: 12.5, weight: .medium))
                        Text("卸载并还原")
                            .font(.system(size: 12.5, weight: .semibold))
                    }
                    .foregroundColor(dangerRed.opacity(0.90))
                    .padding(.horizontal, 15)
                    .frame(height: 38)
                    .background(
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .fill(dangerRed.opacity(uninstallHover.value ? (isDark ? 0.18 : 0.11) : (isDark ? 0.10 : 0.06)))
                    )
                    .overlay(
                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                            .strokeBorder(dangerRed.opacity(uninstallHover.value ? 0.36 : 0.18), lineWidth: 0.75)
                    )
                }
                .buttonStyle(SnappyButtonStyle())
                .onHover { h in withAnimation(.easeOut(duration: 0.12)) { uninstallHover.value = h } }
            }

            Spacer(minLength: 12)

            Button(action: {
                state.applySetup(onSuccess: onApplied)
            }) {
                HStack(spacing: 6.5) {
                    if state.isApplying {
                        ProgressView().controlSize(.small).scaleEffect(0.8)
                    } else {
                        Image(systemName: "checkmark.shield.fill")
                            .font(.system(size: 13, weight: .semibold))
                    }
                    Text(state.isApplying ? "正在部署防线..." : (state.isFirstRun ? "一键部署全套防封防护" : "保存并应用防护"))
                        .font(.system(size: 13, weight: .semibold))
                }
                .padding(.horizontal, 24)
                .frame(height: 38)
                .foregroundColor(.white)
                .background(
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill(brandGradient)
                        .brightness(saveHover.value ? 0.04 : 0)
                )
                .shadow(color: brandTerracotta.opacity(saveHover.value ? 0.28 : 0.16), radius: 6, y: 2)
            }
            .buttonStyle(SnappyButtonStyle(scale: 0.98))
            .onHover { h in withAnimation(.easeOut(duration: 0.12)) { saveHover.value = h } }
            .disabled(state.isApplying)
        }
        .padding(.top, 2)
    }

    private func completionCard(_ report: SetupReportModel) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack(spacing: 12) {
                ZStack {
                    Circle()
                        .fill(safeGreen.opacity(isDark ? 0.18 : 0.12))
                        .frame(width: 44, height: 44)
                    Image(systemName: "checkmark.seal.fill")
                        .font(.system(size: 22))
                        .foregroundColor(safeGreen)
                }
                VStack(alignment: .leading, spacing: 3) {
                    Text("全套本地防封防线已就绪")
                        .font(.system(size: 16, weight: .bold))
                        .foregroundColor(.primary)
                    Text("\(report.expected_ip) · 端口 \(report.proxy_port) · \(report.target_tz) · en_US.UTF-8")
                        .font(.system(size: 12, weight: .medium, design: .monospaced))
                        .foregroundColor(labelColor)
                }
            }

            VStack(alignment: .leading, spacing: 9) {
                ForEach(report.actions, id: \.self) { item in
                    HStack(alignment: .top, spacing: 8) {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.system(size: 13))
                            .foregroundColor(safeGreen)
                            .padding(.top, 1.5)
                        Text(item)
                            .font(.system(size: 13, weight: .medium))
                            .foregroundColor(.primary.opacity(0.9))
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .padding(18)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(RoundedRectangle(cornerRadius: 14, style: .continuous).fill(cardSurface))
            .overlay(RoundedRectangle(cornerRadius: 14, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.85))

            HStack(spacing: 12) {
                Button("返回实时雷达") {
                    state.setupReport = nil
                    withAnimation(.spring(response: 0.28, dampingFraction: 0.84)) {
                        nav.selectedSection = .radar
                    }
                }
                .buttonStyle(SnappyButtonStyle())
                .font(.system(size: 13.5, weight: .semibold))
                .foregroundColor(.primary)
                .padding(.horizontal, 22)
                .frame(height: 44)
                .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(cardSurface))
                .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.9))

                Button("收起到状态栏") {
                    state.setupReport = nil
                    onHideToMenuBar()
                }
                .buttonStyle(SnappyButtonStyle())
                .font(.system(size: 13.5, weight: .semibold))
                .foregroundColor(labelColor)
                .padding(.horizontal, 18)
                .frame(height: 44)
                .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(cardSurface))
                .overlay(RoundedRectangle(cornerRadius: 12, style: .continuous).strokeBorder(cardBorder, lineWidth: 0.9))

                Button(action: {
                    state.setupReport = nil
                    onHideToMenuBar()
                    onLaunchClaude()
                }) {
                    HStack(spacing: 7) {
                        Image(systemName: "play.fill").font(.system(size: 12.5))
                        Text("立即安全启动 Claude").font(.system(size: 14.5, weight: .semibold))
                    }
                    .frame(maxWidth: .infinity)
                    .frame(height: 44)
                    .foregroundColor(.white)
                    .background(RoundedRectangle(cornerRadius: 12, style: .continuous).fill(brandGradient))
                    .shadow(color: Color(red: 0.75, green: 0.31, blue: 0.18).opacity(0.28), radius: 8, y: 3)
                }
                .buttonStyle(SnappyButtonStyle(scale: 0.985))
            }
        }
    }
}

private final class ShieldDashboardWindow: NSWindow {
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
private final class ShieldDashboardWindowController: NSObject, NSWindowDelegate {
    private var window: ShieldDashboardWindow?
    private var navState = ShieldDashboardNavState()
    private var wizardState: SetupWizardState?
    private weak var boundViewModel: ShieldViewModel?
    private var isHiding = false

    var currentSection: ShieldDashboardSection {
        navState.selectedSection
    }

    var isVisible: Bool {
        guard let win = window else { return false }
        return win.isVisible && !win.isMiniaturized
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

        if let existing = window, boundViewModel === viewModel {
            if isFirstRun {
                wizardState?.isFirstRun = true
                wizardState?.setupReport = nil
            }
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
            viewModel.refresh(force: false)
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
                viewModel.refresh()
                viewModel.refreshPurity(silent: true)
            }
        )

        let hc = NSHostingController(rootView: rootView)
        let win = ShieldDashboardWindow(
            contentRect: NSRect(x: 0, y: 0, width: 980, height: 752),
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

        if let screen = NSScreen.main ?? NSScreen.screens.first {
            let vf = screen.visibleFrame
            let w = min(980, vf.width - 64)
            let h = min(752, vf.height - 48)
            win.setFrame(
                NSRect(
                    x: vf.midX - w / 2.0,
                    y: vf.midY - h / 2.0 + 12,
                    width: w,
                    height: h
                ),
                display: true
            )
        } else {
            win.center()
        }

        self.window = win
        presentSmoothly(win)
    }

    func hideToMenuBar(animated: Bool = true, completion: (() -> Void)? = nil) {
        guard let win = window, win.isVisible || win.isMiniaturized else {
            setDockVisible(false)
            completion?()
            return
        }
        if win.isMiniaturized {
            win.orderOut(nil)
            setDockVisible(false)
            completion?()
            return
        }
        guard animated else {
            isHiding = false
            win.orderOut(nil)
            win.alphaValue = 1.0
            setDockVisible(false)
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
                win.orderOut(nil)
                win.alphaValue = 1.0
                self.setDockVisible(false)
                completion?()
            }
        })
    }

    func windowShouldClose(_ sender: NSWindow) -> Bool {
        hideToMenuBar(animated: true)
        return false
    }

    func windowDidDeminiaturize(_ notification: Notification) {
        guard let win = window else { return }
        win.alphaValue = 1.0
        win.makeKeyAndOrderFront(nil)
        NSApp.activate(ignoringOtherApps: true)
    }

    // MARK: - Zero-Stall GPU Window Presentation (No Synchronous Bitmap Capture)

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

// MARK: - AppDelegate (Unified Safe Launcher + Menu Bar Radar)

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate, NSPopoverDelegate {
    private static let reopenNotification = Notification.Name("com.local.claude.shield.launchDesktop")

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

    func applicationDidFinishLaunching(_ notification: Notification) {
        let radarOnly = CommandLine.arguments.contains("--radar-only")

        // Ensure macOS system icon matches our bundled Shield icon
        if let icnsURL = Bundle.main.url(forResource: "app", withExtension: "icns"),
           let icon = NSImage(contentsOf: icnsURL) {
            NSApp.applicationIconImage = icon
        }

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
            button.imagePosition = .imageLeading
            button.action = #selector(togglePopover(_:))
            button.target = self
            // Respond on mouseDown for zero-lag tactile clicks & clean transient popover toggle
            button.sendAction(on: [.leftMouseDown])
            // Instant <5ms warm status bar render from disk cache before first network probe completes
            applyStatusButtonFromSnapshot(viewModel.snapshot, purity: viewModel.purity)
        }

        // Warm up popover lazily after first runloop tick so cold launch stays <20ms
        DispatchQueue.main.async { [weak self] in
            _ = self?.ensurePopover()
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

        viewModel.onShowSetupWizard = { [weak self] isFirstRun in
            guard let self = self else { return }
            if self.popover?.isShown == true { self.popover?.performClose(nil) }
            self.dashboardController.show(viewModel: self.viewModel, section: .settings, isFirstRun: isFirstRun)
        }

        viewModel.onShowDashboard = { [weak self] section, isFirstRun in
            guard let self = self else { return }
            if self.popover?.isShown == true { self.popover?.performClose(nil) }
            self.dashboardController.show(viewModel: self.viewModel, section: section, isFirstRun: isFirstRun)
        }

        viewModel.startMonitoring()
        hasCompletedInitialLaunch = true

        if RustCoreBridge.needsInitialSetup {
            dashboardController.show(viewModel: viewModel, section: .settings, isFirstRun: true)
        } else if !radarOnly {
            dashboardController.show(viewModel: viewModel, section: .radar, isFirstRun: false)
        }
    }

    private func ensurePopover() -> NSPopover {
        if let existing = popover {
            return existing
        }
        let hc = NSHostingController(rootView: ShieldPopoverView(vm: viewModel))
        if #available(macOS 13.0, *) {
            // Let macOS 13+ NSHostingController size the popover natively — zero bottom clipping
            hc.sizingOptions = .preferredContentSize
        }
        self.hostingController = hc

        let pop = NSPopover()
        // Use .applicationDefined + explicit event monitors to eliminate macOS .transient
        // race conditions with NSStatusBarButton mouseDown/activate (flicker & missed opens).
        pop.behavior = .applicationDefined
        pop.animates = true
        pop.delegate = self
        pop.contentViewController = hc
        self.popover = pop
        return pop
    }

    private func applyStatusButtonFromSnapshot(_ snap: TelemetrySnapshot, purity: PurityReport?) {
        if snap.expected_ip == "检测中..." {
            updateStatusButton(state: .loading, text: "Shield")
            return
        }
        if snap.isSafe {
            let bestMs = snap.api_latency.warm_rtt_ms ?? snap.proxy.latency_ms
            let msText = bestMs.map { " \($0)ms" } ?? ""
            let gradeText = purity.map { " · \($0.grade)" } ?? ""
            updateStatusButton(state: .armed, text: "\(snap.region_short)\(msText)\(gradeText)")
        } else if snap.desktopUnprotected || snap.hasUnprotectedCLI {
            updateStatusButton(state: .alert, text: "进程未受保护!")
        } else {
            updateStatusButton(state: .alert, text: "IP 异常!")
        }
    }

    func popoverDidClose(_ notification: Notification) {
        teardownPopoverMonitors()
        lastPopoverClosedAt = Date()
    }

    private func installPopoverMonitors() {
        teardownPopoverMonitors()

        popoverGlobalMonitor = NSEvent.addGlobalMonitorForEvents(
            matching: [.leftMouseDown, .rightMouseDown]
        ) { [weak self] _ in
            Task { @MainActor [weak self] in
                guard let self, let pop = self.popover, pop.isShown else { return }
                // Let togglePopover own clicks on the status bar button itself
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
                if event.keyCode == 53 { // Escape
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

    private func updateStatusButton(state: MenuBarShieldState, text: String) {
        guard let button = statusItem.button else { return }
        button.image = ShieldBrandGraphics.makeMenuBarIcon(state: state)
        let font = NSFont.monospacedDigitSystemFont(ofSize: 12.5, weight: .medium)
        let attrs: [NSAttributedString.Key: Any] = [
            .font: font,
            .baselineOffset: 0.2
        ]
        button.attributedTitle = NSAttributedString(string: " \(text)", attributes: attrs)
    }

    private func showPopoverNow() {
        guard let button = statusItem.button else { return }
        let pop = ensurePopover()
        if #unavailable(macOS 13.0), let hc = hostingController {
            hc.view.layoutSubtreeIfNeeded()
            let fitting = hc.view.fittingSize
            if fitting.width > 0 && fitting.height > 0 {
                pop.contentSize = NSSize(width: 400, height: ceil(fitting.height))
            }
        }
        NSApp.activate(ignoringOtherApps: true)
        pop.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
        pop.contentViewController?.view.window?.makeKey()
        installPopoverMonitors()
        // Debounced background refresh (4s window) so clicking feels instant with zero UI jitter
        viewModel.refresh(force: false)
    }

    @objc private func togglePopover(_ sender: AnyObject?) {
        if let pop = popover, pop.isShown {
            pop.performClose(sender)
            return
        }
        // Minimal debounce to avoid accidental double-trigger on the same click event
        if Date().timeIntervalSince(lastPopoverClosedAt) < 0.06 {
            return
        }
        // Open popover immediately without closing the Console or thrashing Dock activation policy
        showPopoverNow()
    }
}

MainActor.assumeIsolated {
    let app = NSApplication.shared
    app.setActivationPolicy(.accessory)
    let delegate = AppDelegate()
    app.delegate = delegate
    app.run()
}
