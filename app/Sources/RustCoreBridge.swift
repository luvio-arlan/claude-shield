import Foundation

// MARK: - Rust Core Bridge (Single-Binary Zero-Fork-Overhead Engine)

enum RustCoreBridge {
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

    private static func xmlEscape(_ raw: String) -> String {
        raw.replacingOccurrences(of: "&", with: "&amp;")
            .replacingOccurrences(of: "<", with: "&lt;")
            .replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;")
            .replacingOccurrences(of: "'", with: "&apos;")
    }

    static func toggleLaunchAgent(enabled: Bool) -> Bool {
        let home = FileManager.default.homeDirectoryForCurrentUser
        let agentsDir = home.appendingPathComponent("Library/LaunchAgents")
        let plistURL = agentsDir.appendingPathComponent("com.local.claude.shield.radar.plist")
        let uid = getuid()

        if enabled {
            try? FileManager.default.createDirectory(at: agentsDir, withIntermediateDirectories: true)
            let appExecPath: String = {
                if Bundle.main.bundleURL.pathExtension == "app",
                   let execURL = Bundle.main.executableURL {
                    return execURL.path
                }
                return "/Applications/Claude Shield.app/Contents/MacOS/ClaudeShield"
            }()
            let plist = """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
              <key>Label</key><string>com.local.claude.shield.radar</string>
              <key>ProgramArguments</key>
              <array>
                <string>\(xmlEscape(appExecPath))</string>
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
