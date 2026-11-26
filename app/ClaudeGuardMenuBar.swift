import Cocoa
import Foundation

struct GuardStatus: Sendable {
    let expectedIP: String
    let proxyIP: String
    let tunIP: String
    let oauthLocked: Bool
    let originalHidden: Bool
    let sandboxEnabled: Bool
    let desktopRunning: Bool
    let checkedAt: String

    var isSafe: Bool {
        !expectedIP.isEmpty && proxyIP == expectedIP && tunIP == expectedIP
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    private var statusItem: NSStatusItem!
    private var timer: Timer?
    private let proxyPort: String

    override init() {
        let portFile = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".config/claude-guard/proxy_port")
        if let raw = try? String(contentsOf: portFile, encoding: .utf8) {
            let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            self.proxyPort = trimmed.isEmpty ? "7897" : trimmed
        } else {
            self.proxyPort = "7897"
        }
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem.button?.title = "🟡 Claude Guard"
        refreshStatus()

        timer = Timer.scheduledTimer(withTimeInterval: 15.0, repeats: true) { [weak self] _ in
            self?.refreshStatus()
        }
    }

    @objc private func manualRefresh() {
        statusItem.button?.title = "🟡 检测中..."
        refreshStatus()
    }

    @objc private func launchClaudeSafe() {
        let script = FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent(".local/bin/claude-desktop-safe").path
        let task = Process()
        task.executableURL = URL(fileURLWithPath: "/bin/bash")
        task.arguments = [script]
        try? task.run()
    }

    @objc private func quitApp() {
        NSApplication.shared.terminate(nil)
    }

    private func runShell(_ launchPath: String, _ args: [String]) -> String {
        let task = Process()
        task.executableURL = URL(fileURLWithPath: launchPath)
        task.arguments = args
        let pipe = Pipe()
        task.standardOutput = pipe
        task.standardError = FileHandle.nullDevice
        do {
            try task.run()
            task.waitUntilExit()
            let data = pipe.fileHandleForReading.readDataToEndOfFile()
            return String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        } catch {
            return ""
        }
    }

    private func fetchIP(viaProxy: Bool) -> String {
        let urls = ["https://api.ipify.org", "https://ifconfig.me/ip"]
        for url in urls {
            let args: [String] = viaProxy
                ? ["-fsS", "--max-time", "4", "-x", "http://127.0.0.1:\(proxyPort)", url]
                : ["-fsS", "--max-time", "4", "--noproxy", "*", url]
            let ip = runShell("/usr/bin/curl", args)
            if !ip.isEmpty {
                return ip
            }
        }
        return "无法连通"
    }

    private func refreshStatus() {
        let port = self.proxyPort
        DispatchQueue.global(qos: .utility).async { [weak self] in
            guard let self = self else { return }
            let home = FileManager.default.homeDirectoryForCurrentUser
            let fm = FileManager.default

            let ipFile = home.appendingPathComponent(".config/claude-guard/expected_ip")
            let expectedIP = (try? String(contentsOf: ipFile, encoding: .utf8))?
                .trimmingCharacters(in: .whitespacesAndNewlines) ?? "未配置"

            let proxyIP = self.fetchIP(viaProxy: true)
            let tunIP = self.fetchIP(viaProxy: false)

            let oauthPath = home.appendingPathComponent(".local/lib/claude-guard-bin/open").path
            let oauthLocked = fm.isExecutableFile(atPath: oauthPath)

            let origInApps = fm.fileExists(atPath: "/Applications/Claude.app")
            let origInVault = fm.fileExists(atPath: home.appendingPathComponent(".local/apps/Claude.app").path)
            let originalHidden = !origInApps && origInVault

            let settingsPath = home.appendingPathComponent(".claude/settings.json").path
            let settingsText = (try? String(contentsOfFile: settingsPath, encoding: .utf8)) ?? ""
            let sandboxEnabled = settingsText.contains("\"enabled\": true") || settingsText.contains("\"enabled\":true")

            let pgrepOut = self.runShell("/usr/bin/pgrep", ["-x", "Claude"])
            let desktopRunning = !pgrepOut.isEmpty

            let df = DateFormatter()
            df.dateFormat = "HH:mm:ss"
            let nowStr = df.string(from: Date())

            let status = GuardStatus(
                expectedIP: expectedIP,
                proxyIP: proxyIP,
                tunIP: tunIP,
                oauthLocked: oauthLocked,
                originalHidden: originalHidden,
                sandboxEnabled: sandboxEnabled,
                desktopRunning: desktopRunning,
                checkedAt: nowStr
            )

            DispatchQueue.main.async {
                self.updateUI(status: status, port: port)
            }
        }
    }

    private func updateUI(status: GuardStatus, port: String) {
        if status.isSafe {
            statusItem.button?.title = "🟢 LA Safe"
        } else {
            statusItem.button?.title = "🔴 IP 异常!"
        }

        let menu = NSMenu()

        let titleItem = NSMenuItem(
            title: status.isSafe ? "🛡️ Claude Guard · 防护全绿" : "⚠️ Claude Guard · 检测到风险！",
            action: nil,
            keyEquivalent: ""
        )
        titleItem.isEnabled = false
        menu.addItem(titleItem)
        menu.addItem(NSMenuItem.separator())

        let proxyOK = status.proxyIP == status.expectedIP
        let tunOK = status.tunIP == status.expectedIP

        let lines = [
            "白名单 IP: \(status.expectedIP)",
            "\(proxyOK ? "✅" : "❌") 代理出口 (127.0.0.1:\(port)): \(status.proxyIP)",
            "\(tunOK ? "✅" : "❌") 默认路由 (TUN): \(status.tunIP)",
            "✅ 时区 / 语言: America/Los_Angeles · en-US",
            "\(status.oauthLocked ? "✅" : "⚠️") OAuth 拦截: \(status.oauthLocked ? "AdsPower-Only 已锁定" : "未启用")",
            "\(status.originalHidden ? "✅" : "⚠️") 原版 Claude.app: \(status.originalHidden ? "已隐藏防误触" : "仍在应用程序目录")",
            "\(status.sandboxEnabled ? "✅" : "⚠️") macOS 沙盒: \(status.sandboxEnabled ? "Seatbelt 已开启" : "未开启")",
            "💻 桌面版状态: \(status.desktopRunning ? "运行中（受保护）" : "未启动")",
            "🕒 上次刷新: \(status.checkedAt)（每 15 秒自动巡检）"
        ]

        for line in lines {
            let item = NSMenuItem(title: line, action: nil, keyEquivalent: "")
            item.isEnabled = false
            menu.addItem(item)
        }

        menu.addItem(NSMenuItem.separator())

        let launchItem = NSMenuItem(title: "🚀 安全启动 Claude 桌面版", action: #selector(launchClaudeSafe), keyEquivalent: "o")
        launchItem.target = self
        menu.addItem(launchItem)

        let refreshItem = NSMenuItem(title: "🔄 立即重新检测", action: #selector(manualRefresh), keyEquivalent: "r")
        refreshItem.target = self
        menu.addItem(refreshItem)

        menu.addItem(NSMenuItem.separator())

        let quitItem = NSMenuItem(title: "退出 Claude Guard 监控", action: #selector(quitApp), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)

        statusItem.menu = menu
    }
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let delegate = AppDelegate()
app.delegate = delegate
app.run()
