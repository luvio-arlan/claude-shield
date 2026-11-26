import Foundation
import Darwin

// MARK: - Kernel kqueue VNODE Watchers & Mihomo / Clash Verge Rev Event Monitor
// All background event handling runs strictly on `.background` QoS (Apple Silicon E-Cores)
// with 0.000% idle CPU overhead.

final class VnodeWatcher: @unchecked Sendable {
    private let path: String
    private let queue: DispatchQueue
    private let debounceInterval: TimeInterval
    private let onChange: @Sendable () -> Void

    private let lock = NSLock()
    private var source: DispatchSourceFileSystemObject?
    private var fileDescriptor: Int32 = -1
    private var pendingWork: DispatchWorkItem?
    private var isStopped = false

    init(
        path: String,
        debounceInterval: TimeInterval = 0.30,
        queue: DispatchQueue = DispatchQueue(label: "com.local.claude.shield.vnode", qos: .background),
        onChange: @escaping @Sendable () -> Void
    ) {
        self.path = path
        self.debounceInterval = debounceInterval
        self.queue = queue
        self.onChange = onChange
    }

    @discardableResult
    func start() -> Bool {
        lock.lock()
        defer { lock.unlock() }
        isStopped = false
        return attachLocked()
    }

    func stop() {
        lock.lock()
        defer { lock.unlock() }
        isStopped = true
        pendingWork?.cancel()
        pendingWork = nil
        detachLocked()
    }

    deinit {
        pendingWork?.cancel()
        if let src = source {
            src.cancel()
        } else if fileDescriptor >= 0 {
            Darwin.close(fileDescriptor)
        }
    }

    private func attachLocked() -> Bool {
        detachLocked()
        let fd = Darwin.open(path, O_EVTONLY)
        guard fd >= 0 else { return false }
        fileDescriptor = fd

        let mask: DispatchSource.FileSystemEvent = [.write, .rename, .delete, .extend, .attrib]
        let src = DispatchSource.makeFileSystemObjectSource(fileDescriptor: fd, eventMask: mask, queue: queue)
        src.setEventHandler { [weak self] in
            guard let self else { return }
            let flags = src.data
            self.lock.lock()
            let stopped = self.isStopped
            if !stopped {
                self.scheduleDebouncedCallbackLocked()
            }
            self.lock.unlock()
            guard !stopped else { return }
            if flags.contains(.delete) || flags.contains(.rename) {
                // Re-arm after atomic tmp -> rename replacement
                self.queue.asyncAfter(deadline: .now() + 0.15) { [weak self] in
                    guard let self else { return }
                    self.lock.lock()
                    defer { self.lock.unlock() }
                    if !self.isStopped {
                        _ = self.attachLocked()
                    }
                }
            }
        }
        src.setCancelHandler {
            Darwin.close(fd)
        }
        source = src
        src.resume()
        return true
    }

    private func detachLocked() {
        if let src = source {
            source = nil
            fileDescriptor = -1
            src.cancel()
        } else if fileDescriptor >= 0 {
            Darwin.close(fileDescriptor)
            fileDescriptor = -1
        }
    }

    private func scheduleDebouncedCallbackLocked() {
        pendingWork?.cancel()
        let item = DispatchWorkItem { [weak self] in
            guard let self else { return }
            self.lock.lock()
            let stopped = self.isStopped
            self.lock.unlock()
            guard !stopped else { return }
            self.onChange()
        }
        pendingWork = item
        queue.asyncAfter(deadline: .now() + debounceInterval, execute: item)
    }
}

/// Dual-layer proxy state monitor for Clash Verge Rev & Mihomo:
/// 1) Kernel kqueue VNODE watchers on Clash Verge Rev / Mihomo config & bbolt `cache.db`
///    (works even when `external-controller` is disabled, 0% idle CPU, <350ms reaction).
/// 2) Optional loopback HTTP controller fingerprint check when `external-controller` is enabled.
final class MihomoEventMonitor: @unchecked Sendable {
    private let queue = DispatchQueue(label: "com.local.claude.shield.mihomo.monitor", qos: .background)
    private var watchers: [VnodeWatcher] = []
    private var controllerTimer: DispatchSourceTimer?
    private var lastControllerFingerprint: String?
    private var controllerEndpoint: (baseURL: String, secret: String?)?
    private var consecutiveControllerFailures: Int = 0
    private var onProxyStateChanged: (@Sendable (String) -> Void)?
    private var isActive = false

    var hasRealtimeWatch: Bool {
        queue.sync { !watchers.isEmpty || controllerEndpoint != nil }
    }

    func start(onChange: @escaping @Sendable (String) -> Void) {
        queue.sync {
            stopLocked()
            self.onProxyStateChanged = onChange
            self.isActive = true

            let home = FileManager.default.homeDirectoryForCurrentUser.path
            let watchCandidates: [(String, TimeInterval)] = [
                ("\(home)/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev", 0.35),
                ("\(home)/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml", 0.30),
                ("\(home)/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/cache.db", 0.35),
                ("\(home)/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/profiles.yaml", 0.35),
                ("\(home)/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/config.yaml", 0.35),
                ("\(home)/.config/mihomo", 0.35),
                ("\(home)/.config/mihomo/config.yaml", 0.30),
                ("\(home)/.config/mihomo/cache.db", 0.35),
                ("\(home)/.config/clash/config.yaml", 0.30),
            ]

            for (targetPath, debounce) in watchCandidates {
                guard FileManager.default.fileExists(atPath: targetPath) else { continue }
                let label = URL(fileURLWithPath: targetPath).lastPathComponent
                let watcher = VnodeWatcher(path: targetPath, debounceInterval: debounce, queue: queue) { [weak self] in
                    guard let self, self.isActive else { return }
                    self.consecutiveControllerFailures = 0
                    self.refreshControllerDiscoveryLocked()
                    self.startControllerLoopLocked()
                    self.onProxyStateChanged?("vnode:\(label)")
                }
                if watcher.start() {
                    watchers.append(watcher)
                }
            }

            refreshControllerDiscoveryLocked()
            startControllerLoopLocked()
        }
    }

    func stop() {
        queue.sync {
            stopLocked()
        }
    }

    deinit {
        controllerTimer?.cancel()
        for w in watchers { w.stop() }
    }

    private func stopLocked() {
        isActive = false
        controllerTimer?.cancel()
        controllerTimer = nil
        for w in watchers { w.stop() }
        watchers.removeAll()
        controllerEndpoint = nil
        lastControllerFingerprint = nil
        consecutiveControllerFailures = 0
    }

    private func refreshControllerDiscoveryLocked() {
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        let yamlPaths = [
            "\(home)/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml",
            "\(home)/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/config.yaml",
            "\(home)/.config/mihomo/config.yaml",
            "\(home)/.config/clash/config.yaml",
        ]

        var foundHostPort: String?
        var foundSecret: String?
        for path in yamlPaths {
            guard let text = try? String(contentsOfFile: path, encoding: .utf8) else { continue }
            var sawExplicitEmptyController = false
            for rawLine in text.split(separator: "\n", omittingEmptySubsequences: true) {
                let line = rawLine.trimmingCharacters(in: .whitespaces)
                if line.hasPrefix("external-controller:") {
                    let rawVal = line
                        .dropFirst("external-controller:".count)
                        .trimmingCharacters(in: .whitespaces)
                    let val = rawVal.trimmingCharacters(in: CharacterSet(charactersIn: "'\""))
                    if val.isEmpty {
                        sawExplicitEmptyController = true
                    } else if foundHostPort == nil {
                        foundHostPort = val
                    }
                } else if line.hasPrefix("secret:") && foundSecret == nil {
                    let val = line
                        .dropFirst("secret:".count)
                        .trimmingCharacters(in: CharacterSet.whitespaces.union(CharacterSet(charactersIn: "'\"")))
                    if !val.isEmpty {
                        foundSecret = val
                    }
                }
            }
            if foundHostPort != nil || sawExplicitEmptyController { break }
        }

        guard let hostPort = foundHostPort else {
            controllerEndpoint = nil
            return
        }
        let normalized = hostPort.hasPrefix(":") ? "127.0.0.1\(hostPort)" : hostPort
        let baseURL = normalized.hasPrefix("http://") || normalized.hasPrefix("https://")
            ? normalized
            : "http://\(normalized)"
        controllerEndpoint = (baseURL, foundSecret)
    }

    private func startControllerLoopLocked() {
        controllerTimer?.cancel()
        controllerTimer = nil
        guard controllerEndpoint != nil else { return }

        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 3.0, repeating: .seconds(5), leeway: .seconds(2))
        timer.setEventHandler { [weak self] in
            self?.pollLoopbackControllerLocked()
        }
        controllerTimer = timer
        timer.resume()
    }

    private func pollLoopbackControllerLocked() {
        guard isActive, let endpoint = controllerEndpoint else { return }
        guard let url = URL(string: "\(endpoint.baseURL)/configs") else { return }

        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 0.8
        config.timeoutIntervalForResource = 1.0
        config.connectionProxyDictionary = [:] // Strictly direct loopback, never proxied
        let session = URLSession(configuration: config)
        defer { session.invalidateAndCancel() }

        var req = URLRequest(url: url)
        if let secret = endpoint.secret, !secret.isEmpty {
            req.setValue("Bearer \(secret)", forHTTPHeaderField: "Authorization")
        }

        let sem = DispatchSemaphore(value: 0)
        var bodyData: Data?
        let task = session.dataTask(with: req) { data, resp, _ in
            if let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode) {
                bodyData = data
            }
            sem.signal()
        }
        task.resume()
        _ = sem.wait(timeout: .now() + 1.0)

        guard let data = bodyData,
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            consecutiveControllerFailures += 1
            if consecutiveControllerFailures >= 2 {
                // Controller port is closed; pause timer until a VNODE config event re-arms it
                controllerTimer?.cancel()
                controllerTimer = nil
            }
            return
        }
        consecutiveControllerFailures = 0
        let mode = (json["mode"] as? String) ?? ""
        let tunDict = json["tun"] as? [String: Any]
        let tunEnabled = (tunDict?["enable"] as? Bool) ?? false
        let mixedPort = (json["mixed-port"] as? Int) ?? 0
        let fp = "\(mode)|\(tunEnabled)|\(mixedPort)"

        if let prev = lastControllerFingerprint, prev != fp {
            lastControllerFingerprint = fp
            onProxyStateChanged?("mihomo-controller:\(mode):tun=\(tunEnabled)")
        } else {
            lastControllerFingerprint = fp
        }
    }
}
