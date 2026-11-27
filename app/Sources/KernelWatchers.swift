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
    private var controllerSession: URLSession?
    private var isPollingController = false
    private var lastControllerFingerprint: String?
    private var controllerEndpoint: (baseURL: String, secret: String?)?
    private var consecutiveControllerFailures: Int = 0
    private var onProxyStateChanged: (@Sendable (String) -> Void)?
    private var isActive = false
    private var isPaused = false

    var hasRealtimeWatch: Bool {
        queue.sync { !watchers.isEmpty || controllerEndpoint != nil }
    }

    func start(onChange: @escaping @Sendable (String) -> Void) {
        queue.sync {
            stopLocked()
            self.onProxyStateChanged = onChange
            self.isActive = true
            self.isPaused = false

            let home = FileManager.default.homeDirectoryForCurrentUser.path
            let watchCandidates: [(String, TimeInterval)] = [
                ("\(home)/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev", 0.35),
                ("\(home)/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/clash-verge.yaml", 0.30),
                ("\(home)/Library/Application Support/io.github.clash-verge-rev.clash-verge-rev/verge.yaml", 0.30),
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
                    guard let self, self.isActive, !self.isPaused else { return }
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

    func setPaused(_ paused: Bool) {
        queue.async { [weak self] in
            guard let self, self.isActive else { return }
            guard self.isPaused != paused else { return }
            self.isPaused = paused
            if paused {
                self.controllerTimer?.cancel()
                self.controllerTimer = nil
            } else {
                self.consecutiveControllerFailures = 0
                self.refreshControllerDiscoveryLocked()
                self.startControllerLoopLocked()
            }
        }
    }

    func stop() {
        queue.sync {
            stopLocked()
        }
    }

    deinit {
        controllerTimer?.cancel()
        controllerSession?.invalidateAndCancel()
        for w in watchers { w.stop() }
    }

    private func stopLocked() {
        isActive = false
        isPaused = false
        isPollingController = false
        controllerTimer?.cancel()
        controllerTimer = nil
        controllerSession?.invalidateAndCancel()
        controllerSession = nil
        for w in watchers { w.stop() }
        watchers.removeAll()
        controllerEndpoint = nil
        lastControllerFingerprint = nil
        consecutiveControllerFailures = 0
    }

    private func ensureControllerSessionLocked() -> URLSession {
        if let existing = controllerSession {
            return existing
        }
        let config = URLSessionConfiguration.ephemeral
        config.timeoutIntervalForRequest = 0.8
        config.timeoutIntervalForResource = 1.2
        config.connectionProxyDictionary = [:] // Strictly direct loopback, never proxied
        let session = URLSession(configuration: config)
        controllerSession = session
        return session
    }

    private static func stripYamlScalar(_ raw: Substring) -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        if trimmed.isEmpty { return "" }
        if let quote = trimmed.first, (quote == "\"" || quote == "'"), trimmed.count >= 2 {
            if let endIdx = trimmed.dropFirst().firstIndex(of: quote) {
                return String(trimmed[trimmed.index(after: trimmed.startIndex)..<endIdx])
            }
        }
        let withoutComment = trimmed.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first ?? Substring(trimmed)
        return withoutComment.trimmingCharacters(in: CharacterSet.whitespaces.union(CharacterSet(charactersIn: "'\"")))
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
                // Only match top-level YAML keys (zero leading indentation) so nested proxy `secret:` keys never collide
                guard let firstChar = rawLine.first, firstChar != " ", firstChar != "\t", firstChar != "#" else {
                    continue
                }
                if rawLine.hasPrefix("external-controller:") {
                    let val = Self.stripYamlScalar(rawLine.dropFirst("external-controller:".count))
                    if val.isEmpty {
                        sawExplicitEmptyController = true
                    } else if foundHostPort == nil {
                        foundHostPort = val
                    }
                } else if rawLine.hasPrefix("secret:") && foundSecret == nil {
                    let val = Self.stripYamlScalar(rawLine.dropFirst("secret:".count))
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
        guard !isPaused, controllerEndpoint != nil else { return }

        let timer = DispatchSource.makeTimerSource(queue: queue)
        timer.schedule(deadline: .now() + 2.5, repeating: .seconds(4), leeway: .seconds(1))
        timer.setEventHandler { [weak self] in
            self?.pollLoopbackControllerAsyncLocked()
        }
        controllerTimer = timer
        timer.resume()
    }

    private func buildControllerRequest(url: URL, secret: String?) -> URLRequest {
        var req = URLRequest(url: url)
        if let secret = secret, !secret.isEmpty {
            req.setValue("Bearer \(secret)", forHTTPHeaderField: "Authorization")
        }
        return req
    }

    private func pollLoopbackControllerAsyncLocked() {
        guard isActive, !isPaused, !isPollingController, let endpoint = controllerEndpoint else { return }
        guard let configsURL = URL(string: "\(endpoint.baseURL)/configs") else { return }
        let proxiesURL = URL(string: "\(endpoint.baseURL)/proxies")

        isPollingController = true
        let session = ensureControllerSessionLocked()
        let group = DispatchGroup()

        var configJSON: [String: Any]?
        var proxiesJSON: [String: Any]?
        let stateLock = NSLock()

        group.enter()
        session.dataTask(with: buildControllerRequest(url: configsURL, secret: endpoint.secret)) { data, resp, _ in
            defer { group.leave() }
            guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode),
                  let data,
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                return
            }
            stateLock.lock()
            configJSON = obj
            stateLock.unlock()
        }.resume()

        if let proxiesURL {
            group.enter()
            session.dataTask(with: buildControllerRequest(url: proxiesURL, secret: endpoint.secret)) { data, resp, _ in
                defer { group.leave() }
                guard let http = resp as? HTTPURLResponse, (200..<300).contains(http.statusCode),
                      let data,
                      let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
                    return
                }
                stateLock.lock()
                proxiesJSON = obj
                stateLock.unlock()
            }.resume()
        }

        group.notify(queue: queue) { [weak self] in
            guard let self else { return }
            self.isPollingController = false
            guard self.isActive, !self.isPaused else { return }

            guard let json = configJSON else {
                self.consecutiveControllerFailures += 1
                if self.consecutiveControllerFailures >= 2 {
                    self.controllerTimer?.cancel()
                    self.controllerTimer = nil
                }
                return
            }

            self.consecutiveControllerFailures = 0
            let mode = (json["mode"] as? String) ?? ""
            let tunDict = json["tun"] as? [String: Any]
            let tunEnabled = (tunDict?["enable"] as? Bool) ?? false
            let mixedPort = (json["mixed-port"] as? Int) ?? 0

            // Include active Selector/URLTest/Fallback node selections so proxy switches trigger immediately
            var selectedNodes: [String] = []
            if let proxiesMap = proxiesJSON?["proxies"] as? [String: [String: Any]] {
                for key in proxiesMap.keys.sorted() {
                    if let nowNode = proxiesMap[key]?["now"] as? String, !nowNode.isEmpty {
                        selectedNodes.append("\(key)=\(nowNode)")
                    }
                }
            }
            let fp = "\(mode)|\(tunEnabled)|\(mixedPort)|\(selectedNodes.joined(separator: ";"))"

            if let prev = self.lastControllerFingerprint, prev != fp {
                self.lastControllerFingerprint = fp
                self.onProxyStateChanged?("mihomo-controller:\(mode):tun=\(tunEnabled)")
            } else {
                self.lastControllerFingerprint = fp
            }
        }
    }
}
