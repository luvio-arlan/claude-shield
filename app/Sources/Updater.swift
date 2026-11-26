import Foundation
import CryptoKit

// MARK: - GitHub Auto-Updater (Zero-Dependency, Proxy-Aware, SHA-256 Verified)

enum AppReleaseConfig {
    static let githubRepo = "luvio-arlan/claude-shield"

    static var currentVersion: String {
        if let v = Bundle.main.object(forInfoDictionaryKey: "CFBundleShortVersionString") as? String,
           !v.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return v.trimmingCharacters(in: .whitespacesAndNewlines)
        }
        return "3.5.1"
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
    private let stateLock = NSLock()
    private var continuation: CheckedContinuation<URL, Error>?
    private var finished = false

    init(onProgress: @escaping @Sendable (Double) -> Void) {
        self.onProgress = onProgress
    }

    private func takeContinuationOnce() -> CheckedContinuation<URL, Error>? {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard !finished else { return nil }
        finished = true
        let cont = continuation
        continuation = nil
        return cont
    }

    func download(url: URL, session: URLSession) async throws -> URL {
        try await withCheckedThrowingContinuation { cont in
            stateLock.lock()
            self.continuation = cont
            stateLock.unlock()
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
        guard let cont = takeContinuationOnce() else { return }
        if let http = downloadTask.response as? HTTPURLResponse, !(200...299).contains(http.statusCode) {
            cont.resume(throwing: GitHubUpdater.UpdateError.httpStatus(http.statusCode))
            return
        }
        let tempCopy = FileManager.default.temporaryDirectory
            .appendingPathComponent("claude-shield-dl-\(UUID().uuidString).zip")
        do {
            try? FileManager.default.removeItem(at: tempCopy)
            try FileManager.default.moveItem(at: location, to: tempCopy)
            cont.resume(returning: tempCopy)
        } catch {
            cont.resume(throwing: error)
        }
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: Error?) {
        guard let error = error, let cont = takeContinuationOnce() else { return }
        cont.resume(throwing: error)
    }
}

enum GitHubUpdater {
    enum UpdateError: LocalizedError {
        case invalidURL
        case httpStatus(Int)
        case noZipAsset
        case checksumVerificationFailed
        case checksumMismatch
        case extractFailed
        case appNotFoundInArchive

        var errorDescription: String? {
            switch self {
            case .invalidURL: return "更新地址无效"
            case .httpStatus(let code): return "GitHub 接口返回异常（HTTP \(code)）"
            case .noZipAsset: return "该版本未附带 macOS ZIP 安装包，请前往 GitHub 手动下载"
            case .checksumVerificationFailed: return "无法获取或匹配 SHA-256 校验文件，已中止更新"
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

        // Fail-closed SHA-256 verification whenever release publishes SHA256SUMS.txt
        if let sumURL = info.checksumURL, let assetName = info.zipAssetName {
            onStage("正在校验 SHA-256 签名...")
            let (sumData, http) = try await fetchDataWithFallback(url: sumURL, accept: nil, proxyPort: proxyPort)
            guard (200...299).contains(http.statusCode),
                  let sumText = String(data: sumData, encoding: .utf8) else {
                throw UpdateError.checksumVerificationFailed
            }
            let expectedHash = sumText
                .components(separatedBy: .newlines)
                .compactMap { line -> String? in
                    let parts = line.split(whereSeparator: { $0.isWhitespace })
                    guard parts.count >= 2 else { return nil }
                    let name = String(parts[1]).replacingOccurrences(of: "*", with: "")
                    return name == assetName ? String(parts[0]).lowercased() : nil
                }
                .first
            guard let expected = expectedHash else {
                throw UpdateError.checksumVerificationFailed
            }
            let fileData = try Data(contentsOf: zipPath)
            let digest = SHA256.hash(data: fileData).map { String(format: "%02x", $0) }.joined()
            guard digest == expected else {
                throw UpdateError.checksumMismatch
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
          /usr/bin/osascript - "${NEW_APP}" "${TARGET_APP}" "${BACKUP_APP}" <<'APPLESCRIPT'
        on run argv
          set newApp to item 1 of argv
          set targetApp to item 2 of argv
          set backupApp to item 3 of argv
          set cmd to "if [ -d " & quoted form of targetApp & " ]; then mv " & quoted form of targetApp & " " & quoted form of backupApp & "; fi; if mv " & quoted form of newApp & " " & quoted form of targetApp & "; then rm -rf " & quoted form of backupApp & "; else [ -d " & quoted form of backupApp & " ] && mv " & quoted form of backupApp & " " & quoted form of targetApp & "; exit 1; fi"
          do shell script cmd with administrator privileges
        end run
        APPLESCRIPT
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
