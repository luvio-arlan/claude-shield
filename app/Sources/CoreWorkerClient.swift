import Foundation
import Darwin

// MARK: - Persistent Rust Core Worker Client (Zero-Fork NDJSON RPC over stdio)

enum TelemetryProbeMode: String, Sendable {
    case light
    case full
}

private struct WorkerRequestEnvelope: Encodable {
    let id: UInt64
    let cmd: String
    let mode: String?
    let reset_pool: Bool?
}

private struct WorkerResponseEnvelope<T: Decodable>: Decodable {
    let id: UInt64
    let ok: Bool
    let data: T?
    let error: String?
}

private struct WorkerAckPayload: Decodable {
    let reset: Bool?
    let pong: Bool?
}

final class CoreWorkerClient: @unchecked Sendable {
    static let shared = CoreWorkerClient()

    private let queue = DispatchQueue(label: "com.local.claude.shield.worker", qos: .utility)
    private var process: Process?
    private var stdinPipe: Pipe?
    private var stdoutPipe: Pipe?
    private var readBuffer = Data()
    private var nextRequestId: UInt64 = 1
    private var isShutDown = false

    private init() {
        signal(SIGPIPE, SIG_IGN)
    }

    func fetchTelemetry(mode: TelemetryProbeMode, resetPool: Bool = false) -> TelemetrySnapshot? {
        sendRequest(
            cmd: "telemetry",
            mode: mode.rawValue,
            resetPool: resetPool,
            timeoutMs: mode == .full ? 16_000 : 10_000,
            responseType: TelemetrySnapshot.self
        )
    }

    func fetchDefenses() -> LocalDefenseModel? {
        sendRequest(
            cmd: "defenses",
            mode: nil,
            resetPool: nil,
            timeoutMs: 3_000,
            responseType: LocalDefenseModel.self
        )
    }

    func fetchGate(resetPool: Bool = false) -> GateResultModel? {
        sendRequest(
            cmd: "gate",
            mode: nil,
            resetPool: resetPool,
            timeoutMs: 10_000,
            responseType: GateResultModel.self
        )
    }

    func resetPool() {
        _ = sendRequest(
            cmd: "reset_pool",
            mode: nil,
            resetPool: nil,
            timeoutMs: 3_000,
            responseType: WorkerAckPayload.self
        )
    }

    func shutdown() {
        queue.sync {
            isShutDown = true
            teardownLocked()
        }
    }

    private func sendRequest<T: Decodable>(
        cmd: String,
        mode: String?,
        resetPool: Bool?,
        timeoutMs: Int32,
        responseType: T.Type
    ) -> T? {
        queue.sync {
            guard !isShutDown else { return nil }
            for attempt in 0..<2 {
                guard ensureRunningLocked() else { return nil }
                let reqId = nextRequestId
                nextRequestId &+= 1
                let req = WorkerRequestEnvelope(id: reqId, cmd: cmd, mode: mode, reset_pool: resetPool)
                guard var payload = try? JSONEncoder().encode(req) else { return nil }
                payload.append(0x0A) // newline delimiter

                guard writeAllLocked(payload) else {
                    teardownLocked()
                    if attempt == 0 { continue }
                    return nil
                }

                guard let lineData = readLineLocked(timeoutMs: timeoutMs) else {
                    teardownLocked()
                    if attempt == 0 { continue }
                    return nil
                }

                guard let envelope = try? JSONDecoder().decode(WorkerResponseEnvelope<T>.self, from: lineData),
                      envelope.ok,
                      envelope.id == reqId else {
                    if attempt == 0 {
                        teardownLocked()
                        continue
                    }
                    return nil
                }
                return envelope.data
            }
            return nil
        }
    }

    private func ensureRunningLocked() -> Bool {
        if let proc = process, proc.isRunning, stdinPipe != nil, stdoutPipe != nil {
            return true
        }
        teardownLocked()

        let bin = RustCoreBridge.coreBinaryPath
        guard FileManager.default.isExecutableFile(atPath: bin) else { return false }

        let proc = Process()
        proc.executableURL = URL(fileURLWithPath: bin)
        proc.arguments = ["worker"]

        let inPipe = Pipe()
        let outPipe = Pipe()
        proc.standardInput = inPipe
        proc.standardOutput = outPipe
        proc.standardError = FileHandle.nullDevice

        do {
            try proc.run()
            self.process = proc
            self.stdinPipe = inPipe
            self.stdoutPipe = outPipe
            self.readBuffer.removeAll(keepingCapacity: true)
            return true
        } catch {
            return false
        }
    }

    private func writeAllLocked(_ data: Data) -> Bool {
        guard let fd = stdinPipe?.fileHandleForWriting.fileDescriptor, fd >= 0 else { return false }
        return data.withUnsafeBytes { rawBuf in
            guard let base = rawBuf.baseAddress else { return false }
            var offset = 0
            while offset < data.count {
                let written = Darwin.write(fd, base.advanced(by: offset), data.count - offset)
                if written > 0 {
                    offset += written
                } else if written == -1 && errno == EINTR {
                    continue
                } else {
                    return false
                }
            }
            return true
        }
    }

    private func readLineLocked(timeoutMs: Int32) -> Data? {
        guard let fd = stdoutPipe?.fileHandleForReading.fileDescriptor, fd >= 0 else { return nil }
        let deadline = DispatchTime.now().uptimeNanoseconds + UInt64(max(100, timeoutMs)) * 1_000_000
        var chunk = [UInt8](repeating: 0, count: 4096)

        while true {
            if let nlIndex = readBuffer.firstIndex(of: 0x0A) {
                let line = Data(readBuffer[..<nlIndex])
                readBuffer.removeSubrange(...nlIndex)
                if !line.isEmpty {
                    return line
                }
            }

            let now = DispatchTime.now().uptimeNanoseconds
            if now >= deadline {
                return nil
            }
            let remainingMs = Int32(min(UInt64(Int32.max), (deadline - now) / 1_000_000))
            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ready = Darwin.poll(&pfd, 1, max(1, remainingMs))
            if ready < 0 {
                if errno == EINTR { continue }
                return nil
            }
            if ready == 0 {
                return nil
            }
            if (pfd.revents & Int16(POLLERR | POLLNVAL)) != 0 {
                return nil
            }

            let n = Darwin.read(fd, &chunk, chunk.count)
            if n > 0 {
                readBuffer.append(contentsOf: chunk[0..<n])
            } else if n == 0 {
                return nil // EOF
            } else if errno == EINTR {
                continue
            } else {
                return nil
            }
        }
    }

    private func teardownLocked() {
        if let inPipe = stdinPipe {
            try? inPipe.fileHandleForWriting.close()
        }
        if let outPipe = stdoutPipe {
            try? outPipe.fileHandleForReading.close()
        }
        if let proc = process {
            if proc.isRunning {
                proc.terminate()
            }
            proc.waitUntilExit()
        }
        process = nil
        stdinPipe = nil
        stdoutPipe = nil
        readBuffer.removeAll(keepingCapacity: false)
    }
}
