import Foundation
import Darwin

// MARK: - Single-Process In-Process Rust FFI Engine Client (Zero Subprocess / Zero-Copy JSON Decode)

enum TelemetryProbeMode: String, Sendable {
    case light
    case full
}

final class CoreWorkerClient: @unchecked Sendable {
    static let shared = CoreWorkerClient()
    private static let decoder = JSONDecoder()

    private init() {}

    private func decodeFFI<T: Decodable>(_ rawPtr: UnsafeMutablePointer<CChar>?, as type: T.Type) -> T? {
        guard let ptr = rawPtr else { return nil }
        defer { claude_shield_free_string(ptr) }
        let len = strlen(ptr)
        guard len > 0 else { return nil }
        let data = Data(bytesNoCopy: ptr, count: len, deallocator: .none)
        return try? Self.decoder.decode(type, from: data)
    }

    func fetchTelemetry(mode: TelemetryProbeMode, resetPool: Bool = false, skipApi: Bool = false) -> TelemetrySnapshot? {
        decodeFFI(claude_shield_telemetry_json(mode == .light, resetPool, skipApi), as: TelemetrySnapshot.self)
    }

    func fetchDefenses() -> LocalDefenseModel? {
        decodeFFI(claude_shield_defenses_json(), as: LocalDefenseModel.self)
    }

    func fetchGate(resetPool: Bool = false) -> GateResultModel? {
        decodeFFI(claude_shield_gate_json(resetPool), as: GateResultModel.self)
    }

    func fetchPurity() -> PurityReport? {
        decodeFFI(claude_shield_purity_json(), as: PurityReport.self)
    }

    func runPatrol(notify: Bool, autoKill: Bool) -> PatrolReportModel? {
        decodeFFI(claude_shield_patrol_json(notify, autoKill), as: PatrolReportModel.self)
    }

    func detectEnvironment(port: Int?) -> DetectResultModel? {
        let portArg = Int32(port ?? 0)
        return decodeFFI(claude_shield_detect_json(portArg), as: DetectResultModel.self)
    }

    func hideOriginalApp() -> [String]? {
        decodeFFI(claude_shield_hide_original_json(), as: [String].self)
    }

    func launchDesktop(skipGate: Bool, verifiedIP: String?) -> LaunchDesktopOutcomeModel? {
        if let ip = verifiedIP, !ip.isEmpty {
            return ip.withCString { cStr in
                decodeFFI(claude_shield_launch_desktop_json(skipGate, cStr), as: LaunchDesktopOutcomeModel.self)
            }
        }
        return decodeFFI(claude_shield_launch_desktop_json(skipGate, nil), as: LaunchDesktopOutcomeModel.self)
    }

    func killClaude(includeCLI: Bool) -> KillOutcomeModel? {
        decodeFFI(claude_shield_kill_claude_json(includeCLI), as: KillOutcomeModel.self)
    }

    func killPIDs(_ pids: [String]) -> Int {
        guard !pids.isEmpty else { return 0 }
        let csv = pids.joined(separator: ",")
        struct KillCount: Decodable { let killed: Int }
        let res = csv.withCString { cStr in
            decodeFFI(claude_shield_kill_pids_json(cStr), as: KillCount.self)
        }
        return res?.killed ?? 0
    }

    func resetPool() {
        _ = claude_shield_reset_pool()
    }

    func shutdown() {
        claude_shield_shutdown()
    }
}
