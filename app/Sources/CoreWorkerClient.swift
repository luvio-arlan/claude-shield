import Foundation

// MARK: - Single-Process In-Process Rust FFI Engine Client (Zero Subprocess / Zero IPC)

enum TelemetryProbeMode: String, Sendable {
    case light
    case full
}

final class CoreWorkerClient: @unchecked Sendable {
    static let shared = CoreWorkerClient()

    private init() {}

    private func decodeFFI<T: Decodable>(_ rawPtr: UnsafeMutablePointer<CChar>?, as type: T.Type) -> T? {
        guard let ptr = rawPtr else { return nil }
        defer { claude_shield_free_string(ptr) }
        let jsonStr = String(cString: ptr)
        guard let data = jsonStr.data(using: .utf8), !data.isEmpty else { return nil }
        return try? JSONDecoder().decode(type, from: data)
    }

    func fetchTelemetry(mode: TelemetryProbeMode, resetPool: Bool = false) -> TelemetrySnapshot? {
        decodeFFI(claude_shield_telemetry_json(mode == .light, resetPool), as: TelemetrySnapshot.self)
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

    func resetPool() {
        _ = claude_shield_reset_pool()
    }

    func shutdown() {
        claude_shield_shutdown()
    }
}
