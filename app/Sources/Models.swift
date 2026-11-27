import Foundation

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
    let hide_original_enabled: Bool?
    let sandbox_enabled: Bool
    let telemetry_disabled: Bool
    let desktop_pid: String?
    let desktop_pids: [String]?
    let desktop_proxy_bound: Bool
    let desktop_bypass_locked: Bool?
    let desktop_quic_disabled: Bool
    let desktop_webrtc_locked: Bool
    let active_cli_pids: [String]?
    let unprotected_cli_pids: [String]
    let cli_ready: Bool
    let login_item_enabled: Bool
    let daily_patrol_enabled: Bool

    var hideOriginalPreference: Bool { hide_original_enabled ?? true }
    var isDesktopBypassLocked: Bool { desktop_bypass_locked ?? true }
    var allDesktopPIDs: [String] { desktop_pids ?? desktop_pid.map { [$0] } ?? [] }
    var activeCLIPIDs: [String] { active_cli_pids ?? [] }
}

struct LaunchDesktopOutcomeModel: Codable, Sendable {
    let ok: Bool
    let already_running: Bool
    let pid: Int?
    let message: String
}

struct KillOutcomeModel: Codable, Sendable {
    let killed_desktop: Int
    let killed_cli: Int
}

struct TelemetrySnapshot: Codable, Sendable {
    static let blockedRegions: Set<String> = ["CN", "HK", "MO", "RU", "BY", "KP", "IR", "SY", "CU", "VE"]

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
    var regionBanned: Bool {
        if let loc = claude_edge.loc?.trimmingCharacters(in: .whitespacesAndNewlines).uppercased(),
           Self.blockedRegions.contains(loc) {
            return true
        }
        if let loc = tun.loc?.trimmingCharacters(in: .whitespacesAndNewlines).uppercased(),
           Self.blockedRegions.contains(loc) {
            return true
        }
        return false
    }
    var desktopRunning: Bool { defenses.desktop_pid != nil || !defenses.allDesktopPIDs.isEmpty }
    var desktopUnprotected: Bool {
        desktopRunning
            && (!defenses.desktop_proxy_bound
                || !defenses.isDesktopBypassLocked
                || !defenses.desktop_quic_disabled
                || !defenses.desktop_webrtc_locked)
    }
    var hasActiveCLI: Bool { !defenses.activeCLIPIDs.isEmpty }
    var hasUnprotectedCLI: Bool { !defenses.unprotected_cli_pids.isEmpty }
    var anyClaudeRunning: Bool { desktopRunning || hasActiveCLI }

    var isConfirmedIPDrift: Bool {
        guard !expected_ip.isEmpty && expected_ip != "未配置" else { return false }
        let proxyDrifted = proxy.reachable && proxy.ip != expected_ip
        let tunDrifted = tun.reachable && tun.ip != expected_ip
        return proxyDrifted || tunDrifted
    }

    var isConfirmedNetworkBreach: Bool { isConfirmedIPDrift || regionBanned }

    var isSafe: Bool { proxyOK && tunOK && !regionBanned && !desktopUnprotected && !hasUnprotectedCLI }

    var defenseScore: Int {
        var s = 0
        if proxyOK && !regionBanned { s += 1 }
        if tunOK && !regionBanned { s += 1 }
        if defenses.oauth_locked { s += 1 }
        if defenses.original_hidden { s += 1 }
        if defenses.sandbox_enabled && defenses.telemetry_disabled { s += 1 }
        if !desktopUnprotected && !hasUnprotectedCLI && (defenses.cli_ready || desktopRunning) { s += 1 }
        if defenses.login_item_enabled { s += 1 }
        if defenses.daily_patrol_enabled { s += 1 }
        return s
    }

    func replacingDefenses(_ newDefenses: LocalDefenseModel) -> TelemetrySnapshot {
        TelemetrySnapshot(
            expected_ip: expected_ip,
            proxy_port: proxy_port,
            target_tz: target_tz,
            region_short: region_short,
            region_full: region_full,
            proxy: proxy,
            tun: tun,
            claude_edge: claude_edge,
            api_latency: api_latency,
            defenses: newDefenses,
            checked_at: checked_at
        )
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
            hide_original_enabled: true,
            sandbox_enabled: false,
            telemetry_disabled: false,
            desktop_pid: nil,
            desktop_pids: [],
            desktop_proxy_bound: true,
            desktop_bypass_locked: true,
            desktop_quic_disabled: true,
            desktop_webrtc_locked: true,
            active_cli_pids: [],
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
            if !p.region_supported || p.dns_leak || p.ipv6_leak || p.purity_score < 60 { return true }
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
