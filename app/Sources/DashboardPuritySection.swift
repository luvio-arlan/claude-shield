import SwiftUI

// MARK: - Studio Console Section 2: 纯净度体检

extension ShieldDashboardView {
    func puritySectionContent(wide: Bool) -> some View {
        let fourCols = Array(repeating: GridItem(.flexible(), spacing: 12), count: wide ? 4 : 2)
        return VStack(alignment: .leading, spacing: 14) {
            if let p = vm.purity {
                let pc = purityColor(p.purity_score)
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
                        .foregroundColor(palette.primaryCTAForeground)
                        .padding(.horizontal, 14)
                        .frame(height: 34)
                        .background(RoundedRectangle(cornerRadius: 10, style: .continuous).fill(palette.primaryCTAGradient))
                        .overlay(RoundedRectangle(cornerRadius: 10, style: .continuous).strokeBorder(palette.primaryCTABorder, lineWidth: 0.7))
                        .shadow(color: palette.primaryCTAShadow, radius: 5, y: 2)
                    }
                    .buttonStyle(SnappyButtonStyle(scale: 0.97))
                    .disabled(vm.isAuditing)
                }
                .padding(18)
                .background(RoundedRectangle(cornerRadius: 16, style: .continuous).fill(cardSurface))
                .overlay(RoundedRectangle(cornerRadius: 16, style: .continuous).strokeBorder(pc.opacity(0.22), lineWidth: 0.85))
                .shadow(color: cardShadow, radius: 6, y: 2)

                LazyVGrid(columns: fourCols, spacing: 12) {
                    dashboardLeakCard(title: "Claude 边缘", value: p.claude_edge_match ? (p.claude_colo ?? "一致") : "异常", ok: p.claude_edge_match)
                    dashboardLeakCard(title: "DNS 通道", value: p.dns_leak ? "检测到泄露!" : "零泄露", ok: !p.dns_leak)
                    dashboardLeakCard(title: "IPv6 隔离", value: p.ipv6_leak ? "检测到泄露!" : "已封闭", ok: !p.ipv6_leak)
                    dashboardLeakCard(title: "时区对齐", value: p.timezone_aligned ? "完全对齐" : "存在偏移!", ok: p.timezone_aligned)
                }

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
}
