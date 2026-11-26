import Cocoa
import SwiftUI

// MARK: - Shared Metric Thresholds & Interaction Primitives

enum ShieldMetricsStyle {
    static func purityColor(_ score: Int, safe: Color, warn: Color, danger: Color) -> Color {
        if score >= LaunchGuardContext.safePurityThreshold { return safe }
        if score >= 60 { return warn }
        return danger
    }

    static func latencyColor(_ ms: Int, safe: Color, warn: Color, danger: Color) -> Color {
        if ms < 350 { return safe }
        if ms < 700 { return warn }
        return danger
    }

    static func apiLatencyColor(_ ms: Int, jitter: Int?, safe: Color, warn: Color, danger: Color) -> Color {
        let j = jitter ?? 0
        if ms >= 800 || j >= 150 { return danger }
        if ms >= 450 || j >= 80 { return warn }
        return safe
    }
}

final class LocalState<Value>: ObservableObject {
    @Published var value: Value
    init(_ initial: Value) { self.value = initial }
}

struct SnappyButtonStyle: ButtonStyle {
    var scale: CGFloat = 0.97
    var pressedOpacity: Double = 0.88

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .scaleEffect(configuration.isPressed ? scale : 1.0)
            .opacity(configuration.isPressed ? pressedOpacity : 1.0)
            .animation(.easeOut(duration: 0.08), value: configuration.isPressed)
    }
}

enum MenuBarShieldState: Hashable {
    case loading
    case armed
    case alert
}

enum ShieldBrandGraphics {
    private static var menuBarIconCache: [MenuBarShieldState: NSImage] = [:]
    private static var badgeEmblemCache: [String: NSImage] = [:]

    private static let sparkTemplateCG: CGImage? = {
        let candidates: [URL?] = [
            Bundle.main.url(forResource: "claude-spark-template", withExtension: "png"),
            URL(fileURLWithPath: FileManager.default.currentDirectoryPath)
                .appendingPathComponent("assets/claude-spark-template.png"),
        ]
        for url in candidates.compactMap({ $0 }) {
            if let img = NSImage(contentsOf: url),
               let cg = img.cgImage(forProposedRect: nil, context: nil, hints: nil) {
                return cg
            }
        }
        return nil
    }()

    static func tautShieldPath(cx: CGFloat, cy: CGFloat, w: CGFloat, h: CGFloat) -> CGPath {
        let hw = w / 2.0
        let hh = h / 2.0
        func pt(_ nx: CGFloat, _ ny: CGFloat) -> CGPoint {
            CGPoint(x: cx + nx * hw, y: cy + ny * hh)
        }

        let p = CGMutablePath()
        p.move(to: pt(0.0, 0.99))
        p.addCurve(to: pt(0.89, 0.84), control1: pt(0.28, 0.99), control2: pt(0.64, 0.93))
        p.addCurve(to: pt(0.99, 0.70), control1: pt(0.96, 0.81), control2: pt(0.99, 0.77))
        p.addCurve(to: pt(0.90, 0.02), control1: pt(0.99, 0.44), control2: pt(0.97, 0.22))
        p.addCurve(to: pt(0.07, -0.96), control1: pt(0.80, -0.44), control2: pt(0.45, -0.80))
        p.addCurve(to: pt(-0.07, -0.96), control1: pt(0.025, -0.995), control2: pt(-0.025, -0.995))
        p.addCurve(to: pt(-0.90, 0.02), control1: pt(-0.45, -0.80), control2: pt(-0.80, -0.44))
        p.addCurve(to: pt(-0.99, 0.70), control1: pt(-0.97, 0.22), control2: pt(-0.99, 0.44))
        p.addCurve(to: pt(-0.89, 0.84), control1: pt(-0.99, 0.77), control2: pt(-0.96, 0.81))
        p.addCurve(to: pt(0.0, 0.99), control1: pt(-0.64, 0.93), control2: pt(-0.28, 0.99))
        p.closeSubpath()
        return p
    }

    static func drawTwinWingShield(
        in ctx: CGContext,
        cx: CGFloat,
        cy: CGFloat,
        cutCenterY: CGFloat,
        outerW: CGFloat,
        outerH: CGFloat,
        ringThicknessX: CGFloat,
        ringThicknessY: CGFloat,
        gapWidth: CGFloat,
        upperLeftColor: CGColor,
        lowerRightColor: CGColor
    ) {
        let outerShield = tautShieldPath(cx: cx, cy: cy, w: outerW, h: outerH)
        let innerShield = tautShieldPath(
            cx: cx,
            cy: cy + outerH * 0.004,
            w: max(1, outerW - ringThicknessX * 2),
            h: max(1, outerH - ringThicknessY * 2)
        )

        let ring = CGMutablePath()
        ring.addPath(outerShield)
        ring.addPath(innerShield)

        let shift = (gapWidth / 2.0) * sqrt(2.0)
        let span = max(outerW, outerH) * 2.5

        ctx.saveGState()
        ctx.addPath(ring)
        ctx.clip(using: .evenOdd)
        let ulPoly = CGMutablePath()
        ulPoly.move(to: CGPoint(x: cx - span, y: cutCenterY - span + shift))
        ulPoly.addLine(to: CGPoint(x: cx + span, y: cutCenterY + span + shift))
        ulPoly.addLine(to: CGPoint(x: cx + span, y: cutCenterY + span * 2.5))
        ulPoly.addLine(to: CGPoint(x: cx - span, y: cutCenterY + span * 2.5))
        ulPoly.closeSubpath()
        ctx.addPath(ulPoly)
        ctx.setFillColor(upperLeftColor)
        ctx.fillPath()
        ctx.restoreGState()

        ctx.saveGState()
        ctx.addPath(ring)
        ctx.clip(using: .evenOdd)
        let lrPoly = CGMutablePath()
        lrPoly.move(to: CGPoint(x: cx - span, y: cutCenterY - span - shift))
        lrPoly.addLine(to: CGPoint(x: cx + span, y: cutCenterY + span - shift))
        lrPoly.addLine(to: CGPoint(x: cx + span, y: cutCenterY - span * 2.5))
        lrPoly.addLine(to: CGPoint(x: cx - span, y: cutCenterY - span * 2.5))
        lrPoly.closeSubpath()
        ctx.addPath(lrPoly)
        ctx.setFillColor(lowerRightColor)
        ctx.fillPath()
        ctx.restoreGState()
    }

    static func drawClaudeSpark(in ctx: CGContext, rect: CGRect, tint: CGColor) {
        if let sparkCG = sparkTemplateCG {
            ctx.saveGState()
            ctx.interpolationQuality = .high
            ctx.clip(to: rect, mask: sparkCG)
            ctx.setFillColor(tint)
            ctx.fill(rect)
            ctx.restoreGState()
            return
        }

        let cx = rect.midX
        let cy = rect.midY
        let r = min(rect.width, rect.height) * 0.46
        ctx.saveGState()
        ctx.setStrokeColor(tint)
        ctx.setLineWidth(max(1.2, r * 0.22))
        ctx.setLineCap(.round)
        for i in 0..<8 {
            let a = CGFloat(i) * (.pi / 4.0)
            let len = (i % 2 == 0) ? r : r * 0.84
            ctx.move(to: CGPoint(x: cx, y: cy))
            ctx.addLine(to: CGPoint(x: cx + cos(a) * len, y: cy + sin(a) * len))
        }
        ctx.strokePath()
        ctx.restoreGState()
    }

    static func makeMenuBarIcon(state: MenuBarShieldState) -> NSImage {
        if let cached = menuBarIconCache[state] {
            return cached
        }
        let size = NSSize(width: 18, height: 18)
        let image = NSImage(size: size, flipped: false) { rect in
            guard let ctx = NSGraphicsContext.current?.cgContext else { return false }
            ctx.setAllowsAntialiasing(true)
            ctx.setShouldAntialias(true)

            let primaryColor: NSColor
            let secondaryColor: NSColor
            let sparkColor: NSColor
            let dotColor: NSColor

            switch state {
            case .armed:
                primaryColor = NSColor.labelColor
                secondaryColor = NSColor.labelColor.withAlphaComponent(0.72)
                sparkColor = NSColor.labelColor
                dotColor = NSColor(srgbRed: 0.13, green: 0.77, blue: 0.42, alpha: 1.0)
            case .loading:
                primaryColor = NSColor.labelColor.withAlphaComponent(0.88)
                secondaryColor = NSColor.labelColor.withAlphaComponent(0.58)
                sparkColor = NSColor.labelColor.withAlphaComponent(0.85)
                dotColor = NSColor(srgbRed: 0.96, green: 0.65, blue: 0.14, alpha: 1.0)
            case .alert:
                let alertRed = NSColor(srgbRed: 0.95, green: 0.29, blue: 0.29, alpha: 1.0)
                primaryColor = alertRed
                secondaryColor = alertRed.withAlphaComponent(0.76)
                sparkColor = alertRed
                dotColor = alertRed
            }

            let cx = rect.midX - 0.5
            let cy = rect.midY
            let cutY = cy + 0.8

            ctx.beginTransparencyLayer(auxiliaryInfo: nil)

            drawTwinWingShield(
                in: ctx,
                cx: cx,
                cy: cy,
                cutCenterY: cutY,
                outerW: 13.4,
                outerH: 15.8,
                ringThicknessX: 1.95,
                ringThicknessY: 2.15,
                gapWidth: 1.15,
                upperLeftColor: primaryColor.cgColor,
                lowerRightColor: secondaryColor.cgColor
            )

            if state == .alert {
                ctx.saveGState()
                ctx.setFillColor(sparkColor.cgColor)
                let bar = CGRect(x: cx - 0.85, y: cutY - 0.6, width: 1.7, height: 4.5)
                ctx.addPath(CGPath(roundedRect: bar, cornerWidth: 0.85, cornerHeight: 0.85, transform: nil))
                ctx.fillPath()
                ctx.fillEllipse(in: CGRect(x: cx - 0.9, y: cutY - 3.1, width: 1.8, height: 1.8))
                ctx.restoreGState()
            } else {
                let sparkSize: CGFloat = 6.8
                let sparkRect = CGRect(x: cx - sparkSize / 2.0, y: cutY - sparkSize / 2.0, width: sparkSize, height: sparkSize)
                drawClaudeSpark(in: ctx, rect: sparkRect, tint: sparkColor.cgColor)
            }

            let dotCenter = CGPoint(x: rect.maxX - 3.3, y: rect.minY + 3.4)
            let haloR: CGFloat = 3.55
            ctx.saveGState()
            ctx.setBlendMode(.clear)
            ctx.fillEllipse(in: CGRect(x: dotCenter.x - haloR, y: dotCenter.y - haloR, width: haloR * 2, height: haloR * 2))
            ctx.restoreGState()

            ctx.endTransparencyLayer()

            let dotR: CGFloat = 2.45
            ctx.saveGState()
            ctx.setFillColor(dotColor.cgColor)
            ctx.fillEllipse(in: CGRect(x: dotCenter.x - dotR, y: dotCenter.y - dotR, width: dotR * 2, height: dotR * 2))
            ctx.restoreGState()

            return true
        }
        image.isTemplate = false
        menuBarIconCache[state] = image
        return image
    }

    static func makePopoverBadgeEmblem(isSafe: Bool, isDark: Bool) -> NSImage {
        let cacheKey = "\(isSafe)-\(isDark)"
        if let cached = badgeEmblemCache[cacheKey] {
            return cached
        }
        let ptSize: CGFloat = 38
        let scale: CGFloat = 3
        let pxSize = Int(ptSize * scale)
        let cs = CGColorSpace(name: CGColorSpace.sRGB) ?? CGColorSpaceCreateDeviceRGB()
        guard let ctx = CGContext(
            data: nil,
            width: pxSize,
            height: pxSize,
            bitsPerComponent: 8,
            bytesPerRow: 0,
            space: cs,
            bitmapInfo: CGImageAlphaInfo.premultipliedLast.rawValue
        ) else {
            return NSImage(size: NSSize(width: ptSize, height: ptSize))
        }
        ctx.interpolationQuality = .high
        ctx.setAllowsAntialiasing(true)
        ctx.setShouldAntialias(true)
        ctx.scaleBy(x: scale, y: scale)

        let cx = ptSize / 2.0
        let cy = ptSize / 2.0 - 0.3
        let sparkCy = cy + 1.5

        let ulColor: CGColor
        let lrColor: CGColor
        let sparkTint: CGColor

        if isSafe {
            ulColor = isDark
                ? CGColor(srgbRed: 0.95, green: 0.93, blue: 0.89, alpha: 1.0)
                : CGColor(srgbRed: 0.114, green: 0.110, blue: 0.102, alpha: 1.0)
            lrColor = isDark
                ? CGColor(srgbRed: 0.72, green: 0.69, blue: 0.65, alpha: 1.0)
                : CGColor(srgbRed: 0.239, green: 0.227, blue: 0.212, alpha: 1.0)
            sparkTint = CGColor(srgbRed: 0.851, green: 0.463, blue: 0.333, alpha: 1.0)
        } else {
            ulColor = isDark
                ? CGColor(srgbRed: 0.98, green: 0.42, blue: 0.44, alpha: 1.0)
                : CGColor(srgbRed: 0.84, green: 0.16, blue: 0.16, alpha: 1.0)
            lrColor = isDark
                ? CGColor(srgbRed: 0.82, green: 0.26, blue: 0.28, alpha: 1.0)
                : CGColor(srgbRed: 0.68, green: 0.12, blue: 0.12, alpha: 1.0)
            sparkTint = ulColor
        }

        drawTwinWingShield(
            in: ctx,
            cx: cx,
            cy: cy,
            cutCenterY: sparkCy,
            outerW: 23.2,
            outerH: 27.6,
            ringThicknessX: 2.7,
            ringThicknessY: 3.1,
            gapWidth: 1.45,
            upperLeftColor: ulColor,
            lowerRightColor: lrColor
        )

        if isSafe {
            let sparkSize: CGFloat = 11.8
            let sparkRect = CGRect(x: cx - sparkSize / 2.0, y: sparkCy - sparkSize / 2.0, width: sparkSize, height: sparkSize)
            drawClaudeSpark(in: ctx, rect: sparkRect, tint: sparkTint)
        } else {
            ctx.saveGState()
            ctx.setFillColor(sparkTint)
            let bar = CGRect(x: cx - 1.25, y: sparkCy - 1.0, width: 2.5, height: 6.4)
            ctx.addPath(CGPath(roundedRect: bar, cornerWidth: 1.25, cornerHeight: 1.25, transform: nil))
            ctx.fillPath()
            ctx.fillEllipse(in: CGRect(x: cx - 1.35, y: sparkCy - 4.4, width: 2.7, height: 2.7))
            ctx.restoreGState()
        }

        guard let cg = ctx.makeImage() else {
            return NSImage(size: NSSize(width: ptSize, height: ptSize))
        }
        let img = NSImage(cgImage: cg, size: NSSize(width: ptSize, height: ptSize))
        badgeEmblemCache[cacheKey] = img
        return img
    }
}

struct PulsingOpacityView<Content: View>: View {
    let isActive: Bool
    let duration: Double
    let minOpacity: Double
    let maxOpacity: Double
    @ViewBuilder let content: () -> Content

    @StateObject private var isPulsing = LocalState(false)

    private func stopPulse() {
        guard isPulsing.value else { return }
        var tx = Transaction()
        tx.disablesAnimations = true
        withTransaction(tx) {
            isPulsing.value = false
        }
    }

    var body: some View {
        content()
            .opacity(isPulsing.value ? maxOpacity : minOpacity)
            .animation(
                isActive && isPulsing.value
                    ? .easeInOut(duration: duration).repeatForever(autoreverses: true)
                    : nil,
                value: isPulsing.value
            )
            .task(id: isActive) {
                guard isActive else {
                    stopPulse()
                    return
                }
                // Let initial window/layout commit finish before starting leaf opacity pulse
                try? await Task.sleep(nanoseconds: 40_000_000)
                guard !Task.isCancelled, isActive else { return }
                isPulsing.value = true
            }
            .onDisappear {
                stopPulse()
            }
    }
}

struct ShieldStatusBadge: View {
    let isSafe: Bool
    let accentColor: Color
    let isDark: Bool
    var isActive: Bool = true

    var body: some View {
        let tileBgTop = isDark
            ? Color(red: 0.17, green: 0.165, blue: 0.16)
            : Color(red: 0.97, green: 0.953, blue: 0.925)
        let tileBgBot = isDark
            ? Color(red: 0.125, green: 0.12, blue: 0.115)
            : Color(red: 0.925, green: 0.894, blue: 0.843)
        let tileBorder = isSafe
            ? (isDark ? Color.white.opacity(0.14) : Color.black.opacity(0.09))
            : accentColor.opacity(isDark ? 0.55 : 0.45)

        ZStack {
            PulsingOpacityView(
                isActive: isActive,
                duration: 1.9,
                minOpacity: isDark ? 0.09 : 0.06,
                maxOpacity: isDark ? 0.24 : 0.16
            ) {
                RoundedRectangle(cornerRadius: 13.5, style: .continuous)
                    .fill(accentColor)
            }
            .frame(width: 46, height: 46)

            RoundedRectangle(cornerRadius: 10.5, style: .continuous)
                .fill(
                    LinearGradient(
                        colors: [tileBgTop, tileBgBot],
                        startPoint: .top,
                        endPoint: .bottom
                    )
                )
                .frame(width: 38, height: 38)
                .overlay(
                    RoundedRectangle(cornerRadius: 10.5, style: .continuous)
                        .strokeBorder(tileBorder, lineWidth: 0.9)
                )
                .shadow(color: Color.black.opacity(isDark ? 0.30 : 0.09), radius: 4, y: 1.5)

            Image(nsImage: ShieldBrandGraphics.makePopoverBadgeEmblem(isSafe: isSafe, isDark: isDark))
                .resizable()
                .interpolation(.high)
                .frame(width: 38, height: 38)

            Circle()
                .fill(accentColor)
                .frame(width: 8.5, height: 8.5)
                .overlay(
                    Circle()
                        .strokeBorder(isDark ? Color(red: 0.13, green: 0.14, blue: 0.15) : Color(red: 0.96, green: 0.96, blue: 0.95), lineWidth: 1.8)
                )
                .shadow(color: accentColor.opacity(0.45), radius: 2.5, y: 0.5)
                .offset(x: 15.5, y: 15.5)
        }
    }
}

struct HoverableActionButton: View {
    let icon: String
    let title: String
    var tint: Color = .primary
    var isLoading: Bool = false
    var isDestructive: Bool = false
    let isDark: Bool
    let cardSurface: Color
    let cardBorder: Color
    let cardShadow: Color
    let dangerRed: Color
    let helpText: String
    let action: () -> Void

    @StateObject private var hoverState = LocalState(false)

    private var fillColor: Color {
        let hovered = hoverState.value
        if isDestructive {
            return dangerRed.opacity(hovered ? (isDark ? 0.24 : 0.14) : (isDark ? 0.16 : 0.09))
        }
        if hovered {
            return isDark ? Color.white.opacity(0.12) : Color.white.opacity(0.95)
        }
        return cardSurface
    }

    private var borderColor: Color {
        let hovered = hoverState.value
        if isDestructive {
            return dangerRed.opacity(hovered ? 0.45 : (isDark ? 0.35 : 0.25))
        }
        if hovered {
            return isDark ? Color.white.opacity(0.20) : Color.black.opacity(0.14)
        }
        return cardBorder
    }

    var body: some View {
        Button(action: action) {
            HStack(spacing: 5) {
                if isLoading {
                    ProgressView()
                        .controlSize(.mini)
                        .scaleEffect(0.82)
                        .frame(width: 11, height: 11)
                } else {
                    Image(systemName: icon)
                        .font(.system(size: 11, weight: .semibold))
                        .foregroundColor(tint)
                }
                Text(title)
                    .font(.system(size: 10.5, weight: .semibold))
                    .foregroundColor(isDestructive ? dangerRed : .primary)
                    .lineLimit(1)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 7.5)
            .background(
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .fill(fillColor)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 9, style: .continuous)
                    .strokeBorder(borderColor, lineWidth: 0.8)
            )
            .shadow(color: cardShadow, radius: 2, y: 1)
            .contentShape(RoundedRectangle(cornerRadius: 9, style: .continuous))
        }
        .buttonStyle(SnappyButtonStyle())
        .onHover { hovering in
            withAnimation(.easeOut(duration: 0.12)) {
                hoverState.value = hovering
            }
        }
        .disabled(isLoading)
        .help(helpText)
    }
}

struct MatchedHeightTabStack: Layout {
    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        let width = proposal.width ?? 400
        let childProposal = ProposedViewSize(width: width, height: nil)
        let maxHeight = subviews.map { $0.sizeThatFits(childProposal).height }.max() ?? 0
        return CGSize(width: width, height: maxHeight)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) {
        let exactProposal = ProposedViewSize(width: bounds.width, height: bounds.height)
        for subview in subviews {
            subview.place(at: bounds.origin, anchor: .topLeading, proposal: exactProposal)
        }
    }
}

struct SegmentedTabItemButton: View {
    let tab: ShieldTab
    let active: Bool
    let purityScore: Int?
    let scoreColor: Color
    let isDark: Bool
    let brandGradient: LinearGradient
    let namespace: Namespace.ID
    let action: () -> Void

    @StateObject private var hoverState = LocalState(false)

    var body: some View {
        let hovered = hoverState.value && !active
        let textColor: Color = active ? .white : .primary.opacity(hovered ? 0.92 : 0.72)
        let hoverFill: Color = isDark ? Color.white.opacity(0.06) : Color.black.opacity(0.045)

        Button(action: action) {
            HStack(spacing: 5) {
                Image(systemName: tab == .radar ? "shield.checkered" : "sparkle.magnifyingglass")
                    .font(.system(size: 11, weight: .semibold))
                Text(tab.rawValue)
                    .font(.system(size: 11.5, weight: .semibold))
                if tab == .purity, let score = purityScore {
                    Text("\(score)分")
                        .font(.system(size: 9.5, weight: .bold, design: .monospaced))
                        .foregroundColor(active ? .white.opacity(0.95) : scoreColor)
                        .padding(.horizontal, 4.5)
                        .padding(.vertical, 1)
                        .background(Capsule().fill(active ? Color.white.opacity(0.22) : scoreColor.opacity(0.15)))
                }
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 6.5)
            .foregroundColor(textColor)
            .background(
                ZStack {
                    if active {
                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .fill(brandGradient)
                            .shadow(color: Color(red: 0.75, green: 0.31, blue: 0.18).opacity(0.24), radius: 3, y: 1)
                            .matchedGeometryEffect(id: "activeTabPill", in: namespace)
                    } else if hovered {
                        RoundedRectangle(cornerRadius: 8, style: .continuous)
                            .fill(hoverFill)
                    }
                }
            )
            .contentShape(RoundedRectangle(cornerRadius: 8, style: .continuous))
        }
        .buttonStyle(SnappyButtonStyle(scale: 0.985, pressedOpacity: 0.92))
        .onHover { hovering in
            withAnimation(.easeOut(duration: 0.12)) {
                hoverState.value = hovering
            }
        }
    }
}

struct PrimaryLaunchButton: View {
    let desktopRunning: Bool
    let isSafe: Bool
    var isLoading: Bool = false
    let brandGradient: LinearGradient
    let action: () -> Void

    @StateObject private var hoverState = LocalState(false)

    var body: some View {
        let hovered = hoverState.value
        Button(action: action) {
            HStack(spacing: 6) {
                if isLoading {
                    ProgressView()
                        .controlSize(.small)
                        .scaleEffect(0.72)
                        .frame(width: 13, height: 13)
                } else {
                    Image(systemName: desktopRunning ? "macwindow.on.rectangle" : "play.fill")
                        .font(.system(size: 11.5, weight: .semibold))
                }
                Text(isLoading ? "正在核验出口 IP 与纯净度..." : (desktopRunning ? "聚焦 Claude 桌面版" : "安全启动 Claude 桌面版"))
                    .font(.system(size: 12.5, weight: .semibold))
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 9)
            .foregroundColor(.white)
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(isSafe ? AnyShapeStyle(brandGradient) : AnyShapeStyle(Color.gray.opacity(0.65)))
                    .brightness(hovered ? 0.04 : 0)
            )
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .strokeBorder(Color.white.opacity(hovered ? 0.28 : 0.18), lineWidth: 0.7)
            )
            .shadow(color: isSafe ? Color(red: 0.75, green: 0.31, blue: 0.18).opacity(hovered ? 0.36 : 0.28) : .clear, radius: hovered ? 6 : 4, y: 2)
            .contentShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
        }
        .buttonStyle(SnappyButtonStyle(scale: 0.98, pressedOpacity: 0.92))
        .disabled(isLoading)
        .onHover { hovering in
            withAnimation(.easeOut(duration: 0.12)) {
                hoverState.value = hovering
            }
        }
    }
}

struct VisualEffectView: NSViewRepresentable {
    let material: NSVisualEffectView.Material
    let blendingMode: NSVisualEffectView.BlendingMode

    func makeNSView(context: Context) -> NSVisualEffectView {
        let view = NSVisualEffectView()
        view.material = material
        view.blendingMode = blendingMode
        view.state = .active
        return view
    }

    func updateNSView(_ nsView: NSVisualEffectView, context: Context) {
        nsView.material = material
        nsView.blendingMode = blendingMode
    }
}

struct StyledSettingsInput: View {
    let placeholder: String
    @Binding var text: String
    let isDark: Bool
    var isMonospaced: Bool = true
    @FocusState private var isFocused: Bool

    var body: some View {
        let accent = Color(red: 0.85, green: 0.43, blue: 0.27)
        TextField(placeholder, text: $text)
            .textFieldStyle(.plain)
            .focused($isFocused)
            .font(.system(size: 13.5, weight: .medium, design: isMonospaced ? .monospaced : .default))
            .foregroundColor(.primary)
            .padding(.horizontal, 12)
            .frame(height: 38)
            .background(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .fill(isDark ? Color.black.opacity(0.28) : Color.white.opacity(0.92))
            )
            .overlay(
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .strokeBorder(
                        isFocused ? accent.opacity(0.85) : (isDark ? Color.white.opacity(0.13) : Color.black.opacity(0.11)),
                        lineWidth: isFocused ? 1.5 : 0.9
                    )
            )
            .shadow(color: isFocused ? accent.opacity(0.16) : .clear, radius: 4, y: 0)
            .animation(.easeOut(duration: 0.14), value: isFocused)
    }
}
