import SwiftUI

// MARK: - Ivory Porcelain & Brushed Titanium Design System

struct ShieldPalette {
    let isDark: Bool

    // Surfaces
    var canvasBg: Color {
        isDark ? Color(red: 0.078, green: 0.086, blue: 0.098) : Color(red: 0.961, green: 0.965, blue: 0.949)
    }

    var sidebarBg: Color {
        isDark ? Color(red: 0.098, green: 0.110, blue: 0.125) : Color(red: 0.929, green: 0.935, blue: 0.918)
    }

    var popoverGlassWash: Color {
        isDark
            ? Color(red: 0.094, green: 0.104, blue: 0.118).opacity(0.76)
            : Color(red: 0.968, green: 0.971, blue: 0.959).opacity(0.84)
    }

    var cardSurface: Color {
        isDark ? Color(red: 0.128, green: 0.140, blue: 0.158) : Color(red: 0.996, green: 0.997, blue: 0.994)
    }

    var popoverCardSurface: Color {
        isDark ? Color(red: 0.165, green: 0.178, blue: 0.200).opacity(0.76) : Color.white.opacity(0.89)
    }

    var recessedTray: Color {
        isDark ? Color.white.opacity(0.065) : Color(red: 0.09, green: 0.11, blue: 0.13).opacity(0.052)
    }

    var activeSegmentFill: Color {
        isDark ? Color(red: 0.235, green: 0.252, blue: 0.280) : Color.white
    }

    // Borders & Elevation
    var cardBorder: Color {
        isDark ? Color.white.opacity(0.095) : Color.black.opacity(0.065)
    }

    var cardSpecularBorder: LinearGradient {
        LinearGradient(
            colors: isDark
                ? [Color.white.opacity(0.16), Color.white.opacity(0.045)]
                : [Color.white.opacity(0.95), Color.black.opacity(0.075)],
            startPoint: .top,
            endPoint: .bottom
        )
    }

    var dividerColor: Color {
        isDark ? Color.white.opacity(0.075) : Color.black.opacity(0.058)
    }

    var cardShadow: Color {
        isDark ? Color.black.opacity(0.30) : Color(red: 0.06, green: 0.09, blue: 0.12).opacity(0.055)
    }

    // Typography Inks
    var inkPrimary: Color {
        isDark ? Color(red: 0.945, green: 0.953, blue: 0.965) : Color(red: 0.090, green: 0.102, blue: 0.118)
    }

    var labelColor: Color {
        isDark ? Color(red: 0.625, green: 0.655, blue: 0.698) : Color(red: 0.388, green: 0.416, blue: 0.455)
    }

    var subtleLabelColor: Color {
        isDark ? Color(red: 0.465, green: 0.495, blue: 0.538) : Color(red: 0.533, green: 0.561, blue: 0.600)
    }

    // Semantic Status & Mineral Titanium Accents
    var safeGreen: Color {
        isDark ? Color(red: 0.220, green: 0.835, blue: 0.604) : Color(red: 0.067, green: 0.588, blue: 0.396)
    }

    var warnAmber: Color {
        isDark ? Color(red: 0.961, green: 0.718, blue: 0.255) : Color(red: 0.765, green: 0.455, blue: 0.055)
    }

    var dangerRed: Color {
        isDark ? Color(red: 0.973, green: 0.435, blue: 0.455) : Color(red: 0.824, green: 0.196, blue: 0.247)
    }

    var titaniumAccent: Color {
        isDark ? Color(red: 0.320, green: 0.805, blue: 0.640) : Color(red: 0.110, green: 0.515, blue: 0.410)
    }

    // Primary Machined Titanium CTA (Deep Space Titanium on Ivory; Luminous Ivory Titanium on Dark)
    var primaryCTAGradient: LinearGradient {
        LinearGradient(
            colors: isDark
                ? [Color(red: 0.955, green: 0.958, blue: 0.946), Color(red: 0.875, green: 0.882, blue: 0.865)]
                : [Color(red: 0.184, green: 0.200, blue: 0.224), Color(red: 0.110, green: 0.122, blue: 0.141)],
            startPoint: .top,
            endPoint: .bottom
        )
    }

    var primaryCTAForeground: Color {
        isDark ? Color(red: 0.086, green: 0.098, blue: 0.114) : Color.white
    }

    var primaryCTABorder: Color {
        isDark ? Color.white.opacity(0.65) : Color.white.opacity(0.16)
    }

    var primaryCTAShadow: Color {
        isDark ? Color.black.opacity(0.32) : Color(red: 0.07, green: 0.09, blue: 0.12).opacity(0.22)
    }

    // Frosted Jade-Tinted Secondary Action Pill (Console / Launch accent)
    var jadePillFill: Color {
        safeGreen.opacity(isDark ? 0.16 : 0.105)
    }

    var jadePillBorder: Color {
        safeGreen.opacity(isDark ? 0.30 : 0.20)
    }

    // Soft top atmospheric halo inspired by frosted porcelain glass
    func topAtmosphereGlow(isSafe: Bool) -> LinearGradient {
        let tint = isSafe ? safeGreen : dangerRed
        return LinearGradient(
            colors: [
                tint.opacity(isDark ? 0.125 : 0.085),
                tint.opacity(isDark ? 0.035 : 0.025),
                Color.clear
            ],
            startPoint: .top,
            endPoint: .bottom
        )
    }
}
