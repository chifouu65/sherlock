package tui

import (
	"github.com/charmbracelet/lipgloss"
)

// Palette Sherlock 🕵️‍♂️
var colors = struct {
	Bg        lipgloss.Color
	Fg        lipgloss.Color
	Primary   lipgloss.Color
	Secondary lipgloss.Color
	Success   lipgloss.Color
	Warning   lipgloss.Color
	Error     lipgloss.Color
	Info      lipgloss.Color
	Muted     lipgloss.Color
	Accent    lipgloss.Color
	Highlight lipgloss.Color
	Border    lipgloss.Color
	DarkBg    lipgloss.Color
}{
	Bg:        lipgloss.Color("#0F0F1A"),
	Fg:        lipgloss.Color("#E2E8F0"),
	Primary:   lipgloss.Color("#8B5CF6"),
	Secondary: lipgloss.Color("#EC4899"),
	Success:   lipgloss.Color("#10B981"),
	Warning:   lipgloss.Color("#F59E0B"),
	Error:     lipgloss.Color("#EF4444"),
	Info:      lipgloss.Color("#3B82F6"),
	Muted:     lipgloss.Color("#64748B"),
	Accent:    lipgloss.Color("#06B6D4"),
	Highlight: lipgloss.Color("#FCD34D"),
	Border:    lipgloss.Color("#334155"),
	DarkBg:    lipgloss.Color("#1E293B"),
}

var (
	// Layout
	sidebarStyle = lipgloss.NewStyle().
				Background(colors.Bg).
				Foreground(colors.Fg).
				BorderStyle(lipgloss.RoundedBorder()).
				BorderForeground(colors.Primary).
				Padding(1, 1)

	contentStyle = lipgloss.NewStyle().
				Background(colors.Bg).
				Foreground(colors.Fg).
				BorderStyle(lipgloss.RoundedBorder()).
				BorderForeground(colors.Border).
				Padding(1, 2)

	headerStyle = lipgloss.NewStyle().
				Background(colors.DarkBg).
				Foreground(colors.Fg).
				BorderStyle(lipgloss.RoundedBorder()).
				BorderForeground(colors.Primary).
				Padding(0, 2).
				Bold(true)

	titleStyle = lipgloss.NewStyle().
				Foreground(colors.Primary).
				Bold(true).
				Underline(true)

	subtitleStyle = lipgloss.NewStyle().
				Foreground(colors.Muted).
				Italic(true)

	// Severity badges
	criticalBadge = lipgloss.NewStyle().
				Background(colors.Error).
				Foreground(colors.Fg).
				Padding(0, 1).
				Bold(true).
				Render

	highBadge = lipgloss.NewStyle().
				Background(lipgloss.Color("#B91C1C")).
				Foreground(colors.Fg).
				Padding(0, 1).
				Bold(true).
				Render

	mediumBadge = lipgloss.NewStyle().
				Background(colors.Warning).
				Foreground(colors.Bg).
				Padding(0, 1).
				Bold(true).
				Render

	lowBadge = lipgloss.NewStyle().
				Background(lipgloss.Color("#059669")).
				Foreground(colors.Fg).
				Padding(0, 1).
				Render

	infoBadge = lipgloss.NewStyle().
				Background(colors.Info).
				Foreground(colors.Fg).
				Padding(0, 1).
				Render

	// Scan status
	scanningStyle = lipgloss.NewStyle().
				Foreground(colors.Accent).
				Bold(true).
				Blink(true)

	successStyle = lipgloss.NewStyle().
				Foreground(colors.Success).
				Bold(true)

	failStyle = lipgloss.NewStyle().
				Foreground(colors.Error).
				Bold(true)

	// Menu
	menuItemStyle = lipgloss.NewStyle().
				Foreground(colors.Muted)

	menuActiveStyle = lipgloss.NewStyle().
				Background(colors.Primary).
				Foreground(colors.Fg).
				Bold(true).
				Padding(0, 1)

	// Progress bar
	progressBarStyle = lipgloss.NewStyle().
				Background(colors.DarkBg).
				Foreground(colors.Primary)

	progressFillStyle = lipgloss.NewStyle().
				Background(colors.Primary).
				Foreground(colors.Fg)

	// Help bar
	helpStyle = lipgloss.NewStyle().
				Foreground(colors.Muted).
				Background(colors.DarkBg).
				Padding(0, 1)

	// Dialog/Modal
	modalStyle = lipgloss.NewStyle().
				Background(colors.DarkBg).
				BorderStyle(lipgloss.RoundedBorder()).
				BorderForeground(colors.Accent).
				Padding(2, 4).
				Width(60)
)

func severityBadge(sev string) string {
	switch sev {
	case "Critical", "CRITICAL", "critical":
		return criticalBadge("CRITICAL")
	case "High", "HIGH", "high":
		return highBadge("HIGH")
	case "Medium", "MEDIUM", "medium":
		return mediumBadge("MEDIUM")
	case "Low", "LOW", "low":
		return lowBadge("LOW")
	default:
		return infoBadge("INFO")
	}
}
