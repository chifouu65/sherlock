package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
)

func (m Model) renderSidebar() string {
	var b strings.Builder

	// Logo
	logo := lipgloss.NewStyle().
		Foreground(colors.Primary).
		Bold(true).
		Render("🕵️‍♂️  SHERLOCK")

	b.WriteString(logo)
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Render("  Security Agent"))
	b.WriteString("\n\n")

	// Separator
	sep := strings.Repeat("─", 20)
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Border).Render(sep))
	b.WriteString("\n\n")

	// Navigation
	for i, item := range navItems {
		var line string
		if i == m.navIndex {
			line = menuActiveStyle.Render(fmt.Sprintf(" %s %s", item.icon, item.name))
		} else {
			line = menuItemStyle.Render(fmt.Sprintf(" %s %s", item.icon, item.name))
		}
		b.WriteString(line)
		b.WriteString("\n")
	}

	// Separator
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Border).Render(sep))
	b.WriteString("\n\n")

	// Quick stats
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Render("📊 Stats"))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  Scans: %d\n", m.dashboard.totalScans))
	b.WriteString(fmt.Sprintf("  Findings: %d\n", m.dashboard.totalFindings))
	b.WriteString(fmt.Sprintf("  Fixed: %d\n", m.dashboard.fixedCount))

	return b.String()
}

func (m Model) renderHelpBar() string {
	var parts []string

	switch m.state {
	case stateDashboard:
		parts = append(parts, lipgloss.NewStyle().Foreground(colors.Muted).Render("↑↓ Navigate  Enter Select  q Quit"))
	case stateScan:
		parts = append(parts, lipgloss.NewStyle().Foreground(colors.Muted).Render("↑↓ Navigate  Space Toggle  Enter Start  Esc Back"))
	case stateScanning:
		parts = append(parts, lipgloss.NewStyle().Foreground(colors.Muted).Render("Scanning...  Esc Cancel"))
	case stateResults:
		parts = append(parts, lipgloss.NewStyle().Foreground(colors.Muted).Render("↑↓ Navigate  Enter Detail  Space Fix  Esc Back"))
	case stateVulnDB, stateReport, stateConfig:
		parts = append(parts, lipgloss.NewStyle().Foreground(colors.Muted).Render("↑↓ Navigate  Enter Select  Esc Back  q Quit"))
	default:
		parts = append(parts, lipgloss.NewStyle().Foreground(colors.Muted).Render("↑↓ Navigate  Enter Select  Esc Back  q Quit"))
	}

	return helpStyle.Render(strings.Join(parts, " "))
}
