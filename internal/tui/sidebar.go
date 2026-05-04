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
	parts = append(parts, lipgloss.NewStyle().Foreground(colors.Primary).Render("?"))
	parts = append(parts, lipgloss.NewStyle().Foreground(colors.Muted).Render("help"))
	parts = append(parts, lipgloss.NewStyle().Foreground(colors.Muted).Render("·"))

	// Context-sensitive help
	switch m.state {
	case stateDashboard:
		parts = append(parts, lipgloss.NewStyle().Foreground(colors.Primary).Render("s"))
		parts = append(parts, lipgloss.NewStyle().Foreground(colors.Muted).Render("scan"))
	case stateScan:
		parts = append(parts, lipgloss.NewStyle().Foreground(colors.Primary).Render("space"))
		parts = append(parts, lipgloss.NewStyle().Foreground(colors.Muted).Render("toggle"))
		parts = append(parts, lipgloss.NewStyle().Foreground(colors.Muted).Render("·"))
		parts = append(parts, lipgloss.NewStyle().Foreground(colors.Primary).Render("enter"))
		parts = append(parts, lipgloss.NewStyle().Foreground(colors.Muted).Render("start"))
	case stateScanning:
		parts = append(parts, lipgloss.NewStyle().Foreground(colors.Primary).Render("ctrl+c"))
		parts = append(parts, lipgloss.NewStyle().Foreground(colors.Muted).Render("cancel"))
	case stateResults:
		parts = append(parts, lipgloss.NewStyle().Foreground(colors.Primary).Render("↑↓"))
		parts = append(parts, lipgloss.NewStyle().Foreground(colors.Muted).Render("navigate"))
		parts = append(parts, lipgloss.NewStyle().Foreground(colors.Muted).Render("·"))
		parts = append(parts, lipgloss.NewStyle().Foreground(colors.Primary).Render("f"))
		parts = append(parts, lipgloss.NewStyle().Foreground(colors.Muted).Render("fix"))
		parts = append(parts, lipgloss.NewStyle().Foreground(colors.Muted).Render("·"))
		parts = append(parts, lipgloss.NewStyle().Foreground(colors.Primary).Render("e"))
		parts = append(parts, lipgloss.NewStyle().Foreground(colors.Muted).Render("export"))
	}

	parts = append(parts, lipgloss.NewStyle().Foreground(colors.Muted).Render("·"))
	parts = append(parts, lipgloss.NewStyle().Foreground(colors.Primary).Render("q"))
	parts = append(parts, lipgloss.NewStyle().Foreground(colors.Muted).Render("quit"))

	return helpStyle.Render(strings.Join(parts, " "))
}
