package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

func (m Model) updateDashboard(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case msg.String() == "s":
		m.state = stateScan
		m.navIndex = indexOfNav(stateScan)
	case msg.String() == "v":
		m.state = stateVulnDB
		m.navIndex = indexOfNav(stateVulnDB)
	}
	return m, nil
}

func (m Model) renderDashboard() string {
	var b strings.Builder

	// Title
	b.WriteString(titleStyle.Render("Dashboard"))
	b.WriteString("\n")
	b.WriteString(subtitleStyle.Render("Overview of your security posture"))
	b.WriteString("\n\n")

	// Cards grid
	cards := m.renderCards()
	b.WriteString(cards)
	b.WriteString("\n\n")

	// Recent activity
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Render("Recent Activity"))
	b.WriteString("\n")
	if m.dashboard.lastScan.IsZero() {
		b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Italic(true).Render("  No scans yet. Press 's' to start your first scan."))
	} else {
		b.WriteString(fmt.Sprintf("  Last scan: %s ago\n", timeSince(m.dashboard.lastScan)))
		b.WriteString(fmt.Sprintf("  Findings: %d total (%d critical, %d high, %d medium, %d low)\n",
			m.dashboard.totalFindings, m.dashboard.criticalCount, m.dashboard.highCount,
			m.dashboard.mediumCount, m.dashboard.lowCount))
	}

	// Quick actions
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Render("Quick Actions"))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Accent).Render("  [s] Start a scan"))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Accent).Render("  [v] Browse VulnDB"))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Accent).Render("  [?] Show help"))

	return b.String()
}

func (m Model) renderCards() string {
	cardStyle := lipgloss.NewStyle().
		Background(colors.DarkBg).
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(colors.Border).
		Padding(1, 2).
		Width(22)

	var cards []string

	// Total Findings
	cards = append(cards, cardStyle.Render(
		lipgloss.NewStyle().Foreground(colors.Muted).Render("Total Findings")+"\n"+
			lipgloss.NewStyle().Foreground(colors.Fg).Bold(true).FontSize(2).Render(fmt.Sprintf("%d", m.dashboard.totalFindings)),
	))

	// Critical
	cards = append(cards, cardStyle.BorderForeground(colors.Error).Render(
		lipgloss.NewStyle().Foreground(colors.Error).Render("Critical")+"\n"+
			lipgloss.NewStyle().Foreground(colors.Error).Bold(true).FontSize(2).Render(fmt.Sprintf("%d", m.dashboard.criticalCount)),
	))

	// High
	cards = append(cards, cardStyle.BorderForeground(lipgloss.Color("#B91C1C")).Render(
		lipgloss.NewStyle().Foreground(lipgloss.Color("#B91C1C")).Render("High")+"\n"+
			lipgloss.NewStyle().Foreground(lipgloss.Color("#B91C1C")).Bold(true).FontSize(2).Render(fmt.Sprintf("%d", m.dashboard.highCount)),
	))

	// Fixed
	cards = append(cards, cardStyle.BorderForeground(colors.Success).Render(
		lipgloss.NewStyle().Foreground(colors.Success).Render("Fixed")+"\n"+
			lipgloss.NewStyle().Foreground(colors.Success).Bold(true).FontSize(2).Render(fmt.Sprintf("%d", m.dashboard.fixedCount)),
	))

	return lipgloss.JoinHorizontal(lipgloss.Top, cards...)
}

func timeSince(t time.Time) string {
	return t.Format("2006-01-02 15:04")
}
