package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

func (m Model) updateVulnDB(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "b":
		m.state = stateDashboard
		m.navIndex = indexOfNav(stateDashboard)
	case "/":
		// Focus search
	case "u":
		m.toast = "VulnDB updated"
		m.toastTimer = time.Now()
	}
	return m, nil
}

func (m Model) renderVulnDB() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Vulnerability Database"))
	b.WriteString("\n")
	b.WriteString(subtitleStyle.Render("Search and browse known vulnerabilities"))
	b.WriteString("\n\n")

	// Search bar
	searchStyle := lipgloss.NewStyle().
		Background(colors.DarkBg).
		BorderStyle(lipgloss.RoundedBorder()).
		BorderForeground(colors.Border).
		Padding(0, 1).
		Width(50)
	
	searchText := m.vulnSearch
	if searchText == "" {
		searchText = "Search CVE, package, or keyword..."
	}
	b.WriteString(searchStyle.Render(fmt.Sprintf("🔍 %s", searchText)))
	b.WriteString("\n\n")

	// Stats
	b.WriteString(fmt.Sprintf("  Total entries: %s\n",
		lipgloss.NewStyle().Foreground(colors.Accent).Bold(true).Render(fmt.Sprintf("%d", m.dashboard.vulnDBSize))))
	b.WriteString("\n")

	// Recent entries placeholder
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Render("Recent Additions"))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Italic(true).Render("  Use 'u' to update the database"))

	b.WriteString("\n\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Render("[/] Search  [u] Update  [Esc] Back"))

	return b.String()
}
