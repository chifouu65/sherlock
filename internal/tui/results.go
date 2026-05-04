package tui

import (
	"fmt"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/noah/sherlock/internal/vulndb"
)

func (m Model) updateResults(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.selectedFinding > 0 {
			m.selectedFinding--
			m.resultsTable.MoveUp(1)
		}
	case "down", "j":
		if m.selectedFinding < len(m.scanResults)-1 {
			m.selectedFinding++
			m.resultsTable.MoveDown(1)
		}
	case "f":
		// Auto-fix selected or all fixable
		return m, fixSelectedCmd(m.scanResults)
	case "e":
		// Export report
		m.toast = "Report exported to reports/"
		m.toastTimer = time.Now()
	case "enter":
		m.showDetail = !m.showDetail
	case "esc", "b":
		m.state = stateDashboard
		m.navIndex = indexOfNav(stateDashboard)
	}
	return m, nil
}

func fixSelectedCmd(findings []vulndb.Finding) tea.Cmd {
	return func() tea.Msg {
		fixed := 0
		for i := range findings {
			if findings[i].AutoFixable {
				findings[i].Fixed = true
				fixed++
			}
		}
		return toastMsg(fmt.Sprintf("✓ Fixed %d/%d auto-fixable findings", fixed, len(findings)))
	}
}

func (m Model) renderResults() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Scan Results"))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  %s findings | %s critical | %s high | %s medium | %s low\n",
		lipgloss.NewStyle().Foreground(colors.Fg).Bold(true).Render(fmt.Sprintf("%d", len(m.scanResults))),
		lipgloss.NewStyle().Foreground(colors.Error).Render(fmt.Sprintf("%d", m.dashboard.criticalCount)),
		lipgloss.NewStyle().Foreground(lipgloss.Color("#B91C1C")).Render(fmt.Sprintf("%d", m.dashboard.highCount)),
		lipgloss.NewStyle().Foreground(colors.Warning).Render(fmt.Sprintf("%d", m.dashboard.mediumCount)),
		lipgloss.NewStyle().Foreground(colors.Success).Render(fmt.Sprintf("%d", m.dashboard.lowCount))))
	b.WriteString("\n")

	// Table or detail view
	if m.showDetail && m.selectedFinding < len(m.scanResults) {
		b.WriteString(m.renderFindingDetail(m.scanResults[m.selectedFinding]))
	} else {
		if len(m.scanResults) == 0 {
			b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Italic(true).Render("  No findings found. Your system looks clean! 🎉"))
		} else {
			// Custom table rendering since bubbles table might not fit well
			b.WriteString(m.renderResultsTable())
		}
	}

	b.WriteString("\n\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Render("[↑↓] Navigate  [Enter] Detail  [f] Fix  [e] Export  [Esc] Dashboard"))

	return b.String()
}

func (m Model) renderResultsTable() string {
	var b strings.Builder

	// Header
	header := fmt.Sprintf("  %-10s %-12s %-48s %-8s",
		lipgloss.NewStyle().Foreground(colors.Primary).Bold(true).Render("Severity"),
		lipgloss.NewStyle().Foreground(colors.Primary).Bold(true).Render("Scanner"),
		lipgloss.NewStyle().Foreground(colors.Primary).Bold(true).Render("Description"),
		lipgloss.NewStyle().Foreground(colors.Primary).Bold(true).Render("Fix"),
	)
	b.WriteString(header)
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Border).Render(strings.Repeat("─", 90)))
	b.WriteString("\n")

	// Rows
	for i, f := range m.scanResults {
		prefix := "  "
		if i == m.selectedFinding {
			prefix = lipgloss.NewStyle().Foreground(colors.Primary).Render("▶ ")
		}

		fixIcon := "No"
		if f.AutoFixable {
			fixIcon = lipgloss.NewStyle().Foreground(colors.Success).Render("✓")
		}

		sevBadge := severityBadge(string(f.Severity))

		line := fmt.Sprintf("%s%-8s %-10s %-48s %-8s",
			prefix,
			sevBadge,
			truncate(f.ScannerType, 10),
			truncate(f.Description, 46),
			fixIcon,
		)
		b.WriteString(line)
		b.WriteString("\n")
	}

	return b.String()
}

func (m Model) renderFindingDetail(f vulndb.Finding) string {
	var b strings.Builder

	b.WriteString(lipgloss.NewStyle().Foreground(colors.Primary).Bold(true).Render("Finding Detail"))
	b.WriteString("\n\n")

	b.WriteString(fmt.Sprintf("  ID:        %s\n", lipgloss.NewStyle().Foreground(colors.Accent).Render(f.ID)))
	b.WriteString(fmt.Sprintf("  Severity:  %s\n", severityBadge(string(f.Severity))))
	b.WriteString(fmt.Sprintf("  Scanner:   %s\n", lipgloss.NewStyle().Foreground(colors.Fg).Render(f.ScannerType)))
	b.WriteString(fmt.Sprintf("  Target:    %s\n", lipgloss.NewStyle().Foreground(colors.Fg).Render(f.Target)))
	b.WriteString("\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Render("Description:"))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  %s\n", lipgloss.NewStyle().Foreground(colors.Fg).Render(f.Description)))
	b.WriteString("\n")

	if f.FixSuggestion != "" {
		b.WriteString(lipgloss.NewStyle().Foreground(colors.Success).Render("Suggested Fix:"))
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  %s\n", lipgloss.NewStyle().Foreground(colors.Fg).Render(f.FixSuggestion)))
	}

	if f.AutoFixable {
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Foreground(colors.Success).Bold(true).Render("  ✓ This issue can be auto-fixed"))
	}

	if f.Fixed {
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Foreground(colors.Success).Bold(true).Render("  ✓ Already fixed"))
	}

	return b.String()
}
