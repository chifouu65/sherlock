package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

func (m Model) updateReport(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "b":
		m.state = stateDashboard
		m.navIndex = indexOfNav(stateDashboard)
	}
	return m, nil
}

func (m Model) renderReport() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Reports"))
	b.WriteString("\n")
	b.WriteString(subtitleStyle.Render("Generate and export security reports"))
	b.WriteString("\n\n")

	// Available reports
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Render("Last Scan Report"))
	b.WriteString("\n")
	if m.dashboard.lastScan.IsZero() {
		b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Italic(true).Render("  No scan performed yet"))
	} else {
		b.WriteString(fmt.Sprintf("  Scanned: %s\n", lipgloss.NewStyle().Foreground(colors.Accent).Render("Recently")))
		b.WriteString(fmt.Sprintf("  Findings: %d\n", m.dashboard.totalFindings))
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Foreground(colors.Primary).Render("  [M] Markdown  [J] JSON  [H] HTML"))
	}

	b.WriteString("\n\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Render("[Esc] Back"))

	return b.String()
}

func (m Model) updateConfig(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "esc", "b":
		m.state = stateDashboard
		m.navIndex = indexOfNav(stateDashboard)
	}
	return m, nil
}

func (m Model) renderConfig() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Configuration"))
	b.WriteString("\n")
	b.WriteString(subtitleStyle.Render("Sherlock settings"))
	b.WriteString("\n\n")

	// Config info
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Render("Active Config"))
	b.WriteString("\n")
	if m.configFile != "" {
		b.WriteString(fmt.Sprintf("  File: %s\n", lipgloss.NewStyle().Foreground(colors.Fg).Render(m.configFile)))
	} else {
		b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Render("  Using default configuration"))
	}

	b.WriteString("\n\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Render("LLM Configuration"))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  Provider: %s\n", lipgloss.NewStyle().Foreground(colors.Accent).Render("ollama")))
	b.WriteString(fmt.Sprintf("  Model: %s\n", lipgloss.NewStyle().Foreground(colors.Accent).Render("llama3")))

	b.WriteString("\n\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Render("[Esc] Back"))

	return b.String()
}
