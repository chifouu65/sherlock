package tui

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/noah/sherlock/internal/reporter"
	"github.com/noah/sherlock/internal/vulndb"
)

func (m Model) updateReport(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "m", "M":
		if !m.dashboard.lastScan.IsZero() {
			return m, generateReportCmd(m.scanResults, "markdown")
		}
		m.toast = "No scan data to report"
		m.toastTimer = time.Now()
	case "j", "J":
		if !m.dashboard.lastScan.IsZero() {
			return m, generateReportCmd(m.scanResults, "json")
		}
		m.toast = "No scan data to report"
		m.toastTimer = time.Now()
	case "h", "H":
		m.toast = "HTML reports: coming in v0.3.0"
		m.toastTimer = time.Now()
	case "esc", "b":
		m.state = stateDashboard
		m.navIndex = indexOfNav(stateDashboard)
	}
	return m, nil
}

type reportGeneratedMsg struct {
	filename string
	format   string
}

func generateReportCmd(findings []vulndb.Finding, format string) tea.Cmd {
	return func() tea.Msg {
		// Ensure reports directory exists
		reportsDir := "./reports"
		if err := os.MkdirAll(reportsDir, 0755); err != nil {
			return toastMsg(fmt.Sprintf("✗ Failed to create reports dir: %v", err))
		}

		// Build report data
		data := &reporter.ReportData{
			Title:       "Sherlock Security Report",
			GeneratedAt: time.Now(),
			Findings:    findings,
			Summary:     reporter.ComputeSummary(findings),
		}

		// Generate report
		var r reporter.Reporter
		var ext string
		switch format {
		case "markdown":
			r = reporter.NewMarkdownReporter()
			ext = "md"
		case "json":
			r = reporter.NewJSONReporter()
			ext = "json"
		default:
			return toastMsg(fmt.Sprintf("✗ Unknown format: %s", format))
		}

		content, err := r.Generate(context.Background(), data)
		if err != nil {
			return toastMsg(fmt.Sprintf("✗ Report generation failed: %v", err))
		}

		// Write file
		filename := filepath.Join(reportsDir, fmt.Sprintf("sherlock-report-%s.%s",
			time.Now().Format("2006-01-02-15-04-05"), ext))
		if err := os.WriteFile(filename, content, 0644); err != nil {
			return toastMsg(fmt.Sprintf("✗ Failed to write report: %v", err))
		}

		return reportGeneratedMsg{filename: filename, format: format}
	}
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
		b.WriteString(fmt.Sprintf("  Fixed: %d\n", m.dashboard.fixedCount))
		b.WriteString("\n")
		b.WriteString(lipgloss.NewStyle().Foreground(colors.Primary).Render("  [M] Markdown  [J] JSON  [H] HTML (soon)"))
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
