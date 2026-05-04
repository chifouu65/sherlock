package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/lipgloss"
	"github.com/noah/sherlock/internal/vulndb"
)

func (m Model) updateScan(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Up):
		// Navigate options
	case key.Matches(msg, m.keys.Down):
		// Navigate options
	case msg.String() == " ":
		// Toggle current option
		// Simplified: toggle all for now
		m.scanOpts.scanCode = !m.scanOpts.scanCode
		m.scanOpts.scanNetwork = !m.scanOpts.scanNetwork
		m.scanOpts.scanOS = !m.scanOpts.scanOS
	case msg.String() == "l":
		m.scanOpts.useLLM = !m.scanOpts.useLLM
	case msg.String() == "a":
		m.scanOpts.autoFix = !m.scanOpts.autoFix
	case key.Matches(msg, m.keys.Enter):
		// Start scan
		m.prevState = stateScan
		m.state = stateScanning
		m.scanning = true
		m.scanStartTime = time.Now()
		m.scanResults = nil
		m.scanProgress = 0
		return m, tea.Batch(
			m.spinner.Tick,
			startScanCmd(m.scanOpts),
		)
	case key.Matches(msg, m.keys.Back):
		m.state = stateDashboard
		m.navIndex = indexOfNav(stateDashboard)
	}
	return m, nil
}

func startScanCmd(opts scanOptions) tea.Cmd {
	return func() tea.Msg {
		// Simulated scan for now
		// In real implementation, this would run the actual scanners
		return scanCompleteMsg{
			findings: []vulndb.Finding{
				{ID: "SH-001", ScannerType: "code", Severity: vulndb.SeverityHigh, Description: "Hardcoded API key in config.go", AutoFixable: true},
				{ID: "SH-002", ScannerType: "network", Severity: vulndb.SeverityMedium, Description: "Port 8080 open without firewall", AutoFixable: false},
				{ID: "SH-003", ScannerType: "os", Severity: vulndb.SeverityLow, Description: "File permissions too permissive", AutoFixable: true},
			},
			duration: 2_340_000_000, // ~2.3s in ns
		}
	}
}

func (m Model) renderScan() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("New Scan"))
	b.WriteString("\n")
	b.WriteString(subtitleStyle.Render("Configure and launch a security scan"))
	b.WriteString("\n\n")

	// Target
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Render("Target"))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  %s %s\n\n",
		checkbox(m.scanOpts.target != ""),
		lipgloss.NewStyle().Foreground(colors.Fg).Render(m.scanOpts.target)))

	// Scan types
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Render("Scan Types"))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  %s Code analysis (secrets, deps, patterns)\n", checkbox(m.scanOpts.scanCode)))
	b.WriteString(fmt.Sprintf("  %s Network scan (ports, services, certs)\n", checkbox(m.scanOpts.scanNetwork)))
	b.WriteString(fmt.Sprintf("  %s OS scan (perms, services, hardening)\n\n", checkbox(m.scanOpts.scanOS)))

	// Options
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Render("Options"))
	b.WriteString("\n")
	b.WriteString(fmt.Sprintf("  %s LLM Analysis (enhanced findings)\n", checkbox(m.scanOpts.useLLM)))
	b.WriteString(fmt.Sprintf("  %s Auto-fix (apply corrections)\n\n", checkbox(m.scanOpts.autoFix)))

	// Network options (if selected)
	if m.scanOpts.scanNetwork {
		b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Render("Network"))
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("  Ports: %s\n\n",
			lipgloss.NewStyle().Foreground(colors.Accent).Render(m.scanOpts.ports)))
	}

	// Action
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Primary).Bold(true).Render("[Enter] Start Scan"))
	b.WriteString("  ")
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Render("[Esc] Back"))

	return b.String()
}

func checkbox(checked bool) string {
	if checked {
		return lipgloss.NewStyle().Foreground(colors.Success).Render("[✓]")
	}
	return lipgloss.NewStyle().Foreground(colors.Muted).Render("[ ]")
}
