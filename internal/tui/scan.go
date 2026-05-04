package tui

import (
	"fmt"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/noah/sherlock/internal/vulndb"
)

// scanMenuItems defines the interactive items on the scan screen
type scanMenuItem int

const (
	scanItemCode scanMenuItem = iota
	scanItemNetwork
	scanItemOS
	scanItemLLM
	scanItemAutoFix
	scanItemStart
	scanItemBack
)

var scanItemLabels = []string{
	"Code analysis (secrets, deps, patterns)",
	"Network scan (ports, services, certs)",
	"OS scan (perms, services, hardening)",
	"LLM Analysis (enhanced findings)",
	"Auto-fix (apply corrections)",
	"▶ Start Scan",
	"← Back",
}

func (m Model) updateScan(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if m.scanMenuIndex > 0 {
			m.scanMenuIndex--
		}
	case "down", "j":
		if m.scanMenuIndex < len(scanItemLabels)-1 {
			m.scanMenuIndex++
		}
	case " ":
		// Toggle checkbox items
		switch scanMenuItem(m.scanMenuIndex) {
		case scanItemCode:
			m.scanOpts.scanCode = !m.scanOpts.scanCode
		case scanItemNetwork:
			m.scanOpts.scanNetwork = !m.scanOpts.scanNetwork
		case scanItemOS:
			m.scanOpts.scanOS = !m.scanOpts.scanOS
		case scanItemLLM:
			m.scanOpts.useLLM = !m.scanOpts.useLLM
		case scanItemAutoFix:
			m.scanOpts.autoFix = !m.scanOpts.autoFix
		}
	case "enter":
		switch scanMenuItem(m.scanMenuIndex) {
		case scanItemStart:
			return m.startScan()
		case scanItemBack:
			m.state = stateDashboard
			m.navIndex = indexOfNav(stateDashboard)
		}
	case "esc":
		m.state = stateDashboard
		m.navIndex = indexOfNav(stateDashboard)
	}
	return m, nil
}

func (m Model) startScan() (tea.Model, tea.Cmd) {
	// Default to all if none selected
	if !m.scanOpts.scanCode && !m.scanOpts.scanNetwork && !m.scanOpts.scanOS {
		m.scanOpts.scanCode = true
		m.scanOpts.scanNetwork = true
		m.scanOpts.scanOS = true
	}

	m.prevState = stateScan
	m.state = stateScanning
	m.scanning = true
	m.scanStartTime = time.Now()
	m.scanResults = nil
	m.scanProgress = 0
	m.scanMenuIndex = 0

	return m, tea.Batch(
		m.spinner.Tick,
		startScanCmd(m.scanOpts),
	)
}

func startScanCmd(opts scanOptions) tea.Cmd {
	return func() tea.Msg {
		// Simulated scan — replace with real scanner calls
		findings := []vulndb.Finding{
			{ID: "SH-001", ScannerType: "code", Severity: vulndb.SeverityHigh, Description: "Hardcoded API key in config.go", AutoFixable: true},
			{ID: "SH-002", ScannerType: "network", Severity: vulndb.SeverityMedium, Description: "Port 8080 open without firewall", AutoFixable: false},
			{ID: "SH-003", ScannerType: "os", Severity: vulndb.SeverityLow, Description: "File permissions too permissive", AutoFixable: true},
		}
		return scanCompleteMsg{findings: findings, duration: 2340 * time.Millisecond}
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
	b.WriteString(fmt.Sprintf("  📁 %s\n\n", lipgloss.NewStyle().Foreground(colors.Accent).Render(m.scanOpts.target)))

	// Menu items
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Render("Options"))
	b.WriteString("\n")

	items := []struct {
		label   string
		checked bool
		item    scanMenuItem
	}{
		{scanItemLabels[scanItemCode], m.scanOpts.scanCode, scanItemCode},
		{scanItemLabels[scanItemNetwork], m.scanOpts.scanNetwork, scanItemNetwork},
		{scanItemLabels[scanItemOS], m.scanOpts.scanOS, scanItemOS},
		{scanItemLabels[scanItemLLM], m.scanOpts.useLLM, scanItemLLM},
		{scanItemLabels[scanItemAutoFix], m.scanOpts.autoFix, scanItemAutoFix},
	}

	for i, it := range items {
		prefix := "  "
		if i == m.scanMenuIndex {
			prefix = lipgloss.NewStyle().Foreground(colors.Primary).Render("▶ ")
		}
		check := checkbox(it.checked)
		b.WriteString(fmt.Sprintf("%s%s %s\n", prefix, check, it.label))
	}

	// Action buttons
	for i := int(scanItemStart); i < len(scanItemLabels); i++ {
		prefix := "  "
		if i == m.scanMenuIndex {
			prefix = lipgloss.NewStyle().Foreground(colors.Primary).Render("▶ ")
		}
		style := lipgloss.NewStyle().Foreground(colors.Fg)
		if i == int(scanItemStart) {
			style = lipgloss.NewStyle().Foreground(colors.Success).Bold(true)
		}
		b.WriteString(fmt.Sprintf("%s%s\n", prefix, style.Render(scanItemLabels[i])))
	}

	return b.String()
}

func checkbox(checked bool) string {
	if checked {
		return lipgloss.NewStyle().Foreground(colors.Success).Render("[✓]")
	}
	return lipgloss.NewStyle().Foreground(colors.Muted).Render("[ ]")
}
