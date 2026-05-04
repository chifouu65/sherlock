package tui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
)

func (m Model) updateScanning(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	// Only allow quit during scanning
	if msg.String() == "ctrl+c" {
		m.scanning = false
		m.state = stateScan
		m.toast = "Scan cancelled"
		m.toastTimer = time.Now()
	}
	return m, nil
}

func (m Model) renderScanning() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render("Scanning..."))
	b.WriteString("\n\n")

	// Spinner + status
	spin := m.spinner.View()
	b.WriteString(lipgloss.JoinHorizontal(lipgloss.Center, scanningStyle.Render(spin+" "), lipgloss.NewStyle().Foreground(colors.Fg).Render("Running security scan...")))
	b.WriteString("\n\n")

	// Target
	b.WriteString(fmt.Sprintf("  Target: %s\n", lipgloss.NewStyle().Foreground(colors.Accent).Render(m.scanOpts.target)))
	b.WriteString(fmt.Sprintf("  Elapsed: %s\n", m.scanElapsed.Round(time.Second)))
	b.WriteString("\n")

	// Active scanners
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Render("Active Scanners"))
	b.WriteString("\n")
	if m.scanOpts.scanCode {
		b.WriteString(fmt.Sprintf("  %s Code analysis\n", lipgloss.NewStyle().Foreground(colors.Success).Render("✓")))
	}
	if m.scanOpts.scanNetwork {
		b.WriteString(fmt.Sprintf("  %s Network scan\n", lipgloss.NewStyle().Foreground(colors.Success).Render("✓")))
	}
	if m.scanOpts.scanOS {
		b.WriteString(fmt.Sprintf("  %s OS scan\n", lipgloss.NewStyle().Foreground(colors.Success).Render("✓")))
	}
	b.WriteString("\n")

	// Findings found so far
	if len(m.scanResults) > 0 {
		b.WriteString(fmt.Sprintf("  Findings so far: %s\n",
			lipgloss.NewStyle().Foreground(colors.Warning).Bold(true).Render(fmt.Sprintf("%d", len(m.scanResults)))))
	}

	// Progress bar (simplified)
	progress := int(m.scanProgress * 50)
	if progress > 50 {
		progress = 50
	}
	bar := strings.Repeat("█", progress) + strings.Repeat("░", 50-progress)
	b.WriteString("\n")
	b.WriteString(progressBarStyle.Render(bar))
	b.WriteString(fmt.Sprintf(" %d%%", int(m.scanProgress*100)))

	b.WriteString("\n\n")
	b.WriteString(lipgloss.NewStyle().Foreground(colors.Muted).Italic(true).Render("  Press Ctrl+C to cancel"))

	return b.String()
}
