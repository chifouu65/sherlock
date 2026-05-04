package tui

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/noah/sherlock/internal/vulndb"
)

// App states
type appState int

const (
	stateDashboard appState = iota
	stateScan
	stateScanning
	stateResults
	stateVulnDB
	stateReport
	stateConfig
)

// Navigation items
type navItem struct {
	name     string
	icon     string
	shortcut rune
	state    appState
}

var navItems = []navItem{
	{"Dashboard", "📊", 'd', stateDashboard},
	{"Scan", "🔍", 's', stateScan},
	{"VulnDB", "🗄️", 'v', stateVulnDB},
	{"Reports", "📄", 'r', stateReport},
	{"Config", "⚙️", 'c', stateConfig},
}

// Key bindings
type keyMap struct {
	Up      key.Binding
	Down    key.Binding
	Enter   key.Binding
	Tab     key.Binding
	Space   key.Binding
	Back    key.Binding
	Quit    key.Binding
	Help    key.Binding
	ScanAll key.Binding
	Fix     key.Binding
	Export  key.Binding
}

var defaultKeys = keyMap{
	Up:    key.NewBinding(key.WithKeys("up", "k"), key.WithHelp("↑/k", "up")),
	Down:  key.NewBinding(key.WithKeys("down", "j"), key.WithHelp("↓/j", "down")),
	Enter: key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "select")),
	Tab:   key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "next")),
	Space: key.NewBinding(key.WithKeys(" "), key.WithHelp("space", "toggle")),
	Back:  key.NewBinding(key.WithKeys("esc", "b"), key.WithHelp("esc/b", "back")),
	Quit:  key.NewBinding(key.WithKeys("q", "ctrl+c"), key.WithHelp("q", "quit")),
	Help:  key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "help")),
	ScanAll: key.NewBinding(key.WithKeys("a"), key.WithHelp("a", "scan all")),
	Fix:     key.NewBinding(key.WithKeys("f"), key.WithHelp("f", "auto-fix")),
	Export:  key.NewBinding(key.WithKeys("e"), key.WithHelp("e", "export")),
}

// Scan options
type scanOptions struct {
	scanCode    bool
	scanNetwork bool
	scanOS      bool
	useLLM      bool
	autoFix     bool
	target      string
	ports       string
}

// Dashboard data
type dashboardData struct {
	lastScan     time.Time
	totalScans   int
	totalFindings int
	criticalCount int
	highCount     int
	mediumCount   int
	lowCount      int
	fixedCount    int
	vulnDBSize    int
}

// Model is the main TUI model
type Model struct {
	// State
	state      appState
	prevState  appState
	width      int
	height     int
	
	// Navigation
	navIndex   int
	
	// Scan
	scanOpts   scanOptions
	scanning   bool
	spinner    spinner.Model
	scanProgress float64
	scanResults []vulndb.Finding
	scanStartTime time.Time
	scanElapsed  time.Duration
	
	// Results
	resultsTable table.Model
	selectedFinding int
	showDetail   bool
	
	// Dashboard
	dashboard  dashboardData
	
	// VulnDB
	vulnSearch string
	vulnResults []vulndb.Finding
	
	// Config
	configFile string
	
	// Messages / toast
	toast      string
	toastTimer time.Time
	
	// Help
	showHelp   bool
	keys       keyMap
}

// Messages
type (
	scanStartMsg struct{}
	scanProgressMsg struct {
		scanner string
		finding vulndb.Finding
	}
	scanCompleteMsg struct {
		findings []vulndb.Finding
		duration time.Duration
	}
	scanErrorMsg struct {
		err error
	}
	tickMsg      time.Time
	toastMsg     string
)

// NewModel creates a new TUI model
func NewModel() Model {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(colors.Accent)
	
	// Results table
	columns := []table.Column{
		{Title: "Severity", Width: 10},
		{Title: "Scanner", Width: 12},
		{Title: "Description", Width: 50},
		{Title: "Fixable", Width: 8},
	}
	
	t := table.New(
		table.WithColumns(columns),
		table.WithHeight(20),
	)
	
	return Model{
		state:      stateDashboard,
		scanOpts:   scanOptions{target: ".", ports: "1-1000"},
		spinner:    s,
		dashboard: dashboardData{},
		resultsTable: t,
		keys:       defaultKeys,
	}
}

// Init implements tea.Model
func (m Model) Init() tea.Cmd {
	return tea.Batch(
		tea.EnterAltScreen,
		spinner.Tick,
		tickCmd(),
	)
}

func tickCmd() tea.Cmd {
	return tea.Tick(time.Second, func(t time.Time) tea.Msg {
		return tickMsg(t)
	})
}

// Update implements tea.Model
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmds []tea.Cmd
	
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.updateLayout()
		
	case tea.KeyMsg:
		if key.Matches(msg, m.keys.Quit) {
			return m, tea.Quit
		}
		if key.Matches(msg, m.keys.Help) {
			m.showHelp = !m.showHelp
			return m, nil
		}
		
		// Global navigation shortcuts
		for _, item := range navItems {
			if msg.Runes != nil && len(msg.Runes) > 0 && msg.Runes[0] == item.shortcut {
				m.prevState = m.state
				m.state = item.state
				m.navIndex = indexOfNav(item.state)
				m.scanning = false
				m.showDetail = false
				return m, nil
			}
		}
		
		// State-specific handlers
		switch m.state {
		case stateDashboard:
			return m.updateDashboard(msg)
		case stateScan:
			return m.updateScan(msg)
		case stateScanning:
			return m.updateScanning(msg)
		case stateResults:
			return m.updateResults(msg)
		case stateVulnDB:
			return m.updateVulnDB(msg)
		case stateReport:
			return m.updateReport(msg)
		case stateConfig:
			return m.updateConfig(msg)
		}
		
	case tickMsg:
		cmds = append(cmds, tickCmd())
		if m.scanning {
			m.scanElapsed = time.Since(m.scanStartTime)
		}
		if m.toast != "" && time.Since(m.toastTimer) > 3*time.Second {
			m.toast = ""
		}
		
	case scanProgressMsg:
		m.scanResults = append(m.scanResults, msg.finding)
		m.scanProgress += 0.05
		
	case scanCompleteMsg:
		m.scanning = false
		m.scanResults = msg.findings
		m.dashboard.lastScan = time.Now()
		m.dashboard.totalScans++
		m.dashboard.totalFindings += len(msg.findings)
		m.updateDashboardCounts()
		m.state = stateResults
		m.updateResultsTable()
		m.toast = fmt.Sprintf("✓ Scan complete: %d findings in %v", len(msg.findings), msg.duration)
		m.toastTimer = time.Now()
		
	case scanErrorMsg:
		m.scanning = false
		m.toast = fmt.Sprintf("✗ Scan failed: %v", msg.err)
		m.toastTimer = time.Now()
		m.state = stateScan
		
	case toastMsg:
		m.toast = string(msg)
		m.toastTimer = time.Now()
	}
	
	// Update spinner
	if m.scanning {
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		cmds = append(cmds, cmd)
	}
	
	return m, tea.Batch(cmds...)
}

// View implements tea.Model
func (m Model) View() string {
	if m.width == 0 || m.height == 0 {
		return "Loading..."
	}
	
	// Build sidebar
	sidebar := m.renderSidebar()
	
	// Build main content
	var content string
	switch m.state {
	case stateDashboard:
		content = m.renderDashboard()
	case stateScan:
		content = m.renderScan()
	case stateScanning:
		content = m.renderScanning()
	case stateResults:
		content = m.renderResults()
	case stateVulnDB:
		content = m.renderVulnDB()
	case stateReport:
		content = m.renderReport()
	case stateConfig:
		content = m.renderConfig()
	}
	
	// Layout
	sidebarWidth := 28
	contentWidth := m.width - sidebarWidth - 2
	
	sidebarStyle = sidebarStyle.Width(sidebarWidth).Height(m.height - 1)
	contentStyle = contentStyle.Width(contentWidth).Height(m.height - 1)
	
	row := lipgloss.JoinHorizontal(lipgloss.Top,
		sidebarStyle.Render(sidebar),
		contentStyle.Render(content),
	)
	
	// Toast notification
	if m.toast != "" {
		toastBox := lipgloss.NewStyle().
			Background(colors.DarkBg).
			Foreground(colors.Success).
			BorderStyle(lipgloss.RoundedBorder()).
			BorderForeground(colors.Success).
			Padding(0, 2).
			Render(m.toast)
		row = lipgloss.JoinVertical(lipgloss.Left, row, toastBox)
	}
	
	// Help bar
	helpBar := m.renderHelpBar()
	
	return lipgloss.JoinVertical(lipgloss.Left, row, helpBar)
}

// Helpers
func (m *Model) updateLayout() {
	// Recalculate layout dimensions
}

func (m *Model) updateDashboardCounts() {
	m.dashboard.criticalCount = 0
	m.dashboard.highCount = 0
	m.dashboard.mediumCount = 0
	m.dashboard.lowCount = 0
	m.dashboard.fixedCount = 0
	
	for _, f := range m.scanResults {
		switch f.Severity {
		case vulndb.SeverityCritical:
			m.dashboard.criticalCount++
		case vulndb.SeverityHigh:
			m.dashboard.highCount++
		case vulndb.SeverityMedium:
			m.dashboard.mediumCount++
		case vulndb.SeverityLow:
			m.dashboard.lowCount++
		}
		if f.Fixed {
			m.dashboard.fixedCount++
		}
	}
}

func (m *Model) updateResultsTable() {
	rows := make([]table.Row, len(m.scanResults))
	for i, f := range m.scanResults {
		fixable := "No"
		if f.AutoFixable {
			fixable = "Yes"
		}
		rows[i] = table.Row{
			string(f.Severity),
			f.ScannerType,
			truncate(f.Description, 48),
			fixable,
		}
	}
	m.resultsTable.SetRows(rows)
}

func indexOfNav(s appState) int {
	for i, item := range navItems {
		if item.state == s {
			return i
		}
	}
	return 0
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// Run starts the TUI
func Run() error {
	p := tea.NewProgram(NewModel(), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
