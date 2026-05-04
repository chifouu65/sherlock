package reporter

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/noah/sherlock/internal/vulndb"
)

// MarkdownReporter generates Markdown reports.
type MarkdownReporter struct{}

// NewMarkdownReporter creates a new Markdown reporter.
func NewMarkdownReporter() *MarkdownReporter {
	return &MarkdownReporter{}
}

func (m *MarkdownReporter) Extension() string { return "md" }

// Generate creates a Markdown report.
func (m *MarkdownReporter) Generate(ctx context.Context, data *ReportData) ([]byte, error) {
	var buf bytes.Buffer

	buf.WriteString(fmt.Sprintf("# %s\n\n", data.Title))
	buf.WriteString(fmt.Sprintf("Generated at: %s\n\n", data.GeneratedAt.Format(time.RFC3339)))

	// Summary
	buf.WriteString("## Summary\n\n")
	buf.WriteString(fmt.Sprintf("| Metric | Count |\n"))
	buf.WriteString(fmt.Sprintf("|--------|-------|\n"))
	buf.WriteString(fmt.Sprintf("| Total Findings | %d |\n", data.Summary.Total))
	buf.WriteString(fmt.Sprintf("| Critical | %d |\n", data.Summary.Critical))
	buf.WriteString(fmt.Sprintf("| High | %d |\n", data.Summary.High))
	buf.WriteString(fmt.Sprintf("| Medium | %d |\n", data.Summary.Medium))
	buf.WriteString(fmt.Sprintf("| Low | %d |\n", data.Summary.Low))
	buf.WriteString(fmt.Sprintf("| Info | %d |\n", data.Summary.Info))
	buf.WriteString(fmt.Sprintf("| Auto-Fixable | %d |\n\n", data.Summary.AutoFixable))

	// By Scanner
	if len(data.Summary.ByScanner) > 0 {
		buf.WriteString("### Findings by Scanner\n\n")
		buf.WriteString(fmt.Sprintf("| Scanner | Count |\n"))
		buf.WriteString(fmt.Sprintf("|---------|-------|\n"))
		for scanner, count := range data.Summary.ByScanner {
			buf.WriteString(fmt.Sprintf("| %s | %d |\n", scanner, count))
		}
		buf.WriteString("\n")
	}

	// Findings
	if len(data.Findings) > 0 {
		buf.WriteString("## Findings\n\n")

		// Group by severity
		severityOrder := []vulndb.Severity{
			vulndb.SeverityCritical,
			vulndb.SeverityHigh,
			vulndb.SeverityMedium,
			vulndb.SeverityLow,
			vulndb.SeverityInfo,
		}

		for _, sev := range severityOrder {
			sevFindings := filterBySeverity(data.Findings, sev)
			if len(sevFindings) == 0 {
				continue
			}

			buf.WriteString(fmt.Sprintf("### %s\n\n", sev))
			for _, f := range sevFindings {
				buf.WriteString(m.renderFinding(f))
				buf.WriteString("\n---\n\n")
			}
		}
	} else {
		buf.WriteString("## Findings\n\nNo findings detected.\n\n")
	}

	return buf.Bytes(), nil
}

func (m *MarkdownReporter) renderFinding(f vulndb.Finding) string {
	var buf bytes.Buffer

	icon := severityIcon(f.Severity)
	buf.WriteString(fmt.Sprintf("#### %s %s\n\n", icon, f.Title))
	buf.WriteString(fmt.Sprintf("- **ID:** `%s`\n", f.ID))
	buf.WriteString(fmt.Sprintf("- **Severity:** %s\n", f.Severity))
	buf.WriteString(fmt.Sprintf("- **Scanner:** %s\n", f.ScannerType))
	buf.WriteString(fmt.Sprintf("- **Target:** `%s`\n", f.Target))
	if f.Location != "" {
		buf.WriteString(fmt.Sprintf("- **Location:** `%s`\n", f.Location))
	}
	if f.CVE != "" {
		buf.WriteString(fmt.Sprintf("- **CVE:** [%s](https://nvd.nist.gov/vuln/detail/%s)\n", f.CVE, f.CVE))
	}
	if f.CVSS > 0 {
		buf.WriteString(fmt.Sprintf("- **CVSS:** %.1f\n", f.CVSS))
	}

	buf.WriteString(fmt.Sprintf("\n**Description:**\n%s\n", f.Description))

	if f.FixSuggestion != "" {
		buf.WriteString(fmt.Sprintf("\n**Fix Suggestion:**\n%s\n", f.FixSuggestion))
	}

	if f.AutoFixable {
		buf.WriteString("\n*This finding is auto-fixable.*\n")
	}

	if f.Fixed {
		buf.WriteString("\n*Fixed.*\n")
	}

	return buf.String()
}

func severityIcon(s vulndb.Severity) string {
	switch s {
	case vulndb.SeverityCritical:
		return "🔴"
	case vulndb.SeverityHigh:
		return "🟠"
	case vulndb.SeverityMedium:
		return "🟡"
	case vulndb.SeverityLow:
		return "🟢"
	default:
		return "⚪"
	}
}

func filterBySeverity(findings []vulndb.Finding, sev vulndb.Severity) []vulndb.Finding {
	var result []vulndb.Finding
	for _, f := range findings {
		if f.Severity == sev {
			result = append(result, f)
		}
	}
	return result
}

func (m *MarkdownReporter) escapeMarkdown(s string) string {
	s = strings.ReplaceAll(s, "\n", "\n")
	return s
}
