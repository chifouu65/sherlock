package reporter

import (
	"context"
	"time"

	"github.com/noah/sherlock/internal/vulndb"
)

// ReportData holds all data for a report.
type ReportData struct {
	Title       string            `json:"title"`
	GeneratedAt time.Time         `json:"generated_at"`
	Findings    []vulndb.Finding  `json:"findings"`
	Summary     ReportSummary     `json:"summary"`
}

// ReportSummary contains statistics about findings.
type ReportSummary struct {
	Total       int            `json:"total"`
	Critical    int            `json:"critical"`
	High        int            `json:"high"`
	Medium      int            `json:"medium"`
	Low         int            `json:"low"`
	Info        int            `json:"info"`
	ByScanner   map[string]int `json:"by_scanner"`
	AutoFixable int            `json:"auto_fixable"`
}

// Reporter is the interface for all report generators.
type Reporter interface {
	// Generate creates a report from the given data.
	Generate(ctx context.Context, data *ReportData) ([]byte, error)
	// Extension returns the file extension for this report format.
	Extension() string
}

// ComputeSummary computes statistics from findings.
func ComputeSummary(findings []vulndb.Finding) ReportSummary {
	summary := ReportSummary{
		ByScanner: make(map[string]int),
	}

	for _, f := range findings {
		summary.Total++
		summary.ByScanner[f.ScannerType]++

		switch f.Severity {
		case vulndb.SeverityCritical:
			summary.Critical++
		case vulndb.SeverityHigh:
			summary.High++
		case vulndb.SeverityMedium:
			summary.Medium++
		case vulndb.SeverityLow:
			summary.Low++
		case vulndb.SeverityInfo:
			summary.Info++
		}

		if f.AutoFixable {
			summary.AutoFixable++
		}
	}

	return summary
}
