package reporter

import (
	"context"
	"encoding/json"
	"time"

	"github.com/noah/sherlock/internal/vulndb"
)

// JSONReporter generates JSON reports.
type JSONReporter struct{}

// NewJSONReporter creates a new JSON reporter.
func NewJSONReporter() *JSONReporter {
	return &JSONReporter{}
}

func (j *JSONReporter) Extension() string { return "json" }

// Generate creates a JSON report.
func (j *JSONReporter) Generate(ctx context.Context, data *ReportData) ([]byte, error) {
	output := struct {
		Title       string                   `json:"title"`
		GeneratedAt string                   `json:"generated_at"`
		Findings    []vulndb.Finding         `json:"findings"`
		Summary     ReportSummary   `json:"summary"`
	}{
		Title:       data.Title,
		GeneratedAt: data.GeneratedAt.Format(time.RFC3339),
		Findings:    data.Findings,
		Summary:     data.Summary,
	}

	return json.MarshalIndent(output, "", "  ")
}
