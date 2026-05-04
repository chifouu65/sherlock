package vulndb

import "context"

// DB is the interface for the vulnerability database.
type DB interface {
	// Init initializes the database schema.
	Init() error
	// Close closes the database connection.
	Close() error
	// InsertVulnerability inserts a new vulnerability.
	InsertVulnerability(ctx context.Context, v *Vulnerability) error
	// GetVulnerability retrieves a vulnerability by CVE ID.
	GetVulnerability(ctx context.Context, cve string) (*Vulnerability, error)
	// SearchVulnerabilities searches vulnerabilities by keyword.
	SearchVulnerabilities(ctx context.Context, query string) ([]Vulnerability, error)
	// InsertFinding inserts a scan finding.
	InsertFinding(ctx context.Context, f *Finding) error
	// GetFindings retrieves findings for a scan.
	GetFindings(ctx context.Context, scannerType string) ([]Finding, error)
	// MarkFixed marks a finding as fixed.
	MarkFixed(ctx context.Context, id string) error
	// UpdateFindingFix updates the fix suggestion for a finding.
	UpdateFindingFix(ctx context.Context, id, fixSuggestion string) error
}
