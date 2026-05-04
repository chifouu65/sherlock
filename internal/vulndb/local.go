package vulndb

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// LocalDB implements DB with SQLite.
type LocalDB struct {
	db     *sql.DB
	dbPath string
}

// NewLocalDB creates a new SQLite-backed vulnerability database.
func NewLocalDB(dbPath string) (*LocalDB, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite db: %w", err)
	}
	return &LocalDB{db: db, dbPath: dbPath}, nil
}

// Init creates tables if they don't exist.
func (l *LocalDB) Init() error {
	schema := `
	CREATE TABLE IF NOT EXISTS vulnerabilities (
		id TEXT PRIMARY KEY,
		cve TEXT UNIQUE,
		title TEXT NOT NULL,
		description TEXT,
		severity TEXT,
		cvss REAL,
		refs TEXT,
		published_at DATETIME
	);
	CREATE TABLE IF NOT EXISTS findings (
		id TEXT PRIMARY KEY,
		scanner_type TEXT,
		severity TEXT,
		title TEXT,
		description TEXT,
		target TEXT,
		location TEXT,
		cve TEXT,
		cvss REAL,
		fix_suggestion TEXT,
		auto_fixable INTEGER,
		fixed INTEGER DEFAULT 0,
		detected_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);
	CREATE INDEX IF NOT EXISTS idx_findings_cve ON findings(cve);
	CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
	CREATE INDEX IF NOT EXISTS idx_vulns_cve ON vulnerabilities(cve);
	`
	if _, err := l.db.Exec(schema); err != nil {
		return fmt.Errorf("failed to init schema: %w", err)
	}
	return nil
}

// Close closes the database.
func (l *LocalDB) Close() error {
	return l.db.Close()
}

// InsertVulnerability inserts a vulnerability.
func (l *LocalDB) InsertVulnerability(ctx context.Context, v *Vulnerability) error {
	refs := strings.Join(v.References, ",")
	_, err := l.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO vulnerabilities (id, cve, title, description, severity, cvss, refs, published_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, v.ID, v.CVE, v.Title, v.Description, string(v.Severity), v.CVSS, refs, v.PublishedAt)
	return err
}

// GetVulnerability retrieves by CVE.
func (l *LocalDB) GetVulnerability(ctx context.Context, cve string) (*Vulnerability, error) {
	row := l.db.QueryRowContext(ctx, `
		SELECT id, cve, title, description, severity, cvss, refs, published_at
		FROM vulnerabilities WHERE cve = ?
	`, cve)
	var v Vulnerability
	var refs string
	var publishedAt sql.NullTime
	err := row.Scan(&v.ID, &v.CVE, &v.Title, &v.Description, &v.Severity, &v.CVSS, &refs, &publishedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if refs != "" {
		v.References = strings.Split(refs, ",")
	}
	if publishedAt.Valid {
		v.PublishedAt = publishedAt.Time
	}
	return &v, nil
}

// SearchVulnerabilities searches by keyword in title/description.
func (l *LocalDB) SearchVulnerabilities(ctx context.Context, query string) ([]Vulnerability, error) {
	like := "%" + query + "%"
	rows, err := l.db.QueryContext(ctx, `
		SELECT id, cve, title, description, severity, cvss, refs, published_at
		FROM vulnerabilities WHERE title LIKE ? OR description LIKE ? OR cve LIKE ?
	`, like, like, like)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []Vulnerability
	for rows.Next() {
		var v Vulnerability
		var refs string
		var publishedAt sql.NullTime
		if err := rows.Scan(&v.ID, &v.CVE, &v.Title, &v.Description, &v.Severity, &v.CVSS, &refs, &publishedAt); err != nil {
			continue
		}
		if refs != "" {
			v.References = strings.Split(refs, ",")
		}
		if publishedAt.Valid {
			v.PublishedAt = publishedAt.Time
		}
		results = append(results, v)
	}
	return results, nil
}

// InsertFinding inserts a scan finding.
func (l *LocalDB) InsertFinding(ctx context.Context, f *Finding) error {
	if f.ID == "" {
		f.ID = fmt.Sprintf("%s-%d", f.ScannerType, time.Now().UnixNano())
	}
	_, err := l.db.ExecContext(ctx, `
		INSERT OR REPLACE INTO findings (id, scanner_type, severity, title, description, target, location, cve, cvss, fix_suggestion, auto_fixable, fixed, detected_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`, f.ID, f.ScannerType, string(f.Severity), f.Title, f.Description, f.Target, f.Location, f.CVE, f.CVSS, f.FixSuggestion, f.AutoFixable, f.Fixed, f.DetectedAt)
	return err
}

// GetFindings retrieves findings.
func (l *LocalDB) GetFindings(ctx context.Context, scannerType string) ([]Finding, error) {
	query := `SELECT id, scanner_type, severity, title, description, target, location, cve, cvss, fix_suggestion, auto_fixable, fixed, detected_at FROM findings`
	var args []interface{}
	if scannerType != "" {
		query += ` WHERE scanner_type = ?`
		args = append(args, scannerType)
	}
	query += ` ORDER BY detected_at DESC`

	rows, err := l.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []Finding
	for rows.Next() {
		var f Finding
		var detectedAt sql.NullTime
		if err := rows.Scan(&f.ID, &f.ScannerType, &f.Severity, &f.Title, &f.Description, &f.Target, &f.Location, &f.CVE, &f.CVSS, &f.FixSuggestion, &f.AutoFixable, &f.Fixed, &detectedAt); err != nil {
			continue
		}
		if detectedAt.Valid {
			f.DetectedAt = detectedAt.Time
		}
		results = append(results, f)
	}
	return results, nil
}

// MarkFixed marks a finding as fixed.
func (l *LocalDB) MarkFixed(ctx context.Context, id string) error {
	_, err := l.db.ExecContext(ctx, `UPDATE findings SET fixed = 1 WHERE id = ?`, id)
	return err
}

// UpdateFindingFix updates the fix_suggestion for a finding.
func (l *LocalDB) UpdateFindingFix(ctx context.Context, id, fixSuggestion string) error {
	_, err := l.db.ExecContext(ctx, `UPDATE findings SET fix_suggestion = ? WHERE id = ?`, fixSuggestion, id)
	return err
}
