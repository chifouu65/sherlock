package vulndb

import "time"

// Severity levels
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Finding represents a discovered vulnerability or issue.
type Finding struct {
	ID              string    `json:"id" db:"id"`
	ScannerType     string    `json:"scanner_type" db:"scanner_type"`
	Severity        Severity  `json:"severity" db:"severity"`
	Title           string    `json:"title" db:"title"`
	Description     string    `json:"description" db:"description"`
	Target          string    `json:"target" db:"target"`
	Location        string    `json:"location,omitempty" db:"location"`
	CVE             string    `json:"cve,omitempty" db:"cve"`
	CVSS            float64   `json:"cvss,omitempty" db:"cvss"`
	FixSuggestion   string    `json:"fix_suggestion,omitempty" db:"fix_suggestion"`
	AutoFixable     bool      `json:"auto_fixable" db:"auto_fixable"`
	Fixed           bool      `json:"fixed" db:"fixed"`
	DetectedAt      time.Time `json:"detected_at" db:"detected_at"`
}

// Vulnerability is a generic vulnerability entry.
type Vulnerability struct {
	ID          string    `json:"id" db:"id"`
	CVE         string    `json:"cve,omitempty" db:"cve"`
	Title       string    `json:"title" db:"title"`
	Description string    `json:"description" db:"description"`
	Severity    Severity  `json:"severity" db:"severity"`
	CVSS        float64   `json:"cvss,omitempty" db:"cvss"`
	References  []string  `json:"references,omitempty" db:"references"`
	PublishedAt time.Time `json:"published_at" db:"published_at"`
}
