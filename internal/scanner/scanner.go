package scanner

import (
	"context"
	"time"

	"github.com/noah/sherlock/internal/vulndb"
)

// Result holds all findings from a scanner.
type Result struct {
	ScannerType string           `json:"scanner_type"`
	Target      string           `json:"target"`
	Findings    []vulndb.Finding `json:"findings"`
	Errors      []string         `json:"errors,omitempty"`
	StartedAt   time.Time        `json:"started_at"`
	Duration    time.Duration    `json:"duration"`
}

// Scanner is the interface all security scanners implement.
type Scanner interface {
	Name() string
	Type() string
	Scan(ctx context.Context, target string) (*Result, error)
}

// Factory creates scanners.
type Factory struct {
	scanners map[string]Scanner
}

// NewFactory creates a scanner factory.
func NewFactory() *Factory {
	return &Factory{scanners: make(map[string]Scanner)}
}

// Register adds a scanner.
func (f *Factory) Register(s Scanner) {
	f.scanners[s.Type()] = s
}

// Get retrieves a scanner by type.
func (f *Factory) Get(scannerType string) (Scanner, bool) {
	s, ok := f.scanners[scannerType]
	return s, ok
}

// All returns all registered scanners.
func (f *Factory) All() []Scanner {
	list := make([]Scanner, 0, len(f.scanners))
	for _, s := range f.scanners {
		list = append(list, s)
	}
	return list
}
