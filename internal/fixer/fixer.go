package fixer

import (
	"context"
	"fmt"
	"os"

	"github.com/noah/sherlock/internal/vulndb"
)

// Fixer applies automated fixes for findings.
type Fixer struct {
	dryRun bool
}

// NewFixer creates a new fixer.
func NewFixer(dryRun bool) *Fixer {
	return &Fixer{dryRun: dryRun}
}

// FixResult holds the result of a fix operation.
type FixResult struct {
	FindingID   string
	Success     bool
	BackupPath  string
	Error       string
	Action      string
}

// Fix applies an automated fix for a finding.
func (f *Fixer) Fix(ctx context.Context, finding *vulndb.Finding) (*FixResult, error) {
	if !finding.AutoFixable {
		return &FixResult{
			FindingID: finding.ID,
			Success:   false,
			Error:     "finding is not auto-fixable",
			Action:    "none",
		}, nil
	}

	if f.dryRun {
		return &FixResult{
			FindingID: finding.ID,
			Success:   true,
			Action:    fmt.Sprintf("dry-run: would apply fix for %s", finding.Title),
		}, nil
	}

	// Determine fix strategy based on scanner type and finding
	switch finding.ScannerType {
	case "os":
		return f.fixOSFinding(ctx, finding)
	case "code":
		return f.fixCodeFinding(ctx, finding)
	default:
		return &FixResult{
			FindingID: finding.ID,
			Success:   false,
			Error:     fmt.Sprintf("auto-fix not implemented for scanner type: %s", finding.ScannerType),
			Action:    "none",
		}, nil
	}
}

func (f *Fixer) fixOSFinding(ctx context.Context, finding *vulndb.Finding) (*FixResult, error) {
	var action string
	switch finding.Title {
	case "Windows Firewall Disabled":
		action = "netsh advfirewall set allprofiles state on"
	case "iptables INPUT Chain Policy ACCEPT":
		action = "iptables -P INPUT DROP"
	default:
		return &FixResult{
			FindingID: finding.ID,
			Success:   false,
			Error:     "no automated fix available",
			Action:    "none",
		}, nil
	}

	return &FixResult{
		FindingID: finding.ID,
		Success:   true,
		Action:    action,
	}, nil
}

func (f *Fixer) fixCodeFinding(ctx context.Context, finding *vulndb.Finding) (*FixResult, error) {
	if finding.Target == "" || finding.Location == "" {
		return &FixResult{
			FindingID: finding.ID,
			Success:   false,
			Error:     "no target file specified",
			Action:    "none",
		}, nil
	}

	// Backup before modifying
	backupPath, err := Backup(finding.Target)
	if err != nil {
		return &FixResult{
			FindingID: finding.ID,
			Success:   false,
			Error:     fmt.Sprintf("backup failed: %v", err),
			Action:    "none",
		}, nil
	}

	// Apply simple fixes
	content, err := os.ReadFile(finding.Target)
	if err != nil {
		return &FixResult{
			FindingID:  finding.ID,
			Success:    false,
			BackupPath: backupPath,
			Error:      fmt.Sprintf("read failed: %v", err),
			Action:     "backup created",
		}, nil
	}

	_ = string(content)

	switch finding.Title {
	case "Insecure File Permissions":
		// This is OS-level, not code-level
		return &FixResult{
			FindingID:  finding.ID,
			Success:    false,
			BackupPath: backupPath,
			Error:      "use OS-level fix for permission issues",
			Action:     "backup created",
		}, nil
	default:
		return &FixResult{
			FindingID:  finding.ID,
			Success:    false,
			BackupPath: backupPath,
			Error:      "no automated code fix available",
			Action:     "backup created",
		}, nil
	}
}
