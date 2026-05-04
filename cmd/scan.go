package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/noah/sherlock/internal/analyzer"
	"github.com/noah/sherlock/internal/fixer"
	"github.com/noah/sherlock/internal/scanner"
	"github.com/noah/sherlock/internal/scanner/code"
	"github.com/noah/sherlock/internal/scanner/network"
	osscan "github.com/noah/sherlock/internal/scanner/os"
	"github.com/noah/sherlock/internal/vulndb"
	"github.com/spf13/cobra"
)

var (
	scanAll       bool
	scanCode      bool
	scanNetwork   bool
	scanOS        bool
	scanTarget    string
	scanPorts     string
	autoFix       bool
	dryRun        bool
	hardening     bool
	useLLM        bool
)

var scanCmd = &cobra.Command{
	Use:   "scan [target]",
	Short: "Run a security scan",
	Long:  `Run security scans on code, network, or operating system.`,
	Args:  cobra.MaximumNArgs(1),
	RunE:  runScan,
}

func init() {
	scanCmd.Flags().BoolVar(&scanAll, "all", false, "Run all scanners")
	scanCmd.Flags().BoolVar(&scanCode, "code", false, "Run code scanner")
	scanCmd.Flags().BoolVar(&scanNetwork, "network", false, "Run network scanner")
	scanCmd.Flags().BoolVar(&scanOS, "os", false, "Run OS scanner")
	scanCmd.Flags().StringVar(&scanPorts, "ports", "", "Ports to scan (e.g., 1-1000,80,443)")
	scanCmd.Flags().BoolVar(&autoFix, "auto-fix", false, "Automatically fix findings")
	scanCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Show what would be fixed without applying")
	scanCmd.Flags().BoolVar(&hardening, "hardening", false, "Include hardening checks")
	scanCmd.Flags().BoolVar(&useLLM, "llm", false, "Use LLM to enhance analysis of findings")

	rootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Determine target
	target := "."
	if len(args) > 0 {
		target = args[0]
	}
	scanTarget = target

	// Determine which scanners to run
	if !scanAll && !scanCode && !scanNetwork && !scanOS {
		scanAll = true
	}

	factory := scanner.NewFactory()

	if scanAll || scanCode {
		codeScanner := code.NewCodeScanner(cfg.Scanner.Code.IgnorePaths, cfg.Scanner.Code.SecretsPatterns)
		factory.Register(codeScanner)
	}

	if scanAll || scanNetwork {
		netScanner := network.NewNetworkScanner(cfg.Scanner.Network.TimeoutMs, cfg.Scanner.Network.Concurrency)
		if scanPorts != "" {
			netScanner.WithPorts(scanPorts)
		}
		factory.Register(netScanner)
	}

	if scanAll || scanOS {
		osScanner := osscan.NewOSScanner()
		factory.Register(osScanner)
	}

	// Initialize vulnerability DB
	db, err := vulndb.NewLocalDB(cfg.VulnDB.LocalDBPath)
	if err != nil {
		return fmt.Errorf("failed to init vuln db: %w", err)
	}
	defer db.Close()
	if err := db.Init(); err != nil {
		return fmt.Errorf("failed to init db schema: %w", err)
	}

	// Run scanners
	var allFindings []vulndb.Finding
	scanners := factory.All()

	for _, s := range scanners {
		fmt.Printf("[+] Running %s on '%s'...\n", s.Name(), target)
		result, err := s.Scan(ctx, target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Scanner %s failed: %v\n", s.Name(), err)
			continue
		}

		fmt.Printf("    Found %d findings\n", len(result.Findings))
		for i := range result.Findings {
			f := &result.Findings[i]
			f.DetectedAt = time.Now()
			allFindings = append(allFindings, *f)
			if err := db.InsertFinding(ctx, f); err != nil {
				fmt.Fprintf(os.Stderr, "[!] Failed to store finding: %v\n", err)
			}
		}
	}

	// LLM enhancement (optional)
	if useLLM {
		llm := analyzer.NewLLMAnalyzer(cfg.LLM.BaseURL, cfg.LLM.APIKey, cfg.LLM.Model)
		for i := range allFindings {
			fmt.Printf("    [LLM] Analyzing finding %s...\n", allFindings[i].ID)
			enhanced, err := llm.AnalyzeFinding(ctx, &allFindings[i])
			if err != nil {
				fmt.Fprintf(os.Stderr, "[!] LLM analysis failed for %s: %v\n", allFindings[i].ID, err)
				continue
			}
			allFindings[i].FixSuggestion = enhanced.FixSuggestion
			_ = db.UpdateFindingFix(ctx, allFindings[i].ID, enhanced.FixSuggestion)
		}
	}

	// Auto-fix
	if autoFix || dryRun {
		f := fixer.NewFixer(dryRun)
		for i := range allFindings {
			finding := &allFindings[i]
			if finding.AutoFixable {
				res, err := f.Fix(ctx, finding)
				if err != nil {
					fmt.Fprintf(os.Stderr, "[!] Fix failed for %s: %v\n", finding.ID, err)
					continue
				}
				if res.Success {
					fmt.Printf("[FIXED] %s: %s\n", finding.ID, res.Action)
					if res.BackupPath != "" {
						fmt.Printf("    Backup: %s\n", res.BackupPath)
					}
					finding.Fixed = true
					_ = db.MarkFixed(ctx, finding.ID)
				} else {
					fmt.Printf("[SKIP] %s: %s\n", finding.ID, res.Error)
				}
			}
		}
	}

	// Print summary
	fmt.Printf("\n=== Scan Summary ===\n")
	fmt.Printf("Total findings: %d\n", len(allFindings))
	fmt.Printf("Critical: %d\n", countSeverity(allFindings, vulndb.SeverityCritical))
	fmt.Printf("High: %d\n", countSeverity(allFindings, vulndb.SeverityHigh))
	fmt.Printf("Medium: %d\n", countSeverity(allFindings, vulndb.SeverityMedium))
	fmt.Printf("Low: %d\n", countSeverity(allFindings, vulndb.SeverityLow))
	fmt.Printf("Info: %d\n", countSeverity(allFindings, vulndb.SeverityInfo))
	fmt.Printf("Auto-fixable: %d\n", countAutoFixable(allFindings))
	fmt.Printf("Fixed: %d\n", countFixed(allFindings))

	return nil
}

func countSeverity(findings []vulndb.Finding, sev vulndb.Severity) int {
	c := 0
	for _, f := range findings {
		if f.Severity == sev {
			c++
		}
	}
	return c
}

func countAutoFixable(findings []vulndb.Finding) int {
	c := 0
	for _, f := range findings {
		if f.AutoFixable {
			c++
		}
	}
	return c
}

func countFixed(findings []vulndb.Finding) int {
	c := 0
	for _, f := range findings {
		if f.Fixed {
			c++
		}
	}
	return c
}
