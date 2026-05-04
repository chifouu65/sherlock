package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/noah/sherlock/internal/vulndb"
	"github.com/spf13/cobra"
)

var vulndbCmd = &cobra.Command{
	Use:   "vulndb",
	Short: "Vulnerability database operations",
	Long:  `Update and search the vulnerability database.`,
}

var vulndbUpdateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update the vulnerability database",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()

		db, err := vulndb.NewLocalDB(cfg.VulnDB.LocalDBPath)
		if err != nil {
			return fmt.Errorf("failed to init db: %w", err)
		}
		defer db.Close()

		if err := db.Init(); err != nil {
			return fmt.Errorf("failed to init schema: %w", err)
		}

		// Insert sample data for demo purposes
		sampleVulns := []*vulndb.Vulnerability{
			{
				ID:          "CVE-2026-0001",
				CVE:         "CVE-2026-0001",
				Title:       "Sample Remote Code Execution",
				Description: "A sample vulnerability for demonstration purposes.",
				Severity:    vulndb.SeverityCritical,
				CVSS:        9.8,
			},
			{
				ID:          "CVE-2026-0002",
				CVE:         "CVE-2026-0002",
				Title:       "Sample Information Disclosure",
				Description: "A sample vulnerability for demonstration purposes.",
				Severity:    vulndb.SeverityHigh,
				CVSS:        7.5,
			},
		}

		for _, v := range sampleVulns {
			if err := db.InsertVulnerability(ctx, v); err != nil {
				fmt.Fprintf(os.Stderr, "[!] Failed to insert %s: %v\n", v.CVE, err)
			}
		}

		fmt.Println("[+] Vulnerability database updated.")
		return nil
	},
}

var vulndbSearchCmd = &cobra.Command{
	Use:   "search [query]",
	Short: "Search the vulnerability database",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := context.Background()
		query := args[0]

		db, err := vulndb.NewLocalDB(cfg.VulnDB.LocalDBPath)
		if err != nil {
			return fmt.Errorf("failed to init db: %w", err)
		}
		defer db.Close()

		if err := db.Init(); err != nil {
			return fmt.Errorf("failed to init schema: %w", err)
		}

		// Try exact CVE lookup first
		v, err := db.GetVulnerability(ctx, query)
		if err != nil {
			return fmt.Errorf("query failed: %w", err)
		}

		if v != nil {
			fmt.Printf("Found exact match:\n")
			fmt.Printf("  CVE: %s\n", v.CVE)
			fmt.Printf("  Title: %s\n", v.Title)
			fmt.Printf("  Severity: %s\n", v.Severity)
			fmt.Printf("  CVSS: %.1f\n", v.CVSS)
			fmt.Printf("  Description: %s\n", v.Description)
			return nil
		}

		// Search by keyword
		results, err := db.SearchVulnerabilities(ctx, query)
		if err != nil {
			return fmt.Errorf("search failed: %w", err)
		}

		if len(results) == 0 {
			fmt.Println("No vulnerabilities found.")
			return nil
		}

		fmt.Printf("Found %d result(s):\n", len(results))
		for _, r := range results {
			fmt.Printf("  - %s | %s | %s | %.1f\n", r.CVE, r.Title, r.Severity, r.CVSS)
		}

		return nil
	},
}

func init() {
	vulndbCmd.AddCommand(vulndbUpdateCmd)
	vulndbCmd.AddCommand(vulndbSearchCmd)
	rootCmd.AddCommand(vulndbCmd)
}
