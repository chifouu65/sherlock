package cmd

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/noah/sherlock/internal/reporter"
	"github.com/noah/sherlock/internal/vulndb"
	"github.com/spf13/cobra"
)

var (
	reportFormat string
	reportOutput string
	reportTitle  string
)

var reportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate security reports",
	Long:  `Generate reports from scan findings in various formats.`,
}

var reportGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a report",
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

		// Retrieve findings from DB
		findings, err := db.GetFindings(ctx, "")
		if err != nil {
			return fmt.Errorf("failed to get findings: %w", err)
		}

		// Create report data
		data := &reporter.ReportData{
			Title:       reportTitle,
			GeneratedAt: time.Now(),
			Findings:    findings,
			Summary:     reporter.ComputeSummary(findings),
		}

		// Select reporter
		var rep reporter.Reporter
		switch reportFormat {
		case "json":
			rep = reporter.NewJSONReporter()
		case "markdown", "md":
			rep = reporter.NewMarkdownReporter()
		default:
			return fmt.Errorf("unsupported format: %s", reportFormat)
		}

		// Generate report
		output, err := rep.Generate(ctx, data)
		if err != nil {
			return fmt.Errorf("failed to generate report: %w", err)
		}

		// Determine output path
		if reportOutput == "" {
			reportOutput = fmt.Sprintf("report-%s.%s", time.Now().Format("20060102-150405"), rep.Extension())
		}

		// Write to file
		if err := os.MkdirAll(filepath.Dir(reportOutput), 0755); err != nil {
			return fmt.Errorf("failed to create output directory: %w", err)
		}

		if err := os.WriteFile(reportOutput, output, 0644); err != nil {
			return fmt.Errorf("failed to write report: %w", err)
		}

		fmt.Printf("[+] Report generated: %s\n", reportOutput)
		fmt.Printf("    Total findings: %d\n", data.Summary.Total)
		fmt.Printf("    Critical: %d | High: %d | Medium: %d | Low: %d | Info: %d\n",
			data.Summary.Critical, data.Summary.High, data.Summary.Medium,
			data.Summary.Low, data.Summary.Info)

		return nil
	},
}

func init() {
	reportGenerateCmd.Flags().StringVar(&reportFormat, "format", "markdown", "Report format: markdown, json")
	reportGenerateCmd.Flags().StringVar(&reportOutput, "output", "", "Output file path")
	reportGenerateCmd.Flags().StringVar(&reportTitle, "title", "Sherlock Security Report", "Report title")

	reportCmd.AddCommand(reportGenerateCmd)
	rootCmd.AddCommand(reportCmd)
}
