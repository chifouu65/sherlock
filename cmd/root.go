package cmd

import (
	"fmt"
	"os"

	"github.com/noah/sherlock/pkg/sherlock"
	"github.com/spf13/cobra"
)

var cfgFile string
var cfg *sherlock.Config

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "sherlock",
	Short: "Sherlock - A cybersecurity scanning agent",
	Long: `Sherlock is a comprehensive security scanning tool that checks
your code, network, and operating system for vulnerabilities
and provides actionable remediation advice.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		var err error
		cfg, err = sherlock.LoadConfig(cfgFile)
		if err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}
		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./config.yaml)")
}
