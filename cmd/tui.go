package cmd

import (
	"github.com/noah/sherlock/internal/tui"
	"github.com/spf13/cobra"
)

var tuiCmd = &cobra.Command{
	Use:   "tui",
	Short: "Launch the interactive terminal UI",
	Long: `Launch Sherlock's interactive terminal user interface.

Navigate with arrow keys, scan with a few keystrokes, and review
findings in a beautiful terminal dashboard.

Perfect for SSH/VPS usage — no web browser needed.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		return tui.Run()
	},
}

func init() {
	rootCmd.AddCommand(tuiCmd)
}
