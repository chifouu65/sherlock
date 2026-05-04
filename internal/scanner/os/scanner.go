package os

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/noah/sherlock/internal/scanner"
	"github.com/noah/sherlock/internal/vulndb"
)

// OSScanner scans the operating system for security issues.
type OSScanner struct {
	enabledChecks map[string]bool
}

// NewOSScanner creates a new OS scanner.
func NewOSScanner() *OSScanner {
	return &OSScanner{
		enabledChecks: map[string]bool{
			"permissions": true,
			"services":    true,
			"users":       true,
			"firewall":    true,
			"updates":     true,
		},
	}
}

func (o *OSScanner) Name() string { return "OS Scanner" }
func (o *OSScanner) Type() string { return "os" }

// Scan performs OS-level security checks.
func (o *OSScanner) Scan(ctx context.Context, target string) (*scanner.Result, error) {
	result := &scanner.Result{
		ScannerType: o.Type(),
		Target:      target,
		Findings:    []vulndb.Finding{},
		StartedAt:   time.Now(),
	}
	defer func() {
		result.Duration = time.Since(result.StartedAt)
	}()

	// File permissions check
	if o.enabledChecks["permissions"] {
		findings := o.checkPermissions(ctx, target)
		result.Findings = append(result.Findings, findings...)
	}

	// Services check
	if o.enabledChecks["services"] {
		findings := o.checkServices(ctx)
		result.Findings = append(result.Findings, findings...)
	}

	// User configuration check
	if o.enabledChecks["users"] {
		findings := o.checkUsers(ctx)
		result.Findings = append(result.Findings, findings...)
	}

	// Firewall check
	if o.enabledChecks["firewall"] {
		findings := o.checkFirewall(ctx)
		result.Findings = append(result.Findings, findings...)
	}

	return result, nil
}

func (o *OSScanner) checkPermissions(ctx context.Context, target string) []vulndb.Finding {
	var findings []vulndb.Finding

	err := filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err != nil {
			return nil
		}

		mode := info.Mode()
		if mode&077 != 0 && (mode.IsRegular() && (strings.Contains(path, "/etc/") || strings.Contains(path, "\\windows\\system32"))) {
			findings = append(findings, vulndb.Finding{
				ID:          fmt.Sprintf("PERM-%s", path),
				ScannerType: "os",
				Severity:    vulndb.SeverityHigh,
				Title:       "Insecure File Permissions",
				Description: fmt.Sprintf("World-writable file in sensitive location: %s (mode: %s)", path, mode.String()),
				Target:      path,
				Location:    path,
				FixSuggestion: fmt.Sprintf("chmod o-w %s", path),
				AutoFixable: true,
			})
		}

		// Check SUID/SGID files
		if runtime.GOOS != "windows" && mode&04777&04000 != 0 {
			findings = append(findings, vulndb.Finding{
				ID:          fmt.Sprintf("SUID-%s", path),
				ScannerType: "os",
				Severity:    vulndb.SeverityMedium,
				Title:       "SUID/SGID File Detected",
				Description: fmt.Sprintf("File with elevated privileges: %s", path),
				Target:      path,
				Location:    path,
				FixSuggestion: "Review if SUID/SGID is necessary. Remove with chmod u-s/g-s if not.",
				AutoFixable: false,
			})
		}

		return nil
	})

	if err != nil {
		// Don't fail, just continue
	}

	return findings
}

func (o *OSScanner) checkServices(ctx context.Context) []vulndb.Finding {
	var findings []vulndb.Finding

	dangerousServices := []string{
		"telnet", "ftp", "rsh", "rlogin", "rexec",
	}

	for _, svc := range dangerousServices {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		if o.isServiceRunning(ctx, svc) {
			findings = append(findings, vulndb.Finding{
				ID:          fmt.Sprintf("SVC-%s", svc),
				ScannerType: "os",
				Severity:    vulndb.SeverityCritical,
				Title:       fmt.Sprintf("Dangerous Service Running: %s", svc),
				Description: fmt.Sprintf("The %s service is running, which is insecure and should be disabled.", svc),
				Target:      svc,
				Location:    svc,
				FixSuggestion: fmt.Sprintf("Disable the %s service immediately.", svc),
				AutoFixable: false,
			})
		}
	}

	return findings
}

func (o *OSScanner) isServiceRunning(ctx context.Context, name string) bool {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "sc", "query", name)
	} else {
		cmd = exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", name)
	}

	return cmd.Run() == nil
}

func (o *OSScanner) checkUsers(ctx context.Context) []vulndb.Finding {
	var findings []vulndb.Finding

	// Check for empty passwords in /etc/shadow on Unix
	if runtime.GOOS != "windows" {
		f, err := os.Open("/etc/shadow")
		if err == nil {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				select {
				case <-ctx.Done():
					return findings
				default:
				}

				line := scanner.Text()
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					user := parts[0]
					hash := parts[1]
					if hash == "" || hash == "!!" || hash == "*" {
						severity := vulndb.SeverityMedium
						if hash == "" {
							severity = vulndb.SeverityCritical
						}
						findings = append(findings, vulndb.Finding{
							ID:          fmt.Sprintf("USER-%s", user),
							ScannerType: "os",
							Severity:    severity,
							Title:       "Weak or Empty Password",
							Description: fmt.Sprintf("User %s has an empty or locked password.", user),
							Target:      user,
							Location:    "/etc/shadow",
							FixSuggestion: fmt.Sprintf("Set a strong password for user %s.", user),
							AutoFixable: false,
						})
					}
				}
			}
		}
	}

	return findings
}

func (o *OSScanner) checkFirewall(ctx context.Context) []vulndb.Finding {
	var findings []vulndb.Finding

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "netsh", "advfirewall", "show", "currentprofile")
	} else {
		cmd = exec.CommandContext(ctx, "iptables", "-L")
	}

	out, err := cmd.Output()
	if err != nil {
		findings = append(findings, vulndb.Finding{
			ID:          "FIREWALL-001",
			ScannerType: "os",
			Severity:    vulndb.SeverityMedium,
			Title:       "Firewall Status Check Failed",
			Description: fmt.Sprintf("Could not verify firewall status: %v", err),
			Target:      "firewall",
			Location:    "system",
			FixSuggestion: "Ensure the firewall service is installed and running.",
			AutoFixable: false,
		})
		return findings
	}

	if runtime.GOOS == "windows" {
		if !strings.Contains(strings.ToLower(string(out)), "state on") {
			findings = append(findings, vulndb.Finding{
				ID:          "FIREWALL-002",
				ScannerType: "os",
				Severity:    vulndb.SeverityHigh,
				Title:       "Windows Firewall Disabled",
				Description: "The Windows Firewall appears to be disabled.",
				Target:      "firewall",
				Location:    "system",
				FixSuggestion: "Enable the Windows Firewall using: netsh advfirewall set allprofiles state on",
				AutoFixable: true,
			})
		}
	} else {
		if strings.Contains(string(out), "Chain INPUT (policy ACCEPT)") {
			findings = append(findings, vulndb.Finding{
				ID:          "FIREWALL-003",
				ScannerType: "os",
				Severity:    vulndb.SeverityHigh,
				Title:       "iptables INPUT Chain Policy ACCEPT",
				Description: "The iptables INPUT chain has a default policy of ACCEPT.",
				Target:      "firewall",
				Location:    "system",
				FixSuggestion: "Set iptables default policy to DROP: iptables -P INPUT DROP",
				AutoFixable: true,
			})
		}
	}

	return findings
}
