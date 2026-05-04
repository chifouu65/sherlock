package code

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/noah/sherlock/internal/scanner"
	"github.com/noah/sherlock/internal/vulndb"
)

// skipExts lists file extensions to skip (compiled binaries, images, etc.)
var skipExts = map[string]bool{
	".exe":   true,
	".dll":   true,
	".bin":   true,
	".jpg":   true,
	".jpeg":  true,
	".png":   true,
	".gif":   true,
	".ico":   true,
	".svg":   true,
	".woff":  true,
	".woff2": true,
	".ttf":   true,
	".eot":   true,
	".pdf":   true,
	".zip":   true,
	".tar":   true,
	".gz":    true,
	".rar":   true,
	".7z":    true,
	".pyc":   true,
	".o":     true,
	".so":    true,
	".dylib": true,
	".lib":   true,
	".obj":   true,
	".pdb":   true,
}

// Patterns for common issues
var (
	// Hardcoded secrets patterns
	secretPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|passwd|pwd)\s*[:=]\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?i)(api[_-]?key|apikey)\s*[:=]\s*["']([a-zA-Z0-9_\-]{16,})["']`),
		regexp.MustCompile(`(?i)(secret[_-]?key|secret)\s*[:=]\s*["']([a-zA-Z0-9_\-]{16,})["']`),
		regexp.MustCompile(`(?i)(token|auth[_-]?token)\s*[:=]\s*["']([a-zA-Z0-9_\-\.]{20,})["']`),
		regexp.MustCompile(`-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`),
	}

	// SQL Injection patterns
	sqliPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)(SELECT|INSERT|UPDATE|DELETE|DROP)\s+.*\+\s*.*`),
		regexp.MustCompile(`(?i)query\s*\(\s*.*\+\s*.*\)`),
		regexp.MustCompile(`(?i)exec\s*\(\s*["'].*%s.*["']\s*,\s*.*\)`),
		regexp.MustCompile(`(?i)\$\{.*\}.*\+.*\$\{.*\}`),
	}

	// XSS patterns
	xssPatterns = []*regexp.Regexp{
		regexp.MustCompile(`(?i)innerHTML\s*=\s*.*\+`),
		regexp.MustCompile(`(?i)document\.write\s*\(\s*.*\+`),
		regexp.MustCompile(`(?i)eval\s*\(\s*.*\+`),
		regexp.MustCompile(`(?i)\.html\s*\(\s*.*\+`),
	}

	// Dependency file patterns
	depFiles = map[string]string{
		"go.mod":           "go",
		"package.json":     "node",
		"requirements.txt": "python",
		"Cargo.toml":       "rust",
		"pom.xml":          "java",
	}

	findingCounter atomic.Int64
)

func init() {
	// Seed the finding counter with a timestamp to guarantee unique IDs across runs
	findingCounter.Store(time.Now().UnixNano() % 1000000000)
}

// CodeScanner scans source code for vulnerabilities.
type CodeScanner struct {
	ignorePaths []string
	patterns    []string
}

// NewCodeScanner creates a new code scanner.
func NewCodeScanner(ignorePaths, patterns []string) *CodeScanner {
	if ignorePaths == nil {
		ignorePaths = []string{".git", "node_modules", "vendor", "dist", "build"}
	}
	return &CodeScanner{
		ignorePaths: ignorePaths,
		patterns:    patterns,
	}
}

func (c *CodeScanner) Name() string { return "Code Security Scanner" }
func (c *CodeScanner) Type() string { return "code" }

// Scan scans the target directory for code issues.
func (c *CodeScanner) Scan(ctx context.Context, target string) (*scanner.Result, error) {
	result := &scanner.Result{
		ScannerType: c.Type(),
		Target:      target,
		Findings:    []vulndb.Finding{},
		StartedAt:   time.Now(),
	}
	defer func() {
		result.Duration = time.Since(result.StartedAt)
	}()

	// Check if target is a directory
	info, err := os.Stat(target)
	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("failed to stat target: %v", err))
		return result, nil
	}

	if !info.IsDir() {
		// Skip binary single file
		if skipExts[strings.ToLower(filepath.Ext(target))] {
			return result, nil
		}
		// Scan single file
		findings := c.scanFile(ctx, target, target)
		result.Findings = append(result.Findings, findings...)
		return result, nil
	}

	// Walk directory
	err = filepath.Walk(target, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		// Skip ignored paths
		for _, ignore := range c.ignorePaths {
			if strings.Contains(path, ignore) {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
		}

		if info.IsDir() {
			return nil
		}

		// Check for dependency files
		base := filepath.Base(path)
		if _, ok := depFiles[base]; ok {
			finding := c.checkDependencyFile(path, base)
			if finding != nil {
				result.Findings = append(result.Findings, *finding)
			}
		}

		// Skip binary files
		ext := strings.ToLower(filepath.Ext(path))
		if skipExts[ext] {
			return nil
		}

		// Scan file content
		findings := c.scanFile(ctx, path, target)
		result.Findings = append(result.Findings, findings...)

		return nil
	})

	if err != nil {
		result.Errors = append(result.Errors, fmt.Sprintf("walk error: %v", err))
	}

	return result, nil
}

func nextID() int64 {
	return findingCounter.Add(1)
}

func (c *CodeScanner) scanFile(ctx context.Context, path, baseDir string) []vulndb.Finding {
	var findings []vulndb.Finding

	file, err := os.Open(path)
	if err != nil {
		return findings
	}
	defer file.Close()

	relPath, _ := filepath.Rel(baseDir, path)
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		lineNum++
		line := scanner.Text()

		// Check secrets
		for _, pattern := range secretPatterns {
			if matches := pattern.FindStringSubmatch(line); matches != nil {
				// Hash the matched value to avoid exposing it in the report
				secretValue := matches[len(matches)-1]
				hash := sha256.Sum256([]byte(secretValue))
				hashedSecret := hex.EncodeToString(hash[:8])

				findings = append(findings, vulndb.Finding{
					ID:          fmt.Sprintf("SECRET-%s-%d-%d", filepath.Base(path), lineNum, nextID()),
					ScannerType: "code",
					Severity:    vulndb.SeverityHigh,
					Title:       "Hardcoded Secret Detected",
					Description: fmt.Sprintf("Potential hardcoded secret found in %s:%d (hash: %s...)", relPath, lineNum, hashedSecret),
					Target:      path,
					Location:    fmt.Sprintf("%s:%d", relPath, lineNum),
					FixSuggestion: "Use environment variables, a secrets manager, or encrypted configuration files instead of hardcoding secrets.",
					AutoFixable: false,
				})
			}
		}

		// Check SQL injection
		for _, pattern := range sqliPatterns {
			if pattern.MatchString(line) {
				findings = append(findings, vulndb.Finding{
					ID:          fmt.Sprintf("SQLI-%s-%d-%d", filepath.Base(path), lineNum, nextID()),
					ScannerType: "code",
					Severity:    vulndb.SeverityCritical,
					Title:       "Potential SQL Injection",
					Description: fmt.Sprintf("Possible SQL injection vulnerability in %s:%d", relPath, lineNum),
					Target:      path,
					Location:    fmt.Sprintf("%s:%d", relPath, lineNum),
					FixSuggestion: "Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.",
					AutoFixable: false,
				})
				break
			}
		}

		// Check XSS
		for _, pattern := range xssPatterns {
			if pattern.MatchString(line) {
				findings = append(findings, vulndb.Finding{
					ID:          fmt.Sprintf("XSS-%s-%d-%d", filepath.Base(path), lineNum, nextID()),
					ScannerType: "code",
					Severity:    vulndb.SeverityHigh,
					Title:       "Potential Cross-Site Scripting (XSS)",
					Description: fmt.Sprintf("Possible XSS vulnerability in %s:%d", relPath, lineNum),
					Target:      path,
					Location:    fmt.Sprintf("%s:%d", relPath, lineNum),
					FixSuggestion: "Use proper output encoding, Content Security Policy (CSP), and avoid inserting user input into the DOM without sanitization.",
					AutoFixable: false,
				})
				break
			}
		}
	}

	return findings
}

func (c *CodeScanner) checkDependencyFile(path, filename string) *vulndb.Finding {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	contentStr := string(content)
	var issues []string

	switch filename {
	case "go.mod":
		if strings.Contains(contentStr, "replace (") && strings.Contains(contentStr, "=>") {
			issues = append(issues, "go.mod replace directives can be used for dependency confusion attacks")
		}
	case "package.json":
		if strings.Contains(contentStr, `"dependencies"`) {
			// Check for common vulnerable patterns
			if strings.Contains(contentStr, `"lodash"`) && !strings.Contains(contentStr, `"lodash": "^4.17.21"`) {
				issues = append(issues, "potentially outdated lodash version")
			}
		}
	}

	if len(issues) > 0 {
		return &vulndb.Finding{
			ID:          fmt.Sprintf("DEP-%s-%d", filepath.Base(path), nextID()),
			ScannerType: "code",
			Severity:    vulndb.SeverityMedium,
			Title:       "Dependency Configuration Issue",
			Description: fmt.Sprintf("Issues found in %s: %v", path, issues),
			Target:      path,
			Location:    path,
			FixSuggestion: "Review and update dependencies. Use `go get -u` or `npm audit fix` to update packages.",
			AutoFixable: true,
		}
	}

	return nil
}
