package network

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/noah/sherlock/internal/scanner"
	"github.com/noah/sherlock/internal/vulndb"
)

// NetworkScanner scans network targets for open ports and services.
type NetworkScanner struct {
	timeoutMs   int
	concurrency int
	ports       string
}

// NewNetworkScanner creates a new network scanner.
func NewNetworkScanner(timeoutMs, concurrency int) *NetworkScanner {
	if timeoutMs <= 0 {
		timeoutMs = 2000
	}
	if concurrency <= 0 {
		concurrency = 100
	}
	return &NetworkScanner{
		timeoutMs:   timeoutMs,
		concurrency: concurrency,
	}
}

// WithPorts sets the port range to scan.
func (n *NetworkScanner) WithPorts(ports string) *NetworkScanner {
	n.ports = ports
	return n
}

func (n *NetworkScanner) Name() string { return "Network Scanner" }
func (n *NetworkScanner) Type() string { return "network" }

// Scan scans the target for open ports.
func (n *NetworkScanner) Scan(ctx context.Context, target string) (*scanner.Result, error) {
	result := &scanner.Result{
		ScannerType: n.Type(),
		Target:      target,
		Findings:    []vulndb.Finding{},
		StartedAt:   time.Now(),
	}
	defer func() {
		result.Duration = time.Since(result.StartedAt)
	}()

	portSpec := n.ports
	if portSpec == "" {
		portSpec = "1-1000"
	}
	ports := n.parsePorts(portSpec)
	if len(ports) == 0 {
		result.Errors = append(result.Errors, "no ports to scan")
		return result, nil
	}

	// Resolve hostname if needed
	host := target
	if net.ParseIP(target) == nil {
		addrs, err := net.LookupHost(target)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("lookup failed: %v", err))
			return result, nil
		}
		host = addrs[0]
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, n.concurrency)
	var mu sync.Mutex

	for _, port := range ports {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		wg.Add(1)
		sem <- struct{}{}

		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()

			finding := n.scanPort(ctx, host, p)
			if finding != nil {
				mu.Lock()
				result.Findings = append(result.Findings, *finding)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()

	// SSL/TLS check on common ports
	sslPorts := []int{443, 8443, 993, 995, 465, 587}
	for _, p := range sslPorts {
		select {
		case <-ctx.Done():
			return result, ctx.Err()
		default:
		}

		if n.isPortOpen(ctx, host, p) {
			finding := n.checkSSL(ctx, target, p)
			if finding != nil {
				result.Findings = append(result.Findings, *finding)
			}
		}
	}

	return result, nil
}

func (n *NetworkScanner) parsePorts(portSpec string) []int {
	var ports []int
	parts := strings.Split(portSpec, ",")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")
			if len(rangeParts) == 2 {
				start, _ := strconv.Atoi(strings.TrimSpace(rangeParts[0]))
				end, _ := strconv.Atoi(strings.TrimSpace(rangeParts[1]))
				for i := start; i <= end; i++ {
					ports = append(ports, i)
				}
			}
		} else {
			p, _ := strconv.Atoi(part)
			if p > 0 {
				ports = append(ports, p)
			}
		}
	}
	return ports
}

func (n *NetworkScanner) isPortOpen(ctx context.Context, host string, port int) bool {
	addr := fmt.Sprintf("%s:%d", host, port)
	d := time.Duration(n.timeoutMs) * time.Millisecond
	conn, err := net.DialTimeout("tcp", addr, d)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (n *NetworkScanner) scanPort(ctx context.Context, host string, port int) *vulndb.Finding {
	addr := fmt.Sprintf("%s:%d", host, port)
	d := time.Duration(n.timeoutMs) * time.Millisecond

	conn, err := net.DialTimeout("tcp", addr, d)
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Try to grab banner
	conn.SetReadDeadline(time.Now().Add(d))
	buf := make([]byte, 1024)
	nRead, _ := conn.Read(buf)
	banner := strings.TrimSpace(string(buf[:nRead]))

	severity := vulndb.SeverityInfo
	if isSensitivePort(port) {
		severity = vulndb.SeverityMedium
	}

	finding := &vulndb.Finding{
		ID:          fmt.Sprintf("PORT-%d", port),
		ScannerType: "network",
		Severity:    severity,
		Title:       fmt.Sprintf("Open Port %d", port),
		Description: fmt.Sprintf("Port %d is open on %s", port, host),
		Target:      addr,
		Location:    addr,
		FixSuggestion: fmt.Sprintf("Review if port %d needs to be exposed. Close it if not required.", port),
		AutoFixable: false,
	}

	if banner != "" {
		finding.Description += fmt.Sprintf(" | Banner: %s", banner)
		if strings.Contains(strings.ToLower(banner), "ftp") && port != 21 {
			finding.Severity = vulndb.SeverityHigh
			finding.Title = "FTP Service on Non-Standard Port"
			finding.Description = fmt.Sprintf("FTP-like service detected on port %d: %s", port, banner)
		}
	}

	return finding
}

func (n *NetworkScanner) checkSSL(ctx context.Context, host string, port int) *vulndb.Finding {
	addr := fmt.Sprintf("%s:%d", host, port)
	d := time.Duration(n.timeoutMs) * time.Millisecond

	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: d},
		"tcp", addr,
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil {
		return nil
	}
	defer conn.Close()

	state := conn.ConnectionState()
	var issues []string

	if state.Version < tls.VersionTLS12 {
		issues = append(issues, fmt.Sprintf("TLS version %x is outdated (minimum TLS 1.2 required)", state.Version))
	}

	for _, cert := range state.PeerCertificates {
		if cert.NotAfter.Before(time.Now()) {
			issues = append(issues, fmt.Sprintf("Certificate expired on %s", cert.NotAfter.Format("2006-01-02")))
		}
		if cert.NotAfter.Before(time.Now().AddDate(0, 1, 0)) {
			issues = append(issues, fmt.Sprintf("Certificate expires soon: %s", cert.NotAfter.Format("2006-01-02")))
		}
		if len(cert.DNSNames) == 0 && len(cert.IPAddresses) == 0 {
			issues = append(issues, "Certificate has no DNS names or IP addresses")
		}
	}

	if len(issues) > 0 {
		return &vulndb.Finding{
			ID:          fmt.Sprintf("SSL-%d", port),
			ScannerType: "network",
			Severity:    vulndb.SeverityHigh,
			Title:       "SSL/TLS Configuration Issue",
			Description: fmt.Sprintf("SSL/TLS issues on %s: %v", addr, issues),
			Target:      addr,
			Location:    addr,
			FixSuggestion: "Update to TLS 1.2+, renew expired certificates, and ensure proper certificate configuration.",
			AutoFixable: false,
		}
	}

	return nil
}

func isSensitivePort(port int) bool {
	sensitive := []int{21, 22, 23, 25, 53, 110, 143, 3306, 3389, 5432, 6379, 8080, 9200}
	for _, p := range sensitive {
		if p == port {
			return true
		}
	}
	return false
}
