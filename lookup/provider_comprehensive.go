package lookup

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
)

type ComprehensiveProvider struct{}

const ComprehensiveReportName = "Report"

// ReportExcluder may be implemented by a provider to opt out of the
// comprehensive Report (it stays available on its own). "DIG (ANY)" does so
// because most resolvers refuse or minimise ANY queries (RFC 8482).
type ReportExcluder interface {
	ExcludeFromReport() bool
}

func excludedFromReport(p LookupProvider) bool {
	e, ok := p.(ReportExcluder)
	return ok && e.ExcludeFromReport()
}

func (p *ComprehensiveProvider) Name() string {
	return ComprehensiveReportName
}

func (p *ComprehensiveProvider) FlagName() string {
	return "report"
}

func (p *ComprehensiveProvider) Usage() string {
	return fmt.Sprintf("Run %s (all lookups) on domains from <filename>", p.Name())
}

func (p *ComprehensiveProvider) Command() string {
	return ""
}

func (p *ComprehensiveProvider) CheckAvailability() bool {
	return true
}

// Execute runs every other registered provider in parallel and returns a combined report.
// Per-provider failures and unavailable commands are reported inline; the returned error
// is non-nil only if ctx was cancelled.
func (p *ComprehensiveProvider) Execute(ctx context.Context, target string, opts Options) (string, error) {
	if err := ValidateTarget(target); err != nil {
		return "", err
	}
	target = strings.TrimSpace(target)
	isIP := net.ParseIP(target) != nil
	providers := AvailableProviders()

	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make(map[string]string, len(providers))

	for _, prov := range providers {
		if prov.Name() == ComprehensiveReportName || excludedFromReport(prov) {
			continue // Skip self and opted-out providers
		}
		if isIP && domainOnly(prov) {
			continue // e.g. Delegation, Email, DNSSEC need a domain name
		}
		wg.Add(1)
		go func(sub LookupProvider) {
			defer wg.Done()
			var output string
			if sub.CheckAvailability() {
				var err error
				output, err = sub.Execute(ctx, target, opts)
				if err != nil {
					output = fmt.Sprintf("Error executing %s: %v\n--- Raw Output (if any) ---\n%s", sub.Name(), err, output)
				}
			} else {
				output = fmt.Sprintf("(Command for %s not available)", sub.Name())
			}
			mu.Lock()
			results[sub.Name()] = output
			mu.Unlock()
		}(prov)
	}
	wg.Wait()

	if err := ctx.Err(); err != nil {
		return "", err
	}
	return FormatComprehensiveReport(target, results, GetComprehensiveReportOrder()), nil
}

func FormatComprehensiveReport(domain string, results map[string]string, order []string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Comprehensive Report for: %s\n", domain))
	b.WriteString(strings.Repeat("=", 40+len(domain)))
	b.WriteString("\n")

	processed := make(map[string]bool)

	for _, name := range order {
		if result, ok := results[name]; ok {
			b.WriteString(fmt.Sprintf("\n--- %s ---\n", name))
			b.WriteString(strings.TrimSpace(result))
			b.WriteString("\n")
			processed[name] = true
		}
	}

	remainingNames := make([]string, 0, len(results)-len(processed))
	for name := range results {
		if !processed[name] {
			remainingNames = append(remainingNames, name)
		}
	}
	sort.Strings(remainingNames)
	for _, name := range remainingNames {
		result := results[name]
		b.WriteString(fmt.Sprintf("\n--- %s ---\n", name))
		b.WriteString(strings.TrimSpace(result))
		b.WriteString("\n")
	}

	return b.String()
}

func GetComprehensiveReportOrder() []string {
	return []string{
		"NSLOOKUP", "DIG (A)", "DIG (AAAA)", "DIG (CNAME)", "DIG (MX)",
		"DIG (NS)", "DIG (SOA)", "DIG (TXT)", "DIG (SPF)", "DIG (DMARC)",
		"DIG (CAA)", "DIG (PTR)", "Delegation", "DNSSEC", "Email", "RDAP", "WHOIS",
	}
}

func init() {
	RegisterProvider(&ComprehensiveProvider{})
}
