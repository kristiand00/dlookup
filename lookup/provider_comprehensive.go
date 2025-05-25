package lookup

import (
	"fmt"
	"sort"
	"strings"
)

type ComprehensiveProvider struct{}

const ComprehensiveReportName = "Report"

func (p *ComprehensiveProvider) Name() string {
	return ComprehensiveReportName
}

func (p *ComprehensiveProvider) FlagName() string {
	return "report"
}

func (p *ComprehensiveProvider) Usage() string {
	return fmt.Sprintf("Run %s (all lookups) on domains from <filename>", p.Name())
}

func (p *ComprehensiveProvider) CheckAvailability() bool {
	return true
}

func (p *ComprehensiveProvider) Execute(domain string) (string, error) {
	results := make(map[string]string)
	providers := AvailableProviders() // Assuming AvailableProviders() is a function in the lookup package

	for _, provider := range providers {
		if provider.Name() == ComprehensiveReportName {
			continue // Skip self
		}
		if !provider.CheckAvailability() {
			// Optionally, decide if you want to report unavailable providers
			// results[provider.Name()] = "Error: Provider not available"
			continue
		}

		output, err := provider.Execute(domain)
		if err != nil {
			results[provider.Name()] = fmt.Sprintf("Error: %v\nOutput:\n%s", err, output)
		} else {
			results[provider.Name()] = output
		}
	}

	order := GetComprehensiveReportOrder()
	return FormatComprehensiveReport(domain, results, order), nil
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
		"NSLOOKUP", "DIG (A)", "DIG (AAAA)", "DIG (MX)", "DIG (CNAME)",
		"DIG (TXT)", "DIG (SOA)", "DIG (ANY)", "WHOIS",
	}
}

func init() {
	RegisterProvider(&ComprehensiveProvider{})
}
