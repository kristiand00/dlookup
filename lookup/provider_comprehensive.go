package lookup

import (
	"fmt"
	"sort"
	"strings"
)

// ComprehensiveProvider orchestrates running all other lookups.
type ComprehensiveProvider struct{}

// Exported constant for the report name
const ComprehensiveReportName = "Comprehensive Report"

// Name returns the user-facing name.
func (p *ComprehensiveProvider) Name() string {
	return ComprehensiveReportName
}

// FlagName returns the command-line flag name.
func (p *ComprehensiveProvider) FlagName() string {
	// Simple flag name for the combined report
	return "comprehensive-report"
}

// Usage returns the help text for the command-line flag.
func (p *ComprehensiveProvider) Usage() string {
	return fmt.Sprintf("Run %s (all lookups) on domains from <filename>", p.Name())
}

// CheckAvailability for the comprehensive report always returns true,
// as it attempts to run all *available* underlying lookups.
func (p *ComprehensiveProvider) CheckAvailability() bool {
	return true // Individual provider checks happen during Execute
}

// Execute satisfies the LookupProvider interface but should not be called directly
// for ComprehensiveProvider. The orchestration happens in tabModel.
func (p *ComprehensiveProvider) Execute(domain string) (string, error) {
	// This should ideally never be reached if tabModel handles it specially.
	return "", fmt.Errorf("comprehensive provider Execute() should not be called directly")
}

// Execute runs all other registered providers concurrently and formats their results.
/* // Execute logic moved to tabModel.runSelectedLookup's command
func (p *ComprehensiveProvider) Execute(domain string) (string, error) {
	// ... concurrent execution logic ...
	return formatComprehensiveReport(domain, results, providerOrder), nil
}
*/

// formatComprehensiveReport takes the results from individual lookups and formats them.
// Exported so it can be called from main package.
func FormatComprehensiveReport(domain string, results map[string]string, order []string) string {
	var b strings.Builder
	b.WriteString(fmt.Sprintf("Comprehensive Report for: %s\n", domain))
	b.WriteString(strings.Repeat("=", 40+len(domain)))
	b.WriteString("\n")

	processed := make(map[string]bool)

	// Process in the preferred order
	for _, name := range order {
		if result, ok := results[name]; ok {
			b.WriteString(fmt.Sprintf("\n--- %s ---\n", name))
			b.WriteString(strings.TrimSpace(result))
			b.WriteString("\n")
			processed[name] = true
		}
	}

	// Process any remaining results not in the preferred order (sorted alphabetically)
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

// GetComprehensiveReportOrder returns the preferred order for providers in the report.
// Exported for use in the command orchestration.
func GetComprehensiveReportOrder() []string {
	// Return the same order defined in the formatting function
	return []string{
		"NSLOOKUP", "DIG (A)", "DIG (AAAA)", "DIG (MX)", "DIG (CNAME)",
		"DIG (TXT)", "DIG (SOA)", "DIG (ANY)", "WHOIS",
	}
}

// Automatically register the provider.
func init() {
	RegisterProvider(&ComprehensiveProvider{})
}
