package lookup

import (
	"fmt"
	"regexp"
	"strings"
)

// DigProvider implements LookupProvider for various dig commands.
type DigProvider struct {
	name     string   // User-facing name (e.g., "DIG (A)")
	flagName string   // Command-line flag name (e.g., "dig-a")
	args     []string // Arguments to pass to dig (excluding the domain)
}

var nonAlphanumericRegex = regexp.MustCompile(`[^a-zA-Z0-9]+`)

// newDigProvider creates and registers a new DigProvider instance.
func newDigProvider(name string, digArgs ...string) {
	// Generate flag name from the user-facing name
	s := strings.ToLower(name)
	s = nonAlphanumericRegex.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	flagName := "dig-" + s // Prefix with dig- for clarity

	provider := &DigProvider{
		name:     name,
		flagName: flagName,
		args:     digArgs,
	}
	RegisterProvider(provider)
}

// Name returns the user-facing name.
func (p *DigProvider) Name() string {
	return p.name
}

// FlagName returns the command-line flag name.
func (p *DigProvider) FlagName() string {
	return p.flagName
}

// Usage returns the help text for the command-line flag.
func (p *DigProvider) Usage() string {
	return fmt.Sprintf("Run %s lookup on domains from <filename>", p.Name())
}

// Execute runs the dig command with the specific arguments for this provider.
func (p *DigProvider) Execute(domain string) (string, error) {
	if !p.CheckAvailability() {
		return "", fmt.Errorf("command not found: dig")
	}
	// Combine the domain with the pre-defined args
	fullArgs := append([]string{domain}, p.args...)
	return runCommand("dig", fullArgs...)
}

// CheckAvailability checks if the dig command is available.
func (p *DigProvider) CheckAvailability() bool {
	return checkCommand("dig")
}

// Automatically register all dig providers when the package is initialized.
func init() {
	newDigProvider("DIG (ANY)", "ANY", "+noall", "+answer")
	newDigProvider("DIG (A)", "A", "+short")
	newDigProvider("DIG (AAAA)", "AAAA", "+short")
	newDigProvider("DIG (MX)", "MX", "+short")
	newDigProvider("DIG (TXT)", "TXT", "+noall", "+answer")
	newDigProvider("DIG (SOA)", "SOA", "+noall", "+answer")
	newDigProvider("DIG (CNAME)", "CNAME", "+short")
}
