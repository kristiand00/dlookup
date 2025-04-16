package lookup

import "fmt"

// WhoisProvider implements the LookupProvider interface for whois.
type WhoisProvider struct{}

// Name returns the user-facing name.
func (p *WhoisProvider) Name() string {
	return "WHOIS"
}

// FlagName returns the command-line flag name.
func (p *WhoisProvider) FlagName() string {
	return "whois"
}

// Usage returns the help text for the command-line flag.
func (p *WhoisProvider) Usage() string {
	return fmt.Sprintf("Run %s lookup on domains from <filename>", p.Name())
}

// Execute runs the whois command.
func (p *WhoisProvider) Execute(domain string) (string, error) {
	if !p.CheckAvailability() {
		return "", fmt.Errorf("command not found: whois")
	}
	// Whois often provides more useful output on error than the Go error itself
	// so we rely on runCommand's stderr handling.
	return runCommand("whois", domain)
}

// CheckAvailability checks if the whois command is available.
func (p *WhoisProvider) CheckAvailability() bool {
	return checkCommand("whois")
}

// Automatically register the provider when the package is initialized.
func init() {
	RegisterProvider(&WhoisProvider{})
}
