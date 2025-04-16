package lookup

import "fmt"

// NslookupProvider implements the LookupProvider interface for nslookup.
type NslookupProvider struct{}

// Name returns the user-facing name.
func (p *NslookupProvider) Name() string {
	return "NSLOOKUP"
}

// FlagName returns the command-line flag name.
func (p *NslookupProvider) FlagName() string {
	return "nslookup"
}

// Usage returns the help text for the command-line flag.
func (p *NslookupProvider) Usage() string {
	return fmt.Sprintf("Run %s lookup on domains from <filename>", p.Name())
}

// Execute runs the nslookup command.
func (p *NslookupProvider) Execute(domain string) (string, error) {
	if !p.CheckAvailability() {
		return "", fmt.Errorf("command not found: nslookup")
	}
	return runCommand("nslookup", domain)
}

// CheckAvailability checks if the nslookup command is available.
func (p *NslookupProvider) CheckAvailability() bool {
	return checkCommand("nslookup")
}

// Automatically register the provider when the package is initialized.
func init() {
	RegisterProvider(&NslookupProvider{})
}
