package lookup

import (
	"fmt"
	"regexp"
	"strings"
)

type DigProvider struct {
	name     string
	flagName string
	args     []string
}

var nonAlphanumericRegex = regexp.MustCompile(`[^a-zA-Z0-9]+`)

func newDigProvider(name string, digArgs ...string) {
	s := strings.ToLower(name)
	s = nonAlphanumericRegex.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	flagName := "dig-" + s

	provider := &DigProvider{
		name:     name,
		flagName: flagName,
		args:     digArgs,
	}
	RegisterProvider(provider)
}

func (p *DigProvider) Name() string {
	return p.name
}

func (p *DigProvider) FlagName() string {
	return p.flagName
}

func (p *DigProvider) Usage() string {
	return fmt.Sprintf("Run %s lookup on domains from <filename>", p.Name())
}

func (p *DigProvider) Execute(domain string) (string, error) {
	if !p.CheckAvailability() {
		return "", fmt.Errorf("command not found: dig")
	}
	fullArgs := append([]string{domain}, p.args...)
	// Use the new exported RunCommand which allows mocking
	return RunCommand("dig", fullArgs...)
}

func (p *DigProvider) CheckAvailability() bool {
	return LookupCheckCommandFunc("dig") // Use the mockable function
}

func init() {
	newDigProvider("DIG (ANY)", "ANY", "+noall", "+answer")
	newDigProvider("DIG (A)", "A", "+short")
	newDigProvider("DIG (AAAA)", "AAAA", "+short")
	newDigProvider("DIG (MX)", "MX", "+short")
	newDigProvider("DIG (TXT)", "TXT", "+noall", "+answer")
	newDigProvider("DIG (SOA)", "SOA", "+noall", "+answer")
	newDigProvider("DIG (CNAME)", "CNAME", "+short")
}
