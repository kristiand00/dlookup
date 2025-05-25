package lookup

import "fmt"

type WhoisProvider struct{}

func (p *WhoisProvider) Name() string {
	return "WHOIS"
}

func (p *WhoisProvider) FlagName() string {
	return "whois"
}

func (p *WhoisProvider) Usage() string {
	return fmt.Sprintf("Run %s lookup on domains from <filename>", p.Name())
}

func (p *WhoisProvider) Execute(domain string) (string, error) {
	if !p.CheckAvailability() {
		return "", fmt.Errorf("command not found: whois")
	}

	return RunCommand("whois", domain) // Use exported RunCommand
}

func (p *WhoisProvider) CheckAvailability() bool {
	return LookupCheckCommandFunc("whois") // Use the mockable function
}

func init() {
	RegisterProvider(&WhoisProvider{})
}
