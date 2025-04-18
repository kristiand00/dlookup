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

	return runCommand("whois", domain)
}

func (p *WhoisProvider) CheckAvailability() bool {
	return checkCommand("whois")
}

func init() {
	RegisterProvider(&WhoisProvider{})
}
