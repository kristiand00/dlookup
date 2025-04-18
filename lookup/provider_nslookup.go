package lookup

import "fmt"

type NslookupProvider struct{}

func (p *NslookupProvider) Name() string {
	return "NSLOOKUP"
}

func (p *NslookupProvider) FlagName() string {
	return "nslookup"
}

func (p *NslookupProvider) Usage() string {
	return fmt.Sprintf("Run %s lookup on domains from <filename>", p.Name())
}

func (p *NslookupProvider) Execute(domain string) (string, error) {
	if !p.CheckAvailability() {
		return "", fmt.Errorf("command not found: nslookup")
	}
	return runCommand("nslookup", domain)
}

func (p *NslookupProvider) CheckAvailability() bool {
	return checkCommand("nslookup")
}

func init() {
	RegisterProvider(&NslookupProvider{})
}
