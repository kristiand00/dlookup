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
	return RunCommand("nslookup", domain) // Use exported RunCommand
}

func (p *NslookupProvider) CheckAvailability() bool {
	return LookupCheckCommandFunc("nslookup") // Use the mockable function
}

func init() {
	RegisterProvider(&NslookupProvider{})
}
