package lookup

import (
	"context"
	"fmt"
)

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

func (p *WhoisProvider) Command() string {
	return "whois"
}

// Execute runs whois. opts.Server is a DNS server and is ignored here.
func (p *WhoisProvider) Execute(ctx context.Context, target string, opts Options) (string, error) {
	if !p.CheckAvailability() {
		return "", fmt.Errorf("command not found: whois")
	}
	// Defense in depth against argument injection: never pass anything that
	// could be parsed as an option to the external command.
	target, err := NormalizeTarget(target)
	if err != nil {
		return "", err
	}
	return RunCommand(ctx, opts, "whois", target)
}

func (p *WhoisProvider) CheckAvailability() bool {
	return LookupCheckCommandFunc(p.Command())
}

func init() {
	RegisterProvider(&WhoisProvider{})
}
