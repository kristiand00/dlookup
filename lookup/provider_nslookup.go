package lookup

import (
	"context"
	"fmt"
	"net"
)

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

func (p *NslookupProvider) Command() string {
	return "nslookup"
}

func (p *NslookupProvider) Execute(ctx context.Context, target string, opts Options) (string, error) {
	if !p.CheckAvailability() {
		return "", fmt.Errorf("command not found: nslookup")
	}
	// Defense in depth against argument injection: never pass anything that
	// could be parsed as an option to the external command.
	target, err := NormalizeTarget(target)
	if err != nil {
		return "", err
	}
	args := []string{target}
	if opts.Server != "" {
		if err := ValidateServer(opts.Server); err != nil {
			return "", err
		}
		// nslookup [-port=N] target server
		if host, port, err := net.SplitHostPort(opts.Server); err == nil {
			args = []string{"-port=" + port, target, host}
		} else {
			args = append(args, opts.Server)
		}
	}
	return RunCommand(ctx, opts, "nslookup", args...)
}

func (p *NslookupProvider) CheckAvailability() bool {
	return LookupCheckCommandFunc(p.Command())
}

func init() {
	RegisterProvider(&NslookupProvider{})
}
