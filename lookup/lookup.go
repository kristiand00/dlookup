package lookup

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

type LookupProvider interface {
	Name() string
	Execute(domain string) (output string, err error)
	CheckAvailability() bool
	FlagName() string
	Usage() string
}

var (
	registry          = make(map[string]LookupProvider)
	registryMutex     sync.RWMutex
	commandsAvailable = make(map[string]bool)
	cmdCheckMutex     sync.Mutex
	initialCmdCheck   sync.Once
)

func RegisterProvider(provider LookupProvider) {
	registryMutex.Lock()
	defer registryMutex.Unlock()

	name := provider.Name()
	flagName := provider.FlagName()

	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("lookup provider with name %q already registered", name))
	}

	for _, existingProvider := range registry {
		if existingProvider.FlagName() == flagName {
			panic(fmt.Sprintf("lookup provider with flag name %q already registered (by %q)", flagName, existingProvider.Name()))
		}
	}

	registry[name] = provider
}

func GetProvider(name string) (LookupProvider, bool) {
	registryMutex.RLock()
	defer registryMutex.RUnlock()
	provider, exists := registry[name]
	return provider, exists
}

func GetProviderByFlagName(flagName string) (LookupProvider, bool) {
	registryMutex.RLock()
	defer registryMutex.RUnlock()
	for _, provider := range registry {
		if provider.FlagName() == flagName {
			return provider, true
		}
	}
	return nil, false
}

func AvailableProviders() []LookupProvider {

	checkAllCommandsOnce()

	registryMutex.RLock()
	defer registryMutex.RUnlock()
	providers := make([]LookupProvider, 0, len(registry))
	for _, provider := range registry {
		providers = append(providers, provider)
	}
	return providers
}

func checkCommand(cmdName string) bool {
	cmdCheckMutex.Lock()
	defer cmdCheckMutex.Unlock()

	if available, checked := commandsAvailable[cmdName]; checked {
		return available
	}

	_, err := exec.LookPath(cmdName)
	available := (err == nil)
	commandsAvailable[cmdName] = available
	return available
}

func checkAllCommandsOnce() {
	initialCmdCheck.Do(func() {
		requiredCmds := make(map[string]struct{})
		registryMutex.RLock()
		for _, p := range registry {
			switch {
			case strings.HasPrefix(p.Name(), "DIG"):
				requiredCmds["dig"] = struct{}{}
			case strings.HasPrefix(p.Name(), "NSLOOKUP"):
				requiredCmds["nslookup"] = struct{}{}
			case strings.HasPrefix(p.Name(), "WHOIS"):
				requiredCmds["whois"] = struct{}{}
			}
		}
		registryMutex.RUnlock()
		for cmdName := range requiredCmds {
			checkCommand(cmdName)
		}
	})
}

func runCommand(cmdName string, args ...string) (string, error) {
	cmd := exec.Command(cmdName, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	output := strings.TrimSpace(stdout.String())
	errMsg := strings.TrimSpace(stderr.String())
	finalOutput := output

	if errMsg != "" {
		if output != "" {
			finalOutput = fmt.Sprintf(`STDERR:
%s

STDOUT:
%s`, errMsg, output)
		} else {
			finalOutput = fmt.Sprintf(`STDERR:
%s`, errMsg)
		}
	}
	if err != nil {
		detail := fmt.Errorf("command '%s %s' failed: %w", cmdName, strings.Join(args, " "), err)
		if errMsg != "" {
			detail = fmt.Errorf(`%w
STDERR was:
%s`, detail, errMsg)
		}
		return finalOutput, detail
	}
	if finalOutput == "" {
		finalOutput = "(No results found)"
	}
	return finalOutput, nil
}
