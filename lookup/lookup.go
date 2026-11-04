package lookup

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// DefaultTimeout is applied to each command run when Options.Timeout is zero.
const DefaultTimeout = 15 * time.Second

// Options configures a single lookup execution.
type Options struct {
	Server  string        // optional DNS server, e.g. "1.1.1.1" or "1.1.1.1:53"; "" = system default
	Timeout time.Duration // 0 = DefaultTimeout
}

// timeout returns the effective timeout for these options.
func (o Options) timeout() time.Duration {
	if o.Timeout <= 0 {
		return DefaultTimeout
	}
	return o.Timeout
}

// LookupProvider is implemented by every lookup type (dig, nslookup, whois, report, ...).
type LookupProvider interface {
	// Name is the human-readable, unique name (e.g. "DIG (A)").
	Name() string
	// FlagName is the unique CLI flag name (e.g. "dig-dig-a").
	FlagName() string
	// Usage is the CLI flag usage text.
	Usage() string
	// Command is the external binary this provider needs, or "" if none.
	Command() string
	// CheckAvailability reports whether the provider can run on this system.
	CheckAvailability() bool
	// Execute runs the lookup against target.
	Execute(ctx context.Context, target string, opts Options) (string, error)
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
	// Legacy alias: older builds generated "dig-dig-a" style flag names.
	if legacy, ok := strings.CutPrefix(flagName, "dig-dig-"); ok {
		for _, provider := range registry {
			if provider.FlagName() == "dig-"+legacy {
				return provider, true
			}
		}
	}
	return nil, false
}

// AvailableProviders returns all registered providers (in no particular order).
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

// LookupCheckCommandFunc is a function variable that wraps the command checking logic.
// Tests can replace this with a mock implementation.
var LookupCheckCommandFunc = internalCheckCommand

// internalCheckCommand is the actual implementation for checking command availability.
// Results are cached per command name.
func internalCheckCommand(cmdName string) bool {
	cmdCheckMutex.Lock()
	defer cmdCheckMutex.Unlock()

	if available, checked := commandsAvailable[cmdName]; checked {
		return available
	}

	_, err := exec.LookPath(cmdName)
	available := err == nil
	commandsAvailable[cmdName] = available
	return available
}

func checkAllCommandsOnce() {
	initialCmdCheck.Do(func() {
		requiredCmds := make(map[string]struct{})
		registryMutex.RLock()
		for _, p := range registry {
			if c := p.Command(); c != "" {
				requiredCmds[c] = struct{}{}
			}
		}
		registryMutex.RUnlock()
		for cmdName := range requiredCmds {
			LookupCheckCommandFunc(cmdName) // Use the mockable function
		}
	})
}

// osRunCommandInternal is the actual implementation that executes a command.
// It returns the raw output (combined stdout/stderr) and raw error.
func osRunCommandInternal(ctx context.Context, cmdName string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, cmdName, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	output := strings.TrimSpace(stdout.String())
	errMsg := strings.TrimSpace(stderr.String())

	finalOutput := output
	if errMsg != "" {
		if output != "" {
			finalOutput = fmt.Sprintf("STDOUT:\n%s\nSTDERR:\n%s", output, errMsg)
		} else {
			finalOutput = fmt.Sprintf("STDERR:\n%s", errMsg)
		}
	}
	return finalOutput, err
}

// OsRunCommand is a variable that holds the function to execute commands.
// Tests can replace this with a mock implementation. It should return raw output and raw error.
var OsRunCommand = osRunCommandInternal

// RunCommand executes a command via OsRunCommand with opts' timeout applied to ctx,
// then applies transformations (error wrapping, "No results found").
func RunCommand(ctx context.Context, opts Options, cmdName string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, opts.timeout())
	defer cancel()

	rawOutput, rawErr := OsRunCommand(ctx, cmdName, args...)

	if rawErr != nil {
		// Prefer the context error (deadline/cancel) over e.g. "signal: killed".
		if ctxErr := ctx.Err(); ctxErr != nil {
			rawErr = ctxErr
		}
		return rawOutput, fmt.Errorf("command '%s %s' failed: %w", cmdName, strings.Join(args, " "), rawErr)
	}

	if rawOutput == "" {
		return "(No results found)", nil
	}
	return rawOutput, nil
}
