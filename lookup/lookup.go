package lookup

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
	"sync"
)

// LookupProvider defines the interface for executing a specific lookup command.
type LookupProvider interface {
	// Name returns the user-facing name of the lookup type (e.g., "NSLOOKUP", "DIG (A)").
	Name() string
	// Execute runs the lookup for the given domain and returns the output or an error.
	Execute(domain string) (output string, err error)
	// CheckAvailability verifies if the underlying command-line tool is available.
	CheckAvailability() bool
	// FlagName returns the command-line flag name for this provider (e.g., "nslookup", "dig-a").
	FlagName() string
	// Usage returns the help text for the command-line flag.
	Usage() string
}

// registry stores the available lookup providers.
var (
	registry          = make(map[string]LookupProvider)
	registryMutex     sync.RWMutex
	commandsAvailable = make(map[string]bool) // Cache for command availability
	cmdCheckMutex     sync.Mutex
	initialCmdCheck   sync.Once // Ensures commands are checked only once globally
)

// RegisterProvider adds a new lookup provider to the registry.
// It panics if a provider with the same name or flag name is already registered.
func RegisterProvider(provider LookupProvider) {
	registryMutex.Lock()
	defer registryMutex.Unlock()

	name := provider.Name()
	flagName := provider.FlagName()

	if _, exists := registry[name]; exists {
		panic(fmt.Sprintf("lookup provider with name %q already registered", name))
	}
	// Check for flag name collision as well
	for _, existingProvider := range registry {
		if existingProvider.FlagName() == flagName {
			panic(fmt.Sprintf("lookup provider with flag name %q already registered (by %q)", flagName, existingProvider.Name()))
		}
	}

	registry[name] = provider
}

// GetProvider retrieves a provider by its user-facing name.
func GetProvider(name string) (LookupProvider, bool) {
	registryMutex.RLock()
	defer registryMutex.RUnlock()
	provider, exists := registry[name]
	return provider, exists
}

// GetProviderByFlagName retrieves a provider by its command-line flag name.
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

// AvailableProviders returns a slice of all registered lookup providers, sorted by name.
// It also triggers the command availability check if not already done.
func AvailableProviders() []LookupProvider {
	// Ensure commands are checked at least once before returning providers
	checkAllCommandsOnce()

	registryMutex.RLock()
	defer registryMutex.RUnlock()
	providers := make([]LookupProvider, 0, len(registry))
	// TODO: Sort providers consistently if needed
	for _, provider := range registry {
		providers = append(providers, provider)
	}
	// Consider sorting providers alphabetically by Name() here
	return providers
}

// checkCommand checks if a command exists in the system's PATH.
// Results are cached.
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

// checkAllCommandsOnce ensures that the availability of all base commands
// used by registered providers is checked exactly once.
func checkAllCommandsOnce() {
	initialCmdCheck.Do(func() {
		// Get the unique base commands needed by registered providers
		requiredCmds := make(map[string]struct{})
		registryMutex.RLock()
		for _, p := range registry {
			// This assumes providers can tell us their base command (e.g., "dig", "nslookup")
			// We'll need to add a method to the interface or use a convention.
			// For now, let's hardcode the known ones.
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

		// Check each required command
		for cmdName := range requiredCmds {
			checkCommand(cmdName) // This will populate the cache
		}
	})
}

// Helper function to run external commands, similar to the original logic
func runCommand(cmdName string, args ...string) (string, error) {
	cmd := exec.Command(cmdName, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	output := strings.TrimSpace(stdout.String())
	errMsg := strings.TrimSpace(stderr.String())
	finalOutput := output

	// Combine stdout and stderr if stderr has content
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
			// Append stderr output to the error message for clarity
			detail = fmt.Errorf(`%w
STDERR was:
%s`, detail, errMsg)
		}
		// Return the combined output even on error, as it might contain useful info
		return finalOutput, detail
	}

	// Handle cases where the command succeeds but produces no output
	if finalOutput == "" {
		finalOutput = "(No results found)"
	}

	return finalOutput, nil
}
