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

// LookupCheckCommandFunc is a function variable that wraps the command checking logic.
// Tests can replace this with a mock implementation.
var LookupCheckCommandFunc = internalCheckCommand

// internalCheckCommand is the actual implementation for checking command availability.
func internalCheckCommand(cmdName string) bool {
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
			LookupCheckCommandFunc(cmdName) // Use the mockable function
		}
	})
}

// osRunCommandInternal is the actual implementation that executes a command.
// It returns the raw output (potentially combined stdout/stderr) and raw error.
func osRunCommandInternal(cmdName string, args ...string) (string, error) {
	cmd := exec.Command(cmdName, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run() // This is the raw error from the command execution

	output := strings.TrimSpace(stdout.String())
	errMsg := strings.TrimSpace(stderr.String())

	// Combine stdout and stderr into a single output string for simplicity if needed by caller
	// Or, could return them separately if RunCommand is made to handle it.
	// For now, stick to current combined behavior if errMsg is present.
	finalOutput := output
	if errMsg != "" {
		if output != "" {
			finalOutput = fmt.Sprintf("STDOUT:\n%s\nSTDERR:\n%s", output, errMsg) // Adjusted format slightly for clarity
		} else {
			finalOutput = fmt.Sprintf("STDERR:\n%s", errMsg)
		}
	}
	return finalOutput, err // Return raw output and raw error
}

// OsRunCommand is a variable that holds the function to execute commands.
// Tests can replace this with a mock implementation. It should adhere to returning raw output and raw error.
var OsRunCommand = osRunCommandInternal

// RunCommand executes a command using the function assigned to OsRunCommand,
// then applies transformations (error wrapping, "No results found").
func RunCommand(cmdName string, args ...string) (string, error) {
	rawOutput, rawErr := OsRunCommand(cmdName, args...)

	if rawErr != nil {
		// Error wrapping logic, potentially including rawOutput if it's stderr
		// Based on previous osRunCommandInternal, rawOutput might already contain stderr.
		// Let's assume rawOutput is the string to return alongside the error.
		detail := fmt.Errorf("command '%s %s' failed: %w", cmdName, strings.Join(args, " "), rawErr)
		// If rawOutput contains actual stderr info (as per osRunCommandInternal's old logic),
		// it might need to be appended to 'detail' or handled.
		// For now, the tests set rawOutput to "error output" in failure cases.
		return rawOutput, detail
	}

	if rawOutput == "" {
		return "(No results found)", nil
	}
	return rawOutput, nil
}
