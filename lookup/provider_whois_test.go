package lookup_test

import (
	"dlookup/lookup"
	"fmt"
	"strings"
	"testing"
)

// TestWhoisProvider_StaticMethods tests the static methods of the WHOIS provider.
func TestWhoisProvider_StaticMethods(t *testing.T) {
	provider, ok := lookup.GetProvider("WHOIS")
	if !ok {
		t.Fatalf("Expected provider 'WHOIS' not found.")
	}

	expectedName := "WHOIS"
	if name := provider.Name(); name != expectedName {
		t.Errorf("Name() = %q, want %q", name, expectedName)
	}

	expectedFlagName := "whois"
	if flagName := provider.FlagName(); flagName != expectedFlagName {
		t.Errorf("FlagName() = %q, want %q", flagName, expectedFlagName)
	}

	expectedUsagePrefix := fmt.Sprintf("Run %s", expectedName)
	expectedUsageSuffix := "lookup on domains from <filename>"
	if usage := provider.Usage(); !strings.HasPrefix(usage, expectedUsagePrefix) || !strings.HasSuffix(usage, expectedUsageSuffix) {
		t.Errorf("Usage() = %q, want prefix %q and suffix %q", usage, expectedUsagePrefix, expectedUsageSuffix)
	}
}

// TestWhoisProvider_CheckAvailability tests the CheckAvailability method of the WHOIS provider.
func TestWhoisProvider_CheckAvailability(t *testing.T) {
	origCheckCommandFunc := lookup.LookupCheckCommandFunc
	defer func() { lookup.LookupCheckCommandFunc = origCheckCommandFunc }()
	lookup.LookupCheckCommandFunc = func(cmd string) bool {
		return cmd == "whois" // Assume whois is always available for these tests
	}

	provider, ok := lookup.GetProvider("WHOIS")
	if !ok {
		t.Fatalf("Expected provider 'WHOIS' not found.")
	}

	// This test assumes 'whois' command is available in the test environment's PATH.
	if !provider.CheckAvailability() {
		t.Errorf("CheckAvailability() for 'WHOIS' returned false, expected true (assuming 'whois' is available).")
	}
}

// TestWhoisProvider_Execute tests the Execute method of the WHOIS provider.
func TestWhoisProvider_Execute(t *testing.T) {
	origRunCommand := lookup.OsRunCommand
	defer func() { lookup.OsRunCommand = origRunCommand }()

	origCheckCommandFunc := lookup.LookupCheckCommandFunc
	defer func() { lookup.LookupCheckCommandFunc = origCheckCommandFunc }()
	lookup.LookupCheckCommandFunc = func(cmd string) bool {
		return cmd == "whois" // Assume whois is always available for Execute tests
	}

	provider, ok := lookup.GetProvider("WHOIS")
	if !ok {
		t.Fatalf("Expected provider 'WHOIS' not found.")
	}

	var capturedCmdName string
	var capturedArgs []string
	domainToTest := "google.com"

	// Test Case 1: Successful execution
	t.Run("Success", func(t *testing.T) {
		expectedOutput := "Mocked whois output for " + domainToTest
		lookup.OsRunCommand = func(cmdName string, args ...string) (string, error) {
			capturedCmdName = cmdName
			capturedArgs = args
			return expectedOutput, nil
		}

		output, err := provider.Execute(domainToTest)
		if err != nil {
			t.Errorf("Execute() error = %v, want nil", err)
		}
		if output != expectedOutput {
			t.Errorf("Execute() output = %q, want %q", output, expectedOutput)
		}
		if capturedCmdName != "whois" {
			t.Errorf("Execute() called command %q, want 'whois'", capturedCmdName)
		}
		expectedArgs := []string{domainToTest}
		if !equalSlices(capturedArgs, expectedArgs) {
			t.Errorf("Execute() args = %v, want %v", capturedArgs, expectedArgs)
		}
	})

	// Test Case 2: Command execution failure
	t.Run("CommandFailure", func(t *testing.T) {
		mockError := fmt.Errorf("mocked whois error")
		lookup.OsRunCommand = func(cmdName string, args ...string) (string, error) {
			capturedCmdName = cmdName
			capturedArgs = args
			return "error whois output", mockError
		}

		output, err := provider.Execute(domainToTest)
		if err == nil {
			t.Fatalf("Execute() error = nil, want non-nil")
		}
		// RunCommand performs the wrapping.
		expectedWrappedErrStr := fmt.Sprintf("command 'whois %s' failed: %s", domainToTest, mockError.Error())
		if err == nil {
			t.Fatalf("Execute() error = nil, want non-nil")
		} else if err.Error() != expectedWrappedErrStr {
			t.Errorf("Execute() error = %q, want %q", err.Error(), expectedWrappedErrStr)
		}

		// The mock OsRunCommand returns "error whois output" as the string part.
		if output != "error whois output" {
			t.Errorf("Execute() output on error = %q, want %q", output, "error whois output")
		}
	})

	// Test Case 3: Command produces no output (but no error)
	t.Run("NoOutput", func(t *testing.T) {
		// RunCommand should convert empty raw output to "(No results found)"
		expectedOutput := "(No results found)"
		lookup.OsRunCommand = func(cmdName string, args ...string) (string, error) {
			capturedCmdName = cmdName
			capturedArgs = args
			return "", nil // Mock OsRunCommand returns empty string and nil error
		}

		output, err := provider.Execute("nodata.example.com")
		if err != nil {
			t.Errorf("Execute() error = %v, want nil", err)
		}
		if output != expectedOutput {
			t.Errorf("Execute() output = %q, want %q", output, expectedOutput)
		}
	})
}
