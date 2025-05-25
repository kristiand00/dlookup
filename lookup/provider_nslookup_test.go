package lookup_test

import (
	"dlookup/lookup"
	"fmt"
	"strings"
	"testing"
)

// TestNslookupProvider_StaticMethods tests the static methods of the NSLOOKUP provider.
func TestNslookupProvider_StaticMethods(t *testing.T) {
	provider, ok := lookup.GetProvider("NSLOOKUP")
	if !ok {
		t.Fatalf("Expected provider 'NSLOOKUP' not found.")
	}

	expectedName := "NSLOOKUP"
	if name := provider.Name(); name != expectedName {
		t.Errorf("Name() = %q, want %q", name, expectedName)
	}

	expectedFlagName := "nslookup"
	if flagName := provider.FlagName(); flagName != expectedFlagName {
		t.Errorf("FlagName() = %q, want %q", flagName, expectedFlagName)
	}

	expectedUsagePrefix := fmt.Sprintf("Run %s", expectedName)
	expectedUsageSuffix := "lookup on domains from <filename>"
	if usage := provider.Usage(); !strings.HasPrefix(usage, expectedUsagePrefix) || !strings.HasSuffix(usage, expectedUsageSuffix) {
		t.Errorf("Usage() = %q, want prefix %q and suffix %q", usage, expectedUsagePrefix, expectedUsageSuffix)
	}
}

// TestNslookupProvider_CheckAvailability tests the CheckAvailability method of the NSLOOKUP provider.
func TestNslookupProvider_CheckAvailability(t *testing.T) {
	origCheckCommandFunc := lookup.LookupCheckCommandFunc
	defer func() { lookup.LookupCheckCommandFunc = origCheckCommandFunc }()
	lookup.LookupCheckCommandFunc = func(cmd string) bool {
		return cmd == "nslookup" // Assume nslookup is always available for these tests
	}

	provider, ok := lookup.GetProvider("NSLOOKUP")
	if !ok {
		t.Fatalf("Expected provider 'NSLOOKUP' not found.")
	}

	// This test assumes 'nslookup' command is available in the test environment's PATH.
	if !provider.CheckAvailability() {
		t.Errorf("CheckAvailability() for 'NSLOOKUP' returned false, expected true (assuming 'nslookup' is available).")
	}
}

// TestNslookupProvider_Execute tests the Execute method of the NSLOOKUP provider.
func TestNslookupProvider_Execute(t *testing.T) {
	origRunCommand := lookup.OsRunCommand
	defer func() { lookup.OsRunCommand = origRunCommand }()

	origCheckCommandFunc := lookup.LookupCheckCommandFunc
	defer func() { lookup.LookupCheckCommandFunc = origCheckCommandFunc }()
	lookup.LookupCheckCommandFunc = func(cmd string) bool {
		return cmd == "nslookup" // Assume nslookup is always available for Execute tests
	}

	provider, ok := lookup.GetProvider("NSLOOKUP")
	if !ok {
		t.Fatalf("Expected provider 'NSLOOKUP' not found.")
	}

	var capturedCmdName string
	var capturedArgs []string
	domainToTest := "google.com"

	// Test Case 1: Successful execution
	t.Run("Success", func(t *testing.T) {
		expectedOutput := "Mocked nslookup output for " + domainToTest
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
		if capturedCmdName != "nslookup" {
			t.Errorf("Execute() called command %q, want 'nslookup'", capturedCmdName)
		}
		expectedArgs := []string{domainToTest}
		if !equalSlices(capturedArgs, expectedArgs) {
			t.Errorf("Execute() args = %v, want %v", capturedArgs, expectedArgs)
		}
	})

	// Test Case 2: Command execution failure
	t.Run("CommandFailure", func(t *testing.T) {
		mockError := fmt.Errorf("mocked nslookup error")
		lookup.OsRunCommand = func(cmdName string, args ...string) (string, error) {
			capturedCmdName = cmdName
			capturedArgs = args
			return "error nslookup output", mockError
		}

		output, err := provider.Execute(domainToTest)
		if err == nil {
			t.Fatalf("Execute() error = nil, want non-nil")
		}
		// RunCommand performs the wrapping.
		expectedWrappedErrStr := fmt.Sprintf("command 'nslookup %s' failed: %s", domainToTest, mockError.Error())
		if err == nil {
			t.Fatalf("Execute() error = nil, want non-nil")
		} else if err.Error() != expectedWrappedErrStr {
			t.Errorf("Execute() error = %q, want %q", err.Error(), expectedWrappedErrStr)
		}

		// The mock OsRunCommand returns "error nslookup output" as the string part.
		if output != "error nslookup output" {
			t.Errorf("Execute() output on error = %q, want %q", output, "error nslookup output")
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
