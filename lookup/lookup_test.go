package lookup_test

import (
	"dlookup/lookup" // Assuming dlookup is the module name
	"fmt"
	"testing"
)

// mockProvider is a simple implementation of lookup.LookupProvider for testing.
type mockProvider struct {
	name      string
	flagName  string
	usage     string
	available bool
}

func (m *mockProvider) Name() string                                  { return m.name }
func (m *mockProvider) Execute(domain string) (string, error)         { return fmt.Sprintf("executed %s for %s", m.name, domain), nil }
func (m *mockProvider) CheckAvailability() bool                       { return m.available }
func (m *mockProvider) FlagName() string                              { return m.flagName }
func (m *mockProvider) Usage() string                                 { return m.usage }

func assertPanics(t *testing.T, fn func(), expectedPanicValue interface{}) {
	t.Helper()
	defer func() {
		r := recover()
		if r == nil {
			t.Errorf("The code did not panic as expected")
			return
		}
		if r != expectedPanicValue {
			t.Errorf("Panic value was %v, expected %v", r, expectedPanicValue)
		}
	}()
	fn()
}

func TestProviderRegistrationAndRetrieval(t *testing.T) {
	// Note: Due to the lookup package's global registry and lack of a reset mechanism,
	// registered providers in this test will persist for subsequent tests.
	// This is a limitation we have to work with.

	mockP := &mockProvider{
		name:      "test-provider",
		flagName:  "test-flag",
		usage:     "test usage",
		available: true,
	}

	// Test initial registration
	lookup.RegisterProvider(mockP)

	// Test GetProvider
	retrievedProvider, ok := lookup.GetProvider("test-provider")
	if !ok {
		t.Fatalf("GetProvider failed to find 'test-provider'")
	}
	if retrievedProvider.Name() != "test-provider" {
		t.Errorf("GetProvider returned wrong provider name: got %s, want %s", retrievedProvider.Name(), "test-provider")
	}

	// Test GetProviderByFlagName
	retrievedByFlagProvider, ok := lookup.GetProviderByFlagName("test-flag")
	if !ok {
		t.Fatalf("GetProviderByFlagName failed to find 'test-flag'")
	}
	if retrievedByFlagProvider.FlagName() != "test-flag" {
		t.Errorf("GetProviderByFlagName returned wrong provider flag name: got %s, want %s", retrievedByFlagProvider.FlagName(), "test-flag")
	}

	// Test AvailableProviders
	available := lookup.AvailableProviders()
	found := false
	for _, p := range available {
		if p.Name() == "test-provider" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("AvailableProviders did not include the test-provider")
	}

	// Test panic on duplicate name registration
	// Note: The mockP ("test-provider", "test-flag") is already registered.
	duplicateNameProvider := &mockProvider{name: "test-provider", flagName: "other-flag-for-name-test"}
	expectedPanicMsgName := fmt.Sprintf("lookup provider with name %q already registered", "test-provider")
	assertPanics(t, func() {
		lookup.RegisterProvider(duplicateNameProvider)
	}, expectedPanicMsgName)

	// Test panic on duplicate flag name registration
	duplicateFlagProvider := &mockProvider{name: "other-provider-for-flag-test", flagName: "test-flag"}
	// The original provider that registered "test-flag" was "test-provider".
	expectedPanicMsgFlag := fmt.Sprintf("lookup provider with flag name %q already registered (by %q)", "test-flag", "test-provider")
	assertPanics(t, func() {
		lookup.RegisterProvider(duplicateFlagProvider)
	}, expectedPanicMsgFlag)

	// Test GetProvider for non-existent provider
	_, ok = lookup.GetProvider("non-existent-provider")
	if ok {
		t.Errorf("Expected GetProvider to return ok=false for 'non-existent-provider', but got ok=true")
	}
	// Note: The original test was checking for a specific error message.
	// GetProvider returns (LookupProvider, bool), not an error.
	// The error is implicit in ok=false. If specific error messages are desired,
	// the GetProvider function itself would need to change its signature.

	// Test GetProviderByFlagName for non-existent provider
	_, ok = lookup.GetProviderByFlagName("non-existent-flag")
	if ok {
		t.Errorf("Expected GetProviderByFlagName to return ok=false for 'non-existent-flag', but got ok=true")
	}
	// Similar to GetProvider, no explicit error object is returned.
}

func TestProviderAvailability(t *testing.T) {
	// This test indirectly checks the command availability logic by using a mock provider
	// whose CheckAvailability() method can be controlled.

	// Note: Due to the lookup package's global registry and lack of a reset mechanism,
	// this provider will also persist. We use a unique name to avoid conflict.
	mockP := &mockProvider{
		name:      "avail-test-provider",
		flagName:  "avail-flag",
		usage:     "avail test usage",
		available: true, // Initially available
	}
	lookup.RegisterProvider(mockP)

	retrievedProvider, ok := lookup.GetProvider("avail-test-provider")
	if !ok {
		t.Fatalf("GetProvider failed for avail-test-provider")
	}

	// Case 1: Provider's command is available
	// We need to re-cast to *mockProvider to change the 'available' field for the test.
	// The instance from GetProvider is lookup.LookupProvider.
	// This isn't ideal but necessary because the CheckAvailability is on the mockProvider itself.
	// A better way would be if the mockProvider's CheckAvailability consulted a mutable map or channel,
	// but for this structure, we'll manage the original mockP.

	if !retrievedProvider.CheckAvailability() {
		t.Errorf("Expected CheckAvailability to be true when mockProvider.available is true")
	}

	// Case 2: Provider's command becomes unavailable
	mockP.available = false // Modify the original mockP instance that was registered
	// Re-fetch or assume the registry returns the same instance (which it should for pointers)
	// The CheckAvailability() method of the retrieved provider will call the method on the original mockP.

	if retrievedProvider.CheckAvailability() {
		t.Errorf("Expected CheckAvailability to be false when mockProvider.available is false")
	}

	// To ensure a clean state for this specific test's logic if we were to run it multiple times
	// or if other tests depended on this provider's availability state, we would ideally unregister
	// or reset the mockP.available field. Since unregistration is not an option, we'll just
	// set it back to a known state if necessary, though for this test, it's the last action.
	mockP.available = true // Reset for potential other tests if any depended on this exact provider instance
}
