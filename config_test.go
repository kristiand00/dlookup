package main

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestDefaultKeybindingsNoDuplicates(t *testing.T) {
	if err := validateKeybindings(DefaultKeybindings()); err != nil {
		t.Fatal(err)
	}
}

func TestValidateKeybindingsReportsProblems(t *testing.T) {
	k := DefaultKeybindings()
	k.CloseTab = "w" // old default, collides with watch_toggle
	k.Copy = ""
	err := validateKeybindings(k)
	if err == nil {
		t.Fatal("expected error")
	}
	for _, want := range []string{"close_tab", "watch_toggle", "copy is empty"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q missing %q", err, want)
		}
	}
}

func TestSanitizeKeybindings(t *testing.T) {
	// Old config files had close_tab and watch_toggle both "w".
	k := DefaultKeybindings()
	k.CloseTab = "w"
	k.Copy = "  "
	k.Export = "e" // custom, non-conflicting: kept
	fixed, err := sanitizeKeybindings(k)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if fixed.CloseTab != "x" || fixed.WatchToggle != "w" || fixed.Copy != "y" || fixed.Export != "e" {
		t.Fatalf("unexpected fix: %+v", fixed)
	}
	if validateKeybindings(fixed) != nil {
		t.Fatal("sanitized bindings must be valid")
	}

	// Resetting close_tab to "x" collides with a custom copy="x": fall back entirely.
	k = DefaultKeybindings()
	k.CloseTab = "w"
	k.Copy = "x"
	fixed, err = sanitizeKeybindings(k)
	if err == nil || fixed != DefaultKeybindings() {
		t.Fatalf("expected full fallback to defaults, got %+v (err %v)", fixed, err)
	}

	fixed, err = sanitizeKeybindings(DefaultKeybindings())
	if err != nil || fixed != DefaultKeybindings() {
		t.Fatalf("valid bindings changed: %+v %v", fixed, err)
	}
}

func TestOldConfigGetsNewKeyDefaults(t *testing.T) {
	old := []byte("keybindings:\n  quit: ctrl+c\n  close_tab: ctrl+w\n  watch_toggle: w\n")
	cfg := DefaultConfig()
	if err := yaml.Unmarshal(old, &cfg); err != nil {
		t.Fatal(err)
	}
	k := cfg.Keybindings
	if k.CloseTab != "ctrl+w" || k.Copy != "y" || k.Server != "s" || k.ExportAll != "ctrl+e" {
		t.Fatalf("unexpected bindings: %+v", k)
	}
	if err := validateKeybindings(k); err != nil {
		t.Fatal(err)
	}
}
