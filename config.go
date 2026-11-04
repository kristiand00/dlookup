package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// Keybindings defines the configurable key actions.
//
// Global keys (quit, new_tab, close_tab, next_tab, prev_tab, export_all) are
// handled by the tab container; the rest are handled by the active tab. All keys
// must be distinct so a global key never swallows a tab-level one.
type Keybindings struct {
	Quit        string `yaml:"quit"`
	NewTab      string `yaml:"new_tab"`
	CloseTab    string `yaml:"close_tab"`
	NextTab     string `yaml:"next_tab"`
	PrevTab     string `yaml:"prev_tab"`
	Back        string `yaml:"back"`         // Esc always works as well
	Confirm     string `yaml:"confirm"`      // Enter key in most contexts
	WatchToggle string `yaml:"watch_toggle"` // Start (interval prompt) / stop watch mode
	Export      string `yaml:"export"`       // Export the current tab's result to a file
	ExportAll   string `yaml:"export_all"`   // Export all tabs' results into one file
	Copy        string `yaml:"copy"`         // Copy the current result to the clipboard
	Server      string `yaml:"server"`       // Set the DNS server for the current tab
	ZoneDiff    string `yaml:"zone_diff"`    // Open the zone diff form for the current domain
	// ToggleMatches shows/hides matching records in the zone diff view.
	ToggleMatches string `yaml:"toggle_matches"`
}

// keybindingField is a named, addressable keybinding used for validation.
type keybindingField struct {
	name string // yaml name
	val  *string
}

// fields returns all keybindings with their yaml names, in a stable order.
func (k *Keybindings) fields() []keybindingField {
	return []keybindingField{
		{"quit", &k.Quit},
		{"new_tab", &k.NewTab},
		{"close_tab", &k.CloseTab},
		{"next_tab", &k.NextTab},
		{"prev_tab", &k.PrevTab},
		{"back", &k.Back},
		{"confirm", &k.Confirm},
		{"watch_toggle", &k.WatchToggle},
		{"export", &k.Export},
		{"export_all", &k.ExportAll},
		{"copy", &k.Copy},
		{"server", &k.Server},
		{"zone_diff", &k.ZoneDiff},
		{"toggle_matches", &k.ToggleMatches},
	}
}

// AppConfig holds the application configuration.
type AppConfig struct {
	Keybindings Keybindings `yaml:"keybindings"`
	// Add other configuration sections here later (e.g., colors, default_interval)
}

// DefaultKeybindings provides the default key mapping. All values are distinct.
func DefaultKeybindings() Keybindings {
	return Keybindings{
		Quit:          "ctrl+c",
		NewTab:        "n",
		CloseTab:      "x",
		NextTab:       "right",
		PrevTab:       "left",
		Back:          "q",
		Confirm:       "enter",
		WatchToggle:   "w",
		Export:        "ctrl+x",
		ExportAll:     "ctrl+e",
		Copy:          "y",
		Server:        "s",
		ZoneDiff:      "D",
		ToggleMatches: "a",
	}
}

// validateKeybindings reports empty and duplicate keybindings.
func validateKeybindings(k Keybindings) error {
	_, err := keybindingProblems(&k)
	return err
}

// keybindingProblems returns the yaml names of all empty or conflicting fields and
// an error describing them (nil if there are none).
func keybindingProblems(k *Keybindings) (map[string]bool, error) {
	bad := make(map[string]bool)
	var problems []string
	byKey := make(map[string][]string)
	var order []string
	for _, f := range k.fields() {
		v := strings.TrimSpace(*f.val)
		if v == "" {
			bad[f.name] = true
			problems = append(problems, fmt.Sprintf("%s is empty", f.name))
			continue
		}
		if _, seen := byKey[v]; !seen {
			order = append(order, v)
		}
		byKey[v] = append(byKey[v], f.name)
	}
	for _, v := range order {
		names := byKey[v]
		if len(names) > 1 {
			for _, n := range names {
				bad[n] = true
			}
			problems = append(problems, fmt.Sprintf("key %q is bound to multiple actions: %s", v, strings.Join(names, ", ")))
		}
	}
	if len(problems) == 0 {
		return nil, nil
	}
	return bad, fmt.Errorf("invalid keybindings: %s", strings.Join(problems, "; "))
}

// sanitizeKeybindings validates k. If it is invalid, each empty or conflicting
// binding that differs from its default is reset to the default; if that still
// leaves conflicts, all defaults are used. It returns the usable bindings and the
// original validation error (nil when k was valid).
func sanitizeKeybindings(k Keybindings) (Keybindings, error) {
	for _, f := range k.fields() {
		*f.val = strings.TrimSpace(*f.val)
	}
	bad, err := keybindingProblems(&k)
	if err == nil {
		return k, nil
	}
	defaults := DefaultKeybindings()
	defFields := defaults.fields()
	fixed := k
	for i, f := range fixed.fields() {
		if bad[f.name] && *f.val != *defFields[i].val {
			*f.val = *defFields[i].val
		}
	}
	if validateKeybindings(fixed) == nil {
		return fixed, err
	}
	return defaults, err
}

// DefaultConfig returns the default application configuration.
func DefaultConfig() AppConfig {
	return AppConfig{
		Keybindings: DefaultKeybindings(),
	}
}

// getConfigPath determines the path for the configuration file.
// Uses ~/.config/dlookup/config.yaml on Linux and macOS.
func getConfigPath() (string, error) {
	var configDir string
	var err error

	if runtime.GOOS == "darwin" { // Check if OS is macOS
		// Force ~/.config path on macOS
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("could not get user home directory: %w", err)
		}
		configDir = filepath.Join(homeDir, ".config")
	} else {
		// Use standard user config dir for other OSes (Linux, Windows)
		configDir, err = os.UserConfigDir()
		if err != nil {
			return "", fmt.Errorf("could not get user config directory: %w", err)
		}
	}

	appConfigDir := filepath.Join(configDir, "dlookup")
	return filepath.Join(appConfigDir, "config.yaml"), nil
}

// loadConfig loads the application configuration from the YAML file.
// If the file doesn't exist, it creates it with default values.
func loadConfig() (AppConfig, error) {
	configPath, err := getConfigPath()
	if err != nil {
		return AppConfig{}, err
	}

	config := DefaultConfig()

	// Check if the config file exists
	if _, err := os.Stat(configPath); err == nil {
		// File exists, try to read and parse it
		data, err := os.ReadFile(configPath)
		if err != nil {
			return config, fmt.Errorf("error reading config file %s: %w", configPath, err)
		}

		err = yaml.Unmarshal(data, &config)
		if err != nil {
			// If parsing fails, maybe log a warning and return defaults?
			// Or return the error and let main handle it.
			return config, fmt.Errorf("error parsing config file %s: %w", configPath, err)
		}
		fixed, verr := sanitizeKeybindings(config.Keybindings)
		config.Keybindings = fixed
		if verr != nil {
			// Persist the fix so configs written by older versions (where
			// close_tab and watch_toggle were both "w") only warn once.
			if serr := saveConfig(config); serr != nil {
				fmt.Fprintf(os.Stderr, "Warning: config %s: %v\nConflicting/empty keybindings were reset to defaults; please fix the config file.\n", configPath, verr)
			} else {
				fmt.Fprintf(os.Stderr, "Warning: config %s: %v\nConflicting/empty keybindings were reset to defaults and the file was updated.\n", configPath, verr)
			}
		}
	} else if os.IsNotExist(err) {
		// File does not exist, create it with defaults
		fmt.Printf("Config file not found at %s. Creating with defaults.\n", configPath)
		err = saveConfig(config)
		if err != nil {
			// Log error but proceed with defaults
			fmt.Fprintf(os.Stderr, "Warning: Could not save default config file: %v\n", err)
		}
	} else {
		// Other error checking file (permissions?)
		return config, fmt.Errorf("error checking config file %s: %w", configPath, err)
	}

	return config, nil
}

// saveConfig saves the given configuration to the default config file path.
func saveConfig(config AppConfig) error {
	configPath, err := getConfigPath()
	if err != nil {
		return err
	}

	// Ensure the directory exists
	configDir := filepath.Dir(configPath)
	if err := os.MkdirAll(configDir, 0750); err != nil {
		return fmt.Errorf("could not create config directory %s: %w", configDir, err)
	}

	// Marshal the config back to YAML
	data, err := yaml.Marshal(&config)
	if err != nil {
		return fmt.Errorf("error marshalling config: %w", err)
	}

	// Write the file
	if err := os.WriteFile(configPath, data, 0640); err != nil {
		return fmt.Errorf("error writing config file %s: %w", configPath, err)
	}

	return nil
}
