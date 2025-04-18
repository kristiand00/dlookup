package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

// Keybindings defines the configurable key actions.
type Keybindings struct {
	Quit        string `yaml:"quit"`
	NewTab      string `yaml:"new_tab"`
	CloseTab    string `yaml:"close_tab"`
	NextTab     string `yaml:"next_tab"`
	PrevTab     string `yaml:"prev_tab"`
	Back        string `yaml:"back"`         // Esc key in most contexts
	Confirm     string `yaml:"confirm"`      // Enter key in most contexts
	WatchToggle string `yaml:"watch_toggle"` // Key to toggle watch mode input
	// Potentially add keys for list navigation, viewport scrolling if needed
}

// AppConfig holds the application configuration.
type AppConfig struct {
	Keybindings Keybindings `yaml:"keybindings"`
	// Add other configuration sections here later (e.g., colors, default_interval)
}

// DefaultKeybindings provides the default key mapping.
// Includes macOS-friendly alternatives for tab switching.
func DefaultKeybindings() Keybindings {
	return Keybindings{
		Quit:        "c",     // Changed from ctrl+c
		NewTab:      "n",     // Changed from ctrl+n
		CloseTab:    "w",     // Changed from ctrl+w
		NextTab:     "right", // Changed from alt+l
		PrevTab:     "left",  // Changed from alt+h
		Back:        "q",     // Changed from esc
		Confirm:     "enter", // Unchanged
		WatchToggle: "w",     // Unchanged
	}
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
		// TODO: Optionally validate loaded config values?
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
