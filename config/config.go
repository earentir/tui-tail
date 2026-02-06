package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"ttail/app"
)

// Config holds default values for ttail flags.
type Config struct {
	NumLines   int    `json:"num_lines"`
	MaxLines   int    `json:"max_lines"`
	RulesFile  string `json:"rules_file"`
	ColourFile string `json:"colour_file"`
	Full       bool   `json:"full"`
	Head       bool   `json:"head"`
	LogFile    string `json:"log_file"`
}

// Default returns a config with all default values.
func Default() Config {
	return Config{
		NumLines:   app.DefaultInitialLines,
		MaxLines:   app.DefaultMaxLines,
		RulesFile:  "",
		ColourFile: "",
		Full:       false,
		Head:       false,
		LogFile:    "",
	}
}

// Path returns the OS-appropriate config file path.
// Linux: $XDG_CONFIG_HOME/ttail/ttail.json or $HOME/.config/ttail/ttail.json
// Windows: %APPDATA%\ttail\ttail.json
// macOS: $HOME/Library/Application Support/ttail/ttail.json
func Path() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("user config dir: %w", err)
	}
	return filepath.Join(dir, "ttail", "ttail.json"), nil
}

// Load reads config from the default path. If the file does not exist,
// the directory and file are created with default values and those defaults are returned.
// The second return value is true when the config file was created (first run).
func Load() (Config, bool, error) {
	p, err := Path()
	if err != nil {
		return Config{}, false, err
	}

	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			cfg := Default()
			if writeErr := Save(cfg); writeErr != nil {
				return cfg, false, fmt.Errorf("creating default config: %w", writeErr)
			}
			return cfg, true, nil
		}
		return Config{}, false, fmt.Errorf("reading config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, false, fmt.Errorf("parsing config: %w", err)
	}
	return cfg, false, nil
}

// Save writes cfg to the default config path, creating the directory if needed.
func Save(cfg Config) error {
	p, err := Path()
	if err != nil {
		return err
	}

	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("creating config dir: %w", err)
	}

	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding config: %w", err)
	}

	if err := os.WriteFile(p, data, 0o600); err != nil {
		return fmt.Errorf("writing config: %w", err)
	}
	return nil
}
