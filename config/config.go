package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"ttail/app"
)

// Config holds default values for ttail flags. Only options that make sense as
// persistent defaults are stored here; one-shot options (e.g. --bytes, --lines-from,
// --full, --head, --retry) are not in config and use flag defaults only.
type Config struct {
	// NumLines is the default number of initial lines to load (last N, or first N with head).
	// Used as default for -n / --num-lines. Example: 10 or 100.
	NumLines int `json:"num_lines"`

	// MaxLines is the maximum number of lines to keep in memory while tailing.
	// Used as default for --max-lines. Prevents unbounded growth when following.
	MaxLines int `json:"max_lines"`

	// RulesFile is the path to a JSON file of matching rules to load at startup.
	// Used as default for --rules-file. Leave empty to start with no rules.
	RulesFile string `json:"rules_file"`

	// ColourFile is the path to the JSON colour-rule file for highlighting.
	// Used as default for --colour-file. Leave empty for no colour rules.
	ColourFile string `json:"colour_file"`

	// LogFile is the path (file or directory) where ttail writes its own logs.
	// Used as default for --log-file. Leave empty to disable app logging.
	LogFile string `json:"log_file"`

	// Follow, when true, makes ttail follow the file by default (like tail -f).
	// Used as default for -f / --follow. Can be overridden per run.
	Follow bool `json:"follow"`

	// FollowName, when true, makes ttail follow by name (reopen on rotate, like tail -F).
	// Used as default for -F / --follow-name. Implies follow when set.
	FollowName bool `json:"follow_name"`

	// Rollover controls wrap when scrolling past first/last line: "start" (up at first -> end),
	// "end" (down at last -> start), "both", or "none". Default "both".
	Rollover string `json:"rollover"`

	// SearchCase, when true, makes search case-sensitive. When false (default), search is case-insensitive.
	SearchCase bool `json:"searchcase"`
}

// Default returns a config with all default values.
func Default() Config {
	return Config{
		NumLines:   app.DefaultInitialLines,
		MaxLines:   app.DefaultMaxLines,
		RulesFile:  "",
		ColourFile: "",
		LogFile:    "",
		Follow:     false,
		FollowName: false,
		Rollover:   "both",
		SearchCase: false,
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
