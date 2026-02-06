# ttail

A TUI for viewing and filtering log files using matching rules.

## Features

- View files with optional follow (tail) mode; use -F to follow by name (reopen on log rotation)
- Filter lines with regex-based matching rules
- Colour rules via JSON config (e.g. highlight ERROR, WARN, INFO)
- Search, navigate, and save filtered content
- Configurable initial line count and max lines in memory
- Optional “full” mode to navigate the whole file without loading everything into memory
- Optional “head” mode to show the first N lines instead of the last

## Build

```bash
go build -o ttail .
```

## Configuration

Default values for all flags are read from a JSON config file. If the file does not exist, it is created on first run with built-in defaults and a message is printed to stderr:

```text
Default config generated in /home/you/.config/ttail/ttail.json
```

### Config file location

| OS      | Path |
|---------|------|
| Linux   | `$XDG_CONFIG_HOME/ttail/ttail.json` or `~/.config/ttail/ttail.json` |
| Windows | `%APPDATA%\ttail\ttail.json` |
| macOS   | `~/Library/Application Support/ttail/ttail.json` |

Only options that make sense as persistent defaults are stored in config. One-shot options (per run) are not in config and use flag defaults only: `--bytes` / `-c`, `-n +N` (from line N), `--full`, `--head`, `--retry`.

**Example `ttail.json`**

```json
{
  "num_lines": 10,
  "max_lines": 1000,
  "rules_file": "",
  "colour_file": "",
  "log_file": "",
  "follow": false,
  "follow_name": false
}
```

Command-line flags override config file values.

With `--follow` / `-f` the file is followed by descriptor (like GNU `tail -f`). With `--follow-name` / `-F` the file is followed by name (like GNU `tail -F`): if the file is replaced (e.g. by log rotation), ttail reopens it and continues following the same path. Passing `-F` implies `-f`. The defaults shown in the Flags table below are the built-in defaults when no config file exists.

### Colour rule file (`--colour-file`)

The colour file is a JSON file that defines how to highlight parts of each line in the viewer. Pass its path via the main config (`colour_file`) or the `--colour-file` flag.

The file must contain a top-level array **`color_rules`**. Each element is an object with:

| Field      | Meaning |
|------------|--------|
| `pattern`  | Regular expression. Every match in the line is highlighted with the rule’s color. |
| `color`    | tview color tag applied to matches, e.g. `[red]`, `[green]`, `[yellow]`, `[blue]`. Use `[-]` to reset (normally added automatically after each match). |
| `label`   | Short description of the rule (for reference). |
| `rule_id`  | Unique identifier for the rule (for reference). |

Rules are applied in order. Each match is wrapped with the rule’s `color` and a reset, so overlapping patterns will show the colour of the rule that is applied last.

#### Example colour rule file

```json
{
  "color_rules": [
    { "pattern": "ERROR", "color": "[red]", "label": "Error Messages", "rule_id": "error-matcher" },
    { "pattern": "WARN", "color": "[yellow]", "label": "Warning Messages", "rule_id": "warn-matcher" },
    { "pattern": "INFO", "color": "[green]", "label": "Info Messages", "rule_id": "info-matcher" },
    { "pattern": "DEBUG", "color": "[blue]", "label": "Debug Messages", "rule_id": "debug-matcher" }
  ]
}
```

Here, any occurrence of `ERROR`, `WARN`, `INFO`, or `DEBUG` in a line is highlighted in the corresponding colour. You can use full regular expressions in `pattern`, e.g. `\d{4}-\d{2}-\d{2}` to colour ISO dates. A full example is included as `colour_rule_example.json`.

## Usage

```text
ttail [FILE] [flags]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `FILE`   | Log file to view (required) |

### Flags

Flags that match GNU tail have a short form in parentheses.

| Flag            | Short | Description |
|-----------------|-------|-------------|
| `--num-lines`   | `-n`  | Lines: `N` = last N lines, `+N` = from line N to end (same as GNU tail -n; default: 10) |
| `--max-lines`   |       | Maximum number of lines to keep in memory (default: 1000) |
| `--bytes`       | `-c`  | Bytes: `N` = last N bytes, `+N` = from byte N to end (same as GNU tail -c) |
| `--rules-file`  |       | JSON file with matching rules to load at startup |
| `--colour-file` |       | JSON file for color rules and settings |
| `--full`        |       | Load and navigate the full file without loading all lines into memory |
| `--head`        |       | Show the first N lines instead of the last N |
| `--log-file`    |       | Path or directory for application logs |
| `--follow`      | `-f`  | Follow (tail) the file and show new lines as they are written (default: off) |
| `--follow-name` | `-F`  | Follow by name: reopen when the file is replaced (e.g. log rotate); implies `-f` |
| `--retry`       |       | Keep trying to open the file when it is unavailable (e.g. not yet created) |
| `--help`        |       | Show help |
| `--version`     |       | Show version |

### Examples

```bash
ttail /var/log/app.log
ttail /var/log/app.log -n 100 --colour-file colour_rule_example.json
ttail /var/log/app.log -n +100                  # from line 100 to end (like GNU tail -n +100)
ttail /var/log/app.log -c 1024                  # last 1024 bytes
ttail /var/log/app.log -c +100                  # from byte 100 to end
ttail /var/log/app.log --rules-file rules.json --full
```

## License

See [LICENSE](LICENSE).
