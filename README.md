# ttail

A TUI for viewing and filtering log files using matching rules.

## Features

- View **one or more** files side by side (each file gets a header and line list; **Tab** moves focus between files and the rules pane)
- Optional follow (tail) mode; use **-F** to follow by name (reopen on log rotation)
- Filter lines with regex-based **matching rules**
- **Colour rules** via JSON config (e.g. highlight ERROR, WARN, INFO)
- **Search** (`/`), **navigate**, **reload** (`r`), and **save** filtered content
- **Load older lines** from the file without a full reload: extend the initial “last N lines” window toward the start of the file (see [Load older lines](#load-older-lines))
- Configurable initial line count (`-n`), max lines in memory (`--max-lines`), **rollover** at list edges, and default **search case sensitivity** (see [Configuration](#configuration))
- Optional **full** mode to navigate the whole file without loading everything into memory
- Optional **head** mode to show the first N lines instead of the last

## Build

```bash
go build -o ttail .
```

## Configuration

Default values for many flags are read from a JSON config file. If the file does not exist, it is created on first run with built-in defaults and a message is printed to stderr:

```text
Default config generated in /home/you/.config/ttail/ttail.json
```

### Config file location

| OS      | Path |
|---------|------|
| Linux   | `$XDG_CONFIG_HOME/ttail/ttail.json` or `~/.config/ttail/ttail.json` |
| Windows | `%APPDATA%\ttail\ttail.json` |
| macOS   | `~/Library/Application Support/ttail/ttail.json` |

Only options that make sense as persistent defaults are stored in config. One-shot options (per run) are not in config and use flag defaults only: `--bytes` / `-c`, `-n +N` (from line N), `--full`, `--head`, `--retry`, `--zero-terminated` / `-z`.

**Example `ttail.json`**

```json
{
  "num_lines": 10,
  "max_lines": 1000,
  "rules_file": "",
  "colour_file": "",
  "log_file": "",
  "follow": false,
  "follow_name": false,
  "rollover": "both",
  "searchcase": false
}
```

| Field | Meaning |
|-------|---------|
| `num_lines` | Default for `-n` / `--num-lines` (last N lines, or first N with `--head`) |
| `max_lines` | Default for `--max-lines` (cap on lines kept in memory) |
| `rules_file` | Default path for `--rules-file` |
| `colour_file` | Default path for `--colour-file` |
| `log_file` | Default for `--log-file` |
| `follow` | Default for `-f` / `--follow` |
| `follow_name` | Default for `-F` / `--follow-name` |
| `rollover` | Default list wrap: `"none"`, `"start"`, `"end"`, or `"both"` (wrap at top, bottom, or both) |
| `searchcase` | Default: if `true`, search is case-sensitive; if `false`, case-insensitive |

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
ttail [FILE]... [flags]
```

### Arguments

| Argument | Description |
|----------|-------------|
| `FILE`…  | One or more paths to view (required). Each file is shown in its own pane with a path header and scrollable line list. |

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
| `--retry`           |       | Keep trying to open the file when it is unavailable (e.g. not yet created) |
| `--pid`             |       | With `-f`, exit when the process with the given PID dies (GNU tail --pid; Unix) |
| `--sleep-interval`  |       | With `-f`, poll file every N seconds (e.g. network FS); 0 = default (GNU tail -s) |
| `--zero-terminated` | `-z`  | Input is NUL-delimited (GNU tail -z) |
| `--help`            |       | Show help |
| `--version`         |       | Show version |

### Keyboard shortcuts (TUI)

Press **`h`** or **`?`** in the app for the in-TUI help popup. Summary:

**Global**

| Key | Action |
|-----|--------|
| `q` | Quit |
| `h`, `?` | Help |
| `Tab` / `Shift+Tab` | Cycle focus between file list(s) and the rules pane |
| `r` | Reload output from disk (same scope as startup; not while following `-f` or in `--full`) |
| `o` | Cycle rollover mode (how the line list wraps at the first/last line) |

**Messages / file view** (when focus is on a file’s line list)

| Key | Action |
|-----|--------|
| `↑` / `↓` | Move selection |
| `Enter`, `v` | View full selected line |
| `f` | Toggle follow mode (`-f`) |
| `/` | Open search |
| `n` | Jump to next search match |
| `c` | Toggle search case sensitivity (when not in the rules pane for rule-specific `c`) |
| `l` | Load **10** more **older** lines from the file (see [Load older lines](#load-older-lines)) |
| `L` | Prompt for how many older lines to load |

**Rules pane**

| Key | Action |
|-----|--------|
| `d` | Delete selected rule |
| `c` | Toggle case sensitivity for the selected rule |
| `p` | Toggle partial match for the selected rule |
| `a` | Add matching rule (popup) |
| `s` | Save (export) |

**Popups** (search, add rule, load-older amount, help, view line)

| Key | Action |
|-----|--------|
| `Enter` | Confirm |
| `Esc` | Close |

### Load older lines

In the default **last N lines** mode (not `--head`, not `-c`, not `-n +N`, not `--full`), you can extend the window backward toward the start of the file:

- **`l`** — append **10** older lines at the **top** of the buffer; the selection stays on the **same logical line** (the view shifts).
- **`L`** — open a popup to type a positive number of extra older lines, then **Enter** to apply.

**When it is unavailable:** `--full`, **follow** (`-f`), `--head`, **byte mode** (`-c`), or **from-line mode** (`-n +N`). In those cases the app shows a short status message instead.

**Limit:** The total number of lines cannot exceed **`--max-lines`**. If you are already at the cap, you will see a message to that effect.

**Multiple files:** Load-older applies to the **focused** file pane (use **Tab** to switch).

## Examples

```bash
ttail /var/log/app.log
ttail /var/log/a.log /var/log/b.log              # two files side by side
ttail /var/log/app.log -n 100 --colour-file colour_rule_example.json
ttail /var/log/app.log -n +100                  # from line 100 to end (like GNU tail -n +100)
ttail /var/log/app.log -c 1024                  # last 1024 bytes
ttail /var/log/app.log -c +100                  # from byte 100 to end
ttail /var/log/app.log -f --pid 1234           # follow and exit when process 1234 dies
ttail /var/log/app.log -f --sleep-interval 2   # follow, poll every 2 seconds
ttail /var/log/app.log -z file.nul              # NUL-delimited input
ttail /var/log/app.log --rules-file rules.json --full
```

## License

See [LICENSE](LICENSE).
