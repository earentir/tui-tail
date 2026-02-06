# TODO

Features and behaviour to align with or add compared to GNU tail.

## Behaviour change

- [x] **Switch to non-follow by default** – Do not follow (tail -f style) by default; only follow when a `--follow` flag is passed.

## Follow / rotation

- [x] **Follow by name** – Reopen the file when it is replaced (e.g. log rotate) so we keep following the same path (GNU `tail -F`). Ensure we don’t keep reading the old inode after rotation.
- [x] **Retry** – When the file doesn’t exist yet, keep trying to open it (GNU `--retry`) instead of failing immediately.

## Scope / units

- [x] **Byte-based tail** – Support last N bytes and “from byte N” (GNU `tail -c N` / `-c +N`).
- [x] **Start from line N** – Support “from line N to end” (GNU `tail -n +N`), i.e. skip first N−1 lines.

## Multiple inputs

- [x] **Multiple files** – Support tailing multiple files with clear separation. Each file has a single header line (path only, same line style as other panes), no bottom border per file. Tab cycles through file regions then rule input, rules, search. Layout: N regions (1 header + 3+ content lines per file); if terminal height &lt; N×4 + 7 lines, exit with error.

## Follow-related options

- [x] **--pid=PID** – With follow, exit when the process with the given PID dies (for scripting).
- [x] **--sleep-interval** – With follow, poll every N seconds when filesystem notifications aren’t available (e.g. network filesystems).

## Input format

- [x] **NUL-separated lines** – Support null-delimited “lines” (GNU `-z` / `--zero-terminated`).
