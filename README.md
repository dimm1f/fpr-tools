# fpr-tools

A command-line tool for inspecting and querying **Fortify Project Report (FPR)** files — the output of Fortify Static Code Analysis (SCA) security scans. It lets you browse, filter, and read vulnerability data without the AWB.

## Features

- View scan metadata and statistics
- List and filter vulnerabilities by status, severity, rule type, or file path
- Group and sort results
- Inspect individual issues with full trace and source code context
- Decode rule descriptions and explanations
- JSON output for all commands

## Installation

Requires [Rust](https://rustup.rs/).

```sh
cargo build --release
# binary at: target/release/fpr-tools
```

## Usage

```
fpr-tools <FPR_PATH> <COMMAND> [OPTIONS]
```

### Commands

#### `info`

Print scan metadata: project name, scan date, engine version, files scanned, line count, rule packs, and more.

```sh
fpr-tools report.fpr info
fpr-tools report.fpr info --json
```

#### `statistics`

Show issue counts by audit status (audited, unaudited, suppressed, removed).

```sh
fpr-tools report.fpr statistics
fpr-tools report.fpr statistics --tags    # also break down by tag
fpr-tools report.fpr statistics --json   # always includes tag breakdown
```

#### `list`

List vulnerabilities with optional filtering, sorting, grouping, and limiting.

```sh
fpr-tools report.fpr list [OPTIONS]
```

| Option | Description |
|---|---|
| `--status <STATUS>` | Filter by audit status: `all` (default), `unaudited`, `audited`, `suppressed`, `removed` |
| `--severity <EXPR>` | Filter by severity, e.g. `>=4.0`, `>3`, `=5.0`, `<2`. A bare number implies `>=`. |
| `--rule <PATTERN>` | Case-insensitive substring match against Kingdom + Type + Subtype |
| `--file <PATTERN>` | Case-insensitive substring match against primary file path |
| `--group-by <FIELD>` | Group results by: `rule`, `kingdom`, `file`, `status` |
| `--sort <FIELD>` | Sort by: `severity` (default, descending), `rule`, `file`, `status` |
| `--limit <N>` | Return at most N results |
| `--offset <N>` | Skip the first N results (applied after filtering and sorting; entry numbers in output reflect the offset) |
| `--json` | Output as JSON array (minimal fields) |
| `--all-fields` | With `--json`: include all fields for each issue (trace, tags, comments, history, descriptions, source snippet) |

Filters are AND-ed together.

**Examples:**

```sh
# Top 10 issues
fpr-tools report.fpr list --limit 10

# Issues 11–20 (second page)
fpr-tools report.fpr list --offset 10 --limit 10

# High-severity unaudited issues
fpr-tools report.fpr list --severity ">=4.0" --status unaudited

# SQL-related issues in Java files, grouped by rule
fpr-tools report.fpr list --rule "sql" --file ".java" --group-by rule

# Minimal JSON output
fpr-tools report.fpr list --json

# Full detail JSON (same fields as show output)
fpr-tools report.fpr list --json --all-fields

# Full detail JSON for high-severity unaudited issues
fpr-tools report.fpr list --severity ">=4.0" --status unaudited --json --all-fields
```

#### `show`

Show full details for a single vulnerability by Instance ID (or unambiguous prefix).

```sh
fpr-tools report.fpr show <INSTANCE_ID> [OPTIONS]
```

| Option | Description |
|---|---|
| `--all` | Enable all optional output sections below |
| `--explain` | Also print the rule description and explanation |
| `--code` | Print source code snippet from the FPR's src-archive |
| `--tags` | Print audit tags and their values |
| `--comments` | Print audit comments (threaded comments from reviewers) |
| `--history` | Print audit trail (tag changes, suppression, removal history) |

Output includes: rule info, severity and confidence, primary source location, audit status, code trace, and optionally tags, comments, history, rule explanation, and source snippet.

**Examples:**

```sh
fpr-tools report.fpr show 65AD6342C39D043E7705A45CE1066B36
fpr-tools report.fpr show 65AD63 --all                                        # all optional sections
fpr-tools report.fpr show 65AD63 --explain --code --tags --comments --history # prefix matching
```
