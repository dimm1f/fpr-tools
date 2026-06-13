# fpr-tools

A command-line tool for inspecting and querying **Fortify Project Report (FPR)** files — the output of Fortify Static Code Analysis (SCA) security scans. It lets you browse, filter, and read vulnerability data without the Fortify UI.

## Features

- View scan metadata and statistics
- List and filter vulnerabilities by status, severity, rule type, or file path
- Group and sort results
- Inspect individual issues with full trace and source code context
- Decode rule descriptions and explanations

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
```

#### `statistics`

Show issue counts by audit status (audited, unaudited, suppressed, removed).

```sh
fpr-tools report.fpr statistics
fpr-tools report.fpr statistics --tags   # also break down by tag
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
| `--limit <N>` | Limit output to N results |

Filters are AND-ed together.

**Examples:**

```sh
# Top 10 issues
fpr-tools report.fpr list --limit 10

# High-severity unaudited issues
fpr-tools report.fpr list --severity ">=4.0" --status unaudited

# SQL-related issues in Java files, grouped by rule
fpr-tools report.fpr list --rule "sql" --file ".java" --group-by rule
```

#### `show`

Show full details for a single vulnerability by Instance ID (or unambiguous prefix).

```sh
fpr-tools report.fpr show <INSTANCE_ID> [OPTIONS]
```

| Option | Description |
|---|---|
| `--explain` | Also print the rule description and explanation |
| `--code` | Print source code snippet from the FPR's src-archive |
| `--tags` | Print audit tags and their values |

Output includes: rule info, severity and confidence, primary source location, audit status, code trace, and optionally tags, rule explanation, and source snippet.

**Examples:**

```sh
fpr-tools report.fpr show 65AD6342C39D043E7705A45CE1066B36
fpr-tools report.fpr show 65AD63 --explain --code --tags   # prefix matching
```

## FPR File Format

An FPR file is a ZIP archive produced by Fortify SCA. It contains:

- `audit.fvdl` — vulnerability definitions and scan data (FVDL XML)
- `audit.xml` — audit decisions (statuses, tags, comments)
- `filtertemplate.xml` — tag name definitions
- `src-archive/` — source files referenced by the scan (needed for `--code`)
