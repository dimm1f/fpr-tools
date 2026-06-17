mod audit_reader;
mod filter_template_reader;
mod fpr_report;
mod fvdl_reader;
mod list_filter;
mod render;
mod section_index;
mod src_archive_reader;

use std::{fs::File, path::PathBuf};

use clap::{Parser, Subcommand};
use list_filter::{GroupByField, ListOptions, SeverityExpr, SortField, StatusFilter};
use zip::ZipArchive;

#[derive(Parser)]
struct Args {
    /// Path to FPR file
    fpr_path: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Print scan metadata: project, build, engine version, rule packs, issue count
    Info,
    /// Print issue counts by audit status, with optional per-tag breakdown
    Statistics {
        #[arg(long, default_value_t = false)]
        tags: bool,
    },
    /// List vulnerabilities with optional filtering and grouping
    List(ListArgs),
    /// Show full details for one vulnerability by instance ID (or unambiguous prefix)
    Show {
        #[arg(num_args = 1..)]
        instance_ids: Vec<String>,
        /// Enable all optional output sections
        #[arg(long, default_value_t = false)]
        all: bool,
        /// Print rule description and explanation
        #[arg(long, default_value_t = false)]
        explain: bool,
        /// Print source code snippet around the primary location
        #[arg(long, default_value_t = false)]
        code: bool,
        /// Print tags and their values for the vulnerability
        #[arg(long, default_value_t = false)]
        tags: bool,
        /// Print audit comments for the vulnerability
        #[arg(long, default_value_t = false)]
        comments: bool,
        /// Print audit trail (tag changes, suppression, removal history)
        #[arg(long, default_value_t = false)]
        history: bool,
    },
}

#[derive(clap::Args)]
struct ListArgs {
    /// Filter by audit status [possible values: all, unaudited, audited, suppressed, removed]
    #[arg(long, value_name = "STATUS", default_value = "all")]
    status: StatusFilter,
    /// Filter by severity expression, e.g. >=3.0, >4, =5.0
    #[arg(long, value_name = "EXPR")]
    severity: Option<SeverityExpr>,
    /// Filter by rule type/subtype (substring, case-insensitive)
    #[arg(long, value_name = "PATTERN")]
    rule: Option<String>,
    /// Filter by primary file path (substring, case-insensitive)
    #[arg(long, value_name = "PATTERN")]
    file: Option<String>,
    /// Group output by field [possible values: rule, kingdom, file, status]
    #[arg(long, value_name = "FIELD")]
    group_by: Option<GroupByField>,
    /// Sort by field (default: severity descending)
    #[arg(long, value_name = "FIELD")]
    sort: Option<SortField>,
    /// Maximum number of results to show
    #[arg(long, value_name = "N")]
    limit: Option<usize>,
}

impl From<ListArgs> for ListOptions {
    fn from(a: ListArgs) -> Self {
        Self {
            status: a.status,
            severity: a.severity,
            rule: a.rule,
            file: a.file,
            group_by: a.group_by,
            sort: a.sort,
            limit: a.limit,
        }
    }
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let fpr = File::open(args.fpr_path)?;
    let mut fpr = ZipArchive::new(fpr)?;

    match args.command {
        Command::Info => render::print_fpr_info(&mut fpr),
        Command::Statistics { tags: show_tags } => render::print_statistics(&mut fpr, show_tags),
        Command::List(args) => render::print_list(&mut fpr, args.into()),
        Command::Show {
            instance_ids,
            all,
            explain,
            code: show_code,
            tags: show_tags,
            comments: show_comments,
            history: show_history,
        } => render::print_show(
            &mut fpr,
            &instance_ids,
            all || explain,
            all || show_code,
            all || show_tags,
            all || show_comments,
            all || show_history,
        ),
    }
}
