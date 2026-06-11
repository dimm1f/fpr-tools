use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
};

use clap::{Parser, Subcommand};
use fpr_tools::{
    audit_reader::Audit,
    fpr_report::{FprReport, VulnerabilityStatus, primary_location},
    fvdl_reader::{Fvdl, decode_entities, strip_html},
    list_filter::{self, GroupByField, ListRow, SeverityExpr, SortField, StatusFilter},
};
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
        show_tags: bool,
    },
    /// List vulnerabilities with optional filtering and grouping
    List(ListOptions),
    /// Show full details for one vulnerability by instance ID (or unambiguous prefix)
    Show {
        instance_id: String,
        /// Print rule description and explanation
        #[arg(long, default_value_t = false)]
        explain: bool,
    },
}

#[derive(clap::Args)]
struct ListOptions {
    /// Filter by audit status
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
    /// Group output by field
    #[arg(long, value_name = "FIELD")]
    group_by: Option<GroupByField>,
    /// Sort by field (default: severity descending)
    #[arg(long, value_name = "FIELD")]
    sort: Option<SortField>,
    /// Maximum number of results to show
    #[arg(long, value_name = "N")]
    limit: Option<usize>,
}

fn print_fpr_info(fpr: &mut ZipArchive<File>) -> anyhow::Result<()> {
    const ALIGN: usize = 16;

    let mut version = String::new();
    BufReader::new(fpr.by_name("VERSION")?).read_line(&mut version)?;
    println!("{:<ALIGN$}{}", "FPR version:", version.trim_end());

    let fvdl = Fvdl::from_zip_entry(fpr.by_name("audit.fvdl")?)?;
    let meta = fvdl.meta()?;

    println!("{:<ALIGN$}{}", "FVDL version:", meta.version);
    println!("{:<ALIGN$}{}", "UUID:", meta.uuid);

    if let Some(ts) = &meta.created_ts {
        match (&ts.date, &ts.time) {
            (Some(d), Some(t)) => println!("{:<ALIGN$}{} {}", "Scan date:", d, t),
            (Some(d), None) => println!("{:<ALIGN$}{}", "Scan date:", d),
            _ => {}
        }
    }

    if let Some(build) = &meta.build {
        if let Some(name) = &build.project_name {
            print!("{:<ALIGN$}{}", "Project:", name);
            if let Some(v) = &build.version {
                print!(" ({})", v);
            }
            println!();
        }
        if let Some(label) = &build.label {
            println!("{:<ALIGN$}{}", "Build label:", label);
        }
        if let Some(id) = &build.id {
            println!("{:<ALIGN$}{}", "Build ID:", id);
        }
        if let Some(path) = &build.base_path {
            println!("{:<ALIGN$}{}", "Source root:", path);
        }
        if let Some(n) = build.number_files {
            println!("{:<ALIGN$}{}", "Files scanned:", n);
        }
        if let Some(duration) = build.build_duration {
            println!("{:<ALIGN$}{}s", "Build duration:", duration);
        }
        if let Some(epoch) = build.scan_time {
            println!("{:<ALIGN$}{}s (epoch)", "Scan time:", epoch);
        }
        let total_loc: i32 = build.loc_list.iter().filter_map(|l| l.count).sum();
        if total_loc > 0 {
            println!("{:<ALIGN$}{}", "Total LOC:", total_loc);
        }
    }

    if let Some(engine) = fvdl.engine_data()? {
        if let Some(ev) = &engine.engine_version {
            println!("{:<ALIGN$}{}", "Engine version:", ev);
        }
        if let Some(mi) = &engine.machine_info {
            if let Some(h) = &mi.hostname {
                print!("{:<ALIGN$}{}", "Scanned on:", h);
                if let Some(p) = &mi.platform {
                    print!(" ({})", p);
                }
                println!();
            }
            if let Some(u) = &mi.username {
                println!("{:<ALIGN$}{}", "Scanned by:", u);
            }
        }
        if let Some(rps) = &engine.rule_packs {
            let pack_names: Vec<String> = rps
                .rule_packs
                .iter()
                .map(|rp| {
                    let name = rp.name.as_deref().unwrap_or("<unnamed>");
                    let ver = rp.version.as_deref().unwrap_or("?");
                    format!("{} v{}", name, ver)
                })
                .collect();
            if !pack_names.is_empty() {
                println!("{:<ALIGN$}{}", "Rule packs:", pack_names.join("\n  "));
            }
        }
        if !engine.errors.is_empty() {
            println!("{:<ALIGN$}{}", "Scan errors:", engine.errors.len());
        }
        let inactive: i64 = engine.inactive_results.iter().filter_map(|g| g.count).sum();
        if inactive > 0 {
            println!("{:<ALIGN$}{}", "Inactive:", inactive);
        }
    }

    let vulns = fvdl.vulnerabilities()?;
    println!("{:<ALIGN$}{}", "Issues in FVDL:", vulns.len());

    if let Some(index) = fpr.index_for_name("audit.xml") {
        let audit = Audit::from_zip_entry(fpr.by_index(index)?)?;

        let pi = &audit.project_info;
        if let Some(name) = &pi.name {
            print!("{:<ALIGN$}{}", "Audit project:", name);
            if let Some(v) = &pi.project_version_name {
                print!(" ({})", v);
            }
            println!();
        }
        if let Some(wd) = &pi.write_date {
            println!("{:<ALIGN$}{}", "Audit written:", wd);
        }
    }

    Ok(())
}

fn print_statistics(fpr: &mut ZipArchive<File>, show_tags: bool) -> anyhow::Result<()> {
    const ALIGN: usize = 16;

    let report = FprReport::from_zip(fpr)?;
    let entries = report.vulnerabilities()?;

    let mut audited: usize = 0;
    let mut unaudited: usize = 0;
    let mut suppressed: usize = 0;
    let mut removed: usize = 0;

    let mut tag_counts: BTreeMap<(&str, String, String), usize> = BTreeMap::new();

    for entry in &entries {
        let status_lbl = match &entry.status {
            VulnerabilityStatus::Unaudited => {
                unaudited += 1;
                continue;
            }
            s @ VulnerabilityStatus::Suppressed { .. } => {
                suppressed += 1;
                s.as_str()
            }
            s @ VulnerabilityStatus::Removed { .. } => {
                removed += 1;
                s.as_str()
            }
            s @ VulnerabilityStatus::Audited { .. } => {
                audited += 1;
                s.as_str()
            }
        };

        if show_tags {
            for tag in entry.status.tags() {
                if let Some(value) = &tag.value {
                    let name = report.tag_names.resolve(&tag.id).to_owned();
                    *tag_counts
                        .entry((status_lbl, name, value.clone()))
                        .or_default() += 1;
                }
            }
        }
    }

    let counts = [
        ("Audited", audited),
        ("Unaudited", unaudited),
        ("Suppressed", suppressed),
        ("Removed", removed),
    ];

    if show_tags {
        let val_align = tag_counts
            .keys()
            .map(|(_, _, v)| v.len() + 5)
            .max()
            .filter(|&x| x > ALIGN)
            .unwrap_or(ALIGN);
        let value_width = val_align.saturating_sub(5);

        for (status_lbl, total) in counts {
            println!("{:<val_align$}{}", status_lbl, total);
            let mut current_tag: Option<&str> = None;
            for ((_, tag_name, value), count) in tag_counts
                .range((status_lbl, String::new(), String::new())..)
                .take_while(|((s, _, _), _)| *s == status_lbl)
            {
                if current_tag != Some(tag_name.as_str()) {
                    current_tag = Some(tag_name.as_str());
                    println!("  {}", tag_name);
                }
                println!("    {:<value_width$} {}", value, count);
            }
        }
    } else {
        for (status_lbl, total) in counts {
            println!("{:<ALIGN$}{}", status_lbl, total);
        }
    }

    Ok(())
}

fn print_list(fpr: &mut ZipArchive<File>, opts: ListOptions) -> anyhow::Result<()> {
    let report = FprReport::from_zip(fpr)?;
    let entries = report.vulnerabilities()?;

    let rows = list_filter::apply(
        &entries,
        &opts.status,
        opts.severity.as_ref(),
        opts.rule.as_deref(),
        opts.file.as_deref(),
        opts.sort.as_ref(),
        opts.limit,
    );

    if rows.is_empty() {
        println!("No vulnerabilities match the given filters.");
        return Ok(());
    }

    fn print_entry(i: usize, row: &ListRow) {
        println!("# {} {}", i, row.status_label);
        println!("ID: {}", row.instance_id);
        println!("Type: {}", row.rule_type);
        println!("File: {}", row.file_loc);
    }

    if let Some(group_field) = opts.group_by {
        let group_key = |row: &ListRow| -> String {
            match group_field {
                GroupByField::Rule => row.rule_type.clone(),
                GroupByField::Kingdom => row.kingdom.clone(),
                GroupByField::File => row.file_loc.clone(),
                GroupByField::Status => row.status_label.to_owned(),
            }
        };

        let mut groups: BTreeMap<String, Vec<&ListRow>> = BTreeMap::new();
        for row in &rows {
            groups.entry(group_key(row)).or_default().push(row);
        }

        let mut i = 1usize;
        for (key, group_rows) in &groups {
            println!("Group: {} ({})", key, group_rows.len());
            for row in group_rows {
                println!();
                print_entry(i, row);
                i += 1;
            }
            println!();
        }
    } else {
        for (i, row) in rows.iter().enumerate() {
            if i > 0 {
                println!();
            }
            print_entry(i + 1, row);
        }
    }

    Ok(())
}

fn print_show(fpr: &mut ZipArchive<File>, instance_id: &str, explain: bool) -> anyhow::Result<()> {
    const ALIGN: usize = 20;

    let report = FprReport::from_zip(fpr)?;
    let descriptions = report.fvdl.descriptions()?;
    let entries = report.vulnerabilities()?;

    let matches: Vec<_> = entries
        .iter()
        .filter(|e| {
            e.vulnerability
                .instance
                .instance_id
                .starts_with(instance_id)
        })
        .collect();

    if matches.is_empty() {
        anyhow::bail!("No vulnerability found with ID prefix '{instance_id}'");
    }
    if matches.len() > 1 {
        eprintln!(
            "Ambiguous prefix '{instance_id}' matches {} vulnerabilities:",
            matches.len()
        );
        for e in &matches {
            eprintln!("  {}", e.vulnerability.instance.instance_id);
        }
        anyhow::bail!("Provide a longer prefix to disambiguate");
    }

    let entry = matches[0];
    let rule = &entry.vulnerability.rule;
    let inst = &entry.vulnerability.instance;
    let analysis = &entry.vulnerability.analysis;

    // Rule section
    println!("Rule");
    if let Some(k) = &rule.kind {
        println!("{:<ALIGN$}{}", "  Kingdom:", k);
    }
    if let Some(t) = &rule.typ {
        println!("{:<ALIGN$}{}", "  Type:", t);
    }
    if let Some(s) = &rule.subtyp {
        println!("{:<ALIGN$}{}", "  Subtype:", s);
    }
    println!("{:<ALIGN$}{}", "  Rule ID:", rule.rule_id);
    if let Some(sev) = rule.default_severity {
        println!("{:<ALIGN$}{:.1}", "  Default severity:", sev);
    }

    // Instance section
    println!();
    println!("Instance");
    println!("{:<ALIGN$}{}", "  Instance ID:", inst.instance_id);
    if let Some(sev) = inst.instance_severity {
        println!("{:<ALIGN$}{:.1}", "  Severity:", sev);
    }
    if let Some(conf) = inst.confidence {
        println!("{:<ALIGN$}{:.1}", "  Confidence:", conf);
    }
    if let Some(desc) = &inst.instance_description {
        println!("{:<ALIGN$}{}", "  Description:", desc);
    }

    // Primary location
    println!();
    println!("Primary Location");
    match primary_location(analysis) {
        Some((path, line)) => println!("  {}:{}", path, line),
        None => println!("  (none)"),
    }

    // Audit status
    println!();
    let label = entry.status.as_str();
    println!("Audit Status: {}", label);
    let mut resolved_tags = entry
        .status
        .tags()
        .iter()
        .filter_map(|t| {
            t.value
                .as_deref()
                .map(|v| (report.tag_names.resolve(&t.id), v))
        })
        .peekable();
    if resolved_tags.peek().is_some() {
        println!("  Tags:");
        for (name, value) in resolved_tags {
            println!("    {:<ALIGN$}{}", format!("{}:", name), value);
        }
    }

    // MetaInfo
    if !inst.meta_info.is_empty() {
        println!();
        println!("MetaInfo");
        for group in &inst.meta_info {
            if let Some(content) = &group.content {
                println!("  {:<ALIGN$}{}", format!("{}:", group.name), content);
            }
        }
    }

    // Trace
    if let Some(unified) = &analysis.unified
        && let Some(trace) = unified.traces.first()
    {
        let nodes: Vec<_> = trace
            .primary
            .iter()
            .filter_map(|e| {
                if let Some(node) = &e.node {
                    let loc = node.source_location.as_ref()?;
                    let path = loc.path.as_deref().unwrap_or("?");
                    let line = loc.line.unwrap_or(0);
                    let action = node
                        .action
                        .as_ref()
                        .and_then(|a| a.content.as_deref())
                        .unwrap_or("");
                    let action = action.trim();
                    Some(if action.is_empty() {
                        format!("{}:{}", path, line)
                    } else {
                        format!("{}:{} {}", path, line, action)
                    })
                } else {
                    Some("(pool ref)".to_owned())
                }
            })
            .collect();
        if !nodes.is_empty() {
            println!();
            println!("Trace ({} steps)", nodes.len());
            for (i, step) in nodes.iter().enumerate() {
                println!("  {}. {}", i + 1, step);
            }
        }
    }

    let defs = analysis
        .unified
        .as_ref()
        .and_then(|u| u.replacement_definitions.as_ref());

    if let Some(desc) = descriptions
        .iter()
        .find(|d| d.class_id.as_deref() == Some(&rule.rule_id))
    {
        let render = |text: &str| -> String {
            let substituted = defs
                .map(|d| d.apply(text))
                .unwrap_or_else(|| text.to_owned());
            decode_entities(&strip_html(&substituted))
        };
        if let Some(text) = &desc._abstract {
            println!();
            println!("Description");
            println!("{}", render(text).trim());
        }
        if explain && let Some(text) = &desc.explanation {
            println!();
            println!("Explanation");
            println!("{}", render(text).trim());
        }
    }

    Ok(())
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let fpr = File::open(args.fpr_path)?;
    let mut fpr = ZipArchive::new(fpr)?;

    match args.command {
        Command::Info => print_fpr_info(&mut fpr),
        Command::Statistics { show_tags } => print_statistics(&mut fpr, show_tags),
        Command::List(opts) => print_list(&mut fpr, opts),
        Command::Show {
            instance_id,
            explain,
        } => print_show(&mut fpr, &instance_id, explain),
    }
}
