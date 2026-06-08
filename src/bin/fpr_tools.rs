use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
};

use clap::{Parser, Subcommand};
use fpr_tools::{
    audit_reader::Audit,
    fpr_report::{AuditIssue, FprReport, VulnerabilityStatus},
    fvdl_reader::Fvdl,
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
    Info,
    Issues {
        #[arg(long, default_value_t = false)]
        show_tags: bool,
    },
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

fn print_issues(fpr: &mut ZipArchive<File>, show_tags: bool) -> anyhow::Result<()> {
    const ALIGN: usize = 16;

    let report = FprReport::from_zip(fpr)?;
    let entries = report.vulnerabilities()?;

    let mut audited: usize = 0;
    let mut unaudited: usize = 0;
    let mut suppressed: usize = 0;
    let mut removed: usize = 0;

    let mut tag_counts: std::collections::BTreeMap<(&str, String, String), usize> =
        std::collections::BTreeMap::new();

    for entry in &entries {
        let status_label = match &entry.status {
            VulnerabilityStatus::Unaudited => {
                unaudited += 1;
                continue;
            }
            VulnerabilityStatus::Suppressed { .. } => {
                suppressed += 1;
                "Suppressed"
            }
            VulnerabilityStatus::Audited {
                issue: AuditIssue::Removed(_),
            } => {
                removed += 1;
                "Removed"
            }
            VulnerabilityStatus::Audited { .. } => {
                audited += 1;
                "Audited"
            }
        };

        if show_tags
            && let VulnerabilityStatus::Audited { issue }
            | VulnerabilityStatus::Suppressed { issue } = &entry.status
        {
            for tag in issue.tags() {
                if let Some(value) = &tag.value {
                    let name = report.tag_names.resolve(&tag.id).to_owned();
                    *tag_counts
                        .entry((status_label, name, value.clone()))
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
        // +4 for the leading "    " on value lines, +1 for the space before the count.
        // Using this single value for both the status label and the value column keeps
        // all count numbers in the same column.
        let val_align = tag_counts
            .keys()
            .map(|(_, _, v)| v.len() + 5)
            .max()
            .filter(|&x| x > ALIGN)
            .unwrap_or(ALIGN);
        let value_width = val_align.saturating_sub(5);

        for (status_label, total) in counts {
            println!("{:<val_align$}{}", status_label, total);
            let mut current_tag: Option<&str> = None;
            for ((_, tag_name, value), count) in tag_counts
                .range((status_label, String::new(), String::new())..)
                .take_while(|((s, _, _), _)| *s == status_label)
            {
                if current_tag != Some(tag_name.as_str()) {
                    current_tag = Some(tag_name.as_str());
                    println!("  {}", tag_name);
                }
                println!("    {:<value_width$} {}", value, count);
            }
        }
    } else {
        for (status_label, total) in counts {
            println!("{:<ALIGN$}{}", status_label, total);
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
        Command::Issues { show_tags } => print_issues(&mut fpr, show_tags),
    }
}
