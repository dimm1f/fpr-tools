use std::{
    fs::File,
    io::{BufRead, BufReader},
    path::PathBuf,
};

use fpr_tools::{audit_reader::Audit, fvdl_reader::Fvdl};
use zip::ZipArchive;
use clap::{Parser, Subcommand};

#[derive(Parser)]
struct Args {
    /// Path to FPR file
    fpr_path: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Show FPR statistics
    Info,
    /// Show found issues
    Issues,
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
            let pack_names: Vec<String> = rps.rule_packs.iter()
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

        let issues = &audit.issue_list.issues;
        let suppressed = issues.iter().filter(|i| i.suppressed.unwrap_or(false)).count();
        let hidden = issues.iter().filter(|i| i.hidden.unwrap_or(false)).count();
        println!("{:<ALIGN$}{}", "Issues:", issues.len());
        if suppressed > 0 {
            println!("{:<ALIGN$}{}", "  Suppressed:", suppressed);
        }
        if hidden > 0 {
            println!("{:<ALIGN$}{}", "  Hidden:", hidden);
        }
        let custom = &audit.issue_list.custom_issues;
        let custom_suppressed = custom.iter().filter(|i| i.suppressed.unwrap_or(false)).count();
        let custom_hidden = custom.iter().filter(|i| i.hidden.unwrap_or(false)).count();
        println!("{:<ALIGN$}{}", "Custom issues:", custom.len());
        if custom_suppressed > 0 {
            println!("{:<ALIGN$}{}", "  Suppressed:", custom_suppressed);
        }
        if custom_hidden > 0 {
            println!("{:<ALIGN$}{}", "  Hidden:", custom_hidden);
        }
        let removed = &audit.issue_list.removed_issues;
        let removed_suppressed = removed.iter().filter(|i| i.suppressed.unwrap_or(false)).count();
        let removed_hidden = removed.iter().filter(|i| i.hidden.unwrap_or(false)).count();
        println!("{:<ALIGN$}{}", "Removed issues:", removed.len());
        if removed_suppressed > 0 {
            println!("{:<ALIGN$}{}", "  Suppressed:", removed_suppressed);
        }
        if removed_hidden > 0 {
            println!("{:<ALIGN$}{}", "  Hidden:", removed_hidden);
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
        Command::Issues => todo!(),
    }
}
