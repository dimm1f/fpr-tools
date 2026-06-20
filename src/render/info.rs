use std::{
    fs::File,
    io::{BufRead, BufReader},
};

use zip::ZipArchive;

use crate::{audit_reader::Audit, fvdl_reader::Fvdl};

pub fn text(fpr: &mut ZipArchive<File>) -> anyhow::Result<()> {
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

pub fn json(fpr: &mut ZipArchive<File>) -> anyhow::Result<()> {
    let mut version = String::new();
    BufReader::new(fpr.by_name("VERSION")?).read_line(&mut version)?;

    let fvdl = Fvdl::from_zip_entry(fpr.by_name("audit.fvdl")?)?;
    let meta = fvdl.meta()?;

    let scan_date = meta
        .created_ts
        .as_ref()
        .and_then(|ts| match (&ts.date, &ts.time) {
            (Some(d), Some(t)) => Some(format!("{} {}", d, t)),
            (Some(d), None) => Some(d.clone()),
            _ => None,
        });

    let (
        project,
        project_version,
        build_label,
        build_id,
        source_root,
        files_scanned,
        build_duration,
        scan_time,
        total_loc,
    ) = meta
        .build
        .as_ref()
        .map(|b| {
            let loc: i32 = b.loc_list.iter().filter_map(|l| l.count).sum();
            (
                b.project_name.clone(),
                b.version.clone(),
                b.label.clone(),
                b.id.clone(),
                b.base_path.clone(),
                b.number_files,
                b.build_duration,
                b.scan_time,
                if loc > 0 { Some(loc) } else { None },
            )
        })
        .unwrap_or_default();

    let (engine_version, hostname, platform, username, rule_packs, scan_errors, inactive) =
        if let Some(engine) = fvdl.engine_data()? {
            let rule_packs: Vec<_> = engine
                .rule_packs
                .as_ref()
                .map(|rps| {
                    rps.rule_packs
                        .iter()
                        .map(|rp| serde_json::json!({ "name": rp.name, "version": rp.version }))
                        .collect()
                })
                .unwrap_or_default();
            let inactive: i64 = engine.inactive_results.iter().filter_map(|g| g.count).sum();
            let mi = engine.machine_info.as_ref();

            (
                engine.engine_version,
                mi.and_then(|m| m.hostname.clone()),
                mi.and_then(|m| m.platform.clone()),
                mi.and_then(|m| m.username.clone()),
                rule_packs,
                engine.errors.len(),
                inactive,
            )
        } else {
            (None, None, None, None, vec![], 0, 0)
        };

    let issue_count = fvdl.vulnerabilities()?.len();

    let (audit_project, audit_project_version, audit_written) =
        if let Some(index) = fpr.index_for_name("audit.xml") {
            let audit = Audit::from_zip_entry(fpr.by_index(index)?)?;
            let pi = audit.project_info;
            (pi.name, pi.project_version_name, pi.write_date)
        } else {
            (None, None, None)
        };

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "fpr_version": version.trim_end(),
            "fvdl_version": meta.version,
            "uuid": meta.uuid,
            "scan_date": scan_date,
            "project": project,
            "project_version": project_version,
            "build_label": build_label,
            "build_id": build_id,
            "source_root": source_root,
            "files_scanned": files_scanned,
            "build_duration": build_duration,
            "scan_time": scan_time,
            "total_loc": total_loc,
            "engine_version": engine_version,
            "hostname": hostname,
            "platform": platform,
            "username": username,
            "rule_packs": rule_packs,
            "scan_errors": scan_errors,
            "inactive_results": inactive,
            "issue_count": issue_count,
            "audit_project": audit_project,
            "audit_project_version": audit_project_version,
            "audit_written": audit_written,
        }))?
    );
    Ok(())
}
