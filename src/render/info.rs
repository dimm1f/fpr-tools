use std::{
    fs::File,
    io::{BufRead, BufReader},
};

use zip::ZipArchive;

use crate::{
    audit_reader::Audit as AuditDoc,
    fvdl_reader::{EngineData, Fvdl, FvdlMeta},
};

struct Loaded {
    fpr_version: String,
    meta: FvdlMeta,
    engine: Option<EngineData>,
    audit: Option<AuditDoc>,
    issue_count: usize,
}

fn load(fpr: &mut ZipArchive<File>) -> anyhow::Result<Loaded> {
    let mut fpr_version = String::new();
    BufReader::new(fpr.by_name("VERSION")?).read_line(&mut fpr_version)?;
    let fpr_version = fpr_version.trim_end().to_owned();

    let fvdl = Fvdl::from_zip_entry(fpr.by_name("audit.fvdl")?)?;
    let meta = fvdl.meta()?;
    let engine = fvdl.engine_data()?;
    let issue_count = fvdl.vulnerabilities()?.len();

    let audit = if let Some(index) = fpr.index_for_name("audit.xml") {
        Some(AuditDoc::from_zip_entry(fpr.by_index(index)?)?)
    } else {
        None
    };

    Ok(Loaded {
        fpr_version,
        meta,
        engine,
        audit,
        issue_count,
    })
}

struct RulePackInfo<'a> {
    name: Option<&'a str>,
    version: Option<&'a str>,
}

struct InfoData<'a> {
    fpr_version: &'a str,
    fvdl_version: &'a str,
    uuid: &'a str,
    scan_date: Option<String>,
    project: Option<&'a str>,
    project_version: Option<&'a str>,
    build_label: Option<&'a str>,
    build_id: Option<&'a str>,
    source_root: Option<&'a str>,
    files_scanned: Option<u32>,
    build_duration: Option<u32>,
    scan_time: Option<i64>,
    total_loc: Option<i32>,
    engine_version: Option<&'a str>,
    hostname: Option<&'a str>,
    platform: Option<&'a str>,
    username: Option<&'a str>,
    rule_packs: Vec<RulePackInfo<'a>>,
    scan_errors: usize,
    inactive: i64,
    issue_count: usize,
    audit_project: Option<&'a str>,
    audit_project_version: Option<&'a str>,
    audit_written: Option<&'a str>,
}

fn build_info(l: &Loaded) -> InfoData<'_> {
    let scan_date = l
        .meta
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
    ) = l
        .meta
        .build
        .as_ref()
        .map(|b| {
            let loc: i32 = b.loc_list.iter().filter_map(|l| l.count).sum();
            (
                b.project_name.as_deref(),
                b.version.as_deref(),
                b.label.as_deref(),
                b.id.as_deref(),
                b.base_path.as_deref(),
                b.number_files,
                b.build_duration,
                b.scan_time,
                if loc > 0 { Some(loc) } else { None },
            )
        })
        .unwrap_or_default();

    let (engine_version, hostname, platform, username, rule_packs, scan_errors, inactive) =
        if let Some(engine) = &l.engine {
            let rule_packs = engine
                .rule_packs
                .as_ref()
                .map(|rps| {
                    rps.rule_packs
                        .iter()
                        .map(|rp| RulePackInfo {
                            name: rp.name.as_deref(),
                            version: rp.version.as_deref(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            let inactive: i64 = engine.inactive_results.iter().filter_map(|g| g.count).sum();
            let mi = engine.machine_info.as_ref();
            (
                engine.engine_version.as_deref(),
                mi.and_then(|m| m.hostname.as_deref()),
                mi.and_then(|m| m.platform.as_deref()),
                mi.and_then(|m| m.username.as_deref()),
                rule_packs,
                engine.errors.len(),
                inactive,
            )
        } else {
            (None, None, None, None, vec![], 0, 0)
        };

    let (audit_project, audit_project_version, audit_written) = if let Some(audit) = &l.audit {
        let pi = &audit.project_info;
        (
            pi.name.as_deref(),
            pi.project_version_name.as_deref(),
            pi.write_date.as_deref(),
        )
    } else {
        (None, None, None)
    };

    InfoData {
        fpr_version: &l.fpr_version,
        fvdl_version: &l.meta.version,
        uuid: &l.meta.uuid,
        scan_date,
        project,
        project_version,
        build_label,
        build_id,
        source_root,
        files_scanned,
        build_duration,
        scan_time,
        total_loc,
        engine_version,
        hostname,
        platform,
        username,
        rule_packs,
        scan_errors,
        inactive,
        issue_count: l.issue_count,
        audit_project,
        audit_project_version,
        audit_written,
    }
}

pub fn text(fpr: &mut ZipArchive<File>) -> anyhow::Result<()> {
    const ALIGN: usize = 16;
    let loaded = load(fpr)?;
    let d = build_info(&loaded);

    println!("{:<ALIGN$}{}", "FPR version:", d.fpr_version);
    println!("{:<ALIGN$}{}", "FVDL version:", d.fvdl_version);
    println!("{:<ALIGN$}{}", "UUID:", d.uuid);
    if let Some(sd) = &d.scan_date {
        println!("{:<ALIGN$}{}", "Scan date:", sd);
    }
    if let Some(name) = d.project {
        print!("{:<ALIGN$}{}", "Project:", name);
        if let Some(v) = d.project_version {
            print!(" ({})", v);
        }
        println!();
    }
    if let Some(label) = d.build_label {
        println!("{:<ALIGN$}{}", "Build label:", label);
    }
    if let Some(id) = d.build_id {
        println!("{:<ALIGN$}{}", "Build ID:", id);
    }
    if let Some(path) = d.source_root {
        println!("{:<ALIGN$}{}", "Source root:", path);
    }
    if let Some(n) = d.files_scanned {
        println!("{:<ALIGN$}{}", "Files scanned:", n);
    }
    if let Some(duration) = d.build_duration {
        println!("{:<ALIGN$}{}s", "Build duration:", duration);
    }
    if let Some(epoch) = d.scan_time {
        println!("{:<ALIGN$}{}s (epoch)", "Scan time:", epoch);
    }
    if let Some(loc) = d.total_loc {
        println!("{:<ALIGN$}{}", "Total LOC:", loc);
    }
    if let Some(ev) = d.engine_version {
        println!("{:<ALIGN$}{}", "Engine version:", ev);
    }
    if let Some(h) = d.hostname {
        print!("{:<ALIGN$}{}", "Scanned on:", h);
        if let Some(p) = d.platform {
            print!(" ({})", p);
        }
        println!();
    }
    if let Some(u) = d.username {
        println!("{:<ALIGN$}{}", "Scanned by:", u);
    }
    if !d.rule_packs.is_empty() {
        let pack_names: Vec<String> = d
            .rule_packs
            .iter()
            .map(|rp| {
                format!(
                    "{} v{}",
                    rp.name.unwrap_or("<unnamed>"),
                    rp.version.unwrap_or("?")
                )
            })
            .collect();
        println!("{:<ALIGN$}{}", "Rule packs:", pack_names.join("\n  "));
    }
    if d.scan_errors > 0 {
        println!("{:<ALIGN$}{}", "Scan errors:", d.scan_errors);
    }
    if d.inactive > 0 {
        println!("{:<ALIGN$}{}", "Inactive:", d.inactive);
    }
    println!("{:<ALIGN$}{}", "Issues in FVDL:", d.issue_count);
    if let Some(name) = d.audit_project {
        print!("{:<ALIGN$}{}", "Audit project:", name);
        if let Some(v) = d.audit_project_version {
            print!(" ({})", v);
        }
        println!();
    }
    if let Some(wd) = d.audit_written {
        println!("{:<ALIGN$}{}", "Audit written:", wd);
    }

    Ok(())
}

pub fn json(fpr: &mut ZipArchive<File>) -> anyhow::Result<()> {
    let loaded = load(fpr)?;
    let d = build_info(&loaded);

    let rule_packs: Vec<_> = d
        .rule_packs
        .iter()
        .map(|rp| serde_json::json!({ "name": rp.name, "version": rp.version }))
        .collect();

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "fpr_version": d.fpr_version,
            "fvdl_version": d.fvdl_version,
            "uuid": d.uuid,
            "scan_date": d.scan_date,
            "project": d.project,
            "project_version": d.project_version,
            "build_label": d.build_label,
            "build_id": d.build_id,
            "source_root": d.source_root,
            "files_scanned": d.files_scanned,
            "build_duration": d.build_duration,
            "scan_time": d.scan_time,
            "total_loc": d.total_loc,
            "engine_version": d.engine_version,
            "hostname": d.hostname,
            "platform": d.platform,
            "username": d.username,
            "rule_packs": rule_packs,
            "scan_errors": d.scan_errors,
            "inactive_results": d.inactive,
            "issue_count": d.issue_count,
            "audit_project": d.audit_project,
            "audit_project_version": d.audit_project_version,
            "audit_written": d.audit_written,
        }))?
    );
    Ok(())
}
