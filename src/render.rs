use std::{
    collections::BTreeMap,
    fs::File,
    io::{BufRead, BufReader},
};

use zip::ZipArchive;

use crate::{
    audit_reader::Audit,
    fpr_report::{FprReport, VulnerabilityStatus, primary_location},
    fvdl_reader::{Fvdl, UnifiedPrimaryNode, decode_entities, strip_html},
    list_filter::{self, GroupByField, ListOptions, ListRow},
    src_archive::SrcArchive,
};

pub fn print_fpr_info(fpr: &mut ZipArchive<File>) -> anyhow::Result<()> {
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

pub fn print_statistics(fpr: &mut ZipArchive<File>, show_tags: bool) -> anyhow::Result<()> {
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

pub fn print_list(fpr: &mut ZipArchive<File>, opts: ListOptions) -> anyhow::Result<()> {
    let report = FprReport::from_zip(fpr)?;
    let entries = report.vulnerabilities()?;

    let rows = list_filter::apply(&entries, &opts);

    if rows.is_empty() {
        println!("No vulnerabilities match the given filters.");
        return Ok(());
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

pub fn print_show(
    fpr: &mut ZipArchive<File>,
    ids: &[String],
    explain: bool,
    show_code: bool,
    show_tags: bool,
    show_comments: bool,
    show_history: bool,
) -> anyhow::Result<()> {
    const ALIGN: usize = 20;

    let report = FprReport::from_zip(fpr)?;
    let src_archive = if show_code {
        Some(SrcArchive::from_zip(fpr)?)
    } else {
        None
    };
    let descriptions = report.fvdl.descriptions()?;
    let node_pool = report.fvdl.unified_node_pool()?;
    let entries = report.vulnerabilities()?;

    for (i, instance_id) in ids.iter().enumerate() {
        if i > 0 {
            println!();
        }

        let matches: Vec<_> = entries
            .iter()
            .filter(|e| {
                e.vulnerability
                    .instance
                    .instance_id
                    .starts_with(instance_id.as_str())
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

        println!("Vulnerability");
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

        println!();
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

        println!();
        let label = entry.status.as_str();
        println!("Audit Status: {}", label);
        if show_tags {
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
                println!("Tags:");
                for (name, value) in resolved_tags {
                    println!("{:<ALIGN$}{}", format!("  {}:", name), value);
                }
            }
        }

        if !inst.meta_info.is_empty() {
            println!();
            println!("MetaInfo");
            for group in &inst.meta_info {
                if let Some(content) = &group.content {
                    println!("  {:<ALIGN$}{}", format!("{}:", group.name), content);
                }
            }
        }

        println!();
        println!("Primary Location");
        match primary_location(analysis) {
            Some((path, line)) => {
                println!("  {}:{}", path, line);
                if let Some((start, snippet)) = src_archive
                    .as_ref()
                    .and_then(|a| a.snippet(fpr, path, line, 3))
                {
                    println!();
                    for (i, src_line) in snippet.iter().enumerate() {
                        let lineno = start + i;
                        let marker = if lineno == line as usize { '>' } else { ' ' };
                        println!("  {} {:5} | {}", marker, lineno, src_line);
                    }
                }
            }
            None => println!("  (none)"),
        }

        if let Some(unified) = &analysis.unified
            && let Some(trace) = unified.traces.first()
        {
            let nodes: Vec<_> = trace
                .primary
                .iter()
                .filter_map(|e| {
                    if let Some(node) = &e.node {
                        format_node(node)
                    } else if let Some(ref_id) = e.node_ref_id {
                        node_pool
                            .iter()
                            .find(|n| n.id == Some(ref_id))
                            .and_then(format_node)
                    } else {
                        None
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

        if show_comments {
            let comments = entry.status.comments();
            if !comments.is_empty() {
                println!();
                println!("Comments ({})", comments.len());
                for comment in comments {
                    println!();
                    if let Some(user) = &comment.username {
                        print!("{} at {}: ", user, comment.timestamp);
                    } else {
                        println!("{}: ", comment.timestamp);
                    }
                    println!("{}", comment.content);
                }
            }
        }

        if show_history {
            let trail = entry.status.audit_trail();
            if !trail.is_empty() {
                println!();
                println!("History ({})", trail.len());
                for h in trail {
                    println!();
                    let tag_name = report.tag_names.resolve(&h.tag.id);
                    let new_val = h.tag.value.as_deref().unwrap_or("(none)");
                    let old_val = h.old_value.as_deref().unwrap_or("(none)");
                    if let Some(user) = &h.username {
                        print!("{} at {}: ", user, h.edit_time.as_deref().unwrap_or("?"));
                    } else {
                        print!("{}: ", h.edit_time.as_deref().unwrap_or("?"));
                    }
                    println!("{}: {} -> {}", tag_name, old_val, new_val);
                }
            }
        }
    }

    Ok(())
}

fn print_entry(i: usize, row: &ListRow) {
    println!("# {} {}", i, row.status_label);
    println!("Instance ID: {}", row.instance_id);
    println!("Type: {}", row.rule_type);
    println!("File: {}", row.file_loc);
}

fn format_node(node: &UnifiedPrimaryNode) -> Option<String> {
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
}
