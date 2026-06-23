use std::fs::File;

use zip::ZipArchive;

use crate::{
    fpr_report::{FprReport, primary_location},
    list_filter::{self, ListOptions, ListRow},
    src_archive_reader::SrcArchive,
};

use super::{apply_render, collect_trace_nodes};

pub fn text(fpr: &mut ZipArchive<File>, opts: ListOptions) -> anyhow::Result<()> {
    let report = FprReport::from_zip(fpr)?;
    let mut entries = report.vulnerabilities_filtered(opts.vuln_predicate())?;
    entries.retain(opts.status_predicate());
    let rows = list_filter::sort_and_page(&entries, opts.sort, opts.limit, opts.offset);

    if rows.is_empty() {
        println!("No vulnerabilities match the given filters.");
        return Ok(());
    }

    let start = opts.offset.unwrap_or(0) + 1;

    if let Some(group_field) = opts.group_by {
        let groups = list_filter::group(rows, group_field);

        let mut i = start;
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
            print_entry(start + i, row);
        }
    }

    Ok(())
}

pub fn json(fpr: &mut ZipArchive<File>, opts: ListOptions, all_fields: bool) -> anyhow::Result<()> {
    let report = FprReport::from_zip(fpr)?;
    let mut entries = report.vulnerabilities_filtered(opts.vuln_predicate())?;
    entries.retain(opts.status_predicate());
    let rows = list_filter::sort_and_page(&entries, opts.sort, opts.limit, opts.offset);

    if all_fields {
        let src_archive = Some(SrcArchive::from_zip(fpr)?);
        let descriptions = report.fvdl.descriptions()?;
        let node_pool = report.fvdl.unified_node_pool()?;

        let mut json_rows: Vec<serde_json::Value> = Vec::new();
        for row in &rows {
            let entry = row.entry;
            let rule = &entry.vulnerability.rule;
            let inst = &entry.vulnerability.instance;
            let analysis = &entry.vulnerability.analysis;

            let defs = analysis
                .unified
                .as_ref()
                .and_then(|u| u.replacement_definitions.as_ref());

            let desc_entry = descriptions
                .iter()
                .find(|d| d.class_id.as_deref() == Some(&rule.rule_id));

            let tags: Vec<_> = entry
                .status
                .tags()
                .iter()
                .filter_map(|t| {
                    t.value.as_deref().map(|v| {
                        serde_json::json!({
                            "name": report.tag_names.resolve(&t.id),
                            "value": v,
                        })
                    })
                })
                .collect();

            let meta_info: Vec<_> = inst
                .meta_info
                .iter()
                .filter_map(|g| {
                    g.content
                        .as_deref()
                        .map(|c| serde_json::json!({ "name": g.name, "content": c }))
                })
                .collect();

            let trace: Vec<_> = collect_trace_nodes(analysis, &node_pool)
                .into_iter()
                .map(|node| {
                    serde_json::json!({
                        "file": node.file,
                        "line": node.line,
                        "action": node.action,
                        "rule_id": node.rule_id,
                    })
                })
                .collect();

            let primary_loc = primary_location(analysis);

            let source_code: Option<Vec<serde_json::Value>> =
                if let (Some(arc), Some(loc)) = (&src_archive, &primary_loc) {
                    arc.snippet(fpr, loc.path, loc.line, 3)
                        .map(|(start, lines)| {
                            lines
                                .iter()
                                .enumerate()
                                .map(|(j, line)| {
                                    serde_json::json!({
                                        "line": start + j,
                                        "content": line,
                                        "primary": start + j == loc.line as usize,
                                    })
                                })
                                .collect()
                        })
                } else {
                    None
                };

            let comments: Vec<_> = entry
                .status
                .comments()
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "user": c.username,
                        "timestamp": c.timestamp,
                        "content": c.content,
                    })
                })
                .collect();

            let history: Vec<_> = entry
                .status
                .audit_trail()
                .iter()
                .map(|h| {
                    serde_json::json!({
                        "user": h.username,
                        "time": h.edit_time,
                        "tag": report.tag_names.resolve(&h.tag.id),
                        "old_value": h.old_value,
                        "new_value": h.tag.value,
                    })
                })
                .collect();

            json_rows.push(serde_json::json!({
                "instance_id": inst.instance_id,
                "severity": inst.instance_severity,
                "confidence": inst.confidence,
                "instance_description": inst.instance_description,
                "kingdom": rule.kind,
                "rule_type": rule.typ,
                "rule_subtype": rule.subtyp,
                "rule_id": rule.rule_id,
                "default_severity": rule.default_severity,
                "status": entry.status.as_str(),
                "tags": tags,
                "meta_info": meta_info,
                "primary_location": primary_loc.as_ref().map(|l| l.to_string()),
                "source_code": source_code,
                "trace": trace,
                "description": desc_entry.and_then(|d| d._abstract.as_deref()).map(|t| apply_render(defs, t)),
                "explanation": desc_entry.and_then(|d| d.explanation.as_deref()).map(|t| apply_render(defs, t)),
                "comments": comments,
                "history": history,
            }));
        }

        println!("{}", serde_json::to_string_pretty(&json_rows)?);
    } else {
        let json_rows: Vec<_> = rows
            .iter()
            .map(|row| {
                serde_json::json!({
                    "instance_id": row.entry.vulnerability.instance.instance_id,
                    "severity": row.sev,
                    "status": row.status_label,
                    "kingdom": row.kingdom,
                    "rule_type": row.rule_type,
                    "rule_subtype": row.rule_subtype,
                    "file": row.file_loc.as_ref().map(|l| l.to_string()),
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&json_rows)?);
    }

    Ok(())
}

fn print_entry(i: usize, row: &ListRow) {
    let instance_id = &row.entry.vulnerability.instance.instance_id;
    let file = row
        .file_loc
        .as_ref()
        .map(|loc| loc.to_string())
        .unwrap_or_default();

    println!("# {} {}", i, row.status_label);
    println!("Instance ID: {}", instance_id);
    println!("Kingdom: {}", row.kingdom);
    println!(
        "Type: {}{}{}",
        row.rule_type,
        if row.rule_subtype.is_empty() {
            ""
        } else {
            ": "
        },
        row.rule_subtype
    );
    println!("File: {}", file);
}
