use std::fs::File;

use zip::ZipArchive;

use crate::{
    fpr_report::{FprReport, VulnerabilityEntry, primary_location},
    src_archive_reader::SrcArchive,
};

use super::{apply_render, collect_trace_nodes};

pub struct ShowOptions {
    pub explain: bool,
    pub show_code: bool,
    pub show_tags: bool,
    pub show_comments: bool,
    pub show_history: bool,
}

pub fn text(fpr: &mut ZipArchive<File>, ids: &[&str], opts: &ShowOptions) -> anyhow::Result<()> {
    const ALIGN: usize = 20;

    let report = FprReport::from_zip(fpr)?;
    let src_archive = if opts.show_code {
        Some(SrcArchive::from_zip(fpr)?)
    } else {
        None
    };
    let descriptions = report.fvdl.descriptions()?;
    let node_pool = report.fvdl.unified_node_pool()?;
    let entries = report.vulnerabilities()?;

    for (i, id) in ids.iter().enumerate() {
        if i > 0 {
            println!();
        }

        let entry = find_entry(&entries, id)?;
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
        println!("Audit Status: {}", entry.status.as_str());
        if opts.show_tags {
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
            Some(file_loc) => {
                println!("  {}:{}", file_loc.path, file_loc.line);
                if let Some((start, snippet)) = src_archive
                    .as_ref()
                    .and_then(|a| a.snippet(fpr, file_loc.path, file_loc.line, 3))
                {
                    println!();
                    for (j, src_line) in snippet.iter().enumerate() {
                        let lineno = start + j;
                        let marker = if lineno == file_loc.line as usize {
                            '>'
                        } else {
                            ' '
                        };
                        println!("  {} {:5} | {}", marker, lineno, src_line);
                    }
                }
            }
            None => println!("  (none)"),
        }

        let trace_nodes = collect_trace_nodes(analysis, &node_pool);
        if !trace_nodes.is_empty() {
            let number_width = trace_nodes.len().to_string().len();
            println!();
            println!("Trace ({} steps)", trace_nodes.len());
            for (j, node) in trace_nodes.iter().enumerate() {
                let loc = if node.action.is_empty() {
                    format!("{}:{}", node.file, node.line)
                } else {
                    format!("{}:{} {}", node.file, node.line, node.action)
                };
                println!("  {:>number_width$}. {}", j + 1, loc);
                if let Some(rid) = node.rule_id {
                    println!("  {}  Rule: [{}]", " ".repeat(number_width), rid);
                }
            }
        }

        if let Some(desc) = desc_entry {
            if let Some(t) = &desc._abstract {
                println!();
                println!("Description");
                println!("{}", apply_render(defs, t).trim());
            }
            if opts.explain
                && let Some(t) = &desc.explanation
            {
                println!();
                println!("Explanation");
                println!("{}", apply_render(defs, t).trim());
            }
        }

        if opts.show_comments {
            let comments = entry.status.comments();
            if !comments.is_empty() {
                println!();
                println!("Comments ({})", comments.len());
                for comment in comments {
                    println!();
                    if let Some(user) = &comment.username {
                        print!("{} at {}: ", user, comment.timestamp);
                    } else {
                        print!("{}: ", comment.timestamp);
                    }
                    println!("{}", comment.content);
                }
            }
        }

        if opts.show_history {
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

pub(crate) fn find_entry<'a>(
    entries: &'a [VulnerabilityEntry<'a>],
    id: &str,
) -> anyhow::Result<&'a VulnerabilityEntry<'a>> {
    let matches: Vec<_> = entries
        .iter()
        .filter(|e| e.vulnerability.instance.instance_id.starts_with(id))
        .collect();
    if matches.is_empty() {
        anyhow::bail!("No vulnerability found with ID prefix '{id}'");
    }
    if matches.len() > 1 {
        eprintln!(
            "Ambiguous prefix '{id}' matches {} vulnerabilities:",
            matches.len()
        );
        for e in &matches {
            eprintln!("  {}", e.vulnerability.instance.instance_id);
        }
        anyhow::bail!("Provide a longer prefix to disambiguate");
    }
    Ok(matches[0])
}
