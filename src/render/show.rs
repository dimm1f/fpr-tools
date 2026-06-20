use std::fs::File;

use zip::ZipArchive;

use crate::{
    fpr_report::{FprReport, VulnerabilityEntry, primary_location},
    fvdl_reader::{
        AnalysisInfo, ReplacementDefinitions, UnifiedPrimaryNode, decode_entities, strip_html,
    },
    src_archive_reader::SrcArchive,
};

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

pub fn json(fpr: &mut ZipArchive<File>, ids: &[&str], opts: &ShowOptions) -> anyhow::Result<()> {
    let report = FprReport::from_zip(fpr)?;
    let src_archive = if opts.show_code {
        Some(SrcArchive::from_zip(fpr)?)
    } else {
        None
    };
    let descriptions = report.fvdl.descriptions()?;
    let node_pool = report.fvdl.unified_node_pool()?;
    let entries = report.vulnerabilities()?;

    let mut out: Vec<serde_json::Value> = Vec::new();

    for id in ids {
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

        let tags: Vec<_> = if opts.show_tags {
            entry
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
                .collect()
        } else {
            vec![]
        };

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

        let comments: Vec<_> = if opts.show_comments {
            entry
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
                .collect()
        } else {
            vec![]
        };

        let history: Vec<_> = if opts.show_history {
            entry
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
                .collect()
        } else {
            vec![]
        };

        out.push(serde_json::json!({
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
            "explanation": if opts.explain {
                desc_entry.and_then(|d| d.explanation.as_deref()).map(|t| apply_render(defs, t))
            } else {
                None
            },
            "comments": comments,
            "history": history,
        }));
    }

    println!("{}", serde_json::to_string_pretty(&out)?);
    Ok(())
}

fn find_entry<'a>(
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

struct TraceNode<'a> {
    file: &'a str,
    line: i32,
    action: &'a str,
    rule_id: Option<&'a str>,
}

fn collect_trace_nodes<'a>(
    analysis: &'a AnalysisInfo,
    node_pool: &'a [UnifiedPrimaryNode],
) -> Vec<TraceNode<'a>> {
    analysis
        .unified
        .as_ref()
        .and_then(|u| u.traces.first())
        .map(|trace| {
            trace
                .primary
                .iter()
                .filter_map(|e| {
                    if let Some(node) = &e.node {
                        extract_node(node)
                    } else if let Some(ref_id) = e.node_ref_id {
                        node_pool
                            .iter()
                            .find(|n| n.id == Some(ref_id))
                            .and_then(extract_node)
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn extract_node(node: &UnifiedPrimaryNode) -> Option<TraceNode<'_>> {
    let loc = node.source_location.as_ref()?;
    Some(TraceNode {
        file: loc.path.as_deref().unwrap_or("?"),
        line: loc.line.unwrap_or(0),
        action: node
            .action
            .as_ref()
            .and_then(|a| a.content.as_deref())
            .unwrap_or("")
            .trim(),
        rule_id: node.reason.as_ref().and_then(|r| r.rule_id.as_deref()),
    })
}

fn apply_render(defs: Option<&ReplacementDefinitions>, text: &str) -> String {
    let substituted = defs
        .map(|d| d.apply(text))
        .unwrap_or_else(|| text.to_owned());
    decode_entities(&strip_html(&substituted))
}
