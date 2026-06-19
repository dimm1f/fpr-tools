use std::{collections::BTreeMap, fs::File};

use zip::ZipArchive;

use crate::{
    filter_template_reader::TagNameMap,
    fpr_report::{FprReport, VulnerabilityEntry, VulnerabilityStatus},
};

struct Stats {
    audited: usize,
    unaudited: usize,
    suppressed: usize,
    removed: usize,
    tag_counts: BTreeMap<(&'static str, String, String), usize>,
}

fn collect_stats(
    entries: &[VulnerabilityEntry<'_>],
    tag_names: &TagNameMap,
    accumulate_tags: bool,
) -> Stats {
    let mut stats = Stats {
        audited: 0,
        unaudited: 0,
        suppressed: 0,
        removed: 0,
        tag_counts: BTreeMap::new(),
    };
    for entry in entries {
        let status_lbl = match &entry.status {
            VulnerabilityStatus::Unaudited => {
                stats.unaudited += 1;
                continue;
            }
            s @ VulnerabilityStatus::Suppressed { .. } => {
                stats.suppressed += 1;
                s.as_str()
            }
            s @ VulnerabilityStatus::Removed { .. } => {
                stats.removed += 1;
                s.as_str()
            }
            s @ VulnerabilityStatus::Audited { .. } => {
                stats.audited += 1;
                s.as_str()
            }
        };
        if accumulate_tags {
            for tag in entry.status.tags() {
                if let Some(value) = &tag.value {
                    let name = tag_names.resolve(&tag.id).to_owned();
                    *stats
                        .tag_counts
                        .entry((status_lbl, name, value.clone()))
                        .or_default() += 1;
                }
            }
        }
    }
    stats
}

pub fn text(fpr: &mut ZipArchive<File>, show_tags: bool) -> anyhow::Result<()> {
    const ALIGN: usize = 16;

    let report = FprReport::from_zip(fpr)?;
    let entries = report.vulnerabilities()?;
    let stats = collect_stats(&entries, &report.tag_names, show_tags);

    let counts = [
        ("Audited", stats.audited),
        ("Unaudited", stats.unaudited),
        ("Suppressed", stats.suppressed),
        ("Removed", stats.removed),
    ];

    if show_tags {
        let val_align = stats
            .tag_counts
            .keys()
            .map(|(_, _, v)| v.len() + 5)
            .max()
            .filter(|&x| x > ALIGN)
            .unwrap_or(ALIGN);
        let value_width = val_align.saturating_sub(5);

        for (status_lbl, total) in counts {
            println!("{:<val_align$}{}", status_lbl, total);
            let mut current_tag: Option<&str> = None;
            for ((_, tag_name, value), count) in stats
                .tag_counts
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

pub fn json(fpr: &mut ZipArchive<File>) -> anyhow::Result<()> {
    let report = FprReport::from_zip(fpr)?;
    let entries = report.vulnerabilities()?;
    let stats = collect_stats(&entries, &report.tag_names, true);

    let tags: Vec<_> = stats
        .tag_counts
        .iter()
        .map(|((status, tag, value), count)| {
            serde_json::json!({
                "status": status,
                "tag": tag,
                "value": value,
                "count": count,
            })
        })
        .collect();

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "audited": stats.audited,
            "unaudited": stats.unaudited,
            "suppressed": stats.suppressed,
            "removed": stats.removed,
            "tags": tags,
        }))?
    );
    Ok(())
}
