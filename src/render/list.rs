use std::fs::File;

use zip::ZipArchive;

use crate::{
    fpr_report::FprReport,
    list_filter::{self, ListOptions, ListRow},
};

pub fn text(fpr: &mut ZipArchive<File>, opts: ListOptions) -> anyhow::Result<()> {
    let report = FprReport::from_zip(fpr)?;
    let entries = report.vulnerabilities()?;
    let rows = list_filter::apply(&entries, &opts);

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

pub fn json(fpr: &mut ZipArchive<File>, opts: ListOptions) -> anyhow::Result<()> {
    let report = FprReport::from_zip(fpr)?;
    let entries = report.vulnerabilities()?;
    let rows = list_filter::apply(&entries, &opts);

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
