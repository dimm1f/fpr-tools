use std::str::FromStr;

use anyhow::anyhow;

use crate::fpr_report::{VulnerabilityEntry, VulnerabilityStatus, primary_location};

/// Audit status filter. Valid values: all, unaudited, audited, suppressed, removed.
#[derive(Clone, Copy)]
pub enum StatusFilter {
    All,
    Unaudited,
    Audited,
    Suppressed,
    Removed,
}

impl StatusFilter {
    pub fn matches(&self, status: &VulnerabilityStatus<'_>) -> bool {
        match self {
            StatusFilter::All => true,
            StatusFilter::Unaudited => matches!(status, VulnerabilityStatus::Unaudited),
            StatusFilter::Audited => matches!(status, VulnerabilityStatus::Audited { .. }),
            StatusFilter::Suppressed => matches!(status, VulnerabilityStatus::Suppressed { .. }),
            StatusFilter::Removed => matches!(status, VulnerabilityStatus::Removed { .. }),
        }
    }
}

impl FromStr for StatusFilter {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "all" => Ok(StatusFilter::All),
            "unaudited" => Ok(StatusFilter::Unaudited),
            "audited" => Ok(StatusFilter::Audited),
            "suppressed" => Ok(StatusFilter::Suppressed),
            "removed" => Ok(StatusFilter::Removed),
            _ => Err(anyhow!(
                "unknown status '{s}', expected one of: all, unaudited, audited, suppressed, removed"
            )),
        }
    }
}

/// Group-by field. Valid values: rule, kingdom, file, status.
#[derive(Clone, Copy)]
pub enum GroupByField {
    Rule,
    Kingdom,
    File,
    Status,
}

impl FromStr for GroupByField {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "rule" => Ok(GroupByField::Rule),
            "kingdom" => Ok(GroupByField::Kingdom),
            "file" => Ok(GroupByField::File),
            "status" => Ok(GroupByField::Status),
            _ => Err(anyhow!(
                "unknown group-by field '{s}', expected one of: rule, kingdom, file, status"
            )),
        }
    }
}

/// Sort field. Valid values: severity, rule, file, status.
#[derive(Clone, Copy)]
pub enum SortField {
    Severity,
    Rule,
    File,
    Status,
}

impl FromStr for SortField {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "severity" => Ok(SortField::Severity),
            "rule" => Ok(SortField::Rule),
            "file" => Ok(SortField::File),
            "status" => Ok(SortField::Status),
            _ => Err(anyhow!(
                "unknown sort field '{s}', expected one of: severity, rule, file, status"
            )),
        }
    }
}

#[derive(Clone, Copy)]
enum SeverityOp {
    Gt,
    Gte,
    Lt,
    Lte,
    Eq,
}

/// Severity comparison expression, e.g. `>=3.0`, `>4`, `=5.0`. A bare number implies `>=`.
#[derive(Clone)]
pub struct SeverityExpr {
    op: SeverityOp,
    pub threshold: f32,
}

impl FromStr for SeverityExpr {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (op, rest) = if let Some(r) = s.strip_prefix(">=") {
            (SeverityOp::Gte, r)
        } else if let Some(r) = s.strip_prefix("<=") {
            (SeverityOp::Lte, r)
        } else if let Some(r) = s.strip_prefix('>') {
            (SeverityOp::Gt, r)
        } else if let Some(r) = s.strip_prefix('<') {
            (SeverityOp::Lt, r)
        } else if let Some(r) = s.strip_prefix('=') {
            (SeverityOp::Eq, r)
        } else {
            (SeverityOp::Gte, s)
        };
        let threshold = rest
            .parse::<f32>()
            .map_err(|_| anyhow!("invalid severity value: '{rest}'"))?;
        Ok(SeverityExpr { op, threshold })
    }
}

impl SeverityExpr {
    pub fn matches(&self, sev: f32) -> bool {
        match self.op {
            SeverityOp::Gt => sev > self.threshold,
            SeverityOp::Gte => sev >= self.threshold,
            SeverityOp::Lt => sev < self.threshold,
            SeverityOp::Lte => sev <= self.threshold,
            SeverityOp::Eq => (sev - self.threshold).abs() < 0.001,
        }
    }
}

pub struct ListRow {
    pub sev: f32,
    pub rule_type: String,
    pub kingdom: String,
    pub file_loc: String,
    pub status_label: &'static str,
    pub instance_id: String,
}

pub struct ListOptions {
    pub status: StatusFilter,
    pub severity: Option<SeverityExpr>,
    pub rule: Option<String>,
    pub file: Option<String>,
    pub group_by: Option<GroupByField>,
    pub sort: Option<SortField>,
    pub limit: Option<usize>,
}

pub fn apply(entries: &[VulnerabilityEntry<'_>], opts: &ListOptions) -> Vec<ListRow> {
    let rule_lc = opts.rule.as_deref().map(str::to_lowercase);
    let file_lc = opts.file.as_deref().map(str::to_lowercase);

    let mut rows: Vec<ListRow> = entries
        .iter()
        .filter_map(|entry| {
            if !opts.status.matches(&entry.status) {
                return None;
            }

            let sev = entry
                .vulnerability
                .instance
                .instance_severity
                .unwrap_or(0.0);
            if let Some(expr) = opts.severity.as_ref()
                && !expr.matches(sev)
            {
                return None;
            }

            let kind = entry.vulnerability.rule.kind.as_deref().unwrap_or("");
            let typ = entry.vulnerability.rule.typ.as_deref().unwrap_or("");
            let subtyp = entry.vulnerability.rule.subtyp.as_deref().unwrap_or("");
            let rule_type = format!(
                "{}{}{}",
                typ,
                if subtyp.is_empty() { "" } else { ": " },
                subtyp
            );

            if let Some(pat) = &rule_lc {
                let haystack = format!("{} {} {}", kind, typ, subtyp).to_lowercase();
                if !haystack.contains(pat.as_str()) {
                    return None;
                }
            }

            let file_loc = match primary_location(&entry.vulnerability.analysis) {
                Some((path, line)) => format!("{}:{}", path, line),
                None => String::new(),
            };

            if let Some(pat) = &file_lc
                && !file_loc.to_lowercase().contains(pat.as_str())
            {
                return None;
            }

            Some(ListRow {
                sev,
                rule_type,
                kingdom: kind.to_owned(),
                file_loc,
                status_label: entry.status.as_str(),
                instance_id: entry.vulnerability.instance.instance_id.clone(),
            })
        })
        .collect();

    match opts.sort {
        None | Some(SortField::Severity) => {
            rows.sort_by(|a, b| {
                b.sev
                    .partial_cmp(&a.sev)
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
        }
        Some(SortField::Rule) => rows.sort_by(|a, b| a.rule_type.cmp(&b.rule_type)),
        Some(SortField::File) => rows.sort_by(|a, b| a.file_loc.cmp(&b.file_loc)),
        Some(SortField::Status) => rows.sort_by(|a, b| a.status_label.cmp(b.status_label)),
    }

    if let Some(n) = opts.limit {
        rows.truncate(n);
    }

    rows
}
