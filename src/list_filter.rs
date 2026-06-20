use std::{borrow::Cow, collections::BTreeMap, str::FromStr};

use anyhow::anyhow;

use crate::fpr_report::{FileLoc, VulnerabilityEntry, VulnerabilityStatus, primary_location};

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

pub struct ListOptions {
    pub status: StatusFilter,
    pub severity: Option<SeverityExpr>,
    pub rule: Option<String>,
    pub file: Option<String>,
    pub group_by: Option<GroupByField>,
    pub sort: Option<SortField>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

pub struct ListRow<'a> {
    pub sev: f32,
    pub rule_type: &'a str,
    pub rule_subtype: &'a str,
    pub kingdom: &'a str,
    pub file_loc: Option<FileLoc<'a>>,
    pub status_label: &'static str,
    pub entry: &'a VulnerabilityEntry<'a>,
}

pub fn apply<'a>(entries: &'a [VulnerabilityEntry<'_>], opts: &ListOptions) -> Vec<ListRow<'a>> {
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
            let rule_type = entry.vulnerability.rule.typ.as_deref().unwrap_or("");
            let rule_subtype = entry.vulnerability.rule.subtyp.as_deref().unwrap_or("");

            if let Some(pat) = &rule_lc {
                let haystack = format!("{} {} {}", kind, rule_type, rule_subtype).to_lowercase();
                if !haystack.contains(pat.as_str()) {
                    return None;
                }
            }

            let file_loc = primary_location(&entry.vulnerability.analysis);

            if let (Some(pat), Some(floc)) = (&file_lc, &file_loc)
                && !floc.path.to_lowercase().contains(pat.as_str())
            {
                return None;
            }

            Some(ListRow {
                sev,
                rule_type,
                rule_subtype,
                kingdom: kind,
                file_loc,
                status_label: entry.status.as_str(),
                entry,
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
        Some(SortField::Rule) => {
            rows.sort_by(|a, b| (a.rule_type, a.rule_subtype).cmp(&(b.rule_type, b.rule_subtype)))
        }
        Some(SortField::File) => rows.sort_by(|a, b| a.file_loc.cmp(&b.file_loc)),
        Some(SortField::Status) => rows.sort_by(|a, b| a.status_label.cmp(b.status_label)),
    }

    // offset and truncate after sort so --limit/--offset always operate on the chosen sort field
    if let Some(off) = opts.offset {
        rows = rows.split_off(off.min(rows.len()));
    }
    if let Some(n) = opts.limit {
        rows.truncate(n);
    }

    rows
}

pub fn group<'a>(
    rows: Vec<ListRow<'a>>,
    group_by: GroupByField,
) -> BTreeMap<Cow<'a, str>, Vec<ListRow<'a>>> {
    let mut groups: BTreeMap<_, Vec<_>> = BTreeMap::new();
    for row in rows {
        let key = match group_by {
            GroupByField::Rule => Cow::Borrowed(row.rule_type),
            GroupByField::Kingdom => Cow::Borrowed(row.kingdom),
            GroupByField::File => Cow::Owned(
                row.file_loc
                    .as_ref()
                    .map(|loc| loc.to_string())
                    .unwrap_or_default(),
            ),
            GroupByField::Status => Cow::Borrowed(row.status_label),
        };

        groups.entry(key).or_default().push(row);
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_expr_bare_number_implies_gte() {
        let expr: SeverityExpr = "3.0".parse().unwrap();
        assert!(expr.matches(3.0));
        assert!(expr.matches(5.0));
        assert!(!expr.matches(2.9));
    }

    #[test]
    fn severity_expr_gt() {
        let expr: SeverityExpr = ">3.0".parse().unwrap();
        assert!(expr.matches(3.1));
        assert!(!expr.matches(3.0));
    }

    #[test]
    fn severity_expr_lt() {
        let expr: SeverityExpr = "<3.0".parse().unwrap();
        assert!(expr.matches(2.9));
        assert!(!expr.matches(3.0));
    }

    #[test]
    fn severity_expr_lte() {
        let expr: SeverityExpr = "<=5.0".parse().unwrap();
        assert!(expr.matches(5.0));
        assert!(expr.matches(4.9));
        assert!(!expr.matches(5.1));
    }

    #[test]
    fn severity_expr_eq() {
        let expr: SeverityExpr = "=4.0".parse().unwrap();
        assert!(expr.matches(4.0));
        assert!(!expr.matches(4.1));
    }

    #[test]
    fn severity_expr_invalid_returns_err() {
        assert!("abc".parse::<SeverityExpr>().is_err());
        assert!(">abc".parse::<SeverityExpr>().is_err());
    }

    #[test]
    fn status_filter_parses_all_variants() {
        assert!(matches!(
            "all".parse::<StatusFilter>().unwrap(),
            StatusFilter::All
        ));
        assert!(matches!(
            "unaudited".parse::<StatusFilter>().unwrap(),
            StatusFilter::Unaudited
        ));
        assert!(matches!(
            "audited".parse::<StatusFilter>().unwrap(),
            StatusFilter::Audited
        ));
        assert!(matches!(
            "suppressed".parse::<StatusFilter>().unwrap(),
            StatusFilter::Suppressed
        ));
        assert!(matches!(
            "removed".parse::<StatusFilter>().unwrap(),
            StatusFilter::Removed
        ));
    }

    #[test]
    fn status_filter_unknown_returns_err() {
        assert!("unknown".parse::<StatusFilter>().is_err());
        assert!("All".parse::<StatusFilter>().is_err());
    }

    #[test]
    fn group_by_field_parses_all_variants() {
        assert!(matches!(
            "rule".parse::<GroupByField>().unwrap(),
            GroupByField::Rule
        ));
        assert!(matches!(
            "kingdom".parse::<GroupByField>().unwrap(),
            GroupByField::Kingdom
        ));
        assert!(matches!(
            "file".parse::<GroupByField>().unwrap(),
            GroupByField::File
        ));
        assert!(matches!(
            "status".parse::<GroupByField>().unwrap(),
            GroupByField::Status
        ));
        assert!("bad".parse::<GroupByField>().is_err());
    }

    #[test]
    fn sort_field_parses_all_variants() {
        assert!(matches!(
            "severity".parse::<SortField>().unwrap(),
            SortField::Severity
        ));
        assert!(matches!(
            "rule".parse::<SortField>().unwrap(),
            SortField::Rule
        ));
        assert!(matches!(
            "file".parse::<SortField>().unwrap(),
            SortField::File
        ));
        assert!(matches!(
            "status".parse::<SortField>().unwrap(),
            SortField::Status
        ));
        assert!("bad".parse::<SortField>().is_err());
    }
}
