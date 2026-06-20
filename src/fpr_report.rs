use std::{collections::HashMap, fmt::Display, fs::File};

use zip::ZipArchive;

use crate::{
    audit_reader::{Audit, Comment, CustomIssue, Issue, RemovedIssue, Tag, TagHistory},
    filter_template_reader::TagNameMap,
    fvdl_reader::{AnalysisInfo, Fvdl, Vulnerability},
};

/// Returns (path, line) for the primary source location of a vulnerability.
/// Priority: unified trace default node → structural → runtime → configuration → local.
pub fn primary_location(analysis: &AnalysisInfo) -> Option<FileLoc<'_>> {
    analysis
        .unified
        .as_ref()
        .and_then(|u| u.traces.first())
        .and_then(|trace| {
            // Single pass: prefer isDefault node, fall back to first node with any location.
            let mut fallback = None;
            for e in &trace.primary {
                let Some(node) = e.node.as_ref() else {
                    continue;
                };
                let Some(pair) = node
                    .source_location
                    .as_ref()
                    .and_then(|loc| loc.path.as_deref().zip(loc.line))
                else {
                    continue;
                };
                if node.is_default == Some(true) {
                    return Some(pair);
                }
                fallback.get_or_insert(pair);
            }
            fallback
        })
        .or_else(|| {
            analysis
                .structural
                .as_ref()
                .and_then(|s| s.source_location.as_ref())
                .and_then(|loc| loc.path.as_deref().zip(loc.line))
        })
        .or_else(|| {
            analysis
                .runtime
                .as_ref()
                .and_then(|r| r.primary_location.as_ref())
                .and_then(|loc| loc.path.as_deref().zip(loc.line))
        })
        .or_else(|| {
            analysis
                .configuration
                .first()
                .and_then(|loc| loc.path.as_deref().zip(loc.line))
        })
        .or_else(|| {
            let sr = analysis.local.as_ref()?.source_ref.as_ref()?;
            sr.path.as_deref().zip(sr.line)
        })
        .map(|(path, line)| FileLoc { path, line })
}

#[derive(PartialEq, Eq, PartialOrd, Ord)]
pub struct FileLoc<'a> {
    pub path: &'a str,
    pub line: i32,
}

impl<'a> Display for FileLoc<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.path, self.line)
    }
}

pub enum AuditIssue<'a> {
    Standard(&'a Issue),
    Custom(&'a CustomIssue),
}

impl<'a> AuditIssue<'a> {
    pub fn is_suppressed(&self) -> bool {
        match self {
            AuditIssue::Standard(i) => i.suppressed.unwrap_or(false),
            AuditIssue::Custom(i) => i.suppressed.unwrap_or(false),
        }
    }

    pub fn tags(&self) -> &[Tag] {
        match self {
            AuditIssue::Standard(i) => &i.tags,
            AuditIssue::Custom(i) => &i.tags,
        }
    }

    pub fn comments(&self) -> &[Comment] {
        match self {
            AuditIssue::Standard(i) => &i.threaded_comments,
            AuditIssue::Custom(i) => &i.threaded_comments,
        }
    }

    pub fn audit_trail(&self) -> Vec<&TagHistory> {
        match self {
            AuditIssue::Standard(i) => i
                .manager_audit_trail
                .iter()
                .chain(i.client_audit_trail.iter())
                .collect(),
            AuditIssue::Custom(i) => i
                .manager_audit_trail
                .iter()
                .chain(i.client_audit_trail.iter())
                .collect(),
        }
    }
}

enum IssueLocation {
    Standard(usize),
    Custom(usize),
    Removed(usize),
}

pub enum VulnerabilityStatus<'a> {
    Unaudited,
    Removed { issue: &'a RemovedIssue },
    Audited { issue: AuditIssue<'a> },
    Suppressed { issue: AuditIssue<'a> },
}

impl<'a> VulnerabilityStatus<'a> {
    pub const fn as_str(&self) -> &'static str {
        match self {
            VulnerabilityStatus::Unaudited => "Unaudited",
            VulnerabilityStatus::Removed { .. } => "Removed",
            VulnerabilityStatus::Suppressed { .. } => "Suppressed",
            VulnerabilityStatus::Audited { .. } => "Audited",
        }
    }

    pub fn tags(&self) -> &[Tag] {
        match self {
            VulnerabilityStatus::Unaudited => &[],
            VulnerabilityStatus::Removed { issue } => &issue.tags,
            VulnerabilityStatus::Audited { issue } | VulnerabilityStatus::Suppressed { issue } => {
                issue.tags()
            }
        }
    }

    pub fn comments(&self) -> &[Comment] {
        match self {
            VulnerabilityStatus::Unaudited => &[],
            VulnerabilityStatus::Removed { issue } => &issue.threaded_comments,
            VulnerabilityStatus::Audited { issue } | VulnerabilityStatus::Suppressed { issue } => {
                issue.comments()
            }
        }
    }

    pub fn audit_trail(&self) -> Vec<&TagHistory> {
        match self {
            VulnerabilityStatus::Unaudited => vec![],
            VulnerabilityStatus::Removed { issue } => issue
                .manager_audit_trail
                .iter()
                .chain(issue.client_audit_trail.iter())
                .collect(),
            VulnerabilityStatus::Audited { issue } | VulnerabilityStatus::Suppressed { issue } => {
                issue.audit_trail()
            }
        }
    }
}

pub struct VulnerabilityEntry<'a> {
    pub vulnerability: Vulnerability,
    pub status: VulnerabilityStatus<'a>,
}

pub struct FprReport {
    pub fvdl: Fvdl,
    pub audit: Option<Audit>,
    pub tag_names: TagNameMap,
    issue_index: HashMap<String, IssueLocation>,
}

impl FprReport {
    pub fn from_zip(fpr: &mut ZipArchive<File>) -> anyhow::Result<Self> {
        let fvdl = Fvdl::from_zip_entry(fpr.by_name("audit.fvdl")?)?;

        let audit = if let Some(idx) = fpr.index_for_name("audit.xml") {
            Some(Audit::from_zip_entry(fpr.by_index(idx)?)?)
        } else {
            None
        };

        let issue_index = audit
            .as_ref()
            .map(|a| {
                let il = &a.issue_list;
                let mut index = HashMap::new();
                for (i, issue) in il.issues.iter().enumerate() {
                    index.insert(issue.instance_id.clone(), IssueLocation::Standard(i));
                }
                for (i, issue) in il.custom_issues.iter().enumerate() {
                    index.insert(issue.instance_id.clone(), IssueLocation::Custom(i));
                }
                for (i, issue) in il.removed_issues.iter().enumerate() {
                    index.insert(issue.instance_id.clone(), IssueLocation::Removed(i));
                }
                index
            })
            .unwrap_or_default();

        let tag_names = if let Some(idx) = fpr.index_for_name("filtertemplate.xml") {
            TagNameMap::from_zip_entry(fpr.by_index(idx)?)?
        } else {
            TagNameMap::empty()
        };

        Ok(Self {
            fvdl,
            audit,
            tag_names,
            issue_index,
        })
    }

    pub fn vulnerabilities(&self) -> anyhow::Result<Vec<VulnerabilityEntry<'_>>> {
        let vulns = self.fvdl.vulnerabilities()?;
        Ok(vulns
            .into_iter()
            .map(|v| {
                let status = self.resolve_status(&v.instance.instance_id);
                VulnerabilityEntry {
                    vulnerability: v,
                    status,
                }
            })
            .collect())
    }

    fn resolve_status(&self, instance_id: &str) -> VulnerabilityStatus<'_> {
        let Some(audit) = &self.audit else {
            return VulnerabilityStatus::Unaudited;
        };
        let Some(location) = self.issue_index.get(instance_id) else {
            return VulnerabilityStatus::Unaudited;
        };
        let il = &audit.issue_list;
        let issue = match location {
            IssueLocation::Removed(i) => {
                return VulnerabilityStatus::Removed {
                    issue: &il.removed_issues[*i],
                };
            }
            IssueLocation::Standard(i) => AuditIssue::Standard(&il.issues[*i]),
            IssueLocation::Custom(i) => AuditIssue::Custom(&il.custom_issues[*i]),
        };
        if issue.is_suppressed() {
            VulnerabilityStatus::Suppressed { issue }
        } else {
            VulnerabilityStatus::Audited { issue }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fvdl_reader::{AnalysisInfo, Runtime, SourceLocation, Structural};

    fn loc(path: &str, line: i32) -> SourceLocation {
        SourceLocation {
            path: Some(path.to_owned()),
            line: Some(line),
            line_end: None,
            col_start: None,
            col_end: None,
            context_id: None,
            snippet: None,
        }
    }

    fn empty_analysis() -> AnalysisInfo {
        AnalysisInfo {
            unified: None,
            dataflow_id: None,
            local: None,
            stateful_primary: None,
            structural: None,
            configuration: vec![],
            runtime: None,
        }
    }

    #[test]
    fn file_loc_display() {
        assert_eq!(
            FileLoc {
                path: "src/Foo.java",
                line: 42
            }
            .to_string(),
            "src/Foo.java:42"
        );
    }

    #[test]
    fn primary_location_structural_fallback() {
        let mut analysis = empty_analysis();
        analysis.structural = Some(Structural {
            source_location: Some(loc("src/Bar.java", 10)),
            context_id: None,
            structural_matches: vec![],
        });
        let result = primary_location(&analysis).unwrap();
        assert_eq!(result.path, "src/Bar.java");
        assert_eq!(result.line, 10);
    }

    #[test]
    fn primary_location_runtime_fallback() {
        let mut analysis = empty_analysis();
        analysis.runtime = Some(Runtime {
            context_id: None,
            primary_location: Some(loc("src/Baz.java", 5)),
            replacement_definitions: None,
        });
        let result = primary_location(&analysis).unwrap();
        assert_eq!(result.path, "src/Baz.java");
        assert_eq!(result.line, 5);
    }

    #[test]
    fn primary_location_configuration_fallback() {
        let mut analysis = empty_analysis();
        analysis.configuration = vec![loc("config/app.properties", 3)];
        let result = primary_location(&analysis).unwrap();
        assert_eq!(result.path, "config/app.properties");
        assert_eq!(result.line, 3);
    }

    #[test]
    fn primary_location_all_none_returns_none() {
        assert!(primary_location(&empty_analysis()).is_none());
    }

    #[test]
    fn primary_location_structural_preferred_over_runtime() {
        let mut analysis = empty_analysis();
        analysis.structural = Some(Structural {
            source_location: Some(loc("structural.java", 1)),
            context_id: None,
            structural_matches: vec![],
        });
        analysis.runtime = Some(Runtime {
            context_id: None,
            primary_location: Some(loc("runtime.java", 2)),
            replacement_definitions: None,
        });
        let result = primary_location(&analysis).unwrap();
        assert_eq!(result.path, "structural.java");
    }
}
