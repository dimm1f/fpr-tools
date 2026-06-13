use std::{collections::HashMap, fs::File};

use zip::ZipArchive;

use crate::{
    audit_reader::{Audit, Comment, CustomIssue, Issue, RemovedIssue, Tag},
    filter_template::TagNameMap,
    fvdl_reader::{AnalysisInfo, Fvdl, Vulnerability},
};

/// Returns (path, line) for the primary source location of a vulnerability.
/// Priority: unified trace default node → structural → runtime → configuration → local.
pub fn primary_location(analysis: &AnalysisInfo) -> Option<(&str, i32)> {
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
}

enum IssueLocation {
    Standard(usize),
    Custom(usize),
    Removed(usize),
}

pub struct FprReport {
    pub fvdl: Fvdl,
    pub audit: Option<Audit>,
    pub tag_names: TagNameMap,
    issue_index: HashMap<String, IssueLocation>,
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
}

pub struct VulnerabilityEntry<'a> {
    pub vulnerability: Vulnerability,
    pub status: VulnerabilityStatus<'a>,
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
