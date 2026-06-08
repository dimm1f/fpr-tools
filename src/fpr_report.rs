use std::{collections::HashMap, fs::File};

use zip::ZipArchive;

use crate::{
    audit_reader::{Audit, CustomIssue, Issue, RemovedIssue, Tag},
    filter_template::TagNameMap,
    fvdl_reader::{Fvdl, Vulnerability},
};

pub enum AuditIssue<'a> {
    Standard(&'a Issue),
    Custom(&'a CustomIssue),
    Removed(&'a RemovedIssue),
}

impl<'a> AuditIssue<'a> {
    pub fn is_suppressed(&self) -> bool {
        match self {
            AuditIssue::Standard(i) => i.suppressed.unwrap_or(false),
            AuditIssue::Custom(i) => i.suppressed.unwrap_or(false),
            AuditIssue::Removed(i) => i.suppressed.unwrap_or(false),
        }
    }

    pub fn tags(&self) -> &[Tag] {
        match self {
            AuditIssue::Standard(i) => &i.tags,
            AuditIssue::Custom(i) => &i.tags,
            AuditIssue::Removed(i) => &i.tags,
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
    Audited { issue: AuditIssue<'a> },
    Suppressed { issue: AuditIssue<'a> },
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

        Ok(Self { fvdl, audit, tag_names, issue_index })
    }

    pub fn vulnerabilities(&self) -> anyhow::Result<Vec<VulnerabilityEntry<'_>>> {
        let vulns = self.fvdl.vulnerabilities()?;
        Ok(vulns
            .into_iter()
            .map(|v| {
                let status = self.resolve_status(&v.instance.instance_id);
                VulnerabilityEntry { vulnerability: v, status }
            })
            .collect())
    }

    pub fn audited_vulnerabilities(&self) -> anyhow::Result<Vec<VulnerabilityEntry<'_>>> {
        Ok(self
            .vulnerabilities()?
            .into_iter()
            .filter(|e| !matches!(e.status, VulnerabilityStatus::Unaudited))
            .collect())
    }

    pub fn unaudited_vulnerabilities(&self) -> anyhow::Result<Vec<VulnerabilityEntry<'_>>> {
        Ok(self
            .vulnerabilities()?
            .into_iter()
            .filter(|e| matches!(e.status, VulnerabilityStatus::Unaudited))
            .collect())
    }

    pub fn vulnerability_status(&self, instance_id: &str) -> VulnerabilityStatus<'_> {
        self.resolve_status(instance_id)
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
            IssueLocation::Standard(i) => AuditIssue::Standard(&il.issues[*i]),
            IssueLocation::Custom(i) => AuditIssue::Custom(&il.custom_issues[*i]),
            IssueLocation::Removed(i) => AuditIssue::Removed(&il.removed_issues[*i]),
        };
        if issue.is_suppressed() {
            VulnerabilityStatus::Suppressed { issue }
        } else {
            VulnerabilityStatus::Audited { issue }
        }
    }
}
