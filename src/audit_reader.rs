use std::io::Read;

use serde::{Deserialize, Deserializer};
use zip::read::ZipFile;

macro_rules! unwrap_vec {
    ($fn_name:ident, $item_type:ty, $rename:literal) => {
        fn $fn_name<'de, D>(deserializer: D) -> Result<Vec<$item_type>, D::Error>
        where
            D: Deserializer<'de>,
        {
            #[derive(Deserialize)]
            struct Wrapper {
                #[serde(rename = $rename, default)]
                items: Vec<$item_type>,
            }
            Ok(Wrapper::deserialize(deserializer)?.items)
        }
    };
}

macro_rules! define_issue_struct {
    ($(#[$attr:meta])* struct $name:ident { $($extra:tt)* }) => {
        $(#[$attr])*
        #[derive(Debug, Deserialize)]
        pub struct $name {
            #[serde(rename = "@instanceId")]
            pub instance_id: String,
            #[serde(rename = "@revision")]
            pub revision: i32,
            #[serde(rename = "@suppressed")]
            pub suppressed: Option<bool>,
            #[serde(rename = "@hidden")]
            pub hidden: Option<bool>,
            #[serde(rename = "@removed")]
            pub removed: Option<bool>,
            #[serde(rename = "Tag", default)]
            pub tags: Vec<Tag>,
            #[serde(rename = "AssignedUser")]
            pub assigned_user: Option<String>,
            #[serde(
                rename = "ManagerAuditTrail",
                default,
                deserialize_with = "unwrap_tag_history"
            )]
            pub manager_audit_trail: Vec<TagHistory>,
            #[serde(
                rename = "ClientAuditTrail",
                default,
                deserialize_with = "unwrap_tag_history"
            )]
            pub client_audit_trail: Vec<TagHistory>,
            #[serde(
                rename = "ThreadedComments",
                default,
                deserialize_with = "unwrap_comments"
            )]
            pub threaded_comments: Vec<Comment>,
            $($extra)*
        }
    };
}

unwrap_vec!(unwrap_tag_history, TagHistory, "TagHistory");
unwrap_vec!(unwrap_comments, Comment, "Comment");

#[derive(Debug, Deserialize)]
pub struct Tag {
    #[serde(rename = "@id")]
    pub id: String,
    #[serde(rename = "Value")]
    pub value: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct TagHistory {
    #[serde(rename = "Tag")]
    pub tag: Tag,
    #[serde(rename = "EditTime")]
    pub edit_time: Option<String>,
    #[serde(rename = "OldValue")]
    pub old_value: Option<String>,
    #[serde(rename = "Username")]
    pub username: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Comment {
    #[serde(rename = "Content")]
    pub content: String,
    #[serde(rename = "Username")]
    pub username: Option<String>,
    #[serde(rename = "Timestamp")]
    pub timestamp: String,
}

define_issue_struct!(
    #[allow(dead_code)]
    struct Issue {}
);

define_issue_struct!(
    #[allow(dead_code)]
    struct CustomIssue {
        #[serde(rename = "Category")]
        pub category: String,
        #[serde(rename = "File")]
        pub file: Option<String>,
        #[serde(rename = "Line")]
        pub line: Option<i32>,
        #[serde(rename = "CreationDate")]
        pub creation_date: Option<String>,
        #[serde(rename = "RuleId")]
        pub rule_id: Option<String>,
    }
);

define_issue_struct!(
    #[allow(dead_code)]
    struct RemovedIssue {
        #[serde(rename = "Category")]
        pub category: String,
        #[serde(rename = "Product")]
        pub product: String,
        #[serde(rename = "File")]
        pub file: Option<String>,
        #[serde(rename = "Line")]
        pub line: Option<i32>,
        #[serde(rename = "Confidence")]
        pub confidence: Option<f32>,
        #[serde(rename = "Severity")]
        pub severity: Option<f32>,
        #[serde(rename = "Probability")]
        pub probability: Option<f32>,
        #[serde(rename = "Accuracy")]
        pub accuracy: Option<f32>,
        #[serde(rename = "Impact")]
        pub impact: Option<f32>,
        #[serde(rename = "RemoveScanDate")]
        pub remove_scan_date: Option<String>,
    }
);

#[derive(Debug, Deserialize)]
pub struct IssueList {
    #[serde(rename = "Issue", default)]
    pub issues: Vec<Issue>,
    #[serde(rename = "CustomIssue", default)]
    pub custom_issues: Vec<CustomIssue>,
    #[serde(rename = "RemovedIssue", default)]
    pub removed_issues: Vec<RemovedIssue>,
}

#[derive(Debug, Deserialize)]
pub struct ProjectInfo {
    #[serde(rename = "Description")]
    #[allow(dead_code)]
    pub description: Option<String>,
    #[serde(rename = "Name")]
    pub name: Option<String>,
    #[serde(rename = "ProjectVersionName")]
    pub project_version_name: Option<String>,
    #[serde(rename = "ProjectVersionId")]
    #[allow(dead_code)]
    pub project_version_id: Option<i64>,
    #[serde(rename = "WriteDate")]
    pub write_date: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Audit {
    #[serde(rename = "@version")]
    #[allow(dead_code)]
    pub version: String,
    #[serde(rename = "ProjectInfo")]
    pub project_info: ProjectInfo,
    #[serde(rename = "IssueList")]
    pub issue_list: IssueList,
}

impl Audit {
    pub fn from_zip_entry<'a, R: Read>(mut entry: ZipFile<'a, R>) -> anyhow::Result<Self> {
        let mut data = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut data)?;
        Ok(quick_xml::de::from_reader(data.as_slice())?)
    }
}
