use std::io::Read;

use serde::{Deserialize, Deserializer};
use zip::read::ZipFile;

use crate::section_index::SectionIndex;

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

macro_rules! unwrap_attr {
    ($fn_name:ident, $attr:literal, $result:ty) => {
        fn $fn_name<'de, D>(deserializer: D) -> Result<$result, D::Error>
        where
            D: Deserializer<'de>,
        {
            #[derive(Deserialize)]
            struct Wrapper {
                #[serde(rename = $attr)]
                value: $result,
            }
            Ok(Wrapper::deserialize(deserializer)?.value)
        }
    };
}

unwrap_vec!(unwrap_external_entries, ExternalEntry, "Entry");
unwrap_vec!(unwrap_knowledge, Fact, "Fact");
unwrap_vec!(unwrap_source_files, File, "File");
unwrap_vec!(unwrap_meta_info, Group, "Group");
unwrap_vec!(unwrap_audits, Audit, "Audit");
unwrap_vec!(unwrap_trace_primary, UnifiedTracePrimaryEntry, "Entry");
unwrap_vec!(unwrap_tips, String, "Tip");
unwrap_vec!(unwrap_references, Reference, "Reference");
unwrap_vec!(unwrap_configuration, SourceLocation, "SourceLocation");
unwrap_vec!(unwrap_err_msg, Err, "Error");
unwrap_vec!(unwrap_command_line, String, "Argument");
unwrap_vec!(unwrap_rule_info, EngineRuleEntry, "Rule");
unwrap_vec!(unwrap_inactive_results, InactiveGrouping, "Grouping");

unwrap_attr!(unwrap_rule_id, "@ruleID", Option<String>);
unwrap_attr!(unwrap_induction_ref_id, "@id", Option<i32>);
unwrap_attr!(unwrap_scan_time, "@value", Option<i64>);
unwrap_attr!(unwrap_context_id, "@id", Option<i32>);
unwrap_attr!(unwrap_dataflow_id, "@id", Option<String>);
unwrap_attr!(unwrap_stateful_primary, "@primary", Option<i32>);

fn unwrap_node_ref_id<'de, D>(deserializer: D) -> Result<Option<i32>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct Wrapper {
        #[serde(rename = "@id")]
        id: i32,
    }
    Ok(Some(Wrapper::deserialize(deserializer)?.id))
}

fn unwrap_structural_matches<'de, D>(deserializer: D) -> Result<Vec<SourceLocation>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    struct Entry {
        #[serde(rename = "SourceLocation")]
        loc: Option<SourceLocation>,
    }
    Ok(Vec::<Entry>::deserialize(deserializer)?
        .into_iter()
        .filter_map(|e| e.loc)
        .collect())
}

#[derive(Debug, Deserialize)]
pub struct TimeStamp {
    #[serde(rename = "@date")]
    pub date: Option<String>,
    #[serde(rename = "@time")]
    pub time: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "$text")]
    pub content: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SourceLocation {
    #[serde(rename = "@path")]
    pub path: Option<String>,
    #[serde(rename = "@line")]
    pub line: Option<i32>,
    #[allow(dead_code)]
    #[serde(rename = "@lineEnd")]
    pub line_end: Option<i32>,
    #[allow(dead_code)]
    #[serde(rename = "@colStart")]
    pub col_start: Option<i32>,
    #[allow(dead_code)]
    #[serde(rename = "@colEnd")]
    pub col_end: Option<i32>,
    #[allow(dead_code)]
    #[serde(rename = "@contextId")]
    pub context_id: Option<i32>,
    #[allow(dead_code)]
    #[serde(rename = "@snippet")]
    pub snippet: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Action {
    #[allow(dead_code)]
    #[serde(rename = "@type")]
    pub typ: Option<String>,
    #[serde(rename = "$text")]
    pub content: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Group {
    #[serde(rename = "@name")]
    pub name: String,
    #[serde(rename = "$text")]
    pub content: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Loc {
    #[allow(dead_code)]
    #[serde(rename = "@type")]
    pub typ: Option<String>,
    #[serde(rename = "$text")]
    pub count: Option<i32>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct File {
    #[serde(rename = "@id")]
    pub id: Option<i32>,
    #[serde(rename = "@size")]
    pub size: Option<String>,
    #[serde(rename = "@timestamp")]
    pub timestamp: Option<String>,
    #[serde(rename = "@loc")]
    pub loc: Option<i32>,
    #[serde(rename = "@type")]
    pub typ: Option<String>,
    #[serde(rename = "@encoding")]
    pub encoding: Option<String>,
    #[serde(rename = "Name")]
    pub name: Option<String>,
    #[serde(rename = "LOC", default)]
    pub loc_list: Vec<Loc>,
}

#[derive(Debug, Deserialize)]
pub struct Build {
    #[serde(rename = "BuildID")]
    pub id: Option<String>,
    #[serde(rename = "Project")]
    pub project_name: Option<String>,
    #[serde(rename = "Version")]
    pub version: Option<String>,
    #[serde(rename = "Label")]
    pub label: Option<String>,
    #[serde(rename = "BuildDuration")]
    pub build_duration: Option<u32>,
    #[serde(rename = "NumberFiles")]
    pub number_files: Option<u32>,
    #[serde(rename = "LOC", default)]
    pub loc_list: Vec<Loc>,
    #[allow(dead_code)]
    #[serde(rename = "JavaClasspath")]
    pub java_classpath: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "Libdirs")]
    pub lib_dirs: Option<String>,
    #[serde(rename = "SourceBasePath")]
    pub base_path: Option<String>,
    #[allow(dead_code)]
    #[serde(
        rename = "SourceFiles",
        default,
        deserialize_with = "unwrap_source_files"
    )]
    pub source_files: Vec<File>,
    #[serde(rename = "ScanTime", default, deserialize_with = "unwrap_scan_time")]
    pub scan_time: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct ClassInfo {
    #[allow(dead_code)]
    #[serde(rename = "@refid")]
    pub refid: Option<i32>,
    #[serde(rename = "ClassID")]
    pub rule_id: String,
    #[serde(rename = "Kingdom")]
    pub kind: Option<String>,
    #[serde(rename = "Type")]
    pub typ: Option<String>,
    #[serde(rename = "Subtype")]
    pub subtyp: Option<String>,
    #[allow(dead_code)]
    #[serde(rename = "AnalyzerName")]
    pub analyzer_name: Option<String>,
    #[serde(rename = "DefaultSeverity")]
    pub default_severity: Option<f32>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Audit {
    #[serde(rename = "auditor")]
    pub auditor: Option<String>,
    #[serde(rename = "time")]
    pub time: Option<String>,
    #[serde(rename = "auditSeverity")]
    pub audit_severity: Option<f32>,
    #[serde(rename = "status")]
    pub status: Option<String>,
    #[serde(rename = "auditAnalysis")]
    pub analysis: Option<String>,
    #[serde(rename = "comments")]
    pub comments: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct InstanceInfo {
    #[allow(dead_code)]
    #[serde(rename = "@minVirtualCallConfidence")]
    pub min_virtual_call_confidence: Option<f32>,
    #[serde(rename = "InstanceID")]
    pub instance_id: String,
    #[serde(rename = "InstanceSeverity")]
    pub instance_severity: Option<f32>,
    #[serde(rename = "Confidence")]
    pub confidence: Option<f32>,
    #[serde(rename = "InstanceDescription")]
    pub instance_description: Option<String>,
    #[serde(rename = "MetaInfo", default, deserialize_with = "unwrap_meta_info")]
    pub meta_info: Vec<Group>,
    #[allow(dead_code)]
    #[serde(rename = "Audits", default, deserialize_with = "unwrap_audits")]
    pub audits: Vec<Audit>,
}

#[derive(Debug, Deserialize)]
pub struct Def {
    #[serde(rename = "@key")]
    pub key: String,
    #[serde(rename = "@value")]
    pub value: String,
    #[allow(dead_code)]
    #[serde(rename = "SourceLocation")]
    pub source_location: Option<SourceLocation>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct LocationDef {
    #[serde(rename = "@key")]
    pub key: String,
    #[serde(rename = "@path")]
    pub path: Option<String>,
    #[serde(rename = "@line")]
    pub line: Option<i32>,
    #[serde(rename = "@lineEnd")]
    pub line_end: Option<i32>,
    #[serde(rename = "@colStart")]
    pub col_start: Option<i32>,
    #[serde(rename = "@colEnd")]
    pub col_end: Option<i32>,
    #[serde(rename = "@contextId")]
    pub context_id: Option<i32>,
    #[serde(rename = "@snippet")]
    pub snippet: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ReplacementDefinitions {
    #[serde(rename = "Def", default)]
    pub defs: Vec<Def>,
    #[allow(dead_code)]
    #[serde(rename = "LocationDef", default)]
    pub location_defs: Vec<LocationDef>,
}

impl ReplacementDefinitions {
    /// Substitutes `<Replace key="K"/>` placeholders in `text` with values from `defs`.
    pub fn apply(&self, text: &str) -> String {
        let mut result = String::with_capacity(text.len());
        let mut remaining = text;
        while let Some(start) = remaining.find("<Replace ") {
            result.push_str(&remaining[..start]);
            remaining = &remaining[start..];
            if let Some(end) = remaining.find('>') {
                let tag = &remaining[..=end];
                if let Some(key) = attr_value(tag, "key") {
                    let value = self
                        .defs
                        .iter()
                        .find(|d| d.key == key)
                        .map(|d| d.value.as_str())
                        .unwrap_or(key);
                    result.push_str(value);
                }
                remaining = &remaining[end + 1..];
            } else {
                break;
            }
        }
        result.push_str(remaining);
        result
    }
}

fn attr_value<'a>(tag: &'a str, attr: &str) -> Option<&'a str> {
    let i = tag.find(attr)?;
    let rest = tag[i + attr.len()..].strip_prefix("=\"")?;
    Some(&rest[..rest.find('"')?])
}

pub fn strip_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut in_tag = false;
    for ch in s.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => in_tag = false,
            _ if !in_tag => out.push(ch),
            _ => {}
        }
    }
    out
}

pub fn decode_entities(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut remaining = s;
    while let Some(amp) = remaining.find('&') {
        out.push_str(&remaining[..amp]);
        remaining = &remaining[amp..];
        let (replacement, skip) = if remaining.starts_with("&amp;") {
            ("&", 5)
        } else if remaining.starts_with("&lt;") {
            ("<", 4)
        } else if remaining.starts_with("&gt;") {
            (">", 4)
        } else if remaining.starts_with("&quot;") {
            ("\"", 6)
        } else if remaining.starts_with("&apos;") {
            ("'", 6)
        } else if remaining.starts_with("&#39;") {
            ("'", 5)
        } else if remaining.starts_with("&nbsp;") {
            (" ", 6)
        } else {
            out.push('&');
            remaining = &remaining[1..];
            continue;
        };
        out.push_str(replacement);
        remaining = &remaining[skip..];
    }
    out.push_str(remaining);
    out
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Fact {
    #[serde(rename = "@primary")]
    pub primary: Option<String>,
    #[serde(rename = "@type")]
    pub typ: Option<String>,
    #[serde(rename = "$text")]
    pub content: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Reason {
    #[serde(rename = "Rule", deserialize_with = "unwrap_rule_id", default)]
    pub rule_id: Option<String>,
    #[serde(
        rename = "InductionRef",
        deserialize_with = "unwrap_induction_ref_id",
        default
    )]
    pub induction_ref_id: Option<i32>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct UnifiedPrimaryNode {
    #[serde(rename = "@id")]
    pub id: Option<i32>,
    #[serde(rename = "@isDefault")]
    pub is_default: Option<bool>,
    #[serde(rename = "@detailsOnly")]
    pub details_only: Option<bool>,
    #[serde(rename = "@label")]
    pub label: Option<String>,
    #[serde(rename = "SourceLocation")]
    pub source_location: Option<SourceLocation>,
    #[serde(rename = "SecondaryLocation")]
    pub secondary_location: Option<SourceLocation>,
    #[serde(rename = "Action")]
    pub action: Option<Action>,
    #[serde(rename = "Reason")]
    pub reason: Option<Reason>,
    #[serde(rename = "Knowledge", default, deserialize_with = "unwrap_knowledge")]
    pub facts: Vec<Fact>,
}

#[derive(Debug, Deserialize)]
pub struct UnifiedTracePrimaryEntry {
    #[serde(rename = "Node")]
    pub node: Option<UnifiedPrimaryNode>,
    #[allow(dead_code)]
    #[serde(rename = "NodeRef", default, deserialize_with = "unwrap_node_ref_id")]
    pub node_ref_id: Option<i32>,
}

#[derive(Debug, Deserialize)]
pub struct UnifiedTrace {
    #[allow(dead_code)]
    #[serde(rename = "@id")]
    pub id: Option<i32>,
    #[serde(rename = "Primary", deserialize_with = "unwrap_trace_primary")]
    pub primary: Vec<UnifiedTracePrimaryEntry>,
}

#[derive(Debug, Deserialize)]
pub struct Unified {
    #[allow(dead_code)]
    #[serde(rename = "Context")]
    pub context: ContextEntry,
    #[serde(rename = "ReplacementDefinitions")]
    pub replacement_definitions: Option<ReplacementDefinitions>,
    #[serde(rename = "Trace", default)]
    pub traces: Vec<UnifiedTrace>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Arg {
    #[serde(rename = "@relevance")]
    pub relevance: Option<String>,
    #[serde(rename = "$text")]
    pub content: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Local {
    #[serde(rename = "SourceRef")]
    pub source_ref: Option<SourceLocation>,
    #[serde(rename = "Context", default, deserialize_with = "unwrap_context_id")]
    pub context_id: Option<i32>,
    #[serde(rename = "Arg", default)]
    pub args: Vec<Arg>,
    #[serde(rename = "ExternalID", default)]
    pub external_ids: Vec<ExternalId>,
}

#[derive(Debug, Deserialize)]
pub struct Structural {
    #[serde(rename = "SourceLocation")]
    pub source_location: Option<SourceLocation>,
    #[allow(dead_code)]
    #[serde(rename = "Context", default, deserialize_with = "unwrap_context_id")]
    pub context_id: Option<i32>,
    #[allow(dead_code)]
    #[serde(
        rename = "StructuralMatch",
        default,
        deserialize_with = "unwrap_structural_matches"
    )]
    pub structural_matches: Vec<SourceLocation>,
}

#[derive(Debug, Deserialize)]
pub struct Runtime {
    #[allow(dead_code)]
    #[serde(rename = "Context", default, deserialize_with = "unwrap_context_id")]
    pub context_id: Option<i32>,
    #[serde(rename = "PrimaryLocation")]
    pub primary_location: Option<SourceLocation>,
    #[allow(dead_code)]
    #[serde(rename = "ReplacementDefinitions")]
    pub replacement_definitions: Option<ReplacementDefinitions>,
}

#[derive(Debug, Deserialize)]
pub struct AnalysisInfo {
    #[serde(rename = "Unified")]
    pub unified: Option<Unified>,
    #[allow(dead_code)]
    #[serde(rename = "Dataflow", default, deserialize_with = "unwrap_dataflow_id")]
    pub dataflow_id: Option<String>,
    #[serde(rename = "Local")]
    pub local: Option<Local>,
    #[allow(dead_code)]
    #[serde(
        rename = "Stateful",
        default,
        deserialize_with = "unwrap_stateful_primary"
    )]
    pub stateful_primary: Option<i32>,
    #[serde(rename = "Structural")]
    pub structural: Option<Structural>,
    #[serde(
        rename = "Configuration",
        default,
        deserialize_with = "unwrap_configuration"
    )]
    pub configuration: Vec<SourceLocation>,
    #[serde(rename = "Runtime")]
    pub runtime: Option<Runtime>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct ExternalEntry {
    #[serde(rename = "@name")]
    pub name: Option<String>,
    #[serde(rename = "@type")]
    pub typ: Option<String>,
    #[serde(rename = "URL")]
    pub url: Option<String>,
    #[serde(rename = "SourceLocation")]
    pub source_location: Option<SourceLocation>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct AuxiliaryData {
    #[serde(rename = "@contentType")]
    pub content_type: Option<String>,
    #[serde(rename = "$text")]
    pub content: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct ExternalId {
    #[serde(rename = "@name")]
    pub name: Option<String>,
    #[serde(rename = "$text")]
    pub content: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Vulnerability {
    #[serde(rename = "ClassInfo")]
    pub rule: ClassInfo,
    #[serde(rename = "InstanceInfo")]
    pub instance: InstanceInfo,
    #[serde(rename = "AnalysisInfo")]
    pub analysis: AnalysisInfo,
    #[allow(dead_code)]
    #[serde(
        rename = "ExternalEntries",
        default,
        deserialize_with = "unwrap_external_entries"
    )]
    pub external_entries: Vec<ExternalEntry>,
    #[allow(dead_code)]
    #[serde(rename = "AuxiliaryData", default)]
    pub auxiliary_data: Vec<AuxiliaryData>,
    #[allow(dead_code)]
    #[serde(rename = "ExternalID", default)]
    pub external_ids: Vec<ExternalId>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct ContextFunction {
    #[serde(rename = "@name")]
    pub name: Option<String>,
    #[serde(rename = "@namespace")]
    pub namespace: Option<String>,
    #[serde(rename = "@enclosingClass")]
    pub enclosing_class: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct ClassIdentSymbol {
    #[serde(rename = "@name")]
    pub name: Option<String>,
    #[serde(rename = "@namespace")]
    pub namespace: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct ContextEntry {
    #[serde(rename = "@id")]
    pub id: Option<i32>,
    #[serde(rename = "Function")]
    pub function: Option<ContextFunction>,
    #[serde(rename = "ClassIdent")]
    pub class_ident: Option<ClassIdentSymbol>,
    #[serde(rename = "FunctionDeclarationSourceLocation")]
    pub function_decl_source_location: Option<SourceLocation>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Reference {
    #[serde(rename = "Title")]
    pub title: Option<String>,
    #[serde(rename = "Publisher")]
    pub publisher: Option<String>,
    #[serde(rename = "Author")]
    pub author: Option<String>,
    #[serde(rename = "Source")]
    pub source: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct CustomDescription {
    #[serde(rename = "@ruleID")]
    pub rule_id: Option<String>,
    #[serde(rename = "@header")]
    pub header: Option<String>,
    #[serde(rename = "@contentType")]
    pub content_type: Option<String>,
    #[serde(rename = "Abstract")]
    pub _abstract: Option<String>,
    #[serde(rename = "Explanation")]
    pub explanation: Option<String>,
    #[serde(rename = "Recommendations")]
    pub recommendations: Option<String>,
    #[serde(rename = "Tips", default, deserialize_with = "unwrap_tips")]
    pub tips: Vec<String>,
    #[serde(rename = "References", default, deserialize_with = "unwrap_references")]
    pub references: Vec<Reference>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Description {
    #[serde(rename = "@classID")]
    pub class_id: Option<String>,
    #[serde(rename = "@contentType")]
    pub content_type: Option<String>,
    #[serde(rename = "Abstract")]
    pub _abstract: Option<String>,
    #[serde(rename = "Explanation")]
    pub explanation: Option<String>,
    #[serde(rename = "Recommendations")]
    pub recommendations: Option<String>,
    #[serde(rename = "Details")]
    pub details: Option<String>,
    #[serde(rename = "Tips", default, deserialize_with = "unwrap_tips")]
    pub tips: Vec<String>,
    #[serde(rename = "References", default, deserialize_with = "unwrap_references")]
    pub references: Vec<Reference>,
    #[serde(rename = "CustomDescription", default)]
    pub custom_descriptions: Vec<CustomDescription>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct RulePack {
    #[serde(rename = "RulePackID")]
    pub rule_pack_id: Option<String>,
    #[serde(rename = "SKU")]
    pub sku: Option<String>,
    #[serde(rename = "Name")]
    pub name: Option<String>,
    #[serde(rename = "Version")]
    pub version: Option<String>,
    #[serde(rename = "MAC")]
    pub mac: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct RuleFile {
    #[serde(rename = "@version")]
    pub version: Option<String>,
    #[serde(rename = "@MAC")]
    pub mac: Option<String>,
    #[serde(rename = "$text")]
    pub path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RulePackList {
    #[serde(rename = "RulePack", default)]
    pub rule_packs: Vec<RulePack>,
    #[allow(dead_code)]
    #[serde(rename = "RuleFile", default)]
    pub rule_files: Vec<RuleFile>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct NameValuePair {
    #[serde(rename = "name")]
    pub name: Option<String>,
    #[serde(rename = "value")]
    pub value: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct PropertyList {
    #[serde(rename = "@type")]
    pub typ: Option<String>,
    #[serde(rename = "Property", default)]
    pub properties: Vec<NameValuePair>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Err {
    #[serde(rename = "@code")]
    pub code: Option<String>,
    #[serde(rename = "$text")]
    pub content: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct MachineInfo {
    #[serde(rename = "Hostname")]
    pub hostname: Option<String>,
    #[serde(rename = "Username")]
    pub username: Option<String>,
    #[serde(rename = "Platform")]
    pub platform: Option<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct FilterResult {
    #[serde(rename = "Instance", default)]
    pub instances: Vec<String>,
    #[serde(rename = "Rule", default)]
    pub rules: Vec<String>,
    #[serde(rename = "Category", default)]
    pub categories: Vec<String>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct EngineRuleEntry {
    #[serde(rename = "@id")]
    pub id: Option<String>,
    #[serde(rename = "MetaInfo", default, deserialize_with = "unwrap_meta_info")]
    pub meta_info: Vec<Group>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct Capability {
    #[serde(rename = "Name")]
    pub name: Option<String>,
    #[serde(rename = "Expiration")]
    pub expiration: Option<String>,
    #[serde(rename = "Attribute", default)]
    pub attributes: Vec<NameValuePair>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct LicenseInfo {
    #[serde(rename = "Metadata", default)]
    pub metadata: Vec<NameValuePair>,
    #[serde(rename = "Capability", default)]
    pub capabilities: Vec<Capability>,
}

#[derive(Debug, Deserialize)]
pub struct InactiveGrouping {
    #[allow(dead_code)]
    #[serde(rename = "@category")]
    pub category: Option<String>,
    #[serde(rename = "@count")]
    pub count: Option<i64>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
pub struct EngineData {
    #[serde(rename = "EngineVersion")]
    pub engine_version: Option<String>,
    #[serde(
        rename = "InactiveResults",
        default,
        deserialize_with = "unwrap_inactive_results"
    )]
    pub inactive_results: Vec<InactiveGrouping>,
    #[serde(rename = "RulePacks")]
    pub rule_packs: Option<RulePackList>,
    #[serde(rename = "ExpiredRulePacks")]
    pub expired_rule_packs: Option<RulePackList>,
    #[serde(rename = "UnlicensedRulePacks")]
    pub unlicensed_rule_packs: Option<RulePackList>,
    #[serde(rename = "Properties", default)]
    pub properties: Vec<PropertyList>,
    #[serde(
        rename = "CommandLine",
        default,
        deserialize_with = "unwrap_command_line"
    )]
    pub command_line: Vec<String>,
    #[serde(rename = "Errors", default, deserialize_with = "unwrap_err_msg")]
    pub errors: Vec<Err>,
    #[serde(rename = "MachineInfo")]
    pub machine_info: Option<MachineInfo>,
    #[serde(rename = "FilterResult")]
    pub filter_result: Option<FilterResult>,
    #[serde(rename = "RuleInfo", default, deserialize_with = "unwrap_rule_info")]
    pub rule_info: Vec<EngineRuleEntry>,
    #[serde(rename = "LicenseInfo")]
    pub license_info: Option<LicenseInfo>,
}

/// Lightweight metadata parsed from the FVDL root — excludes all large collections.
#[derive(Debug, Deserialize)]
pub struct FvdlMeta {
    #[serde(rename = "@version")]
    pub version: String,
    #[serde(rename = "CreatedTS")]
    pub created_ts: Option<TimeStamp>,
    #[allow(dead_code)]
    #[serde(rename = "WriteDate")]
    pub write_date: Option<TimeStamp>,
    #[allow(dead_code)]
    #[serde(rename = "ModifiedDate", default)]
    pub modified_dates: Vec<TimeStamp>,
    #[serde(rename = "UUID")]
    pub uuid: String,
    #[serde(rename = "Build")]
    pub build: Option<Build>,
}

/// Holds the raw decompressed FVDL bytes alongside a byte-range index of every
/// top-level element, built in a single `quick_xml` event scan at construction time.
/// Each accessor slices directly into `data` and deserialises only that window.
pub struct Fvdl {
    data: Vec<u8>,
    index: SectionIndex,
}

impl Fvdl {
    pub fn from_zip_entry<'a, R: Read>(mut entry: ZipFile<'a, R>) -> anyhow::Result<Self> {
        let mut data = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut data)?;
        let index = SectionIndex::build(&data)?;
        Ok(Self { data, index })
    }

    /// Parses lightweight scan metadata from the FVDL root element and its early children.
    /// This is the only accessor that re-reads from the beginning of `data` because
    /// `FvdlMeta` requires the `@version` attribute on the root `<FVDL>` element.
    pub fn meta(&self) -> anyhow::Result<FvdlMeta> {
        Ok(quick_xml::de::from_reader(self.data.as_slice())?)
    }

    pub fn vulnerabilities(&self) -> anyhow::Result<Vec<Vulnerability>> {
        #[derive(Deserialize)]
        struct W {
            #[serde(rename = "Vulnerability", default)]
            items: Vec<Vulnerability>,
        }
        let Some((s, e)) = self.index.first("Vulnerabilities") else {
            return Ok(vec![]);
        };
        Ok(quick_xml::de::from_reader::<_, W>(&self.data[s..e])?.items)
    }

    // `Description` appears once per rule at the top level; each is deserialized individually.
    pub fn descriptions(&self) -> anyhow::Result<Vec<Description>> {
        let ranges = self.index.all("Description");
        let mut result = Vec::with_capacity(ranges.len());
        for &(s, e) in ranges {
            result.push(quick_xml::de::from_reader::<_, Description>(
                &self.data[s..e],
            )?);
        }
        Ok(result)
    }

    pub fn unified_node_pool(&self) -> anyhow::Result<Vec<UnifiedPrimaryNode>> {
        #[derive(Deserialize)]
        struct W {
            #[serde(rename = "Node", default)]
            items: Vec<UnifiedPrimaryNode>,
        }
        let Some((s, e)) = self.index.first("UnifiedNodePool") else {
            return Ok(vec![]);
        };
        Ok(quick_xml::de::from_reader::<_, W>(&self.data[s..e])?.items)
    }

    pub fn engine_data(&self) -> anyhow::Result<Option<EngineData>> {
        let Some((s, e)) = self.index.first("EngineData") else {
            return Ok(None);
        };
        Ok(Some(quick_xml::de::from_reader::<_, EngineData>(
            &self.data[s..e],
        )?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_html_removes_tags() {
        assert_eq!(strip_html("<b>bold</b>"), "bold");
        assert_eq!(strip_html("no tags"), "no tags");
        assert_eq!(strip_html(r#"<a href="x">link</a>"#), "link");
        assert_eq!(strip_html("<br/>"), "");
        assert_eq!(strip_html(""), "");
    }

    #[test]
    fn decode_entities_named() {
        assert_eq!(decode_entities("&amp;"), "&");
        assert_eq!(decode_entities("&lt;"), "<");
        assert_eq!(decode_entities("&gt;"), ">");
        assert_eq!(decode_entities("&quot;"), "\"");
        assert_eq!(decode_entities("&apos;"), "'");
        assert_eq!(decode_entities("&#39;"), "'");
        assert_eq!(decode_entities("&nbsp;"), " ");
    }

    #[test]
    fn decode_entities_unknown_passthrough() {
        assert_eq!(decode_entities("&foo;"), "&foo;");
    }

    #[test]
    fn decode_entities_no_entities() {
        assert_eq!(decode_entities("hello world"), "hello world");
    }

    #[test]
    fn decode_entities_mixed() {
        assert_eq!(
            decode_entities("a &lt; b &amp;&amp; c &gt; d"),
            "a < b && c > d"
        );
    }

    #[test]
    fn attr_value_extracts_quoted_value() {
        assert_eq!(attr_value(r#"<Replace key="foo"/>"#, "key"), Some("foo"));
        assert_eq!(
            attr_value(r#"<tag name="bar" value="baz"/>"#, "value"),
            Some("baz")
        );
    }

    #[test]
    fn attr_value_missing_returns_none() {
        assert_eq!(attr_value("<Replace/>", "key"), None);
    }

    #[test]
    fn replacement_definitions_substitutes_known_key() {
        let rd = ReplacementDefinitions {
            defs: vec![Def {
                key: "name".to_owned(),
                value: "Alice".to_owned(),
                source_location: None,
            }],
            location_defs: vec![],
        };
        assert_eq!(rd.apply(r#"Hello <Replace key="name"/>!"#), "Hello Alice!");
    }

    #[test]
    fn replacement_definitions_unknown_key_falls_back_to_key() {
        let rd = ReplacementDefinitions {
            defs: vec![],
            location_defs: vec![],
        };
        assert_eq!(rd.apply(r#"<Replace key="x"/>"#), "x");
    }

    #[test]
    fn replacement_definitions_no_placeholders() {
        let rd = ReplacementDefinitions {
            defs: vec![],
            location_defs: vec![],
        };
        assert_eq!(rd.apply("plain text"), "plain text");
    }
}
