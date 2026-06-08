use std::{collections::HashMap, io::Read};

use serde::Deserialize;
use zip::read::ZipFile;

#[derive(Deserialize)]
struct TagDefinitionXml {
    #[serde(rename = "@id")]
    id: String,
    #[serde(rename = "name")]
    name: String,
}

#[derive(Deserialize)]
struct FilterTemplateXml {
    #[serde(rename = "TagDefinition", default)]
    tag_definitions: Vec<TagDefinitionXml>,
}

/// Maps tag GUIDs to human-readable names parsed from filtertemplate.xml.
pub struct TagNameMap(HashMap<String, String>);

impl TagNameMap {
    pub fn empty() -> Self {
        Self(HashMap::new())
    }

    pub fn from_zip_entry<R: Read>(mut entry: ZipFile<'_, R>) -> anyhow::Result<Self> {
        let mut data = Vec::with_capacity(entry.size() as usize);
        entry.read_to_end(&mut data)?;
        let ft: FilterTemplateXml = quick_xml::de::from_reader(data.as_slice())?;
        let map = ft
            .tag_definitions
            .into_iter()
            .map(|td| (td.id, td.name))
            .collect();
        Ok(Self(map))
    }

    pub fn resolve<'a>(&'a self, guid: &'a str) -> &'a str {
        self.0.get(guid).map(String::as_str).unwrap_or(guid)
    }
}
