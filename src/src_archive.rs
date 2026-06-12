use std::{collections::HashMap, fs::File, io::Read};

use quick_xml::{Reader, events::Event};
use zip::ZipArchive;

/// Parsed `src-archive/index.xml`: maps each logical source path to its zip entry name.
pub struct SrcArchive {
    index: HashMap<String, String>,
}

impl SrcArchive {
    pub fn from_zip(fpr: &mut ZipArchive<File>) -> anyhow::Result<Self> {
        let Some(idx) = fpr.index_for_name("src-archive/index.xml") else {
            return Ok(Self {
                index: HashMap::new(),
            });
        };
        let mut entry = fpr.by_index(idx)?;
        let mut xml = Vec::new();
        entry.read_to_end(&mut xml)?;
        drop(entry);
        Ok(Self {
            index: parse_index(&xml)?,
        })
    }

    /// Returns `(start_line, lines)` for `context` lines around `line` (1-based).
    /// `start_line` is the 1-based line number of the first returned line.
    pub fn snippet(
        &self,
        fpr: &mut ZipArchive<File>,
        path: &str,
        line: i32,
        context: usize,
    ) -> Option<(usize, Vec<String>)> {
        let entry_name = self.resolve_entry(path)?.to_owned();
        let mut zip_entry = fpr.by_name(&entry_name).ok()?;
        let mut content = String::new();
        zip_entry.read_to_string(&mut content).ok()?;

        let lines: Vec<&str> = content.lines().collect();
        let total = lines.len();
        let line_1 = line as usize;
        if line_1 == 0 || line_1 > total {
            return None;
        }
        let start = line_1.saturating_sub(context + 1);
        let end = (line_1 + context).min(total);
        Some((
            start + 1,
            lines[start..end].iter().map(|&l| l.to_owned()).collect(),
        ))
    }

    fn resolve_entry(&self, path: &str) -> Option<&str> {
        if let Some(v) = self.index.get(path) {
            return Some(v);
        }
        // Fallback: the FVDL path may include a leading source-root prefix not present in the index key
        self.index
            .iter()
            .find(|(k, _)| path.ends_with(k.as_str()) || k.ends_with(path))
            .map(|(_, v)| v.as_str())
    }
}

fn parse_index(xml: &[u8]) -> anyhow::Result<HashMap<String, String>> {
    let mut reader = Reader::from_reader(xml);
    let mut map = HashMap::new();
    let mut buf = Vec::new();
    let mut pending_key: Option<String> = None;

    loop {
        match reader.read_event_into(&mut buf)? {
            Event::Start(tag) if tag.local_name().as_ref() == b"entry" => {
                let key = tag
                    .attributes()
                    .filter_map(|a| a.ok())
                    .find(|a| a.key.as_ref() == b"key")
                    .and_then(|a| std::str::from_utf8(a.value.as_ref()).ok().map(str::to_owned));
                pending_key = key;
            }
            Event::Text(text) => {
                if let Some(key) = pending_key.take() {
                    map.insert(key, text.decode()?.into_owned());
                }
            }
            Event::Eof => break,
            _ => {}
        }
        buf.clear();
    }

    Ok(map)
}
