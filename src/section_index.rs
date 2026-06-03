use std::collections::HashMap;

use quick_xml::{events::Event, Reader};

pub(crate) struct SectionIndex {
    sections: HashMap<String, Vec<(usize, usize)>>,
}

impl SectionIndex {
    pub(crate) fn build(data: &[u8]) -> anyhow::Result<Self> {
        let mut reader = Reader::from_reader(data);
        let mut sections: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
        let mut buf = Vec::new();
        let mut depth: usize = 0;
        let mut current: Option<(String, usize)> = None;

        loop {
            let pre = reader.buffer_position() as usize;
            match reader.read_event_into(&mut buf)? {
                Event::Start(tag) => {
                    if depth == 1 {
                        let name = std::str::from_utf8(tag.name().as_ref())
                            .unwrap_or("")
                            .to_owned();
                        current = Some((name, pre));
                    }
                    depth += 1;
                }
                Event::End(_) => {
                    depth -= 1;
                    if depth == 1 {
                        let post = reader.buffer_position() as usize;
                        if let Some((name, start)) = current.take() {
                            sections.entry(name).or_default().push((start, post));
                        }
                    }
                }
                Event::Empty(tag) => {
                    if depth == 1 {
                        let name = std::str::from_utf8(tag.name().as_ref())
                            .unwrap_or("")
                            .to_owned();
                        let post = reader.buffer_position() as usize;
                        sections.entry(name).or_default().push((pre, post));
                    }
                }
                Event::Eof => break,
                _ => {}
            }
            buf.clear();
        }

        Ok(Self { sections })
    }

    /// Byte range of the first occurrence of `tag`, or `None` if absent.
    pub(crate) fn first(&self, tag: &str) -> Option<(usize, usize)> {
        self.sections.get(tag)?.first().copied()
    }

    /// Byte ranges of all occurrences of `tag` in document order.
    pub(crate) fn all(&self, tag: &str) -> &[(usize, usize)] {
        self.sections.get(tag).map(Vec::as_slice).unwrap_or(&[])
    }
}
