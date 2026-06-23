use std::collections::HashMap;

use quick_xml::{Reader, events::Event};

pub(crate) struct SectionIndex {
    sections: HashMap<String, Vec<(usize, usize)>>,
}

impl SectionIndex {
    pub(crate) fn build(data: &[u8]) -> anyhow::Result<Self> {
        fn tag_name(tag: &quick_xml::events::BytesStart<'_>) -> String {
            std::str::from_utf8(tag.name().as_ref())
                .unwrap_or("")
                .to_owned()
        }

        let mut reader = Reader::from_reader(data);
        let mut sections: HashMap<String, Vec<(usize, usize)>> = HashMap::new();
        let mut buf = Vec::new();
        let mut depth: usize = 0;
        let mut current: Option<(String, usize)> = None;

        loop {
            let pre = reader.buffer_position() as usize;
            match reader.read_event_into(&mut buf)? {
                Event::Start(ref tag) => {
                    if depth == 1 {
                        current = Some((tag_name(tag), pre));
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
                Event::Empty(ref tag) => {
                    if depth == 1 {
                        let post = reader.buffer_position() as usize;
                        sections.entry(tag_name(tag)).or_default().push((pre, post));
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_returns_slice_containing_element_content() {
        let xml = b"<Root><Alpha>hello</Alpha><Beta>world</Beta></Root>";
        let idx = SectionIndex::build(xml).unwrap();
        let (s, e) = idx.first("Alpha").unwrap();
        let slice = std::str::from_utf8(&xml[s..e]).unwrap();
        assert!(slice.contains("hello"));
        assert!(!slice.contains("world"));
    }

    #[test]
    fn all_returns_all_occurrences() {
        let xml = b"<Root><Foo>a</Foo><Bar>x</Bar><Foo>b</Foo></Root>";
        let idx = SectionIndex::build(xml).unwrap();
        assert_eq!(idx.all("Foo").len(), 2);
        assert_eq!(idx.all("Bar").len(), 1);
    }

    #[test]
    fn absent_tag_returns_none_and_empty() {
        let xml = b"<Root><Foo>hello</Foo></Root>";
        let idx = SectionIndex::build(xml).unwrap();
        assert!(idx.first("Missing").is_none());
        assert!(idx.all("Missing").is_empty());
    }

    #[test]
    fn self_closing_tag_is_indexed() {
        let xml = b"<Root><Empty/></Root>";
        let idx = SectionIndex::build(xml).unwrap();
        assert!(idx.first("Empty").is_some());
    }
}
