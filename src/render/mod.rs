pub mod info;
pub mod list;
pub mod show;
pub mod statistics;

use crate::fvdl_reader::{
    AnalysisInfo, ReplacementDefinitions, UnifiedPrimaryNode, decode_entities, strip_html,
};

pub(crate) struct TraceNode<'a> {
    pub file: &'a str,
    pub line: i32,
    pub action: &'a str,
    pub rule_id: Option<&'a str>,
}

pub(crate) fn collect_trace_nodes<'a>(
    analysis: &'a AnalysisInfo,
    node_pool: &'a [UnifiedPrimaryNode],
) -> Vec<TraceNode<'a>> {
    analysis
        .unified
        .as_ref()
        .and_then(|u| u.traces.first())
        .map(|trace| {
            trace
                .primary
                .iter()
                .filter_map(|e| {
                    if let Some(node) = &e.node {
                        extract_node(node)
                    } else if let Some(ref_id) = e.node_ref_id {
                        node_pool
                            .iter()
                            .find(|n| n.id == Some(ref_id))
                            .and_then(extract_node)
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

fn extract_node(node: &UnifiedPrimaryNode) -> Option<TraceNode<'_>> {
    let loc = node.source_location.as_ref()?;
    Some(TraceNode {
        file: loc.path.as_deref().unwrap_or("?"),
        line: loc.line.unwrap_or(0),
        action: node
            .action
            .as_ref()
            .and_then(|a| a.content.as_deref())
            .unwrap_or("")
            .trim(),
        rule_id: node.reason.as_ref().and_then(|r| r.rule_id.as_deref()),
    })
}

pub(crate) fn apply_render(defs: Option<&ReplacementDefinitions>, text: &str) -> String {
    let substituted = defs
        .map(|d| d.apply(text))
        .unwrap_or_else(|| text.to_owned());
    decode_entities(&strip_html(&substituted))
}
