use std::collections::BTreeMap;

/// Group `items` by `key`, then render them into `output` either as a flat
/// list (one group → no subheader) or as labeled blocks (multiple groups →
/// each gets a subheader line via `emit_subheader`).
///
/// Used by `format_propagation` in the human and markdown formatters to keep
/// the "consensus values / inconsistencies / nameserver-IP inconsistencies"
/// sections symmetric: when the section contains items of a single kind we
/// elide the per-kind subheader for compactness; multi-kind sections get one
/// labeled block per kind. The `nested` flag passed to `emit_item` tells the
/// caller whether to use deeper indentation / prefix.
///
/// Groups are emitted in `BTreeMap` key order so output is deterministic.
pub(super) fn render_grouped<T, F, G, H>(
    output: &mut Vec<String>,
    items: &[T],
    key: F,
    mut emit_subheader: G,
    mut emit_item: H,
) where
    F: Fn(&T) -> String,
    G: FnMut(&mut Vec<String>, &str),
    H: FnMut(&mut Vec<String>, &T, bool),
{
    let mut grouped: BTreeMap<String, Vec<&T>> = BTreeMap::new();
    for item in items {
        grouped.entry(key(item)).or_default().push(item);
    }

    let nested = grouped.len() > 1;
    for (header, group) in &grouped {
        if nested {
            emit_subheader(output, header);
        }
        for it in group {
            emit_item(output, it, nested);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_group_skips_subheader() {
        let items = vec!["a", "b", "c"];
        let mut out = Vec::new();
        render_grouped(
            &mut out,
            &items,
            |_| "G".to_string(),
            |o, h| o.push(format!("# {}", h)),
            |o, item, nested| o.push(format!("{}- {}", if nested { "  " } else { "" }, item)),
        );
        assert_eq!(out, vec!["- a", "- b", "- c"]);
    }

    #[test]
    fn multi_group_emits_subheaders_and_nested_indent() {
        let items = vec![("A", "1"), ("B", "2"), ("A", "3")];
        let mut out = Vec::new();
        render_grouped(
            &mut out,
            &items,
            |(k, _)| k.to_string(),
            |o, h| o.push(format!("# {}", h)),
            |o, (_, v), nested| o.push(format!("{}- {}", if nested { "  " } else { "" }, v)),
        );
        assert_eq!(out, vec!["# A", "  - 1", "  - 3", "# B", "  - 2",]);
    }
}
