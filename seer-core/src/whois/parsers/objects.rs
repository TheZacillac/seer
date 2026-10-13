//! Shared reader for RPSL-style object replies: blank-line-separated objects
//! of `key: value` lines, each opened by its class key (`domain:`,
//! `contact:`, `nic-hdl:`, `nsset:`, …). Used by the FRED, AFNIC and SK-NIC parsers,
//! whose contact objects repeat domain labels (`created:`, `changed:`,
//! `eppstatus:`) that a flat label scan would mistake for the domain's.

static_regex! {
    // Keys may contain spaces (SK-NIC `Domain registrant:`).
    KEY_VALUE = r"^([A-Za-z][A-Za-z0-9 -]*?):[ \t]*(.*?)[ \t]*$";
}

/// One object: its `key: value` lines in order, keys lowercased.
pub(super) type Object<'a> = Vec<(String, &'a str)>;

/// Splits the reply into objects at blank lines, skipping `%` comments.
/// Lines that are not `key: value` (keys with spaces, prose) are skipped.
pub(super) fn objects(raw: &str) -> Vec<Object<'_>> {
    let mut out = Vec::new();
    let mut current: Object<'_> = Vec::new();
    for line in raw.lines() {
        let line = line.trim_end_matches('\r');
        if line.trim().is_empty() {
            if !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            continue;
        }
        if line.starts_with('%') {
            continue;
        }
        if let Some(caps) = KEY_VALUE.captures(line) {
            if let (Some(k), Some(v)) = (caps.get(1), caps.get(2)) {
                current.push((k.as_str().to_ascii_lowercase(), v.as_str()));
            }
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// The object's class: the key of its first line.
pub(super) fn class<'a>(object: &'a Object<'_>) -> Option<&'a str> {
    object.first().map(|(k, _)| k.as_str())
}

/// The first non-empty value for `key` in `object`.
pub(super) fn first<'a>(object: &Object<'a>, key: &str) -> Option<&'a str> {
    values(object, key).next()
}

/// Every non-empty value for `key` in `object`, in order.
pub(super) fn values<'a, 'o>(
    object: &'o Object<'a>,
    key: &'o str,
) -> impl Iterator<Item = &'a str> + 'o {
    object
        .iter()
        .filter(move |(k, v)| k == key && !v.is_empty())
        .map(|(_, v)| *v)
}

/// The object of class `class` whose opening value is `handle`
/// (case-insensitive): how a `registrant:` / `holder-c:` handle resolves to
/// its contact.
pub(super) fn find_by_handle<'o, 'a>(
    objects: &'o [Object<'a>],
    class_key: &str,
    handle: &str,
) -> Option<&'o Object<'a>> {
    objects.iter().find(|o| {
        o.first()
            .is_some_and(|(k, v)| k == class_key && v.eq_ignore_ascii_case(handle))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_at_blank_lines_and_skips_comments() {
        let raw = "% banner\r\ndomain: a.cz\r\nstatus: x\r\n\r\ncontact: H1\r\nname: N\r\n";
        let objs = objects(raw);
        assert_eq!(objs.len(), 2);
        assert_eq!(class(&objs[0]), Some("domain"));
        assert_eq!(first(&objs[1], "name"), Some("N"));
        assert_eq!(
            find_by_handle(&objs, "contact", "h1").map(|o| first(o, "name")),
            Some(Some("N"))
        );
    }
}
