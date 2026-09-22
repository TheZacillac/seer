//! Public Suffix List helpers: registrable-domain detection.
//!
//! Registries sell names at "one label + public suffix" — `example.com`, but
//! also `example.co.uk`, `example.com.au`, `example.co.jp`. Splitting on the
//! last dot gets every multi-label suffix wrong, so callers that need the
//! registry-level boundary go through here instead. The list itself is the
//! `psl` crate's compiled-in snapshot of Mozilla's PSL (no runtime fetch).
//!
//! Only the **ICANN** section counts. Private-section entries (`github.io`,
//! `blogspot.com`, …) are hosting platforms, not registries: `foo.github.io`
//! cannot be registered at any registry — it is a name under the registered
//! domain `github.io`. Both callers want the registry view:
//!
//! - [`crate::confusables`] permutes the brand label, which for `github.io`
//!   is `github`, not the whole name.
//! - [`crate::availability`] must not call `mail.google.com` (or
//!   `foo.github.io`) "available" because the registry has no object by that
//!   exact name.
//!
//! Inputs are expected to be normalized (lowercase, A-label/punycode, no
//! trailing dot) — i.e. the output of [`crate::validation::normalize_domain`].
//! The PSL snapshot carries both punycode and Unicode forms of IDN suffixes,
//! and a TLD missing from it falls back to the PSL's implicit `*` rule (the
//! TLD alone is the suffix).

/// Returns the ICANN public suffix of `name`: `co.uk` for
/// `mail.example.co.uk`, `io` for `foo.github.io` (the private `github.io`
/// rule is skipped — see the module docs), `com` for `example.com`.
///
/// Returns `None` for input the list cannot classify (e.g. empty).
pub(crate) fn public_suffix(name: &str) -> Option<&str> {
    let mut candidate = name;
    loop {
        let suffix = ::psl::suffix(candidate.as_bytes())?.trim();
        // The suffix is a label-aligned tail of `candidate` (itself a tail of
        // `name`), so slicing by length keeps the borrow tied to `name`.
        let len = suffix.as_bytes().len();
        let start = candidate.len().checked_sub(len)?;
        let tail = candidate.get(start..)?;
        match suffix.typ() {
            // A private rule sits under an ICANN one: drop its leftmost
            // label and resolve the remainder again. Private rules always
            // have at least two labels, so this strictly shrinks.
            Some(::psl::Type::Private) => {
                let (_, rest) = tail.split_once('.')?;
                candidate = rest;
            }
            // ICANN rule, or the implicit `*` rule for an unlisted TLD.
            _ => return Some(tail),
        }
    }
}

/// Returns the registrable domain of `name` — one label plus its ICANN
/// public suffix: `example.co.uk` for `mail.example.co.uk`, `google.com` for
/// `mail.google.com`, `github.io` for `foo.github.io`.
///
/// Returns `None` when `name` is itself a public suffix (`co.uk`, `com`).
pub(crate) fn registrable_domain(name: &str) -> Option<&str> {
    let suffix = public_suffix(name)?;
    // `name` must be strictly longer than the suffix, with a dot at the join.
    let prefix = name.strip_suffix(suffix)?.strip_suffix('.')?;
    if prefix.is_empty() {
        return None;
    }
    let label = prefix.rsplit('.').next()?;
    let start = prefix.len() - label.len();
    name.get(start..)
}

/// Returns the registrable parent when `name` sits strictly *below* it
/// (`mail.google.com` → `google.com`). `None` when `name` is itself
/// registrable (`google.com`, `example.co.uk`) or is a bare public suffix.
pub(crate) fn registrable_parent(name: &str) -> Option<&str> {
    registrable_domain(name).filter(|reg| reg.len() < name.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_suffix_handles_multi_label_icann_suffixes() {
        assert_eq!(public_suffix("example.com"), Some("com"));
        assert_eq!(public_suffix("example.co.uk"), Some("co.uk"));
        assert_eq!(public_suffix("mail.example.com.au"), Some("com.au"));
        assert_eq!(public_suffix("example.co.jp"), Some("co.jp"));
        assert_eq!(public_suffix("example.com.br"), Some("com.br"));
    }

    #[test]
    fn public_suffix_skips_private_section_rules() {
        // github.io / blogspot.com are private-section PSL entries: hosting
        // platforms, not registries.
        assert_eq!(public_suffix("foo.github.io"), Some("io"));
        assert_eq!(public_suffix("github.io"), Some("io"));
        assert_eq!(public_suffix("foo.blogspot.co.uk"), Some("co.uk"));
    }

    #[test]
    fn public_suffix_falls_back_to_tld_for_unlisted_tlds() {
        assert_eq!(
            public_suffix("example.notarealtld-seer"),
            Some("notarealtld-seer")
        );
    }

    #[test]
    fn public_suffix_matches_punycode_idn_tlds() {
        // рф in A-label form (normalize_domain emits punycode).
        assert_eq!(public_suffix("example.xn--p1ai"), Some("xn--p1ai"));
    }

    #[test]
    fn registrable_domain_is_one_label_plus_suffix() {
        assert_eq!(registrable_domain("example.com"), Some("example.com"));
        assert_eq!(registrable_domain("mail.google.com"), Some("google.com"));
        assert_eq!(
            registrable_domain("a.b.example.co.uk"),
            Some("example.co.uk")
        );
        assert_eq!(registrable_domain("foo.github.io"), Some("github.io"));
    }

    #[test]
    fn registrable_domain_is_none_for_bare_suffixes() {
        assert_eq!(registrable_domain("com"), None);
        assert_eq!(registrable_domain("co.uk"), None);
        assert_eq!(registrable_domain(""), None);
    }

    #[test]
    fn registrable_parent_only_for_names_below_the_registrable_domain() {
        assert_eq!(registrable_parent("mail.google.com"), Some("google.com"));
        assert_eq!(
            registrable_parent("www.example.co.uk"),
            Some("example.co.uk")
        );
        assert_eq!(registrable_parent("foo.github.io"), Some("github.io"));
        assert_eq!(registrable_parent("google.com"), None);
        assert_eq!(registrable_parent("example.co.uk"), None);
        assert_eq!(registrable_parent("co.uk"), None);
    }
}
