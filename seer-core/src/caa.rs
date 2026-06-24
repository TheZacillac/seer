//! CAA (Certification Authority Authorization) lookup and policy comparison.
//!
//! CAA records (RFC 8659) let domain owners declare which Certificate
//! Authorities may issue certificates for the domain. They are consulted
//! by CAs at issuance time only; they are *not* part of certificate
//! validation. A presented certificate whose issuer is not in the current
//! CAA policy is therefore not necessarily invalid — it may have been
//! issued before the policy was updated, or via a parent zone. See
//! [`ISSUANCE_TIME_NOTE`].

use serde::{Deserialize, Serialize};

use crate::dns::{DnsResolver, RecordData, RecordType};

/// Informational note surfaced alongside every CAA report.
///
/// Explains why an issuer/CAA mismatch is not the same as an invalid cert.
pub const ISSUANCE_TIME_NOTE: &str = "CAA is checked by CAs at issuance time, not by \
clients at validation time. A cert whose issuer is not in the current CAA policy is \
not invalid — it may have been issued before the policy was set, or under a parent \
zone. Treat mismatches as informational.";

/// A single CAA resource record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaaRecord {
    /// CAA flags (only `issuer_critical` = 128 is defined).
    pub flags: u8,
    /// Property tag (e.g., `issue`, `issuewild`, `iodef`).
    pub tag: String,
    /// Property value (e.g., `letsencrypt.org` or a URI for `iodef`).
    pub value: String,
}

/// Result of how a presented cert's issuer relates to the CAA policy.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IssuerCaaMatch {
    /// No CAA records exist (any CA may issue per default).
    NoPolicy,
    /// CAA records exist and at least one `issue`/`issuewild` value plausibly
    /// matches the presented issuer.
    Permitted,
    /// CAA records exist but none of the allowed CAs appear to match the
    /// presented issuer. Informational, not a validation failure.
    Mismatch,
    /// CAA records exist but only contain `iodef` / unknown tags — no
    /// authoritative answer about issuance.
    Indeterminate,
}

/// CAA policy collected for a domain, plus the informational note that
/// callers should surface to users.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CaaPolicy {
    /// Records discovered (may be empty if no policy is set).
    pub records: Vec<CaaRecord>,
    /// Domain at which the records were found. Per RFC 8659 the resolver
    /// climbs the tree until a CAA RRset is encountered, so this may be a
    /// parent of the queried name.
    pub effective_domain: Option<String>,
    /// True iff at least one CAA record was found in the tree-walk.
    pub has_policy: bool,
    /// Result of comparing a presented cert's issuer against the policy.
    /// `None` if no cert was supplied for comparison.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer_match: Option<IssuerCaaMatch>,
    /// Informational note about CAA semantics. Always populated.
    pub note: String,
}

impl CaaPolicy {
    /// Empty policy — used when no CAA records were found anywhere in the tree.
    pub fn empty() -> Self {
        Self {
            records: Vec::new(),
            effective_domain: None,
            has_policy: false,
            issuer_match: None,
            note: ISSUANCE_TIME_NOTE.to_string(),
        }
    }
}

/// Looks up CAA records for `domain`, climbing the DNS tree per RFC 8659
/// section 3 until a record set is found or only a TLD remains.
///
/// Returns an [`CaaPolicy::empty`] on resolver errors — CAA is advisory,
/// so we never want to fail a higher-level check just because a CAA query
/// did not return.
pub async fn lookup_caa(resolver: &DnsResolver, domain: &str) -> CaaPolicy {
    let mut current = domain.trim_end_matches('.').to_ascii_lowercase();

    loop {
        match resolver.resolve(&current, RecordType::CAA, None).await {
            Ok(records) if !records.is_empty() => {
                let caa: Vec<CaaRecord> = records
                    .into_iter()
                    .filter_map(|r| match r.data {
                        RecordData::CAA { flags, tag, value } => Some(CaaRecord {
                            flags,
                            tag: tag.to_ascii_lowercase(),
                            value,
                        }),
                        _ => None,
                    })
                    .collect();

                if !caa.is_empty() {
                    return CaaPolicy {
                        has_policy: true,
                        records: caa,
                        effective_domain: Some(current),
                        issuer_match: None,
                        note: ISSUANCE_TIME_NOTE.to_string(),
                    };
                }
            }
            Ok(_) | Err(_) => {}
        }

        // Strip the leftmost label. Stop when only one label (TLD) remains.
        match current.split_once('.') {
            Some((_, rest)) if rest.contains('.') => current = rest.to_string(),
            _ => return CaaPolicy::empty(),
        }
    }
}

/// Compares a presented certificate's issuer string against a CAA policy
/// and returns a classification. Pure function — no I/O.
pub fn classify_issuer(issuer: &str, policy: &CaaPolicy) -> IssuerCaaMatch {
    if !policy.has_policy {
        return IssuerCaaMatch::NoPolicy;
    }

    // RFC 8659 §4.1: if any CAA record has the Issuer Critical flag (bit 7,
    // 0x80) set AND its tag is unknown to us, the spec mandates that
    // issuance be treated as forbidden — we cannot honor a critical
    // property we don't understand. Surface that as `Mismatch` so callers
    // see a non-permitted verdict.
    const KNOWN_TAGS: &[&str] = &["issue", "issuewild", "iodef"];
    let critical_unknown = policy
        .records
        .iter()
        .any(|r| (r.flags & 0x80) != 0 && !KNOWN_TAGS.contains(&r.tag.as_str()));
    if critical_unknown {
        return IssuerCaaMatch::Mismatch;
    }

    let issue_values: Vec<String> = policy
        .records
        .iter()
        .filter(|r| r.tag == "issue" || r.tag == "issuewild")
        .map(|r| {
            // RFC 8659 §4.2: value is "<CA domain> [; <parameters>]". We
            // only need the domain portion for matching.
            r.value
                .split(';')
                .next()
                .unwrap_or(&r.value)
                .trim()
                .to_ascii_lowercase()
        })
        .collect();

    if issue_values.is_empty() {
        return IssuerCaaMatch::Indeterminate;
    }

    let issuer_lc = issuer.to_ascii_lowercase();
    let allowed_any = issue_values.iter().any(|v| !v.is_empty());

    let matched = issue_values
        .iter()
        .any(|v| !v.is_empty() && ca_value_matches_issuer(v, &issuer_lc));

    if matched {
        IssuerCaaMatch::Permitted
    } else if allowed_any {
        IssuerCaaMatch::Mismatch
    } else {
        // Only entries are empty-value (";") — issuance is explicitly forbidden,
        // yet a cert exists. Report as mismatch with the informational note.
        IssuerCaaMatch::Mismatch
    }
}

/// Best-effort comparison between a CAA `issue` value (a CA's domain) and a
/// certificate issuer string (typically a CN/O like "Let's Encrypt").
///
/// CAA values are short reverse-DNS-ish labels; issuer strings vary by CA.
/// We use a small alias table for the common public CAs and fall back to a
/// direct substring check.
fn ca_value_matches_issuer(caa_value: &str, issuer_lc: &str) -> bool {
    // 1. The CAA value appears verbatim in the issuer (e.g. "ssl.com"), but
    //    only when it is long enough AND lands on a word boundary. A
    //    pathologically short value ("ca", "ssl") would otherwise blanket-match
    //    any issuer that merely contains those letters — the same over-match the
    //    base-label fallback guards against (issue #56). Length is gated by
    //    MIN_FALLBACK_BASE_LEN so the verbatim and base paths share one bar.
    if caa_value.len() >= MIN_FALLBACK_BASE_LEN && contains_word(issuer_lc, caa_value) {
        return true;
    }
    // 2. Curated aliases for well-known CAs — preferred over the generic base
    //    fallback so a precise mapping wins (e.g. "ssl.com" -> "ssl.com",
    //    never bare "ssl").
    for (cv, aliases) in CA_ALIASES {
        if caa_value == *cv && aliases.iter().any(|a| issuer_lc.contains(a)) {
            return true;
        }
    }
    // 3. Generic fallback for CAs not in the alias table: the base label (the
    //    CAA value minus its trailing TLD) appears in the issuer AS A WHOLE
    //    WORD. Guarded by a minimum length so a short, ambiguous base — "ssl"
    //    from "ssl.com" — can't collide with unrelated issuer text like
    //    "...SSL CA..." and report a genuine mismatch as Permitted (issue #56).
    let base = caa_value
        .rsplit_once('.')
        .map(|(b, _)| b)
        .unwrap_or(caa_value);
    base.len() >= MIN_FALLBACK_BASE_LEN && contains_word(issuer_lc, base)
}

/// Minimum base-label length for the generic substring fallback in
/// [`ca_value_matches_issuer`]. Shorter bases (e.g. "ssl", "ca", "pki") are too
/// ambiguous to match by substring and must go through the curated alias table
/// or a verbatim value match instead.
const MIN_FALLBACK_BASE_LEN: usize = 6;

/// Returns true if `needle` occurs in `haystack` as a whole word — i.e. bounded
/// by string start/end or a non-alphanumeric character on each side — so a base
/// like "examplecorp" matches "ExampleCorp Root" but not "NotExamplecorporated".
/// Both arguments are expected lowercase.
fn contains_word(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() {
        return false;
    }
    let bytes = haystack.as_bytes();
    let mut from = 0;
    while let Some(rel) = haystack[from..].find(needle) {
        let start = from + rel;
        let end = start + needle.len();
        let before_ok = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let after_ok = end == bytes.len() || !bytes[end].is_ascii_alphanumeric();
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

/// Hand-maintained map from common CAA `issue` values to substrings that
/// frequently appear in the issuer CN/O of certs from that CA.
const CA_ALIASES: &[(&str, &[&str])] = &[
    ("letsencrypt.org", &["let's encrypt", "letsencrypt"]),
    ("pki.goog", &["google trust services", "gts "]),
    ("digicert.com", &["digicert"]),
    ("sectigo.com", &["sectigo", "comodo"]),
    ("globalsign.com", &["globalsign"]),
    ("amazon.com", &["amazon"]),
    ("amazontrust.com", &["amazon"]),
    ("zerossl.com", &["zerossl"]),
    ("buypass.com", &["buypass"]),
    ("entrust.net", &["entrust"]),
    ("ssl.com", &["ssl.com"]),
    ("certum.pl", &["certum"]),
    ("identrust.com", &["identrust"]),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_with(records: Vec<(&str, &str)>) -> CaaPolicy {
        CaaPolicy {
            records: records
                .into_iter()
                .map(|(tag, value)| CaaRecord {
                    flags: 0,
                    tag: tag.to_string(),
                    value: value.to_string(),
                })
                .collect(),
            effective_domain: Some("example.com".to_string()),
            has_policy: true,
            issuer_match: None,
            note: ISSUANCE_TIME_NOTE.to_string(),
        }
    }

    #[test]
    fn classify_no_policy() {
        assert_eq!(
            classify_issuer("Let's Encrypt R3", &CaaPolicy::empty()),
            IssuerCaaMatch::NoPolicy
        );
    }

    #[test]
    fn classify_indeterminate_when_only_iodef() {
        let policy = policy_with(vec![("iodef", "mailto:sec@example.com")]);
        assert_eq!(
            classify_issuer("Let's Encrypt R3", &policy),
            IssuerCaaMatch::Indeterminate
        );
    }

    #[test]
    fn classify_permitted_letsencrypt() {
        let policy = policy_with(vec![("issue", "letsencrypt.org")]);
        assert_eq!(
            classify_issuer("CN=R3, O=Let's Encrypt", &policy),
            IssuerCaaMatch::Permitted
        );
    }

    #[test]
    fn classify_permitted_via_alias() {
        // Issuer CN/O does not literally contain "pki.goog"; alias table
        // maps it to "Google Trust Services".
        let policy = policy_with(vec![("issue", "pki.goog")]);
        assert_eq!(
            classify_issuer("CN=GTS CA 1C3, O=Google Trust Services LLC", &policy),
            IssuerCaaMatch::Permitted
        );
    }

    #[test]
    fn classify_mismatch_when_only_other_ca_allowed() {
        let policy = policy_with(vec![("issue", "digicert.com")]);
        assert_eq!(
            classify_issuer("CN=R3, O=Let's Encrypt", &policy),
            IssuerCaaMatch::Mismatch
        );
    }

    #[test]
    fn classify_verbatim_match_is_length_guarded() {
        // A pathologically short CAA `issue` value (here "ca") must not
        // blanket-match an unrelated issuer just because the two letters appear
        // verbatim somewhere in the issuer string. The verbatim path is now
        // length-guarded just like the base-label fallback (issue #56 follow-up).
        let policy = policy_with(vec![("issue", "ca")]);
        assert_eq!(
            classify_issuer("CN=Verisign Class 3 CA, O=Symantec", &policy),
            IssuerCaaMatch::Mismatch,
            "two-letter verbatim CAA value must not over-match unrelated issuers"
        );
    }

    #[test]
    fn classify_full_domain_verbatim_still_matches() {
        // A real, full-domain CAA value that appears verbatim in the issuer is
        // still Permitted — the length guard must not break the common case.
        let policy = policy_with(vec![("issue", "letsencrypt.org")]);
        assert_eq!(
            classify_issuer("CN=R3, O=letsencrypt.org", &policy),
            IssuerCaaMatch::Permitted,
            "full-domain verbatim value must still match"
        );
    }

    #[test]
    fn classify_does_not_overmatch_short_base_substring() {
        // CAA `issue "ssl.com"` must NOT mark an unrelated issuer that merely
        // contains the substring "ssl" as permitted — the base "ssl" is too
        // short/ambiguous for the generic fallback (issue #56).
        let policy = policy_with(vec![("issue", "ssl.com")]);
        assert_eq!(
            classify_issuer("CN=WoanWolf SSL Root CA, O=Other", &policy),
            IssuerCaaMatch::Mismatch,
            "bare 'ssl' substring must not over-match"
        );
        // The genuine SSL.com issuer (value appears verbatim) is still permitted.
        assert_eq!(
            classify_issuer("CN=SSL.com RSA SSL subCA, O=SSL Corp", &policy),
            IssuerCaaMatch::Permitted
        );
    }

    #[test]
    fn classify_unknown_ca_base_matches_only_on_word_boundary() {
        // A long, distinctive base still matches via the guarded fallback — but
        // only as a whole word, never buried inside a larger token (issue #56).
        let policy = policy_with(vec![("issue", "examplecorp.test")]);
        assert_eq!(
            classify_issuer("CN=ExampleCorp Root, O=ExampleCorp", &policy),
            IssuerCaaMatch::Permitted
        );
        assert_eq!(
            classify_issuer("CN=NotExamplecorporated CA", &policy),
            IssuerCaaMatch::Mismatch,
            "base inside a larger word must not match"
        );
    }

    #[test]
    fn classify_mismatch_when_issuance_forbidden() {
        // A bare `issue ";"` forbids all issuance, yet a cert exists.
        let policy = policy_with(vec![("issue", ";")]);
        assert_eq!(
            classify_issuer("CN=R3, O=Let's Encrypt", &policy),
            IssuerCaaMatch::Mismatch
        );
    }

    #[test]
    fn classify_issuewild_treated_like_issue() {
        let policy = policy_with(vec![("issuewild", "letsencrypt.org")]);
        assert_eq!(
            classify_issuer("CN=R3, O=Let's Encrypt", &policy),
            IssuerCaaMatch::Permitted
        );
    }

    #[test]
    fn empty_policy_has_no_issuer_match_set() {
        let p = CaaPolicy::empty();
        assert!(p.records.is_empty());
        assert!(!p.has_policy);
        assert!(p.issuer_match.is_none());
        assert_eq!(p.note, ISSUANCE_TIME_NOTE);
    }

    /// RFC 8659 §4.1: a CAA record carrying an unknown tag with the Issuer
    /// Critical flag (bit 7 of `flags`) set MUST be treated as forbidding
    /// issuance — we cannot honor a critical property we don't understand.
    #[test]
    fn classify_unknown_critical_tag_forces_mismatch() {
        let policy = CaaPolicy {
            records: vec![
                // Valid issue that would otherwise match Let's Encrypt.
                CaaRecord {
                    flags: 0,
                    tag: "issue".to_string(),
                    value: "letsencrypt.org".to_string(),
                },
                // Unknown tag with critical flag — must veto issuance.
                CaaRecord {
                    flags: 0x80,
                    tag: "auth".to_string(),
                    value: "future-extension".to_string(),
                },
            ],
            effective_domain: Some("example.com".to_string()),
            has_policy: true,
            issuer_match: None,
            note: ISSUANCE_TIME_NOTE.to_string(),
        };
        assert_eq!(
            classify_issuer("CN=R3, O=Let's Encrypt", &policy),
            IssuerCaaMatch::Mismatch,
            "critical unknown tag must veto otherwise-matching issue"
        );
    }

    #[test]
    fn classify_unknown_non_critical_tag_does_not_veto() {
        // Same shape but flags = 0 (non-critical). Per RFC the unknown tag
        // is ignored; the matching `issue` carries through.
        let policy = CaaPolicy {
            records: vec![
                CaaRecord {
                    flags: 0,
                    tag: "issue".to_string(),
                    value: "letsencrypt.org".to_string(),
                },
                CaaRecord {
                    flags: 0,
                    tag: "auth".to_string(),
                    value: "future-extension".to_string(),
                },
            ],
            effective_domain: Some("example.com".to_string()),
            has_policy: true,
            issuer_match: None,
            note: ISSUANCE_TIME_NOTE.to_string(),
        };
        assert_eq!(
            classify_issuer("CN=R3, O=Let's Encrypt", &policy),
            IssuerCaaMatch::Permitted
        );
    }

    #[test]
    fn classify_critical_known_tag_does_not_veto() {
        // A critical `issue` (a known tag) is just a normal critical-issue.
        // It must NOT trip the unknown-critical veto.
        let policy = CaaPolicy {
            records: vec![CaaRecord {
                flags: 0x80,
                tag: "issue".to_string(),
                value: "letsencrypt.org".to_string(),
            }],
            effective_domain: Some("example.com".to_string()),
            has_policy: true,
            issuer_match: None,
            note: ISSUANCE_TIME_NOTE.to_string(),
        };
        assert_eq!(
            classify_issuer("CN=R3, O=Let's Encrypt", &policy),
            IssuerCaaMatch::Permitted
        );
    }
}
