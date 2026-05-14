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
    if issuer_lc.contains(caa_value) {
        return true;
    }
    // Strip the registrable trailing label (e.g. ".org", ".com") to match
    // base names — "letsencrypt" in "let's encrypt".
    let base = caa_value
        .rsplit_once('.')
        .map(|(b, _)| b)
        .unwrap_or(caa_value);
    if !base.is_empty() && issuer_lc.contains(base) {
        return true;
    }
    // Curated aliases for well-known CAs.
    for (cv, aliases) in CA_ALIASES {
        if caa_value == *cv && aliases.iter().any(|a| issuer_lc.contains(a)) {
            return true;
        }
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
}
