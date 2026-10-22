//! DKIM selector probing.
//!
//! DKIM keys live at `<selector>._domainkey.<domain>`, and selectors are not
//! discoverable from DNS, so this probes the common ones ([`DKIM_SELECTORS`])
//! concurrently, each bounded by one deadline. It can confirm a key exists
//! and grade its size (RSA below 1024 bits is forgeable; 1024 is weak), but
//! it can never prove absence: a domain may sign with a selector not in the
//! table. Consumers must treat "none found" as informational.
//!
//! Each selector is one TXT query through [`DnsResolver::resolve`]
//! (NXDOMAIN/NODATA → absent, a resolver error → unknown). Parsing is pure.

use std::time::Duration;

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use x509_parser::prelude::FromDer as _;
use x509_parser::x509::SubjectPublicKeyInfo;

use crate::dns::{DnsResolver, RecordData, RecordType};
use crate::error::Result;
use crate::validation::normalize_domain;

/// Common DKIM selectors (mail providers and defaults). Sorted and unique —
/// enforced by a test; extend here, never in a copy.
pub const DKIM_SELECTORS: &[&str] = &[
    "default",
    "dkim",
    "everlytickey1",
    "everlytickey2",
    "google",
    "k1",
    "k2",
    "k3",
    "mail",
    "mandrill",
    "mxvault",
    "protonmail",
    "s1",
    "s2",
    "selector1",
    "selector2",
    "sig1",
    "smtp",
    "zoho",
];

/// Default bound on the whole probe.
pub const DEFAULT_DKIM_DEADLINE: Duration = Duration::from_secs(10);

/// The key algorithm (`k=`, default `rsa`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DkimKeyType {
    Rsa,
    Ed25519,
    Other,
}

/// What one selector holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case")]
pub enum SelectorState {
    /// NXDOMAIN/NODATA, or no DKIM record among the TXT strings.
    Absent,
    /// The query failed; nothing is known.
    Unknown { reason: String },
    /// `p=` is empty: the key was revoked (RFC 6376 §3.6.1).
    Revoked,
    /// A published key. `bits` is `None` when the key could not be decoded.
    Key {
        key_type: DkimKeyType,
        #[serde(skip_serializing_if = "Option::is_none")]
        bits: Option<u32>,
        /// `t=y`: the domain is testing DKIM; verifiers may ignore failures.
        testing: bool,
    },
}

/// One probed selector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkimSelector {
    pub selector: String,
    #[serde(flatten)]
    pub state: SelectorState,
}

/// The result of probing [`DKIM_SELECTORS`] for a domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DkimReport {
    pub domain: String,
    /// How many selectors were probed.
    pub probed: usize,
    /// Selectors that were not absent (keys, revocations, failed queries).
    pub selectors: Vec<DkimSelector>,
}

/// Probes every selector in [`DKIM_SELECTORS`] for `domain`.
///
/// # Errors
/// `InvalidDomain` only; per-selector failures are [`SelectorState::Unknown`].
pub async fn probe_dkim(
    resolver: &DnsResolver,
    domain: &str,
    deadline: Duration,
) -> Result<DkimReport> {
    let domain = normalize_domain(domain)?;
    let queries = DKIM_SELECTORS.iter().map(|selector| {
        let name = format!("{selector}._domainkey.{domain}");
        async move {
            let state = match tokio::time::timeout(
                deadline,
                resolver.resolve(&name, RecordType::TXT, None),
            )
            .await
            {
                Err(_) => SelectorState::Unknown {
                    reason: "deadline exceeded".to_string(),
                },
                Ok(Err(e)) => {
                    tracing::debug!(%name, error = %e, "dkim selector query failed");
                    SelectorState::Unknown {
                        reason: e.sanitized_message(),
                    }
                }
                Ok(Ok(records)) => records
                    .iter()
                    .filter_map(|r| match &r.data {
                        RecordData::TXT { text, .. } => parse_record(text),
                        _ => None,
                    })
                    .next()
                    .unwrap_or(SelectorState::Absent),
            };
            DkimSelector {
                selector: (*selector).to_string(),
                state,
            }
        }
    });
    let selectors = futures::future::join_all(queries)
        .await
        .into_iter()
        .filter(|s| s.state != SelectorState::Absent)
        .collect();
    Ok(DkimReport {
        domain,
        probed: DKIM_SELECTORS.len(),
        selectors,
    })
}

/// Parses one TXT record; `None` when it is not a DKIM key record (no `p=`).
pub(crate) fn parse_record(txt: &str) -> Option<SelectorState> {
    let mut key_type = DkimKeyType::Rsa;
    let mut public_key: Option<String> = None;
    let mut testing = false;
    for tag in txt.split(';') {
        let Some((name, value)) = tag.split_once('=') else {
            continue;
        };
        let value: String = value.chars().filter(|c| !c.is_whitespace()).collect();
        match name.trim().to_ascii_lowercase().as_str() {
            "k" => {
                key_type = match value.to_ascii_lowercase().as_str() {
                    "rsa" => DkimKeyType::Rsa,
                    "ed25519" => DkimKeyType::Ed25519,
                    _ => DkimKeyType::Other,
                }
            }
            "p" => public_key = Some(value),
            "t" => testing = value.split(':').any(|flag| flag.eq_ignore_ascii_case("y")),
            _ => {}
        }
    }
    let public_key = public_key?;
    if public_key.is_empty() {
        return Some(SelectorState::Revoked);
    }
    let der = base64::engine::general_purpose::STANDARD
        .decode(public_key.as_bytes())
        .ok();
    let bits = match key_type {
        DkimKeyType::Rsa => der.as_deref().and_then(rsa_bits),
        DkimKeyType::Ed25519 => der.filter(|k| k.len() == 32).map(|_| 256),
        DkimKeyType::Other => None,
    };
    Some(SelectorState::Key {
        key_type,
        bits,
        testing,
    })
}

/// RSA modulus size from a SubjectPublicKeyInfo DER blob.
fn rsa_bits(der: &[u8]) -> Option<u32> {
    let (_, spki) = SubjectPublicKeyInfo::from_der(der).ok()?;
    crate::ssl::extract_key_info(&spki).1
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::test_support::{mock_dns_resolver_default, spawn_mock_dns_fn, MockReply};
    use hickory_resolver::proto::op::ResponseCode;
    use hickory_resolver::proto::rr::rdata as wire;
    use hickory_resolver::proto::rr::{RData, RecordType as WireType};

    // `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:N | openssl pkey -pubout -outform DER | base64 -w0`
    const RSA_512: &str = "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOeQ6SWKJlm1QOVUHTi4A8QtjWZLZ9owHWx00T838aweoQzlqmNou2ZW+eVqC+am0EQtsYGL43Sashay0OvjD8cCAwEAAQ==";
    const RSA_1024: &str = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+as2gvWHcF9xJ5MsGInI1t6YVgMf8n48Ngb1VhLRDlxfqIB3GFzE8WV9wMAWqrL4yQFSk5ICoEOKnvodzxH+eU89mNnwHZ9GIjnIP1L753zDugwE2moH81tXJolqTeQGWtv4Ea/S8PKZXgiTGojqo41WEhzWq+RX3+TIxzcHAvQIDAQAB";
    const RSA_2048: &str = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArkP2vb3GUcpty40YUqoTQxV65uIwjl/Yx/+5ghSXTSF2lxs6U24rhMdp+2qxZ7kF9erXJ/WYjz70jtFVVAu/dYjI1P+veDIevfWuEhl0kwRdM0RhQin0hJEGIa0RPepEz3zm5W1Wm5SWMFb9X9CuSdOL1z1m1lWZDM6kE34ajTK9Z/5NRtmykyA3Qn7YuVlyMMNRa+6MefUt2QPCuP2c4/UKnNGSpoFZZdzX06uuozipASjQ0H5FvbNvb/OEmpa0+rGgLCaVKn9gkjsNPRGR5StWEKzHT+eIqKf/NJV3tqiwKJ227zsiA0v1lqqy4z56e0FG4RES3+NpZUMBAWoSrQIDAQAB";

    /// A TXT answer split into 255-byte character-strings, as DNS requires.
    fn txt(value: &str) -> MockReply {
        let chunks = value
            .as_bytes()
            .chunks(255)
            .map(|c| String::from_utf8(c.to_vec()).unwrap())
            .collect();
        MockReply::Answer(vec![RData::TXT(wire::TXT::new(chunks))])
    }

    fn key(state: &SelectorState) -> (DkimKeyType, Option<u32>, bool) {
        match state {
            SelectorState::Key {
                key_type,
                bits,
                testing,
            } => (*key_type, *bits, *testing),
            other => panic!("expected a key, got {other:?}"),
        }
    }

    #[test]
    fn selector_table_is_sorted_and_unique() {
        let mut sorted = DKIM_SELECTORS.to_vec();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted, DKIM_SELECTORS);
    }

    #[test]
    fn parses_rsa_key_sizes() {
        for (b64, bits) in [(RSA_512, 512), (RSA_1024, 1024), (RSA_2048, 2048)] {
            let state = parse_record(&format!("v=DKIM1; k=rsa; p={b64}")).unwrap();
            assert_eq!(key(&state), (DkimKeyType::Rsa, Some(bits), false));
        }
    }

    #[test]
    fn rsa_is_the_default_key_type_and_t_y_is_testing() {
        let state = parse_record(&format!("v=DKIM1; t=y:s; p={RSA_2048}")).unwrap();
        assert_eq!(key(&state), (DkimKeyType::Rsa, Some(2048), true));
    }

    #[test]
    fn ed25519_empty_p_and_non_dkim_records() {
        let ed = parse_record("v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=")
            .unwrap();
        assert_eq!(key(&ed), (DkimKeyType::Ed25519, Some(256), false));
        assert_eq!(parse_record("v=DKIM1; p="), Some(SelectorState::Revoked));
        assert_eq!(parse_record("v=spf1 -all"), None);
    }

    #[test]
    fn undecodable_rsa_key_has_unknown_size() {
        let state = parse_record("v=DKIM1; k=rsa; p=not-base64!!").unwrap();
        assert_eq!(key(&state), (DkimKeyType::Rsa, None, false));
    }

    #[tokio::test]
    async fn probes_selectors_and_reports_found_and_unknown() {
        let port = spawn_mock_dns_fn(|qname, qtype| match (qname, qtype) {
            ("selector1._domainkey.mail.test", WireType::TXT) => {
                txt(&format!("v=DKIM1; k=rsa; p={RSA_2048}"))
            }
            ("google._domainkey.mail.test", WireType::TXT) => {
                txt(&format!("v=DKIM1; k=rsa; p={RSA_1024}"))
            }
            ("k1._domainkey.mail.test", WireType::TXT) => MockReply::Rcode(ResponseCode::ServFail),
            _ => MockReply::NxDomain,
        })
        .await;
        let report = probe_dkim(
            &mock_dns_resolver_default(port),
            "mail.test",
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        assert_eq!(report.probed, DKIM_SELECTORS.len());
        let by_name = |n: &str| {
            report
                .selectors
                .iter()
                .find(|s| s.selector == n)
                .map(|s| s.state.clone())
        };
        assert_eq!(key(&by_name("selector1").unwrap()).1, Some(2048));
        assert_eq!(key(&by_name("google").unwrap()).1, Some(1024));
        assert!(matches!(by_name("k1"), Some(SelectorState::Unknown { .. })));
        assert_eq!(by_name("s1"), None, "absent selectors are not listed");
    }
}
