use std::time::Duration;

use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

use super::propagation::read_reply;
use super::resolver::ServerReply;
use crate::dns::{DnsQueryResult, DnsRecord, DnsResolver, DnsStatus, RecordType};
use crate::error::Result;

/// One nameserver's answer in a [`DnsComparison`].
///
/// A server that answered NOERROR or NXDOMAIN has its `status`, its CNAME
/// chain and the records of the compared type, and no `error`. SERVFAIL,
/// REFUSED or another code, a referral (a server that is neither recursive
/// nor authoritative for the name) or no response at all sets `error` to
/// the reason; `status` is kept whenever the server responded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerResult {
    pub nameserver: String,
    /// The response code the server sent; `None` when it sent no response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<DnsStatus>,
    /// The CNAME records the answer led with, in chain order (owner →
    /// target), under their real owner names.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cname_chain: Vec<DnsRecord>,
    /// The answers of the compared type (for ANY: every answer).
    pub records: Vec<DnsRecord>,
    pub error: Option<String>,
}

impl ServerResult {
    /// Folds one server's reply into a result.
    fn from_reply(nameserver: &str, record_type: RecordType, reply: Result<ServerReply>) -> Self {
        let (cname_chain, (records, status, error)) = match reply {
            Ok(ServerReply::Response(response)) => read_response(response, record_type),
            Ok(ServerReply::Silent(reason)) => (vec![], (vec![], None, Some(reason))),
            Err(e) => {
                debug!(server = %nameserver, error = %e, "DNS compare query failed");
                // Sanitized for external return; full detail logged above.
                (vec![], (vec![], None, Some(e.sanitized_message())))
            }
        };
        Self {
            nameserver: nameserver.to_string(),
            status,
            cname_chain,
            records,
            error,
        }
    }

    /// How this server's outcome reads: its response code, with an empty
    /// NOERROR answer read as `NODATA`; `None` when it sent no response.
    pub fn status_label(&self) -> Option<String> {
        self.status.map(|status| match status {
            DnsStatus::NoError if self.records.is_empty() => "NODATA".to_string(),
            other => other.to_string(),
        })
    }

    /// The chain as compared: each hop's owner and target, case-folded.
    fn chain_keys(&self) -> Vec<(String, String)> {
        self.cname_chain
            .iter()
            .map(|r| {
                (
                    r.name.trim_end_matches('.').to_ascii_lowercase(),
                    r.data.comparison_key(),
                )
            })
            .collect()
    }
}

/// One server's reading: `(cname_chain, records, status, error)`.
type Reading = (
    Vec<DnsRecord>,
    (Vec<DnsRecord>, Option<DnsStatus>, Option<String>),
);

/// Splits a response into its CNAME chain and the propagation reading of it
/// ([`read_reply`]: records of the type, status, error).
fn read_response(response: DnsQueryResult, record_type: RecordType) -> Reading {
    let chain = response.cname_chain().cloned().collect();
    (chain, read_reply(response, record_type))
}

/// Comparison of DNS responses between two nameservers.
///
/// Contains each server's answer, whether they match, and the set
/// differences of the records (only_in_a, only_in_b, common). Two servers
/// match only when both answered, with the same outcome (NXDOMAIN and
/// NODATA are different answers), the same CNAME chain and the same records.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsComparison {
    pub domain: String,
    pub record_type: RecordType,
    pub server_a: ServerResult,
    pub server_b: ServerResult,
    pub matches: bool,
    pub only_in_a: Vec<String>,
    pub only_in_b: Vec<String>,
    pub common: Vec<String>,
}

impl DnsComparison {
    /// Whether both servers gave the same outcome
    /// ([`ServerResult::status_label`]).
    pub fn status_matches(&self) -> bool {
        self.server_a.status_label() == self.server_b.status_label()
    }

    /// Whether both servers' CNAME chains name the same hops (case-folded).
    pub fn chain_matches(&self) -> bool {
        self.server_a.chain_keys() == self.server_b.chain_keys()
    }

    /// One line saying how the servers compare — the reading every renderer
    /// shares: `Records match`, both outcomes when they differ
    /// (`Responses differ: NXDOMAIN vs NODATA`), `CNAME chains differ`, or
    /// `Records differ`.
    pub fn summary(&self) -> String {
        if self.matches {
            return "Records match".to_string();
        }
        if self.server_a.error.is_none() && self.server_b.error.is_none() {
            if !self.status_matches() {
                let label = |s: &ServerResult| s.status_label().unwrap_or_default();
                return format!(
                    "Responses differ: {} vs {}",
                    label(&self.server_a),
                    label(&self.server_b)
                );
            }
            if !self.chain_matches() {
                return "CNAME chains differ".to_string();
            }
        }
        "Records differ".to_string()
    }
}

/// Compares DNS records for a domain across two nameservers.
///
/// Queries both servers concurrently — one direct query each, as dig sends
/// it — and compares their response codes, CNAME chains and records.
pub struct DnsComparator {
    resolver: DnsResolver,
}

impl Default for DnsComparator {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsComparator {
    /// Creates a new DNS comparator with default resolver settings.
    pub fn new() -> Self {
        Self {
            resolver: DnsResolver::new(),
        }
    }

    /// Builds a comparator honoring `~/.seer/config.toml`
    /// (`timeouts.dns_secs`). The two nameservers are always the caller's,
    /// so the configured nameserver does not apply.
    pub fn from_config(config: &crate::config::SeerConfig) -> Self {
        Self::new().with_timeout(config.dns_timeout())
    }

    /// Sets the per-query timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.resolver = self.resolver.with_timeout(timeout);
        self
    }

    /// Compares DNS records for a domain between two nameservers.
    ///
    /// # Arguments
    /// * `domain` - The domain name to query
    /// * `record_type` - The type of DNS record to compare (A, AAAA, MX, etc.)
    /// * `server_a` - The first nameserver (a
    ///   [`NameserverSpec`](crate::dns::NameserverSpec))
    /// * `server_b` - The second nameserver
    ///
    /// # Returns
    /// A `DnsComparison` showing each server's answer, whether they match,
    /// and which records are unique to each server or shared.
    #[instrument(skip(self), fields(domain = %domain, record_type = %record_type, server_a = %server_a, server_b = %server_b))]
    pub async fn compare(
        &self,
        domain: &str,
        record_type: RecordType,
        server_a: &str,
        server_b: &str,
    ) -> Result<DnsComparison> {
        // The resolver's per-name normalization, so the stored name matches
        // what was queried: `www.` is kept, and an IPv6 PTR literal is passed
        // through instead of being mangled as `host:port`. A bad name (or a
        // bare-domain SRV query) fails once, here, not as two server errors.
        let domain = crate::dns::resolver::prepare_query(domain, record_type)?;
        crate::dns::resolver::wire_query_name(&domain, record_type)?;

        // Direct queries, like propagation: each server's response as sent —
        // status, chain and records — rather than `resolve`, which folds
        // NXDOMAIN and NODATA into the same empty list and hides the chain.
        let (reply_a, reply_b) = tokio::join!(
            self.resolver.query_server(&domain, record_type, server_a),
            self.resolver.query_server(&domain, record_type, server_b)
        );

        let server_a = ServerResult::from_reply(server_a, record_type, reply_a);
        let server_b = ServerResult::from_reply(server_b, record_type, reply_b);

        // Compare record values on their comparison key: domain-name fields
        // case-insensitively (two servers returning `NS1.EXAMPLE.COM.` vs
        // `ns1.example.com.` under 0x20 randomization agree), case-sensitive
        // data (TXT, DNSKEY) verbatim. See `RecordData::comparison_key`.
        let (values_equal, only_in_a, only_in_b, mut common) =
            compare_server_values(&server_a, &server_b);
        common.sort();

        let mut comparison = DnsComparison {
            domain,
            record_type,
            server_a,
            server_b,
            matches: false,
            only_in_a,
            only_in_b,
            common,
        };
        comparison.matches = values_equal
            && comparison.server_a.error.is_none()
            && comparison.server_b.error.is_none()
            && comparison.status_matches()
            && comparison.chain_matches();

        debug!(
            matches = comparison.matches,
            common = comparison.common.len(),
            only_in_a = comparison.only_in_a.len(),
            only_in_b = comparison.only_in_b.len(),
            "DNS comparison complete"
        );

        Ok(comparison)
    }
}

/// Compares the record sets of two servers, returning
/// `(values_equal, only_in_a, only_in_b, common)`. Each entry is the
/// original-cased `format_short()` value (for `common`, server A's) so
/// display preserves what the server actually returned, but membership is
/// decided on
/// [`RecordData::comparison_key`](crate::dns::RecordData::comparison_key)
/// (domain names case-folded, case-sensitive data verbatim).
fn compare_server_values(
    a: &ServerResult,
    b: &ServerResult,
) -> (bool, Vec<String>, Vec<String>, Vec<String>) {
    use std::collections::HashSet;

    let keys_a: HashSet<String> = a.records.iter().map(|r| r.data.comparison_key()).collect();
    let keys_b: HashSet<String> = b.records.iter().map(|r| r.data.comparison_key()).collect();

    let only_in = |records: &[DnsRecord], other: &HashSet<String>| {
        let mut values: Vec<String> = records
            .iter()
            .filter(|r| !other.contains(&r.data.comparison_key()))
            .map(|r| r.format_short())
            .collect();
        values.sort();
        values.dedup();
        values
    };
    let only_in_a = only_in(&a.records, &keys_b);
    let only_in_b = only_in(&b.records, &keys_a);

    let mut seen: HashSet<String> = HashSet::new();
    let common = a
        .records
        .iter()
        .filter(|r| {
            let key = r.data.comparison_key();
            keys_b.contains(&key) && seen.insert(key)
        })
        .map(|r| r.format_short())
        .collect();

    let values_equal = only_in_a.is_empty() && only_in_b.is_empty();
    (values_equal, only_in_a, only_in_b, common)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::{RecordData, RecordType};

    #[test]
    fn test_dns_comparison_serialization() {
        let comparison = DnsComparison {
            domain: "example.com".to_string(),
            record_type: RecordType::A,
            server_a: ServerResult {
                nameserver: "8.8.8.8".to_string(),
                records: vec![DnsRecord {
                    name: "example.com".to_string(),
                    record_type: RecordType::A,
                    ttl: 300,
                    data: RecordData::A {
                        address: "93.184.216.34".to_string(),
                    },
                }],
                error: None,
                status: Some(DnsStatus::NoError),
                cname_chain: vec![],
            },
            server_b: ServerResult {
                nameserver: "1.1.1.1".to_string(),
                records: vec![DnsRecord {
                    name: "example.com".to_string(),
                    record_type: RecordType::A,
                    ttl: 300,
                    data: RecordData::A {
                        address: "93.184.216.34".to_string(),
                    },
                }],
                error: None,
                status: Some(DnsStatus::NoError),
                cname_chain: vec![],
            },
            matches: true,
            only_in_a: vec![],
            only_in_b: vec![],
            common: vec!["93.184.216.34".to_string()],
        };

        let json = serde_json::to_string(&comparison).unwrap();
        assert!(json.contains("example.com"));
        assert!(json.contains("93.184.216.34"));
        assert!(json.contains("\"matches\":true"));
    }

    #[test]
    fn test_server_result_with_error() {
        let result = ServerResult {
            nameserver: "8.8.8.8".to_string(),
            records: vec![],
            error: Some("connection timed out".to_string()),
            status: None,
            cname_chain: vec![],
        };

        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("connection timed out"));
    }

    /// Two servers returning the same NS record with different casing (common
    /// with 0x20 query-name randomization) must be treated as a match, not a
    /// mismatch. The comparison key is case-folded so `NS1.EXAMPLE.COM.` and
    /// `ns1.example.com.` are equal.
    #[test]
    fn compare_values_case_insensitive_match() {
        let upper = ServerResult {
            nameserver: "8.8.8.8".to_string(),
            records: vec![DnsRecord {
                name: "example.com".to_string(),
                record_type: RecordType::NS,
                ttl: 300,
                data: RecordData::NS {
                    nameserver: "NS1.EXAMPLE.COM.".to_string(),
                },
            }],
            error: None,
            status: Some(DnsStatus::NoError),
            cname_chain: vec![],
        };
        let lower = ServerResult {
            nameserver: "1.1.1.1".to_string(),
            records: vec![DnsRecord {
                name: "example.com".to_string(),
                record_type: RecordType::NS,
                ttl: 300,
                data: RecordData::NS {
                    nameserver: "ns1.example.com.".to_string(),
                },
            }],
            error: None,
            status: Some(DnsStatus::NoError),
            cname_chain: vec![],
        };

        let (matches, only_in_a, only_in_b, _) = compare_server_values(&upper, &lower);
        assert!(matches, "case-only difference must be a match");
        assert!(
            only_in_a.is_empty(),
            "no records unique to A: {only_in_a:?}"
        );
        assert!(
            only_in_b.is_empty(),
            "no records unique to B: {only_in_b:?}"
        );
    }

    /// TXT data is case-sensitive: a verification token that differs only in
    /// case between two servers is a real disagreement, not a 0x20 artefact.
    /// (Case was previously folded for every record type.)
    #[test]
    fn compare_values_txt_case_difference_is_a_mismatch() {
        let txt = |ns: &str, text: &str| ServerResult {
            nameserver: ns.to_string(),
            records: vec![DnsRecord {
                name: "example.com".to_string(),
                record_type: RecordType::TXT,
                ttl: 300,
                data: RecordData::txt(vec![text.to_string()]),
            }],
            error: None,
            status: Some(DnsStatus::NoError),
            cname_chain: vec![],
        };
        let (matches, only_in_a, only_in_b, _) = compare_server_values(
            &txt("8.8.8.8", "verify=AbCd"),
            &txt("1.1.1.1", "verify=abcd"),
        );
        assert!(!matches);
        assert_eq!(only_in_a, vec!["\"verify=AbCd\"".to_string()]);
        assert_eq!(only_in_b, vec!["\"verify=abcd\"".to_string()]);
    }

    /// End to end against the mock fixture: `compare` must keep `www.` and
    /// accept an IPv6 PTR literal, like `resolve` does. It previously ran
    /// `normalize_domain`, which stripped `www.` (querying the apex) and
    /// mangled `2606:4700:4700::1111` as `host:port`.
    #[tokio::test]
    async fn compare_uses_per_name_normalization() {
        use crate::dns::test_support::{mock_dns_resolver, spawn_mock_dns, MockMode};

        let port = spawn_mock_dns(MockMode::Zone).await;
        let comparator = DnsComparator {
            resolver: mock_dns_resolver(port),
        };

        let cmp = comparator
            .compare("www.seer.test", RecordType::CNAME, "127.0.0.1", "127.0.0.1")
            .await
            .expect("compare www");
        assert_eq!(cmp.domain, "www.seer.test");
        assert!(cmp.matches);
        assert_eq!(cmp.common, vec!["edge.cdn.test.".to_string()]);

        let cmp = comparator
            .compare(
                "2606:4700:4700::1111",
                RecordType::PTR,
                "127.0.0.1",
                "127.0.0.1",
            )
            .await
            .expect("IPv6 PTR literal must be accepted");
        assert_eq!(cmp.domain, "2606:4700:4700::1111");
        assert_eq!(cmp.common, vec!["one.one.one.one.".to_string()]);
    }

    /// A comparator whose two servers are separate loopback mocks (the port
    /// rides in each spec, so no port override).
    fn two_server_comparator() -> DnsComparator {
        DnsComparator {
            resolver: DnsResolver::new()
                .with_timeout(Duration::from_millis(500))
                .allowing_private_hosts(),
        }
    }

    /// Regression: `compare` went through `resolve`, which folds NXDOMAIN
    /// and NODATA into the same empty list, so a server saying the name does
    /// not exist "matched" one saying it exists without records.
    #[tokio::test]
    async fn nxdomain_and_nodata_do_not_match() {
        use crate::dns::test_support::{spawn_mock_dns_fn, MockReply};

        let nx = spawn_mock_dns_fn(|_, _| MockReply::NxDomainWithSoa("seer.test")).await;
        let nodata = spawn_mock_dns_fn(|_, _| MockReply::NoDataWithSoa("seer.test")).await;
        let cmp = two_server_comparator()
            .compare(
                "gone.seer.test",
                RecordType::A,
                &format!("127.0.0.1:{nx}"),
                &format!("127.0.0.1:{nodata}"),
            )
            .await
            .expect("compare");
        assert_eq!(cmp.server_a.status, Some(DnsStatus::NxDomain));
        assert_eq!(cmp.server_b.status, Some(DnsStatus::NoError));
        assert!(cmp.server_a.error.is_none() && cmp.server_b.error.is_none());
        assert!(!cmp.matches, "NXDOMAIN vs NODATA must differ");
        assert_eq!(cmp.summary(), "Responses differ: NXDOMAIN vs NODATA");

        // The same negative answer on both sides is a match.
        let cmp = two_server_comparator()
            .compare(
                "gone.seer.test",
                RecordType::A,
                &format!("127.0.0.1:{nx}"),
                &format!("127.0.0.1:{nx}"),
            )
            .await
            .expect("compare");
        assert!(cmp.matches);
        assert_eq!(cmp.summary(), "Records match");
    }

    /// Regression: the resolver chased CNAMEs and returned only the final
    /// records, so two servers pointing a name at different targets that
    /// happen to share an address "matched".
    #[tokio::test]
    async fn differing_cname_chains_do_not_match() {
        use crate::dns::test_support::{
            a_rdata, cname_rdata, record, spawn_mock_dns_fn, MockReply,
        };

        let via = |target: &'static str| {
            move |_: &str, _| {
                MockReply::Records(vec![
                    record("www.seer.test", 300, cname_rdata(target)),
                    record(target, 300, a_rdata([192, 0, 2, 1])),
                ])
            }
        };
        let old = spawn_mock_dns_fn(via("old.cdn.test")).await;
        let new = spawn_mock_dns_fn(via("new.cdn.test")).await;
        let comparator = two_server_comparator();
        let cmp = comparator
            .compare(
                "www.seer.test",
                RecordType::A,
                &format!("127.0.0.1:{old}"),
                &format!("127.0.0.1:{new}"),
            )
            .await
            .expect("compare");
        assert_eq!(cmp.common, vec!["192.0.2.1".to_string()]);
        assert_eq!(cmp.server_a.cname_chain.len(), 1);
        assert!(!cmp.matches, "different chains must differ");
        assert_eq!(cmp.summary(), "CNAME chains differ");

        let cmp = comparator
            .compare(
                "www.seer.test",
                RecordType::A,
                &format!("127.0.0.1:{old}"),
                &format!("127.0.0.1:{old}"),
            )
            .await
            .expect("compare");
        assert!(cmp.matches);
    }

    /// SERVFAIL is kept as the status and reported as the error, and a
    /// silent server's reason is its error; neither matches.
    #[tokio::test]
    async fn failures_carry_status_and_reason() {
        use crate::dns::test_support::{spawn_mock_dns_fn, MockReply};
        use hickory_resolver::proto::op::ResponseCode;

        let servfail = spawn_mock_dns_fn(|_, _| MockReply::Rcode(ResponseCode::ServFail)).await;
        let silent = spawn_mock_dns_fn(|_, _| MockReply::NoReply).await;
        let cmp = two_server_comparator()
            .compare(
                "seer.test",
                RecordType::A,
                &format!("127.0.0.1:{servfail}"),
                &format!("127.0.0.1:{silent}"),
            )
            .await
            .expect("compare");
        assert_eq!(cmp.server_a.status, Some(DnsStatus::ServFail));
        assert_eq!(cmp.server_a.error.as_deref(), Some("SERVFAIL"));
        assert_eq!(cmp.server_b.status, None);
        assert_eq!(cmp.server_b.error.as_deref(), Some("timed out"));
        assert!(!cmp.matches);
        assert_eq!(cmp.summary(), "Records differ");
    }

    #[test]
    fn from_config_applies_dns_timeout() {
        let mut config = crate::config::SeerConfig::default();
        config.timeouts.dns_secs = 9;
        let comparator = DnsComparator::from_config(&config);
        assert_eq!(comparator.resolver.timeout(), Duration::from_secs(9));
    }
}
