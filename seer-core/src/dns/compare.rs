use serde::{Deserialize, Serialize};
use tracing::{debug, instrument};

use crate::dns::{DnsRecord, DnsResolver, RecordType};
use crate::error::Result;

/// Result of querying DNS records from a single nameserver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerResult {
    pub nameserver: String,
    pub records: Vec<DnsRecord>,
    pub error: Option<String>,
}

impl ServerResult {
    /// Folds one server's query outcome into a result.
    fn from_query(nameserver: &str, result: Result<Vec<DnsRecord>>) -> Self {
        let (records, error) = match result {
            Ok(records) => (records, None),
            Err(e) => {
                debug!(server = %nameserver, error = %e, "DNS compare query failed");
                // Sanitized for external return; full detail logged above.
                (vec![], Some(e.sanitized_message()))
            }
        };
        Self {
            nameserver: nameserver.to_string(),
            records,
            error,
        }
    }
}

/// Comparison of DNS records between two nameservers.
///
/// Contains the records from each server, whether they match,
/// and the set differences (only_in_a, only_in_b, common).
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

/// Compares DNS records for a domain across two nameservers.
///
/// Queries both servers concurrently and produces a structured
/// comparison showing common records, differences, and errors.
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

    /// Compares DNS records for a domain between two nameservers.
    ///
    /// # Arguments
    /// * `domain` - The domain name to query
    /// * `record_type` - The type of DNS record to compare (A, AAAA, MX, etc.)
    /// * `server_a` - IP address of the first nameserver
    /// * `server_b` - IP address of the second nameserver
    ///
    /// # Returns
    /// A `DnsComparison` showing records from each server, whether they match,
    /// and which records are unique to each server or shared.
    #[instrument(skip(self), fields(domain = %domain, record_type = %record_type, server_a = %server_a, server_b = %server_b))]
    pub async fn compare(
        &self,
        domain: &str,
        record_type: RecordType,
        server_a: &str,
        server_b: &str,
    ) -> Result<DnsComparison> {
        // Same per-name normalization `resolve` applies, so the stored name
        // matches what was queried: `www.` is kept, and an IPv6 PTR literal
        // is passed through instead of being mangled as `host:port`.
        let domain = crate::dns::resolver::prepare_query(domain, record_type)?;

        // Query both servers concurrently
        let (result_a, result_b) = tokio::join!(
            self.resolver.resolve(&domain, record_type, Some(server_a)),
            self.resolver.resolve(&domain, record_type, Some(server_b))
        );

        let server_a_result = ServerResult::from_query(server_a, result_a);
        let server_b_result = ServerResult::from_query(server_b, result_b);

        // Compare record values on their comparison key: domain-name fields
        // case-insensitively (two servers returning `NS1.EXAMPLE.COM.` vs
        // `ns1.example.com.` under 0x20 randomization agree), case-sensitive
        // data (TXT, DNSKEY) verbatim. See `RecordData::comparison_key`.
        let (values_equal, only_in_a, only_in_b) =
            compare_server_values(&server_a_result, &server_b_result);

        // `common` is informational; build it on the same key but emit the
        // original-cased values from server A for display.
        let mut common = common_values(&server_a_result, &server_b_result);
        common.sort();

        let matches =
            values_equal && server_a_result.error.is_none() && server_b_result.error.is_none();

        debug!(
            matches = matches,
            common = common.len(),
            only_in_a = only_in_a.len(),
            only_in_b = only_in_b.len(),
            "DNS comparison complete"
        );

        Ok(DnsComparison {
            domain: domain.to_string(),
            record_type,
            server_a: server_a_result,
            server_b: server_b_result,
            matches,
            only_in_a,
            only_in_b,
            common,
        })
    }
}

/// Compares the record sets of two servers, returning
/// `(values_equal, only_in_a, only_in_b)`. Each `only_in_*` entry is the
/// original-cased `format_short()` value so display preserves what the server
/// actually returned, but membership is decided on
/// [`RecordData::comparison_key`](crate::dns::RecordData::comparison_key)
/// (domain names case-folded, case-sensitive data verbatim).
fn compare_server_values(a: &ServerResult, b: &ServerResult) -> (bool, Vec<String>, Vec<String>) {
    use std::collections::HashSet;

    let keys_a: HashSet<String> = a.records.iter().map(|r| r.data.comparison_key()).collect();
    let keys_b: HashSet<String> = b.records.iter().map(|r| r.data.comparison_key()).collect();

    let mut only_in_a: Vec<String> = a
        .records
        .iter()
        .filter(|r| !keys_b.contains(&r.data.comparison_key()))
        .map(|r| r.format_short())
        .collect();
    let mut only_in_b: Vec<String> = b
        .records
        .iter()
        .filter(|r| !keys_a.contains(&r.data.comparison_key()))
        .map(|r| r.format_short())
        .collect();
    only_in_a.sort();
    only_in_a.dedup();
    only_in_b.sort();
    only_in_b.dedup();

    let values_equal = only_in_a.is_empty() && only_in_b.is_empty();
    (values_equal, only_in_a, only_in_b)
}

/// Returns the values present (by comparison key) on both servers, emitting
/// server A's original casing for each shared value.
fn common_values(a: &ServerResult, b: &ServerResult) -> Vec<String> {
    use std::collections::HashSet;
    let keys_b: HashSet<String> = b.records.iter().map(|r| r.data.comparison_key()).collect();
    let mut seen: HashSet<String> = HashSet::new();
    let mut common = Vec::new();
    for r in &a.records {
        let key = r.data.comparison_key();
        if keys_b.contains(&key) && seen.insert(key) {
            common.push(r.format_short());
        }
    }
    common
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
        };

        let (matches, only_in_a, only_in_b) = compare_server_values(&upper, &lower);
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
                data: RecordData::TXT {
                    text: text.to_string(),
                },
            }],
            error: None,
        };
        let (matches, only_in_a, only_in_b) = compare_server_values(
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
}
