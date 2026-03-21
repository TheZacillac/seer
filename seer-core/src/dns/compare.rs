use serde::{Deserialize, Serialize};

use crate::dns::{DnsRecord, DnsResolver, RecordType};
use crate::error::Result;

/// Result of querying DNS records from a single nameserver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerResult {
    pub nameserver: String,
    pub records: Vec<DnsRecord>,
    pub error: Option<String>,
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
    pub async fn compare(
        &self,
        domain: &str,
        record_type: RecordType,
        server_a: &str,
        server_b: &str,
    ) -> Result<DnsComparison> {
        // Query both servers concurrently
        let (result_a, result_b) = tokio::join!(
            self.resolver.resolve(domain, record_type, Some(server_a)),
            self.resolver.resolve(domain, record_type, Some(server_b))
        );

        let server_a_result = match result_a {
            Ok(records) => ServerResult {
                nameserver: server_a.to_string(),
                records,
                error: None,
            },
            Err(e) => ServerResult {
                nameserver: server_a.to_string(),
                records: vec![],
                error: Some(e.to_string()),
            },
        };

        let server_b_result = match result_b {
            Ok(records) => ServerResult {
                nameserver: server_b.to_string(),
                records,
                error: None,
            },
            Err(e) => ServerResult {
                nameserver: server_b.to_string(),
                records: vec![],
                error: Some(e.to_string()),
            },
        };

        // Compare record values using format_short for comparison
        let values_a: std::collections::HashSet<String> = server_a_result
            .records
            .iter()
            .map(|r| r.format_short())
            .collect();
        let values_b: std::collections::HashSet<String> = server_b_result
            .records
            .iter()
            .map(|r| r.format_short())
            .collect();

        let mut only_in_a: Vec<String> = values_a.difference(&values_b).cloned().collect();
        let mut only_in_b: Vec<String> = values_b.difference(&values_a).cloned().collect();
        let mut common: Vec<String> = values_a.intersection(&values_b).cloned().collect();

        // Sort for deterministic output
        only_in_a.sort();
        only_in_b.sort();
        common.sort();

        let matches = only_in_a.is_empty()
            && only_in_b.is_empty()
            && server_a_result.error.is_none()
            && server_b_result.error.is_none();

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
}
