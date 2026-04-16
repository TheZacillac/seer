use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Complete status response for a domain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    /// The domain that was checked
    pub domain: String,
    /// HTTP status code (e.g., 200, 301, 404)
    pub http_status: Option<u16>,
    /// HTTP status text (e.g., "OK", "Not Found")
    pub http_status_text: Option<String>,
    /// Page title extracted from HTML
    pub title: Option<String>,
    /// SSL certificate information
    pub certificate: Option<CertificateInfo>,
    /// Domain registration expiration information
    pub domain_expiration: Option<DomainExpiration>,
    /// DNS root record resolution information
    pub dns_resolution: Option<DnsResolution>,
    /// Errors from sub-checks that failed (check name → error message)
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<StatusError>,
}

/// An error from a specific sub-check within a status operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusError {
    /// Which check failed (e.g., "http", "ssl", "expiration", "dns")
    pub check: String,
    /// Error message
    pub message: String,
}

/// SSL certificate information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    /// Certificate issuer (e.g., "Let's Encrypt")
    pub issuer: String,
    /// Certificate subject (the domain it's issued for)
    pub subject: String,
    /// Certificate validity start date
    pub valid_from: DateTime<Utc>,
    /// Certificate expiration date
    pub valid_until: DateTime<Utc>,
    /// Days until certificate expires
    pub days_until_expiry: i64,
    /// Whether the certificate is currently valid
    pub is_valid: bool,
    /// Whether the certificate's SAN/CN matches the queried hostname.
    ///
    /// This is an additive signal independent of `is_valid` (which reflects
    /// only date-range validity). Because cert inspection uses
    /// `danger_accept_invalid_certs(true)` to see certs on mildly-broken
    /// sites, hostname verification is performed manually after extraction.
    #[serde(default)]
    pub hostname_verified: bool,
}

/// Domain registration expiration information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainExpiration {
    /// Domain expiration date
    pub expiration_date: DateTime<Utc>,
    /// Days until domain expires
    pub days_until_expiry: i64,
    /// Domain registrar name
    pub registrar: Option<String>,
}

/// DNS root record resolution information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResolution {
    /// IPv4 addresses (A records)
    pub a_records: Vec<String>,
    /// IPv6 addresses (AAAA records)
    pub aaaa_records: Vec<String>,
    /// CNAME target if domain is an alias
    pub cname_target: Option<String>,
    /// Authoritative nameservers
    pub nameservers: Vec<String>,
    /// Whether domain resolves (has A/AAAA or CNAME)
    pub resolves: bool,
}

impl StatusResponse {
    /// Creates a new StatusResponse with just the domain name.
    pub fn new(domain: String) -> Self {
        Self {
            domain,
            http_status: None,
            http_status_text: None,
            title: None,
            certificate: None,
            domain_expiration: None,
            dns_resolution: None,
            errors: Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_status_response_new() {
        let response = StatusResponse::new("example.com".to_string());
        assert_eq!(response.domain, "example.com");
        assert!(response.http_status.is_none());
        assert!(response.certificate.is_none());
        assert!(response.domain_expiration.is_none());
        assert!(response.dns_resolution.is_none());
    }

    #[test]
    fn test_status_response_serialization() {
        let response = StatusResponse {
            domain: "example.com".to_string(),
            http_status: Some(200),
            http_status_text: Some("OK".to_string()),
            title: Some("Example".to_string()),
            certificate: None,
            domain_expiration: None,
            dns_resolution: Some(DnsResolution {
                a_records: vec!["93.184.216.34".to_string()],
                aaaa_records: vec![],
                cname_target: None,
                nameservers: vec!["ns1.example.com".to_string()],
                resolves: true,
            }),
            errors: vec![],
        };
        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"http_status\":200"));
        assert!(json.contains("93.184.216.34"));
        assert!(json.contains("\"resolves\":true"));
    }

    #[test]
    fn test_dns_resolution_resolves() {
        let dns = DnsResolution {
            a_records: vec!["1.2.3.4".to_string()],
            aaaa_records: vec![],
            cname_target: None,
            nameservers: vec![],
            resolves: true,
        };
        assert!(dns.resolves);

        let dns_empty = DnsResolution {
            a_records: vec![],
            aaaa_records: vec![],
            cname_target: None,
            nameservers: vec![],
            resolves: false,
        };
        assert!(!dns_empty.resolves);
    }

    #[test]
    fn test_certificate_info_serialization() {
        use chrono::Utc;
        let cert = CertificateInfo {
            issuer: "Let's Encrypt".to_string(),
            subject: "example.com".to_string(),
            valid_from: Utc::now(),
            valid_until: Utc::now(),
            days_until_expiry: 90,
            is_valid: true,
            hostname_verified: true,
        };
        let json = serde_json::to_string(&cert).unwrap();
        assert!(json.contains("Let's Encrypt"));
        assert!(json.contains("\"is_valid\":true"));
    }
}
