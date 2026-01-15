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

impl StatusResponse {
    /// Create a new StatusResponse with just the domain name
    pub fn new(domain: String) -> Self {
        Self {
            domain,
            http_status: None,
            http_status_text: None,
            title: None,
            certificate: None,
            domain_expiration: None,
        }
    }
}
