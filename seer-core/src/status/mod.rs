//! Domain status checking module
//!
//! Provides functionality to check the health of a domain including:
//! - HTTP status code and page title
//! - SSL certificate validity and expiration
//! - Domain registration expiration

mod client;
mod types;

pub use client::StatusClient;
pub use types::{CertificateInfo, DnsResolution, DomainExpiration, StatusResponse};
