//! Domain status checking module
//!
//! Provides functionality to check the health of a domain including:
//! - HTTP status code and page title
//! - SSL certificate validity and expiration
//! - Domain registration expiration
//! - DNS resolution (A, AAAA, CNAME, NS)
//!
//! Every check is single-attempt by design (see `client.rs`), and every
//! outbound connection goes through the SSRF guards in [`crate::net`].

mod client;
mod types;

pub use client::StatusClient;
pub use types::{CertificateInfo, DnsResolution, DomainExpiration, StatusError, StatusResponse};
