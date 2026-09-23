//! WHOIS client (TCP port 43) and response parsing.
//!
//! [`WhoisClient`] picks the server from the built-in TLD map (`servers.rs`),
//! falling back to IANA discovery for unmapped TLDs (cached 24h), follows
//! registrar referrals up to 3 levels with cycle detection, caps responses at
//! 1 MB and retries transient failures through [`crate::retry`]. Responses are
//! parsed into [`WhoisResponse`] by the generic parser or a registry-specific
//! one from [`parsers`].

mod client;
mod parser;
pub mod parsers;
mod servers;

pub use client::WhoisClient;
pub use parser::WhoisResponse;
// Tolerant multi-format date parser, reused by the RDAP types module.
pub(crate) use parser::parse_date;
pub use servers::{all_tlds, get_registry_url, get_tld, get_whois_server};
