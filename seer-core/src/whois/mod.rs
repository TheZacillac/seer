//! WHOIS client (TCP port 43) and response parsing.
//!
//! [`WhoisClient`] picks the server from the built-in TLD map (`servers.rs`).
//! A TLD the catalog knows has no port-43 service (RDAP-only, retired, or
//! server-less per IANA) fails fast with `WhoisServerNotFound`; any other
//! unmapped TLD is discovered from IANA (a server cached 24h, IANA's
//! definitive "no server" 1h, transient failures never). It connects IPv4
//! first with each address bounded to its share of the timeout, follows
//! registrar referrals up to 3 levels with cycle detection (one attempt per
//! referral hop — the registry record is already in hand), caps responses at
//! 1 MB and retries transient registry failures through [`crate::retry`].
//! Responses are parsed into [`WhoisResponse`] by a registry-specific parser
//! from the `parsers` table (keyed by TLD or second-level zone) or, failing a
//! match, the generic parser.

mod client;
mod parser;
mod parsers;
mod servers;

pub use client::WhoisClient;
pub use parser::WhoisResponse;
// Tolerant multi-format date parser, reused by the RDAP types module.
pub(crate) use parser::parse_date;
pub use servers::{all_tlds, get_registry_url, get_tld, get_whois_server};
