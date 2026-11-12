//! What every handler shares: the settings and the seer-core clients.
//!
//! The clients are built once from the user's config (timeouts, default
//! nameserver) and shared by reference; none is rebuilt per request.

use std::collections::HashMap;
use std::sync::Arc;

use seer_core::{
    AvailabilityChecker, DnsResolver, RdapClient, SeerConfig, SmartLookup, SslChecker,
    StatusClient, WhoisClient,
};

use crate::settings::Settings;
use crate::tier::Tier;

/// One of each seer-core client the routes call.
pub struct Clients {
    /// RDAP-first, WHOIS-fallback registration lookup.
    pub lookup: SmartLookup,
    /// WHOIS only.
    pub whois: WhoisClient,
    /// RDAP only (domains, IPs, ASNs) and the TLD bootstrap data.
    pub rdap: RdapClient,
    /// DNS queries (`dig`).
    pub dns: DnsResolver,
    /// TLS certificate inspection.
    pub ssl: SslChecker,
    /// HTTP status, title, certificate and expiry.
    pub status: StatusClient,
    /// Registration availability.
    pub availability: AvailabilityChecker,
}

impl Clients {
    /// Builds every client from the user's config.
    pub fn from_config(config: &SeerConfig) -> Self {
        Self {
            lookup: SmartLookup::from_config(config),
            whois: WhoisClient::from_config(config),
            rdap: RdapClient::from_config(config),
            dns: DnsResolver::from_config(config),
            ssl: SslChecker::from_config(config),
            status: StatusClient::from_config(config),
            availability: AvailabilityChecker::from_config(config),
        }
    }
}

/// The state Axum hands to handlers and middleware. Cheap to clone.
#[derive(Clone)]
pub struct AppState {
    /// Validated server settings.
    pub settings: Arc<Settings>,
    /// The seer-core clients.
    pub clients: Arc<Clients>,
    /// Each route pattern's tier, for the gate.
    pub(crate) tiers: Arc<HashMap<&'static str, Tier>>,
}
