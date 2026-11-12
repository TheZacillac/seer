//! What every handler shares: the settings and the seer-core clients.
//!
//! The clients are built once from the user's config (timeouts, default
//! nameserver) and shared by reference; none is rebuilt per request.

use std::collections::HashMap;
use std::sync::Arc;

use seer_core::contract::CostClass;
use seer_core::{
    AvailabilityChecker, DnsResolver, RdapClient, SeerConfig, SmartLookup, SslChecker,
    StatusClient, WhoisClient,
};

use tokio::sync::{AcquireError, Semaphore, SemaphorePermit};

use crate::app::Route;
use crate::cache::ResponseCache;
use crate::limit::Limits;
use crate::settings::Settings;
use crate::tier::{Caller, Tier};

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

/// Slots for lookups in flight.
///
/// A total pool bounds the server's concurrent work. Anonymous callers
/// also need a slot from a pool half that size, so the public tier cannot
/// take every slot from keyed callers.
pub struct Permits {
    total: Semaphore,
    anonymous: Semaphore,
}

/// Slots held for one lookup; returned when dropped.
pub struct Held<'a> {
    _anonymous: Option<SemaphorePermit<'a>>,
    _total: SemaphorePermit<'a>,
}

impl Permits {
    /// `max_in_flight` slots in total; anonymous callers share half (at
    /// least one).
    pub fn new(max_in_flight: usize) -> Self {
        Self {
            total: Semaphore::new(max_in_flight),
            anonymous: Semaphore::new((max_in_flight / 2).max(1)),
        }
    }

    /// Waits for the slots `caller` needs. An anonymous caller takes its
    /// anonymous slot first, so while it waits there it holds no total
    /// slot. Dropping the wait returns whatever was already taken.
    pub async fn acquire(&self, caller: Caller) -> Result<Held<'_>, AcquireError> {
        let anonymous = match caller {
            Caller::Anonymous => Some(self.anonymous.acquire().await?),
            Caller::Keyed => None,
        };
        Ok(Held {
            _anonymous: anonymous,
            _total: self.total.acquire().await?,
        })
    }

    /// Free slots right now, as (total, anonymous).
    pub fn available(&self) -> (usize, usize) {
        (
            self.total.available_permits(),
            self.anonymous.available_permits(),
        )
    }
}

/// What the gate needs to know about a route.
#[derive(Debug, Clone, Copy)]
pub struct RouteMeta {
    /// Who may call it.
    pub tier: Tier,
    /// How expensive it is, which sets its rate limit.
    pub cost: CostClass,
}

/// The state Axum hands to handlers and middleware. Cheap to clone.
#[derive(Clone)]
pub struct AppState {
    /// Validated server settings.
    pub settings: Arc<Settings>,
    /// The seer-core clients.
    pub clients: Arc<Clients>,
    /// Each route pattern's tier and cost class, for the gate.
    pub(crate) rows: Arc<HashMap<&'static str, RouteMeta>>,
    /// The rate limiters.
    pub(crate) limits: Arc<Limits>,
    /// The response cache.
    pub(crate) cache: Arc<ResponseCache>,
    /// Slots for lookups in flight.
    pub(crate) permits: Arc<Permits>,
}

impl AppState {
    /// Builds the shared state for a server exposing `routes`.
    pub fn new(settings: Settings, clients: Clients, routes: &[Route]) -> Self {
        let rows = routes
            .iter()
            .map(|route| {
                let meta = RouteMeta {
                    tier: route.tier,
                    cost: route.cost,
                };
                (route.path, meta)
            })
            .collect();
        Self {
            rows: Arc::new(rows),
            limits: Arc::new(Limits::new(settings.keyed_rate_multiplier)),
            cache: Arc::new(ResponseCache::new(settings.cache_ttl)),
            permits: Arc::new(Permits::new(settings.max_in_flight)),
            settings: Arc::new(settings),
            clients: Arc::new(clients),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    const SOON: Duration = Duration::from_millis(50);

    #[tokio::test]
    async fn anonymous_callers_share_half_the_slots() {
        let permits = Permits::new(4);
        assert_eq!(permits.available(), (4, 2));
        let first = permits.acquire(Caller::Anonymous).await.unwrap();
        let second = permits.acquire(Caller::Anonymous).await.unwrap();
        assert_eq!(permits.available(), (2, 0));
        // A third anonymous caller waits; a keyed one does not.
        assert!(timeout(SOON, permits.acquire(Caller::Anonymous))
            .await
            .is_err());
        let keyed = timeout(SOON, permits.acquire(Caller::Keyed)).await;
        assert!(
            keyed.is_ok(),
            "the public tier must not starve keyed callers"
        );
        drop(first);
        assert!(timeout(SOON, permits.acquire(Caller::Anonymous))
            .await
            .is_ok());
        drop(second);
    }

    #[tokio::test]
    async fn keyed_callers_are_bounded_by_the_total() {
        let permits = Permits::new(2);
        let _a = permits.acquire(Caller::Keyed).await.unwrap();
        let _b = permits.acquire(Caller::Keyed).await.unwrap();
        assert!(timeout(SOON, permits.acquire(Caller::Keyed)).await.is_err());
        // An anonymous waiter holds no total slot while it waits for one.
        assert_eq!(permits.available(), (0, 1));
    }

    #[tokio::test]
    async fn a_dropped_wait_returns_what_it_held() {
        let permits = Permits::new(2);
        let held = permits.acquire(Caller::Keyed).await.unwrap();
        let _other = permits.acquire(Caller::Keyed).await.unwrap();
        // This anonymous caller takes its anonymous slot, then times out
        // waiting for a total slot. Both must come back.
        assert!(timeout(SOON, permits.acquire(Caller::Anonymous))
            .await
            .is_err());
        assert_eq!(permits.available(), (0, 1));
        drop(held);
        assert_eq!(permits.available(), (1, 1));
    }
}
