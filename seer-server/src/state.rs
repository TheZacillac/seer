//! What every handler shares: the settings and the seer-core clients.
//!
//! The clients are built once from the user's config (timeouts, default
//! nameserver) and shared by reference; none is rebuilt per request.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};

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

/// How many lookups each anonymous client has in flight.
///
/// The pools in [`Permits`] bound the server; this bounds one client. An
/// anonymous caller chooses the target of an SSL, status or DNS lookup, so
/// it chooses how slow that lookup is. Without a per-client bound, a few
/// addresses aiming at slow targets could hold every anonymous slot.
pub struct PerClient {
    limit: u32,
    in_flight: Mutex<HashMap<IpAddr, u32>>,
}

/// One client's lookup in flight; released when dropped.
pub struct ClientSlot<'a> {
    owner: &'a PerClient,
    client: IpAddr,
}

impl PerClient {
    /// At most `limit` lookups in flight per client.
    pub fn new(limit: u32) -> Self {
        Self {
            limit,
            in_flight: Mutex::new(HashMap::new()),
        }
    }

    /// Records one more lookup for `client`, or `None` if it already has
    /// the most allowed. Never waits: the caller is told to retry.
    pub fn enter(&self, client: IpAddr) -> Option<ClientSlot<'_>> {
        let mut in_flight = self.lock();
        let count = in_flight.get(&client).copied().unwrap_or(0);
        if count >= self.limit {
            return None;
        }
        in_flight.insert(client, count + 1);
        Some(ClientSlot {
            owner: self,
            client,
        })
    }

    /// Clients with a lookup in flight right now.
    pub fn clients(&self) -> usize {
        self.lock().len()
    }

    /// The map is plain counters, valid at every step, so a poisoned lock
    /// is recovered rather than propagated.
    fn lock(&self) -> MutexGuard<'_, HashMap<IpAddr, u32>> {
        self.in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Drop for ClientSlot<'_> {
    fn drop(&mut self) {
        let mut in_flight = self.owner.lock();
        if let Some(count) = in_flight.get_mut(&self.client) {
            *count = count.saturating_sub(1);
            // Forget idle clients, so the map holds only lookups in flight.
            if *count == 0 {
                in_flight.remove(&self.client);
            }
        }
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
    /// Each anonymous client's lookups in flight.
    pub(crate) per_client: Arc<PerClient>,
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
            per_client: Arc::new(PerClient::new(settings.max_in_flight_per_client)),
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
    #[test]
    fn one_client_gets_only_so_many_lookups_at_once() {
        let ip = |text: &str| text.parse::<IpAddr>().unwrap();
        let per_client = PerClient::new(2);
        let first = per_client.enter(ip("203.0.113.7")).unwrap();
        let _second = per_client.enter(ip("203.0.113.7")).unwrap();
        assert!(per_client.enter(ip("203.0.113.7")).is_none());
        // Another client is not affected.
        let other = per_client.enter(ip("203.0.113.8")).unwrap();
        assert_eq!(per_client.clients(), 2);
        // Finishing a lookup frees its slot, and idle clients are forgotten.
        drop(first);
        assert!(per_client.enter(ip("203.0.113.7")).is_some());
        drop(other);
        assert_eq!(per_client.clients(), 1);
    }
}
