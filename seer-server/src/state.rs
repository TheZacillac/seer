//! What every handler shares: the settings and the seer-core clients.
//!
//! The clients are built once from the user's config (timeouts, default
//! nameserver) and shared by reference; none is rebuilt per request.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use seer_core::contract::CostClass;
use seer_core::dns::{DelegationChecker, PropagationChecker};
use seer_core::{
    Auditor, AvailabilityChecker, DnsComparator, DnsResolver, DnsTracer, DnssecChecker,
    DomainDiffer, RdapClient, SeerConfig, SmartLookup, SslChecker, StatusClient,
    SubdomainEnumerator, WhoisClient,
};

use tokio::sync::{AcquireError, Semaphore, SemaphorePermit};

use crate::app::Route;
use crate::cache::ResponseCache;
use crate::limit::Limits;
use crate::settings::Settings;
use crate::tier::{Caller, Tier};

/// How much longer than the audit's own timeout its request may run, so
/// the request deadline never cuts a finishing audit short.
const AUDIT_GRACE: Duration = Duration::from_secs(5);

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
    /// Subdomains from Certificate Transparency logs.
    pub subdomains: SubdomainEnumerator,
    /// DNSSEC chain checks.
    pub dnssec: DnssecChecker,
    /// Parent-versus-child NS delegation checks.
    pub delegation: DelegationChecker,
    /// Side-by-side comparison of two domains.
    pub differ: DomainDiffer,
    /// The graded security audit.
    pub auditor: Auditor,
    /// One query fanned out to public resolvers.
    pub propagation: PropagationChecker,
    /// The walk from the root servers down.
    pub tracer: DnsTracer,
    /// One query asked of two named servers.
    pub comparator: DnsComparator,
    /// Timeout for the HTTP probes that take one per call (headers,
    /// takeover).
    pub http_timeout: Duration,
    /// Deadline for an audit request: the audit timeout plus a grace.
    pub audit_deadline: Duration,
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
            subdomains: SubdomainEnumerator::from_config(config),
            dnssec: DnssecChecker::from_config(config),
            delegation: DelegationChecker::from_config(config),
            differ: DomainDiffer::from_config(config),
            auditor: Auditor::from_config(config),
            propagation: PropagationChecker::from_config(config),
            tracer: DnsTracer::from_config(config),
            comparator: DnsComparator::from_config(config),
            http_timeout: config.http_timeout(),
            audit_deadline: config.audit_timeout() + AUDIT_GRACE,
        }
    }
}

/// Most heavy fan-outs (audit, trace, takeover and the like) at once,
/// mirroring seer-api's bulk cap.
const HEAVY_SLOTS: usize = 8;

/// Slots for lookups in flight.
///
/// A total pool bounds the server's concurrent work. Anonymous callers
/// also need a slot from a pool half that size, so the public tier cannot
/// take every slot from keyed callers. Heavy routes also need one from a
/// small pool of their own, so fan-outs cannot take every slot from
/// ordinary lookups.
pub struct Permits {
    total: Semaphore,
    anonymous: Semaphore,
    heavy: Semaphore,
}

/// Slots held for one lookup; returned when dropped.
pub struct Held<'a> {
    _heavy: Option<SemaphorePermit<'a>>,
    _anonymous: Option<SemaphorePermit<'a>>,
    _total: SemaphorePermit<'a>,
}

impl Permits {
    /// `max_in_flight` slots in total; anonymous callers share half (at
    /// least one); heavy routes share `HEAVY_SLOTS`, kept one below the
    /// total so they never hold every slot.
    pub fn new(max_in_flight: usize) -> Self {
        Self {
            total: Semaphore::new(max_in_flight),
            anonymous: Semaphore::new((max_in_flight / 2).max(1)),
            heavy: Semaphore::new(HEAVY_SLOTS.min(max_in_flight.saturating_sub(1)).max(1)),
        }
    }

    /// Waits for the slots a `cost`-class lookup by `caller` needs. The
    /// scarcest pool is taken first (heavy, then anonymous, then total),
    /// so a waiter never sits on a slot that others could use. Dropping
    /// the wait returns whatever was already taken.
    pub async fn acquire(&self, caller: Caller, cost: CostClass) -> Result<Held<'_>, AcquireError> {
        let heavy = if cost == CostClass::Heavy {
            Some(self.heavy.acquire().await?)
        } else {
            None
        };
        let anonymous = match caller {
            Caller::Anonymous => Some(self.anonymous.acquire().await?),
            Caller::Keyed => None,
        };
        Ok(Held {
            _heavy: heavy,
            _anonymous: anonymous,
            _total: self.total.acquire().await?,
        })
    }

    /// Free heavy slots right now.
    pub fn heavy_available(&self) -> usize {
        self.heavy.available_permits()
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

/// Which deadline a route's requests run under.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deadline {
    /// `[server] request_timeout_secs`.
    Default,
    /// The audit timeout plus a grace: an audit is allowed far longer than
    /// one lookup.
    Audit,
}

/// What the gate and `Call` need to know about a route.
#[derive(Debug, Clone, Copy)]
pub struct RouteMeta {
    /// Who may call it.
    pub tier: Tier,
    /// How expensive it is, which sets its rate limit.
    pub cost: CostClass,
    /// Which deadline its requests run under.
    pub deadline: Deadline,
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
                    deadline: route.deadline,
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
    use tokio::time::timeout;

    const SOON: Duration = Duration::from_millis(50);

    #[tokio::test]
    async fn anonymous_callers_share_half_the_slots() {
        let permits = Permits::new(4);
        assert_eq!(permits.available(), (4, 2));
        let first = permits
            .acquire(Caller::Anonymous, CostClass::Light)
            .await
            .unwrap();
        let second = permits
            .acquire(Caller::Anonymous, CostClass::Light)
            .await
            .unwrap();
        assert_eq!(permits.available(), (2, 0));
        // A third anonymous caller waits; a keyed one does not.
        assert!(
            timeout(SOON, permits.acquire(Caller::Anonymous, CostClass::Light))
                .await
                .is_err()
        );
        let keyed = timeout(SOON, permits.acquire(Caller::Keyed, CostClass::Light)).await;
        assert!(
            keyed.is_ok(),
            "the public tier must not starve keyed callers"
        );
        drop(first);
        assert!(
            timeout(SOON, permits.acquire(Caller::Anonymous, CostClass::Light))
                .await
                .is_ok()
        );
        drop(second);
    }

    #[tokio::test]
    async fn keyed_callers_are_bounded_by_the_total() {
        let permits = Permits::new(2);
        let _a = permits
            .acquire(Caller::Keyed, CostClass::Light)
            .await
            .unwrap();
        let _b = permits
            .acquire(Caller::Keyed, CostClass::Light)
            .await
            .unwrap();
        assert!(
            timeout(SOON, permits.acquire(Caller::Keyed, CostClass::Light))
                .await
                .is_err()
        );
        // An anonymous waiter holds no total slot while it waits for one.
        assert_eq!(permits.available(), (0, 1));
    }

    #[tokio::test]
    async fn a_dropped_wait_returns_what_it_held() {
        let permits = Permits::new(2);
        let held = permits
            .acquire(Caller::Keyed, CostClass::Light)
            .await
            .unwrap();
        let _other = permits
            .acquire(Caller::Keyed, CostClass::Light)
            .await
            .unwrap();
        // This anonymous caller takes its anonymous slot, then times out
        // waiting for a total slot. Both must come back.
        assert!(
            timeout(SOON, permits.acquire(Caller::Anonymous, CostClass::Light))
                .await
                .is_err()
        );
        assert_eq!(permits.available(), (0, 1));
        drop(held);
        assert_eq!(permits.available(), (1, 1));
    }

    #[tokio::test]
    async fn heavy_lookups_share_a_small_pool() {
        let permits = Permits::new(64);
        assert_eq!(permits.heavy_available(), 8);
        let mut held = Vec::new();
        for _ in 0..8 {
            held.push(
                permits
                    .acquire(Caller::Keyed, CostClass::Heavy)
                    .await
                    .unwrap(),
            );
        }
        // A ninth fan-out waits; a light lookup does not.
        assert!(
            timeout(SOON, permits.acquire(Caller::Keyed, CostClass::Heavy))
                .await
                .is_err()
        );
        assert!(
            timeout(SOON, permits.acquire(Caller::Keyed, CostClass::Light))
                .await
                .is_ok()
        );
        held.pop();
        assert!(
            timeout(SOON, permits.acquire(Caller::Keyed, CostClass::Heavy))
                .await
                .is_ok()
        );
    }

    #[test]
    fn the_heavy_pool_always_leaves_a_slot_for_other_work() {
        assert_eq!(Permits::new(2).heavy_available(), 1);
        assert_eq!(Permits::new(4).heavy_available(), 3);
        assert_eq!(Permits::new(1024).heavy_available(), 8);
    }

    #[tokio::test]
    async fn a_heavy_waiter_holds_no_other_slot() {
        let permits = Permits::new(2);
        let _running = permits
            .acquire(Caller::Keyed, CostClass::Heavy)
            .await
            .unwrap();
        assert!(
            timeout(SOON, permits.acquire(Caller::Anonymous, CostClass::Heavy))
                .await
                .is_err()
        );
        // Only the running fan-out's total slot is gone.
        assert_eq!(permits.available(), (1, 1));
        assert_eq!(permits.heavy_available(), 0);
    }

    #[test]
    fn the_lookups_behind_the_keyed_routes_are_small_futures() {
        // PR 2 shipped a crash from 45-65 KB futures overflowing a worker
        // stack in debug builds. Building a future sends nothing; none is
        // polled here.
        use seer_core::{AuditOptions, RecordType};
        use std::mem::size_of_val;

        let c = Clients::from_config(&SeerConfig::default());
        let (d, a) = ("example.com", RecordType::A);
        let soon = Duration::from_secs(1);
        let sizes = [
            ("subdomains", size_of_val(&c.subdomains.enumerate(d))),
            (
                "classify",
                size_of_val(&seer_core::classify_subdomains(&c.dns, d, vec![], 10)),
            ),
            ("dnssec", size_of_val(&c.dnssec.check(d))),
            ("delegation", size_of_val(&c.delegation.check(d))),
            ("diff", size_of_val(&c.differ.diff(d, d))),
            (
                "caa",
                size_of_val(&seer_core::caa::lookup_caa(&c.dns, d, None)),
            ),
            (
                "posture",
                size_of_val(&seer_core::lookup_email_posture(&c.dns, d, None)),
            ),
            ("headers", size_of_val(&seer_core::audit_headers(d, soon))),
            (
                "audit",
                size_of_val(&c.auditor.audit(d, AuditOptions::default())),
            ),
            (
                "takeover",
                size_of_val(&seer_core::scan_takeover(&c.dns, d, vec![], 10, soon)),
            ),
            (
                "confusables",
                size_of_val(&seer_core::find_confusables(&c.lookup, d, 10)),
            ),
            ("propagation", size_of_val(&c.propagation.check(d, a))),
            ("trace", size_of_val(&c.tracer.trace(d, a))),
            (
                "compare",
                size_of_val(&c.comparator.compare(d, a, "8.8.8.8", "1.1.1.1")),
            ),
        ];
        for (name, size) in sizes {
            assert!(
                size <= 16 * 1024,
                "the {name} future is {size} bytes; box its stages in seer-core with `.boxed()`"
            );
        }
    }

    #[test]
    fn the_audit_deadline_is_the_audit_timeout_plus_five_seconds() {
        // An audit may take its whole timeout (60 s by default); the request
        // deadline must not cut it short.
        let clients = Clients::from_config(&SeerConfig::default());
        assert_eq!(clients.audit_deadline, Duration::from_secs(65));
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
