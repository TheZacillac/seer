use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::sync::{LazyLock, Mutex, MutexGuard, OnceLock};

use pyo3::exceptions::{PyConnectionError, PyRuntimeError, PyTimeoutError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict};
use pyo3::Py;
use seer_core::{
    bulk::{BulkExecutor, BulkOperation},
    dns::{
        DelegationChecker, DnsComparator, DnsFollower, DnsResolver, DnssecChecker, FollowConfig,
        NameserverSpec, PropagationChecker, RecordType,
    },
    lookup::SmartLookup,
    rdap::RdapClient,
    status::StatusClient,
    whois::WhoisClient,
    AvailabilityChecker, DomainDiffer, SeerError, SslChecker, SubdomainEnumerator,
};
use tokio::sync::watch;

/// Global cancellation sender for the currently-active `dns_follow` call.
///
/// The sender is replaced at the start of each `dns_follow` invocation so that
/// calls do not see cancellations from previous calls. `cancel_follow()`
/// signals whatever call is currently active.
fn follow_cancel_sender() -> &'static Mutex<watch::Sender<bool>> {
    static INSTANCE: OnceLock<Mutex<watch::Sender<bool>>> = OnceLock::new();
    INSTANCE.get_or_init(|| {
        let (tx, _rx) = watch::channel(false);
        Mutex::new(tx)
    })
}

/// Poison-tolerant lock helper for the follow cancel sender.
///
/// If a prior `dns_follow` panicked while holding this lock, the mutex is
/// poisoned. We recover the inner value rather than propagating the panic —
/// the channel's state is effectively "fresh" since the worst case is that a
/// stale cancel signal is in the watch, and each `dns_follow` installs a new
/// channel anyway.
fn lock_follow() -> MutexGuard<'static, watch::Sender<bool>> {
    follow_cancel_sender()
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

/// Guard enforcing that only a single `dns_follow` call is active at a time.
///
/// `dns_follow` installs a shared `watch::Sender<bool>` into a global slot so
/// that `cancel_follow()` can signal the running task. Without a guard, a
/// concurrent call would silently overwrite the sender, leaking the ability to
/// cancel the earlier call. We fail loudly instead.
static FOLLOW_ACTIVE: AtomicBool = AtomicBool::new(false);

struct FollowActiveGuard;

impl FollowActiveGuard {
    fn acquire() -> PyResult<Self> {
        if FOLLOW_ACTIVE
            .compare_exchange(false, true, SeqCst, SeqCst)
            .is_err()
        {
            return Err(PyRuntimeError::new_err(
                "dns_follow is already running; cancel it or wait",
            ));
        }
        Ok(Self)
    }
}

impl Drop for FollowActiveGuard {
    fn drop(&mut self) {
        FOLLOW_ACTIVE.store(false, SeqCst);
    }
}

fn get_runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create Tokio runtime")
    })
}

/// Map a `SeerError` to a Python exception using the variant-aware
/// `sanitized_message()` so that internal URLs, hostnames, and raw system
/// errors never leak to Python callers. Validation-shaped errors become
/// `ValueError`; everything else is a `RuntimeError`.
fn seer_err_to_py(e: &SeerError) -> PyErr {
    use SeerError::*;
    match e {
        InvalidInput(_)
        | InvalidDomain(_)
        | InvalidIpAddress(_)
        | InvalidRecordType(_)
        | DomainNotAllowed { .. } => PyValueError::new_err(e.sanitized_message()),
        // Map transient categories to specific Python builtin exceptions so
        // downstream consumers (MCP server, direct seer-py users) can do
        // targeted `except TimeoutError` / `except ConnectionError` retries
        // instead of catching the broad `RuntimeError` umbrella.
        Timeout(_) => PyTimeoutError::new_err(e.sanitized_message()),
        WhoisConnectionFailed { .. } => PyConnectionError::new_err(e.sanitized_message()),
        // RetryExhausted wraps the retry framework's final failure; classify
        // by the inner error so a retried timeout still surfaces as
        // TimeoutError (which seer-api maps to 504/502) rather than a generic
        // RuntimeError. Recursion also unwraps layered retry wrappers.
        RetryExhausted { last_error, .. } => seer_err_to_py(last_error),
        _ => PyRuntimeError::new_err(e.sanitized_message()),
    }
}

/// Run an async `SeerError`-returning future on the shared Tokio runtime and
/// marshal the outcome into a `PyResult`.
///
/// Errors are routed through `seer_err_to_py` so that sanitized, typed
/// messages reach the caller. Panic safety comes from
/// [`run_async_infallible`].
fn run_async<F, T>(py: Python<'_>, fut: F) -> PyResult<T>
where
    F: Future<Output = seer_core::Result<T>> + Send,
    T: Send,
{
    run_async_infallible(py, fut)?.map_err(|e| seer_err_to_py(&e))
}

/// Serialize a Rust response to `serde_json::Value`, mapping any error to a
/// generic `PyRuntimeError`. `serde_json::to_value` on our own domain types
/// should never fail; if it does, that's an internal bug — do not leak the
/// underlying error text (which could include type/field names) to callers.
fn serialize_response<T: serde::Serialize>(value: &T) -> PyResult<serde_json::Value> {
    serde_json::to_value(value)
        .map_err(|_| PyRuntimeError::new_err("internal error: failed to serialize response"))
}

/// Serialize a core response and convert it into a Python object.
fn to_py<'py, T: serde::Serialize>(py: Python<'py>, value: &T) -> PyResult<Bound<'py, PyAny>> {
    json_to_python(py, &serialize_response(value)?)
}

/// Parse a DNS record-type name; an unknown one raises `ValueError`.
fn parse_record_type(record_type: &str) -> PyResult<RecordType> {
    record_type
        .parse()
        .map_err(|e: SeerError| seer_err_to_py(&e))
}

/// Run a future on the shared Tokio runtime with the GIL released. Used
/// directly for futures that do not return a `SeerError` (e.g.
/// `BulkExecutor::execute`, which reports per-item failures in the returned
/// `Vec<BulkResult>`).
///
/// Wraps the `block_on` in `std::panic::catch_unwind`: a panic that unwinds
/// through the FFI boundary is UB and would abort the Python process. Common
/// causes include calling a blocking runtime from inside another async runtime
/// (e.g. from `asyncio`) which tokio explicitly panics on. We surface that as
/// a `RuntimeError` instead.
fn run_async_infallible<F, T>(py: Python<'_>, fut: F) -> PyResult<T>
where
    F: Future<Output = T> + Send,
    T: Send,
{
    py.detach(
        || match catch_unwind(AssertUnwindSafe(|| get_runtime().block_on(fut))) {
            Ok(v) => Ok(v),
            Err(_) => Err(PyRuntimeError::new_err(
                "panic in seer runtime (likely nested async context or internal bug)",
            )),
        },
    )
}

// Process-wide core clients, each built on first use and shared by every call.
static SMART_LOOKUP: LazyLock<SmartLookup> = LazyLock::new(SmartLookup::new);
static WHOIS_CLIENT: LazyLock<WhoisClient> = LazyLock::new(WhoisClient::new);
static RDAP_CLIENT: LazyLock<RdapClient> = LazyLock::new(RdapClient::new);
static DNS_RESOLVER: LazyLock<DnsResolver> = LazyLock::new(DnsResolver::new);
static PROPAGATION_CHECKER: LazyLock<PropagationChecker> = LazyLock::new(PropagationChecker::new);
static STATUS_CLIENT: LazyLock<StatusClient> = LazyLock::new(StatusClient::new);
static AVAILABILITY_CHECKER: LazyLock<AvailabilityChecker> =
    LazyLock::new(AvailabilityChecker::new);
static SUBDOMAIN_ENUMERATOR: LazyLock<SubdomainEnumerator> =
    LazyLock::new(SubdomainEnumerator::new);
static SSL_CHECKER: LazyLock<SslChecker> = LazyLock::new(SslChecker::new);
static DNSSEC_CHECKER: LazyLock<DnssecChecker> = LazyLock::new(DnssecChecker::new);
static DELEGATION_CHECKER: LazyLock<DelegationChecker> = LazyLock::new(DelegationChecker::new);
static DNS_COMPARATOR: LazyLock<DnsComparator> = LazyLock::new(DnsComparator::new);
static DNS_FOLLOWER: LazyLock<DnsFollower> = LazyLock::new(DnsFollower::new);
static DOMAIN_DIFFER: LazyLock<DomainDiffer> = LazyLock::new(DomainDiffer::new);

/// Validate that a host is safe to connect to (not a reserved/loopback/private IP).
///
/// Wraps `seer_core::net::validate_public_host`. Raises `ValueError` if the host
/// is an IP literal in a reserved range, or if it resolves to such an address.
/// Used by `seer-api` to block SSRF before dispatching outbound calls.
#[pyfunction]
fn validate_public_host(py: Python<'_>, host: String, port: u16) -> PyResult<()> {
    run_async(py, async move {
        seer_core::net::validate_public_host(&host, port).await
    })
}

/// The `(host, port)` a nameserver spec (`8.8.8.8`, `9.9.9.9:5353`,
/// `tls://host[:port]`, `https://host[:port][/path]`) makes the resolver
/// contact, or `None` for a spec seer-core rejects. Lets `seer-api` SSRF-check
/// the address actually connected to with the core's own parser rather than
/// a hand-synced copy. Pure parsing; no network I/O.
#[pyfunction]
fn nameserver_target(spec: &str) -> Option<(String, u16)> {
    NameserverSpec::parse(spec).ok().map(|s| (s.host, s.port))
}

/// Generates the single-argument bindings that make one core call and return
/// its serialized result. `$call` runs inside the runtime, so a client static
/// it names is built there on first use, with the GIL released.
macro_rules! call_fn {
    ($(
        $(#[$meta:meta])*
        $name:ident($arg:ident: $ty:ty) => $call:expr;
    )*) => {$(
        $(#[$meta])*
        #[pyfunction]
        fn $name<'py>(py: Python<'py>, $arg: $ty) -> PyResult<Bound<'py, PyAny>> {
            let response = run_async(py, async move { $call.await })?;
            to_py(py, &response)
        }
    )*};
}

call_fn! {
    lookup(domain: String) => SMART_LOOKUP.lookup(&domain);
    whois(domain: String) => WHOIS_CLIENT.lookup(&domain);
    rdap_domain(domain: String) => RDAP_CLIENT.lookup_domain(&domain);
    rdap_ip(ip: String) => RDAP_CLIENT.lookup_ip(&ip);
    rdap_asn(asn: u32) => RDAP_CLIENT.lookup_asn(asn);
    /// Look up RDAP data for a domain, IP address or ASN. The shape of
    /// `query` picks the lookup:
    ///
    /// - an IPv4 or IPv6 address (8.8.8.8, 2606:4700:4700::1111): IP lookup
    /// - AS15169 or as15169, with no dots: ASN lookup
    /// - anything else: domain lookup (so as1234.io stays a domain)
    ///
    /// Returns the RDAP response as a dict. seer.rdap is the same function.
    rdap_auto(query: String) => seer_core::rdap::auto_lookup(&RDAP_CLIENT, &query);
    status(domain: String) => STATUS_CLIENT.check(&domain);
    availability(domain: String) => AVAILABILITY_CHECKER.check(&domain);
    subdomains(domain: String) => SUBDOMAIN_ENUMERATOR.enumerate(&domain);
    ssl(domain: String) => SSL_CHECKER.check(&domain);
    dnssec(domain: String) => DNSSEC_CHECKER.check(&domain);
    delegation(domain: String) => DELEGATION_CHECKER.check(&domain);
    posture(domain: String) => seer_core::lookup_email_posture(&DNS_RESOLVER, &domain);
    headers(domain: String)
        => seer_core::audit_headers(&domain, seer_core::DEFAULT_HEADER_TIMEOUT);
}

#[pyfunction]
#[pyo3(signature = (domain, record_type = "A", nameserver = None))]
fn dig<'py>(
    py: Python<'py>,
    domain: String,
    record_type: &str,
    nameserver: Option<String>,
) -> PyResult<Bound<'py, PyAny>> {
    let rt_parsed = parse_record_type(record_type)?;

    let records = run_async(py, async move {
        DNS_RESOLVER
            .resolve(&domain, rt_parsed, nameserver.as_deref())
            .await
    })?;

    to_py(py, &records)
}

#[pyfunction]
#[pyo3(signature = (domain, record_type = "A"))]
fn propagation<'py>(
    py: Python<'py>,
    domain: String,
    record_type: &str,
) -> PyResult<Bound<'py, PyAny>> {
    let rt_parsed = parse_record_type(record_type)?;

    let response = run_async(py, async move {
        PROPAGATION_CHECKER.check(&domain, rt_parsed).await
    })?;
    to_py(py, &response)
}

const MAX_CONCURRENCY: usize = 50;

/// Maximum number of domains accepted by a single `bulk_*` call. Mirrors the
/// FastAPI router's `MAX_BULK_DOMAINS` (seer-api) so the binding — the real
/// trust boundary for direct seer-py and MCP callers, which bypass the REST
/// router — rejects oversized lists up front instead of buffering an unbounded
/// `Vec` / JSON value / Python object graph with no backpressure (issue #58).
const MAX_BULK_DOMAINS: usize = 100;

/// Validates a requested bulk concurrency. The two bounds are intentionally
/// asymmetric: `> MAX_CONCURRENCY` is a hard ceiling and is *rejected* (a DoS
/// guard — see issue #58), whereas `0` is a nonsensical request that is quietly
/// *floored to 1* rather than erroring, so a caller that derives concurrency
/// from arithmetic (e.g. `len / chunk`) can't accidentally deadlock on a
/// zero-permit semaphore.
fn validate_concurrency(concurrency: usize) -> PyResult<usize> {
    if concurrency > MAX_CONCURRENCY {
        return Err(PyValueError::new_err(format!(
            "concurrency must be <= {} (got {})",
            MAX_CONCURRENCY, concurrency
        )));
    }
    Ok(concurrency.max(1))
}

fn validate_domains(domains: &[String]) -> PyResult<()> {
    if domains.len() > MAX_BULK_DOMAINS {
        return Err(PyValueError::new_err(format!(
            "too many domains: {} (max {})",
            domains.len(),
            MAX_BULK_DOMAINS
        )));
    }
    Ok(())
}

/// Internal progress event carried from the Tokio workers (where
/// `ProgressCallback` fires) to the dedicated OS thread that actually
/// invokes the Python callable.
struct ProgressEvent {
    completed: usize,
    total: usize,
    domain: String,
}

/// Decoupling pipe between seer-core's `ProgressCallback` (called from
/// Tokio worker threads) and the Python callable supplied by the caller.
///
/// Rationale: if the Python callable itself blocks — or even just yields
/// GIL contention — a closure that acquires the GIL directly from a Tokio
/// worker can deadlock the runtime. The GIL-holding thread may be waiting
/// on a Tokio task that cannot make progress because every worker is
/// parked behind `Python::with_gil`. Bulk runs with `n` domains under
/// high concurrency turn this into an `O(n)` pile-up.
///
/// Instead we post lightweight events to a bounded `sync_channel`. A
/// single dedicated OS thread drains the channel and holds the GIL only
/// while invoking the callback. Tokio workers never touch Python.
///
/// Progress is advisory, so if the channel is full we drop the event
/// rather than back-pressuring the Tokio worker.
///
/// Lifecycle: the pipe is kept alive by an `Arc` captured in the
/// `ProgressCallback` closure returned from `build_progress_callback`.
/// When seer-core drops that callback at the end of the bulk run, the
/// `Arc` refcount drops to zero, the sender is dropped, the channel
/// closes, `rx.recv()` returns `Err`, and the drainer thread exits.
struct ProgressPipe {
    /// Wrapped in `Option` so `Drop` can take ownership and drop the
    /// sender *before* joining the drainer — otherwise the drainer would
    /// block forever on `rx.recv()`.
    tx: Option<std::sync::mpsc::SyncSender<ProgressEvent>>,
    /// Drainer thread handle. Joined on drop so all queued events fire
    /// before the bulk call returns to Python. Option so `Drop::drop`
    /// can take ownership.
    drainer: Option<std::thread::JoinHandle<()>>,
}

impl ProgressPipe {
    /// Construct the pipe and spawn the drainer thread.
    ///
    /// Returns `Err` if the OS refuses to spawn the drainer (typically
    /// resource exhaustion). Propagating this as a `PyErr` is mandatory:
    /// every other `block_on` in this module is wrapped in `catch_unwind`
    /// because a panic unwinding across the FFI boundary is UB. An
    /// `.expect()` here would bypass that protection and abort the Python
    /// process on a transient failure.
    fn new(py_cb: Py<PyAny>) -> Result<Self, PyErr> {
        // Bounded channel. 1024 is deep enough to smooth over brief GIL
        // contention but shallow enough that a pathologically slow
        // callback causes `try_send` to drop events rather than ballooning
        // memory.
        let (tx, rx) = std::sync::mpsc::sync_channel::<ProgressEvent>(1024);
        let drainer = std::thread::Builder::new()
            .name("seer-progress-drainer".to_string())
            .spawn(move || {
                // Blocks holding no resources until an event arrives or
                // the last sender is dropped (= pipe teardown).
                while let Ok(ev) = rx.recv() {
                    Python::attach(|py| {
                        let bound = py_cb.bind(py);
                        if let Err(err) = bound.call1((ev.completed, ev.total, ev.domain)) {
                            // A callback raising is not fatal: log and
                            // keep draining so later events still fire.
                            tracing::warn!(
                                error = %err,
                                "bulk progress callback raised; ignoring",
                            );
                        }
                    });
                }
            })
            .map_err(|e| {
                PyRuntimeError::new_err(format!("failed to spawn progress drainer thread: {e}"))
            })?;
        Ok(Self {
            tx: Some(tx),
            drainer: Some(drainer),
        })
    }

    /// Non-blocking send. Drops the event if the channel is full or the
    /// drainer has exited — progress is advisory.
    fn send(&self, ev: ProgressEvent) {
        if let Some(tx) = &self.tx {
            let _ = tx.try_send(ev);
        }
    }
}

impl Drop for ProgressPipe {
    fn drop(&mut self) {
        // Close the channel first by dropping the sender; otherwise the
        // drainer's `rx.recv()` would block forever waiting on us.
        drop(self.tx.take());
        // Then wait for the drainer to process any still-queued events
        // and exit. We intentionally join so that callers observe all
        // callback invocations before `bulk_*` returns — otherwise a
        // test that asserts "N events fired" would race with the drainer.
        if let Some(handle) = self.drainer.take() {
            // A panic on the drainer thread would already have been
            // surfaced via `e.print(py)` inside the loop; a secondary
            // panic from join itself should not crash the bulk run.
            if let Err(e) = handle.join() {
                tracing::warn!(?e, "progress drainer thread panicked during teardown");
            }
        }
    }
}

/// Converts an optional Python callable into a Rust `ProgressCallback`.
///
/// The returned callback posts to a `ProgressPipe` and never touches the
/// GIL, so Tokio workers cannot deadlock on GIL contention when the
/// Python callback is slow. See [`ProgressPipe`] for the full rationale.
///
/// Returns `Err` if pipe construction fails (e.g. the OS refuses to spawn
/// the drainer thread). Callers propagate the error with `?` so the Python
/// caller sees a `RuntimeError` rather than a panic across FFI.
fn build_progress_callback(
    progress: Option<Py<PyAny>>,
) -> PyResult<Option<seer_core::bulk::ProgressCallback>> {
    match progress {
        None => Ok(None),
        Some(py_cb) => {
            // `Arc` so the pipe (which owns the drainer thread) lives as
            // long as the callback itself. When the executor drops this
            // Box at the end of the bulk run, the Arc's refcount hits
            // zero, the ProgressPipe drops, the sender closes, and the
            // drainer exits.
            let pipe = std::sync::Arc::new(ProgressPipe::new(py_cb)?);
            Ok(Some(
                Box::new(move |completed: usize, total: usize, domain: &str| {
                    pipe.send(ProgressEvent {
                        completed,
                        total,
                        domain: domain.to_string(),
                    });
                }) as seer_core::bulk::ProgressCallback,
            ))
        }
    }
}

/// Runs a prepared batch on a fresh executor and returns its serialized
/// results. Deliberately non-generic, so the executor future is instantiated
/// once rather than per binding.
fn execute_bulk<'py>(
    py: Python<'py>,
    operations: Vec<BulkOperation>,
    concurrency: usize,
    progress: Option<Py<PyAny>>,
) -> PyResult<Bound<'py, PyAny>> {
    let executor = BulkExecutor::new().with_concurrency(concurrency);
    let cb = build_progress_callback(progress)?;
    let result = run_async_infallible(py, async move { executor.execute(operations, cb).await })?;
    to_py(py, &result)
}

/// Validates a bulk call's domain count and concurrency, then runs one
/// operation per domain.
fn run_bulk<'py>(
    py: Python<'py>,
    domains: Vec<String>,
    concurrency: usize,
    progress: Option<Py<PyAny>>,
    op: impl Fn(String) -> BulkOperation,
) -> PyResult<Bound<'py, PyAny>> {
    validate_domains(&domains)?;
    let concurrency = validate_concurrency(concurrency)?;
    let operations = domains.into_iter().map(op).collect();
    execute_bulk(py, operations, concurrency, progress)
}

/// Generates the `bulk_*` bindings whose operation needs only the domain.
macro_rules! bulk_fn {
    ($($name:ident => $variant:ident;)*) => {$(
        #[pyfunction]
        #[pyo3(signature = (domains, concurrency = 10, *, progress = None))]
        fn $name<'py>(
            py: Python<'py>,
            domains: Vec<String>,
            concurrency: usize,
            progress: Option<Py<PyAny>>,
        ) -> PyResult<Bound<'py, PyAny>> {
            run_bulk(py, domains, concurrency, progress, |domain| {
                BulkOperation::$variant { domain }
            })
        }
    )*};
}

bulk_fn! {
    bulk_lookup => Lookup;
    bulk_whois => Whois;
    bulk_status => Status;
    bulk_ssl => Ssl;
    bulk_availability => Avail;
    bulk_info => Info;
}

#[pyfunction]
#[pyo3(signature = (domains, record_type = "A", concurrency = 10, *, progress = None))]
fn bulk_dig<'py>(
    py: Python<'py>,
    domains: Vec<String>,
    record_type: &str,
    concurrency: usize,
    progress: Option<Py<PyAny>>,
) -> PyResult<Bound<'py, PyAny>> {
    validate_domains(&domains)?;
    let concurrency = validate_concurrency(concurrency)?;
    let record_type = parse_record_type(record_type)?;
    let operations = domains
        .into_iter()
        .map(|domain| BulkOperation::Dns {
            domain,
            record_type,
        })
        .collect();
    execute_bulk(py, operations, concurrency, progress)
}

#[pyfunction]
#[pyo3(signature = (domains, record_type = "A", concurrency = 5, *, progress = None))]
fn bulk_propagation<'py>(
    py: Python<'py>,
    domains: Vec<String>,
    record_type: &str,
    concurrency: usize,
    progress: Option<Py<PyAny>>,
) -> PyResult<Bound<'py, PyAny>> {
    validate_domains(&domains)?;
    let concurrency = validate_concurrency(concurrency)?;
    let record_type = parse_record_type(record_type)?;
    let operations = domains
        .into_iter()
        .map(|domain| BulkOperation::Propagation {
            domain,
            record_type,
        })
        .collect();
    execute_bulk(py, operations, concurrency, progress)
}

#[pyfunction]
fn caa<'py>(py: Python<'py>, domain: String) -> PyResult<Bound<'py, PyAny>> {
    let normalized = seer_core::normalize_domain(&domain).map_err(|e| seer_err_to_py(&e))?;
    let policy = run_async_infallible(py, async move {
        seer_core::caa::lookup_caa(&DNS_RESOLVER, &normalized).await
    })?;
    to_py(py, &policy)
}

#[pyfunction]
#[pyo3(signature = (domain, concurrency = 10))]
fn takeover<'py>(
    py: Python<'py>,
    domain: String,
    concurrency: usize,
) -> PyResult<Bound<'py, PyAny>> {
    let concurrency = validate_concurrency(concurrency)?;
    let response = run_async(py, async move {
        let result = SUBDOMAIN_ENUMERATOR.enumerate(&domain).await?;
        seer_core::scan_takeover(
            &DNS_RESOLVER,
            &result.domain,
            result.subdomains,
            concurrency,
        )
        .await
    })?;
    to_py(py, &response)
}

#[pyfunction]
#[pyo3(signature = (domain, concurrency = 10))]
fn confusables<'py>(
    py: Python<'py>,
    domain: String,
    concurrency: usize,
) -> PyResult<Bound<'py, PyAny>> {
    let concurrency = validate_concurrency(concurrency)?;
    let response = run_async(py, async move {
        seer_core::find_confusables(&SMART_LOOKUP, &domain, concurrency).await
    })?;
    to_py(py, &response)
}

#[pyfunction]
#[pyo3(signature = (domain, concurrency = 10))]
fn subdomains_classify<'py>(
    py: Python<'py>,
    domain: String,
    concurrency: usize,
) -> PyResult<Bound<'py, PyAny>> {
    let concurrency = validate_concurrency(concurrency)?;
    let response = run_async(py, async move {
        let result = SUBDOMAIN_ENUMERATOR.enumerate(&domain).await?;
        Ok::<_, SeerError>(
            seer_core::classify_subdomains(
                &DNS_RESOLVER,
                &result.domain,
                result.subdomains,
                concurrency,
            )
            .await,
        )
    })?;
    to_py(py, &response)
}

#[pyfunction]
fn dns_compare<'py>(
    py: Python<'py>,
    domain: String,
    record_type: &str,
    server_a: String,
    server_b: String,
) -> PyResult<Bound<'py, PyAny>> {
    let rt_parsed = parse_record_type(record_type)?;

    let response = run_async(py, async move {
        DNS_COMPARATOR
            .compare(&domain, rt_parsed, &server_a, &server_b)
            .await
    })?;

    to_py(py, &response)
}

#[pyfunction]
#[pyo3(signature = (domain, record_type="A", nameserver=None, iterations=3, interval_minutes=1.0))]
fn dns_follow<'py>(
    py: Python<'py>,
    domain: String,
    record_type: &str,
    nameserver: Option<String>,
    iterations: usize,
    interval_minutes: f64,
) -> PyResult<Bound<'py, PyAny>> {
    // Refuse concurrent calls before touching any shared state — a second
    // call would overwrite the global cancel sender, silently orphaning the
    // first call's ability to be cancelled. The guard releases on return.
    let _active = FollowActiveGuard::acquire()?;

    let rt_parsed = parse_record_type(record_type)?;

    // Validate iteration/interval via core; this rejects NaN/inf/negative and
    // enforces the per-interval cap (<= 60 minutes).
    let config = FollowConfig::new(iterations, interval_minutes).map_err(|e| seer_err_to_py(&e))?;

    // Binding-specific caps, intentionally STRICTER than `FollowConfig`'s core
    // limits (10_000 iterations / 60-min interval): seer-py drives a single
    // shared, process-wide Tokio runtime, so an over-long follow would block it
    // for every other caller. These are not redundant with the core caps — do
    // not "deduplicate" them away; they bound total wall-clock on the shared
    // runtime, which the core (used by the CLI's own runtime) does not.
    const MAX_ITERATIONS: usize = 100;
    if iterations > MAX_ITERATIONS {
        return Err(PyValueError::new_err(format!(
            "iterations must be <= {} (got {})",
            MAX_ITERATIONS, iterations
        )));
    }
    let total_minutes = iterations as f64 * interval_minutes;
    const MAX_TOTAL_MINUTES: f64 = 60.0;
    if total_minutes > MAX_TOTAL_MINUTES {
        return Err(PyValueError::new_err(format!(
            "Total follow duration ({:.0} minutes) exceeds maximum of {:.0} minutes. Reduce iterations or interval.",
            total_minutes, MAX_TOTAL_MINUTES
        )));
    }

    // Install a fresh cancellation channel for this call so that any previous
    // `cancel_follow()` signals do not affect it. Use `lock_follow` rather
    // than `.expect` so a prior panic cannot permanently break the endpoint.
    let cancel_rx = {
        let (tx, rx) = watch::channel(false);
        let mut slot = lock_follow();
        *slot = tx;
        rx
    };

    let response = run_async(py, async move {
        DNS_FOLLOWER
            .follow(
                &domain,
                rt_parsed,
                nameserver.as_deref(),
                config,
                None,
                Some(cancel_rx),
            )
            .await
    });

    // Reset the global sender so stale `cancel_follow()` calls after this
    // invocation returns do not affect a subsequent call that happens to race
    // before it installs its own sender.
    {
        let (tx, _rx) = watch::channel(false);
        let mut slot = lock_follow();
        *slot = tx;
    }

    let response = response?;
    to_py(py, &response)
}

/// Signal the currently-running `dns_follow` call (if any) to cancel.
///
/// This is a best-effort signal: the call will return on its next cancellation
/// check point (between DNS lookups or while sleeping between iterations).
/// If no `dns_follow` is currently running, this is a no-op.
///
/// Intentionally does not acquire `FollowActiveGuard`: its purpose is to
/// interrupt a running `dns_follow`, so it must be callable concurrently with
/// one.
#[pyfunction]
fn cancel_follow() -> PyResult<()> {
    let slot = lock_follow();
    let _ = slot.send(true);
    Ok(())
}

#[pyfunction]
fn diff<'py>(py: Python<'py>, domain_a: String, domain_b: String) -> PyResult<Bound<'py, PyAny>> {
    let response = run_async(
        py,
        async move { DOMAIN_DIFFER.diff(&domain_a, &domain_b).await },
    )?;
    to_py(py, &response)
}

#[pyfunction]
fn info<'py>(py: Python<'py>, domain: String) -> PyResult<Bound<'py, PyAny>> {
    let lookup_result = run_async(py, async move { SMART_LOOKUP.lookup(&domain).await })?;
    let domain_info = seer_core::domain_info::DomainInfo::from_lookup_result(&lookup_result);
    to_py(py, &domain_info)
}

/// Look up information about a TLD: WHOIS server, RDAP endpoint, registry
/// URL, and classification (generic/country-code/sponsored/infrastructure).
///
/// Accepts the TLD with or without a leading dot (e.g. "com" or ".com").
/// The WHOIS server / registry URL / classification come from the embedded
/// TLD map; the RDAP URL requires the IANA bootstrap data (async network
/// call, cached 24h) and is `None` when the bootstrap is unavailable.
#[pyfunction]
fn tld_info<'py>(py: Python<'py>, tld: String) -> PyResult<Bound<'py, PyAny>> {
    // `lookup_tld` is infallible: unknown TLDs yield a TldInfo with None
    // fields rather than an error.
    let info = run_async_infallible(py, async move { seer_core::lookup_tld(&tld).await })?;
    to_py(py, &info)
}

/// Return the full catalog of TLDs seer knows about (sorted, deduplicated).
/// Purely embedded data — no network access.
#[pyfunction]
fn all_tlds() -> Vec<String> {
    seer_core::all_tlds()
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Return every DNS record type `dig`/`propagation` accept, in canonical
/// order. Purely embedded data — no network access.
///
/// Exists so Python surfaces (the MCP tool schema, in particular) can render
/// the list instead of hand-mirroring it: the MCP schema had drifted to 13 of
/// 16 types, leaving NAPTR/TLSA/SSHFP queryable but undiscoverable by the AI
/// clients that read it.
#[pyfunction]
fn record_types() -> Vec<String> {
    RecordType::ALL_NAMES
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Maximum recursion depth permitted when converting `serde_json::Value`
/// into a Python object graph.
///
/// An adversarial WHOIS or RDAP response could nest arrays or objects
/// deeply enough to overflow the thread stack during conversion, which
/// aborts the process unrecoverably. The cap surfaces the failure as a
/// catchable `ValueError` instead. 128 levels is well above anything any
/// real-world registry response has ever contained.
const MAX_JSON_DEPTH: usize = 128;

/// Entry point for converting a `serde_json::Value` into a Python object.
/// Starts the recursion at depth 0; the inner helper enforces
/// [`MAX_JSON_DEPTH`].
fn json_to_python<'py>(py: Python<'py>, value: &serde_json::Value) -> PyResult<Bound<'py, PyAny>> {
    json_to_python_inner(py, value, 0)
}

fn json_to_python_inner<'py>(
    py: Python<'py>,
    value: &serde_json::Value,
    depth: usize,
) -> PyResult<Bound<'py, PyAny>> {
    // `>` (not `>=`): unlike `walk_depth` in `rdap/types.rs` (which only
    // recurses into entity arrays), this function visits EVERY node — the
    // leaf value of a structure nested MAX_JSON_DEPTH levels deep arrives
    // here with `depth == MAX_JSON_DEPTH`. The contract is that exactly
    // MAX_JSON_DEPTH nesting levels convert successfully, so only depths
    // beyond that are rejected (`tests/test_json_depth.py` pins both
    // boundaries).
    if depth > MAX_JSON_DEPTH {
        return Err(PyValueError::new_err(format!(
            "JSON structure exceeds max depth {MAX_JSON_DEPTH}"
        )));
    }
    match value {
        serde_json::Value::Null => Ok(py.None().into_bound(py)),
        serde_json::Value::Bool(b) => Ok(b.into_pyobject(py)?.to_owned().into_any()),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_pyobject(py)?.into_any())
            } else if let Some(u) = n.as_u64() {
                Ok(u.into_pyobject(py)?.into_any())
            } else if let Some(f) = n.as_f64() {
                Ok(f.into_pyobject(py)?.into_any())
            } else {
                Err(PyRuntimeError::new_err("Invalid number"))
            }
        }
        serde_json::Value::String(s) => Ok(s.into_pyobject(py)?.to_owned().into_any()),
        serde_json::Value::Array(arr) => {
            let list: Vec<Bound<'py, PyAny>> = arr
                .iter()
                .map(|v| json_to_python_inner(py, v, depth + 1))
                .collect::<PyResult<_>>()?;
            Ok(list.into_pyobject(py)?.into_any())
        }
        serde_json::Value::Object(obj) => {
            let dict = PyDict::new(py);
            for (k, v) in obj {
                dict.set_item(k, json_to_python_inner(py, v, depth + 1)?)?;
            }
            Ok(dict.into_any())
        }
    }
}

/// Largest `depth` [`_json_to_python_nested_for_test`] will build: far past
/// [`MAX_JSON_DEPTH`] (so over-limit inputs still exercise the guard) yet
/// shallow enough that building and recursively dropping the value is safe
/// on any thread's stack.
const MAX_TEST_NESTING: usize = 1024;

/// Test hook: constructs a `serde_json::Value` with `depth` levels of
/// nested arrays and runs it through [`json_to_python`].
///
/// Used by `tests/test_json_depth.py` to verify the [`MAX_JSON_DEPTH`]
/// guard raises `ValueError` instead of overflowing the thread stack on
/// an adversarial payload.
///
/// This is a `#[pyfunction]` rather than a `#[cfg(test)]` Rust unit test
/// because `seer-py` is a `cdylib` crate — a Rust test binary would fail
/// to link against `libpython`. The function is prefixed with `_` to
/// signal that it is not part of the public API and is undocumented in
/// `__all__`.
///
/// `depth` is capped at [`MAX_TEST_NESTING`]: the hook ships in the release
/// module, and dropping a `serde_json::Value` is itself recursive, so an
/// uncapped `depth=10**6` overflowed the stack while freeing the value and
/// aborted the interpreter — the exact failure mode the depth guard exists
/// to prevent.
#[pyfunction]
fn _json_to_python_nested_for_test<'py>(
    py: Python<'py>,
    depth: usize,
) -> PyResult<Bound<'py, PyAny>> {
    if depth > MAX_TEST_NESTING {
        return Err(PyValueError::new_err(format!(
            "test nesting depth {depth} exceeds the hook's cap of {MAX_TEST_NESTING}"
        )));
    }
    let mut v = serde_json::Value::Null;
    for _ in 0..depth {
        v = serde_json::Value::Array(vec![v]);
    }
    json_to_python(py, &v)
}

/// Test hook: build a `RetryExhausted`-wrapped `SeerError` of the given
/// `kind` and raise it through [`seer_err_to_py`], so the Python suite can
/// pin the exception-type mapping without a live network failure.
///
/// A `#[pyfunction]` rather than a Rust unit test for the same reason as
/// [`_json_to_python_nested_for_test`]: `seer-py` is a `cdylib` crate and
/// cannot link libpython from a test binary.
#[pyfunction]
fn _raise_retry_exhausted_for_test(kind: &str) -> PyResult<()> {
    let inner = match kind {
        "timeout" => SeerError::Timeout("operation timed out".to_string()),
        "connection" => SeerError::WhoisConnectionFailed("connection refused".to_string()),
        "rate_limited" => SeerError::RateLimited("throttled".to_string()),
        // Doubly wrapped: layered retries must still unwrap to the leaf type.
        "nested_timeout" => SeerError::RetryExhausted {
            attempts: 2,
            last_error: Box::new(SeerError::Timeout("operation timed out".to_string())),
        },
        other => {
            return Err(PyValueError::new_err(format!(
                "unknown test error kind: {other}"
            )))
        }
    };
    Err(seer_err_to_py(&SeerError::RetryExhausted {
        attempts: 3,
        last_error: Box::new(inner),
    }))
}

/// The `seer._seer` extension module; `python/seer/__init__.py` re-exports
/// its public functions.
#[pymodule]
mod _seer {
    #[pymodule_export]
    use super::{
        _json_to_python_nested_for_test, _raise_retry_exhausted_for_test, all_tlds, availability,
        bulk_availability, bulk_dig, bulk_info, bulk_lookup, bulk_propagation, bulk_ssl,
        bulk_status, bulk_whois, caa, cancel_follow, confusables, delegation, diff, dig,
        dns_compare, dns_follow, dnssec, headers, info, lookup, nameserver_target, posture,
        propagation, rdap_asn, rdap_auto, rdap_domain, rdap_ip, record_types, ssl, status,
        subdomains, subdomains_classify, takeover, tld_info, validate_public_host, whois,
    };

    /// Forwards Rust `log` records into Python's `logging` — and `tracing`
    /// events too, via tracing's `log` feature, since no tracing subscriber
    /// is installed inside a Python process. Runs once, at import;
    /// `try_init` leaves an already-installed logger alone.
    #[pymodule_init]
    fn init(_m: &pyo3::Bound<'_, pyo3::types::PyModule>) -> pyo3::PyResult<()> {
        let _ = pyo3_log::try_init();
        Ok(())
    }
}
