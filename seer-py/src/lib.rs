mod bridge;

use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::sync::{Mutex, MutexGuard, OnceLock};

use pyo3::exceptions::{PyConnectionError, PyRuntimeError, PyTimeoutError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyAny, PyDict};
use pyo3::Py;
use seer_core::{
    bulk::{BulkExecutor, BulkOperation},
    dns::{
        DnsComparator, DnsFollower, DnsResolver, DnssecChecker, FollowConfig, PropagationChecker,
        RecordType,
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
        _ => PyRuntimeError::new_err(e.sanitized_message()),
    }
}

/// Run an async `SeerError`-returning future on the shared Tokio runtime and
/// marshal the outcome into a `PyResult`.
///
/// Wraps the `block_on` in `std::panic::catch_unwind`: a panic that unwinds
/// through the FFI boundary is UB and would abort the Python process. Common
/// causes include calling a blocking runtime from inside another async runtime
/// (e.g. from `asyncio`) which tokio explicitly panics on. We surface that as
/// a `RuntimeError` instead.
///
/// Errors are routed through `seer_err_to_py` so that sanitized, typed
/// messages reach the caller.
fn run_async<F, T>(py: Python<'_>, fut: F) -> PyResult<T>
where
    F: Future<Output = seer_core::Result<T>> + Send,
    T: Send,
{
    py.detach(
        || match catch_unwind(AssertUnwindSafe(|| get_runtime().block_on(fut))) {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(seer_err_to_py(&e)),
            Err(_) => Err(PyRuntimeError::new_err(
                "panic in seer runtime (likely nested async context or internal bug)",
            )),
        },
    )
}

/// Serialize a Rust response to `serde_json::Value`, mapping any error to a
/// generic `PyRuntimeError`. `serde_json::to_value` on our own domain types
/// should never fail; if it does, that's an internal bug — do not leak the
/// underlying error text (which could include type/field names) to callers.
fn serialize_response<T: serde::Serialize>(value: &T) -> PyResult<serde_json::Value> {
    serde_json::to_value(value)
        .map_err(|_| PyRuntimeError::new_err("internal error: failed to serialize response"))
}

/// Infallible variant of `run_async` for futures that do not return a
/// `SeerError` (e.g. `BulkExecutor::execute` which reports per-item failures
/// in the returned `Vec<BulkResult>`). Still wraps `block_on` in
/// `catch_unwind` so that a panic in the runtime surfaces as a Python
/// exception rather than aborting the process.
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

fn get_smart_lookup() -> &'static SmartLookup {
    static INSTANCE: OnceLock<SmartLookup> = OnceLock::new();
    INSTANCE.get_or_init(SmartLookup::new)
}

fn get_whois_client() -> &'static WhoisClient {
    static INSTANCE: OnceLock<WhoisClient> = OnceLock::new();
    INSTANCE.get_or_init(WhoisClient::new)
}

fn get_rdap_client() -> &'static RdapClient {
    static INSTANCE: OnceLock<RdapClient> = OnceLock::new();
    INSTANCE.get_or_init(RdapClient::new)
}

fn get_dns_resolver() -> &'static DnsResolver {
    static INSTANCE: OnceLock<DnsResolver> = OnceLock::new();
    INSTANCE.get_or_init(DnsResolver::new)
}

fn get_propagation_checker() -> &'static PropagationChecker {
    static INSTANCE: OnceLock<PropagationChecker> = OnceLock::new();
    INSTANCE.get_or_init(PropagationChecker::new)
}

fn get_status_client() -> &'static StatusClient {
    static INSTANCE: OnceLock<StatusClient> = OnceLock::new();
    INSTANCE.get_or_init(StatusClient::new)
}

fn get_availability_checker() -> &'static AvailabilityChecker {
    static INSTANCE: OnceLock<AvailabilityChecker> = OnceLock::new();
    INSTANCE.get_or_init(AvailabilityChecker::new)
}

fn get_subdomain_enumerator() -> &'static SubdomainEnumerator {
    static INSTANCE: OnceLock<SubdomainEnumerator> = OnceLock::new();
    INSTANCE.get_or_init(SubdomainEnumerator::new)
}

fn get_ssl_checker() -> &'static SslChecker {
    static INSTANCE: OnceLock<SslChecker> = OnceLock::new();
    INSTANCE.get_or_init(SslChecker::new)
}

fn get_dnssec_checker() -> &'static DnssecChecker {
    static INSTANCE: OnceLock<DnssecChecker> = OnceLock::new();
    INSTANCE.get_or_init(DnssecChecker::new)
}

fn get_dns_comparator() -> &'static DnsComparator {
    static INSTANCE: OnceLock<DnsComparator> = OnceLock::new();
    INSTANCE.get_or_init(DnsComparator::new)
}

fn get_dns_follower() -> &'static DnsFollower {
    static INSTANCE: OnceLock<DnsFollower> = OnceLock::new();
    INSTANCE.get_or_init(DnsFollower::new)
}

fn get_domain_differ() -> &'static DomainDiffer {
    static INSTANCE: OnceLock<DomainDiffer> = OnceLock::new();
    INSTANCE.get_or_init(DomainDiffer::new)
}

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

#[pyfunction]
fn lookup<'py>(py: Python<'py>, domain: String) -> PyResult<Bound<'py, PyAny>> {
    let smart_lookup = get_smart_lookup();
    let response = run_async(py, async move { smart_lookup.lookup(&domain).await })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

#[pyfunction]
fn whois<'py>(py: Python<'py>, domain: String) -> PyResult<Bound<'py, PyAny>> {
    let client = get_whois_client();
    let response = run_async(py, async move { client.lookup(&domain).await })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

#[pyfunction]
fn rdap_domain<'py>(py: Python<'py>, domain: String) -> PyResult<Bound<'py, PyAny>> {
    let client = get_rdap_client();
    let response = run_async(py, async move { client.lookup_domain(&domain).await })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

#[pyfunction]
fn rdap_ip<'py>(py: Python<'py>, ip: String) -> PyResult<Bound<'py, PyAny>> {
    let client = get_rdap_client();
    let response = run_async(py, async move { client.lookup_ip(&ip).await })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

#[pyfunction]
fn rdap_asn<'py>(py: Python<'py>, asn: u32) -> PyResult<Bound<'py, PyAny>> {
    let client = get_rdap_client();
    let response = run_async(py, async move { client.lookup_asn(asn).await })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

/// Auto-routing RDAP lookup: classifies `query` as IP / ASN / domain in
/// Rust and dispatches to the correct endpoint. Replaces the former
/// Python-side dispatcher, which silently misrouted `AS`-prefixed domains
/// like `as1234.io` to the ASN endpoint.
#[pyfunction]
fn rdap_auto<'py>(py: Python<'py>, query: String) -> PyResult<Bound<'py, PyAny>> {
    let client = get_rdap_client();
    let response = run_async(py, async move {
        seer_core::rdap::auto_lookup(client, &query).await
    })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

#[pyfunction]
#[pyo3(signature = (domain, record_type = "A", nameserver = None))]
fn dig<'py>(
    py: Python<'py>,
    domain: String,
    record_type: &str,
    nameserver: Option<String>,
) -> PyResult<Bound<'py, PyAny>> {
    let resolver = get_dns_resolver();

    let rt_parsed: RecordType = record_type
        .parse()
        .map_err(|e: SeerError| seer_err_to_py(&e))?;

    let records = run_async(py, async move {
        resolver
            .resolve(&domain, rt_parsed, nameserver.as_deref())
            .await
    })?;

    let json = serialize_response(&records)?;
    json_to_python(py, &json)
}

#[pyfunction]
#[pyo3(signature = (domain, record_type = "A"))]
fn propagation<'py>(
    py: Python<'py>,
    domain: String,
    record_type: &str,
) -> PyResult<Bound<'py, PyAny>> {
    let checker = get_propagation_checker();

    let rt_parsed: RecordType = record_type
        .parse()
        .map_err(|e: SeerError| seer_err_to_py(&e))?;

    let response = run_async(py, async move { checker.check(&domain, rt_parsed).await })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
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

#[pyfunction]
#[pyo3(signature = (domains, concurrency = 10, *, progress = None))]
fn bulk_lookup<'py>(
    py: Python<'py>,
    domains: Vec<String>,
    concurrency: usize,
    progress: Option<Py<PyAny>>,
) -> PyResult<Bound<'py, PyAny>> {
    validate_domains(&domains)?;
    let executor = BulkExecutor::new().with_concurrency(validate_concurrency(concurrency)?);

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Lookup { domain })
        .collect();

    let cb = build_progress_callback(progress)?;
    let result = run_async_infallible(py, async move { executor.execute(operations, cb).await })?;

    let json = serialize_response(&result)?;
    json_to_python(py, &json)
}

#[pyfunction]
#[pyo3(signature = (domains, concurrency = 10, *, progress = None))]
fn bulk_whois<'py>(
    py: Python<'py>,
    domains: Vec<String>,
    concurrency: usize,
    progress: Option<Py<PyAny>>,
) -> PyResult<Bound<'py, PyAny>> {
    validate_domains(&domains)?;
    let executor = BulkExecutor::new().with_concurrency(validate_concurrency(concurrency)?);

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Whois { domain })
        .collect();

    let cb = build_progress_callback(progress)?;
    let result = run_async_infallible(py, async move { executor.execute(operations, cb).await })?;

    let json = serialize_response(&result)?;
    json_to_python(py, &json)
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
    let executor = BulkExecutor::new().with_concurrency(validate_concurrency(concurrency)?);

    let rt_parsed: RecordType = record_type
        .parse()
        .map_err(|e: SeerError| seer_err_to_py(&e))?;

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Dns {
            domain,
            record_type: rt_parsed,
        })
        .collect();

    let cb = build_progress_callback(progress)?;
    let result = run_async_infallible(py, async move { executor.execute(operations, cb).await })?;

    let json = serialize_response(&result)?;
    json_to_python(py, &json)
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
    let executor = BulkExecutor::new().with_concurrency(validate_concurrency(concurrency)?);

    let rt_parsed: RecordType = record_type
        .parse()
        .map_err(|e: SeerError| seer_err_to_py(&e))?;

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Propagation {
            domain,
            record_type: rt_parsed,
        })
        .collect();

    let cb = build_progress_callback(progress)?;
    let result = run_async_infallible(py, async move { executor.execute(operations, cb).await })?;

    let json = serialize_response(&result)?;
    json_to_python(py, &json)
}

#[pyfunction]
fn status<'py>(py: Python<'py>, domain: String) -> PyResult<Bound<'py, PyAny>> {
    let client = get_status_client();
    let response = run_async(py, async move { client.check(&domain).await })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

#[pyfunction]
#[pyo3(signature = (domains, concurrency = 10, *, progress = None))]
fn bulk_status<'py>(
    py: Python<'py>,
    domains: Vec<String>,
    concurrency: usize,
    progress: Option<Py<PyAny>>,
) -> PyResult<Bound<'py, PyAny>> {
    validate_domains(&domains)?;
    let executor = BulkExecutor::new().with_concurrency(validate_concurrency(concurrency)?);

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Status { domain })
        .collect();

    let cb = build_progress_callback(progress)?;
    let result = run_async_infallible(py, async move { executor.execute(operations, cb).await })?;

    let json = serialize_response(&result)?;
    json_to_python(py, &json)
}

#[pyfunction]
#[pyo3(signature = (domains, concurrency = 10, *, progress = None))]
fn bulk_ssl<'py>(
    py: Python<'py>,
    domains: Vec<String>,
    concurrency: usize,
    progress: Option<Py<PyAny>>,
) -> PyResult<Bound<'py, PyAny>> {
    validate_domains(&domains)?;
    let executor = BulkExecutor::new().with_concurrency(validate_concurrency(concurrency)?);

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Ssl { domain })
        .collect();

    let cb = build_progress_callback(progress)?;
    let result = run_async_infallible(py, async move { executor.execute(operations, cb).await })?;

    let json = serialize_response(&result)?;
    json_to_python(py, &json)
}

#[pyfunction]
#[pyo3(signature = (domains, concurrency = 10, *, progress = None))]
fn bulk_availability<'py>(
    py: Python<'py>,
    domains: Vec<String>,
    concurrency: usize,
    progress: Option<Py<PyAny>>,
) -> PyResult<Bound<'py, PyAny>> {
    validate_domains(&domains)?;
    let executor = BulkExecutor::new().with_concurrency(validate_concurrency(concurrency)?);

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Avail { domain })
        .collect();

    let cb = build_progress_callback(progress)?;
    let result = run_async_infallible(py, async move { executor.execute(operations, cb).await })?;

    let json = serialize_response(&result)?;
    json_to_python(py, &json)
}

#[pyfunction]
fn availability<'py>(py: Python<'py>, domain: String) -> PyResult<Bound<'py, PyAny>> {
    let checker = get_availability_checker();
    let response = run_async(py, async move { checker.check(&domain).await })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

#[pyfunction]
fn subdomains<'py>(py: Python<'py>, domain: String) -> PyResult<Bound<'py, PyAny>> {
    let enumerator = get_subdomain_enumerator();
    let response = run_async(py, async move { enumerator.enumerate(&domain).await })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

#[pyfunction]
fn ssl<'py>(py: Python<'py>, domain: String) -> PyResult<Bound<'py, PyAny>> {
    let checker = get_ssl_checker();
    let response = run_async(py, async move { checker.check(&domain).await })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

#[pyfunction]
fn dnssec<'py>(py: Python<'py>, domain: String) -> PyResult<Bound<'py, PyAny>> {
    let checker = get_dnssec_checker();
    let response = run_async(py, async move { checker.check(&domain).await })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

#[pyfunction]
fn caa<'py>(py: Python<'py>, domain: String) -> PyResult<Bound<'py, PyAny>> {
    let resolver = get_dns_resolver();
    let normalized = seer_core::normalize_domain(&domain).map_err(|e| seer_err_to_py(&e))?;
    let policy = run_async_infallible(py, async move {
        seer_core::caa::lookup_caa(resolver, &normalized).await
    })?;
    let json = serialize_response(&policy)?;
    json_to_python(py, &json)
}

#[pyfunction]
fn posture<'py>(py: Python<'py>, domain: String) -> PyResult<Bound<'py, PyAny>> {
    let resolver = get_dns_resolver();
    let response = run_async(py, async move {
        seer_core::lookup_email_posture(resolver, &domain).await
    })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

#[pyfunction]
#[pyo3(signature = (domain, concurrency = 10))]
fn confusables<'py>(
    py: Python<'py>,
    domain: String,
    concurrency: usize,
) -> PyResult<Bound<'py, PyAny>> {
    let lookup = get_smart_lookup();
    let concurrency = validate_concurrency(concurrency)?;
    let response = run_async(py, async move {
        seer_core::find_confusables(lookup, &domain, concurrency).await
    })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

#[pyfunction]
#[pyo3(signature = (domain, concurrency = 10))]
fn subdomains_classify<'py>(
    py: Python<'py>,
    domain: String,
    concurrency: usize,
) -> PyResult<Bound<'py, PyAny>> {
    let enumerator = get_subdomain_enumerator();
    let resolver = get_dns_resolver();
    let concurrency = validate_concurrency(concurrency)?;
    let response = run_async(py, async move {
        let result = enumerator.enumerate(&domain).await?;
        Ok::<_, SeerError>(
            seer_core::classify_subdomains(
                resolver,
                &result.domain,
                result.subdomains,
                concurrency,
            )
            .await,
        )
    })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

#[pyfunction]
fn dns_compare<'py>(
    py: Python<'py>,
    domain: String,
    record_type: &str,
    server_a: String,
    server_b: String,
) -> PyResult<Bound<'py, PyAny>> {
    let comparator = get_dns_comparator();

    let rt_parsed: RecordType = record_type
        .parse()
        .map_err(|e: SeerError| seer_err_to_py(&e))?;

    let response = run_async(py, async move {
        comparator
            .compare(&domain, rt_parsed, &server_a, &server_b)
            .await
    })?;

    let json = serialize_response(&response)?;
    json_to_python(py, &json)
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

    let follower = get_dns_follower();

    let rt_parsed: RecordType = record_type
        .parse()
        .map_err(|e: SeerError| seer_err_to_py(&e))?;

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
        follower
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
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
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
    let differ = get_domain_differ();
    let response = run_async(py, async move { differ.diff(&domain_a, &domain_b).await })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

#[pyfunction]
fn info<'py>(py: Python<'py>, domain: String) -> PyResult<Bound<'py, PyAny>> {
    let smart_lookup = get_smart_lookup();
    let lookup_result = run_async(py, async move { smart_lookup.lookup(&domain).await })?;
    let domain_info = seer_core::domain_info::DomainInfo::from_lookup_result(&lookup_result);
    let json = serialize_response(&domain_info)?;
    json_to_python(py, &json)
}

#[pyfunction]
#[pyo3(signature = (domains, concurrency = 10, *, progress = None))]
fn bulk_info<'py>(
    py: Python<'py>,
    domains: Vec<String>,
    concurrency: usize,
    progress: Option<Py<PyAny>>,
) -> PyResult<Bound<'py, PyAny>> {
    validate_domains(&domains)?;
    let executor = BulkExecutor::new().with_concurrency(validate_concurrency(concurrency)?);

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Info { domain })
        .collect();

    let cb = build_progress_callback(progress)?;
    let result = run_async_infallible(py, async move { executor.execute(operations, cb).await })?;

    let json = serialize_response(&result)?;
    json_to_python(py, &json)
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
#[pyfunction]
fn _json_to_python_nested_for_test<'py>(
    py: Python<'py>,
    depth: usize,
) -> PyResult<Bound<'py, PyAny>> {
    let mut v = serde_json::Value::Null;
    for _ in 0..depth {
        v = serde_json::Value::Array(vec![v]);
    }
    json_to_python(py, &v)
}

/// Install a tracing subscriber that forwards Rust log events into Python's
/// ``logging`` module.  Safe to call multiple times — only the first call
/// takes effect.
#[pyfunction]
fn init_rust_logging() {
    bridge::install_bridge();
}

#[pymodule]
fn _seer(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(init_rust_logging, m)?)?;
    m.add_function(wrap_pyfunction!(_json_to_python_nested_for_test, m)?)?;
    m.add_function(wrap_pyfunction!(validate_public_host, m)?)?;
    m.add_function(wrap_pyfunction!(lookup, m)?)?;
    m.add_function(wrap_pyfunction!(whois, m)?)?;
    m.add_function(wrap_pyfunction!(rdap_domain, m)?)?;
    m.add_function(wrap_pyfunction!(rdap_ip, m)?)?;
    m.add_function(wrap_pyfunction!(rdap_asn, m)?)?;
    m.add_function(wrap_pyfunction!(rdap_auto, m)?)?;
    m.add_function(wrap_pyfunction!(dig, m)?)?;
    m.add_function(wrap_pyfunction!(propagation, m)?)?;
    m.add_function(wrap_pyfunction!(status, m)?)?;
    m.add_function(wrap_pyfunction!(bulk_lookup, m)?)?;
    m.add_function(wrap_pyfunction!(bulk_whois, m)?)?;
    m.add_function(wrap_pyfunction!(bulk_dig, m)?)?;
    m.add_function(wrap_pyfunction!(bulk_propagation, m)?)?;
    m.add_function(wrap_pyfunction!(bulk_status, m)?)?;
    m.add_function(wrap_pyfunction!(bulk_ssl, m)?)?;
    m.add_function(wrap_pyfunction!(bulk_availability, m)?)?;
    m.add_function(wrap_pyfunction!(availability, m)?)?;
    m.add_function(wrap_pyfunction!(subdomains, m)?)?;
    m.add_function(wrap_pyfunction!(ssl, m)?)?;
    m.add_function(wrap_pyfunction!(dnssec, m)?)?;
    m.add_function(wrap_pyfunction!(caa, m)?)?;
    m.add_function(wrap_pyfunction!(posture, m)?)?;
    m.add_function(wrap_pyfunction!(confusables, m)?)?;
    m.add_function(wrap_pyfunction!(subdomains_classify, m)?)?;
    m.add_function(wrap_pyfunction!(dns_compare, m)?)?;
    m.add_function(wrap_pyfunction!(dns_follow, m)?)?;
    m.add_function(wrap_pyfunction!(cancel_follow, m)?)?;
    m.add_function(wrap_pyfunction!(diff, m)?)?;
    m.add_function(wrap_pyfunction!(info, m)?)?;
    m.add_function(wrap_pyfunction!(bulk_info, m)?)?;
    Ok(())
}
