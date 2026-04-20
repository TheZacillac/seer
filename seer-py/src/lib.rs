mod bridge;

use std::future::Future;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, Ordering::SeqCst};
use std::sync::{Mutex, MutexGuard, OnceLock};

use pyo3::exceptions::{PyRuntimeError, PyValueError};
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
        Timeout(_) => PyRuntimeError::new_err(e.sanitized_message()),
        RateLimited(_) => PyRuntimeError::new_err(e.sanitized_message()),
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
    py.allow_threads(
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
    py.allow_threads(
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
fn lookup(py: Python<'_>, domain: String) -> PyResult<PyObject> {
    let smart_lookup = get_smart_lookup();
    let response = run_async(py, async move { smart_lookup.lookup(&domain).await })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

#[pyfunction]
fn whois(py: Python<'_>, domain: String) -> PyResult<PyObject> {
    let client = get_whois_client();
    let response = run_async(py, async move { client.lookup(&domain).await })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

#[pyfunction]
fn rdap_domain(py: Python<'_>, domain: String) -> PyResult<PyObject> {
    let client = get_rdap_client();
    let response = run_async(py, async move { client.lookup_domain(&domain).await })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

#[pyfunction]
fn rdap_ip(py: Python<'_>, ip: String) -> PyResult<PyObject> {
    let client = get_rdap_client();
    let response = run_async(py, async move { client.lookup_ip(&ip).await })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

#[pyfunction]
fn rdap_asn(py: Python<'_>, asn: u32) -> PyResult<PyObject> {
    let client = get_rdap_client();
    let response = run_async(py, async move { client.lookup_asn(asn).await })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

#[pyfunction]
#[pyo3(signature = (domain, record_type = "A", nameserver = None))]
fn dig(
    py: Python<'_>,
    domain: String,
    record_type: &str,
    nameserver: Option<String>,
) -> PyResult<PyObject> {
    let resolver = get_dns_resolver();

    let rt_parsed: RecordType = record_type.parse().map_err(|e: SeerError| seer_err_to_py(&e))?;

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
fn propagation(py: Python<'_>, domain: String, record_type: &str) -> PyResult<PyObject> {
    let checker = get_propagation_checker();

    let rt_parsed: RecordType = record_type.parse().map_err(|e: SeerError| seer_err_to_py(&e))?;

    let response = run_async(py, async move { checker.check(&domain, rt_parsed).await })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

const MAX_CONCURRENCY: usize = 50;

fn validate_concurrency(concurrency: usize) -> PyResult<usize> {
    if concurrency > MAX_CONCURRENCY {
        return Err(PyValueError::new_err(format!(
            "concurrency must be <= {} (got {})",
            MAX_CONCURRENCY, concurrency
        )));
    }
    Ok(concurrency.max(1))
}

/// Converts an optional Python callable into a Rust `ProgressCallback`.
///
/// The returned callback acquires the GIL on every invocation. Exceptions
/// raised from the Python callable are logged at `warn` and swallowed —
/// a broken progress callback must not kill a bulk run.
fn build_progress_callback(
    progress: Option<Py<PyAny>>,
) -> Option<seer_core::bulk::ProgressCallback> {
    progress.map(|py_cb| {
        Box::new(move |completed: usize, total: usize, domain: &str| {
            Python::with_gil(|py| {
                let bound = py_cb.bind(py);
                if let Err(err) = bound.call1((completed, total, domain)) {
                    tracing::warn!(error = %err, "bulk progress callback raised; ignoring");
                }
            });
        }) as seer_core::bulk::ProgressCallback
    })
}

#[pyfunction]
#[pyo3(signature = (domains, concurrency = 10, *, progress = None))]
fn bulk_lookup(
    py: Python<'_>,
    domains: Vec<String>,
    concurrency: usize,
    progress: Option<Py<PyAny>>,
) -> PyResult<PyObject> {
    let executor = BulkExecutor::new().with_concurrency(validate_concurrency(concurrency)?);

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Lookup { domain })
        .collect();

    let cb = build_progress_callback(progress);
    let result =
        run_async_infallible(py, async move { executor.execute(operations, cb).await })?;

    let json = serialize_response(&result)?;
    json_to_python(py, &json)
}

#[pyfunction]
#[pyo3(signature = (domains, concurrency = 10, *, progress = None))]
fn bulk_whois(
    py: Python<'_>,
    domains: Vec<String>,
    concurrency: usize,
    progress: Option<Py<PyAny>>,
) -> PyResult<PyObject> {
    let executor = BulkExecutor::new().with_concurrency(validate_concurrency(concurrency)?);

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Whois { domain })
        .collect();

    let cb = build_progress_callback(progress);
    let result =
        run_async_infallible(py, async move { executor.execute(operations, cb).await })?;

    let json = serialize_response(&result)?;
    json_to_python(py, &json)
}

#[pyfunction]
#[pyo3(signature = (domains, record_type = "A", concurrency = 10, *, progress = None))]
fn bulk_dig(
    py: Python<'_>,
    domains: Vec<String>,
    record_type: &str,
    concurrency: usize,
    progress: Option<Py<PyAny>>,
) -> PyResult<PyObject> {
    let executor = BulkExecutor::new().with_concurrency(validate_concurrency(concurrency)?);

    let rt_parsed: RecordType = record_type.parse().map_err(|e: SeerError| seer_err_to_py(&e))?;

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Dns {
            domain,
            record_type: rt_parsed,
        })
        .collect();

    let cb = build_progress_callback(progress);
    let result =
        run_async_infallible(py, async move { executor.execute(operations, cb).await })?;

    let json = serialize_response(&result)?;
    json_to_python(py, &json)
}

#[pyfunction]
#[pyo3(signature = (domains, record_type = "A", concurrency = 5, *, progress = None))]
fn bulk_propagation(
    py: Python<'_>,
    domains: Vec<String>,
    record_type: &str,
    concurrency: usize,
    progress: Option<Py<PyAny>>,
) -> PyResult<PyObject> {
    let executor = BulkExecutor::new().with_concurrency(validate_concurrency(concurrency)?);

    let rt_parsed: RecordType = record_type.parse().map_err(|e: SeerError| seer_err_to_py(&e))?;

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Propagation {
            domain,
            record_type: rt_parsed,
        })
        .collect();

    let cb = build_progress_callback(progress);
    let result =
        run_async_infallible(py, async move { executor.execute(operations, cb).await })?;

    let json = serialize_response(&result)?;
    json_to_python(py, &json)
}

#[pyfunction]
fn status(py: Python<'_>, domain: String) -> PyResult<PyObject> {
    let client = get_status_client();
    let response = run_async(py, async move { client.check(&domain).await })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

#[pyfunction]
#[pyo3(signature = (domains, concurrency = 10, *, progress = None))]
fn bulk_status(
    py: Python<'_>,
    domains: Vec<String>,
    concurrency: usize,
    progress: Option<Py<PyAny>>,
) -> PyResult<PyObject> {
    let executor = BulkExecutor::new().with_concurrency(validate_concurrency(concurrency)?);

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Status { domain })
        .collect();

    let cb = build_progress_callback(progress);
    let result =
        run_async_infallible(py, async move { executor.execute(operations, cb).await })?;

    let json = serialize_response(&result)?;
    json_to_python(py, &json)
}

#[pyfunction]
#[pyo3(signature = (domains, concurrency = 10, *, progress = None))]
fn bulk_availability(
    py: Python<'_>,
    domains: Vec<String>,
    concurrency: usize,
    progress: Option<Py<PyAny>>,
) -> PyResult<PyObject> {
    let executor = BulkExecutor::new().with_concurrency(validate_concurrency(concurrency)?);

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Avail { domain })
        .collect();

    let cb = build_progress_callback(progress);
    let result =
        run_async_infallible(py, async move { executor.execute(operations, cb).await })?;

    let json = serialize_response(&result)?;
    json_to_python(py, &json)
}

#[pyfunction]
fn availability(py: Python<'_>, domain: String) -> PyResult<PyObject> {
    let checker = get_availability_checker();
    let response = run_async(py, async move { checker.check(&domain).await })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

#[pyfunction]
fn subdomains(py: Python<'_>, domain: String) -> PyResult<PyObject> {
    let enumerator = get_subdomain_enumerator();
    let response = run_async(py, async move { enumerator.enumerate(&domain).await })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

#[pyfunction]
fn ssl(py: Python<'_>, domain: String) -> PyResult<PyObject> {
    let checker = get_ssl_checker();
    let response = run_async(py, async move { checker.check(&domain).await })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

#[pyfunction]
fn dnssec(py: Python<'_>, domain: String) -> PyResult<PyObject> {
    let checker = get_dnssec_checker();
    let response = run_async(py, async move { checker.check(&domain).await })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

#[pyfunction]
fn dns_compare(
    py: Python<'_>,
    domain: String,
    record_type: &str,
    server_a: String,
    server_b: String,
) -> PyResult<PyObject> {
    let comparator = get_dns_comparator();

    let rt_parsed: RecordType = record_type.parse().map_err(|e: SeerError| seer_err_to_py(&e))?;

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
fn dns_follow(
    py: Python<'_>,
    domain: String,
    record_type: &str,
    nameserver: Option<String>,
    iterations: usize,
    interval_minutes: f64,
) -> PyResult<PyObject> {
    // Refuse concurrent calls before touching any shared state — a second
    // call would overwrite the global cancel sender, silently orphaning the
    // first call's ability to be cancelled. The guard releases on return.
    let _active = FollowActiveGuard::acquire()?;

    let follower = get_dns_follower();

    let rt_parsed: RecordType = record_type.parse().map_err(|e: SeerError| seer_err_to_py(&e))?;

    // Validate iteration/interval via core; this rejects NaN/inf/negative and
    // enforces the per-interval cap (<= 60 minutes).
    let config =
        FollowConfig::new(iterations, interval_minutes).map_err(|e| seer_err_to_py(&e))?;

    // Additionally cap total wall-clock time and iteration count to prevent
    // blocking the shared Tokio runtime for excessive durations.
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
fn diff(py: Python<'_>, domain_a: String, domain_b: String) -> PyResult<PyObject> {
    let differ = get_domain_differ();
    let response = run_async(py, async move { differ.diff(&domain_a, &domain_b).await })?;
    let json = serialize_response(&response)?;
    json_to_python(py, &json)
}

#[pyfunction]
fn info(py: Python<'_>, domain: String) -> PyResult<PyObject> {
    let smart_lookup = get_smart_lookup();
    let lookup_result = run_async(py, async move { smart_lookup.lookup(&domain).await })?;
    let domain_info = seer_core::domain_info::DomainInfo::from_lookup_result(&lookup_result);
    let json = serialize_response(&domain_info)?;
    json_to_python(py, &json)
}

#[pyfunction]
#[pyo3(signature = (domains, concurrency = 10, *, progress = None))]
fn bulk_info(
    py: Python<'_>,
    domains: Vec<String>,
    concurrency: usize,
    progress: Option<Py<PyAny>>,
) -> PyResult<PyObject> {
    let executor = BulkExecutor::new().with_concurrency(validate_concurrency(concurrency)?);

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Info { domain })
        .collect();

    let cb = build_progress_callback(progress);
    let result =
        run_async_infallible(py, async move { executor.execute(operations, cb).await })?;

    let json = serialize_response(&result)?;
    json_to_python(py, &json)
}

fn json_to_python(py: Python<'_>, value: &serde_json::Value) -> PyResult<PyObject> {
    match value {
        serde_json::Value::Null => Ok(py.None()),
        serde_json::Value::Bool(b) => Ok(b.into_pyobject(py)?.to_owned().into_any().unbind()),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_pyobject(py)?.into_any().unbind())
            } else if let Some(u) = n.as_u64() {
                Ok(u.into_pyobject(py)?.into_any().unbind())
            } else if let Some(f) = n.as_f64() {
                Ok(f.into_pyobject(py)?.into_any().unbind())
            } else {
                Err(PyRuntimeError::new_err("Invalid number"))
            }
        }
        serde_json::Value::String(s) => Ok(s.into_pyobject(py)?.to_owned().into_any().unbind()),
        serde_json::Value::Array(arr) => {
            let list: Vec<PyObject> = arr
                .iter()
                .map(|v| json_to_python(py, v))
                .collect::<PyResult<_>>()?;
            Ok(list.into_pyobject(py)?.into_any().unbind())
        }
        serde_json::Value::Object(obj) => {
            let dict = PyDict::new(py);
            for (k, v) in obj {
                dict.set_item(k, json_to_python(py, v)?)?;
            }
            Ok(dict.into_any().unbind())
        }
    }
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
    m.add_function(wrap_pyfunction!(validate_public_host, m)?)?;
    m.add_function(wrap_pyfunction!(lookup, m)?)?;
    m.add_function(wrap_pyfunction!(whois, m)?)?;
    m.add_function(wrap_pyfunction!(rdap_domain, m)?)?;
    m.add_function(wrap_pyfunction!(rdap_ip, m)?)?;
    m.add_function(wrap_pyfunction!(rdap_asn, m)?)?;
    m.add_function(wrap_pyfunction!(dig, m)?)?;
    m.add_function(wrap_pyfunction!(propagation, m)?)?;
    m.add_function(wrap_pyfunction!(status, m)?)?;
    m.add_function(wrap_pyfunction!(bulk_lookup, m)?)?;
    m.add_function(wrap_pyfunction!(bulk_whois, m)?)?;
    m.add_function(wrap_pyfunction!(bulk_dig, m)?)?;
    m.add_function(wrap_pyfunction!(bulk_propagation, m)?)?;
    m.add_function(wrap_pyfunction!(bulk_status, m)?)?;
    m.add_function(wrap_pyfunction!(bulk_availability, m)?)?;
    m.add_function(wrap_pyfunction!(availability, m)?)?;
    m.add_function(wrap_pyfunction!(subdomains, m)?)?;
    m.add_function(wrap_pyfunction!(ssl, m)?)?;
    m.add_function(wrap_pyfunction!(dnssec, m)?)?;
    m.add_function(wrap_pyfunction!(dns_compare, m)?)?;
    m.add_function(wrap_pyfunction!(dns_follow, m)?)?;
    m.add_function(wrap_pyfunction!(cancel_follow, m)?)?;
    m.add_function(wrap_pyfunction!(diff, m)?)?;
    m.add_function(wrap_pyfunction!(info, m)?)?;
    m.add_function(wrap_pyfunction!(bulk_info, m)?)?;
    Ok(())
}
