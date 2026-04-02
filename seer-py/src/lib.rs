mod bridge;

use std::sync::OnceLock;

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyDict;
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
    AvailabilityChecker, DomainDiffer, SslChecker, SubdomainEnumerator,
};

fn get_runtime() -> &'static tokio::runtime::Runtime {
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create Tokio runtime")
    })
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

#[pyfunction]
fn lookup(py: Python<'_>, domain: String) -> PyResult<PyObject> {
    let rt = get_runtime();
    let smart_lookup = get_smart_lookup();

    let result = py.allow_threads(|| rt.block_on(async { smart_lookup.lookup(&domain).await }));

    match result {
        Ok(response) => {
            let json = serde_json::to_value(&response)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            json_to_python(py, &json)
        }
        Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
    }
}

#[pyfunction]
fn whois(py: Python<'_>, domain: String) -> PyResult<PyObject> {
    let rt = get_runtime();
    let client = get_whois_client();

    let result = py.allow_threads(|| rt.block_on(async { client.lookup(&domain).await }));

    match result {
        Ok(response) => {
            let json = serde_json::to_value(&response)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            json_to_python(py, &json)
        }
        Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
    }
}

#[pyfunction]
fn rdap_domain(py: Python<'_>, domain: String) -> PyResult<PyObject> {
    let rt = get_runtime();
    let client = get_rdap_client();

    let result = py.allow_threads(|| rt.block_on(async { client.lookup_domain(&domain).await }));

    match result {
        Ok(response) => {
            let json = serde_json::to_value(&response)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            json_to_python(py, &json)
        }
        Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
    }
}

#[pyfunction]
fn rdap_ip(py: Python<'_>, ip: String) -> PyResult<PyObject> {
    let rt = get_runtime();
    let client = get_rdap_client();

    let result = py.allow_threads(|| rt.block_on(async { client.lookup_ip(&ip).await }));

    match result {
        Ok(response) => {
            let json = serde_json::to_value(&response)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            json_to_python(py, &json)
        }
        Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
    }
}

#[pyfunction]
fn rdap_asn(py: Python<'_>, asn: u32) -> PyResult<PyObject> {
    let rt = get_runtime();
    let client = get_rdap_client();

    let result = py.allow_threads(|| rt.block_on(async { client.lookup_asn(asn).await }));

    match result {
        Ok(response) => {
            let json = serde_json::to_value(&response)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            json_to_python(py, &json)
        }
        Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
    }
}

#[pyfunction]
#[pyo3(signature = (domain, record_type = "A", nameserver = None))]
fn dig(
    py: Python<'_>,
    domain: String,
    record_type: &str,
    nameserver: Option<String>,
) -> PyResult<PyObject> {
    let rt = get_runtime();
    let resolver = get_dns_resolver();

    let rt_parsed: RecordType = record_type
        .parse()
        .map_err(|e: seer_core::SeerError| PyValueError::new_err(e.to_string()))?;

    let result = py.allow_threads(|| {
        rt.block_on(async {
            resolver
                .resolve(&domain, rt_parsed, nameserver.as_deref())
                .await
        })
    });

    match result {
        Ok(records) => {
            let json = serde_json::to_value(&records)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            json_to_python(py, &json)
        }
        Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
    }
}

#[pyfunction]
#[pyo3(signature = (domain, record_type = "A"))]
fn propagation(py: Python<'_>, domain: String, record_type: &str) -> PyResult<PyObject> {
    let rt = get_runtime();
    let checker = get_propagation_checker();

    let rt_parsed: RecordType = record_type
        .parse()
        .map_err(|e: seer_core::SeerError| PyValueError::new_err(e.to_string()))?;

    let result =
        py.allow_threads(|| rt.block_on(async { checker.check(&domain, rt_parsed).await }));

    match result {
        Ok(result) => {
            let json = serde_json::to_value(&result)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            json_to_python(py, &json)
        }
        Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
    }
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

#[pyfunction]
#[pyo3(signature = (domains, concurrency = 10))]
fn bulk_lookup(py: Python<'_>, domains: Vec<String>, concurrency: usize) -> PyResult<PyObject> {
    let rt = get_runtime();
    let executor = BulkExecutor::new().with_concurrency(validate_concurrency(concurrency)?);

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Lookup { domain })
        .collect();

    let result =
        py.allow_threads(|| rt.block_on(async { executor.execute(operations, None).await }));

    let json = serde_json::to_value(&result).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    json_to_python(py, &json)
}

#[pyfunction]
#[pyo3(signature = (domains, concurrency = 10))]
fn bulk_whois(py: Python<'_>, domains: Vec<String>, concurrency: usize) -> PyResult<PyObject> {
    let rt = get_runtime();
    let executor = BulkExecutor::new().with_concurrency(validate_concurrency(concurrency)?);

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Whois { domain })
        .collect();

    let result =
        py.allow_threads(|| rt.block_on(async { executor.execute(operations, None).await }));

    let json = serde_json::to_value(&result).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    json_to_python(py, &json)
}

#[pyfunction]
#[pyo3(signature = (domains, record_type = "A", concurrency = 10))]
fn bulk_dig(
    py: Python<'_>,
    domains: Vec<String>,
    record_type: &str,
    concurrency: usize,
) -> PyResult<PyObject> {
    let rt = get_runtime();
    let executor = BulkExecutor::new().with_concurrency(validate_concurrency(concurrency)?);

    let rt_parsed: RecordType = record_type
        .parse()
        .map_err(|e: seer_core::SeerError| PyValueError::new_err(e.to_string()))?;

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Dns {
            domain,
            record_type: rt_parsed,
        })
        .collect();

    let result =
        py.allow_threads(|| rt.block_on(async { executor.execute(operations, None).await }));

    let json = serde_json::to_value(&result).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    json_to_python(py, &json)
}

#[pyfunction]
#[pyo3(signature = (domains, record_type = "A", concurrency = 5))]
fn bulk_propagation(
    py: Python<'_>,
    domains: Vec<String>,
    record_type: &str,
    concurrency: usize,
) -> PyResult<PyObject> {
    let rt = get_runtime();
    let executor = BulkExecutor::new().with_concurrency(validate_concurrency(concurrency)?);

    let rt_parsed: RecordType = record_type
        .parse()
        .map_err(|e: seer_core::SeerError| PyValueError::new_err(e.to_string()))?;

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Propagation {
            domain,
            record_type: rt_parsed,
        })
        .collect();

    let result =
        py.allow_threads(|| rt.block_on(async { executor.execute(operations, None).await }));

    let json = serde_json::to_value(&result).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    json_to_python(py, &json)
}

#[pyfunction]
fn status(py: Python<'_>, domain: String) -> PyResult<PyObject> {
    let rt = get_runtime();
    let client = get_status_client();

    let result = py.allow_threads(|| rt.block_on(async { client.check(&domain).await }));

    match result {
        Ok(response) => {
            let json = serde_json::to_value(&response)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            json_to_python(py, &json)
        }
        Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
    }
}

#[pyfunction]
#[pyo3(signature = (domains, concurrency = 10))]
fn bulk_status(py: Python<'_>, domains: Vec<String>, concurrency: usize) -> PyResult<PyObject> {
    let rt = get_runtime();
    let executor = BulkExecutor::new().with_concurrency(validate_concurrency(concurrency)?);

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Status { domain })
        .collect();

    let result =
        py.allow_threads(|| rt.block_on(async { executor.execute(operations, None).await }));

    let json = serde_json::to_value(&result).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    json_to_python(py, &json)
}

#[pyfunction]
#[pyo3(signature = (domains, concurrency = 10))]
fn bulk_availability(
    py: Python<'_>,
    domains: Vec<String>,
    concurrency: usize,
) -> PyResult<PyObject> {
    let rt = get_runtime();
    let executor = BulkExecutor::new().with_concurrency(validate_concurrency(concurrency)?);

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Avail { domain })
        .collect();

    let result =
        py.allow_threads(|| rt.block_on(async { executor.execute(operations, None).await }));

    let json = serde_json::to_value(&result).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    json_to_python(py, &json)
}

#[pyfunction]
fn availability(py: Python<'_>, domain: String) -> PyResult<PyObject> {
    let rt = get_runtime();
    let checker = get_availability_checker();

    let result = py.allow_threads(|| rt.block_on(async { checker.check(&domain).await }));

    match result {
        Ok(response) => {
            let json = serde_json::to_value(&response)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            json_to_python(py, &json)
        }
        Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
    }
}

#[pyfunction]
fn subdomains(py: Python<'_>, domain: String) -> PyResult<PyObject> {
    let rt = get_runtime();
    let enumerator = get_subdomain_enumerator();

    let result = py.allow_threads(|| rt.block_on(async { enumerator.enumerate(&domain).await }));

    match result {
        Ok(response) => {
            let json = serde_json::to_value(&response)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            json_to_python(py, &json)
        }
        Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
    }
}

#[pyfunction]
fn ssl(py: Python<'_>, domain: String) -> PyResult<PyObject> {
    let rt = get_runtime();
    let checker = get_ssl_checker();

    let result = py.allow_threads(|| rt.block_on(async { checker.check(&domain).await }));

    match result {
        Ok(response) => {
            let json = serde_json::to_value(&response)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            json_to_python(py, &json)
        }
        Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
    }
}

#[pyfunction]
fn dnssec(py: Python<'_>, domain: String) -> PyResult<PyObject> {
    let rt = get_runtime();
    let checker = get_dnssec_checker();

    let result = py.allow_threads(|| rt.block_on(async { checker.check(&domain).await }));

    match result {
        Ok(response) => {
            let json = serde_json::to_value(&response)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            json_to_python(py, &json)
        }
        Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
    }
}

#[pyfunction]
fn dns_compare(
    py: Python<'_>,
    domain: String,
    record_type: &str,
    server_a: String,
    server_b: String,
) -> PyResult<PyObject> {
    let rt = get_runtime();
    let comparator = get_dns_comparator();

    let rt_parsed: RecordType = record_type
        .parse()
        .map_err(|e: seer_core::SeerError| PyValueError::new_err(e.to_string()))?;

    let result = py.allow_threads(|| {
        rt.block_on(async {
            comparator
                .compare(&domain, rt_parsed, &server_a, &server_b)
                .await
        })
    });

    match result {
        Ok(response) => {
            let json = serde_json::to_value(&response)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            json_to_python(py, &json)
        }
        Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
    }
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
    let rt = get_runtime();
    let follower = get_dns_follower();

    let rt_parsed: RecordType = record_type
        .parse()
        .map_err(|e: seer_core::SeerError| PyValueError::new_err(e.to_string()))?;

    // Cap parameters to prevent blocking the shared Tokio runtime for excessive durations
    let iterations = iterations.min(100);
    let interval_minutes = interval_minutes.clamp(0.1, 60.0);

    // Cap total wall-clock time to 1 hour to prevent blocking the shared runtime
    let total_minutes = iterations as f64 * interval_minutes;
    const MAX_TOTAL_MINUTES: f64 = 60.0;
    if total_minutes > MAX_TOTAL_MINUTES {
        return Err(PyValueError::new_err(format!(
            "Total follow duration ({:.0} minutes) exceeds maximum of {:.0} minutes. Reduce iterations or interval.",
            total_minutes, MAX_TOTAL_MINUTES
        )));
    }

    let config = FollowConfig {
        iterations,
        interval_secs: (interval_minutes * 60.0) as u64,
        changes_only: false,
    };

    let result = py.allow_threads(|| {
        rt.block_on(async {
            follower
                .follow_simple(&domain, rt_parsed, nameserver.as_deref(), config)
                .await
        })
    });

    match result {
        Ok(response) => {
            let json = serde_json::to_value(&response)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            json_to_python(py, &json)
        }
        Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
    }
}

#[pyfunction]
fn diff(py: Python<'_>, domain_a: String, domain_b: String) -> PyResult<PyObject> {
    let rt = get_runtime();
    let differ = get_domain_differ();

    let result =
        py.allow_threads(|| rt.block_on(async { differ.diff(&domain_a, &domain_b).await }));

    match result {
        Ok(response) => {
            let json = serde_json::to_value(&response)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            json_to_python(py, &json)
        }
        Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
    }
}

#[pyfunction]
fn info(py: Python<'_>, domain: String) -> PyResult<PyObject> {
    let rt = get_runtime();
    let smart_lookup = get_smart_lookup();

    let result = py.allow_threads(|| rt.block_on(async { smart_lookup.lookup(&domain).await }));

    match result {
        Ok(lookup_result) => {
            let domain_info = seer_core::domain_info::DomainInfo::from_lookup_result(&lookup_result);
            let json = serde_json::to_value(&domain_info)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            json_to_python(py, &json)
        }
        Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
    }
}

#[pyfunction]
#[pyo3(signature = (domains, concurrency = 10))]
fn bulk_info(py: Python<'_>, domains: Vec<String>, concurrency: usize) -> PyResult<PyObject> {
    let rt = get_runtime();
    let executor = BulkExecutor::new().with_concurrency(validate_concurrency(concurrency)?);

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Info { domain })
        .collect();

    let result =
        py.allow_threads(|| rt.block_on(async { executor.execute(operations, None).await }));

    let json = serde_json::to_value(&result).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
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
    m.add_function(wrap_pyfunction!(diff, m)?)?;
    m.add_function(wrap_pyfunction!(info, m)?)?;
    m.add_function(wrap_pyfunction!(bulk_info, m)?)?;
    Ok(())
}
