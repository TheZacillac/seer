use pyo3::prelude::*;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::types::PyDict;
use seer_core::{
    bulk::{BulkExecutor, BulkOperation},
    dns::{DnsResolver, PropagationChecker, RecordType},
    lookup::SmartLookup,
    rdap::RdapClient,
    status::StatusClient,
    whois::WhoisClient,
};

fn get_runtime() -> &'static tokio::runtime::Runtime {
    use std::sync::OnceLock;
    static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("Failed to create Tokio runtime")
    })
}

#[pyfunction]
fn lookup(py: Python<'_>, domain: String) -> PyResult<PyObject> {
    let rt = get_runtime();
    let smart_lookup = SmartLookup::new();

    let result = rt.block_on(async { smart_lookup.lookup(&domain).await });

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
    let client = WhoisClient::new();

    let result = rt.block_on(async { client.lookup(&domain).await });

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
    let client = RdapClient::new();

    let result = rt.block_on(async { client.lookup_domain(&domain).await });

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
    let client = RdapClient::new();

    let result = rt.block_on(async { client.lookup_ip(&ip).await });

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
    let client = RdapClient::new();

    let result = rt.block_on(async { client.lookup_asn(asn).await });

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
    let resolver = DnsResolver::new();

    let rt_parsed: RecordType = record_type
        .parse()
        .map_err(|e: seer_core::SeerError| PyValueError::new_err(e.to_string()))?;

    let result = rt.block_on(async {
        resolver
            .resolve(&domain, rt_parsed, nameserver.as_deref())
            .await
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
    let checker = PropagationChecker::new();

    let rt_parsed: RecordType = record_type
        .parse()
        .map_err(|e: seer_core::SeerError| PyValueError::new_err(e.to_string()))?;

    let result = rt.block_on(async { checker.check(&domain, rt_parsed).await });

    match result {
        Ok(result) => {
            let json = serde_json::to_value(&result)
                .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
            json_to_python(py, &json)
        }
        Err(e) => Err(PyRuntimeError::new_err(e.to_string())),
    }
}

#[pyfunction]
#[pyo3(signature = (domains, concurrency = 10))]
fn bulk_lookup(py: Python<'_>, domains: Vec<String>, concurrency: usize) -> PyResult<PyObject> {
    let rt = get_runtime();
    let executor = BulkExecutor::new().with_concurrency(concurrency);

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Lookup { domain })
        .collect();

    let result = rt.block_on(async { executor.execute(operations, None).await });

    let json =
        serde_json::to_value(&result).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    json_to_python(py, &json)
}

#[pyfunction]
#[pyo3(signature = (domains, concurrency = 10))]
fn bulk_whois(py: Python<'_>, domains: Vec<String>, concurrency: usize) -> PyResult<PyObject> {
    let rt = get_runtime();
    let executor = BulkExecutor::new().with_concurrency(concurrency);

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Whois { domain })
        .collect();

    let result = rt.block_on(async { executor.execute(operations, None).await });

    let json =
        serde_json::to_value(&result).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
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
    let executor = BulkExecutor::new().with_concurrency(concurrency);

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

    let result = rt.block_on(async { executor.execute(operations, None).await });

    let json =
        serde_json::to_value(&result).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
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
    let executor = BulkExecutor::new().with_concurrency(concurrency);

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

    let result = rt.block_on(async { executor.execute(operations, None).await });

    let json =
        serde_json::to_value(&result).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    json_to_python(py, &json)
}

#[pyfunction]
fn status(py: Python<'_>, domain: String) -> PyResult<PyObject> {
    let rt = get_runtime();
    let client = StatusClient::new();

    let result = rt.block_on(async { client.check(&domain).await });

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
    let executor = BulkExecutor::new().with_concurrency(concurrency);

    let operations: Vec<BulkOperation> = domains
        .into_iter()
        .map(|domain| BulkOperation::Status { domain })
        .collect();

    let result = rt.block_on(async { executor.execute(operations, None).await });

    let json =
        serde_json::to_value(&result).map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    json_to_python(py, &json)
}

fn json_to_python(py: Python<'_>, value: &serde_json::Value) -> PyResult<PyObject> {
    match value {
        serde_json::Value::Null => Ok(py.None()),
        serde_json::Value::Bool(b) => Ok(b.into_pyobject(py)?.to_owned().into_any().unbind()),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.into_pyobject(py)?.into_any().unbind())
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

#[pymodule]
fn _seer(m: &Bound<'_, PyModule>) -> PyResult<()> {
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
    Ok(())
}
