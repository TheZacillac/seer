use seer_core::bulk::{BulkOperation, BulkResult, BulkResultData};

pub fn format_interval(minutes: f64) -> String {
    if minutes < 1.0 {
        format!("{}s", (minutes * 60.0) as u64)
    } else if minutes == 1.0 {
        "1m".to_string()
    } else {
        format!("{}m", minutes)
    }
}

pub fn bulk_results_to_csv(results: &[BulkResult], operation: &str) -> String {
    let mut csv = String::new();

    // Write header based on operation type
    match operation {
        "status" => {
            csv.push_str("domain,success,http_status,http_status_text,title,ssl_issuer,ssl_valid_until,ssl_days_remaining,domain_expires,domain_days_remaining,registrar,dns_resolves,dns_a_records,dns_aaaa_records,dns_cname,dns_nameservers,duration_ms,error\n");
        }
        "lookup" | "whois" | "rdap" => {
            csv.push_str("domain,success,registrar,created,expires,updated,duration_ms,error\n");
        }
        "dig" | "dns" => {
            csv.push_str("domain,success,record_type,records,duration_ms,error\n");
        }
        "propagation" | "prop" => {
            csv.push_str(
                "domain,success,propagation_pct,servers_total,servers_responded,duration_ms,error\n",
            );
        }
        "avail" => {
            csv.push_str("domain,success,available,confidence,method,details,duration_ms,error\n");
        }
        _ => {
            csv.push_str("domain,success,duration_ms,error\n");
        }
    }

    // Write data rows
    for result in results {
        let domain = escape_csv_field(&get_domain_from_operation(&result.operation));
        let success = result.success;
        let duration_ms = result.duration_ms;
        let error = escape_csv_field(result.error.as_deref().unwrap_or(""));

        match operation {
            "status" => {
                let (
                    http_status,
                    http_text,
                    title,
                    ssl_issuer,
                    ssl_valid_until,
                    ssl_days,
                    domain_expires,
                    domain_days,
                    registrar,
                ) = if let Some(BulkResultData::Status(ref s)) = result.data {
                    (
                        s.http_status
                            .map(|v: u16| v.to_string())
                            .unwrap_or_default(),
                        s.http_status_text.clone().unwrap_or_default(),
                        s.title.clone().unwrap_or_default(),
                        s.certificate
                            .as_ref()
                            .map(|c| c.issuer.clone())
                            .unwrap_or_default(),
                        s.certificate
                            .as_ref()
                            .map(|c| c.valid_until.format("%Y-%m-%d").to_string())
                            .unwrap_or_default(),
                        s.certificate
                            .as_ref()
                            .map(|c| c.days_until_expiry.to_string())
                            .unwrap_or_default(),
                        s.domain_expiration
                            .as_ref()
                            .map(|d| d.expiration_date.format("%Y-%m-%d").to_string())
                            .unwrap_or_default(),
                        s.domain_expiration
                            .as_ref()
                            .map(|d| d.days_until_expiry.to_string())
                            .unwrap_or_default(),
                        s.domain_expiration
                            .as_ref()
                            .and_then(|d| d.registrar.clone())
                            .unwrap_or_default(),
                    )
                } else {
                    Default::default()
                };
                let (dns_resolves, dns_a, dns_aaaa, dns_cname, dns_ns) =
                    if let Some(BulkResultData::Status(ref s)) = result.data {
                        (
                            s.dns_resolution
                                .as_ref()
                                .map(|d| d.resolves.to_string())
                                .unwrap_or_default(),
                            s.dns_resolution
                                .as_ref()
                                .map(|d| d.a_records.join(";"))
                                .unwrap_or_default(),
                            s.dns_resolution
                                .as_ref()
                                .map(|d| d.aaaa_records.join(";"))
                                .unwrap_or_default(),
                            s.dns_resolution
                                .as_ref()
                                .and_then(|d| d.cname_target.clone())
                                .unwrap_or_default(),
                            s.dns_resolution
                                .as_ref()
                                .map(|d| d.nameservers.join(";"))
                                .unwrap_or_default(),
                        )
                    } else {
                        Default::default()
                    };
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                    domain,
                    success,
                    http_status,
                    escape_csv_field(&http_text),
                    escape_csv_field(&title),
                    escape_csv_field(&ssl_issuer),
                    ssl_valid_until,
                    ssl_days,
                    domain_expires,
                    domain_days,
                    escape_csv_field(&registrar),
                    dns_resolves,
                    escape_csv_field(&dns_a),
                    escape_csv_field(&dns_aaaa),
                    escape_csv_field(&dns_cname),
                    escape_csv_field(&dns_ns),
                    duration_ms,
                    error
                ));
            }
            "lookup" => {
                let (registrar, created, expires, updated) = if let Some(ref data) = result.data {
                    match data {
                        BulkResultData::Lookup(seer_core::lookup::LookupResult::Rdap {
                            data: r,
                            ..
                        }) => extract_rdap_dates(r),
                        BulkResultData::Lookup(seer_core::lookup::LookupResult::Whois {
                            data: w,
                            ..
                        }) => (
                            w.registrar.clone().unwrap_or_default(),
                            w.creation_date
                                .map(|d| d.format("%Y-%m-%d").to_string())
                                .unwrap_or_default(),
                            w.expiration_date
                                .map(|d| d.format("%Y-%m-%d").to_string())
                                .unwrap_or_default(),
                            w.updated_date
                                .map(|d| d.format("%Y-%m-%d").to_string())
                                .unwrap_or_default(),
                        ),
                        _ => Default::default(),
                    }
                } else {
                    Default::default()
                };
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{},{}\n",
                    domain,
                    success,
                    escape_csv_field(&registrar),
                    created,
                    expires,
                    updated,
                    duration_ms,
                    error
                ));
            }
            "whois" => {
                let (registrar, created, expires, updated) =
                    if let Some(BulkResultData::Whois(ref w)) = result.data {
                        (
                            w.registrar.clone().unwrap_or_default(),
                            w.creation_date
                                .map(|d| d.format("%Y-%m-%d").to_string())
                                .unwrap_or_default(),
                            w.expiration_date
                                .map(|d| d.format("%Y-%m-%d").to_string())
                                .unwrap_or_default(),
                            w.updated_date
                                .map(|d| d.format("%Y-%m-%d").to_string())
                                .unwrap_or_default(),
                        )
                    } else {
                        Default::default()
                    };
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{},{}\n",
                    domain,
                    success,
                    escape_csv_field(&registrar),
                    created,
                    expires,
                    updated,
                    duration_ms,
                    error
                ));
            }
            "rdap" => {
                let (registrar, created, expires, updated) =
                    if let Some(BulkResultData::Rdap(ref r)) = result.data {
                        extract_rdap_dates(r)
                    } else {
                        Default::default()
                    };
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{},{}\n",
                    domain,
                    success,
                    escape_csv_field(&registrar),
                    created,
                    expires,
                    updated,
                    duration_ms,
                    error
                ));
            }
            "dig" | "dns" => {
                let (record_type, records) =
                    if let Some(BulkResultData::Dns(ref recs)) = result.data {
                        let rt = recs
                            .first()
                            .map(|r| r.record_type.to_string())
                            .unwrap_or_default();
                        let vals: Vec<String> = recs
                            .iter()
                            .map(seer_core::DnsRecord::format_short)
                            .collect();
                        (rt, vals.join("; "))
                    } else {
                        Default::default()
                    };
                csv.push_str(&format!(
                    "{},{},{},{},{},{}\n",
                    domain,
                    success,
                    record_type,
                    escape_csv_field(&records),
                    duration_ms,
                    error
                ));
            }
            "propagation" | "prop" => {
                let (pct, total, responded) =
                    if let Some(BulkResultData::Propagation(ref p)) = result.data {
                        let total = p.results.len();
                        let responded = p.results.iter().filter(|r| r.success).count();
                        let pct = if total > 0 {
                            (responded as f64 / total as f64) * 100.0
                        } else {
                            0.0
                        };
                        (
                            format!("{:.1}", pct),
                            total.to_string(),
                            responded.to_string(),
                        )
                    } else {
                        Default::default()
                    };
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{}\n",
                    domain, success, pct, total, responded, duration_ms, error
                ));
            }
            "avail" => {
                let (available, confidence, method, details) =
                    if let Some(BulkResultData::Avail(ref a)) = result.data {
                        (
                            a.available.to_string(),
                            a.confidence.clone(),
                            a.method.clone(),
                            a.details.clone().unwrap_or_default(),
                        )
                    } else {
                        Default::default()
                    };
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{},{}\n",
                    domain,
                    success,
                    available,
                    confidence,
                    method,
                    escape_csv_field(&details),
                    duration_ms,
                    error
                ));
            }
            _ => {
                csv.push_str(&format!(
                    "{},{},{},{}\n",
                    domain, success, duration_ms, error
                ));
            }
        }
    }

    csv
}

/// Escapes a CSV field for safe output, following RFC 4180 with Excel formula
/// injection protection.
///
/// # Anti-formula protection
/// Fields starting with `=`, `+`, `-`, `@`, `\t`, or `\r` are prefixed with a
/// single quote (`'`) to prevent formula injection in Excel and LibreOffice.
/// This prefix is a display convention specific to spreadsheet applications and
/// will appear as a literal character in non-spreadsheet CSV parsers.
///
/// For programmatic CSV consumption (non-spreadsheet), consider using the
/// `--format json` output instead which does not apply this transformation.
pub fn escape_csv_field(s: &str) -> String {
    // Protect against CSV injection by prefixing formula-starting characters with a single quote
    // This prevents Excel/Sheets from interpreting the content as a formula
    let s = if s.starts_with('=')
        || s.starts_with('+')
        || s.starts_with('-')
        || s.starts_with('@')
        || s.starts_with('\t')
        || s.starts_with('\r')
    {
        format!("'{}", s)
    } else {
        s.to_string()
    };

    // RFC 4180 quoting: if the field contains a comma, double-quote, or newline,
    // wrap it in double quotes and escape internal double-quotes by doubling them.
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s
    }
}

pub fn get_domain_from_operation(op: &BulkOperation) -> String {
    match op {
        BulkOperation::Whois { domain } => domain.clone(),
        BulkOperation::Rdap { domain } => domain.clone(),
        BulkOperation::Dns { domain, .. } => domain.clone(),
        BulkOperation::Propagation { domain, .. } => domain.clone(),
        BulkOperation::Lookup { domain } => domain.clone(),
        BulkOperation::Status { domain } => domain.clone(),
        BulkOperation::Avail { domain } => domain.clone(),
        BulkOperation::Info { domain } => domain.clone(),
    }
}

pub fn extract_rdap_dates(r: &seer_core::rdap::RdapResponse) -> (String, String, String, String) {
    let registrar = r.get_registrar().unwrap_or_default();

    let created = r
        .creation_date()
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default();

    let expires = r
        .expiration_date()
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default();

    let updated = r
        .last_updated()
        .map(|d| d.format("%Y-%m-%d").to_string())
        .unwrap_or_default();

    (registrar, created, expires, updated)
}
