use std::path::Path;

use seer_core::bulk::{BulkResult, BulkResultData};

/// RAII guard that enables crossterm raw mode on creation and disables it on
/// drop — including when a panic unwinds through the guarded region. The
/// `follow` command (CLI and REPL) enables raw mode to capture an Esc/Ctrl-C
/// keypress; without a Drop guard, a panic during a live follow left the
/// terminal stuck in raw mode and the user needed `reset` (issue #60).
///
/// If enabling raw mode fails (e.g. stdin is not a TTY), the guard is inert and
/// its drop is a no-op, so we never disable a mode we did not enable.
pub struct RawModeGuard {
    enabled: bool,
}

impl RawModeGuard {
    /// Enables raw mode, returning a guard that restores cooked mode on drop.
    pub fn new() -> Self {
        let enabled = crossterm::terminal::enable_raw_mode().is_ok();
        Self { enabled }
    }
}

impl Default for RawModeGuard {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        if self.enabled {
            let _ = crossterm::terminal::disable_raw_mode();
        }
    }
}

/// Write `content` to `path` atomically: write to a sibling `.tmp` file and
/// then `rename` it over the destination. `rename` is atomic on POSIX, so a
/// crash mid-write cannot leave the destination truncated. Mirrors the same
/// pattern used by `seer_core::LookupHistory::save`.
pub fn atomic_write<P: AsRef<Path>>(path: P, content: &str) -> std::io::Result<()> {
    let path = path.as_ref();
    let tmp_path = match path.extension() {
        Some(ext) => {
            let mut ext = ext.to_os_string();
            ext.push(".tmp");
            path.with_extension(ext)
        }
        None => path.with_extension("tmp"),
    };
    std::fs::write(&tmp_path, content)?;
    if let Err(e) = std::fs::rename(&tmp_path, path) {
        // Best-effort cleanup so we don't leave the `.tmp` behind.
        let _ = std::fs::remove_file(&tmp_path);
        return Err(e);
    }
    Ok(())
}

/// Maximum allowed size of a bulk input file, in bytes (1 MB).
pub const MAX_BULK_FILE_SIZE: u64 = 1024 * 1024;

/// Safely reads the contents of a bulk input file.
///
/// Guards against FIFOs, sockets, block/char devices, and directories by
/// requiring the path to point at a regular file. Also rejects files larger
/// than [`MAX_BULK_FILE_SIZE`] *before* attempting to read them, preventing
/// indefinite hangs on special files (e.g. paths created by `mkfifo`) that
/// would otherwise cause `read_to_string` to block forever.
pub fn read_bulk_input<P: AsRef<Path>>(path: P) -> Result<String, String> {
    let path = path.as_ref();
    let metadata = std::fs::metadata(path)
        .map_err(|e| format!("cannot stat input file {}: {}", path.display(), e))?;

    if !metadata.is_file() {
        return Err(format!(
            "input path is not a regular file: {}",
            path.display()
        ));
    }

    if metadata.len() > MAX_BULK_FILE_SIZE {
        return Err(format!(
            "input file exceeds {} byte limit: {} bytes",
            MAX_BULK_FILE_SIZE,
            metadata.len()
        ));
    }

    std::fs::read_to_string(path)
        .map_err(|e| format!("failed to read input file {}: {}", path.display(), e))
}

/// Expands a leading `~` or `~/...` in a path to the user's home directory.
///
/// Plain CWD-relative paths (`./foo`, `../foo`, `foo.txt`) and absolute paths
/// are returned unchanged. If `~` appears anywhere other than the start, or
/// `dirs::home_dir()` cannot determine a home, the input is returned as-is
/// and the filesystem call will surface the resulting error.
pub fn expand_tilde(s: &str) -> String {
    if s == "~" {
        if let Some(home) = dirs::home_dir() {
            return home.to_string_lossy().into_owned();
        }
        return s.to_string();
    }
    if let Some(rest) = s.strip_prefix("~/") {
        if let Some(mut home) = dirs::home_dir() {
            home.push(rest);
            return home.to_string_lossy().into_owned();
        }
    }
    s.to_string()
}

pub fn format_interval(minutes: f64) -> String {
    if minutes < 1.0 {
        format!("{}s", (minutes * 60.0) as u64)
    } else if minutes == 1.0 {
        "1m".to_string()
    } else {
        format!("{}m", minutes)
    }
}

/// Renders a machine-readable error payload for non-human formats so that
/// `--format json|yaml` (and the REPL's `set output json|yaml`) stays
/// parseable on the error path. Returns `None` for Human (callers render
/// colored prose). JSON is a subset of YAML, so the same `{"error": ...}`
/// document is valid for both.
pub fn machine_error(output_format: seer_core::output::OutputFormat, msg: &str) -> Option<String> {
    use seer_core::output::OutputFormat;
    match output_format {
        OutputFormat::Human => None,
        OutputFormat::Json | OutputFormat::Yaml => {
            Some(serde_json::json!({ "error": msg }).to_string())
        }
        OutputFormat::Markdown => Some(format!("**Error:** {}", msg)),
    }
}

/// Process exit code for a completed bulk run. Zero successes over a
/// non-empty batch means the run as a whole failed (network down, every
/// domain malformed) and scripted callers must see a non-zero exit; partial
/// failures keep exit 0 because per-row status is already in the output.
pub fn bulk_exit_code(success_count: usize, total: usize) -> i32 {
    if total > 0 && success_count == 0 {
        1
    } else {
        0
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
            csv.push_str("domain,success,registrar,created,expires,updated,duration_ms,availability_verdict,error\n");
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
        "info" => {
            csv.push_str("domain,success,source,registrar,registrant,organization,created,expires,updated,nameservers,status,dnssec,registrant_email,registrant_phone,registrant_address,registrant_country,admin_name,admin_organization,admin_email,admin_phone,tech_name,tech_organization,tech_email,tech_phone,whois_server,rdap_url,registrar_abuse_email,registrar_abuse_phone,registrar_iana_id,registrar_url,days_until_expiration,domain_age_days,expiry_status,availability_verdict,duration_ms,error\n");
        }
        "ssl" => {
            csv.push_str("domain,success,subject,issuer,valid_from,valid_until,days_remaining,signature_algorithm,key_type,key_bits,chain_length,san_count,sans,protocol_version,is_valid,duration_ms,error\n");
        }
        "posture" => {
            csv.push_str("domain,success,spf_verdict,spf_all_qualifier,dmarc_verdict,dmarc_policy,mta_sts_verdict,bimi_verdict,dane_verdict,notes,duration_ms,error\n");
        }
        "confusables" => {
            csv.push_str("domain,success,candidates_generated,candidates_checked,registered_count,registered,duration_ms,error\n");
        }
        "caa" => {
            csv.push_str("domain,success,has_policy,effective_domain,issue,issuewild,iodef,wildcard_note,duration_ms,error\n");
        }
        _ => {
            csv.push_str("domain,success,duration_ms,error\n");
        }
    }

    // Write data rows
    for result in results {
        let domain = escape_csv_field(result.operation.domain());
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
                let availability_verdict = match &result.data {
                    Some(BulkResultData::Lookup(seer_core::lookup::LookupResult::Available {
                        data,
                        ..
                    })) => data.verdict(),
                    _ => "",
                };
                let availability_verdict = escape_csv_field(availability_verdict);
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{}\n",
                    domain,
                    success,
                    escape_csv_field(&registrar),
                    created,
                    expires,
                    updated,
                    duration_ms,
                    availability_verdict,
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
                let availability_verdict = escape_csv_field("");
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{}\n",
                    domain,
                    success,
                    escape_csv_field(&registrar),
                    created,
                    expires,
                    updated,
                    duration_ms,
                    availability_verdict,
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
                let availability_verdict = escape_csv_field("");
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{}\n",
                    domain,
                    success,
                    escape_csv_field(&registrar),
                    created,
                    expires,
                    updated,
                    duration_ms,
                    availability_verdict,
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
            "info" => {
                let availability_verdict = match &result.data {
                    Some(BulkResultData::Info(info)) => {
                        info.availability_verdict.as_deref().unwrap_or("")
                    }
                    _ => "",
                };
                let availability_verdict = escape_csv_field(availability_verdict);
                if let Some(BulkResultData::Info(ref info)) = result.data {
                    csv.push_str(&format!(
                        "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                        domain,
                        success,
                        info.source, // Display impl renders the same lowercase form as JSON
                        escape_csv_field(info.registrar.as_deref().unwrap_or("")),
                        escape_csv_field(info.registrant.as_deref().unwrap_or("")),
                        escape_csv_field(info.organization.as_deref().unwrap_or("")),
                        info.creation_date.map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default(),
                        info.expiration_date.map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default(),
                        info.updated_date.map(|d| d.format("%Y-%m-%d").to_string()).unwrap_or_default(),
                        escape_csv_field(&info.nameservers.join(";")),
                        escape_csv_field(&info.status.join(";")),
                        escape_csv_field(info.dnssec.as_deref().unwrap_or("")),
                        escape_csv_field(info.registrant_email.as_deref().unwrap_or("")),
                        escape_csv_field(info.registrant_phone.as_deref().unwrap_or("")),
                        escape_csv_field(info.registrant_address.as_deref().unwrap_or("")),
                        escape_csv_field(info.registrant_country.as_deref().unwrap_or("")),
                        escape_csv_field(info.admin_name.as_deref().unwrap_or("")),
                        escape_csv_field(info.admin_organization.as_deref().unwrap_or("")),
                        escape_csv_field(info.admin_email.as_deref().unwrap_or("")),
                        escape_csv_field(info.admin_phone.as_deref().unwrap_or("")),
                        escape_csv_field(info.tech_name.as_deref().unwrap_or("")),
                        escape_csv_field(info.tech_organization.as_deref().unwrap_or("")),
                        escape_csv_field(info.tech_email.as_deref().unwrap_or("")),
                        escape_csv_field(info.tech_phone.as_deref().unwrap_or("")),
                        escape_csv_field(info.whois_server.as_deref().unwrap_or("")),
                        escape_csv_field(info.rdap_url.as_deref().unwrap_or("")),
                        escape_csv_field(info.registrar_abuse_email.as_deref().unwrap_or("")),
                        escape_csv_field(info.registrar_abuse_phone.as_deref().unwrap_or("")),
                        escape_csv_field(info.registrar_iana_id.as_deref().unwrap_or("")),
                        escape_csv_field(info.registrar_url.as_deref().unwrap_or("")),
                        info.days_until_expiration.map(|d| d.to_string()).unwrap_or_default(),
                        info.domain_age_days.map(|d| d.to_string()).unwrap_or_default(),
                        info.expiry_status.map(|s| s.to_string()).unwrap_or_default(),
                        availability_verdict,
                        duration_ms,
                        error
                    ));
                } else {
                    csv.push_str(&format!(
                        "{},{},,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,{},{},{}\n",
                        domain, success, availability_verdict, duration_ms, error
                    ));
                }
            }
            "ssl" => {
                let (
                    subject,
                    issuer,
                    valid_from,
                    valid_until,
                    days_remaining,
                    signature_algorithm,
                    key_type,
                    key_bits,
                    chain_length,
                    san_count,
                    sans,
                    protocol_version,
                    is_valid,
                ) = if let Some(BulkResultData::Ssl(ref r)) = result.data {
                    let leaf = r.chain.first();
                    (
                        leaf.map(|c| c.subject.clone()).unwrap_or_default(),
                        leaf.map(|c| c.issuer.clone()).unwrap_or_default(),
                        leaf.map(|c| c.valid_from.format("%Y-%m-%d").to_string())
                            .unwrap_or_default(),
                        leaf.map(|c| c.valid_until.format("%Y-%m-%d").to_string())
                            .unwrap_or_default(),
                        r.days_until_expiry.to_string(),
                        leaf.and_then(|c| c.signature_algorithm.clone())
                            .unwrap_or_default(),
                        leaf.and_then(|c| c.key_type.clone()).unwrap_or_default(),
                        leaf.and_then(|c| c.key_bits)
                            .map(|n| n.to_string())
                            .unwrap_or_default(),
                        r.chain.len().to_string(),
                        r.san_names.len().to_string(),
                        join_sans(&r.san_names),
                        r.protocol_version.clone().unwrap_or_default(),
                        r.is_valid.to_string(),
                    )
                } else {
                    // `Default` is only implemented for tuples up to 12 elements,
                    // so spell out 13 empty Strings explicitly.
                    (
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                        String::new(),
                    )
                };
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n",
                    domain,
                    success,
                    escape_csv_field(&subject),
                    escape_csv_field(&issuer),
                    valid_from,
                    valid_until,
                    days_remaining,
                    escape_csv_field(&signature_algorithm),
                    escape_csv_field(&key_type),
                    key_bits,
                    chain_length,
                    san_count,
                    escape_csv_field(&sans),
                    escape_csv_field(&protocol_version),
                    is_valid,
                    duration_ms,
                    error
                ));
            }
            "posture" => {
                let (spf_verdict, spf_all, dmarc_verdict, dmarc_policy, mta_sts, bimi, dane, notes) =
                    if let Some(BulkResultData::Posture(ref p)) = result.data {
                        (
                            posture_verdict_str(p.spf.verdict).to_string(),
                            p.spf.all_qualifier.clone().unwrap_or_default(),
                            posture_verdict_str(p.dmarc.verdict).to_string(),
                            p.dmarc.policy.clone().unwrap_or_default(),
                            posture_verdict_str(p.mta_sts.verdict).to_string(),
                            posture_verdict_str(p.bimi.verdict).to_string(),
                            posture_verdict_str(p.dane.verdict).to_string(),
                            p.notes.join(";"),
                        )
                    } else {
                        Default::default()
                    };
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{},{},{}\n",
                    domain,
                    success,
                    spf_verdict,
                    escape_csv_field(&spf_all),
                    dmarc_verdict,
                    escape_csv_field(&dmarc_policy),
                    mta_sts,
                    bimi,
                    dane,
                    escape_csv_field(&notes),
                    duration_ms,
                    error
                ));
            }
            "confusables" => {
                let (generated, checked, count, registered) =
                    if let Some(BulkResultData::Confusables(ref r)) = result.data {
                        let joined = r
                            .registered
                            .iter()
                            .map(|l| format!("{}({})", l.domain, l.technique))
                            .collect::<Vec<_>>()
                            .join(";");
                        (
                            r.candidates_generated.to_string(),
                            r.candidates_checked.to_string(),
                            r.registered.len().to_string(),
                            joined,
                        )
                    } else {
                        Default::default()
                    };
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{},{}\n",
                    domain,
                    success,
                    generated,
                    checked,
                    count,
                    escape_csv_field(&registered),
                    duration_ms,
                    error
                ));
            }
            "caa" => {
                let (has_policy, effective_domain, issue, issuewild, iodef, wildcard_note) =
                    if let Some(BulkResultData::Caa(ref p)) = result.data {
                        let tag_values = |tag: &str| {
                            p.records
                                .iter()
                                .filter(|r| r.tag == tag)
                                .map(|r| r.value.clone())
                                .collect::<Vec<_>>()
                                .join(";")
                        };
                        (
                            p.has_policy.to_string(),
                            p.effective_domain.clone().unwrap_or_default(),
                            tag_values("issue"),
                            tag_values("issuewild"),
                            p.iodef.join(";"),
                            p.wildcard_note.clone().unwrap_or_default(),
                        )
                    } else {
                        Default::default()
                    };
                csv.push_str(&format!(
                    "{},{},{},{},{},{},{},{},{},{}\n",
                    domain,
                    success,
                    has_policy,
                    escape_csv_field(&effective_domain),
                    escape_csv_field(&issue),
                    escape_csv_field(&issuewild),
                    escape_csv_field(&iodef),
                    escape_csv_field(&wildcard_note),
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

/// CSV cell rendering for a [`seer_core::PostureVerdict`] — matches the
/// kebab-case serde form used in JSON output.
fn posture_verdict_str(v: seer_core::PostureVerdict) -> &'static str {
    use seer_core::PostureVerdict;
    match v {
        PostureVerdict::Absent => "absent",
        PostureVerdict::Weak => "weak",
        PostureVerdict::Moderate => "moderate",
        PostureVerdict::Strict => "strict",
        PostureVerdict::Present => "present",
    }
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

/// SAN limit before truncation in CSV output. A handful of certs have
/// hundreds of SANs (wildcards, CDNs); writing them all into a single CSV
/// cell makes the file unreadable. We keep the first `SAN_DISPLAY_LIMIT`
/// and append `;…+N more` so the column stays truthful about the count.
const SAN_DISPLAY_LIMIT: usize = 10;

/// Joins a SAN list with `;`, truncating to the first `SAN_DISPLAY_LIMIT`
/// entries and appending `;…+N more` when the list is longer.
pub fn join_sans(sans: &[String]) -> String {
    if sans.len() <= SAN_DISPLAY_LIMIT {
        return sans.join(";");
    }
    let head = sans[..SAN_DISPLAY_LIMIT].join(";");
    let remainder = sans.len() - SAN_DISPLAY_LIMIT;
    format!("{head};…+{remainder} more")
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use seer_core::bulk::BulkOperation;
    use seer_core::ssl::{CertDetail, SslReport};

    #[test]
    fn raw_mode_guard_constructs_and_drops_without_panic() {
        // In a non-TTY test environment enable_raw_mode() fails, so the guard
        // is inert; constructing and dropping it must be safe either way, and
        // Drop must never disable a mode that was never enabled (issue #60).
        let guard = RawModeGuard::new();
        drop(guard); // must not panic
    }

    #[test]
    fn expand_tilde_returns_home_for_lone_tilde() {
        let home = dirs::home_dir().expect("home dir for test");
        assert_eq!(expand_tilde("~"), home.to_string_lossy());
    }

    #[test]
    fn expand_tilde_joins_relative_under_home() {
        let home = dirs::home_dir().expect("home dir for test");
        let got = expand_tilde("~/Projects/foo/bar.txt");
        let want = home
            .join("Projects/foo/bar.txt")
            .to_string_lossy()
            .into_owned();
        assert_eq!(got, want);
    }

    #[test]
    fn expand_tilde_leaves_other_paths_unchanged() {
        // CWD-relative and absolute paths must not be rewritten.
        for p in [
            "domains.txt",
            "./domains.txt",
            "../domains.txt",
            "/etc/hosts",
            // `~` mid-path must NOT trigger expansion — only a leading `~/` or
            // a bare `~`. Filenames legitimately containing `~` (rare but
            // possible) would otherwise break.
            "foo~bar.txt",
            "/tmp/~something",
        ] {
            assert_eq!(expand_tilde(p), p, "input {p:?} should be unchanged");
        }
    }

    #[test]
    fn join_sans_returns_all_when_under_limit() {
        let sans = vec!["a.example.com".to_string(), "b.example.com".to_string()];
        assert_eq!(join_sans(&sans), "a.example.com;b.example.com");
    }

    #[test]
    fn join_sans_truncates_with_remainder_suffix() {
        // 12 SANs → first 10 joined, then ";…+2 more"
        let sans: Vec<String> = (1..=12).map(|i| format!("h{i}.example.com")).collect();
        let joined = join_sans(&sans);
        let expected_first_ten = (1..=10)
            .map(|i| format!("h{i}.example.com"))
            .collect::<Vec<_>>()
            .join(";");
        assert_eq!(joined, format!("{};…+2 more", expected_first_ten));
    }

    #[test]
    fn join_sans_exactly_ten_is_not_truncated() {
        let sans: Vec<String> = (1..=10).map(|i| format!("h{i}.example.com")).collect();
        let joined = join_sans(&sans);
        assert!(!joined.contains("more"), "got: {joined}");
        assert_eq!(joined.matches(';').count(), 9);
    }

    fn sample_cert_detail() -> CertDetail {
        CertDetail {
            subject: "CN=example.com".to_string(),
            issuer: "C=US, O=Test Org, CN=Test Root CA".to_string(),
            valid_from: chrono::Utc.with_ymd_and_hms(2024, 1, 30, 0, 0, 0).unwrap(),
            valid_until: chrono::Utc.with_ymd_and_hms(2025, 3, 1, 0, 0, 0).unwrap(),
            serial_number: "deadbeef".to_string(),
            signature_algorithm: Some("sha256WithRSAEncryption".to_string()),
            is_ca: false,
            key_type: Some("RSA".to_string()),
            key_bits: Some(2048),
        }
    }

    fn sample_report() -> SslReport {
        SslReport {
            domain: "example.com".to_string(),
            chain: vec![
                sample_cert_detail(),
                CertDetail {
                    is_ca: true,
                    ..sample_cert_detail()
                },
            ],
            protocol_version: Some("TLS 1.3".to_string()),
            san_names: vec!["example.com".to_string(), "www.example.com".to_string()],
            is_valid: true,
            hostname_verified: true,
            days_until_expiry: 89,
            caa: None,
            warnings: vec![],
        }
    }

    #[test]
    fn ssl_csv_emits_expected_header_and_row() {
        let report = sample_report();
        let result = BulkResult {
            operation: BulkOperation::Ssl {
                domain: "example.com".to_string(),
            },
            success: true,
            data: Some(BulkResultData::Ssl(report)),
            error: None,
            duration_ms: 612,
        };
        let csv = bulk_results_to_csv(std::slice::from_ref(&result), "ssl");
        let mut lines = csv.lines();
        assert_eq!(
            lines.next().expect("header line"),
            "domain,success,subject,issuer,valid_from,valid_until,days_remaining,signature_algorithm,key_type,key_bits,chain_length,san_count,sans,protocol_version,is_valid,duration_ms,error"
        );
        let row = lines.next().expect("data row");
        // Spot-check key fields are present and ordered correctly.
        assert!(row.starts_with("example.com,true,CN=example.com,"));
        assert!(row.contains(",2024-01-30,2025-03-01,89,"));
        assert!(row.contains(",sha256WithRSAEncryption,RSA,2048,"));
        // chain_length=2, san_count=2, sans joined
        assert!(row.contains(",2,2,example.com;www.example.com,"));
        assert!(row.contains(",TLS 1.3,true,612,"));
        assert!(
            row.contains("\"C=US, O=Test Org, CN=Test Root CA\""),
            "issuer should be RFC-4180 quoted when it contains commas; got row: {row}"
        );
    }

    #[test]
    fn ssl_csv_failure_row_has_empty_ssl_columns() {
        let result = BulkResult {
            operation: BulkOperation::Ssl {
                domain: "broken.invalid".to_string(),
            },
            success: false,
            data: None,
            error: Some("could not resolve broken.invalid".to_string()),
            duration_ms: 12,
        };
        let csv = bulk_results_to_csv(std::slice::from_ref(&result), "ssl");
        let row = csv.lines().nth(1).expect("data row");
        // domain, success=false, then 13 empty SSL columns, then duration, then error.
        assert!(row.starts_with("broken.invalid,false,,,,,,,,,,,,,,12,"));
        assert!(row.ends_with("could not resolve broken.invalid"));
    }

    #[test]
    fn read_bulk_input_rejects_directory() {
        // A directory is a readable filesystem entry but not a regular file;
        // the metadata guard must reject it so we don't hit `read_to_string`
        // on something that is not a plain file.
        let dir = std::env::temp_dir();
        let md = std::fs::metadata(&dir).expect("temp dir should exist");
        assert!(!md.is_file(), "temp dir should not be a regular file");

        let err = read_bulk_input(&dir).expect_err("directory must be rejected");
        assert!(
            err.contains("not a regular file"),
            "unexpected error message: {err}"
        );
    }

    #[test]
    fn read_bulk_input_rejects_missing_path() {
        let missing = std::env::temp_dir().join("seer-bulk-input-does-not-exist-xyzzy");
        // Best-effort cleanup in case a stray entry exists.
        let _ = std::fs::remove_file(&missing);

        let err = read_bulk_input(&missing).expect_err("missing path must error");
        assert!(
            err.contains("cannot stat"),
            "unexpected error message: {err}"
        );
    }

    #[test]
    fn read_bulk_input_reads_regular_file() {
        let path = std::env::temp_dir().join("seer-bulk-input-regular-file.txt");
        std::fs::write(&path, "example.com\n").expect("write temp file");

        let content = read_bulk_input(&path).expect("regular file should be readable");
        assert_eq!(content, "example.com\n");

        let _ = std::fs::remove_file(&path);
    }

    fn sample_posture() -> seer_core::EmailPosture {
        use seer_core::{
            BimiPolicy, DanePolicy, DmarcPolicy, EmailPosture, MtaStsPolicy, PostureVerdict,
            SpfPolicy,
        };
        EmailPosture {
            domain: "example.com".to_string(),
            spf: SpfPolicy {
                present: true,
                record: Some("v=spf1 -all".to_string()),
                all_qualifier: Some("-".to_string()),
                verdict: PostureVerdict::Strict,
            },
            dmarc: DmarcPolicy {
                present: true,
                record: Some("v=DMARC1; p=reject".to_string()),
                policy: Some("reject".to_string()),
                subdomain_policy: None,
                aggregate_reports: vec![],
                percent: None,
                verdict: PostureVerdict::Strict,
            },
            mta_sts: MtaStsPolicy {
                present: true,
                record: Some("v=STSv1; id=2024".to_string()),
                id: Some("2024".to_string()),
                verdict: PostureVerdict::Present,
            },
            bimi: BimiPolicy {
                present: false,
                record: None,
                logo_url: None,
                authority_url: None,
                verdict: PostureVerdict::Absent,
            },
            dane: DanePolicy {
                present: false,
                records: vec![],
                verdict: PostureVerdict::Absent,
            },
            notes: vec!["strong posture".to_string()],
        }
    }

    #[test]
    fn posture_csv_emits_expected_header_and_row() {
        let result = BulkResult {
            operation: BulkOperation::Posture {
                domain: "example.com".to_string(),
            },
            success: true,
            data: Some(BulkResultData::Posture(sample_posture())),
            error: None,
            duration_ms: 842,
        };
        let csv = bulk_results_to_csv(std::slice::from_ref(&result), "posture");
        let mut lines = csv.lines();
        assert_eq!(
            lines.next().expect("header line"),
            "domain,success,spf_verdict,spf_all_qualifier,dmarc_verdict,dmarc_policy,mta_sts_verdict,bimi_verdict,dane_verdict,notes,duration_ms,error"
        );
        let row = lines.next().expect("data row");
        // The `-` all-qualifier must be formula-guarded (leading `-` in a cell).
        assert!(
            row.starts_with("example.com,true,strict,'-,strict,reject,present,absent,absent,"),
            "got row: {row}"
        );
        assert!(row.contains("strong posture"));
        assert!(row.contains(",842,"));
    }

    #[test]
    fn confusables_csv_emits_expected_header_and_row() {
        let report = seer_core::ConfusableReport {
            domain: "example.com".to_string(),
            candidates_generated: 214,
            candidates_checked: 180,
            registered: vec![seer_core::RegisteredLookalike {
                domain: "examp1e.com".to_string(),
                technique: "homoglyph".to_string(),
                registrar: None,
                creation_date: None,
                nameservers: vec![],
            }],
        };
        let result = BulkResult {
            operation: BulkOperation::Confusables {
                domain: "example.com".to_string(),
            },
            success: true,
            data: Some(BulkResultData::Confusables(report)),
            error: None,
            duration_ms: 9214,
        };
        let csv = bulk_results_to_csv(std::slice::from_ref(&result), "confusables");
        let mut lines = csv.lines();
        assert_eq!(
            lines.next().expect("header line"),
            "domain,success,candidates_generated,candidates_checked,registered_count,registered,duration_ms,error"
        );
        let row = lines.next().expect("data row");
        assert!(
            row.starts_with("example.com,true,214,180,1,examp1e.com(homoglyph),9214,"),
            "got row: {row}"
        );
    }

    #[test]
    fn caa_csv_emits_expected_header_and_row() {
        let policy = seer_core::CaaPolicy {
            records: vec![
                seer_core::CaaRecord {
                    flags: 0,
                    tag: "issue".to_string(),
                    value: "letsencrypt.org".to_string(),
                },
                seer_core::CaaRecord {
                    flags: 0,
                    tag: "issue".to_string(),
                    value: "digicert.com".to_string(),
                },
                seer_core::CaaRecord {
                    flags: 0,
                    tag: "iodef".to_string(),
                    value: "mailto:security@example.com".to_string(),
                },
            ],
            effective_domain: Some("example.com".to_string()),
            has_policy: true,
            issuer_match: None,
            iodef: vec!["mailto:security@example.com".to_string()],
            wildcard_note: None,
            note: "CAA restricts which CAs may issue".to_string(),
        };
        let result = BulkResult {
            operation: BulkOperation::Caa {
                domain: "example.com".to_string(),
            },
            success: true,
            data: Some(BulkResultData::Caa(policy)),
            error: None,
            duration_ms: 133,
        };
        let csv = bulk_results_to_csv(std::slice::from_ref(&result), "caa");
        let mut lines = csv.lines();
        assert_eq!(
            lines.next().expect("header line"),
            "domain,success,has_policy,effective_domain,issue,issuewild,iodef,wildcard_note,duration_ms,error"
        );
        let row = lines.next().expect("data row");
        assert!(
            row.starts_with(
                "example.com,true,true,example.com,letsencrypt.org;digicert.com,,mailto:security@example.com,,133,"
            ),
            "got row: {row}"
        );
    }

    #[test]
    fn new_op_failure_rows_have_empty_data_columns() {
        for (op, operation) in [
            (
                "posture",
                BulkOperation::Posture {
                    domain: "bad.invalid".to_string(),
                },
            ),
            (
                "confusables",
                BulkOperation::Confusables {
                    domain: "bad.invalid".to_string(),
                },
            ),
            (
                "caa",
                BulkOperation::Caa {
                    domain: "bad.invalid".to_string(),
                },
            ),
        ] {
            let result = BulkResult {
                operation,
                success: false,
                data: None,
                error: Some("boom".to_string()),
                duration_ms: 7,
            };
            let csv = bulk_results_to_csv(std::slice::from_ref(&result), op);
            let header = csv.lines().next().expect("header");
            let row = csv.lines().nth(1).expect("data row");
            assert_eq!(
                header.matches(',').count(),
                row.matches(',').count(),
                "{op} failure row must match header column count; row: {row}"
            );
            assert!(row.starts_with("bad.invalid,false,"), "got: {row}");
            assert!(row.ends_with(",7,boom"), "got: {row}");
        }
    }

    #[test]
    fn json_error_is_parseable_and_carries_message() {
        use seer_core::output::OutputFormat;
        let s = machine_error(OutputFormat::Json, "lookup failed: boom").unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).expect("valid JSON on error path");
        assert_eq!(v["error"], "lookup failed: boom");
    }

    #[test]
    fn yaml_error_is_structured_json_subset() {
        use seer_core::output::OutputFormat;
        // JSON is a valid YAML document; assert it parses and carries the message.
        let s = machine_error(OutputFormat::Yaml, "boom").unwrap();
        let v: serde_json::Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["error"], "boom");
    }

    #[test]
    fn human_error_has_no_machine_payload() {
        use seer_core::output::OutputFormat;
        assert!(machine_error(OutputFormat::Human, "boom").is_none());
    }

    #[test]
    fn markdown_error_is_rendered() {
        use seer_core::output::OutputFormat;
        assert_eq!(
            machine_error(OutputFormat::Markdown, "boom").unwrap(),
            "**Error:** boom"
        );
    }

    #[test]
    fn bulk_exit_code_signals_total_failure_only() {
        // `seer bulk` exited 0 even when every domain failed (network down,
        // malformed list), giving scripted callers a false green
        // (2026-07-11 review). All-fail → 1; partial failure stays 0 since
        // per-row status lives in the CSV/JSON output.
        assert_eq!(bulk_exit_code(0, 5), 1, "all failed");
        assert_eq!(bulk_exit_code(3, 5), 0, "partial failure");
        assert_eq!(bulk_exit_code(5, 5), 0, "all succeeded");
        assert_eq!(bulk_exit_code(0, 0), 0, "empty batch is not a failure");
    }

    #[test]
    fn info_csv_includes_registrar_detail_and_lifecycle_columns() {
        // The PR #101 registrar-detail + lifecycle fields must reach the bulk
        // "info" CSV export, matching what JSON/YAML already expose
        // (2026-07-11 review). Also guards header/row column parity for both
        // the populated and the failure row shapes.
        let whois = seer_core::WhoisResponse::parse(
            "example.com",
            "whois.test",
            "Registrar: Example Registrar\n\
             Creation Date: 2020-01-01T00:00:00Z\n\
             Registry Expiry Date: 2099-01-01T00:00:00Z\n\
             Domain Status: clientTransferProhibited\n",
        );
        let mut info =
            seer_core::domain_info::DomainInfo::from_sources("example.com", None, Some(&whois));
        info.registrar_abuse_email = Some("abuse@registrar.test".to_string());
        info.registrar_iana_id = Some("9999".to_string());

        let results = [
            BulkResult {
                operation: BulkOperation::Info {
                    domain: "example.com".to_string(),
                },
                success: true,
                data: Some(seer_core::bulk::BulkResultData::Info(info)),
                error: None,
                duration_ms: 5,
            },
            BulkResult {
                operation: BulkOperation::Info {
                    domain: "bad.invalid".to_string(),
                },
                success: false,
                data: None,
                error: Some("boom".to_string()),
                duration_ms: 7,
            },
        ];
        let csv = bulk_results_to_csv(&results, "info");
        let mut lines = csv.lines();
        let header = lines.next().expect("header");
        for col in [
            "registrar_abuse_email",
            "registrar_abuse_phone",
            "registrar_iana_id",
            "registrar_url",
            "days_until_expiration",
            "domain_age_days",
            "expiry_status",
        ] {
            assert!(header.contains(col), "missing column {col} in: {header}");
        }
        let populated = lines.next().expect("populated row");
        assert!(populated.contains("abuse@registrar.test"), "{populated}");
        assert!(populated.contains("9999"), "{populated}");
        let failure = lines.next().expect("failure row");
        for row in [populated, failure] {
            assert_eq!(
                header.matches(',').count(),
                row.matches(',').count(),
                "info row must match header column count; row: {row}"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn read_bulk_input_rejects_fifo() {
        use std::os::unix::fs::FileTypeExt;
        use std::process::Command;

        let path =
            std::env::temp_dir().join(format!("seer-bulk-input-fifo-{}", std::process::id()));
        // Clean any leftover from a previous run.
        let _ = std::fs::remove_file(&path);

        // Create a FIFO via the system `mkfifo` binary. This keeps the test
        // dependency-free (no `nix`, no `libc` dev-dep) while still exercising
        // the exact filesystem type that motivated the hardening.
        let status = Command::new("mkfifo").arg(&path).status();
        let ok = match status {
            Ok(s) => s.success(),
            Err(_) => false,
        };
        if !ok {
            eprintln!("skipping FIFO test: mkfifo binary unavailable or failed");
            return;
        }

        let md = std::fs::metadata(&path).expect("stat fifo");
        assert!(md.file_type().is_fifo(), "expected a FIFO");
        assert!(
            !md.is_file(),
            "FIFO must not be classified as a regular file"
        );

        let err = read_bulk_input(&path).expect_err("FIFO must be rejected");
        assert!(
            err.contains("not a regular file"),
            "unexpected error message: {err}"
        );

        let _ = std::fs::remove_file(&path);
    }
}
