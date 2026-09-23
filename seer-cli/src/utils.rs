use std::path::Path;

use chrono::{DateTime, Utc};
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

    /// Whether raw mode was actually enabled (false when there is no usable
    /// terminal, e.g. stdin/stdout redirected in CI).
    pub fn is_enabled(&self) -> bool {
        self.enabled
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

/// Poll timeout for the follow key listener; also bounds how long
/// [`FollowKeyListener::stop`] waits for the thread to notice its stop flag.
const KEY_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(100);

/// True for the keys that cancel a live `follow`: Esc, or Ctrl-C (which
/// arrives as a key event rather than SIGINT while raw mode is on).
pub fn is_follow_cancel_key(
    code: crossterm::event::KeyCode,
    modifiers: crossterm::event::KeyModifiers,
) -> bool {
    use crossterm::event::{KeyCode, KeyModifiers};
    match code {
        KeyCode::Esc => true,
        KeyCode::Char('c') => modifiers.contains(KeyModifiers::CONTROL),
        _ => false,
    }
}

/// The follow key listener's loop, generic over the key source so it can be
/// tested without a terminal. `next_key` blocks for at most one poll interval
/// and yields `Ok(Some(key))`, `Ok(None)` (nothing pressed), or `Err` (no
/// usable terminal). The loop ends when a cancel key is pressed (signalling
/// `cancel_tx`), when `stop` is set, when the follow's receiver is gone, or
/// on the first poll error — an erroring poll returns immediately, so
/// retrying it would spin a core at 100%.
pub fn run_follow_key_loop<F>(
    mut next_key: F,
    stop: &std::sync::atomic::AtomicBool,
    cancel_tx: &tokio::sync::watch::Sender<bool>,
) where
    F: FnMut() -> std::io::Result<
        Option<(crossterm::event::KeyCode, crossterm::event::KeyModifiers)>,
    >,
{
    use std::sync::atomic::Ordering;
    while !stop.load(Ordering::Relaxed) && !cancel_tx.is_closed() {
        match next_key() {
            Ok(Some((code, modifiers))) if is_follow_cancel_key(code, modifiers) => {
                let _ = cancel_tx.send(true);
                break;
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }
}

/// Esc / Ctrl-C listener for the `follow` command (CLI and REPL).
///
/// crossterm's `event::poll` is a blocking call, so the loop runs on a
/// blocking-pool thread via `spawn_blocking` — running it inside
/// `tokio::spawn` pinned a runtime worker for the whole follow (starving DNS
/// queries and timers on a single-worker runtime), and `abort()` could not
/// interrupt it. A shared stop flag, checked every poll interval, is what
/// actually ends it.
pub struct FollowKeyListener {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: tokio::task::JoinHandle<()>,
}

impl FollowKeyListener {
    /// Starts the listener, or returns `None` when there is no terminal to
    /// read keys from: raw mode could not be enabled, or stdin is not a TTY.
    /// Callers keep their other cancellation paths (the CLI's SIGINT task),
    /// so a missing listener only loses the Esc shortcut.
    pub fn spawn(
        cancel_tx: tokio::sync::watch::Sender<bool>,
        raw_mode_enabled: bool,
    ) -> Option<Self> {
        use std::io::IsTerminal;
        if !raw_mode_enabled || !std::io::stdin().is_terminal() {
            return None;
        }
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_flag = stop.clone();
        let handle = tokio::task::spawn_blocking(move || {
            use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
            let next_key = || -> std::io::Result<Option<(KeyCode, KeyModifiers)>> {
                if event::poll(KEY_POLL_INTERVAL)? {
                    if let Event::Key(KeyEvent {
                        code, modifiers, ..
                    }) = event::read()?
                    {
                        return Ok(Some((code, modifiers)));
                    }
                }
                Ok(None)
            };
            run_follow_key_loop(next_key, &stop_flag, &cancel_tx);
        });
        Some(Self { stop, handle })
    }

    /// Signals the listener to stop and waits (at most one poll interval) for
    /// its thread to exit, so it can no longer consume keystrokes meant for
    /// whatever reads the terminal next (e.g. the REPL prompt).
    pub async fn stop(self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = self.handle.await;
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

/// Reads a bulk domain list from `reader` (stdin for `bulk -`), enforcing the
/// same [`MAX_BULK_FILE_SIZE`] cap as [`read_bulk_input`]. Reads at most one
/// byte past the cap, so an endless or huge pipe can't exhaust memory.
pub fn read_bulk_stdin<R: std::io::Read>(reader: R) -> Result<String, String> {
    use std::io::Read;
    let mut buf = Vec::new();
    reader
        .take(MAX_BULK_FILE_SIZE + 1)
        .read_to_end(&mut buf)
        .map_err(|e| format!("reading domains from stdin: {e}"))?;
    if buf.len() as u64 > MAX_BULK_FILE_SIZE {
        return Err(format!(
            "input on stdin exceeds {} byte limit",
            MAX_BULK_FILE_SIZE
        ));
    }
    String::from_utf8(buf).map_err(|e| format!("reading domains from stdin: {e}"))
}

/// Expands a leading `~` or `~/...` in a path to the user's home directory.
///
/// Plain CWD-relative paths (`./foo`, `../foo`, `foo.txt`) and absolute paths
/// are returned unchanged. If `~` appears anywhere other than the start, or
/// `std::env::home_dir()` cannot determine a home, the input is returned as-is
/// and the filesystem call will surface the resulting error.
pub fn expand_tilde(s: &str) -> String {
    if s == "~" {
        if let Some(home) = std::env::home_dir() {
            return home.to_string_lossy().into_owned();
        }
        return s.to_string();
    }
    if let Some(rest) = s.strip_prefix("~/") {
        if let Some(mut home) = std::env::home_dir() {
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

/// Renders bulk results as CSV: `domain,success,<op columns>,duration_ms,
/// <trailing op columns>,error`. Text cells are formula-guarded via
/// [`escape_csv_field`]; numbers, dates, and fixed vocabularies are not, so
/// e.g. a negative `ssl_days_remaining` stays a number in spreadsheets.
pub fn bulk_results_to_csv(results: &[BulkResult], operation: &str) -> String {
    let (columns, trailing, cells_of) = csv_layout(operation);
    let (width, trailing_width) = (column_count(columns), column_count(trailing));

    let header = [
        "domain",
        "success",
        columns,
        "duration_ms",
        trailing,
        "error",
    ];
    let header: Vec<&str> = header.into_iter().filter(|c| !c.is_empty()).collect();
    let mut csv = header.join(",");
    csv.push('\n');

    for result in results {
        // Failed rows (no data) keep every op column, just empty.
        let mut cells = result
            .data
            .as_ref()
            .and_then(cells_of)
            .unwrap_or_else(|| vec![String::new(); width + trailing_width]);
        debug_assert_eq!(
            cells.len(),
            width + trailing_width,
            "{operation} CSV cells out of step with its header"
        );
        let after_duration = cells.split_off(width);
        let row: Vec<String> = [
            escape_csv_field(result.operation.domain()),
            result.success.to_string(),
        ]
        .into_iter()
        .chain(cells)
        .chain([result.duration_ms.to_string()])
        .chain(after_duration)
        .chain([escape_csv_field(result.error.as_deref().unwrap_or(""))])
        .collect();
        csv.push_str(&row.join(","));
        csv.push('\n');
    }

    csv
}

/// Cell values for one result's data — the op's columns, then its trailing
/// columns — or `None` when the data is not that op's shape.
type CsvCells = fn(&BulkResultData) -> Option<Vec<String>>;

/// Shared by the lookup/whois/rdap layouts.
const REGISTRATION_COLUMNS: &str = "registrar,created,expires,updated";

/// Per-op CSV layout: the columns between `success` and `duration_ms`, the
/// trailing ones between `duration_ms` and `error`, and the cell builder.
/// lookup/whois/rdap put `availability_verdict` after `duration_ms` (it was
/// appended later); it stays there so existing spreadsheets keep lining up.
fn csv_layout(operation: &str) -> (&'static str, &'static str, CsvCells) {
    match operation {
        "status" => (
            "http_status,http_status_text,title,ssl_issuer,ssl_valid_until,ssl_days_remaining,\
             domain_expires,domain_days_remaining,registrar,dns_resolves,dns_a_records,\
             dns_aaaa_records,dns_cname,dns_nameservers",
            "",
            status_cells,
        ),
        "lookup" | "whois" | "rdap" => (
            REGISTRATION_COLUMNS,
            "availability_verdict",
            registration_cells,
        ),
        "dig" | "dns" => ("record_type,records", "", dns_cells),
        "propagation" | "prop" => (
            "propagation_pct,servers_total,servers_responded",
            "",
            propagation_cells,
        ),
        "avail" => ("available,confidence,method,details", "", avail_cells),
        "info" => (
            "source,registrar,registrant,organization,created,expires,updated,nameservers,status,\
             dnssec,registrant_email,registrant_phone,registrant_address,registrant_country,\
             admin_name,admin_organization,admin_email,admin_phone,tech_name,tech_organization,\
             tech_email,tech_phone,whois_server,rdap_url,registrar_abuse_email,\
             registrar_abuse_phone,registrar_iana_id,registrar_url,days_until_expiration,\
             domain_age_days,expiry_status,availability_verdict",
            "",
            info_cells,
        ),
        "ssl" => (
            "subject,issuer,valid_from,valid_until,days_remaining,signature_algorithm,key_type,\
             key_bits,chain_length,san_count,sans,protocol_version,is_valid",
            "",
            ssl_cells,
        ),
        "posture" => (
            "spf_verdict,spf_all_qualifier,dmarc_verdict,dmarc_policy,mta_sts_verdict,\
             bimi_verdict,dane_verdict,notes",
            "",
            posture_cells,
        ),
        "confusables" => (
            "candidates_generated,candidates_checked,registered_count,registered",
            "",
            confusables_cells,
        ),
        "caa" => (
            "has_policy,effective_domain,issue,issuewild,iodef,wildcard_note",
            "",
            caa_cells,
        ),
        _ => ("", "", |_| None),
    }
}

fn column_count(columns: &str) -> usize {
    if columns.is_empty() {
        0
    } else {
        columns.split(',').count()
    }
}

/// A formula-guarded text cell (empty when absent).
fn text(value: Option<&str>) -> String {
    escape_csv_field(value.unwrap_or(""))
}

/// An unescaped cell for numbers, booleans, and fixed vocabularies.
fn plain<T: ToString>(value: Option<T>) -> String {
    value.map(|v| v.to_string()).unwrap_or_default()
}

/// A `YYYY-MM-DD` date cell (empty when unknown).
fn ymd(date: Option<DateTime<Utc>>) -> String {
    plain(date.map(|d| d.format("%Y-%m-%d")))
}

fn status_cells(data: &BulkResultData) -> Option<Vec<String>> {
    let BulkResultData::Status(s) = data else {
        return None;
    };
    let cert = s.certificate.as_ref();
    let expiry = s.domain_expiration.as_ref();
    let dns = s.dns_resolution.as_ref();
    Some(vec![
        plain(s.http_status),
        text(s.http_status_text.as_deref()),
        text(s.title.as_deref()),
        text(cert.map(|c| c.issuer.as_str())),
        ymd(cert.map(|c| c.valid_until)),
        plain(cert.map(|c| c.days_until_expiry)),
        ymd(expiry.map(|d| d.expiration_date)),
        plain(expiry.map(|d| d.days_until_expiry)),
        text(expiry.and_then(|d| d.registrar.as_deref())),
        plain(dns.map(|d| d.resolves)),
        text(dns.map(|d| d.a_records.join(";")).as_deref()),
        text(dns.map(|d| d.aaaa_records.join(";")).as_deref()),
        text(dns.and_then(|d| d.cname_target.as_deref())),
        text(dns.map(|d| d.nameservers.join(";")).as_deref()),
    ])
}

/// `registrar,created,expires,updated` + trailing `availability_verdict`,
/// from a smart lookup (whichever source answered) or a direct WHOIS/RDAP
/// query.
fn registration_cells(data: &BulkResultData) -> Option<Vec<String>> {
    use seer_core::LookupResult;
    let (registrar, dates, verdict) = match data {
        BulkResultData::Lookup(LookupResult::Rdap { data: r, .. }) | BulkResultData::Rdap(r) => (
            r.get_registrar(),
            [r.creation_date(), r.expiration_date(), r.last_updated()],
            "",
        ),
        BulkResultData::Lookup(LookupResult::Whois { data: w, .. }) | BulkResultData::Whois(w) => (
            w.registrar.clone(),
            [w.creation_date, w.expiration_date, w.updated_date],
            "",
        ),
        BulkResultData::Lookup(LookupResult::Available { data, .. }) => {
            (None, [None; 3], data.verdict())
        }
        _ => return None,
    };
    let mut cells = vec![text(registrar.as_deref())];
    cells.extend(dates.map(ymd));
    cells.push(escape_csv_field(verdict));
    Some(cells)
}

fn dns_cells(data: &BulkResultData) -> Option<Vec<String>> {
    let BulkResultData::Dns(records) = data else {
        return None;
    };
    let values: Vec<String> = records
        .iter()
        .map(seer_core::DnsRecord::format_short)
        .collect();
    Some(vec![
        plain(records.first().map(|r| r.record_type)),
        escape_csv_field(&values.join("; ")),
    ])
}

fn propagation_cells(data: &BulkResultData) -> Option<Vec<String>> {
    let BulkResultData::Propagation(p) = data else {
        return None;
    };
    // Core's figure verbatim: the share of ALL servers agreeing with the
    // consensus (what human/markdown show), not the response rate.
    Some(vec![
        format!("{:.1}", p.propagation_percentage),
        p.servers_checked.to_string(),
        p.servers_responding.to_string(),
    ])
}

fn avail_cells(data: &BulkResultData) -> Option<Vec<String>> {
    let BulkResultData::Avail(a) = data else {
        return None;
    };
    Some(vec![
        a.available.to_string(),
        a.confidence.clone(),
        a.method.clone(),
        text(a.details.as_deref()),
    ])
}

fn info_cells(data: &BulkResultData) -> Option<Vec<String>> {
    let BulkResultData::Info(info) = data else {
        return None;
    };
    Some(vec![
        info.source.to_string(), // Display matches the lowercase JSON form
        text(info.registrar.as_deref()),
        text(info.registrant.as_deref()),
        text(info.organization.as_deref()),
        ymd(info.creation_date),
        ymd(info.expiration_date),
        ymd(info.updated_date),
        escape_csv_field(&info.nameservers.join(";")),
        escape_csv_field(&info.status.join(";")),
        text(info.dnssec.as_deref()),
        text(info.registrant_email.as_deref()),
        text(info.registrant_phone.as_deref()),
        text(info.registrant_address.as_deref()),
        text(info.registrant_country.as_deref()),
        text(info.admin_name.as_deref()),
        text(info.admin_organization.as_deref()),
        text(info.admin_email.as_deref()),
        text(info.admin_phone.as_deref()),
        text(info.tech_name.as_deref()),
        text(info.tech_organization.as_deref()),
        text(info.tech_email.as_deref()),
        text(info.tech_phone.as_deref()),
        text(info.whois_server.as_deref()),
        text(info.rdap_url.as_deref()),
        text(info.registrar_abuse_email.as_deref()),
        text(info.registrar_abuse_phone.as_deref()),
        text(info.registrar_iana_id.as_deref()),
        text(info.registrar_url.as_deref()),
        plain(info.days_until_expiration),
        plain(info.domain_age_days),
        plain(info.expiry_status),
        text(info.availability_verdict.as_deref()),
    ])
}

fn ssl_cells(data: &BulkResultData) -> Option<Vec<String>> {
    let BulkResultData::Ssl(r) = data else {
        return None;
    };
    let leaf = r.chain.first();
    Some(vec![
        text(leaf.map(|c| c.subject.as_str())),
        text(leaf.map(|c| c.issuer.as_str())),
        ymd(leaf.map(|c| c.valid_from)),
        ymd(leaf.map(|c| c.valid_until)),
        r.days_until_expiry.to_string(),
        text(leaf.and_then(|c| c.signature_algorithm.as_deref())),
        text(leaf.and_then(|c| c.key_type.as_deref())),
        plain(leaf.and_then(|c| c.key_bits)),
        r.chain.len().to_string(),
        r.san_names.len().to_string(),
        escape_csv_field(&join_sans(&r.san_names)),
        text(r.protocol_version.as_deref()),
        r.is_valid.to_string(),
    ])
}

fn posture_cells(data: &BulkResultData) -> Option<Vec<String>> {
    let BulkResultData::Posture(p) = data else {
        return None;
    };
    let verdict = |v: seer_core::PostureVerdict| v.as_str().to_string();
    Some(vec![
        verdict(p.spf.verdict),
        text(p.spf.all_qualifier.as_deref()),
        verdict(p.dmarc.verdict),
        text(p.dmarc.policy.as_deref()),
        verdict(p.mta_sts.verdict),
        verdict(p.bimi.verdict),
        verdict(p.dane.verdict),
        escape_csv_field(&p.notes.join(";")),
    ])
}

fn confusables_cells(data: &BulkResultData) -> Option<Vec<String>> {
    let BulkResultData::Confusables(r) = data else {
        return None;
    };
    let registered: Vec<String> = r
        .registered
        .iter()
        .map(|l| format!("{}({})", l.domain, l.technique))
        .collect();
    Some(vec![
        r.candidates_generated.to_string(),
        r.candidates_checked.to_string(),
        r.registered.len().to_string(),
        escape_csv_field(&registered.join(";")),
    ])
}

fn caa_cells(data: &BulkResultData) -> Option<Vec<String>> {
    let BulkResultData::Caa(p) = data else {
        return None;
    };
    let tag_values = |tag: &str| {
        let values: Vec<&str> = p
            .records
            .iter()
            .filter(|r| r.tag == tag)
            .map(|r| r.value.as_str())
            .collect();
        escape_csv_field(&values.join(";"))
    };
    Some(vec![
        p.has_policy.to_string(),
        text(p.effective_domain.as_deref()),
        tag_values("issue"),
        tag_values("issuewild"),
        escape_csv_field(&p.iodef.join(";")),
        text(p.wildcard_note.as_deref()),
    ])
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use seer_core::bulk::BulkOperation;
    use seer_core::ssl::{CertDetail, SslReport};
    use std::sync::atomic::{AtomicBool, Ordering};

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
        let home = std::env::home_dir().expect("home dir for test");
        assert_eq!(expand_tilde("~"), home.to_string_lossy());
    }

    #[test]
    fn expand_tilde_joins_relative_under_home() {
        let home = std::env::home_dir().expect("home dir for test");
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
            valid_from: Utc.with_ymd_and_hms(2024, 1, 30, 0, 0, 0).unwrap(),
            valid_until: Utc.with_ymd_and_hms(2025, 3, 1, 0, 0, 0).unwrap(),
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
    fn prop_csv_uses_core_consensus_percentage_not_response_rate() {
        // All 10 servers answered, but only 7 agreed with the consensus.
        // The CSV previously recomputed responded/total (→ 100.0) instead of
        // core's consensus-based figure (→ 70.0) that human/markdown show.
        let prop = seer_core::dns::PropagationResult {
            domain: "example.com".to_string(),
            record_type: seer_core::RecordType::A,
            servers_checked: 10,
            servers_responding: 10,
            propagation_percentage: 70.0,
            results: vec![],
            consensus_values: vec![],
            inconsistencies: vec![],
            unreachable_servers: vec![],
            dnssec_validated: false,
            nameserver_details: None,
        };
        let result = BulkResult {
            operation: BulkOperation::Propagation {
                domain: "example.com".to_string(),
                record_type: seer_core::RecordType::A,
            },
            success: true,
            data: Some(BulkResultData::Propagation(prop)),
            error: None,
            duration_ms: 42,
        };
        let csv = bulk_results_to_csv(std::slice::from_ref(&result), "prop");
        let mut lines = csv.lines();
        assert_eq!(
            lines.next().expect("header"),
            "domain,success,propagation_pct,servers_total,servers_responded,duration_ms,error"
        );
        assert_eq!(
            lines.next().expect("data row"),
            "example.com,true,70.0,10,10,42,"
        );
    }

    #[test]
    fn read_bulk_stdin_accepts_input_under_the_cap() {
        let got = read_bulk_stdin(std::io::Cursor::new(b"a.com\nb.com\n".to_vec()))
            .expect("small input is accepted");
        assert_eq!(got, "a.com\nb.com\n");
    }

    #[test]
    fn read_bulk_stdin_rejects_input_over_the_cap() {
        // `bulk -` previously read stdin unbounded while the file path was
        // capped at MAX_BULK_FILE_SIZE; both must enforce the same limit.
        let at_cap = vec![b'a'; MAX_BULK_FILE_SIZE as usize];
        assert!(read_bulk_stdin(std::io::Cursor::new(at_cap)).is_ok());

        let over_cap = vec![b'a'; MAX_BULK_FILE_SIZE as usize + 1];
        let err = read_bulk_stdin(std::io::Cursor::new(over_cap)).expect_err("must reject");
        assert!(err.contains("byte limit"), "got: {err}");
    }

    #[test]
    fn follow_key_listener_is_not_started_without_raw_mode() {
        // With no usable terminal the listener must not run at all: crossterm
        // polling then errors immediately, which previously spun a core.
        let (tx, _rx) = tokio::sync::watch::channel(false);
        assert!(FollowKeyListener::spawn(tx, false).is_none());
    }

    #[test]
    fn follow_cancel_keys_are_esc_and_ctrl_c_only() {
        use crossterm::event::{KeyCode, KeyModifiers};
        assert!(is_follow_cancel_key(KeyCode::Esc, KeyModifiers::NONE));
        assert!(is_follow_cancel_key(
            KeyCode::Char('c'),
            KeyModifiers::CONTROL
        ));
        assert!(!is_follow_cancel_key(
            KeyCode::Char('c'),
            KeyModifiers::NONE
        ));
        assert!(!is_follow_cancel_key(KeyCode::Enter, KeyModifiers::NONE));
    }

    #[test]
    fn follow_key_loop_exits_on_poll_error_without_cancelling() {
        // No TTY: `event::poll` errors. The loop must stop instead of
        // spinning, and must not cancel the follow on the user's behalf.
        let (tx, rx) = tokio::sync::watch::channel(false);
        let stop = AtomicBool::new(false);
        let mut polls = 0;
        run_follow_key_loop(
            || {
                polls += 1;
                Err(std::io::Error::other("not a tty"))
            },
            &stop,
            &tx,
        );
        assert_eq!(polls, 1, "must stop after the first poll error");
        assert!(!*rx.borrow());
    }

    #[test]
    fn follow_key_loop_cancels_on_esc() {
        use crossterm::event::{KeyCode, KeyModifiers};
        let (tx, rx) = tokio::sync::watch::channel(false);
        let stop = AtomicBool::new(false);
        let mut keys = vec![
            Ok(Some((KeyCode::Esc, KeyModifiers::NONE))),
            Ok(Some((KeyCode::Char('x'), KeyModifiers::NONE))),
            Ok(None),
        ];
        run_follow_key_loop(|| keys.pop().expect("loop ends at Esc"), &stop, &tx);
        assert!(*rx.borrow(), "Esc must cancel the follow");
    }

    #[test]
    fn follow_key_loop_honors_stop_flag() {
        // The follow finished: the stop flag must end the loop even though no
        // key was ever pressed (the old tokio task could not be stopped).
        let (tx, rx) = tokio::sync::watch::channel(false);
        let stop = AtomicBool::new(false);
        let mut polls = 0;
        run_follow_key_loop(
            || {
                polls += 1;
                if polls == 3 {
                    stop.store(true, Ordering::Relaxed);
                }
                Ok(None)
            },
            &stop,
            &tx,
        );
        assert_eq!(polls, 3);
        assert!(!*rx.borrow());
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
                data: Some(BulkResultData::Info(info)),
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

    /// Byte-exact CSV goldens for every bulk operation (populated + failure rows),
    /// so any change to `bulk_results_to_csv` that moves a column, drops an
    /// escape, or adds one to a numeric cell fails loudly.
    mod csv_golden {
        use crate::utils::bulk_results_to_csv;
        use chrono::TimeZone;
        use seer_core::bulk::{BulkOperation, BulkResult, BulkResultData};
        use seer_core::dns::{RecordData, RecordType};

        fn date(y: i32, m: u32, d: u32) -> chrono::DateTime<chrono::Utc> {
            chrono::Utc.with_ymd_and_hms(y, m, d, 0, 0, 0).unwrap()
        }

        fn ok(operation: BulkOperation, data: BulkResultData) -> BulkResult {
            BulkResult {
                operation,
                success: true,
                data: Some(data),
                error: None,
                duration_ms: 42,
            }
        }

        fn failed(operation: BulkOperation) -> BulkResult {
            BulkResult {
                operation,
                success: false,
                data: None,
                error: Some("timed out, giving up".to_string()),
                duration_ms: 7,
            }
        }

        fn whois() -> seer_core::WhoisResponse {
            seer_core::WhoisResponse::parse(
                "example.com",
                "whois.test",
                "Registrar: Example Registrar, LLC\n\
             Creation Date: 1995-08-14T04:00:00Z\n\
             Registry Expiry Date: 2025-08-13T04:00:00Z\n\
             Updated Date: 2024-08-14T07:01:34Z\n",
            )
        }

        fn rdap() -> seer_core::RdapResponse {
            serde_json::from_value(serde_json::json!({
                "ldhName": "example.com",
                "events": [
                    {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
                    {"eventAction": "expiration", "eventDate": "2025-08-13T04:00:00Z"},
                    {"eventAction": "last changed", "eventDate": "2024-08-14T07:01:34Z"}
                ],
                "entities": [{
                    "objectClassName": "entity",
                    "handle": "376",
                    "roles": ["registrar"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "=Formula Registrar"]]]
                }]
            }))
            .unwrap()
        }

        fn avail() -> seer_core::AvailabilityResult {
            seer_core::AvailabilityResult {
                domain: "free.example".to_string(),
                available: true,
                confidence: "high".to_string(),
                method: "rdap".to_string(),
                details: Some("No RDAP object, domain unregistered".to_string()),
            }
        }

        fn csv(op: &str, results: &[BulkResult]) -> String {
            bulk_results_to_csv(results, op)
        }

        #[test]
        fn status_golden() {
            let status = seer_core::StatusResponse {
                domain: "example.com".to_string(),
                http_status: Some(200),
                http_status_text: Some("OK".to_string()),
                title: Some("Example, Inc.".to_string()),
                certificate: Some(seer_core::status::CertificateInfo {
                    issuer: "DigiCert Inc".to_string(),
                    subject: "example.com".to_string(),
                    valid_from: date(2024, 1, 30),
                    valid_until: date(2025, 3, 1),
                    // Negative: numeric cells are never formula-guarded.
                    days_until_expiry: -3,
                    is_valid: false,
                    hostname_verified: true,
                }),
                domain_expiration: Some(seer_core::status::DomainExpiration {
                    expiration_date: date(2025, 8, 13),
                    days_until_expiry: 204,
                    registrar: Some("RESERVED-IANA".to_string()),
                }),
                dns_resolution: Some(seer_core::status::DnsResolution {
                    a_records: vec!["93.184.216.34".to_string()],
                    aaaa_records: vec!["2606:2800::1".to_string(), "2606:2800::2".to_string()],
                    cname_target: None,
                    nameservers: vec!["a.iana-servers.net".to_string()],
                    resolves: true,
                }),
                caa: None,
                errors: vec![],
            };
            let results = [
                ok(
                    BulkOperation::Status {
                        domain: "example.com".into(),
                    },
                    BulkResultData::Status(status),
                ),
                failed(BulkOperation::Status {
                    domain: "bad.invalid".into(),
                }),
            ];
            assert_eq!(
                csv("status", &results),
                concat!(
                    "domain,success,http_status,http_status_text,title,ssl_issuer,ssl_valid_until,ssl_days_remaining,domain_expires,domain_days_remaining,registrar,dns_resolves,dns_a_records,dns_aaaa_records,dns_cname,dns_nameservers,duration_ms,error\n",
                    "example.com,true,200,OK,\"Example, Inc.\",DigiCert Inc,2025-03-01,-3,2025-08-13,204,RESERVED-IANA,true,93.184.216.34,2606:2800::1;2606:2800::2,,a.iana-servers.net,42,\n",
                    "bad.invalid,false,,,,,,,,,,,,,,,7,\"timed out, giving up\"\n",
                )
            );
        }

        fn lookup_results() -> Vec<BulkResult> {
            let op = |d: &str| BulkOperation::Lookup { domain: d.into() };
            vec![
                ok(
                    op("rdap.example"),
                    BulkResultData::Lookup(seer_core::LookupResult::Rdap {
                        data: Box::new(rdap()),
                        whois_fallback: None,
                    }),
                ),
                ok(
                    op("whois.example"),
                    BulkResultData::Lookup(seer_core::LookupResult::Whois {
                        data: whois(),
                        rdap_error: None,
                        rdap_fallback: None,
                    }),
                ),
                ok(
                    op("free.example"),
                    BulkResultData::Lookup(seer_core::LookupResult::Available {
                        data: Box::new(avail()),
                        rdap_error: "404".to_string(),
                        whois_error: "no match".to_string(),
                        whois_data: None,
                    }),
                ),
                failed(op("bad.invalid")),
            ]
        }

        #[test]
        fn lookup_golden() {
            assert_eq!(
                csv("lookup", &lookup_results()),
                concat!(
                    "domain,success,registrar,created,expires,updated,duration_ms,availability_verdict,error\n",
                    "rdap.example,true,'=Formula Registrar,1995-08-14,2025-08-13,2024-08-14,42,,\n",
                    "whois.example,true,\"Example Registrar, LLC\",1995-08-14,2025-08-13,2024-08-14,42,,\n",
                    "free.example,true,,,,,42,available,\n",
                    "bad.invalid,false,,,,,7,,\"timed out, giving up\"\n",
                )
            );
        }

        #[test]
        fn whois_and_rdap_golden() {
            let whois_results = [
                ok(
                    BulkOperation::Whois {
                        domain: "example.com".into(),
                    },
                    BulkResultData::Whois(whois()),
                ),
                failed(BulkOperation::Whois {
                    domain: "bad.invalid".into(),
                }),
            ];
            assert_eq!(
                csv("whois", &whois_results),
                concat!(
                    "domain,success,registrar,created,expires,updated,duration_ms,availability_verdict,error\n",
                    "example.com,true,\"Example Registrar, LLC\",1995-08-14,2025-08-13,2024-08-14,42,,\n",
                    "bad.invalid,false,,,,,7,,\"timed out, giving up\"\n",
                )
            );
            let rdap_results = [
                ok(
                    BulkOperation::Rdap {
                        domain: "example.com".into(),
                    },
                    BulkResultData::Rdap(Box::new(rdap())),
                ),
                failed(BulkOperation::Rdap {
                    domain: "bad.invalid".into(),
                }),
            ];
            assert_eq!(
                csv("rdap", &rdap_results),
                concat!(
                    "domain,success,registrar,created,expires,updated,duration_ms,availability_verdict,error\n",
                    "example.com,true,'=Formula Registrar,1995-08-14,2025-08-13,2024-08-14,42,,\n",
                    "bad.invalid,false,,,,,7,,\"timed out, giving up\"\n",
                )
            );
        }

        #[test]
        fn dig_golden_including_alias() {
            let op = |d: &str| BulkOperation::Dns {
                domain: d.to_string(),
                record_type: RecordType::MX,
            };
            let record = |preference, exchange: &str| seer_core::DnsRecord {
                name: "example.com".to_string(),
                record_type: RecordType::MX,
                ttl: 300,
                data: RecordData::MX {
                    preference,
                    exchange: exchange.to_string(),
                },
            };
            let results = [
                ok(
                    op("example.com"),
                    BulkResultData::Dns(vec![
                        record(10, "mail.example.com."),
                        record(20, "backup.example.com."),
                    ]),
                ),
                ok(op("empty.example"), BulkResultData::Dns(vec![])),
                failed(op("bad.invalid")),
            ];
            let expected = concat!(
                "domain,success,record_type,records,duration_ms,error\n",
                "example.com,true,MX,10 mail.example.com.; 20 backup.example.com.,42,\n",
                "empty.example,true,,,42,\n",
                "bad.invalid,false,,,7,\"timed out, giving up\"\n"
            );
            assert_eq!(csv("dig", &results), expected);
            assert_eq!(csv("dns", &results), expected);
        }

        #[test]
        fn avail_golden() {
            let results = [
                ok(
                    BulkOperation::Avail {
                        domain: "free.example".into(),
                    },
                    BulkResultData::Avail(avail()),
                ),
                failed(BulkOperation::Avail {
                    domain: "bad.invalid".into(),
                }),
            ];
            assert_eq!(
                csv("avail", &results),
                concat!(
                    "domain,success,available,confidence,method,details,duration_ms,error\n",
                    "free.example,true,true,high,rdap,\"No RDAP object, domain unregistered\",42,\n",
                    "bad.invalid,false,,,,,7,\"timed out, giving up\"\n",
                )
            );
        }

        #[test]
        fn prop_golden_including_alias() {
            let op = |d: &str| BulkOperation::Propagation {
                domain: d.to_string(),
                record_type: RecordType::A,
            };
            let prop = seer_core::dns::PropagationResult {
                domain: "example.com".to_string(),
                record_type: RecordType::A,
                servers_checked: 30,
                servers_responding: 29,
                propagation_percentage: 96.666,
                results: vec![],
                consensus_values: vec![],
                inconsistencies: vec![],
                unreachable_servers: vec![],
                dnssec_validated: false,
                nameserver_details: None,
            };
            let results = [
                ok(op("example.com"), BulkResultData::Propagation(prop)),
                failed(op("bad.invalid")),
            ];
            let expected = concat!(
                "domain,success,propagation_pct,servers_total,servers_responded,duration_ms,error\n",
                "example.com,true,96.7,30,29,42,\n",
                "bad.invalid,false,,,,7,\"timed out, giving up\"\n",
            );
            assert_eq!(csv("prop", &results), expected);
            assert_eq!(csv("propagation", &results), expected);
        }

        #[test]
        fn info_golden() {
            let mut info = seer_core::domain_info::DomainInfo::from_sources(
                "example.com",
                Some(&rdap()),
                Some(&whois()),
            );
            info.availability_verdict = Some("registered".to_string());
            info.registrant_phone = Some("+1.5555550100".to_string());
            // Pin the clock-derived lifecycle fields so the golden is stable.
            info.days_until_expiration = Some(-405);
            info.domain_age_days = Some(11362);
            info.expiry_status = Some(seer_core::domain_info::ExpiryStatus::Expired);
            let results = [
                ok(
                    BulkOperation::Info {
                        domain: "example.com".into(),
                    },
                    BulkResultData::Info(info),
                ),
                failed(BulkOperation::Info {
                    domain: "bad.invalid".into(),
                }),
            ];
            assert_eq!(
                csv("info", &results),
                concat!(
                    "domain,success,source,registrar,registrant,organization,created,expires,updated,nameservers,status,dnssec,registrant_email,registrant_phone,registrant_address,registrant_country,admin_name,admin_organization,admin_email,admin_phone,tech_name,tech_organization,tech_email,tech_phone,whois_server,rdap_url,registrar_abuse_email,registrar_abuse_phone,registrar_iana_id,registrar_url,days_until_expiration,domain_age_days,expiry_status,availability_verdict,duration_ms,error\n",
                    "example.com,true,both,'=Formula Registrar,,,1995-08-14,2025-08-13,2024-08-14,,,,,'+1.5555550100,,,,,,,,,,,whois.test,,,,,,-405,11362,expired,registered,42,\n",
                    "bad.invalid,false,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,7,\"timed out, giving up\"\n",
                )
            );
        }

        #[test]
        fn ssl_posture_confusables_caa_golden() {
            let ssl = [
                ok(
                    BulkOperation::Ssl {
                        domain: "example.com".into(),
                    },
                    BulkResultData::Ssl(super::sample_report()),
                ),
                failed(BulkOperation::Ssl {
                    domain: "bad.invalid".into(),
                }),
            ];
            assert_eq!(
                csv("ssl", &ssl),
                concat!(
                    "domain,success,subject,issuer,valid_from,valid_until,days_remaining,signature_algorithm,key_type,key_bits,chain_length,san_count,sans,protocol_version,is_valid,duration_ms,error\n",
                    "example.com,true,CN=example.com,\"C=US, O=Test Org, CN=Test Root CA\",2024-01-30,2025-03-01,89,sha256WithRSAEncryption,RSA,2048,2,2,example.com;www.example.com,TLS 1.3,true,42,\n",
                    "bad.invalid,false,,,,,,,,,,,,,,7,\"timed out, giving up\"\n",
                )
            );
            let posture = [
                ok(
                    BulkOperation::Posture {
                        domain: "example.com".into(),
                    },
                    BulkResultData::Posture(super::sample_posture()),
                ),
                failed(BulkOperation::Posture {
                    domain: "bad.invalid".into(),
                }),
            ];
            assert_eq!(
                csv("posture", &posture),
                concat!(
                    "domain,success,spf_verdict,spf_all_qualifier,dmarc_verdict,dmarc_policy,mta_sts_verdict,bimi_verdict,dane_verdict,notes,duration_ms,error\n",
                    "example.com,true,strict,'-,strict,reject,present,absent,absent,strong posture,42,\n",
                    "bad.invalid,false,,,,,,,,,7,\"timed out, giving up\"\n",
                )
            );
            let report = seer_core::ConfusableReport {
                domain: "example.com".to_string(),
                candidates_generated: 214,
                candidates_checked: 180,
                registered: vec![
                    seer_core::RegisteredLookalike {
                        domain: "examp1e.com".to_string(),
                        technique: "homoglyph".to_string(),
                        registrar: None,
                        creation_date: None,
                        nameservers: vec![],
                    },
                    seer_core::RegisteredLookalike {
                        domain: "exampel.com".to_string(),
                        technique: "transposition".to_string(),
                        registrar: None,
                        creation_date: None,
                        nameservers: vec![],
                    },
                ],
            };
            let confusables = [
                ok(
                    BulkOperation::Confusables {
                        domain: "example.com".into(),
                    },
                    BulkResultData::Confusables(report),
                ),
                failed(BulkOperation::Confusables {
                    domain: "bad.invalid".into(),
                }),
            ];
            assert_eq!(
                csv("confusables", &confusables),
                concat!(
                    "domain,success,candidates_generated,candidates_checked,registered_count,registered,duration_ms,error\n",
                    "example.com,true,214,180,2,examp1e.com(homoglyph);exampel.com(transposition),42,\n",
                    "bad.invalid,false,,,,,7,\"timed out, giving up\"\n",
                )
            );
            let caa_record = |tag: &str, value: &str| seer_core::CaaRecord {
                flags: 0,
                tag: tag.to_string(),
                value: value.to_string(),
            };
            let policy = seer_core::CaaPolicy {
                records: vec![
                    caa_record("issue", "letsencrypt.org"),
                    caa_record("issuewild", "digicert.com"),
                    caa_record("iodef", "mailto:security@example.com"),
                ],
                effective_domain: Some("example.com".to_string()),
                has_policy: true,
                issuer_match: None,
                iodef: vec!["mailto:security@example.com".to_string()],
                wildcard_note: Some("wildcards restricted, see issuewild".to_string()),
                note: "CAA restricts which CAs may issue".to_string(),
            };
            let caa = [
                ok(
                    BulkOperation::Caa {
                        domain: "example.com".into(),
                    },
                    BulkResultData::Caa(policy),
                ),
                failed(BulkOperation::Caa {
                    domain: "bad.invalid".into(),
                }),
            ];
            assert_eq!(
                csv("caa", &caa),
                concat!(
                    "domain,success,has_policy,effective_domain,issue,issuewild,iodef,wildcard_note,duration_ms,error\n",
                    "example.com,true,true,example.com,letsencrypt.org,digicert.com,mailto:security@example.com,\"wildcards restricted, see issuewild\",42,\n",
                    "bad.invalid,false,,,,,,,7,\"timed out, giving up\"\n",
                )
            );
        }

        #[test]
        fn unknown_op_golden() {
            let results = [
                ok(
                    BulkOperation::Avail {
                        domain: "free.example".into(),
                    },
                    BulkResultData::Avail(avail()),
                ),
                failed(BulkOperation::Avail {
                    domain: "bad.invalid".into(),
                }),
            ];
            assert_eq!(
                csv("bogus", &results),
                concat!(
                    "domain,success,duration_ms,error\n",
                    "free.example,true,42,\n",
                    "bad.invalid,false,7,\"timed out, giving up\"\n"
                )
            );
        }
    }
}
