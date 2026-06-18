use std::collections::HashSet;

use chrono::{DateTime, FixedOffset, Utc};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Pre-compiled regexes for WHOIS field extraction.
static REGISTRAR_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Registrar:\s*(.+)").expect("Invalid regex for Registrar"),
        Regex::new(r"(?i)Registrar Name:\s*(.+)").expect("Invalid regex for Registrar Name"),
        Regex::new(r"(?i)Sponsoring Registrar:\s*(.+)")
            .expect("Invalid regex for Sponsoring Registrar"),
    ]
});

static REGISTRANT_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Registrant Name:\s*(.+)").expect("Invalid regex for Registrant Name"),
        Regex::new(r"(?i)Registrant:\s*(.+)").expect("Invalid regex for Registrant"),
    ]
});

static ORGANIZATION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Registrant Organization:\s*(.+)")
            .expect("Invalid regex for Registrant Organization"),
        Regex::new(r"(?i)Organization:\s*(.+)").expect("Invalid regex for Organization"),
        Regex::new(r"(?i)org-name:\s*(.+)").expect("Invalid regex for org-name"),
        Regex::new(r"(?i)Org Name:\s*(.+)").expect("Invalid regex for Org Name"),
    ]
});

static CREATION_DATE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Creation Date:\s*(.+)").expect("Invalid regex for Creation Date"),
        Regex::new(r"(?i)Created Date:\s*(.+)").expect("Invalid regex for Created Date"),
        Regex::new(r"(?i)Created On:\s*(.+)").expect("Invalid regex for Created On"),
        Regex::new(r"(?i)Created:\s*(.+)").expect("Invalid regex for Created"),
        Regex::new(r"(?i)Registration Date:\s*(.+)").expect("Invalid regex for Registration Date"),
        Regex::new(r"(?i)Domain Registration Date:\s*(.+)")
            .expect("Invalid regex for Domain Registration Date"),
    ]
});

static EXPIRATION_DATE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)(?:Registry )?Expir(?:y|ation) Date:\s*(.+)")
            .expect("Invalid regex for Expiry/Expiration Date"),
        Regex::new(r"(?i)Expiration Date:\s*(.+)").expect("Invalid regex for Expiration Date"),
        Regex::new(r"(?i)Expires On:\s*(.+)").expect("Invalid regex for Expires On"),
        Regex::new(r"(?i)Expires:\s*(.+)").expect("Invalid regex for Expires"),
        Regex::new(r"(?i)Expiry Date:\s*(.+)").expect("Invalid regex for Expiry Date"),
        Regex::new(r"(?i)paid-till:\s*(.+)").expect("Invalid regex for paid-till"),
    ]
});

static UPDATED_DATE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Updated Date:\s*(.+)").expect("Invalid regex for Updated Date"),
        Regex::new(r"(?i)Last Updated On:\s*(.+)").expect("Invalid regex for Last Updated On"),
        Regex::new(r"(?i)Last Modified:\s*(.+)").expect("Invalid regex for Last Modified"),
        Regex::new(r"(?i)Last Update:\s*(.+)").expect("Invalid regex for Last Update"),
        Regex::new(r"(?i)Modified:\s*(.+)").expect("Invalid regex for Modified"),
    ]
});

static DNSSEC_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)DNSSEC:\s*(.+)").expect("Invalid regex for DNSSEC"),
        Regex::new(r"(?i)DNSSEC Status:\s*(.+)").expect("Invalid regex for DNSSEC Status"),
    ]
});

static NAMESERVER_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Name Server:\s*(.+)").expect("Invalid regex for Name Server"),
        Regex::new(r"(?i)Nameserver:\s*(.+)").expect("Invalid regex for Nameserver"),
        Regex::new(r"(?i)nserver:\s*(.+)").expect("Invalid regex for nserver"),
        Regex::new(r"(?im)^NS:\s+(.+)$").expect("Invalid regex for NS"),
    ]
});

static REGISTRANT_EMAIL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Registrant Email:\s*(.+)").expect("Invalid regex for Registrant Email"),
        Regex::new(r"(?i)Registrant E-mail:\s*(.+)").expect("Invalid regex for Registrant E-mail"),
    ]
});

static REGISTRANT_PHONE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Registrant Phone:\s*(.+)").expect("Invalid regex for Registrant Phone"),
        Regex::new(r"(?i)Registrant Tel:\s*(.+)").expect("Invalid regex for Registrant Tel"),
    ]
});

static REGISTRANT_ADDRESS_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Registrant Street:\s*(.+)").expect("Invalid regex for Registrant Street"),
        Regex::new(r"(?i)Registrant Address:\s*(.+)")
            .expect("Invalid regex for Registrant Address"),
    ]
});

static REGISTRANT_COUNTRY_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![Regex::new(r"(?i)Registrant Country:\s*(.+)")
        .expect("Invalid regex for Registrant Country")]
});

static ADMIN_NAME_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Admin Name:\s*(.+)").expect("Invalid regex for Admin Name"),
        Regex::new(r"(?i)Administrative Contact Name:\s*(.+)")
            .expect("Invalid regex for Administrative Contact Name"),
    ]
});

static ADMIN_ORG_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![Regex::new(r"(?i)Admin Organization:\s*(.+)")
        .expect("Invalid regex for Admin Organization")]
});

static ADMIN_EMAIL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Admin Email:\s*(.+)").expect("Invalid regex for Admin Email"),
        Regex::new(r"(?i)Admin E-mail:\s*(.+)").expect("Invalid regex for Admin E-mail"),
    ]
});

static ADMIN_PHONE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Admin Phone:\s*(.+)").expect("Invalid regex for Admin Phone"),
        Regex::new(r"(?i)Admin Tel:\s*(.+)").expect("Invalid regex for Admin Tel"),
    ]
});

static TECH_NAME_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Tech Name:\s*(.+)").expect("Invalid regex for Tech Name"),
        Regex::new(r"(?i)Technical Contact Name:\s*(.+)")
            .expect("Invalid regex for Technical Contact Name"),
    ]
});

static TECH_ORG_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![Regex::new(r"(?i)Tech Organization:\s*(.+)").expect("Invalid regex for Tech Organization")]
});

static TECH_EMAIL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Tech Email:\s*(.+)").expect("Invalid regex for Tech Email"),
        Regex::new(r"(?i)Tech E-mail:\s*(.+)").expect("Invalid regex for Tech E-mail"),
    ]
});

static TECH_PHONE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Tech Phone:\s*(.+)").expect("Invalid regex for Tech Phone"),
        Regex::new(r"(?i)Tech Tel:\s*(.+)").expect("Invalid regex for Tech Tel"),
    ]
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisResponse {
    pub domain: String,
    pub registrar: Option<String>,
    pub registrant: Option<String>,
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registrant_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registrant_phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registrant_address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registrant_country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tech_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tech_organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tech_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tech_phone: Option<String>,
    pub creation_date: Option<DateTime<Utc>>,
    pub expiration_date: Option<DateTime<Utc>>,
    pub updated_date: Option<DateTime<Utc>>,
    pub nameservers: Vec<String>,
    pub status: Vec<String>,
    pub dnssec: Option<String>,
    pub whois_server: String,
    // Suppressed from default serialization: the raw response is up to 1 MB of
    // attacker-controlled content from third-party registries/registrars. It
    // leaking into API/MCP JSON output creates a prompt-injection vector for
    // downstream LLM consumers. The field is still populated internally for
    // is_available() / indicates_not_found() scanning and for callers that
    // access it directly via struct field.
    #[serde(skip_serializing)]
    pub raw_response: String,
}

impl WhoisResponse {
    /// Parses a WHOIS response using the parser registry.
    ///
    /// This method delegates to specialized parsers for known TLDs
    /// and falls back to the generic parser otherwise.
    pub fn parse(domain: &str, whois_server: &str, raw: &str) -> Self {
        super::parsers::PARSER_REGISTRY.parse(domain, whois_server, raw)
    }

    /// Internal parsing using the generic regex-based approach.
    ///
    /// This is called by the GenericParser and can be overridden
    /// by specialized parsers for specific TLDs.
    pub fn parse_internal(domain: &str, whois_server: &str, raw: &str) -> Self {
        let registrar = extract_field_with_patterns(raw, &REGISTRAR_PATTERNS);
        let registrant = extract_field_with_patterns(raw, &REGISTRANT_PATTERNS);
        let organization = extract_field_with_patterns(raw, &ORGANIZATION_PATTERNS);
        let registrant_email = extract_field_with_patterns(raw, &REGISTRANT_EMAIL_PATTERNS);
        let registrant_phone = extract_field_with_patterns(raw, &REGISTRANT_PHONE_PATTERNS);
        let registrant_address = extract_field_with_patterns(raw, &REGISTRANT_ADDRESS_PATTERNS);
        let registrant_country = extract_field_with_patterns(raw, &REGISTRANT_COUNTRY_PATTERNS);
        let admin_name = extract_field_with_patterns(raw, &ADMIN_NAME_PATTERNS);
        let admin_organization = extract_field_with_patterns(raw, &ADMIN_ORG_PATTERNS);
        let admin_email = extract_field_with_patterns(raw, &ADMIN_EMAIL_PATTERNS);
        let admin_phone = extract_field_with_patterns(raw, &ADMIN_PHONE_PATTERNS);
        let tech_name = extract_field_with_patterns(raw, &TECH_NAME_PATTERNS);
        let tech_organization = extract_field_with_patterns(raw, &TECH_ORG_PATTERNS);
        let tech_email = extract_field_with_patterns(raw, &TECH_EMAIL_PATTERNS);
        let tech_phone = extract_field_with_patterns(raw, &TECH_PHONE_PATTERNS);
        let creation_date = extract_date_with_patterns(raw, &CREATION_DATE_PATTERNS);
        let expiration_date = extract_date_with_patterns(raw, &EXPIRATION_DATE_PATTERNS);
        let updated_date = extract_date_with_patterns(raw, &UPDATED_DATE_PATTERNS);
        let nameservers = extract_nameservers(raw);
        let status = extract_status_top_level(raw);
        let dnssec = extract_field_with_patterns(raw, &DNSSEC_PATTERNS);

        WhoisResponse {
            domain: domain.to_string(),
            registrar,
            registrant,
            organization,
            registrant_email,
            registrant_phone,
            registrant_address,
            registrant_country,
            admin_name,
            admin_organization,
            admin_email,
            admin_phone,
            tech_name,
            tech_organization,
            tech_email,
            tech_phone,
            creation_date,
            expiration_date,
            updated_date,
            nameservers,
            status,
            dnssec,
            whois_server: whois_server.to_string(),
            raw_response: raw.to_string(),
        }
    }

    /// Returns true if the response contains the core registration fields
    /// that registries typically provide (registrar, dates, nameservers).
    /// When true, following the registrar referral can be skipped since the
    /// additional detail (contact info) is usually GDPR-redacted anyway.
    ///
    /// Some registries (NIC.LV, SIDN/.nl) intentionally omit creation/expiry
    /// from their WHOIS, so accept a non-empty `status` field as an
    /// alternative registry signal alongside registrar + nameservers — this
    /// avoids a wasted referral attempt on every lookup for those TLDs.
    pub fn has_core_data(&self) -> bool {
        let has_dates_or_status = self.creation_date.is_some()
            || self.expiration_date.is_some()
            || !self.status.is_empty();
        self.registrar.is_some() && has_dates_or_status && !self.nameservers.is_empty()
    }

    /// Returns true when the registry's WHOIS server replied with a
    /// service-level "this TLD is not served here" / malformed-query sentinel
    /// instead of domain data — i.e. there is no usable port-43 WHOIS for this
    /// query. This is common for Identity Digital RDAP-only TLDs (.email,
    /// .life, .ninja, …) whose `whois.nic.<tld>` host answers "TLD is not
    /// supported." to every query and whose RDAP advertises `port43: null`.
    ///
    /// Distinct from [`is_available`](Self::is_available) (the domain is
    /// unregistered) and from a thin-but-valid record: it only fires when no
    /// registration field was extracted AND the body matches a known
    /// service-error sentinel at the start of a line.
    pub fn registry_unavailable(&self) -> bool {
        // Only meaningful when we extracted no registration data at all — a
        // record with a registrar / dates / nameservers / status is real data,
        // never a service error.
        if self.registrar.is_some()
            || self.creation_date.is_some()
            || self.expiration_date.is_some()
            || !self.nameservers.is_empty()
            || !self.status.is_empty()
        {
            return false;
        }
        // Match known service-error sentinels at the start of a (trimmed) line,
        // mirroring `indicates_not_found`'s anchoring to avoid false positives
        // from TOS boilerplate that may quote these phrases.
        const SERVICE_ERROR_SENTINELS: &[&str] = &[
            "tld is not supported",
            "this tld is not",
            "malformed request",
            "invalid query",
            "no whois server is known",
            "this server does not",
        ];
        let lower = self.raw_response.to_lowercase();
        lower.lines().any(|line| {
            let t = line.trim_start();
            SERVICE_ERROR_SENTINELS.iter().any(|s| t.starts_with(s))
        })
    }

    pub fn is_available(&self) -> bool {
        // A response carrying concrete registration data is registered, full
        // stop — never let an unanchored substring match (a "not found" /
        // "object not found" fragment buried in an abuse-contact line, notice,
        // or registrant value) flip a registered domain to "available". This
        // guards the H6 false-positive class without having to anchor every
        // pattern (which would regress legitimate mid-line phrasings like
        // TWNIC "Domain not found." or HKIRC "...has not been registered.").
        if self.registrar.is_some()
            || self.creation_date.is_some()
            || self.expiration_date.is_some()
            || !self.nameservers.is_empty()
        {
            return false;
        }

        // Scan the full response (excluding empty lines and comment lines). Some
        // registries (TWNIC, JPRS, NIC.br) prepend 3-4 notice lines before the
        // "no match" line, which would escape a small take(N) window.
        //
        // Stream the scan line-by-line — avoids the ~1 MB `Vec<&str>` +
        // ~1 MB joined `String` the previous implementation allocated for
        // every call. Each line's lowercase form is a fresh small `String`
        // (the size of one line, not the whole body) which is dropped at
        // the end of the iteration.
        for line in self.raw_response.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
                continue;
            }
            // Normalize internal whitespace (tabs, runs of spaces) to single
            // spaces before matching. Registries like DNS Belgium print
            // "Status:\tAVAILABLE" with a tab, which would otherwise slip
            // past space-delimited patterns such as "status: available".
            let lower = trimmed.to_lowercase();
            let words: Vec<&str> = lower.split_whitespace().collect();
            // Availability indicators are short status lines — the longest
            // known registry phrasing ("No information was found matching
            // that query.") is 7 words. Anything longer is prose (a TOS or
            // notice footer) that may merely quote a phrase like "not found"
            // or "does not exist"; skipping it avoids flipping a registered
            // (but thin, fieldless) response to "available". The H6 guard
            // above already covers responses that DO carry registration data.
            if words.len() > MAX_STATUS_LINE_WORDS {
                continue;
            }
            let normalized = words.join(" ");
            if AVAILABILITY_PATTERNS.iter().any(|p| normalized.contains(p)) {
                return true;
            }
        }
        false
    }

    /// Checks if the response indicates the registrar doesn't have data for this domain.
    /// This is different from is_available() - the domain may exist at the registry level
    /// but the referral registrar may not have data for it.
    ///
    /// Matches patterns only at the start of a (trimmed) line to avoid false
    /// positives from TOS footer boilerplate that may quote these phrases.
    pub fn indicates_not_found(&self) -> bool {
        let lower = self.raw_response.to_lowercase();
        lower.lines().any(|line| {
            let t = line.trim_start();
            NOT_FOUND_PATTERNS.iter().any(|p| t.starts_with(p))
        })
    }
}

/// Maximum word count for a line to be considered an availability *status*
/// line rather than prose. Registry "not found" phrasings are short (the
/// longest observed is 7 words); TOS/notice footers that merely quote such
/// phrases run much longer. Lines above this bound are ignored by
/// `is_available()` so footer prose can't flip a thin response to available.
const MAX_STATUS_LINE_WORDS: usize = 10;

/// Patterns indicating a domain is available (unregistered).
/// Matched case-insensitively via `contains()` on short status lines only
/// (see `MAX_STATUS_LINE_WORDS`).
const AVAILABILITY_PATTERNS: &[&str] = &[
    "no match for",
    "no match",
    "not found",
    "no data found",
    "no entries found",
    "domain not found",
    "available for registration",
    "not registered",
    // HKIRC (.hk / .香港) phrases it "has not been registered" — the bare
    // "not registered" above does not cover the interposed "been".
    "not been registered",
    "status: available",
    "status: free",
    "no object found",
    "does not exist",
    // Additional registry phrasings surfaced by a cross-TLD audit, mostly
    // no-RDAP ccTLDs where WHOIS is the only registry signal. All are unique
    // to "not found" responses (verified not to collide with registered or
    // "not available" bodies).
    "nothing found",   // KazNIC .kz / .қаз ("*** Nothing found for this query.")
    "no found",        // TWNIC .tw / 台灣 / 台湾 ("No Found")
    "no record found", // .ls and others ("No record found for '...'.")
    "no information was found", // .africa ("No information was found matching that query.")
    "object not found", // generic ("Object not found")
    "not find matchingrecord", // CONAC .政务 / .公益 ("Not find MatchingRecord")
];

/// Patterns indicating the registrar didn't have data for this domain.
/// Matched at the start of a trimmed line (not inside TOS footers).
const NOT_FOUND_PATTERNS: &[&str] = &[
    "no match for",
    "domain not found",
    "no data found",
    "queried object does not exist",
    "object does not exist",
    "not found:",
    "status: free",
    "domain is not registered",
];

fn extract_field_with_patterns(text: &str, patterns: &[Regex]) -> Option<String> {
    for re in patterns {
        if let Some(caps) = re.captures(text) {
            if let Some(m) = caps.get(1) {
                let value = m.as_str().trim();
                if value.is_empty() {
                    continue;
                }
                let lower = value.to_lowercase();

                // Filter out redacted/privacy-protected values
                let is_redacted = lower.contains("redacted")
                    || lower.contains("data protected")
                    || lower.contains("privacy")
                    || lower.contains("not disclosed")
                    || lower.contains("withheld")
                    || lower == "n/a"
                    || lower == "none";

                if !is_redacted {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

fn extract_date_with_patterns(text: &str, patterns: &[Regex]) -> Option<DateTime<Utc>> {
    let date_str = extract_field_with_patterns(text, patterns)?;
    parse_date(&date_str)
}

/// Parse a date string from registry output into a UTC datetime, tolerating
/// the ~20 formats registries emit in practice. Shared with the RDAP parser
/// (RDAP's `eventDate` is nominally strict RFC 3339, but real servers are as
/// sloppy as WHOIS, so both reuse this tolerant parser).
pub(crate) fn parse_date(date_str: &str) -> Option<DateTime<Utc>> {
    let cleaned = date_str
        .trim()
        .replace(" UTC", "Z")
        .replace(" (UTC)", "")
        .replace(" +0000", "Z");

    // First: try RFC 3339, which handles any timezone offset (e.g., +05:30, +01:00, Z)
    if let Ok(dt) = DateTime::parse_from_rfc3339(&cleaned) {
        return Some(dt.with_timezone(&Utc));
    }

    // Second: try ISO 8601 with timezone offset (e.g., 2024-01-15T10:30:00+05:30)
    if let Ok(dt) = DateTime::<FixedOffset>::parse_from_str(&cleaned, "%Y-%m-%dT%H:%M:%S%z") {
        return Some(dt.with_timezone(&Utc));
    }

    // Third: try space-separated datetime with timezone offset (e.g., 2024-01-15 10:30:00+05:30)
    if let Ok(dt) = DateTime::<FixedOffset>::parse_from_str(&cleaned, "%Y-%m-%d %H:%M:%S%z") {
        return Some(dt.with_timezone(&Utc));
    }

    // Fourth: try NaiveDateTime / NaiveDate formats (timezone-less dates)
    let naive_formats = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%.fZ",
        "%Y-%m-%d %H:%M:%S",
        "%d-%b-%Y %H:%M:%S",
        "%d-%b-%Y %H:%M:%S%.f",
        // " UTC" gets normalized to "Z" at the top of parse_date(); match both
        "%d-%b-%Y %H:%M:%SZ",
        "%d-%b-%Y %H:%M:%S UTC",
        "%Y-%m-%d",
        "%d-%b-%Y",
        "%d-%B-%Y",
        "%Y.%m.%d",
        "%Y/%m/%d",
        // Day-first (international norm). Ambiguous all-numeric dates (both
        // day and month <= 12) are interpreted here, so DMY wins ties.
        "%d.%m.%Y",
        "%d/%m/%Y",
        // US month-first fallback: only reached when the day-first parse
        // above fails (i.e. the leading field is > 12), recovering
        // unambiguous MDY dates that would otherwise be dropped. This never
        // changes the interpretation of a date the day-first formats accept.
        "%m.%d.%Y",
        "%m/%d/%Y",
        "%b %d %Y",
    ];

    for fmt in &naive_formats {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(&cleaned, fmt) {
            return Some(dt.and_utc());
        }
        if let Ok(d) = chrono::NaiveDate::parse_from_str(&cleaned, fmt) {
            return Some(d.and_hms_opt(0, 0, 0)?.and_utc());
        }
    }

    // Last resort: try parsing ISO 8601 directly
    if let Ok(dt) = cleaned.parse::<DateTime<Utc>>() {
        return Some(dt);
    }

    None
}

/// Maximum number of nameservers extracted from a single WHOIS response.
/// Real domains have ≤ 13 NS records (DNS protocol limit). Cap defensively
/// to prevent a malicious / malformed registry response from driving
/// unbounded allocation.
const MAX_NAMESERVERS: usize = 32;

fn extract_nameservers(text: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut nameservers = Vec::new();

    for re in NAMESERVER_PATTERNS.iter() {
        for caps in re.captures_iter(text) {
            if nameservers.len() >= MAX_NAMESERVERS {
                return nameservers;
            }
            if let Some(m) = caps.get(1) {
                // Strip glue IP addresses that some registries append after the hostname
                // e.g., "ns1.example.br 200.1.2.3 2001:db8::1" → "ns1.example.br"
                let raw = m.as_str().trim();
                let ns = raw.split_whitespace().next().unwrap_or(raw).to_lowercase();
                if !ns.is_empty() && seen.insert(ns.clone()) {
                    nameservers.push(ns);
                }
            }
        }
    }

    nameservers
}

/// Maximum number of domain-level status codes we extract. EPP defines
/// ~16 status values; a real domain rarely has more than 5-6. Cap to
/// prevent a malicious registry response from driving unbounded
/// allocation.
const MAX_STATUSES: usize = 32;

/// Extracts Status values only from the top-level domain block of a WHOIS
/// response. Stops scanning as soon as a RIPE-style `[Section-Header]` line is
/// encountered, which prevents contact-object `Status:` lines (e.g., inside
/// `[Tech-C]` blocks) from polluting the domain status list.
fn extract_status_top_level(raw: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut statuses = Vec::new();

    for line in raw.lines() {
        if statuses.len() >= MAX_STATUSES {
            break;
        }
        let trimmed = line.trim_start();

        // Stop at the first RIPE/JPRS-style sub-object section header.
        if trimmed.starts_with('[') && trimmed.contains(']') {
            break;
        }
        // Skip comments and empty lines.
        if trimmed.is_empty() || trimmed.starts_with('%') || trimmed.starts_with('#') {
            continue;
        }

        // Match "Domain Status:", "Status:", "status:", "state:" case-insensitively
        // via a prefix check on the lowercased line.
        let lower = trimmed.to_lowercase();
        // Slice the ORIGINAL line by the ASCII prefix length. The prefixes are
        // pure ASCII, so their byte length is identical in `trimmed` and
        // `lower`; deriving the slice point from `lower`'s suffix length is
        // unsound because `to_lowercase()` is not length-preserving for all
        // Unicode (e.g. Turkish İ → i̇ grows 2→3 bytes), which could make the
        // lowercased suffix longer than the whole original line and underflow
        // `trimmed.len() - rest.len()` into an out-of-bounds slice panic.
        let value_opt = if lower.starts_with("domain status:") {
            Some(&trimmed["domain status:".len()..])
        } else if lower.starts_with("status:") {
            Some(&trimmed["status:".len()..])
        } else if lower.starts_with("state:") {
            Some(&trimmed["state:".len()..])
        } else {
            None
        };

        if let Some(rest) = value_opt {
            let raw_val = rest.trim();
            if let Some(first) = raw_val.split_whitespace().next() {
                if !first.is_empty() && seen.insert(first.to_string()) {
                    statuses.push(first.to_string());
                }
            }
        }
    }

    statuses
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_response(raw: &str) -> WhoisResponse {
        WhoisResponse::parse_internal("example.jp", "whois.jprs.jp", raw)
    }

    // --- H10: is_available() scans the full response --------------------

    #[test]
    fn is_available_jprs_style_with_notice_preamble() {
        // JPRS prepends notice lines before the availability indicator.
        let raw = "\
Notice: JPRS database is provided for information purposes only.
Notice: Use of this service is subject to the JPRS terms.
Notice: For more info see https://jprs.jp/
Notice: Copyright (C) JPRS.

No match!!

";
        assert!(make_response(raw).is_available());
    }

    #[test]
    fn is_available_nic_br_style() {
        let raw = "\
% Copyright (c) Nic.br
% The use of the data below is only permitted as described in
% full by the terms of use at https://registro.br/termo/en.html,
% being prohibited its distribution, commercialization or
% reproduction, in particular, to use it for advertising or
% any similar purpose.

No match for domain exemplo.br.
";
        assert!(make_response(raw).is_available());
    }

    #[test]
    fn is_available_twnic_style() {
        let raw = "\
TWNIC WHOIS Server. This service is free and is provided as is.

Notice: Use of this service is subject to terms.
Notice: Do not use for spam.

Domain not found.
";
        assert!(make_response(raw).is_available());
    }

    #[test]
    fn is_available_false_when_registration_data_present_despite_noise() {
        // A registered domain whose WHOIS prose contains an availability
        // fragment (here in an abuse-contact/notice line) must NOT read as
        // available — concrete registration data (registrar/dates/NS) wins
        // over an unanchored substring match. This is the H6 false-positive
        // class: "<registered domain> reported AVAILABLE".
        let raw = "\
Domain Name: example.com
Registrar: Example Registrar, Inc.
Creation Date: 2020-01-01T00:00:00Z
Name Server: ns1.example.com
Registrar Abuse Contact: please report if the object not found in directory
";
        assert!(!make_response(raw).is_available());
    }

    #[test]
    fn is_available_false_for_registered_domain() {
        let raw = "\
Domain Name: example.com
Registrar: Example Registrar, Inc.
Creation Date: 2020-01-01T00:00:00Z
Name Server: ns1.example.com
";
        assert!(!make_response(raw).is_available());
    }

    // --- registry_unavailable(): registry serves no usable WHOIS --------

    #[test]
    fn registry_unavailable_true_for_tld_not_supported_sentinel() {
        // Identity Digital (.email/.life/.ninja/…) port-43 servers reply
        // "TLD is not supported." with no domain fields — RDAP-only TLDs.
        let raw = "\
TLD is not supported.
>>> Last update of WHOIS database: 2026-06-03T22:45:28Z <<<

Terms of Use: Access to WHOIS information is provided to assist persons ...
";
        assert!(make_response(raw).registry_unavailable());
    }

    #[test]
    fn registry_unavailable_true_for_malformed_request_sentinel() {
        let raw = "\
Malformed request.
>>> Last update of WHOIS database: 2026-06-03T22:46:35Z <<<
";
        assert!(make_response(raw).registry_unavailable());
    }

    #[test]
    fn registry_unavailable_false_for_registered_domain() {
        let raw = "\
Domain Name: example.com
Registrar: Example Registrar, Inc.
Creation Date: 2020-01-01T00:00:00Z
Name Server: ns1.example.com
";
        assert!(!make_response(raw).registry_unavailable());
    }

    #[test]
    fn registry_unavailable_false_for_available_domain() {
        // An unregistered-domain "no match" response is NOT a service error —
        // it must read as available, not registry-unavailable.
        let raw = "No match for domain EXAMPLE.\n";
        assert!(!make_response(raw).registry_unavailable());
    }

    #[test]
    fn extract_status_does_not_panic_on_unicode_lowercasing_expansion() {
        // Turkish dotted capital İ (2 bytes) lowercases to i̇ (3 bytes), so a
        // status VALUE full of them makes the lowercased line longer than the
        // original. The old code sliced the original by a length derived from
        // the lowercased copy (`trimmed.len() - rest.len()`), which underflowed
        // and panicked out-of-bounds. `raw` is attacker-controlled (a hostile
        // WHOIS server), so this was a remotely-triggerable panic / DoS.
        let raw = format!("Domain Status: {}\n", "İ".repeat(40));
        let r = make_response(&raw); // must not panic
        assert!(
            !r.status.is_empty(),
            "status value should still be extracted"
        );
    }

    #[test]
    fn is_available_hkirc_has_not_been_registered() {
        // HKIRC (.hk and the IDN .香港/xn--j6w193g) signals an unregistered
        // domain with "The domain has not been registered." — note the
        // wording is "has not BEEN registered", which does NOT contain the
        // bare "not registered" substring the old pattern list relied on.
        let raw = "The domain has not been registered.\n";
        assert!(make_response(raw).is_available());
    }

    #[test]
    fn is_available_tab_delimited_status_available() {
        // DNS Belgium (.be) and similar registries separate the label and
        // value with a TAB: "Status:\tAVAILABLE". The scan must normalize
        // internal whitespace so the "status: available" pattern still hits.
        let raw = "Domain:\tfoo.be\nStatus:\tAVAILABLE\n";
        assert!(make_response(raw).is_available());
    }

    #[test]
    fn is_not_available_tab_delimited_status_not_available() {
        // Guard against a false positive from whitespace normalization:
        // "Status:\tNOT AVAILABLE" (a registered .be domain) must NOT be
        // read as available — "status: available" is not a substring of
        // "status: not available".
        let raw = "Domain:\tfoo.be\nStatus:\tNOT AVAILABLE\n";
        assert!(!make_response(raw).is_available());
    }

    #[test]
    fn is_available_recognizes_additional_registry_phrasings() {
        // "Not found" wordings surfaced by the cross-TLD audit, mostly from
        // no-RDAP ccTLDs where WHOIS is the only registry signal.
        for raw in [
            "*** Nothing found for this query.\n", // .kz / .қаз (KazNIC)
            "No Found\n",                          // TWNIC .tw / 台灣 / 台湾
            "No record found for 'example.ls'.\n", // .ls (Lesotho)
            "No information was found matching that query.\n", // .africa
            "Object not found\n",                  // generic
            "Not find MatchingRecord\n",           // CONAC .政务 / .公益
        ] {
            assert!(
                make_response(raw).is_available(),
                "should detect available from: {raw:?}"
            );
        }
    }

    #[test]
    fn is_available_does_not_match_registered_or_blocked_phrasings() {
        // Guard against false positives from the broadened pattern list: a
        // registered domain, a "not available" status, a port-43 refusal, and
        // TOS prose containing "free" must all stay NOT-available.
        for raw in [
            "Domain Status: clientTransferProhibited\nRegistrar: Example, Inc.\n",
            "Status: NOT AVAILABLE\n",
            "Requests of this client are not permitted. Please use the web form.\n",
            "This WHOIS service is free for personal, non-commercial use.\n",
        ] {
            assert!(
                !make_response(raw).is_available(),
                "must NOT detect available from: {raw:?}"
            );
        }
    }

    #[test]
    fn is_available_ignores_not_found_phrase_buried_in_prose() {
        // A thin response with NO parsed registration fields (so the H6
        // registration-data guard does not fire) whose only "does not exist"
        // / "not found" occurrence is inside a long prose/notice sentence
        // must NOT be read as available. Availability indicators are short
        // status lines, not phrases buried in footer prose.
        let raw = "\
This is an informational banner from the registry WHOIS service provider.
Note that if the queried object does not exist in our database we simply return an empty result rather than an error response.
Records not found in this directory may still exist upstream in the thick registry, so please check with the sponsoring registrar.
";
        assert!(
            !make_response(raw).is_available(),
            "long prose sentences must not trigger availability"
        );
    }

    // --- M19: indicates_not_found anchors at line start -----------------

    #[test]
    fn indicates_not_found_true_on_line_start() {
        let raw = "\
Domain Name: example.com
queried object does not exist
";
        assert!(make_response(raw).indicates_not_found());
    }

    #[test]
    fn indicates_not_found_false_when_phrase_is_in_tos_footer() {
        // A registered-domain response whose TOS footer quotes the phrase
        // must not be flagged as not-found.
        let raw = "\
Domain Name: example.com
Registrar: Example Registrar, Inc.
Creation Date: 2020-01-01T00:00:00Z
Name Server: ns1.example.com

Terms of Service:
Note that if the queried object does not exist in our database we return NXDOMAIN.
This document does not imply anything about specific domains.
";
        assert!(!make_response(raw).indicates_not_found());
    }

    // --- M13: extract_status_top_level skips sub-object sections --------

    #[test]
    fn status_extracted_only_from_top_level_block() {
        let raw = "\
Domain Name: example.jp
Status: Active
Registrar: Example Registrar

[Tech-C]
Status: ok
Name: Technical Contact
";
        let parsed = make_response(raw);
        // Only the top-level Active should be present; the Tech-C "ok" is skipped.
        assert_eq!(parsed.status, vec!["Active".to_string()]);
    }

    #[test]
    fn status_multiple_top_level_values_deduped() {
        let raw = "\
Domain Name: example.com
Domain Status: clientTransferProhibited
Domain Status: clientUpdateProhibited
Domain Status: clientTransferProhibited
";
        let parsed = make_response(raw);
        assert_eq!(
            parsed.status,
            vec![
                "clientTransferProhibited".to_string(),
                "clientUpdateProhibited".to_string(),
            ]
        );
    }

    // --- M14: parse_date handles "15-Jan-2024 10:30:00" -----------------

    #[test]
    fn parse_date_handles_d_b_y_with_time() {
        let parsed = parse_date("15-Jan-2024 10:30:00").expect("should parse");
        use chrono::Datelike;
        assert_eq!(parsed.year(), 2024);
        assert_eq!(parsed.month(), 1);
        assert_eq!(parsed.day(), 15);
    }

    #[test]
    fn parse_date_handles_d_b_y_with_time_utc_suffix() {
        let parsed = parse_date("15-Jan-2024 10:30:00 UTC").expect("should parse");
        use chrono::Datelike;
        assert_eq!(parsed.year(), 2024);
    }

    #[test]
    fn parse_date_still_handles_d_b_y_date_only() {
        let parsed = parse_date("15-Jan-2024").expect("should parse");
        use chrono::Datelike;
        assert_eq!(parsed.year(), 2024);
    }

    // --- parse_date: ambiguous numeric dates default to day-first, but
    //     unambiguous US month-first dates are recovered (not dropped) ----

    #[test]
    fn parse_date_recovers_unambiguous_us_mdy() {
        // Some registrars emit US month-first numeric dates. When the day
        // field is > 12 the date is unambiguously MDY and was previously
        // dropped (there was no %m/%d/%Y format). Recover it rather than
        // returning None.
        use chrono::Datelike;
        let parsed = parse_date("02/13/2024").expect("unambiguous MDY should parse");
        assert_eq!(parsed.year(), 2024);
        assert_eq!(parsed.month(), 2);
        assert_eq!(parsed.day(), 13);
    }

    #[test]
    fn parse_date_ambiguous_numeric_is_day_first() {
        // Documented precedence: ambiguous all-numeric dates (both fields
        // <= 12) are interpreted day-first (the international norm), matching
        // the %d/%m/%Y format ordering. "06/07/2024" => 6 July 2024. The
        // month-first fallback must NOT change this.
        use chrono::Datelike;
        let parsed = parse_date("06/07/2024").expect("should parse");
        assert_eq!(parsed.year(), 2024);
        assert_eq!(parsed.month(), 7);
        assert_eq!(parsed.day(), 6);
    }

    // --- H3: raw_response is not serialized -----------------------------

    #[test]
    fn raw_response_is_skipped_from_json_output() {
        let raw = "Domain Name: example.com\nRegistrar: Example Registrar\n";
        let parsed = make_response(raw);
        assert!(
            !parsed.raw_response.is_empty(),
            "raw_response still populated internally"
        );
        let json = serde_json::to_string(&parsed).expect("serialize");
        assert!(
            !json.contains("raw_response"),
            "raw_response must not appear in serialized JSON output: {}",
            json
        );
        assert!(
            !json.contains("Domain Name: example.com"),
            "raw response content must not leak in JSON: {}",
            json
        );
    }
}
