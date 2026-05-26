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

    pub fn is_available(&self) -> bool {
        // Scan the full response (excluding empty lines and comment lines). Some
        // registries (TWNIC, JPRS, NIC.br) prepend 3-4 notice lines before the
        // "no match" line, which would escape a small take(N) window.
        let lower = self
            .raw_response
            .lines()
            .filter(|line| {
                let trimmed = line.trim();
                !trimmed.is_empty() && !trimmed.starts_with('#') && !trimmed.starts_with('%')
            })
            .collect::<Vec<_>>()
            .join("\n")
            .to_lowercase();

        AVAILABILITY_PATTERNS.iter().any(|p| lower.contains(p))
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

/// Patterns indicating a domain is available (unregistered).
/// Matched case-insensitively via `contains()` on the filtered response.
const AVAILABILITY_PATTERNS: &[&str] = &[
    "no match for",
    "no match",
    "not found",
    "no data found",
    "no entries found",
    "domain not found",
    "available for registration",
    "not registered",
    "status: available",
    "status: free",
    "no object found",
    "does not exist",
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

fn parse_date(date_str: &str) -> Option<DateTime<Utc>> {
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
        "%d.%m.%Y",
        "%d/%m/%Y",
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

fn extract_nameservers(text: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut nameservers = Vec::new();

    for re in NAMESERVER_PATTERNS.iter() {
        for caps in re.captures_iter(text) {
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

/// Extracts Status values only from the top-level domain block of a WHOIS
/// response. Stops scanning as soon as a RIPE-style `[Section-Header]` line is
/// encountered, which prevents contact-object `Status:` lines (e.g., inside
/// `[Tech-C]` blocks) from polluting the domain status list.
fn extract_status_top_level(raw: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut statuses = Vec::new();

    for line in raw.lines() {
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
        let value_opt = if let Some(rest) = lower.strip_prefix("domain status:") {
            Some(&trimmed[trimmed.len() - rest.len()..])
        } else if let Some(rest) = lower.strip_prefix("status:") {
            Some(&trimmed[trimmed.len() - rest.len()..])
        } else {
            lower
                .strip_prefix("state:")
                .map(|rest| &trimmed[trimmed.len() - rest.len()..])
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
    fn is_available_false_for_registered_domain() {
        let raw = "\
Domain Name: example.com
Registrar: Example Registrar, Inc.
Creation Date: 2020-01-01T00:00:00Z
Name Server: ns1.example.com
";
        assert!(!make_response(raw).is_available());
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
