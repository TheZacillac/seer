use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Pre-compiled regexes for WHOIS field extraction
static REGISTRAR_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Registrar:\s*(.+)").unwrap(),
        Regex::new(r"(?i)Registrar Name:\s*(.+)").unwrap(),
        Regex::new(r"(?i)Sponsoring Registrar:\s*(.+)").unwrap(),
    ]
});

static REGISTRANT_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Registrant Name:\s*(.+)").unwrap(),
        Regex::new(r"(?i)Registrant:\s*(.+)").unwrap(),
    ]
});

static ORGANIZATION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Registrant Organization:\s*(.+)").unwrap(),
        Regex::new(r"(?i)Organization:\s*(.+)").unwrap(),
        Regex::new(r"(?i)org-name:\s*(.+)").unwrap(),
        Regex::new(r"(?i)Org Name:\s*(.+)").unwrap(),
    ]
});

static CREATION_DATE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Creation Date:\s*(.+)").unwrap(),
        Regex::new(r"(?i)Created Date:\s*(.+)").unwrap(),
        Regex::new(r"(?i)Created On:\s*(.+)").unwrap(),
        Regex::new(r"(?i)Created:\s*(.+)").unwrap(),
        Regex::new(r"(?i)Registration Date:\s*(.+)").unwrap(),
        Regex::new(r"(?i)Domain Registration Date:\s*(.+)").unwrap(),
    ]
});

static EXPIRATION_DATE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)(?:Registry )?Expir(?:y|ation) Date:\s*(.+)").unwrap(),
        Regex::new(r"(?i)Expiration Date:\s*(.+)").unwrap(),
        Regex::new(r"(?i)Expires On:\s*(.+)").unwrap(),
        Regex::new(r"(?i)Expires:\s*(.+)").unwrap(),
        Regex::new(r"(?i)Expiry Date:\s*(.+)").unwrap(),
        Regex::new(r"(?i)paid-till:\s*(.+)").unwrap(),
    ]
});

static UPDATED_DATE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Updated Date:\s*(.+)").unwrap(),
        Regex::new(r"(?i)Last Updated On:\s*(.+)").unwrap(),
        Regex::new(r"(?i)Last Modified:\s*(.+)").unwrap(),
        Regex::new(r"(?i)Last Update:\s*(.+)").unwrap(),
        Regex::new(r"(?i)Modified:\s*(.+)").unwrap(),
    ]
});

static DNSSEC_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)DNSSEC:\s*(.+)").unwrap(),
        Regex::new(r"(?i)DNSSEC Status:\s*(.+)").unwrap(),
    ]
});

static NAMESERVER_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Name Server:\s*(.+)").unwrap(),
        Regex::new(r"(?i)Nameserver:\s*(.+)").unwrap(),
        Regex::new(r"(?i)nserver:\s*(.+)").unwrap(),
        Regex::new(r"(?i)NS:\s*(.+)").unwrap(),
    ]
});

static STATUS_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Domain Status:\s*(.+)").unwrap(),
        Regex::new(r"(?i)Status:\s*(.+)").unwrap(),
        Regex::new(r"(?i)state:\s*(.+)").unwrap(),
    ]
});

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisResponse {
    pub domain: String,
    pub registrar: Option<String>,
    pub registrant: Option<String>,
    pub organization: Option<String>,
    pub creation_date: Option<DateTime<Utc>>,
    pub expiration_date: Option<DateTime<Utc>>,
    pub updated_date: Option<DateTime<Utc>>,
    pub nameservers: Vec<String>,
    pub status: Vec<String>,
    pub dnssec: Option<String>,
    pub whois_server: String,
    pub raw_response: String,
}

impl WhoisResponse {
    pub fn parse(domain: &str, whois_server: &str, raw: &str) -> Self {
        let registrar = extract_field_with_patterns(raw, &REGISTRAR_PATTERNS);
        let registrant = extract_field_with_patterns(raw, &REGISTRANT_PATTERNS);
        let organization = extract_field_with_patterns(raw, &ORGANIZATION_PATTERNS);
        let creation_date = extract_date_with_patterns(raw, &CREATION_DATE_PATTERNS);
        let expiration_date = extract_date_with_patterns(raw, &EXPIRATION_DATE_PATTERNS);
        let updated_date = extract_date_with_patterns(raw, &UPDATED_DATE_PATTERNS);
        let nameservers = extract_nameservers(raw);
        let status = extract_status(raw);
        let dnssec = extract_field_with_patterns(raw, &DNSSEC_PATTERNS);

        WhoisResponse {
            domain: domain.to_string(),
            registrar,
            registrant,
            organization,
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

    pub fn is_available(&self) -> bool {
        let available_patterns = [
            "no match",
            "not found",
            "no data found",
            "no entries found",
            "status: free",
            "status: available",
            "domain not found",
            "no object found",
            "does not exist",
        ];

        let lower = self.raw_response.to_lowercase();
        available_patterns.iter().any(|p| lower.contains(p))
    }

    /// Checks if the response indicates the registrar doesn't have data for this domain.
    /// This is different from is_available() - the domain may exist at the registry level
    /// but the referral registrar may not have data for it.
    pub fn indicates_not_found(&self) -> bool {
        let not_found_patterns = [
            "queried object does not exist",
            "object does not exist",
            "no match for domain",
            "domain is not registered",
        ];

        let lower = self.raw_response.to_lowercase();
        not_found_patterns.iter().any(|p| lower.contains(p))
    }
}

fn extract_field_with_patterns(text: &str, patterns: &[Regex]) -> Option<String> {
    for re in patterns {
        if let Some(caps) = re.captures(text) {
            if let Some(m) = caps.get(1) {
                let value = m.as_str().trim().to_string();
                if !value.is_empty() && value.to_lowercase() != "redacted" {
                    return Some(value);
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
    let formats = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%.fZ",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d",
        "%d-%b-%Y",
        "%d-%B-%Y",
        "%Y.%m.%d",
        "%Y/%m/%d",
        "%d.%m.%Y",
        "%d/%m/%Y",
        "%b %d %Y",
    ];

    let cleaned = date_str
        .trim()
        .replace(" UTC", "Z")
        .replace(" (UTC)", "")
        .replace(" +0000", "Z");

    for fmt in &formats {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(&cleaned, fmt) {
            return Some(dt.and_utc());
        }
        if let Ok(d) = chrono::NaiveDate::parse_from_str(&cleaned, fmt) {
            return Some(d.and_hms_opt(0, 0, 0)?.and_utc());
        }
    }

    // Try parsing ISO 8601 directly
    if let Ok(dt) = cleaned.parse::<DateTime<Utc>>() {
        return Some(dt);
    }

    None
}

fn extract_nameservers(text: &str) -> Vec<String> {
    let mut nameservers = Vec::new();

    for re in NAMESERVER_PATTERNS.iter() {
        for caps in re.captures_iter(text) {
            if let Some(m) = caps.get(1) {
                let ns = m.as_str().trim().to_lowercase();
                if !ns.is_empty() && !nameservers.contains(&ns) {
                    nameservers.push(ns);
                }
            }
        }
    }

    nameservers
}

fn extract_status(text: &str) -> Vec<String> {
    let mut statuses = Vec::new();

    for re in STATUS_PATTERNS.iter() {
        for caps in re.captures_iter(text) {
            if let Some(m) = caps.get(1) {
                let status = m.as_str().trim().to_string();
                // Extract just the status code without the URL
                let status = status.split_whitespace().next().unwrap_or(&status).to_string();
                if !status.is_empty() && !statuses.contains(&status) {
                    statuses.push(status);
                }
            }
        }
    }

    statuses
}
