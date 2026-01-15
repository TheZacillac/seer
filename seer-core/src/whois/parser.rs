use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisResponse {
    pub domain: String,
    pub registrar: Option<String>,
    pub registrant: Option<String>,
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
        let registrar = extract_field(raw, &[
            r"(?i)Registrar:\s*(.+)",
            r"(?i)Registrar Name:\s*(.+)",
            r"(?i)Sponsoring Registrar:\s*(.+)",
        ]);

        let registrant = extract_field(raw, &[
            r"(?i)Registrant Organization:\s*(.+)",
            r"(?i)Registrant Name:\s*(.+)",
            r"(?i)Registrant:\s*(.+)",
            r"(?i)org-name:\s*(.+)",
        ]);

        let creation_date = extract_date(raw, &[
            r"(?i)Creation Date:\s*(.+)",
            r"(?i)Created Date:\s*(.+)",
            r"(?i)Created On:\s*(.+)",
            r"(?i)Created:\s*(.+)",
            r"(?i)Registration Date:\s*(.+)",
            r"(?i)Domain Registration Date:\s*(.+)",
        ]);

        let expiration_date = extract_date(raw, &[
            r"(?i)(?:Registry )?Expir(?:y|ation) Date:\s*(.+)",
            r"(?i)Expiration Date:\s*(.+)",
            r"(?i)Expires On:\s*(.+)",
            r"(?i)Expires:\s*(.+)",
            r"(?i)Expiry Date:\s*(.+)",
            r"(?i)paid-till:\s*(.+)",
        ]);

        let updated_date = extract_date(raw, &[
            r"(?i)Updated Date:\s*(.+)",
            r"(?i)Last Updated On:\s*(.+)",
            r"(?i)Last Modified:\s*(.+)",
            r"(?i)Last Update:\s*(.+)",
            r"(?i)Modified:\s*(.+)",
        ]);

        let nameservers = extract_nameservers(raw);
        let status = extract_status(raw);

        let dnssec = extract_field(raw, &[
            r"(?i)DNSSEC:\s*(.+)",
            r"(?i)DNSSEC Status:\s*(.+)",
        ]);

        WhoisResponse {
            domain: domain.to_string(),
            registrar,
            registrant,
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
        ];

        let lower = self.raw_response.to_lowercase();
        available_patterns.iter().any(|p| lower.contains(p))
    }
}

fn extract_field(text: &str, patterns: &[&str]) -> Option<String> {
    for pattern in patterns {
        if let Ok(re) = Regex::new(pattern) {
            if let Some(caps) = re.captures(text) {
                if let Some(m) = caps.get(1) {
                    let value = m.as_str().trim().to_string();
                    if !value.is_empty() && value.to_lowercase() != "redacted" {
                        return Some(value);
                    }
                }
            }
        }
    }
    None
}

fn extract_date(text: &str, patterns: &[&str]) -> Option<DateTime<Utc>> {
    let date_str = extract_field(text, patterns)?;
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
    let patterns = [
        r"(?i)Name Server:\s*(.+)",
        r"(?i)Nameserver:\s*(.+)",
        r"(?i)nserver:\s*(.+)",
        r"(?i)NS:\s*(.+)",
    ];

    let mut nameservers = Vec::new();

    for pattern in &patterns {
        if let Ok(re) = Regex::new(pattern) {
            for caps in re.captures_iter(text) {
                if let Some(m) = caps.get(1) {
                    let ns = m.as_str().trim().to_lowercase();
                    if !ns.is_empty() && !nameservers.contains(&ns) {
                        nameservers.push(ns);
                    }
                }
            }
        }
    }

    nameservers
}

fn extract_status(text: &str) -> Vec<String> {
    let patterns = [
        r"(?i)Domain Status:\s*(.+)",
        r"(?i)Status:\s*(.+)",
        r"(?i)state:\s*(.+)",
    ];

    let mut statuses = Vec::new();

    for pattern in &patterns {
        if let Ok(re) = Regex::new(pattern) {
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
    }

    statuses
}
