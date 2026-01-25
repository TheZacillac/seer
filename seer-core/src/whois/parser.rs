use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Pre-compiled regexes for WHOIS field extraction
static REGISTRAR_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Registrar:\s*(.+)")
            .expect("Invalid regex for Registrar"),
        Regex::new(r"(?i)Registrar Name:\s*(.+)")
            .expect("Invalid regex for Registrar Name"),
        Regex::new(r"(?i)Sponsoring Registrar:\s*(.+)")
            .expect("Invalid regex for Sponsoring Registrar"),
    ]
});

static REGISTRANT_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Registrant Name:\s*(.+)")
            .expect("Invalid regex for Registrant Name"),
        Regex::new(r"(?i)Registrant:\s*(.+)")
            .expect("Invalid regex for Registrant"),
    ]
});

static ORGANIZATION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Registrant Organization:\s*(.+)")
            .expect("Invalid regex for Registrant Organization"),
        Regex::new(r"(?i)Organization:\s*(.+)")
            .expect("Invalid regex for Organization"),
        Regex::new(r"(?i)org-name:\s*(.+)")
            .expect("Invalid regex for org-name"),
        Regex::new(r"(?i)Org Name:\s*(.+)")
            .expect("Invalid regex for Org Name"),
    ]
});

static CREATION_DATE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Creation Date:\s*(.+)")
            .expect("Invalid regex for Creation Date"),
        Regex::new(r"(?i)Created Date:\s*(.+)")
            .expect("Invalid regex for Created Date"),
        Regex::new(r"(?i)Created On:\s*(.+)")
            .expect("Invalid regex for Created On"),
        Regex::new(r"(?i)Created:\s*(.+)")
            .expect("Invalid regex for Created"),
        Regex::new(r"(?i)Registration Date:\s*(.+)")
            .expect("Invalid regex for Registration Date"),
        Regex::new(r"(?i)Domain Registration Date:\s*(.+)")
            .expect("Invalid regex for Domain Registration Date"),
    ]
});

static EXPIRATION_DATE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)(?:Registry )?Expir(?:y|ation) Date:\s*(.+)")
            .expect("Invalid regex for Expiry/Expiration Date"),
        Regex::new(r"(?i)Expiration Date:\s*(.+)")
            .expect("Invalid regex for Expiration Date"),
        Regex::new(r"(?i)Expires On:\s*(.+)")
            .expect("Invalid regex for Expires On"),
        Regex::new(r"(?i)Expires:\s*(.+)")
            .expect("Invalid regex for Expires"),
        Regex::new(r"(?i)Expiry Date:\s*(.+)")
            .expect("Invalid regex for Expiry Date"),
        Regex::new(r"(?i)paid-till:\s*(.+)")
            .expect("Invalid regex for paid-till"),
    ]
});

static UPDATED_DATE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Updated Date:\s*(.+)")
            .expect("Invalid regex for Updated Date"),
        Regex::new(r"(?i)Last Updated On:\s*(.+)")
            .expect("Invalid regex for Last Updated On"),
        Regex::new(r"(?i)Last Modified:\s*(.+)")
            .expect("Invalid regex for Last Modified"),
        Regex::new(r"(?i)Last Update:\s*(.+)")
            .expect("Invalid regex for Last Update"),
        Regex::new(r"(?i)Modified:\s*(.+)")
            .expect("Invalid regex for Modified"),
    ]
});

static DNSSEC_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)DNSSEC:\s*(.+)")
            .expect("Invalid regex for DNSSEC"),
        Regex::new(r"(?i)DNSSEC Status:\s*(.+)")
            .expect("Invalid regex for DNSSEC Status"),
    ]
});

static NAMESERVER_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Name Server:\s*(.+)")
            .expect("Invalid regex for Name Server"),
        Regex::new(r"(?i)Nameserver:\s*(.+)")
            .expect("Invalid regex for Nameserver"),
        Regex::new(r"(?i)nserver:\s*(.+)")
            .expect("Invalid regex for nserver"),
        Regex::new(r"(?i)NS:\s*(.+)")
            .expect("Invalid regex for NS"),
    ]
});

static STATUS_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Domain Status:\s*(.+)")
            .expect("Invalid regex for Domain Status"),
        Regex::new(r"(?i)Status:\s*(.+)")
            .expect("Invalid regex for Status"),
        Regex::new(r"(?i)state:\s*(.+)")
            .expect("Invalid regex for state"),
    ]
});

static REGISTRANT_EMAIL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Registrant Email:\s*(.+)")
            .expect("Invalid regex for Registrant Email"),
        Regex::new(r"(?i)Registrant E-mail:\s*(.+)")
            .expect("Invalid regex for Registrant E-mail"),
    ]
});

static REGISTRANT_PHONE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Registrant Phone:\s*(.+)")
            .expect("Invalid regex for Registrant Phone"),
        Regex::new(r"(?i)Registrant Tel:\s*(.+)")
            .expect("Invalid regex for Registrant Tel"),
    ]
});

static REGISTRANT_ADDRESS_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Registrant Street:\s*(.+)")
            .expect("Invalid regex for Registrant Street"),
        Regex::new(r"(?i)Registrant Address:\s*(.+)")
            .expect("Invalid regex for Registrant Address"),
    ]
});

static REGISTRANT_COUNTRY_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Registrant Country:\s*(.+)")
            .expect("Invalid regex for Registrant Country"),
    ]
});

static ADMIN_NAME_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Admin Name:\s*(.+)")
            .expect("Invalid regex for Admin Name"),
        Regex::new(r"(?i)Administrative Contact Name:\s*(.+)")
            .expect("Invalid regex for Administrative Contact Name"),
    ]
});

static ADMIN_ORG_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Admin Organization:\s*(.+)")
            .expect("Invalid regex for Admin Organization"),
    ]
});

static ADMIN_EMAIL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Admin Email:\s*(.+)")
            .expect("Invalid regex for Admin Email"),
        Regex::new(r"(?i)Admin E-mail:\s*(.+)")
            .expect("Invalid regex for Admin E-mail"),
    ]
});

static ADMIN_PHONE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Admin Phone:\s*(.+)")
            .expect("Invalid regex for Admin Phone"),
        Regex::new(r"(?i)Admin Tel:\s*(.+)")
            .expect("Invalid regex for Admin Tel"),
    ]
});

static TECH_NAME_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Tech Name:\s*(.+)")
            .expect("Invalid regex for Tech Name"),
        Regex::new(r"(?i)Technical Contact Name:\s*(.+)")
            .expect("Invalid regex for Technical Contact Name"),
    ]
});

static TECH_ORG_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Tech Organization:\s*(.+)")
            .expect("Invalid regex for Tech Organization"),
    ]
});

static TECH_EMAIL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Tech Email:\s*(.+)")
            .expect("Invalid regex for Tech Email"),
        Regex::new(r"(?i)Tech E-mail:\s*(.+)")
            .expect("Invalid regex for Tech E-mail"),
    ]
});

static TECH_PHONE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Tech Phone:\s*(.+)")
            .expect("Invalid regex for Tech Phone"),
        Regex::new(r"(?i)Tech Tel:\s*(.+)")
            .expect("Invalid regex for Tech Tel"),
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
    pub raw_response: String,
}

impl WhoisResponse {
    pub fn parse(domain: &str, whois_server: &str, raw: &str) -> Self {
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
        let status = extract_status(raw);
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
                let lower = value.to_lowercase();

                // Filter out redacted/privacy-protected values
                let is_redacted = lower.contains("redacted")
                    || lower.contains("data protected")
                    || lower.contains("privacy")
                    || lower.contains("not disclosed")
                    || lower.contains("withheld")
                    || lower == "n/a"
                    || lower == "none"
                    || value.is_empty();

                if !is_redacted {
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
