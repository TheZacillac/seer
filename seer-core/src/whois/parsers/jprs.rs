//! Parser for .jp domains (JPRS format).
//!
//! JPRS uses a unique format where fields are prefixed with a letter code
//! followed by a Japanese label in brackets. Nameservers use the key
//! `p. [ネームサーバ]`.
//!
//! Example JPRS response:
//! ```text
//! Domain Information: [ドメイン情報]
//! a. [ドメイン名]                 TOKYO.JP
//! f. [組織名]                     東京ドメイン
//! g. [Organization]               Tokyo Domain
//! p. [ネームサーバ]               a.dns.jp
//! p. [ネームサーバ]               b.dns.jp
//! [状態]                          Reserved
//! [最終更新]                      2005/03/30 17:37:52 (JST)
//! ```

use chrono::{DateTime, NaiveDateTime, Utc};
use once_cell::sync::Lazy;
use regex::Regex;

use super::{push_bounded, RegistryParser, MAX_NAMESERVERS, MAX_STATUSES};
use crate::whois::parser::WhoisResponse;

/// Matches nameserver lines: `p. [ネームサーバ]   value`
static NS_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^p\.\s+\[ネームサーバ\]\s+(.+)$").expect("Invalid JPRS NS regex")
});

/// Matches organization (English): `g. [Organization]   value`
static ORG_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^g\.\s+\[Organization\]\s+(.+)$").expect("Invalid JPRS org regex")
});

/// Matches organization (Japanese): `f. [組織名]   value`
static ORG_JP_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)^f\.\s+\[組織名\]\s+(.+)$").expect("Invalid JPRS org JP regex"));

/// Matches state: `[状態]   value`
static STATUS_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)^\[状態\]\s+(.+)$").expect("Invalid JPRS status regex"));

/// Matches last updated: `[最終更新]   YYYY/MM/DD HH:MM:SS (JST)`
static UPDATED_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?m)^\[最終更新\]\s+(.+)$").expect("Invalid JPRS updated regex"));

/// Matches creation date: `[登録年月日]   YYYY/MM/DD` or `[接続年月日]   YYYY/MM/DD`
static CREATED_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^\[(?:登録年月日|接続年月日)\]\s+(.+)$").expect("Invalid JPRS created regex")
});

/// Matches DNSSEC signing key line: `s. [署名鍵]   value`
/// The value portion is optional — an empty value means unsigned.
/// Uses `[^\S\n]*` instead of `\s*` to avoid matching across newlines in multiline mode.
static SIGNING_KEY_LINE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?m)^s\.\s+\[署名鍵\][^\S\n]*(.+)?$").expect("Invalid JPRS signing key regex")
});

// Also support the English-appended format (when /e is used)
/// Matches `Name Server:   value` and the `p.`-prefixed form. For the `p.`
/// branch an optional bracketed label (e.g. `[Name Server]`) is consumed but
/// not captured, so only the trailing hostname lands in the capture group —
/// otherwise a `p. [label] host` line yields `[label] host` as the nameserver.
static NS_EN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?im)^(?:Name Server\s*:?|p\.\s*(?:\[[^\]]*\])?)\s+(.+)$")
        .expect("Invalid JPRS NS EN regex")
});

/// Parser for .jp domains using the JPRS format.
#[derive(Debug, Clone, Default)]
pub struct JprsParser;

impl JprsParser {
    pub fn new() -> Self {
        Self
    }

    fn parse_jprs_date(date_str: &str) -> Option<DateTime<Utc>> {
        let cleaned = date_str.trim().trim_end_matches("(JST)").trim();

        // JPRS uses "YYYY/MM/DD HH:MM:SS" or "YYYY/MM/DD"
        if let Ok(dt) = NaiveDateTime::parse_from_str(cleaned, "%Y/%m/%d %H:%M:%S") {
            // JST is UTC+9
            return Some(dt.and_utc() - chrono::Duration::hours(9));
        }
        if let Ok(dt) =
            NaiveDateTime::parse_from_str(&format!("{} 00:00:00", cleaned), "%Y/%m/%d %H:%M:%S")
        {
            return Some(dt.and_utc());
        }

        None
    }
}

impl RegistryParser for JprsParser {
    fn supported_tlds(&self) -> &[&str] {
        &["jp"]
    }

    fn parse(&self, domain: &str, server: &str, raw: &str) -> WhoisResponse {
        let mut nameservers = Vec::new();
        let mut organization = None;
        let mut status = Vec::new();
        let mut updated_date = None;
        let mut creation_date = None;
        let mut has_signing_key = false;

        // Extract nameservers (Japanese format)
        for caps in NS_PATTERN.captures_iter(raw) {
            if let Some(m) = caps.get(1) {
                let ns = m.as_str().trim().to_lowercase();
                push_bounded(&mut nameservers, ns, MAX_NAMESERVERS);
            }
        }

        // If no Japanese-format NS found, try English format
        // (some .jp responses use "Name Server:" style after /e suffix)
        if nameservers.is_empty() {
            for caps in NS_EN_PATTERN.captures_iter(raw) {
                if let Some(m) = caps.get(1) {
                    let ns = m.as_str().trim().to_lowercase();
                    push_bounded(&mut nameservers, ns, MAX_NAMESERVERS);
                }
            }
        }

        // Extract organization (prefer English, fall back to Japanese)
        if let Some(caps) = ORG_PATTERN.captures(raw) {
            if let Some(m) = caps.get(1) {
                let org = m.as_str().trim().to_string();
                if !org.is_empty() {
                    organization = Some(org);
                }
            }
        }
        if organization.is_none() {
            if let Some(caps) = ORG_JP_PATTERN.captures(raw) {
                if let Some(m) = caps.get(1) {
                    let org = m.as_str().trim().to_string();
                    if !org.is_empty() {
                        organization = Some(org);
                    }
                }
            }
        }

        // Extract status
        if let Some(caps) = STATUS_PATTERN.captures(raw) {
            if let Some(m) = caps.get(1) {
                let s = m.as_str().trim().to_string();
                push_bounded(&mut status, s, MAX_STATUSES);
            }
        }

        // Extract dates
        if let Some(caps) = UPDATED_PATTERN.captures(raw) {
            if let Some(m) = caps.get(1) {
                updated_date = Self::parse_jprs_date(m.as_str());
            }
        }
        if let Some(caps) = CREATED_PATTERN.captures(raw) {
            if let Some(m) = caps.get(1) {
                creation_date = Self::parse_jprs_date(m.as_str());
            }
        }

        // DNSSEC — check if signing key has an actual value
        if let Some(caps) = SIGNING_KEY_LINE.captures(raw) {
            if let Some(m) = caps.get(1) {
                if !m.as_str().trim().is_empty() {
                    has_signing_key = true;
                }
            }
        }

        WhoisResponse {
            domain: domain.to_string(),
            registrar: Some("JPRS".to_string()),
            registrant: organization.clone(),
            organization,
            registrant_email: None,
            registrant_phone: None,
            registrant_address: None,
            registrant_country: Some("JP".to_string()),
            admin_name: None,
            admin_organization: None,
            admin_email: None,
            admin_phone: None,
            tech_name: None,
            tech_organization: None,
            tech_email: None,
            tech_phone: None,
            creation_date,
            expiration_date: None, // JPRS doesn't include expiry in public WHOIS
            updated_date,
            nameservers,
            status,
            dnssec: if has_signing_key {
                Some("signedDelegation".to_string())
            } else {
                None
            },
            whois_server: server.to_string(),
            raw_response: raw.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_JPRS_RESPONSE: &str = r#"[ JPRS database provides information on network administration. Its use is    ]
[ restricted to network administration purposes. For further information,     ]
[ use 'whois -h whois.jprs.jp help'. To suppress Japanese output, add'/e'     ]
[ at the end of command, e.g. 'whois -h whois.jprs.jp xxx/e'.                 ]
Domain Information: [ドメイン情報]
a. [ドメイン名]                 TOKYO.JP
e. [そしきめい]
f. [組織名]                     東京ドメイン
g. [Organization]               Tokyo Domain
k. [組織種別]
l. [Organization Type]
m. [登録担当者]
n. [技術連絡担当者]
p. [ネームサーバ]               a.dns.jp
p. [ネームサーバ]               b.dns.jp
p. [ネームサーバ]               c.dns.jp
p. [ネームサーバ]               d.dns.jp
p. [ネームサーバ]               e.dns.jp
p. [ネームサーバ]               f.dns.jp
p. [ネームサーバ]               g.dns.jp
p. [ネームサーバ]               h.dns.jp
s. [署名鍵]
[状態]                          Reserved
[登録年月日]
[接続年月日]
[最終更新]                      2005/03/30 17:37:52 (JST)"#;

    const SAMPLE_JPRS_DOMAIN: &str = r#"[ JPRS database provides information on network administration. Its use is    ]
Domain Information: [ドメイン情報]
a. [ドメイン名]                 EXAMPLE.JP
f. [組織名]                     株式会社エグザンプル
g. [Organization]               Example Inc.
p. [ネームサーバ]               ns1.example.jp
p. [ネームサーバ]               ns2.example.jp
s. [署名鍵]
[状態]                          Active
[登録年月日]                    2001/03/22
[接続年月日]                    2001/03/22
[最終更新]                      2024/04/01 01:05:10 (JST)"#;

    #[test]
    fn test_jprs_nameservers() {
        let parser = JprsParser::new();
        let result = parser.parse("tokyo.jp", "whois.jprs.jp", SAMPLE_JPRS_RESPONSE);

        assert_eq!(result.nameservers.len(), 8);
        assert!(result.nameservers.contains(&"a.dns.jp".to_string()));
        assert!(result.nameservers.contains(&"h.dns.jp".to_string()));
    }

    #[test]
    fn test_jprs_organization() {
        let parser = JprsParser::new();
        let result = parser.parse("tokyo.jp", "whois.jprs.jp", SAMPLE_JPRS_RESPONSE);

        assert_eq!(result.organization, Some("Tokyo Domain".to_string()));
    }

    #[test]
    fn test_jprs_status() {
        let parser = JprsParser::new();
        let result = parser.parse("tokyo.jp", "whois.jprs.jp", SAMPLE_JPRS_RESPONSE);

        assert!(result.status.contains(&"Reserved".to_string()));
    }

    #[test]
    fn test_jprs_updated_date() {
        let parser = JprsParser::new();
        let result = parser.parse("tokyo.jp", "whois.jprs.jp", SAMPLE_JPRS_RESPONSE);

        assert!(result.updated_date.is_some());
    }

    #[test]
    fn test_jprs_domain_with_dates() {
        let parser = JprsParser::new();
        let result = parser.parse("example.jp", "whois.jprs.jp", SAMPLE_JPRS_DOMAIN);

        assert_eq!(result.nameservers.len(), 2);
        assert!(result.nameservers.contains(&"ns1.example.jp".to_string()));
        assert!(result.nameservers.contains(&"ns2.example.jp".to_string()));
        assert_eq!(result.organization, Some("Example Inc.".to_string()));
        assert!(result.status.contains(&"Active".to_string()));
        assert!(result.creation_date.is_some());
        assert!(result.updated_date.is_some());
    }

    #[test]
    fn test_jprs_no_signing_key() {
        let parser = JprsParser::new();
        let result = parser.parse("tokyo.jp", "whois.jprs.jp", SAMPLE_JPRS_RESPONSE);

        // s. [署名鍵] is empty, so no DNSSEC
        assert!(result.dnssec.is_none());
    }

    /// English-appended (/e) variant whose NS lines carry a `p.` prefix and a
    /// bracketed label that is NOT the exact Japanese `[ネームサーバ]`. The strict
    /// Japanese NS_PATTERN doesn't match, so parsing falls back to NS_EN_PATTERN.
    /// That fallback must extract only the hostname, not swallow the bracket
    /// label into the nameserver value.
    const SAMPLE_JPRS_EN_BRACKET_NS: &str = r#"Domain Information:
a. [Domain Name]                EXAMPLE.JP
p.        [Name Server]              a.dns.jp
p.        [Name Server]              b.dns.jp
[State]                         Active"#;

    #[test]
    fn test_jprs_en_fallback_strips_bracket_label() {
        let parser = JprsParser::new();
        let result = parser.parse("example.jp", "whois.jprs.jp", SAMPLE_JPRS_EN_BRACKET_NS);

        assert_eq!(
            result.nameservers,
            vec!["a.dns.jp".to_string(), "b.dns.jp".to_string()],
            "fallback must capture only the hostname, not the bracket label"
        );
    }

    #[test]
    fn test_supported_tlds() {
        let parser = JprsParser::new();
        assert_eq!(parser.supported_tlds(), &["jp"]);
    }
}
