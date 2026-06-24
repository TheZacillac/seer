//! Parser for .kr domains (KISA/KRNIC format).
//!
//! KISA uses a bilingual format (Korean + English) with nameservers in
//! nested sub-sections. The English section has:
//! ```text
//! Primary Name Server
//!    Host Name                : ns1.google.com
//!
//! Secondary Name Server
//!    Host Name                : ns2.google.com
//! ```
//!
//! Some domains have more than two nameservers, listed as additional
//! "Secondary Name Server" sections or numbered entries.

use chrono::{DateTime, NaiveDate, Utc};
use once_cell::sync::Lazy;
use regex::Regex;

use super::{push_bounded, RegistryParser, MAX_NAMESERVERS};
use crate::whois::parser::WhoisResponse;

/// Matches nameserver host lines in both Korean and English sections.
/// Korean: `   호스트이름               : ns1.google.com`
/// English: `   Host Name                : ns1.google.com`
static HOST_NAME_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?im)^\s+(?:Host Name|호스트이름)\s*:\s*(.+)$")
        .expect("Invalid KISA hostname regex")
});

/// Inline fields in the English section
static REGISTRANT_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?im)^Registrant\s*:\s*(.+)$").expect("Invalid KISA registrant regex")
});

static ADMIN_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?im)^Administrative Contact\(AC\)\s*:\s*(.+)$").expect("Invalid KISA admin regex")
});

static AC_EMAIL_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?im)^AC E-Mail\s*:\s*(.+)$").expect("Invalid KISA AC email regex"));

static AC_PHONE_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?im)^AC Phone Number\s*:\s*(.+)$").expect("Invalid KISA AC phone regex")
});

static REGISTERED_DATE_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?im)^Registered Date\s*:\s*(.+)$").expect("Invalid KISA registered date regex")
});

static EXPIRATION_DATE_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?im)^Expiration Date\s*:\s*(.+)$").expect("Invalid KISA expiration date regex")
});

static LAST_UPDATED_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?im)^Last Updated Date\s*:\s*(.+)$")
        .expect("Invalid KISA last updated date regex")
});

static AUTHORIZED_AGENCY_PATTERN: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"(?im)^Authorized Agency\s*:\s*(.+)$")
        .expect("Invalid KISA authorized agency regex")
});

static DNSSEC_PATTERN: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?im)^DNSSEC\s*:\s*(.+)$").expect("Invalid KISA DNSSEC regex"));

/// Parser for .kr domains using the KISA/KRNIC format.
#[derive(Debug, Clone, Default)]
pub struct KisaParser;

impl KisaParser {
    pub fn new() -> Self {
        Self
    }

    /// Parses KISA date format: "YYYY. MM. DD." (with dots and spaces)
    fn parse_kisa_date(date_str: &str) -> Option<DateTime<Utc>> {
        let cleaned = date_str.trim().trim_end_matches('.');

        // KISA uses "YYYY. MM. DD." format
        let normalized = cleaned.replace(". ", "-").replace('.', "");
        if let Ok(d) = NaiveDate::parse_from_str(&normalized, "%Y-%m-%d") {
            return Some(d.and_hms_opt(0, 0, 0)?.and_utc());
        }

        // Also try standard format
        if let Ok(d) = NaiveDate::parse_from_str(cleaned, "%Y-%m-%d") {
            return Some(d.and_hms_opt(0, 0, 0)?.and_utc());
        }

        None
    }
}

impl RegistryParser for KisaParser {
    fn supported_tlds(&self) -> &[&str] {
        &["kr"]
    }

    fn parse(&self, domain: &str, server: &str, raw: &str) -> WhoisResponse {
        let mut nameservers = Vec::new();
        let mut registrant = None;
        let mut registrar = None;
        let mut admin_name = None;
        let mut admin_email = None;
        let mut admin_phone = None;
        let mut creation_date = None;
        let mut expiration_date = None;
        let mut updated_date = None;
        let mut dnssec = None;

        // Extract all nameservers from Host Name fields
        // Use only the English section to avoid duplicates
        let english_section = if let Some(pos) = raw.find("# ENGLISH") {
            &raw[pos..]
        } else {
            raw
        };

        for caps in HOST_NAME_PATTERN.captures_iter(english_section) {
            if let Some(m) = caps.get(1) {
                let ns = m.as_str().trim().to_lowercase();
                push_bounded(&mut nameservers, ns, MAX_NAMESERVERS);
            }
        }

        // If no English section, try the full text
        if nameservers.is_empty() {
            for caps in HOST_NAME_PATTERN.captures_iter(raw) {
                if let Some(m) = caps.get(1) {
                    let ns = m.as_str().trim().to_lowercase();
                    push_bounded(&mut nameservers, ns, MAX_NAMESERVERS);
                }
            }
        }

        // Extract inline fields from English section
        if let Some(caps) = REGISTRANT_PATTERN.captures(raw) {
            if let Some(m) = caps.get(1) {
                let val = m.as_str().trim().to_string();
                if !val.is_empty() {
                    registrant = Some(val);
                }
            }
        }

        if let Some(caps) = ADMIN_PATTERN.captures(raw) {
            if let Some(m) = caps.get(1) {
                let val = m.as_str().trim().to_string();
                if !val.is_empty() {
                    admin_name = Some(val);
                }
            }
        }

        if let Some(caps) = AC_EMAIL_PATTERN.captures(raw) {
            if let Some(m) = caps.get(1) {
                let val = m.as_str().trim().to_string();
                if !val.is_empty() {
                    admin_email = Some(val);
                }
            }
        }

        if let Some(caps) = AC_PHONE_PATTERN.captures(raw) {
            if let Some(m) = caps.get(1) {
                let val = m.as_str().trim().to_string();
                if !val.is_empty() {
                    admin_phone = Some(val);
                }
            }
        }

        if let Some(caps) = REGISTERED_DATE_PATTERN.captures(raw) {
            if let Some(m) = caps.get(1) {
                creation_date = Self::parse_kisa_date(m.as_str());
            }
        }

        if let Some(caps) = EXPIRATION_DATE_PATTERN.captures(raw) {
            if let Some(m) = caps.get(1) {
                expiration_date = Self::parse_kisa_date(m.as_str());
            }
        }

        if let Some(caps) = LAST_UPDATED_PATTERN.captures(raw) {
            if let Some(m) = caps.get(1) {
                updated_date = Self::parse_kisa_date(m.as_str());
            }
        }

        if let Some(caps) = AUTHORIZED_AGENCY_PATTERN.captures(raw) {
            if let Some(m) = caps.get(1) {
                let val = m.as_str().trim().to_string();
                // Strip URL in parens: "Whois Corp.(http://whois.co.kr)" → "Whois Corp."
                let name = val.split('(').next().unwrap_or(&val).trim().to_string();
                if !name.is_empty() {
                    registrar = Some(name);
                }
            }
        }

        if let Some(caps) = DNSSEC_PATTERN.captures(raw) {
            if let Some(m) = caps.get(1) {
                let val = m.as_str().trim();
                dnssec = Some(
                    if val.eq_ignore_ascii_case("unsigned") || val.eq_ignore_ascii_case("미서명")
                    {
                        "unsigned".to_string()
                    } else {
                        "signedDelegation".to_string()
                    },
                );
            }
        }

        WhoisResponse {
            domain: domain.to_string(),
            registrar,
            registrant: registrant.clone(),
            organization: registrant,
            registrant_email: None,
            registrant_phone: None,
            registrant_address: None,
            registrant_country: Some("KR".to_string()),
            admin_name,
            admin_organization: None,
            admin_email,
            admin_phone,
            tech_name: None,
            tech_organization: None,
            tech_email: None,
            tech_phone: None,
            creation_date,
            expiration_date,
            updated_date,
            nameservers,
            status: Vec::new(),
            dnssec,
            whois_server: server.to_string(),
            raw_response: raw.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;

    const SAMPLE_KISA_RESPONSE: &str = r#"query : google.kr


# KOREAN(UTF8)

도메인이름                  : google.kr
등록인                      : 구글코리아유한회사
등록인 주소                 : 서울시 강남구 역삼동 737 강남파이낸스센터 22층
등록인 우편번호             : 135984
책임자                      : Domain Administrator
책임자 전자우편             : dns-admin@google.com
책임자 전화번호             : 82.25319000
등록일                      : 2007. 03. 02.
최근 정보 변경일            : 2010. 10. 04.
사용 종료일                 : 2027. 03. 02.
정보공개여부                : Y
등록대행자                  : (주)후이즈(http://whois.co.kr)
DNSSEC                      : 미서명

1차 네임서버 정보
   호스트이름               : ns1.google.com

2차 네임서버 정보
   호스트이름               : ns2.google.com

네임서버 이름이 .kr이 아닌 경우는 IP주소가 보이지 않습니다.


# ENGLISH

Domain Name                 : google.kr
Registrant                  : Google Korea, LLC
Registrant Address          : 22nd Floor Gangnam Finance Center, 737 Yeoksam-dong Kangnam-ku Seoul
Registrant Zip Code         : 135984
Administrative Contact(AC)  : Domain Administrator
AC E-Mail                   : dns-admin@google.com
AC Phone Number             : 82.25319000
Registered Date             : 2007. 03. 02.
Last Updated Date           : 2010. 10. 04.
Expiration Date             : 2027. 03. 02.
Publishes                   : Y
Authorized Agency           : Whois Corp.(http://whois.co.kr)
DNSSEC                      : unsigned

Primary Name Server
   Host Name                : ns1.google.com

Secondary Name Server
   Host Name                : ns2.google.com


- KISA/KRNIC WHOIS Service -"#;

    #[test]
    fn test_kisa_nameservers() {
        let parser = KisaParser::new();
        let result = parser.parse("google.kr", "whois.kr", SAMPLE_KISA_RESPONSE);

        assert_eq!(result.nameservers.len(), 2);
        assert!(result.nameservers.contains(&"ns1.google.com".to_string()));
        assert!(result.nameservers.contains(&"ns2.google.com".to_string()));
    }

    #[test]
    fn test_kisa_registrant() {
        let parser = KisaParser::new();
        let result = parser.parse("google.kr", "whois.kr", SAMPLE_KISA_RESPONSE);

        assert_eq!(result.registrant, Some("Google Korea, LLC".to_string()));
    }

    #[test]
    fn test_kisa_registrar() {
        let parser = KisaParser::new();
        let result = parser.parse("google.kr", "whois.kr", SAMPLE_KISA_RESPONSE);

        assert_eq!(result.registrar, Some("Whois Corp.".to_string()));
    }

    #[test]
    fn test_kisa_admin_contact() {
        let parser = KisaParser::new();
        let result = parser.parse("google.kr", "whois.kr", SAMPLE_KISA_RESPONSE);

        assert_eq!(result.admin_name, Some("Domain Administrator".to_string()));
        assert_eq!(result.admin_email, Some("dns-admin@google.com".to_string()));
        assert_eq!(result.admin_phone, Some("82.25319000".to_string()));
    }

    #[test]
    fn test_kisa_dates() {
        let parser = KisaParser::new();
        let result = parser.parse("google.kr", "whois.kr", SAMPLE_KISA_RESPONSE);

        assert!(result.creation_date.is_some());
        let creation = result.creation_date.unwrap();
        assert_eq!(creation.year(), 2007);
        assert_eq!(creation.month(), 3);
        assert_eq!(creation.day(), 2);

        assert!(result.expiration_date.is_some());
        let expiry = result.expiration_date.unwrap();
        assert_eq!(expiry.year(), 2027);
        assert_eq!(expiry.month(), 3);
        assert_eq!(expiry.day(), 2);

        assert!(result.updated_date.is_some());
        let updated = result.updated_date.unwrap();
        assert_eq!(updated.year(), 2010);
        assert_eq!(updated.month(), 10);
        assert_eq!(updated.day(), 4);
    }

    #[test]
    fn test_kisa_dnssec() {
        let parser = KisaParser::new();
        let result = parser.parse("google.kr", "whois.kr", SAMPLE_KISA_RESPONSE);

        assert_eq!(result.dnssec, Some("unsigned".to_string()));
    }

    #[test]
    fn test_kisa_country() {
        let parser = KisaParser::new();
        let result = parser.parse("google.kr", "whois.kr", SAMPLE_KISA_RESPONSE);

        assert_eq!(result.registrant_country, Some("KR".to_string()));
    }

    #[test]
    fn test_kisa_date_parsing() {
        assert!(KisaParser::parse_kisa_date("2007. 03. 02.").is_some());
        assert!(KisaParser::parse_kisa_date("2010. 10. 04.").is_some());
    }

    #[test]
    fn test_supported_tlds() {
        let parser = KisaParser::new();
        assert_eq!(parser.supported_tlds(), &["kr"]);
    }
}
