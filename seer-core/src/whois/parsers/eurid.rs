//! Parser for .eu domains (EURid format).
//!
//! EURid uses a section-based format where nameservers appear under a
//! `Name servers:` header with indented hostnames, optionally followed
//! by IP addresses in parentheses. The same hostname may appear multiple
//! times (once per IP), so deduplication is required.
//!
//! Example EURid response:
//! ```text
//! Domain: europa.eu
//! Script: LATIN
//!
//! Registrant:
//!         NOT DISCLOSED!
//!
//! Registrar:
//!         Name: ClearMedia NV
//!         Website: https://www.clearmedia.be
//!
//! Name servers:
//!         ns1lux.europa.eu (147.67.12.2)
//!         ns1.bt.net
//!         ns2bru.europa.eu (147.67.250.3)
//! ```

use once_cell::sync::Lazy;
use regex::Regex;

use super::RegistryParser;
use crate::whois::parser::WhoisResponse;

static REGISTRANT_SECTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Registrant:\s*$").expect("Invalid EURid registrant regex"));

static TECHNICAL_SECTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Technical:\s*$").expect("Invalid EURid technical regex"));

static REGISTRAR_SECTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Registrar:\s*$").expect("Invalid EURid registrar regex"));

static NAME_SERVERS_SECTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Name servers:\s*$").expect("Invalid EURid name servers regex"));

static KEYS_SECTION: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)^Keys:\s*$").expect("Invalid EURid keys regex"));

/// Parser for .eu domains using the EURid format.
#[derive(Debug, Clone, Default)]
pub struct EuridParser;

impl EuridParser {
    pub fn new() -> Self {
        Self
    }
}

impl RegistryParser for EuridParser {
    fn supported_tlds(&self) -> &[&str] {
        &["eu"]
    }

    fn parse(&self, domain: &str, server: &str, raw: &str) -> WhoisResponse {
        let mut registrar = None;
        let mut registrar_url = None;
        let mut nameservers = Vec::new();
        let mut tech_org = None;
        let mut tech_email = None;
        let mut has_keys = false;

        #[derive(Clone, Copy)]
        enum Section {
            None,
            Registrant,
            Technical,
            Registrar,
            NameServers,
            Keys,
        }

        let mut current_section = Section::None;

        for line in raw.lines() {
            let trimmed = line.trim();

            // Skip comment lines
            if trimmed.starts_with('%') {
                continue;
            }

            // Check section headers
            if REGISTRANT_SECTION.is_match(trimmed) {
                current_section = Section::Registrant;
                continue;
            } else if TECHNICAL_SECTION.is_match(trimmed) {
                current_section = Section::Technical;
                continue;
            } else if REGISTRAR_SECTION.is_match(trimmed) {
                current_section = Section::Registrar;
                continue;
            } else if NAME_SERVERS_SECTION.is_match(trimmed) {
                current_section = Section::NameServers;
                continue;
            } else if KEYS_SECTION.is_match(trimmed) {
                current_section = Section::Keys;
                has_keys = true;
                continue;
            }

            // Empty line ends current section (except nameservers which can span blanks)
            if trimmed.is_empty() {
                match current_section {
                    Section::NameServers if nameservers.is_empty() => {}
                    Section::NameServers => current_section = Section::None,
                    _ => current_section = Section::None,
                }
                continue;
            }

            // Parse indented content
            if line.starts_with(' ') || line.starts_with('\t') {
                match current_section {
                    Section::NameServers => {
                        // Strip trailing IP in parens: "ns1.example.eu (1.2.3.4)" → "ns1.example.eu"
                        let ns = trimmed
                            .split_whitespace()
                            .next()
                            .unwrap_or(trimmed)
                            .to_lowercase();
                        if !ns.is_empty() && !nameservers.contains(&ns) {
                            nameservers.push(ns);
                        }
                    }
                    Section::Registrar => {
                        if let Some(val) = extract_field(trimmed, "Name") {
                            if registrar.is_none() {
                                registrar = Some(val);
                            }
                        } else if let Some(val) = extract_field(trimmed, "Website") {
                            if registrar_url.is_none() {
                                registrar_url = Some(val);
                            }
                        }
                    }
                    Section::Technical => {
                        if let Some(val) = extract_field(trimmed, "Organisation") {
                            if tech_org.is_none() {
                                tech_org = Some(val);
                            }
                        } else if let Some(val) = extract_field(trimmed, "Email") {
                            if tech_email.is_none() {
                                tech_email = Some(val);
                            }
                        }
                    }
                    _ => {}
                }
            } else {
                // Non-indented, non-section-header line
                current_section = Section::None;
            }
        }

        WhoisResponse {
            domain: domain.to_string(),
            registrar,
            registrant: None, // EURid redacts registrant info on port 43
            organization: None,
            registrant_email: None,
            registrant_phone: None,
            registrant_address: None,
            registrant_country: None,
            admin_name: None,
            admin_organization: None,
            admin_email: None,
            admin_phone: None,
            tech_name: None,
            tech_organization: tech_org,
            tech_email,
            tech_phone: None,
            creation_date: None, // EURid doesn't include dates on port 43
            expiration_date: None,
            updated_date: None,
            nameservers,
            status: Vec::new(),
            dnssec: if has_keys {
                Some("signedDelegation".to_string())
            } else {
                None
            },
            whois_server: server.to_string(),
            raw_response: raw.to_string(),
        }
    }
}

fn extract_field(line: &str, key: &str) -> Option<String> {
    let lower_line = line.to_lowercase();
    let lower_key = format!("{}:", key.to_lowercase());
    if lower_line.starts_with(&lower_key) {
        let val = line[key.len() + 1..].trim().to_string();
        if !val.is_empty() {
            return Some(val);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_EURID_RESPONSE: &str = r#"% The WHOIS service offered by EURid and the access to the records
% in the EURid WHOIS database are provided for information purposes
% only.
%
% WHOIS europa.eu
Domain: europa.eu
Script: LATIN

Registrant:
        NOT DISCLOSED!
        Visit www.eurid.eu for the web-based WHOIS.

Technical:
        Organisation: ClearMedia NV
        Language: nl
        Email: support@clearmedia.be

Registrar:
        Name: ClearMedia NV
        Website: https://www.clearmedia.be

Name servers:
        ns1lux.europa.eu (147.67.12.2)
        ns1.bt.net
        ns2bru.europa.eu (147.67.250.3)
        ns4az1.europa.eu (2a05:d018:c5f:3701:cc8a:9177:b28:c034)
        ns4az1.europa.eu (54.154.94.36)
        ans1.cw.net
        ns3lux.europa.eu (147.67.12.4)
        ns3lux.europa.eu (2a01:7080:24:101::2)
        ns2lux.europa.eu (147.67.12.3)
        ns1bru.europa.eu (147.67.250.2)
        ns3bru.europa.eu (147.67.250.4)
        ns3bru.europa.eu (2a01:7080:14:101::2)
        ns2eu.bt.net
        ns4az2.europa.eu (34.255.155.194)
        ns4az2.europa.eu (2a05:d018:c5f:3702:4df4:7b41:c0a1:34e4)
        ans2.cw.net

Keys:
        flags:KSK protocol:3 algorithm:RSA_SHA256 pubKey:AwEAAtest

Please visit www.eurid.eu for more info."#;

    #[test]
    fn test_eurid_nameservers() {
        let parser = EuridParser::new();
        let result = parser.parse("europa.eu", "whois.eu", SAMPLE_EURID_RESPONSE);

        // 16 lines but some duplicates (same host with different IPs)
        assert_eq!(result.nameservers.len(), 12);
        assert!(result.nameservers.contains(&"ns1lux.europa.eu".to_string()));
        assert!(result.nameservers.contains(&"ns1.bt.net".to_string()));
        assert!(result.nameservers.contains(&"ns2bru.europa.eu".to_string()));
        assert!(result.nameservers.contains(&"ns4az1.europa.eu".to_string()));
        assert!(result.nameservers.contains(&"ans1.cw.net".to_string()));
        assert!(result.nameservers.contains(&"ans2.cw.net".to_string()));
        assert!(result.nameservers.contains(&"ns2eu.bt.net".to_string()));
    }

    #[test]
    fn test_eurid_nameserver_dedup() {
        let parser = EuridParser::new();
        let result = parser.parse("europa.eu", "whois.eu", SAMPLE_EURID_RESPONSE);

        // ns3bru.europa.eu appears twice (IPv4 and IPv6) but should only be listed once
        let count = result
            .nameservers
            .iter()
            .filter(|ns| *ns == "ns3bru.europa.eu")
            .count();
        assert_eq!(count, 1);
    }

    #[test]
    fn test_eurid_registrar() {
        let parser = EuridParser::new();
        let result = parser.parse("europa.eu", "whois.eu", SAMPLE_EURID_RESPONSE);

        assert_eq!(result.registrar, Some("ClearMedia NV".to_string()));
    }

    #[test]
    fn test_eurid_tech_contact() {
        let parser = EuridParser::new();
        let result = parser.parse("europa.eu", "whois.eu", SAMPLE_EURID_RESPONSE);

        assert_eq!(result.tech_organization, Some("ClearMedia NV".to_string()));
        assert_eq!(result.tech_email, Some("support@clearmedia.be".to_string()));
    }

    #[test]
    fn test_eurid_dnssec() {
        let parser = EuridParser::new();
        let result = parser.parse("europa.eu", "whois.eu", SAMPLE_EURID_RESPONSE);

        assert_eq!(result.dnssec, Some("signedDelegation".to_string()));
    }

    #[test]
    fn test_eurid_redacted_registrant() {
        let parser = EuridParser::new();
        let result = parser.parse("europa.eu", "whois.eu", SAMPLE_EURID_RESPONSE);

        // EURid redacts registrant on port 43
        assert!(result.registrant.is_none());
    }

    #[test]
    fn test_supported_tlds() {
        let parser = EuridParser::new();
        assert_eq!(parser.supported_tlds(), &["eu"]);
    }
}
