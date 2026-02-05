//! Generic WHOIS parser for standard formats.
//!
//! This parser uses the original regex-based parsing logic and serves
//! as a fallback when no specialized parser is available for a TLD.

use super::RegistryParser;
use crate::whois::parser::WhoisResponse;

/// Generic WHOIS parser that handles standard formats.
///
/// This parser uses regex patterns that work for most WHOIS responses,
/// including common gTLD and ccTLD formats.
#[derive(Debug, Clone, Default)]
pub struct GenericParser;

impl GenericParser {
    pub fn new() -> Self {
        Self
    }
}

impl RegistryParser for GenericParser {
    fn supported_tlds(&self) -> &[&str] {
        // Empty - this is the fallback parser
        &[]
    }

    fn parse(&self, domain: &str, server: &str, raw: &str) -> WhoisResponse {
        // Delegate to the original parsing logic
        WhoisResponse::parse_internal(domain, server, raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generic_parser_basic() {
        let parser = GenericParser::new();
        let raw = r#"
Domain Name: example.com
Registrar: Example Registrar, Inc.
Creation Date: 2020-01-15T00:00:00Z
Expiration Date: 2025-01-15T00:00:00Z
Name Server: ns1.example.com
Name Server: ns2.example.com
"#;
        let result = parser.parse("example.com", "whois.example.com", raw);

        assert_eq!(result.domain, "example.com");
        assert_eq!(result.registrar, Some("Example Registrar, Inc.".to_string()));
        assert_eq!(result.nameservers.len(), 2);
    }
}
