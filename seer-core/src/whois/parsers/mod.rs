//! Registry-specific WHOIS response parsers.
//!
//! This module provides a parser registry system that allows for TLD-specific
//! parsing of WHOIS responses. Different registries use different formats,
//! field names, and date formats, so having specialized parsers improves
//! data extraction reliability.

mod denic;
mod generic;
mod nominet;

use once_cell::sync::Lazy;

use super::parser::WhoisResponse;
pub use denic::DenicParser;
pub use generic::GenericParser;
pub use nominet::NominetParser;

/// Trait for registry-specific WHOIS parsers.
///
/// Implementors of this trait can provide specialized parsing logic for
/// specific TLDs that don't follow the standard WHOIS format.
pub trait RegistryParser: Send + Sync {
    /// Returns the TLDs this parser handles.
    fn supported_tlds(&self) -> &[&str];

    /// Parses a raw WHOIS response into a structured response.
    fn parse(&self, domain: &str, server: &str, raw: &str) -> WhoisResponse;
}

/// Registry of all available parsers.
///
/// The registry maintains a list of specialized parsers and falls back
/// to the generic parser when no specialized parser is available.
pub struct ParserRegistry {
    parsers: Vec<Box<dyn RegistryParser>>,
    fallback: GenericParser,
}

impl ParserRegistry {
    /// Creates a new parser registry with all known parsers.
    pub fn new() -> Self {
        Self {
            parsers: vec![
                Box::new(DenicParser::new()),   // .de
                Box::new(NominetParser::new()), // .uk, .co.uk
            ],
            fallback: GenericParser::new(),
        }
    }

    /// Parses a WHOIS response using the appropriate parser for the TLD.
    ///
    /// This method first checks if any specialized parser handles the TLD,
    /// and falls back to the generic parser if not.
    pub fn parse(&self, domain: &str, server: &str, raw: &str) -> WhoisResponse {
        // Extract TLD (and second-level TLD for ccSLDs like .co.uk)
        let tld = extract_tld(domain);
        let sld_tld = extract_second_level_tld(domain);

        // Try to find a specialized parser
        for parser in &self.parsers {
            let supported = parser.supported_tlds();
            // Check for exact second-level TLD match first (e.g., "co.uk")
            if let Some(sld) = &sld_tld {
                if supported.contains(&sld.as_str()) {
                    return parser.parse(domain, server, raw);
                }
            }
            // Then check for TLD match (e.g., "uk")
            if let Some(tld) = &tld {
                if supported.contains(&tld.as_str()) {
                    return parser.parse(domain, server, raw);
                }
            }
        }

        // Fall back to generic parser
        self.fallback.parse(domain, server, raw)
    }
}

impl Default for ParserRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Global parser registry instance.
pub static PARSER_REGISTRY: Lazy<ParserRegistry> = Lazy::new(ParserRegistry::new);

/// Extracts the TLD from a domain name.
fn extract_tld(domain: &str) -> Option<String> {
    domain.rsplit('.').next().map(|s| s.to_lowercase())
}

/// Extracts the second-level TLD from a domain name (e.g., "co.uk" from "example.co.uk").
fn extract_second_level_tld(domain: &str) -> Option<String> {
    let parts: Vec<&str> = domain.rsplit('.').collect();
    if parts.len() >= 2 {
        Some(format!("{}.{}", parts[1].to_lowercase(), parts[0].to_lowercase()))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_tld() {
        assert_eq!(extract_tld("example.com"), Some("com".to_string()));
        assert_eq!(extract_tld("example.co.uk"), Some("uk".to_string()));
        assert_eq!(extract_tld("example.de"), Some("de".to_string()));
    }

    #[test]
    fn test_extract_second_level_tld() {
        assert_eq!(
            extract_second_level_tld("example.co.uk"),
            Some("co.uk".to_string())
        );
        assert_eq!(
            extract_second_level_tld("example.com"),
            Some("example.com".to_string())
        );
    }

    #[test]
    fn test_parser_registry_selects_denic_for_de() {
        let registry = ParserRegistry::new();
        // Just test that it doesn't panic
        let result = registry.parse("example.de", "whois.denic.de", "Domain: example.de\nStatus: connect");
        assert_eq!(result.domain, "example.de");
    }

    #[test]
    fn test_parser_registry_selects_nominet_for_uk() {
        let registry = ParserRegistry::new();
        let result = registry.parse("example.co.uk", "whois.nic.uk", "Domain name:\n    example.co.uk");
        assert_eq!(result.domain, "example.co.uk");
    }

    #[test]
    fn test_parser_registry_uses_generic_for_unknown() {
        let registry = ParserRegistry::new();
        let result = registry.parse("example.com", "whois.verisign-grs.com", "Domain Name: example.com");
        assert_eq!(result.domain, "example.com");
    }
}
