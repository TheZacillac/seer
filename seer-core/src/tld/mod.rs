use serde::{Deserialize, Serialize};

use crate::rdap::RdapClient;
use crate::whois::{get_registry_url, get_whois_server};

/// The full catalog of TLDs seer knows about (sorted, deduplicated). Re-exported
/// from the WHOIS server registry so callers can browse every TLD, not just the
/// ones with a static WHOIS server.
pub use crate::whois::all_tlds;

/// Information about a Top-Level Domain (TLD).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TldInfo {
    /// The normalized TLD (without leading dot).
    pub tld: String,
    /// The WHOIS server responsible for this TLD, if known.
    pub whois_server: Option<String>,
    /// The RDAP base URL from the IANA bootstrap registry, if known.
    pub rdap_url: Option<String>,
    /// The registry website URL for this TLD.
    pub registry_url: Option<String>,
    /// The classification of this TLD (e.g., "generic", "country-code", "sponsored", "infrastructure").
    pub tld_type: String,
}

/// Looks up information about a TLD.
///
/// Resolves WHOIS server, RDAP endpoint, registry URL, and TLD classification.
/// The RDAP URL requires loading IANA bootstrap data (async network call).
///
/// # Arguments
/// * `tld` - The TLD to look up (with or without leading dot, e.g., ".com" or "com")
///
/// # Returns
/// A `TldInfo` struct with all available information about the TLD.
pub async fn lookup_tld(tld: &str) -> TldInfo {
    let tld = tld.trim_start_matches('.').to_lowercase();

    let whois_server = get_whois_server(&tld).map(|s| s.to_string());
    let registry_url = get_registry_url(&tld);
    let tld_type = classify_tld(&tld);

    // Try to get RDAP URL from bootstrap data
    let rdap_client = RdapClient::new();
    let rdap_url = rdap_client.get_rdap_base_url_for_tld(&tld).await;

    TldInfo {
        tld,
        whois_server,
        rdap_url,
        registry_url,
        tld_type,
    }
}

/// Classifies a TLD into its category.
fn classify_tld(tld: &str) -> String {
    if tld.len() == 2 && tld.chars().all(|c| c.is_ascii_alphabetic()) {
        "country-code".to_string()
    } else if ["arpa", "root"].contains(&tld) {
        "infrastructure".to_string()
    } else if [
        "aero", "asia", "cat", "coop", "edu", "gov", "int", "jobs", "mil", "museum", "post", "tel",
        "travel", "xxx",
    ]
    .contains(&tld)
    {
        "sponsored".to_string()
    } else {
        "generic".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_tld_country_code() {
        assert_eq!(classify_tld("uk"), "country-code");
        assert_eq!(classify_tld("de"), "country-code");
        assert_eq!(classify_tld("jp"), "country-code");
    }

    #[test]
    fn test_classify_tld_infrastructure() {
        assert_eq!(classify_tld("arpa"), "infrastructure");
        assert_eq!(classify_tld("root"), "infrastructure");
    }

    #[test]
    fn test_classify_tld_sponsored() {
        assert_eq!(classify_tld("edu"), "sponsored");
        assert_eq!(classify_tld("gov"), "sponsored");
        assert_eq!(classify_tld("museum"), "sponsored");
    }

    #[test]
    fn test_classify_tld_generic() {
        assert_eq!(classify_tld("com"), "generic");
        assert_eq!(classify_tld("net"), "generic");
        assert_eq!(classify_tld("org"), "generic");
        assert_eq!(classify_tld("app"), "generic");
    }

    #[test]
    fn test_classify_tld_numeric_not_country_code() {
        // Two chars but not all alphabetic
        assert_eq!(classify_tld("a1"), "generic");
    }
}
