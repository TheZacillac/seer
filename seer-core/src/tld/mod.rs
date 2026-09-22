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

/// Internationalized country-code TLDs (IANA root-zone type
/// "country-code"), as A-labels, sorted for binary search. ASCII ccTLDs are
/// recognised by shape (two letters); IDN ccTLDs have no such shape, so they
/// need an explicit list.
const IDN_CCTLDS: &[&str] = &[
    "xn--2scrj9c",            // ಭಾರತ (India)
    "xn--3e0b707e",           // 한국 (Korea)
    "xn--3hcrj9c",            // ଭାରତ (India)
    "xn--45br5cyl",           // ভাৰত (India)
    "xn--45brj9c",            // ভারত (India)
    "xn--4dbrk0ce",           // ישראל (Israel)
    "xn--54b7fta0cc",         // বাংলা (Bangladesh)
    "xn--80ao21a",            // қаз (Kazakhstan)
    "xn--90a3ac",             // срб (Serbia)
    "xn--90ae",               // бг (Bulgaria)
    "xn--90ais",              // бел (Belarus)
    "xn--clchc0ea0b2g2a9gcd", // சிங்கப்பூர் (Singapore)
    "xn--d1alf",              // мкд (North Macedonia)
    "xn--e1a4c",              // ею (EU)
    "xn--fiqs8s",             // 中国 (China)
    "xn--fiqz9s",             // 中國 (China)
    "xn--fpcrj9c3d",          // భారత్ (India)
    "xn--fzc2c9e2c",          // ලංකා (Sri Lanka)
    "xn--gecrj9c",            // ભારત (India)
    "xn--h2breg3eve",         // भारतम् (India)
    "xn--h2brj9c",            // भारत (India)
    "xn--h2brj9c8c",          // भारोत (India)
    "xn--j1amh",              // укр (Ukraine)
    "xn--j6w193g",            // 香港 (Hong Kong)
    "xn--kprw13d",            // 台湾 (Taiwan)
    "xn--kpry57d",            // 台灣 (Taiwan)
    "xn--l1acc",              // мон (Mongolia)
    "xn--lgbbat1ad8j",        // الجزائر (Algeria)
    "xn--mgb9awbf",           // عمان (Oman)
    "xn--mgba3a4f16a",        // ایران (Iran)
    "xn--mgbaam7a8h",         // امارات (UAE)
    "xn--mgbah1a3hjkrd",      // موريتانيا (Mauritania)
    "xn--mgbai9azgqp6j",      // پاکستان (Pakistan)
    "xn--mgbayh7gpa",         // الاردن (Jordan)
    "xn--mgbbh1a",            // بارت (India)
    "xn--mgbbh1a71e",         // بھارت (India)
    "xn--mgbc0a9azcg",        // المغرب (Morocco)
    "xn--mgbcpq6gpa1a",       // البحرين (Bahrain)
    "xn--mgberp4a5d4ar",      // السعودية (Saudi Arabia)
    "xn--mgbgu82a",           // ڀارت (India)
    "xn--mgbpl2fh",           // سودان (Sudan)
    "xn--mgbtx2b",            // عراق (Iraq)
    "xn--mgbx4cd0ab",         // مليسيا (Malaysia)
    "xn--mix891f",            // 澳門 (Macao)
    "xn--node",               // გე (Georgia)
    "xn--o3cw4h",             // ไทย (Thailand)
    "xn--ogbpf8fl",           // سورية (Syria)
    "xn--p1ai",               // рф (Russia)
    "xn--pgbs0dh",            // تونس (Tunisia)
    "xn--q7ce6a",             // ລາວ (Laos)
    "xn--qxa6a",              // ευ (EU)
    "xn--qxam",               // ελ (Greece)
    "xn--rvc1e0am3e",         // ഭാരതം (India)
    "xn--s9brj9c",            // ਭਾਰਤ (India)
    "xn--wgbh1c",             // مصر (Egypt)
    "xn--wgbl6a",             // قطر (Qatar)
    "xn--xkc2al3hye2a",       // இலங்கை (Sri Lanka)
    "xn--xkc2dl3a5ee0h",      // இந்தியா (India)
    "xn--y9a3aq",             // հայ (Armenia)
    "xn--yfro4i67o",          // 新加坡 (Singapore)
    "xn--ygbi2ammx",          // فلسطين (Palestine)
];

/// Classifies a TLD into its category. Accepts the Unicode (U-label) or
/// punycode (A-label) form of an IDN TLD.
fn classify_tld(tld: &str) -> String {
    let tld = if tld.is_ascii() {
        tld.to_ascii_lowercase()
    } else {
        crate::validation::domain_to_ascii(tld).unwrap_or_else(|_| tld.to_lowercase())
    };
    let tld = tld.as_str();
    if (tld.len() == 2 && tld.chars().all(|c| c.is_ascii_alphabetic()))
        || IDN_CCTLDS.binary_search(&tld).is_ok()
    {
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
    fn test_classify_tld_idn_country_code() {
        // Punycode and Unicode forms alike.
        for tld in [
            "xn--p1ai",
            "рф",
            "xn--fiqs8s",
            "中国",
            "xn--3e0b707e",
            "한국",
            "xn--4dbrk0ce",
            "ישראל",
            "XN--P1AI",
        ] {
            assert_eq!(classify_tld(tld), "country-code", "{tld}");
        }
        // IDN gTLDs stay generic.
        for tld in [
            "xn--80asehdb",
            "онлайн",
            "xn--q9jyb4c",
            "みんな",
            "xn--fiq228c5hs",
        ] {
            assert_eq!(classify_tld(tld), "generic", "{tld}");
        }
    }

    /// The IDN ccTLD list must stay sorted (binary search) and contain only
    /// real TLDs — every entry is in the full catalog, which catches typos.
    #[test]
    fn idn_cctld_list_is_sorted_and_in_catalog() {
        for w in IDN_CCTLDS.windows(2) {
            assert!(w[0] < w[1], "IDN_CCTLDS not sorted at {w:?}");
        }
        let catalog = all_tlds();
        for tld in IDN_CCTLDS {
            assert!(
                catalog.binary_search(tld).is_ok(),
                ".{tld} is not a known TLD"
            );
        }
    }

    #[test]
    fn test_classify_tld_numeric_not_country_code() {
        // Two chars but not all alphabetic
        assert_eq!(classify_tld("a1"), "generic");
    }
}
