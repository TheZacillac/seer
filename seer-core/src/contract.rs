//! The input and rate-limit contract every network-facing surface shares.
//!
//! seer-api (REST and MCP) and seer-server enforce the same limits; they
//! are defined here once. Python reads them through seer-py's
//! `seer.contract()` and `seer.clean_message()`, so neither server keeps a
//! copy. Error classification lives beside the error type instead:
//! [`crate::ErrorCategory`].

/// Longest domain name accepted: RFC 1035's 253-octet presentation form.
pub const DOMAIN_MAX_LENGTH: usize = 253;

/// Longest nameserver spec accepted; leaves room for a DoH URL
/// (`https://host/path`).
pub const NAMESERVER_MAX_LENGTH: usize = 512;

/// Longest DNS record-type token accepted at the edge.
pub const RECORD_TYPE_MAX_LENGTH: usize = 10;

/// The record-type token rule as a regular expression, for surfaces that
/// publish it in a schema (OpenAPI, MCP). [`is_record_type_token`] is the
/// same rule plus the length cap; a test holds the two together.
pub const RECORD_TYPE_PATTERN: &str = "^[A-Z0-9]+$";

/// Most characters of error text an external surface shows a client.
pub const MESSAGE_MAX_LENGTH: usize = 200;

/// Fan-out width used when a caller does not choose one.
pub const CONCURRENCY_DEFAULT: usize = 10;

/// Widest fan-out a caller or a config file may ask for.
pub const CONCURRENCY_MAX: usize = 50;

// The default must itself be a legal choice.
const _: () = assert!(CONCURRENCY_DEFAULT >= 1 && CONCURRENCY_DEFAULT <= CONCURRENCY_MAX);

/// Whether `token` is a plausible DNS record-type name: 1 to
/// [`RECORD_TYPE_MAX_LENGTH`] ASCII uppercase letters or digits. An edge
/// check only — parsing the name is `RecordType`'s job.
pub fn is_record_type_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= RECORD_TYPE_MAX_LENGTH
        && token
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
}

/// The TLD token rule as a regular expression, for surfaces that publish
/// it or validate with a regex engine. [`is_tld_token`] is the same rule; a
/// test holds the two together.
pub const TLD_TOKEN_PATTERN: &str = r"^\.?[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$";

/// Whether `token` is a plausible TLD: an optional leading dot, then 1 to
/// 63 ASCII letters, digits or hyphens with no leading or trailing hyphen
/// (so punycode A-labels such as `xn--p1ai` pass). An edge check that
/// rejects junk with a clear error; a TLD is a lookup key, never a connect
/// target.
pub fn is_tld_token(token: &str) -> bool {
    let label = token.strip_prefix('.').unwrap_or(token);
    (1..=63).contains(&label.len())
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

/// Makes error text safe to put on the wire: C0 and C1 control characters
/// (CR/LF, NUL, the ESC that starts an ANSI sequence) are removed, then the
/// result is cut to [`MESSAGE_MAX_LENGTH`] characters. Stripping comes
/// first so control-byte padding cannot push visible text past the cap.
pub fn clean_message(message: &str) -> String {
    message
        .chars()
        .filter(|c| !c.is_control())
        .take(MESSAGE_MAX_LENGTH)
        .collect()
}

/// How expensive an operation is to serve, which sets its rate limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CostClass {
    /// One cheap query (a dig, a TLD lookup).
    Light,
    /// One registry or probe round trip (WHOIS, RDAP, SSL).
    Standard,
    /// Several round trips to one target (status, propagation).
    Moderate,
    /// A fan-out to many hosts, or a long walk (trace, takeover, audit).
    Heavy,
}

impl CostClass {
    /// Every cost class, cheapest first.
    pub const ALL: [CostClass; 4] = [
        CostClass::Light,
        CostClass::Standard,
        CostClass::Moderate,
        CostClass::Heavy,
    ];

    /// Requests allowed per minute, per caller.
    pub fn per_minute(self) -> u32 {
        match self {
            CostClass::Light => 60,
            CostClass::Standard => 30,
            CostClass::Moderate => 20,
            CostClass::Heavy => 5,
        }
    }

    /// The lowercase name used as a key by non-Rust consumers.
    pub fn name(self) -> &'static str {
        match self {
            CostClass::Light => "light",
            CostClass::Standard => "standard",
            CostClass::Moderate => "moderate",
            CostClass::Heavy => "heavy",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_type_token_rule_agrees_with_its_pattern() {
        let pattern = regex::Regex::new(RECORD_TYPE_PATTERN).unwrap();
        for token in ["A", "AAAA", "TYPE65", "a", "A B", "A-B", "", "A\n", "Ä"] {
            assert_eq!(
                is_record_type_token(token),
                pattern.is_match(token),
                "rule and pattern disagree on {token:?}"
            );
        }
    }

    #[test]
    fn record_type_token_is_length_capped() {
        assert!(is_record_type_token(&"A".repeat(RECORD_TYPE_MAX_LENGTH)));
        assert!(!is_record_type_token(
            &"A".repeat(RECORD_TYPE_MAX_LENGTH + 1)
        ));
    }

    #[test]
    fn clean_message_strips_control_characters() {
        // CR/LF, NUL, the ESC of an ANSI sequence, DEL and a C1 control.
        let dirty = "ok\r\n\0\x1b[31mred\x7f\u{9b}end";
        assert_eq!(clean_message(dirty), "ok[31mredend");
    }

    #[test]
    fn clean_message_strips_before_capping() {
        // Padding with control bytes must not push visible text past the cap.
        let padded = format!("{}{}", "\x00".repeat(500), "x".repeat(300));
        let cleaned = clean_message(&padded);
        assert_eq!(cleaned, "x".repeat(MESSAGE_MAX_LENGTH));
    }

    #[test]
    fn clean_message_caps_by_character() {
        // 300 two-byte characters: the cap counts characters and never
        // splits one.
        let cleaned = clean_message(&"é".repeat(300));
        assert_eq!(cleaned.chars().count(), MESSAGE_MAX_LENGTH);
        assert!(cleaned.chars().all(|c| c == 'é'));
    }

    #[test]
    fn cost_classes_carry_the_published_limits() {
        let table = [
            (CostClass::Light, "light", 60),
            (CostClass::Standard, "standard", 30),
            (CostClass::Moderate, "moderate", 20),
            (CostClass::Heavy, "heavy", 5),
        ];
        assert_eq!(CostClass::ALL.len(), table.len());
        for (class, name, per_minute) in table {
            assert!(CostClass::ALL.contains(&class));
            assert_eq!(class.name(), name);
            assert_eq!(class.per_minute(), per_minute);
        }
    }

    #[test]
    fn tld_token_rule_agrees_with_its_pattern() {
        let pattern = regex::Regex::new(TLD_TOKEN_PATTERN).unwrap();
        let label_63 = "a".repeat(63);
        let label_64 = "a".repeat(64);
        let dotted_63 = format!(".{label_63}");
        for token in [
            "com", ".com", "COM", "xn--p1ai", "a", "a1", "co.uk", "-a", "a-", "", ".", "..com",
            "a b", "é", "a\n", &label_63, &label_64, &dotted_63,
        ] {
            assert_eq!(
                is_tld_token(token),
                pattern.is_match(token),
                "rule and pattern disagree on {token:?}"
            );
        }
        assert!(is_tld_token("com"));
        assert!(is_tld_token(".xn--p1ai"));
        assert!(!is_tld_token("co.uk"));
        assert!(!is_tld_token(&label_64));
    }

    #[test]
    fn limits_match_the_published_values() {
        assert_eq!(DOMAIN_MAX_LENGTH, 253);
        assert_eq!(NAMESERVER_MAX_LENGTH, 512);
        assert_eq!(RECORD_TYPE_MAX_LENGTH, 10);
        assert_eq!(MESSAGE_MAX_LENGTH, 200);
    }
}
