use std::collections::HashSet;

use chrono::{DateTime, FixedOffset, Utc};
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};

/// Pre-compiled regexes for WHOIS field extraction.
static REGISTRAR_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Registrar:\s*(.+)").expect("Invalid regex for Registrar"),
        Regex::new(r"(?i)Registrar Name:\s*(.+)").expect("Invalid regex for Registrar Name"),
        Regex::new(r"(?i)Sponsoring Registrar:\s*(.+)")
            .expect("Invalid regex for Sponsoring Registrar"),
    ]
});

static REGISTRANT_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Registrant Name:\s*(.+)").expect("Invalid regex for Registrant Name"),
        Regex::new(r"(?i)Registrant:\s*(.+)").expect("Invalid regex for Registrant"),
    ]
});

static ORGANIZATION_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Registrant Organization:\s*(.+)")
            .expect("Invalid regex for Registrant Organization"),
        // Anchor the bare/ambiguous org labels to the start of a line (allowing
        // indentation) so they cannot match the "Organization:" substring
        // inside "Admin Organization:" / "Tech Organization:" lines and thereby
        // attribute another contact's org to the registrant.
        Regex::new(r"(?im)^[ \t]*Organization:\s*(.+)").expect("Invalid regex for Organization"),
        Regex::new(r"(?im)^[ \t]*org-name:\s*(.+)").expect("Invalid regex for org-name"),
        Regex::new(r"(?im)^[ \t]*Org Name:\s*(.+)").expect("Invalid regex for Org Name"),
    ]
});

static CREATION_DATE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Creation Date:\s*(.+)").expect("Invalid regex for Creation Date"),
        Regex::new(r"(?i)Created Date:\s*(.+)").expect("Invalid regex for Created Date"),
        Regex::new(r"(?i)Created On:\s*(.+)").expect("Invalid regex for Created On"),
        Regex::new(r"(?i)Created:\s*(.+)").expect("Invalid regex for Created"),
        Regex::new(r"(?i)Registration Date:\s*(.+)").expect("Invalid regex for Registration Date"),
        Regex::new(r"(?i)Domain Registration Date:\s*(.+)")
            .expect("Invalid regex for Domain Registration Date"),
        // Punktum (.dk) style: `Registered:           2018-01-25`
        Regex::new(r"(?im)^\s*Registered:\s*(.+)$").expect("Invalid regex for Registered"),
    ]
});

static EXPIRATION_DATE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)(?:Registry )?Expir(?:y|ation) Date:\s*(.+)")
            .expect("Invalid regex for Expiry/Expiration Date"),
        Regex::new(r"(?i)Expiration Date:\s*(.+)").expect("Invalid regex for Expiration Date"),
        Regex::new(r"(?i)Expires On:\s*(.+)").expect("Invalid regex for Expires On"),
        Regex::new(r"(?i)Expires:\s*(.+)").expect("Invalid regex for Expires"),
        Regex::new(r"(?i)Expiry Date:\s*(.+)").expect("Invalid regex for Expiry Date"),
        Regex::new(r"(?i)paid-till:\s*(.+)").expect("Invalid regex for paid-till"),
    ]
});

static UPDATED_DATE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Updated Date:\s*(.+)").expect("Invalid regex for Updated Date"),
        Regex::new(r"(?i)Last Updated On:\s*(.+)").expect("Invalid regex for Last Updated On"),
        Regex::new(r"(?i)Last Modified:\s*(.+)").expect("Invalid regex for Last Modified"),
        Regex::new(r"(?i)Last Update:\s*(.+)").expect("Invalid regex for Last Update"),
        Regex::new(r"(?i)Modified:\s*(.+)").expect("Invalid regex for Modified"),
    ]
});

static DNSSEC_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)DNSSEC:\s*(.+)").expect("Invalid regex for DNSSEC"),
        Regex::new(r"(?i)DNSSEC Status:\s*(.+)").expect("Invalid regex for DNSSEC Status"),
    ]
});

static NAMESERVER_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Name Server:\s*(.+)").expect("Invalid regex for Name Server"),
        Regex::new(r"(?i)Nameserver:\s*(.+)").expect("Invalid regex for Nameserver"),
        Regex::new(r"(?i)nserver:\s*(.+)").expect("Invalid regex for nserver"),
        Regex::new(r"(?im)^NS:\s+(.+)$").expect("Invalid regex for NS"),
        // Punktum (.dk) lists nameservers as `Hostname:` lines under a
        // `Nameservers` heading. Anchored to line start to avoid matching
        // hostname mentions inside prose.
        Regex::new(r"(?im)^\s*Hostname:\s*(.+)$").expect("Invalid regex for Hostname"),
    ]
});

static REGISTRANT_EMAIL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Registrant Email:\s*(.+)").expect("Invalid regex for Registrant Email"),
        Regex::new(r"(?i)Registrant E-mail:\s*(.+)").expect("Invalid regex for Registrant E-mail"),
    ]
});

static REGISTRANT_PHONE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Registrant Phone:\s*(.+)").expect("Invalid regex for Registrant Phone"),
        Regex::new(r"(?i)Registrant Tel:\s*(.+)").expect("Invalid regex for Registrant Tel"),
    ]
});

static REGISTRANT_ADDRESS_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Registrant Street:\s*(.+)").expect("Invalid regex for Registrant Street"),
        Regex::new(r"(?i)Registrant Address:\s*(.+)")
            .expect("Invalid regex for Registrant Address"),
    ]
});

static REGISTRANT_COUNTRY_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![Regex::new(r"(?i)Registrant Country:\s*(.+)")
        .expect("Invalid regex for Registrant Country")]
});

static ADMIN_NAME_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Admin Name:\s*(.+)").expect("Invalid regex for Admin Name"),
        Regex::new(r"(?i)Administrative Contact Name:\s*(.+)")
            .expect("Invalid regex for Administrative Contact Name"),
    ]
});

static ADMIN_ORG_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![Regex::new(r"(?i)Admin Organization:\s*(.+)")
        .expect("Invalid regex for Admin Organization")]
});

static ADMIN_EMAIL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Admin Email:\s*(.+)").expect("Invalid regex for Admin Email"),
        Regex::new(r"(?i)Admin E-mail:\s*(.+)").expect("Invalid regex for Admin E-mail"),
    ]
});

static ADMIN_PHONE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Admin Phone:\s*(.+)").expect("Invalid regex for Admin Phone"),
        Regex::new(r"(?i)Admin Tel:\s*(.+)").expect("Invalid regex for Admin Tel"),
    ]
});

static TECH_NAME_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Tech Name:\s*(.+)").expect("Invalid regex for Tech Name"),
        Regex::new(r"(?i)Technical Contact Name:\s*(.+)")
            .expect("Invalid regex for Technical Contact Name"),
    ]
});

static TECH_ORG_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![Regex::new(r"(?i)Tech Organization:\s*(.+)").expect("Invalid regex for Tech Organization")]
});

static TECH_EMAIL_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Tech Email:\s*(.+)").expect("Invalid regex for Tech Email"),
        Regex::new(r"(?i)Tech E-mail:\s*(.+)").expect("Invalid regex for Tech E-mail"),
    ]
});

static TECH_PHONE_PATTERNS: Lazy<Vec<Regex>> = Lazy::new(|| {
    vec![
        Regex::new(r"(?i)Tech Phone:\s*(.+)").expect("Invalid regex for Tech Phone"),
        Regex::new(r"(?i)Tech Tel:\s*(.+)").expect("Invalid regex for Tech Tel"),
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
    // Suppressed from default serialization: the raw response is up to 1 MB of
    // attacker-controlled content from third-party registries/registrars. It
    // leaking into API/MCP JSON output creates a prompt-injection vector for
    // downstream LLM consumers. The field is still populated internally for
    // is_available() / indicates_not_found() scanning and for callers that
    // access it directly via struct field.
    //
    // `default` is required alongside `skip_serializing`: without it, a
    // round-trip through serialized JSON (e.g. lookup history persistence,
    // the lookup cache) fails to deserialize with "missing field
    // `raw_response`", because—unlike `Option`—a bare `String` is not
    // defaulted on absence. The skip keeps it out of the JSON; the default
    // lets it read back as empty.
    #[serde(skip_serializing, default)]
    pub raw_response: String,
}

impl WhoisResponse {
    /// Parses a WHOIS response using the parser registry.
    ///
    /// This method delegates to specialized parsers for known TLDs
    /// and falls back to the generic parser otherwise.
    pub fn parse(domain: &str, whois_server: &str, raw: &str) -> Self {
        super::parsers::PARSER_REGISTRY.parse(domain, whois_server, raw)
    }

    /// Internal parsing using the generic regex-based approach.
    ///
    /// This is called by the GenericParser and can be overridden
    /// by specialized parsers for specific TLDs.
    pub fn parse_internal(domain: &str, whois_server: &str, raw: &str) -> Self {
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
        // Extract the raw date strings first so the registry's date order can
        // be inferred from any unambiguous one before parsing the ambiguous
        // ones (issue #47). A registry is internally consistent, so the order
        // revealed by one date applies to all dates in the response.
        let creation_str = extract_field_with_patterns(raw, &CREATION_DATE_PATTERNS);
        let expiration_str = extract_field_with_patterns(raw, &EXPIRATION_DATE_PATTERNS);
        let updated_str = extract_field_with_patterns(raw, &UPDATED_DATE_PATTERNS);
        let date_order = infer_date_order(
            [&creation_str, &expiration_str, &updated_str]
                .into_iter()
                .flatten()
                .map(String::as_str),
        )
        .unwrap_or(DateOrder::DayFirst);
        let creation_date = creation_str
            .as_deref()
            .and_then(|s| parse_date_with_order(s, date_order));
        let expiration_date = expiration_str
            .as_deref()
            .and_then(|s| parse_date_with_order(s, date_order));
        let updated_date = updated_str
            .as_deref()
            .and_then(|s| parse_date_with_order(s, date_order));
        let nameservers = extract_nameservers(raw);
        let status = extract_status_top_level(raw);
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

    /// Returns true if the response contains the core registration fields
    /// that registries typically provide (registrar, dates, nameservers).
    /// When true, following the registrar referral can be skipped since the
    /// additional detail (contact info) is usually GDPR-redacted anyway.
    ///
    /// Some registries (NIC.LV, SIDN/.nl) intentionally omit creation/expiry
    /// from their WHOIS, so accept a non-empty `status` field as an
    /// alternative registry signal alongside registrar + nameservers — this
    /// avoids a wasted referral attempt on every lookup for those TLDs.
    pub fn has_core_data(&self) -> bool {
        let has_dates_or_status = self.creation_date.is_some()
            || self.expiration_date.is_some()
            || !self.status.is_empty();
        self.registrar.is_some() && has_dates_or_status && !self.nameservers.is_empty()
    }

    /// Returns true when the registry's WHOIS server replied with a
    /// service-level "this TLD is not served here" / malformed-query sentinel
    /// instead of domain data — i.e. there is no usable port-43 WHOIS for this
    /// query. This is common for Identity Digital RDAP-only TLDs (.email,
    /// .life, .ninja, …) whose `whois.nic.<tld>` host answers "TLD is not
    /// supported." to every query and whose RDAP advertises `port43: null`.
    ///
    /// Distinct from [`is_available`](Self::is_available) (the domain is
    /// unregistered) and from a thin-but-valid record: it only fires when no
    /// registration field was extracted AND the body matches a known
    /// service-error sentinel at the start of a line.
    pub fn registry_unavailable(&self) -> bool {
        // Only meaningful when we extracted no registration data at all — a
        // record with a registrar / dates / nameservers / status is real data,
        // never a service error.
        if self.registrar.is_some()
            || self.creation_date.is_some()
            || self.expiration_date.is_some()
            || !self.nameservers.is_empty()
            || !self.status.is_empty()
        {
            return false;
        }
        // Match known service-error sentinels at the start of a (trimmed) line,
        // mirroring `indicates_not_found`'s anchoring to avoid false positives
        // from TOS boilerplate that may quote these phrases.
        const SERVICE_ERROR_SENTINELS: &[&str] = &[
            "tld is not supported",
            "this tld is not",
            "malformed request",
            "invalid query",
            "no whois server is known",
            "this server does not",
        ];
        // Registries retiring port-43 WHOIS under ICANN's RDAP transition
        // (e.g. GMO Registry, May 2026) answer every query with a prose
        // retirement notice; the phrase can sit mid-sentence, so it is
        // matched with contains() rather than the line-start sentinels.
        const SERVICE_RETIRED_PHRASES: &[&str] =
            &["whois service has been retired", "whois has been retired"];
        let lower = self.raw_response.to_lowercase();
        lower.lines().any(|line| {
            let t = line.trim_start();
            SERVICE_ERROR_SENTINELS.iter().any(|s| t.starts_with(s))
                || SERVICE_RETIRED_PHRASES.iter().any(|s| t.contains(s))
        })
    }

    pub fn is_available(&self) -> bool {
        // A response carrying concrete registration data is registered, full
        // stop — never let an unanchored substring match (a "not found" /
        // "object not found" fragment buried in an abuse-contact line, notice,
        // or registrant value) flip a registered domain to "available". This
        // guards the H6 false-positive class without having to anchor every
        // pattern (which would regress legitimate mid-line phrasings like
        // TWNIC "Domain not found." or HKIRC "...has not been registered.").
        if self.registrar.is_some()
            || self.creation_date.is_some()
            || self.expiration_date.is_some()
            || !self.nameservers.is_empty()
        {
            return false;
        }

        // Scan the full response line-by-line (excluding empty lines). Some
        // registries (TWNIC, JPRS, NIC.br) prepend 3-4 notice lines before the
        // "no match" line, which would escape a small take(N) window.
        //
        // Comment markers are STRIPPED rather than skipped: many ccTLD
        // registries print the verdict itself on a comment line (AFNIC
        // "%% NOT FOUND", NORID "% No match", CZ.NIC "%ERROR:101: no entries
        // found", RESTENA "% No such domain" — captured live 2026-07). The
        // word-count gate and the non-availability veto below still shield
        // against TOS prose on those same comment lines.
        //
        // Stream the scan line-by-line — avoids the ~1 MB `Vec<&str>` +
        // ~1 MB joined `String` the previous implementation allocated for
        // every call. Each line's lowercase form is a fresh small `String`
        // (the size of one line, not the whole body) which is dropped at
        // the end of the iteration.
        for line in self.raw_response.lines() {
            let content = line.trim().trim_start_matches(['%', '#']).trim_start();
            if content.is_empty() {
                continue;
            }
            // Normalize internal whitespace (tabs, runs of spaces) to single
            // spaces before matching. Registries like DNS Belgium print
            // "Status:\tAVAILABLE" with a tab, which would otherwise slip
            // past space-delimited patterns such as "status: available".
            let lower = content.to_lowercase();
            let words: Vec<&str> = lower.split_whitespace().collect();
            let normalized = words.join(" ");
            // A line that negates or refuses availability is never an
            // availability indicator, even when it contains an availability
            // substring (e.g. "available for registration" inside "not
            // available for registration", or "no data found" inside a
            // rate-limit banner). Skip it BEFORE the positive match so the
            // unanchored contains() cannot invert a refused/reserved name into
            // "available" (issue #45).
            if NON_AVAILABILITY_PATTERNS
                .iter()
                .any(|p| normalized.contains(p))
            {
                continue;
            }
            // Sentence-form verdicts (KISA, EDUCAUSE, NASK) run past the word
            // gate; they are matched anchored at line start instead, which a
            // footer merely *quoting* the phrase mid-sentence cannot satisfy.
            if AVAILABILITY_SENTENCE_PATTERNS
                .iter()
                .any(|p| normalized.starts_with(p))
            {
                return true;
            }
            // Availability indicators are short status lines — the longest
            // known registry phrasing ("No information was found matching
            // that query.") is 7 words. Anything longer is prose (a TOS or
            // notice footer) that may merely quote a phrase like "not found"
            // or "does not exist"; skipping it avoids flipping a registered
            // (but thin, fieldless) response to "available". The H6 guard
            // above already covers responses that DO carry registration data.
            if words.len() > MAX_STATUS_LINE_WORDS {
                continue;
            }
            if AVAILABILITY_PATTERNS.iter().any(|p| normalized.contains(p)) {
                return true;
            }
            // SIDN (.nl) / SETAR (.aw) style "<domain> is free": suffix-anchored
            // so prose like "registration is free of charge" cannot match.
            if normalized.ends_with(" is free") {
                return true;
            }
        }
        false
    }

    /// Checks if the response indicates the registrar doesn't have data for this domain.
    /// This is different from is_available() - the domain may exist at the registry level
    /// but the referral registrar may not have data for it.
    ///
    /// Matches patterns only at the start of a (trimmed) line to avoid false
    /// positives from TOS footer boilerplate that may quote these phrases.
    pub fn indicates_not_found(&self) -> bool {
        let lower = self.raw_response.to_lowercase();
        lower.lines().any(|line| {
            let t = line.trim_start();
            NOT_FOUND_PATTERNS.iter().any(|p| t.starts_with(p))
        })
    }

    /// Returns true when the WHOIS body explicitly *refuses*, *throttles*, or
    /// *negates* availability rather than answering it: a rate-limit / quota /
    /// access-denied banner, a port-43 refusal, a reserved/blocked status, or an
    /// explicit "not available for registration". Used by the availability
    /// fallback ([`crate::availability`]) to route such bodies to an
    /// inconclusive verdict instead of guessing "available"/"registered" from
    /// weaker signals like DNS presence.
    ///
    /// Distinct from [`is_available`](Self::is_available) (a conclusive
    /// "no match") and [`registry_unavailable`](Self::registry_unavailable)
    /// (the TLD has no usable port-43 WHOIS server at all). Scans every
    /// non-comment line (no word-count gate) so a sentence-form refusal like
    /// SWITCH's "Requests of this client are not permitted." is caught.
    pub fn indicates_registry_refusal(&self) -> bool {
        for line in self.raw_response.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('%') {
                continue;
            }
            let lower = trimmed.to_lowercase();
            let normalized = lower.split_whitespace().collect::<Vec<_>>().join(" ");
            if NON_AVAILABILITY_PATTERNS
                .iter()
                .any(|p| normalized.contains(p))
            {
                return true;
            }
        }
        false
    }
}

/// Maximum word count for a line to be considered an availability *status*
/// line rather than prose. Registry "not found" phrasings are short (the
/// longest observed is 7 words); TOS/notice footers that merely quote such
/// phrases run much longer. Lines above this bound are ignored by
/// `is_available()` so footer prose can't flip a thin response to available.
const MAX_STATUS_LINE_WORDS: usize = 10;

/// Patterns indicating a domain is available (unregistered).
/// Matched case-insensitively via `contains()` on short status lines only
/// (see `MAX_STATUS_LINE_WORDS`).
const AVAILABILITY_PATTERNS: &[&str] = &[
    "no match for",
    "no match",
    "not found",
    "no data found",
    "no entries found",
    "domain not found",
    "available for registration",
    "not registered",
    // HKIRC (.hk / .香港) phrases it "has not been registered" — the bare
    // "not registered" above does not cover the interposed "been".
    "not been registered",
    "status: available",
    "status: free",
    "no object found",
    "does not exist",
    // Additional registry phrasings surfaced by a cross-TLD audit, mostly
    // no-RDAP ccTLDs where WHOIS is the only registry signal. All are unique
    // to "not found" responses (verified not to collide with registered or
    // "not available" bodies).
    "nothing found", // KazNIC .kz / .қаз ("*** Nothing found for this query.") and NIC.AT .at
    "no found",      // TWNIC .tw / 台灣 / 台湾 ("No Found")
    "no record found", // .ls and others ("No record found for '...'.")
    "no information was found", // .africa ("No information was found matching that query.")
    "object not found", // generic ("Object not found")
    "not find matchingrecord", // CONAC .政务 / .公益 ("Not find MatchingRecord")
    // Phrasings surfaced by the 2026-07 full-TLD live sweep:
    "no such domain",             // RESTENA .lu ("% No such domain")
    "object_not_found",           // NIC Mexico .mx ("No_Se_Encontro_El_Objeto/Object_Not_Found")
    "no se encuentra registrado", // NIC Argentina .ar (Spanish-only response)
];

/// Sentence-form "not found" verdicts that exceed [`MAX_STATUS_LINE_WORDS`].
/// Matched with `starts_with` on the normalized line (anchored), so TOS
/// footers that merely quote such a phrase mid-sentence cannot match.
/// Wording captured live 2026-07.
const AVAILABILITY_SENTENCE_PATTERNS: &[&str] = &[
    // KISA .kr: "The requested domain was not found in the Registry or
    // Registrar’s WHOIS Server."
    "the requested domain was not found",
    // EDUCAUSE .edu: "The domain name you requested was not found in our
    // database."
    "the domain name you requested was not found",
    // NASK .pl: "No information available about domain name <x> in the
    // Registry NASK database."
    "no information available about domain name",
];

/// Phrases that mark a status line as the *opposite* of available — an explicit
/// negation ("not available"), a reserved/blocked status, or a throttle/refusal
/// (rate limit, quota, access denied). Checked BEFORE [`AVAILABILITY_PATTERNS`]
/// in `is_available` so an unanchored positive substring (e.g. "available for
/// registration" inside "not available for registration", or "no data found"
/// inside a rate-limit banner) cannot invert a refused/reserved name into
/// "available, high confidence" (issue #45). Also backs
/// [`WhoisResponse::indicates_registry_refusal`] for routing such bodies to an
/// inconclusive availability verdict.
const NON_AVAILABILITY_PATTERNS: &[&str] = &[
    "not available", // "...is not available for registration."
    "reserved",      // "reserved - not registered for public use"
    "rate limit",    // "rate limited" / "Access rate limited; ..."
    "rate-limit",    // hyphenated variant
    "rate exceeded",
    "quota",
    "too many requests",
    "access denied",
    "denied",
    "not permitted", // SWITCH .ch "Requests of this client are not permitted."
    "refused",
    "try again", // throttle hint ("please try again later")
    "temporarily unavailable",
    "blocked",
];

/// Patterns indicating the registrar didn't have data for this domain.
/// Matched at the start of a trimmed line (not inside TOS footers).
const NOT_FOUND_PATTERNS: &[&str] = &[
    "no match for",
    "domain not found",
    "no data found",
    "queried object does not exist",
    "object does not exist",
    "not found:",
    "status: free",
    "domain is not registered",
];

fn extract_field_with_patterns(text: &str, patterns: &[Regex]) -> Option<String> {
    for re in patterns {
        if let Some(caps) = re.captures(text) {
            if let Some(m) = caps.get(1) {
                let value = m.as_str().trim();
                if value.is_empty() {
                    continue;
                }
                let lower = value.to_lowercase();

                // Filter out redacted/privacy-protected values
                let is_redacted = lower.contains("redacted")
                    || lower.contains("data protected")
                    || lower.contains("privacy")
                    || lower.contains("not disclosed")
                    || lower.contains("withheld")
                    || lower == "n/a"
                    || lower == "none";

                if !is_redacted {
                    return Some(value.to_string());
                }
            }
        }
    }
    None
}

/// Interpretation order for ambiguous all-numeric dates (`A/B/YYYY` /
/// `A.B.YYYY` where both `A` and `B` are <= 12). `DayFirst` reads them as
/// `DD/MM` (the international norm, Seer's documented default); `MonthFirst`
/// reads them as `MM/DD` (the US convention). Unambiguous dates (a field > 12,
/// ISO, or named-month) parse identically under either order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DateOrder {
    DayFirst,
    MonthFirst,
}

/// Infer the date order for a response from any *unambiguous* candidate date: a
/// numeric `A/B/YYYY` or `A.B.YYYY` where exactly one of the first two fields
/// exceeds 12 reveals whether the registry writes day-first or month-first.
/// Registries are internally consistent, so one unambiguous date fixes the order
/// for every ambiguous date in the same response. Returns `None` when nothing
/// disambiguates (ISO, named-month, or both fields no greater than 12) — callers
/// then fall back to the documented [`DateOrder::DayFirst`] default. This
/// replaces the old hardcoded global DMY tie-break with per-response (hence
/// per-registry) evidence, fixing US `MM/DD/YYYY` registries without a fragile
/// server table (issue #47).
fn infer_date_order<'a>(candidates: impl IntoIterator<Item = &'a str>) -> Option<DateOrder> {
    static NUMERIC_DATE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"^\s*(\d{1,2})[/.](\d{1,2})[/.]\d{4}\b").expect("numeric date"));
    for s in candidates {
        if let Some(c) = NUMERIC_DATE.captures(s) {
            if let (Ok(a), Ok(b)) = (c[1].parse::<u32>(), c[2].parse::<u32>()) {
                if a > 12 && b <= 12 {
                    return Some(DateOrder::DayFirst); // first field can only be a day
                }
                if b > 12 && a <= 12 {
                    return Some(DateOrder::MonthFirst); // second field can only be a day
                }
            }
        }
    }
    None
}

/// Parse a date string from registry output into a UTC datetime, using the
/// documented international day-first interpretation for ambiguous all-numeric
/// dates. Thin wrapper over [`parse_date_with_order`].
pub(crate) fn parse_date(date_str: &str) -> Option<DateTime<Utc>> {
    parse_date_with_order(date_str, DateOrder::DayFirst)
}

/// Parse a date string from registry output into a UTC datetime, tolerating the
/// ~20 formats registries emit in practice. `order` decides how an ambiguous
/// all-numeric date is read (see [`DateOrder`]); unambiguous dates parse the
/// same either way. Shared with the RDAP parser (RDAP's `eventDate` is nominally
/// strict RFC 3339, but real servers are as sloppy as WHOIS, so both reuse this
/// tolerant parser).
pub(crate) fn parse_date_with_order(date_str: &str, order: DateOrder) -> Option<DateTime<Utc>> {
    let cleaned = date_str
        .trim()
        .replace(" UTC", "Z")
        .replace(" (UTC)", "")
        .replace(" +0000", "Z");

    // First: try RFC 3339, which handles any timezone offset (e.g., +05:30, +01:00, Z)
    if let Ok(dt) = DateTime::parse_from_rfc3339(&cleaned) {
        return Some(dt.with_timezone(&Utc));
    }

    // Second: try ISO 8601 with timezone offset (e.g., 2024-01-15T10:30:00+05:30)
    if let Ok(dt) = DateTime::<FixedOffset>::parse_from_str(&cleaned, "%Y-%m-%dT%H:%M:%S%z") {
        return Some(dt.with_timezone(&Utc));
    }

    // Third: try space-separated datetime with timezone offset (e.g., 2024-01-15 10:30:00+05:30)
    if let Ok(dt) = DateTime::<FixedOffset>::parse_from_str(&cleaned, "%Y-%m-%d %H:%M:%S%z") {
        return Some(dt.with_timezone(&Utc));
    }

    // Fourth: try NaiveDateTime / NaiveDate formats (timezone-less dates).
    // Unambiguous formats (year-first, named-month) first — these never depend
    // on the day/month order.
    const UNAMBIGUOUS_FORMATS: &[&str] = &[
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S%.fZ",
        "%Y-%m-%d %H:%M:%S",
        "%d-%b-%Y %H:%M:%S",
        "%d-%b-%Y %H:%M:%S%.f",
        // " UTC" gets normalized to "Z" at the top of parse_date(); match both
        "%d-%b-%Y %H:%M:%SZ",
        "%d-%b-%Y %H:%M:%S UTC",
        "%Y-%m-%d",
        "%d-%b-%Y",
        "%d-%B-%Y",
        "%Y.%m.%d",
        "%Y/%m/%d",
        "%b %d %Y",
    ];
    // Ambiguous all-numeric pairs, tried in the hinted order first. The other
    // order is still tried second so an unambiguous date (a field > 12) is
    // recovered rather than dropped — the second pass can only succeed for an
    // input the first rejected, so it never reinterprets an accepted date.
    const DAY_FIRST: &[&str] = &["%d.%m.%Y", "%d/%m/%Y"];
    const MONTH_FIRST: &[&str] = &["%m.%d.%Y", "%m/%d/%Y"];
    let (first_pair, second_pair) = match order {
        DateOrder::DayFirst => (DAY_FIRST, MONTH_FIRST),
        DateOrder::MonthFirst => (MONTH_FIRST, DAY_FIRST),
    };

    for fmt in UNAMBIGUOUS_FORMATS
        .iter()
        .chain(first_pair.iter())
        .chain(second_pair.iter())
    {
        if let Ok(dt) = chrono::NaiveDateTime::parse_from_str(&cleaned, fmt) {
            return Some(dt.and_utc());
        }
        if let Ok(d) = chrono::NaiveDate::parse_from_str(&cleaned, fmt) {
            return Some(d.and_hms_opt(0, 0, 0)?.and_utc());
        }
    }

    // Last resort: try parsing ISO 8601 directly
    if let Ok(dt) = cleaned.parse::<DateTime<Utc>>() {
        return Some(dt);
    }

    None
}

/// Maximum number of nameservers extracted from a single WHOIS response.
/// Real domains have ≤ 13 NS records (DNS protocol limit). Cap defensively
/// to prevent a malicious / malformed registry response from driving
/// unbounded allocation.
const MAX_NAMESERVERS: usize = 32;

fn extract_nameservers(text: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut nameservers = Vec::new();

    for re in NAMESERVER_PATTERNS.iter() {
        for caps in re.captures_iter(text) {
            if nameservers.len() >= MAX_NAMESERVERS {
                return nameservers;
            }
            if let Some(m) = caps.get(1) {
                // Strip glue IP addresses that some registries append after the hostname
                // e.g., "ns1.example.br 200.1.2.3 2001:db8::1" → "ns1.example.br"
                let raw = m.as_str().trim();
                let ns = raw.split_whitespace().next().unwrap_or(raw).to_lowercase();
                if !ns.is_empty() && seen.insert(ns.clone()) {
                    nameservers.push(ns);
                }
            }
        }
    }

    nameservers
}

/// Maximum number of domain-level status codes we extract. EPP defines
/// ~16 status values; a real domain rarely has more than 5-6. Cap to
/// prevent a malicious registry response from driving unbounded
/// allocation.
const MAX_STATUSES: usize = 32;

/// Extracts Status values only from the top-level domain block of a WHOIS
/// response. Stops scanning as soon as a RIPE-style `[Section-Header]` line is
/// encountered, which prevents contact-object `Status:` lines (e.g., inside
/// `[Tech-C]` blocks) from polluting the domain status list.
fn extract_status_top_level(raw: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut statuses = Vec::new();

    for line in raw.lines() {
        if statuses.len() >= MAX_STATUSES {
            break;
        }
        let trimmed = line.trim_start();

        // Stop at the first RIPE/JPRS-style sub-object section header.
        if trimmed.starts_with('[') && trimmed.contains(']') {
            break;
        }
        // Skip comments and empty lines.
        if trimmed.is_empty() || trimmed.starts_with('%') || trimmed.starts_with('#') {
            continue;
        }

        // Match "Domain Status:", "Status:", "status:", "state:" case-insensitively
        // via a prefix check on the lowercased line.
        let lower = trimmed.to_lowercase();
        // Slice the ORIGINAL line by the ASCII prefix length. The prefixes are
        // pure ASCII, so their byte length is identical in `trimmed` and
        // `lower`; deriving the slice point from `lower`'s suffix length is
        // unsound because `to_lowercase()` is not length-preserving for all
        // Unicode (e.g. Turkish İ → i̇ grows 2→3 bytes), which could make the
        // lowercased suffix longer than the whole original line and underflow
        // `trimmed.len() - rest.len()` into an out-of-bounds slice panic.
        let value_opt = if lower.starts_with("domain status:") {
            Some(&trimmed["domain status:".len()..])
        } else if lower.starts_with("status:") {
            Some(&trimmed["status:".len()..])
        } else if lower.starts_with("state:") {
            Some(&trimmed["state:".len()..])
        } else {
            None
        };

        if let Some(rest) = value_opt {
            let raw_val = rest.trim();
            if let Some(first) = raw_val.split_whitespace().next() {
                if !first.is_empty() && seen.insert(first.to_string()) {
                    statuses.push(first.to_string());
                }
            }
        }
    }

    statuses
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_response(raw: &str) -> WhoisResponse {
        WhoisResponse::parse_internal("example.jp", "whois.jprs.jp", raw)
    }

    #[test]
    fn organization_pattern_ignores_admin_and_tech_org_lines() {
        // With no registrant organization present, the bare `Organization:`
        // pattern must not capture the org from an `Admin Organization:` /
        // `Tech Organization:` line and mislabel it as the registrant org.
        let raw = "Domain Name: example.com\n\
                   Admin Organization: AcmeAdminCorp\n\
                   Tech Organization: AcmeTechCorp\n";
        assert_eq!(
            extract_field_with_patterns(raw, &ORGANIZATION_PATTERNS),
            None
        );

        // A genuine (possibly indented) registrant Organization: line is still
        // captured.
        let raw2 = "Domain Name: example.com\n\
                    Registrant Contact:\n\
                    \tOrganization: Real Registrant LLC\n\
                    Admin Organization: AcmeAdminCorp\n";
        assert_eq!(
            extract_field_with_patterns(raw2, &ORGANIZATION_PATTERNS).as_deref(),
            Some("Real Registrant LLC")
        );
    }

    // --- H10: is_available() scans the full response --------------------

    #[test]
    fn is_available_jprs_style_with_notice_preamble() {
        // JPRS prepends notice lines before the availability indicator.
        let raw = "\
Notice: JPRS database is provided for information purposes only.
Notice: Use of this service is subject to the JPRS terms.
Notice: For more info see https://jprs.jp/
Notice: Copyright (C) JPRS.

No match!!

";
        assert!(make_response(raw).is_available());
    }

    #[test]
    fn is_available_nic_br_style() {
        let raw = "\
% Copyright (c) Nic.br
% The use of the data below is only permitted as described in
% full by the terms of use at https://registro.br/termo/en.html,
% being prohibited its distribution, commercialization or
% reproduction, in particular, to use it for advertising or
% any similar purpose.

No match for domain exemplo.br.
";
        assert!(make_response(raw).is_available());
    }

    #[test]
    fn is_available_twnic_style() {
        let raw = "\
TWNIC WHOIS Server. This service is free and is provided as is.

Notice: Use of this service is subject to terms.
Notice: Do not use for spam.

Domain not found.
";
        assert!(make_response(raw).is_available());
    }

    #[test]
    fn is_available_false_when_registration_data_present_despite_noise() {
        // A registered domain whose WHOIS prose contains an availability
        // fragment (here in an abuse-contact/notice line) must NOT read as
        // available — concrete registration data (registrar/dates/NS) wins
        // over an unanchored substring match. This is the H6 false-positive
        // class: "<registered domain> reported AVAILABLE".
        let raw = "\
Domain Name: example.com
Registrar: Example Registrar, Inc.
Creation Date: 2020-01-01T00:00:00Z
Name Server: ns1.example.com
Registrar Abuse Contact: please report if the object not found in directory
";
        assert!(!make_response(raw).is_available());
    }

    #[test]
    fn is_available_false_for_registered_domain() {
        let raw = "\
Domain Name: example.com
Registrar: Example Registrar, Inc.
Creation Date: 2020-01-01T00:00:00Z
Name Server: ns1.example.com
";
        assert!(!make_response(raw).is_available());
    }

    // --- registry_unavailable(): registry serves no usable WHOIS --------

    #[test]
    fn registry_unavailable_true_for_tld_not_supported_sentinel() {
        // Identity Digital (.email/.life/.ninja/…) port-43 servers reply
        // "TLD is not supported." with no domain fields — RDAP-only TLDs.
        let raw = "\
TLD is not supported.
>>> Last update of WHOIS database: 2026-06-03T22:45:28Z <<<

Terms of Use: Access to WHOIS information is provided to assist persons ...
";
        assert!(make_response(raw).registry_unavailable());
    }

    #[test]
    fn registry_unavailable_true_for_malformed_request_sentinel() {
        let raw = "\
Malformed request.
>>> Last update of WHOIS database: 2026-06-03T22:46:35Z <<<
";
        assert!(make_response(raw).registry_unavailable());
    }

    #[test]
    fn registry_unavailable_false_for_registered_domain() {
        let raw = "\
Domain Name: example.com
Registrar: Example Registrar, Inc.
Creation Date: 2020-01-01T00:00:00Z
Name Server: ns1.example.com
";
        assert!(!make_response(raw).registry_unavailable());
    }

    #[test]
    fn registry_unavailable_false_for_available_domain() {
        // An unregistered-domain "no match" response is NOT a service error —
        // it must read as available, not registry-unavailable.
        let raw = "No match for domain EXAMPLE.\n";
        assert!(!make_response(raw).registry_unavailable());
    }

    #[test]
    fn extract_status_does_not_panic_on_unicode_lowercasing_expansion() {
        // Turkish dotted capital İ (2 bytes) lowercases to i̇ (3 bytes), so a
        // status VALUE full of them makes the lowercased line longer than the
        // original. The old code sliced the original by a length derived from
        // the lowercased copy (`trimmed.len() - rest.len()`), which underflowed
        // and panicked out-of-bounds. `raw` is attacker-controlled (a hostile
        // WHOIS server), so this was a remotely-triggerable panic / DoS.
        let raw = format!("Domain Status: {}\n", "İ".repeat(40));
        let r = make_response(&raw); // must not panic
        assert!(
            !r.status.is_empty(),
            "status value should still be extracted"
        );
    }

    #[test]
    fn is_available_hkirc_has_not_been_registered() {
        // HKIRC (.hk and the IDN .香港/xn--j6w193g) signals an unregistered
        // domain with "The domain has not been registered." — note the
        // wording is "has not BEEN registered", which does NOT contain the
        // bare "not registered" substring the old pattern list relied on.
        let raw = "The domain has not been registered.\n";
        assert!(make_response(raw).is_available());
    }

    #[test]
    fn is_available_tab_delimited_status_available() {
        // DNS Belgium (.be) and similar registries separate the label and
        // value with a TAB: "Status:\tAVAILABLE". The scan must normalize
        // internal whitespace so the "status: available" pattern still hits.
        let raw = "Domain:\tfoo.be\nStatus:\tAVAILABLE\n";
        assert!(make_response(raw).is_available());
    }

    #[test]
    fn is_not_available_tab_delimited_status_not_available() {
        // Guard against a false positive from whitespace normalization:
        // "Status:\tNOT AVAILABLE" (a registered .be domain) must NOT be
        // read as available — "status: available" is not a substring of
        // "status: not available".
        let raw = "Domain:\tfoo.be\nStatus:\tNOT AVAILABLE\n";
        assert!(!make_response(raw).is_available());
    }

    #[test]
    fn is_available_recognizes_additional_registry_phrasings() {
        // "Not found" wordings surfaced by the cross-TLD audit, mostly from
        // no-RDAP ccTLDs where WHOIS is the only registry signal.
        for raw in [
            "*** Nothing found for this query.\n", // .kz / .қаз (KazNIC)
            "No Found\n",                          // TWNIC .tw / 台灣 / 台湾
            "No record found for 'example.ls'.\n", // .ls (Lesotho)
            "No information was found matching that query.\n", // .africa
            "Object not found\n",                  // generic
            "Not find MatchingRecord\n",           // CONAC .政务 / .公益
        ] {
            assert!(
                make_response(raw).is_available(),
                "should detect available from: {raw:?}"
            );
        }
    }

    #[test]
    fn is_available_does_not_match_registered_or_blocked_phrasings() {
        // Guard against false positives from the broadened pattern list: a
        // registered domain, a "not available" status, a port-43 refusal, and
        // TOS prose containing "free" must all stay NOT-available.
        for raw in [
            "Domain Status: clientTransferProhibited\nRegistrar: Example, Inc.\n",
            "Status: NOT AVAILABLE\n",
            "Requests of this client are not permitted. Please use the web form.\n",
            "This WHOIS service is free for personal, non-commercial use.\n",
        ] {
            assert!(
                !make_response(raw).is_available(),
                "must NOT detect available from: {raw:?}"
            );
        }
    }

    #[test]
    fn is_available_false_for_negation_and_refusal_lines() {
        // Regression for the availability-inversion bug (#45): the per-line
        // scan matched AVAILABILITY_PATTERNS via an unanchored contains() with
        // no negation guard, so a short status line that *negates* or *refuses*
        // availability ("not available for registration", "not registered" in a
        // reserved status, "no data found" while rate-limited) was inverted into
        // "available, high confidence". All three must read as NOT available.
        for raw in [
            // reserved/premium — registry refuses registration (contains the
            // "available for registration" substring after "not ").
            "This domain name is not available for registration.\n",
            // reserved/blocked status (contains the "not registered" substring).
            "Domain Status: reserved - not registered for public use\n",
            // throttled — inconclusive, not free (contains "no data found").
            "Access rate limited; no data found for unauthenticated clients\n",
        ] {
            assert!(
                !make_response(raw).is_available(),
                "negation/refusal line must NOT read as available: {raw:?}"
            );
        }
    }

    #[test]
    fn indicates_registry_refusal_detects_throttle_and_negation() {
        // The refusal detector backs decide_fallback's inconclusive routing: a
        // thin body that explicitly refuses / throttles / negates availability
        // must be flagged so the fallback decision does not guess.
        for raw in [
            "This domain name is not available for registration.\n",
            "Domain Status: reserved - not registered for public use\n",
            "Access rate limited; no data found for unauthenticated clients\n",
            "Requests of this client are not permitted. Please use the web form.\n",
        ] {
            assert!(
                make_response(raw).indicates_registry_refusal(),
                "should flag refusal/throttle/negation: {raw:?}"
            );
        }
    }

    #[test]
    fn indicates_registry_refusal_false_for_plain_not_found_and_registered() {
        // A genuine "no match" availability response and a registered domain
        // must NOT be flagged as refusal — those are conclusive signals.
        for raw in [
            "No match for domain EXAMPLE.\n",
            "Domain not found.\n",
            "Conditions of use for the whois service via port 43\n",
            "Domain Name: example.com\nRegistrar: Example, Inc.\nName Server: ns1.example.com\n",
        ] {
            assert!(
                !make_response(raw).indicates_registry_refusal(),
                "must NOT flag as refusal: {raw:?}"
            );
        }
    }

    #[test]
    fn is_available_ignores_not_found_phrase_buried_in_prose() {
        // A thin response with NO parsed registration fields (so the H6
        // registration-data guard does not fire) whose only "does not exist"
        // / "not found" occurrence is inside a long prose/notice sentence
        // must NOT be read as available. Availability indicators are short
        // status lines, not phrases buried in footer prose.
        let raw = "\
This is an informational banner from the registry WHOIS service provider.
Note that if the queried object does not exist in our database we simply return an empty result rather than an error response.
Records not found in this directory may still exist upstream in the thick registry, so please check with the sponsoring registrar.
";
        assert!(
            !make_response(raw).is_available(),
            "long prose sentences must not trigger availability"
        );
    }

    // --- M19: indicates_not_found anchors at line start -----------------

    #[test]
    fn indicates_not_found_true_on_line_start() {
        let raw = "\
Domain Name: example.com
queried object does not exist
";
        assert!(make_response(raw).indicates_not_found());
    }

    #[test]
    fn indicates_not_found_false_when_phrase_is_in_tos_footer() {
        // A registered-domain response whose TOS footer quotes the phrase
        // must not be flagged as not-found.
        let raw = "\
Domain Name: example.com
Registrar: Example Registrar, Inc.
Creation Date: 2020-01-01T00:00:00Z
Name Server: ns1.example.com

Terms of Service:
Note that if the queried object does not exist in our database we return NXDOMAIN.
This document does not imply anything about specific domains.
";
        assert!(!make_response(raw).indicates_not_found());
    }

    // --- M13: extract_status_top_level skips sub-object sections --------

    #[test]
    fn status_extracted_only_from_top_level_block() {
        let raw = "\
Domain Name: example.jp
Status: Active
Registrar: Example Registrar

[Tech-C]
Status: ok
Name: Technical Contact
";
        let parsed = make_response(raw);
        // Only the top-level Active should be present; the Tech-C "ok" is skipped.
        assert_eq!(parsed.status, vec!["Active".to_string()]);
    }

    #[test]
    fn status_multiple_top_level_values_deduped() {
        let raw = "\
Domain Name: example.com
Domain Status: clientTransferProhibited
Domain Status: clientUpdateProhibited
Domain Status: clientTransferProhibited
";
        let parsed = make_response(raw);
        assert_eq!(
            parsed.status,
            vec![
                "clientTransferProhibited".to_string(),
                "clientUpdateProhibited".to_string(),
            ]
        );
    }

    // --- M14: parse_date handles "15-Jan-2024 10:30:00" -----------------

    #[test]
    fn parse_date_handles_d_b_y_with_time() {
        let parsed = parse_date("15-Jan-2024 10:30:00").expect("should parse");
        use chrono::Datelike;
        assert_eq!(parsed.year(), 2024);
        assert_eq!(parsed.month(), 1);
        assert_eq!(parsed.day(), 15);
    }

    #[test]
    fn parse_date_handles_d_b_y_with_time_utc_suffix() {
        let parsed = parse_date("15-Jan-2024 10:30:00 UTC").expect("should parse");
        use chrono::Datelike;
        assert_eq!(parsed.year(), 2024);
    }

    #[test]
    fn parse_date_still_handles_d_b_y_date_only() {
        let parsed = parse_date("15-Jan-2024").expect("should parse");
        use chrono::Datelike;
        assert_eq!(parsed.year(), 2024);
    }

    // --- parse_date: ambiguous numeric dates default to day-first, but
    //     unambiguous US month-first dates are recovered (not dropped) ----

    #[test]
    fn parse_date_recovers_unambiguous_us_mdy() {
        // Some registrars emit US month-first numeric dates. When the day
        // field is > 12 the date is unambiguously MDY and was previously
        // dropped (there was no %m/%d/%Y format). Recover it rather than
        // returning None.
        use chrono::Datelike;
        let parsed = parse_date("02/13/2024").expect("unambiguous MDY should parse");
        assert_eq!(parsed.year(), 2024);
        assert_eq!(parsed.month(), 2);
        assert_eq!(parsed.day(), 13);
    }

    #[test]
    fn parse_date_ambiguous_numeric_is_day_first() {
        // Documented precedence: ambiguous all-numeric dates (both fields
        // <= 12) are interpreted day-first (the international norm), matching
        // the %d/%m/%Y format ordering. "06/07/2024" => 6 July 2024. The
        // month-first fallback must NOT change this.
        use chrono::Datelike;
        let parsed = parse_date("06/07/2024").expect("should parse");
        assert_eq!(parsed.year(), 2024);
        assert_eq!(parsed.month(), 7);
        assert_eq!(parsed.day(), 6);
    }

    // --- #47: per-registry date order disambiguation --------------------

    #[test]
    fn parse_date_with_order_disambiguates_month_first() {
        // The same ambiguous string reads differently per order hint:
        // day-first => 3 April; month-first (US) => 4 March.
        use chrono::Datelike;
        let dmy = parse_date_with_order("03/04/2024", DateOrder::DayFirst).expect("parse");
        assert_eq!(
            (dmy.month(), dmy.day()),
            (4, 3),
            "day-first reads 03/04 as 3 April"
        );
        let mdy = parse_date_with_order("03/04/2024", DateOrder::MonthFirst).expect("parse");
        assert_eq!(
            (mdy.month(), mdy.day()),
            (3, 4),
            "month-first reads 03/04 as 4 March"
        );
    }

    #[test]
    fn parse_date_with_order_unambiguous_is_order_independent() {
        // A field > 12 disambiguates the date regardless of the hint.
        use chrono::Datelike;
        for s in ["13/04/2024", "04/13/2024"] {
            for order in [DateOrder::DayFirst, DateOrder::MonthFirst] {
                let d = parse_date_with_order(s, order).expect("parse");
                assert_eq!(
                    (d.year(), d.month(), d.day()),
                    (2024, 4, 13),
                    "{s:?} under {order:?} must be 2024-04-13"
                );
            }
        }
    }

    #[test]
    fn parse_internal_infers_us_month_first_from_unambiguous_sibling() {
        // A US-format registry response: the ambiguous creation date
        // "03/04/2024" (both fields <= 12) must be read month-first (4 March)
        // because the sibling expiry "04/15/2034" is unambiguously month-first
        // (day 15). Registries are internally consistent, so one unambiguous
        // date reveals the order for the whole response (issue #47).
        use chrono::Datelike;
        let raw = "Creation Date: 03/04/2024\nRegistry Expiry Date: 04/15/2034\n";
        let r = make_response(raw);
        let creation = r.creation_date.expect("creation parsed");
        assert_eq!(
            (creation.month(), creation.day()),
            (3, 4),
            "ambiguous date must follow the registry's revealed month-first order"
        );
    }

    #[test]
    fn parse_internal_defaults_day_first_without_disambiguating_sibling() {
        // No unambiguous sibling → the documented day-first default holds.
        use chrono::Datelike;
        let raw = "Creation Date: 06/07/2024\n";
        let r = make_response(raw);
        let creation = r.creation_date.expect("creation parsed");
        assert_eq!(
            (creation.month(), creation.day()),
            (7, 6),
            "no disambiguating sibling keeps the day-first default"
        );
    }

    // --- H3: raw_response is not serialized -----------------------------

    #[test]
    fn raw_response_is_skipped_from_json_output() {
        let raw = "Domain Name: example.com\nRegistrar: Example Registrar\n";
        let parsed = make_response(raw);
        assert!(
            !parsed.raw_response.is_empty(),
            "raw_response still populated internally"
        );
        let json = serde_json::to_string(&parsed).expect("serialize");
        assert!(
            !json.contains("raw_response"),
            "raw_response must not appear in serialized JSON output: {}",
            json
        );
        assert!(
            !json.contains("Domain Name: example.com"),
            "raw response content must not leak in JSON: {}",
            json
        );
    }

    /// Regression: a serialized `WhoisResponse` must deserialize back.
    /// `raw_response` is `skip_serializing` (the 1 MB raw blob must never leak),
    /// but it also needs `default` — otherwise deserialization fails with
    /// "missing field `raw_response`", which silently corrupts persisted lookup
    /// history / cache files (the corrupt-file branch then discards them).
    #[test]
    fn whois_response_survives_json_round_trip() {
        let parsed = make_response("Domain Name: example.com\nRegistrar: Example Registrar\n");
        let json = serde_json::to_string(&parsed).expect("serialize");
        let back: WhoisResponse =
            serde_json::from_str(&json).expect("round-trip must not fail (missing field?)");
        assert_eq!(back.domain, parsed.domain, "domain survives round-trip");
        assert!(
            back.raw_response.is_empty(),
            "skipped raw_response defaults to empty on load"
        );
    }

    /// Punktum (.dk) format, captured live 2026-07: nameservers appear as
    /// `Hostname:` lines under a `Nameservers` heading, and the creation
    /// date is labelled `Registered:`.
    #[test]
    fn punktum_dk_hostnames_and_registered_date() {
        let raw = "Domain:               punktum.dk\n\
                   DNS:                  punktum.dk\n\
                   Registered:           2018-01-25\n\
                   Expires:              2027-01-31\n\
                   Registration period:  1 year\n\
                   DNSSEC:               Signed delegation\n\
                   Status:               Active\n\
                   \n\
                   Nameservers\n\
                   Hostname:             auth01.ns.dk-hostmaster.dk\n\
                   Hostname:             auth02.ns.dk-hostmaster.dk\n\
                   Hostname:             auth03.ns.dk-hostmaster.dk\n";
        let r = WhoisResponse::parse("punktum.dk", "whois.punktum.dk", raw);
        assert_eq!(
            r.nameservers,
            vec![
                "auth01.ns.dk-hostmaster.dk",
                "auth02.ns.dk-hostmaster.dk",
                "auth03.ns.dk-hostmaster.dk"
            ]
        );
        assert!(r.creation_date.is_some(), "created from 'Registered:'");
        assert!(r.expiration_date.is_some(), "expires from 'Expires:'");
    }

    /// Many ccTLD registries print the availability verdict on `%`-comment
    /// lines (wording captured live 2026-07). The comment marker must be
    /// stripped and the remainder evaluated, not skipped wholesale.
    #[test]
    fn availability_verdicts_on_comment_lines_are_detected() {
        let cases: &[(&str, &str)] = &[
            (
                "fr/AFNIC",
                "%% This is the AFNIC Whois server.\n%%\n%% NOT FOUND\n",
            ),
            (
                "br/NIC.br",
                "% Copyright (c) Nic.br\n% No match for seer-sweep.br\n",
            ),
            ("no/NORID", "% Norid AS holds the copyright\n% No match\n"),
            (
                "at/NIC.AT",
                "% Copyright (c)2026 by NIC.AT (1)\n% nothing found\n",
            ),
            (
                "cz/CZ.NIC",
                "%ERROR:101: no entries found\n% No entries found.\n",
            ),
            ("rs/RNIDS", "%ERROR:103: Domain is not registered\n"),
            (
                "is/ISNIC",
                "% Rights restricted by copyright.\n% No entries found for query \"x.is\".\n",
            ),
            ("lu/RESTENA", "% WHOIS x.lu\n% No such domain\n"),
            ("dz/NIC.DZ", "% No match for domain 'X.DZ'.\n"),
            ("sn/NIC.SN", "%% NOT FOUND\n"),
        ];
        for (name, raw) in cases {
            let r = WhoisResponse::parse("example.test", "whois.test", raw);
            assert!(
                r.is_available(),
                "{name}: comment-line verdict must mark available:\n{raw}"
            );
        }
    }

    /// Sentence-form "not found" phrasings exceed the 10-word status-line
    /// gate; they are matched anchored at line start instead (live 2026-07).
    #[test]
    fn availability_sentence_phrasings_are_detected() {
        let cases: &[(&str, &str)] = &[
            (
                "kr/KISA",
                "query : x.kr\nThe requested domain was not found in the Registry or Registrar\u{2019}s WHOIS Server.\n",
            ),
            (
                "edu/EDUCAUSE",
                "Domain Name: X.EDU\nThe domain name you requested was not found in our database.\n",
            ),
            (
                "pl/NASK",
                "No information available about domain name x.pl in the Registry NASK database.\n",
            ),
        ];
        for (name, raw) in cases {
            let r = WhoisResponse::parse("example.test", "whois.test", raw);
            assert!(
                r.is_available(),
                "{name}: sentence-form verdict must mark available:\n{raw}"
            );
        }
    }

    /// Registry-specific short phrasings captured live 2026-07: SIDN/.aw
    /// "<domain> is free" (suffix-anchored so prose like "registration is
    /// free of charge" cannot match), NIC Mexico's underscore token, and
    /// NIC Argentina's Spanish phrasing.
    #[test]
    fn availability_special_short_phrasings_are_detected() {
        for (name, raw) in [
            ("nl/SIDN", "x.nl is free\n"),
            ("aw/SETAR", "x.aw is free\n"),
            (
                "mx/NICMexico",
                "No_Se_Encontro_El_Objeto/Object_Not_Found\n",
            ),
            (
                "ar/NICArgentina",
                "El dominio no se encuentra registrado en NIC Argentina\n",
            ),
        ] {
            let r = WhoisResponse::parse("example.test", "whois.test", raw);
            assert!(r.is_available(), "{name} must mark available:\n{raw}");
        }
        // Suffix anchoring: "is free" mid-sentence must NOT flip availability.
        let prose = WhoisResponse::parse(
            "example.test",
            "whois.test",
            "Registration is free of charge today\n",
        );
        assert!(
            !prose.is_available(),
            "'is free' inside prose must not mark available"
        );
    }

    /// GMO Registry retired port-43 WHOIS (May 2026, ICANN RDAP transition)
    /// and now answers every query with a retirement notice. That is a
    /// service-level "no usable WHOIS" signal, not a registered/available
    /// verdict.
    #[test]
    fn whois_retirement_notice_is_registry_unavailable() {
        let raw = "Notice: Effective May 1, 2026, the WHOIS service has been retired in accordance with ICANN's RDAP transition policy. All registration data queries are now served via RDAP. The Registration Data Access Protocol (RDAP) base URL is: https://rdap.gmoregistry.net/rdap/";
        let r = WhoisResponse::parse("nic.canon", "whois.nic.canon", raw);
        assert!(
            r.registry_unavailable(),
            "retirement notice must be registry_unavailable"
        );
        assert!(!r.is_available(), "retirement notice is not 'available'");
    }
}
