//! Typosquat / homoglyph look-alike generation and registration scoring.
//!
//! Given a domain, generates candidate look-alikes (typo permutations plus a
//! small ASCII-homoglyph map and common TLD swaps) and scores which candidates
//! are registered, ranking freshly-registered squats first. This is a
//! brand-protection / phishing-defense capability built entirely on primitives
//! seer already has (normalization, smart lookup, availability inference) — no
//! new protocol code. The brand label is found with the Public Suffix List, so
//! `example.co.uk` permutes `example`, not `co`.
//!
//! Candidate generation is pure and unit-tested; only the registration scoring
//! is async.
//!
//! ## DNS presence pre-filter (scoring)
//!
//! Most generated candidates are unregistered typos, so before paying for a
//! full RDAP+WHOIS race on each one, [`score_candidates`] first probes every
//! candidate with a cheap [`DnsResolver::presence`](crate::dns::DnsResolver::presence)
//! query and drops the ones that answer `NXDOMAIN` — the same signal the
//! smart-lookup thin-fallback ladder uses to call an apex unregistered. Only
//! `Present`/`Unknown` candidates get the full lookup (a failed probe is not
//! evidence, so it is never skipped).
//!
//! Caveat: DNS presence is a cheaper but slightly different signal from a
//! registry lookup. A registered-but-unresolvable domain only looks `Absent`
//! via NXDOMAIN, which for a registered name is rare; parked squats are
//! `Present` and still receive the full lookup. The pre-filter therefore trades
//! a negligible miss rate for a large reduction in registry queries (a
//! rate-limit-ban risk against port-43 WHOIS).

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::dns::DnsPresence;
use crate::domain_info::DomainInfo;
use crate::error::Result;
use crate::lookup::{LookupResult, SmartLookup};
use crate::validation::normalize_domain;

/// Upper bound on generated candidates, to keep the subsequent network scoring
/// bounded regardless of label length. The public docs of
/// [`generate_candidates`] state the value; keep them in step.
const MAX_CANDIDATES: usize = 600;

/// Concurrency for the cheap DNS presence pre-filter. DNS probes are far
/// lighter than a full RDAP+WHOIS race, so we fan them out wider than the
/// (registry-facing) full-lookup concurrency to keep the pre-filter fast.
/// The public docs of [`score_candidates`] state the value; keep them in step.
const PREFILTER_CONCURRENCY: usize = 50;

/// Common alternate TLDs used for TLD-swap squats.
const SWAP_TLDS: &[&str] = &[
    "com", "net", "org", "co", "io", "info", "biz", "app", "dev", "xyz", "online", "site",
];

/// A generated look-alike candidate and the technique that produced it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfusableCandidate {
    pub domain: String,
    /// The permutation technique (e.g. `omission`, `homoglyph`, `tld-swap`).
    pub technique: String,
}

/// A registered look-alike surfaced by scoring.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisteredLookalike {
    pub domain: String,
    pub technique: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registrar: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub creation_date: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub nameservers: Vec<String>,
}

/// The result of a confusables scan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfusableReport {
    pub domain: String,
    pub candidates_generated: usize,
    pub candidates_checked: usize,
    /// Registered look-alikes, most-recently-registered first.
    pub registered: Vec<RegisteredLookalike>,
}

/// Returns the QWERTY-adjacent keys for `c` (used for fat-finger substitutions).
fn keyboard_neighbors(c: char) -> &'static [char] {
    match c {
        'a' => &['q', 'w', 's', 'z'],
        'b' => &['v', 'g', 'h', 'n'],
        'c' => &['x', 'd', 'f', 'v'],
        'd' => &['s', 'e', 'f', 'c', 'x'],
        'e' => &['w', 'r', 'd', 's'],
        'f' => &['d', 'r', 'g', 'v', 'c'],
        'g' => &['f', 't', 'h', 'b', 'v'],
        'h' => &['g', 'y', 'j', 'n', 'b'],
        'i' => &['u', 'o', 'k', 'j'],
        'j' => &['h', 'u', 'k', 'm', 'n'],
        'k' => &['j', 'i', 'l', 'm'],
        'l' => &['k', 'o', 'p'],
        'm' => &['n', 'j', 'k'],
        'n' => &['b', 'h', 'j', 'm'],
        'o' => &['i', 'p', 'l', 'k'],
        'p' => &['o', 'l'],
        'q' => &['w', 'a'],
        'r' => &['e', 't', 'f', 'd'],
        's' => &['a', 'w', 'd', 'x', 'z'],
        't' => &['r', 'y', 'g', 'f'],
        'u' => &['y', 'i', 'j', 'h'],
        'v' => &['c', 'f', 'g', 'b'],
        'w' => &['q', 'e', 's', 'a'],
        'x' => &['z', 's', 'd', 'c'],
        'y' => &['t', 'u', 'h', 'g'],
        'z' => &['a', 's', 'x'],
        _ => &[],
    }
}

/// Returns ASCII-homoglyph replacement strings for `c` (visual look-alikes).
fn homoglyphs(c: char) -> &'static [&'static str] {
    match c {
        'o' => &["0"],
        '0' => &["o"],
        'l' => &["1", "i"],
        'i' => &["1", "l"],
        '1' => &["l", "i"],
        'e' => &["3"],
        'a' => &["4"],
        's' => &["5"],
        'b' => &["6"],
        't' => &["7"],
        'g' => &["9"],
        'm' => &["rn"],
        'w' => &["vv"],
        _ => &[],
    }
}

/// Whether a character is legal in an LDH (letter-digit-hyphen) DNS label.
fn is_ldh(c: char) -> bool {
    c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-'
}

/// Whether a permuted label is valid in DNS: 1–63 octets, no leading or
/// trailing hyphen, and `--` at positions 3–4 only in a well-formed IDNA
/// A-label (RFC 5891 §4.2.3.1). Permuting an `xn--` label, or inserting a
/// hyphen, otherwise yields names no registry accepts (`nx--…`, undecodable
/// punycode).
fn is_valid_label(label: &str) -> bool {
    if label.is_empty() || label.len() > 63 || label.starts_with('-') || label.ends_with('-') {
        return false;
    }
    if label.get(2..4) != Some("--") {
        return true;
    }
    if !label.starts_with("xn--") {
        return false;
    }
    // A valid A-label decodes, and re-encoding its U-label gives the same
    // A-label back (rejecting non-canonical and all-ASCII encodings).
    let (unicode, decoded) = idna::domain_to_unicode(label);
    decoded.is_ok()
        && unicode != label
        && idna::domain_to_ascii(&unicode).is_ok_and(|ascii| ascii == label)
}

/// Records `candidate` under `technique` unless it is the original name or
/// was already produced (by this or an earlier technique).
fn push_unique(
    seen: &mut HashSet<String>,
    bucket: &mut Vec<ConfusableCandidate>,
    original: &str,
    candidate: String,
    technique: &str,
) {
    if candidate != original && seen.insert(candidate.clone()) {
        bucket.push(ConfusableCandidate {
            domain: candidate,
            technique: technique.to_string(),
        });
    }
}

/// Splits `cap` across buckets of the given `sizes` by water-filling: every
/// bucket is offered an equal share of what is left, and a bucket smaller
/// than its share hands the remainder on to the larger ones. Only buckets
/// larger than an equal split are truncated, so every non-empty technique
/// keeps at least `cap / buckets` candidates (or all of them).
fn fair_shares(sizes: &[usize], cap: usize) -> Vec<usize> {
    let mut order: Vec<usize> = (0..sizes.len()).collect();
    order.sort_by_key(|&i| sizes[i]);
    let mut shares = vec![0; sizes.len()];
    let mut remaining = cap;
    for (k, &i) in order.iter().enumerate() {
        let take = sizes[i].min(remaining / (sizes.len() - k));
        shares[i] = take;
        remaining -= take;
    }
    shares
}

/// Generates typo/homoglyph look-alike candidates for `domain`.
///
/// Squats are registrations, so candidates are built from the registrable
/// domain found with the Public Suffix List: `mail.example.co.uk` is scanned
/// as `example.co.uk`, and its brand label (`example`, the one immediately
/// left of the ICANN public suffix) is permuted with the suffix kept, except
/// for the dedicated `tld-swap` technique, which swaps the whole suffix
/// (`example.co.uk` → `example.com`). Subdomain labels are dropped: a
/// `mail.xample.com` candidate names a host the squatter never has to
/// create, so its DNS probe reads as unregistered and the real squat
/// `xample.com` is missed. Every candidate is a valid DNS name (labels of at
/// most 63 octets, `--` at positions 3–4 only in a well-formed `xn--`
/// A-label). Output is deduplicated, excludes the registrable domain itself,
/// and capped at 600 candidates with the budget shared fairly across
/// techniques: each keeps an equal share (or all of its candidates, if it has
/// fewer), and a small technique's unused share passes to the larger ones. A
/// bare public suffix has no brand label and yields nothing.
pub fn generate_candidates(domain: &str) -> Vec<ConfusableCandidate> {
    let Ok(normalized) = normalize_domain(domain) else {
        return Vec::new();
    };
    let Some(registrable) = crate::psl::registrable_domain(&normalized) else {
        return Vec::new();
    };
    // The registrable domain is one label plus the (possibly multi-label)
    // public suffix.
    let Some((label, tld)) = registrable.split_once('.') else {
        return Vec::new();
    };

    // Rebuilds the candidate name around a permuted label, rejecting labels
    // (and names, RFC 1035's 253 octets) that are not valid in DNS.
    let with_label = |variant: &str| -> Option<String> {
        let valid = is_valid_label(variant) && variant.len() + 1 + tld.len() <= 253;
        valid.then(|| format!("{variant}.{tld}"))
    };

    let mut seen = HashSet::new();
    // One bucket per technique, in generation order (which also decides
    // attribution when two techniques produce the same name).
    let mut buckets: Vec<Vec<ConfusableCandidate>> = Vec::new();
    let mut emit = |technique: &str, variants: Vec<String>| {
        let mut bucket = Vec::new();
        for variant in variants {
            if let Some(candidate) = with_label(&variant) {
                push_unique(&mut seen, &mut bucket, registrable, candidate, technique);
            }
        }
        buckets.push(bucket);
    };

    let chars: Vec<char> = label.chars().collect();
    let join_chars = |v: Vec<char>| v.into_iter().collect::<String>();

    // Omission: drop each character.
    emit(
        "omission",
        (0..chars.len())
            .map(|i| {
                let mut v = chars.clone();
                v.remove(i);
                join_chars(v)
            })
            .collect(),
    );

    // Transposition: swap adjacent characters.
    emit(
        "transposition",
        (0..chars.len().saturating_sub(1))
            .map(|i| {
                let mut v = chars.clone();
                v.swap(i, i + 1);
                join_chars(v)
            })
            .collect(),
    );

    // Repetition: double each character.
    emit(
        "repetition",
        (0..chars.len())
            .map(|i| {
                let mut v = chars.clone();
                v.insert(i, chars[i]);
                join_chars(v)
            })
            .collect(),
    );

    // Adjacent-key replacement.
    let mut replacements = Vec::new();
    for (i, &c) in chars.iter().enumerate() {
        for &n in keyboard_neighbors(c) {
            let mut v = chars.clone();
            v[i] = n;
            replacements.push(join_chars(v));
        }
    }
    emit("replacement", replacements);

    // Insertion: insert each lowercase letter at every gap.
    let mut insertions = Vec::new();
    for i in 0..=chars.len() {
        for n in b'a'..=b'z' {
            let mut v = chars.clone();
            v.insert(i, n as char);
            insertions.push(join_chars(v));
        }
    }
    emit("insertion", insertions);

    // Bitsquatting: flip each bit of each byte; keep valid LDH results. The
    // label is an A-label (normalized), so every char is ASCII.
    let mut bitsquats = Vec::new();
    for (i, &c) in chars.iter().enumerate() {
        for bit in 0..7 {
            let fc = ((c as u8) ^ (1 << bit)) as char;
            if is_ldh(fc) && fc != c {
                let mut v = chars.clone();
                v[i] = fc;
                bitsquats.push(join_chars(v));
            }
        }
    }
    emit("bitsquat", bitsquats);

    // Homoglyph substitution.
    let mut glyphs = Vec::new();
    for (i, &c) in chars.iter().enumerate() {
        for &sub_str in homoglyphs(c) {
            let mut variant = String::new();
            for (j, &cc) in chars.iter().enumerate() {
                if i == j {
                    variant.push_str(sub_str);
                } else {
                    variant.push(cc);
                }
            }
            glyphs.push(variant);
        }
    }
    emit("homoglyph", glyphs);

    // TLD swap: keep the label, swap the whole public suffix.
    let mut swaps = Vec::new();
    for &swap in SWAP_TLDS {
        if swap != tld {
            let candidate = format!("{label}.{swap}");
            push_unique(&mut seen, &mut swaps, registrable, candidate, "tld-swap");
        }
    }
    buckets.push(swaps);

    // Share the cap across techniques. Label permutations grow with label
    // length (insertion alone is 26×(L+1)), and a plain tail truncation
    // silently dropped whole techniques — every tld-swap for ~16+ char
    // labels, and bitsquat + homoglyph (the namesake technique) for
    // `paypalsecurelogin.com`. Water-filling only trims the techniques that
    // exceed an equal split, in practice insertion.
    let sizes: Vec<usize> = buckets.iter().map(Vec::len).collect();
    let shares = fair_shares(&sizes, MAX_CANDIDATES);
    buckets
        .into_iter()
        .zip(shares)
        .flat_map(|(mut bucket, share)| {
            bucket.truncate(share);
            bucket
        })
        .collect()
}

/// Whether a candidate survives the DNS presence pre-filter and warrants a
/// full registry lookup. `Absent` (NXDOMAIN) is treated as unregistered and
/// dropped; `Unknown` (a failed probe) is not evidence, so it is kept — this
/// mirrors the smart-lookup thin-fallback ladder's handling of a failed probe.
fn survives_prefilter(presence: DnsPresence) -> bool {
    !matches!(presence, DnsPresence::Absent)
}

/// Turns a candidate's lookup into a registered look-alike, or `None` when
/// the lookup says the name appears available.
///
/// Only an availability claim drops a candidate. `LookupResult::Available`
/// (and so `DomainInfoSource::Available`) also carries *registered* verdicts
/// — a delegated apex behind a failed registry leg (`dns_present`), a
/// throttled registry (`inconclusive`) — and dropping those silently hid
/// registered look-alikes, exactly the ones a brand-protection scan exists
/// to surface.
fn lookalike_from_result(
    cand: ConfusableCandidate,
    result: &LookupResult,
) -> Option<RegisteredLookalike> {
    if let LookupResult::Available { data, .. } = result {
        if data.available {
            return None;
        }
    }
    let info = DomainInfo::from_lookup_result(result);
    Some(RegisteredLookalike {
        domain: cand.domain,
        technique: cand.technique,
        registrar: info.registrar,
        creation_date: info.creation_date,
        nameservers: info.nameservers,
    })
}

/// Orders registered look-alikes newest registration first, undated entries
/// last; ties (and undated entries) by domain name for a stable report.
fn rank_lookalikes(registered: &mut [RegisteredLookalike]) {
    registered.sort_by(|a, b| match (a.creation_date, b.creation_date) {
        (Some(ad), Some(bd)) => bd.cmp(&ad).then_with(|| a.domain.cmp(&b.domain)),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.domain.cmp(&b.domain),
    });
}

/// Scores which `candidates` are registered.
///
/// Candidates are first pre-filtered by a cheap DNS presence probe: those that
/// return `NXDOMAIN` are unregistered and dropped without a registry lookup
/// (see the module docs). The survivors get a full smart lookup and are kept
/// unless the lookup says the name appears available. Only that claim drops
/// one: an inconclusive lookup (a throttled registry) or a DNS-only
/// registration signal keeps it.
///
/// Returns the ranked registered look-alikes together with the number of
/// candidates that passed the pre-filter and received a full lookup — the
/// accurate `candidates_checked` figure for the report.
///
/// The full lookups run up to `concurrency` at a time; the pre-filter probes
/// run up to 50 at a time, independent of `concurrency`.
pub async fn score_candidates(
    lookup: &SmartLookup,
    candidates: Vec<ConfusableCandidate>,
    concurrency: usize,
) -> (Vec<RegisteredLookalike>, usize) {
    score_with(lookup, candidates, FanOut::shared(concurrency, 1)).await
}

/// How many pre-filter probes and full lookups one scan runs at a time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FanOut {
    prefilter: usize,
    lookups: usize,
}

impl FanOut {
    /// One scan's budget (`concurrency` lookups, at least 50 probes) split
    /// evenly across `scans` scans running at once, so a bulk batch of
    /// confusables scans keeps the total in flight within that budget instead
    /// of multiplying it (50 rows × 50 lookups).
    fn shared(concurrency: usize, scans: usize) -> Self {
        let concurrency = concurrency.max(1);
        let scans = scans.max(1);
        Self {
            prefilter: (concurrency.max(PREFILTER_CONCURRENCY) / scans).max(1),
            lookups: (concurrency / scans).max(1),
        }
    }
}

async fn score_with(
    lookup: &SmartLookup,
    candidates: Vec<ConfusableCandidate>,
    fan_out: FanOut,
) -> (Vec<RegisteredLookalike>, usize) {
    use futures::stream::{self, StreamExt};

    // Pre-filter: probe DNS presence and drop NXDOMAIN candidates before any
    // registry query. A wider fan-out is fine here — DNS is far cheaper than a
    // full RDAP+WHOIS race.
    let survivors: Vec<ConfusableCandidate> = stream::iter(candidates)
        .map(|cand| async move {
            survives_prefilter(lookup.presence(&cand.domain).await).then_some(cand)
        })
        .buffer_unordered(fan_out.prefilter)
        .filter_map(|c| async move { c })
        .collect()
        .await;

    let candidates_checked = survivors.len();

    let mut registered: Vec<RegisteredLookalike> = stream::iter(survivors)
        .map(|cand| async move {
            let result = lookup.lookup(&cand.domain).await.ok()?;
            lookalike_from_result(cand, &result)
        })
        .buffer_unordered(fan_out.lookups)
        .filter_map(|r| async move { r })
        .collect()
        .await;

    // Freshly-registered squats are the most actionable — newest first,
    // undated entries last.
    rank_lookalikes(&mut registered);
    (registered, candidates_checked)
}

/// Generates look-alike candidates for `domain` and scores which are
/// registered, returning a ranked [`ConfusableReport`].
///
/// A subdomain is scanned at its registrable domain (see
/// [`generate_candidates`]); the report keeps the name as given.
pub async fn find_confusables(
    lookup: &SmartLookup,
    domain: &str,
    concurrency: usize,
) -> Result<ConfusableReport> {
    find_confusables_shared(lookup, domain, concurrency, 1).await
}

/// [`find_confusables`] for one of `scans` scans running concurrently (a
/// bulk batch): the per-scan fan-out is `concurrency` divided among them.
pub(crate) async fn find_confusables_shared(
    lookup: &SmartLookup,
    domain: &str,
    concurrency: usize,
    scans: usize,
) -> Result<ConfusableReport> {
    let domain = normalize_domain(domain)?;
    let candidates = generate_candidates(&domain);
    let candidates_generated = candidates.len();
    let (registered, candidates_checked) =
        score_with(lookup, candidates, FanOut::shared(concurrency, scans)).await;
    Ok(ConfusableReport {
        domain,
        candidates_generated,
        candidates_checked,
        registered,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn domains(candidates: &[ConfusableCandidate]) -> Vec<&str> {
        candidates.iter().map(|c| c.domain.as_str()).collect()
    }

    #[test]
    fn generates_omission_transposition_and_tld_swaps() {
        let cands = generate_candidates("example.com");
        let d = domains(&cands);
        // Omission of the leading 'e'.
        assert!(d.contains(&"xample.com"), "omission missing");
        // Transposition of 'xa' -> 'ax'.
        assert!(d.contains(&"eaxmple.com"), "transposition missing");
        // TLD swap.
        assert!(d.contains(&"example.net"), "tld-swap missing");
        // Homoglyph e -> 3.
        assert!(d.contains(&"3xample.com"), "homoglyph missing");
    }

    #[test]
    fn never_includes_the_original_and_is_deduped() {
        let cands = generate_candidates("example.com");
        assert!(!cands.iter().any(|c| c.domain == "example.com"));
        let mut uniq = HashSet::new();
        for c in &cands {
            assert!(uniq.insert(&c.domain), "duplicate candidate: {}", c.domain);
        }
    }

    #[test]
    fn subdomain_input_is_scanned_at_its_registrable_domain() {
        // `mail.xample.com` was generated before: a host the squatter never
        // creates, whose NXDOMAIN presence probe dropped the real squat
        // `xample.com`. Candidates are registrations, so subdomain labels go.
        let cands = generate_candidates("mail.example.com");
        assert_eq!(cands, generate_candidates("example.com"));
        assert!(cands
            .iter()
            .any(|c| c.domain == "xample.com" && c.technique == "omission"));
        assert!(cands
            .iter()
            .any(|c| c.domain == "example.net" && c.technique == "tld-swap"));
        assert!(cands.iter().all(|c| !c.domain.contains("mail")));
        // The registrable domain itself is never a candidate.
        assert!(!cands.iter().any(|c| c.domain == "example.com"));
    }

    #[test]
    fn candidates_are_valid_dns_names() {
        // A 63-octet label must not grow past 63 by insertion/repetition.
        let long = format!("{}.com", "a".repeat(63));
        let cands = generate_candidates(&long);
        assert!(!cands.is_empty());
        assert!(cands
            .iter()
            .all(|c| c.domain.split('.').all(|l| l.len() <= 63)));

        // Permuting an A-label must not produce `nx--…`, `x--n…` or
        // undecodable punycode; every surviving `--` label is a valid A-label.
        let cands = generate_candidates("xn--mnchen-3ya.de");
        assert!(!cands.is_empty());
        for c in &cands {
            let label = c.domain.split('.').next().unwrap();
            if label.get(2..4) == Some("--") {
                assert!(label.starts_with("xn--"), "{}", c.domain);
                let (_, ok) = idna::domain_to_unicode(label);
                assert!(ok.is_ok(), "undecodable A-label {}", c.domain);
            }
        }
        assert!(!cands.iter().any(|c| c.domain.starts_with("nx--")));
    }

    #[test]
    fn label_validation_rules() {
        assert!(is_valid_label("example"));
        assert!(is_valid_label("ex-ample"));
        assert!(is_valid_label("xn--mnchen-3ya"));
        assert!(!is_valid_label(""));
        assert!(!is_valid_label("-example"));
        assert!(!is_valid_label("example-"));
        assert!(!is_valid_label(&"a".repeat(64)));
        assert!(is_valid_label(&"a".repeat(63)));
        // Reserved `--` at positions 3–4 outside the IDNA prefix.
        assert!(!is_valid_label("nx--mnchen-3ya"));
        assert!(!is_valid_label("ab--cd"));
        // `xn--` that does not decode (a control char, truncated punycode),
        // does not round-trip, or is malformed.
        assert!(!is_valid_label("xn--mnchen-3ay"));
        assert!(!is_valid_label("xn--zzzz"));
        assert!(!is_valid_label("xn--mnchn-3yae"));
        assert!(!is_valid_label("xn--abc-"));
        assert!(!is_valid_label("xn--example-"));
    }

    #[test]
    fn fan_out_is_shared_across_concurrent_scans() {
        // One scan: `concurrency` lookups, at least 50 probes.
        assert_eq!(
            FanOut::shared(10, 1),
            FanOut {
                prefilter: 50,
                lookups: 10
            }
        );
        // A bulk batch of 10 concurrent scans keeps the same totals.
        assert_eq!(
            FanOut::shared(10, 10),
            FanOut {
                prefilter: 5,
                lookups: 1
            }
        );
        assert_eq!(
            FanOut::shared(50, 50),
            FanOut {
                prefilter: 1,
                lookups: 1
            }
        );
        // Never zero (buffer_unordered(0) would stall).
        assert_eq!(
            FanOut::shared(0, 0),
            FanOut {
                prefilter: 50,
                lookups: 1
            }
        );
    }

    #[test]
    fn candidate_count_is_capped() {
        // A long label produces many insertions; the cap must hold.
        let cands = generate_candidates("averylongexamplelabelname.com");
        assert!(cands.len() <= MAX_CANDIDATES);
    }

    #[test]
    fn tld_swaps_survive_the_cap_for_long_labels() {
        // tld-swaps are generated last; a naive tail truncation dropped every
        // one of them for ~16+ char labels (insertion alone is 26×(L+1)),
        // silently disabling one of the most common real squat patterns for
        // exactly the brand names most worth checking (2026-07-11 review).
        for domain in ["wellsfargobanking.com", "averylongexamplelabelname.com"] {
            let cands = generate_candidates(domain);
            assert!(cands.len() <= MAX_CANDIDATES);
            let swaps = cands.iter().filter(|c| c.technique == "tld-swap").count();
            assert_eq!(
                swaps,
                SWAP_TLDS.len() - 1, // minus the domain's own TLD
                "{domain}: every tld-swap candidate must survive the cap"
            );
        }
    }

    #[test]
    fn variants_are_valid_labels() {
        // No candidate label may start/end with a hyphen or be empty.
        for c in generate_candidates("ab.com") {
            let label = c.domain.rsplit_once('.').unwrap().0;
            assert!(!label.is_empty());
            assert!(!label.starts_with('-') && !label.ends_with('-'));
        }
    }

    #[test]
    fn single_label_input_yields_nothing() {
        assert!(generate_candidates("localhost").is_empty());
    }

    #[test]
    fn prefilter_drops_only_nxdomain_candidates() {
        // NXDOMAIN (Absent) is the unregistered signal → drop it. A delegated
        // apex (Present) and a failed probe (Unknown) both survive to the full
        // lookup; a failed probe is not evidence, mirroring the smart-lookup
        // thin-fallback ladder.
        assert!(!survives_prefilter(DnsPresence::Absent));
        assert!(survives_prefilter(DnsPresence::Present));
        assert!(survives_prefilter(DnsPresence::Unknown));
    }

    // ---- multi-label public suffixes (PSL) --------------------------------

    #[test]
    fn multi_label_suffix_permutes_the_brand_not_the_suffix() {
        // `example.co.uk` used to permute `co` (example.o.uk, example.oc.uk)
        // and never vary `example`.
        let cands = generate_candidates("example.co.uk");
        let d = domains(&cands);
        assert!(d.contains(&"xample.co.uk"), "omission of the brand label");
        assert!(d.contains(&"3xample.co.uk"), "homoglyph of the brand label");
        assert!(
            d.contains(&"example.com"),
            "tld-swap replaces the whole suffix"
        );
        assert!(!d
            .iter()
            .any(|c| c.ends_with(".o.uk") || c.ends_with(".oc.uk")));
        assert!(cands
            .iter()
            .all(|c| c.domain.ends_with(".co.uk") || c.technique == "tld-swap"));

        // A subdomain under a multi-label suffix is scanned at its
        // registrable domain.
        let cands = generate_candidates("shop.example.com.au");
        assert!(cands
            .iter()
            .any(|c| c.domain == "xample.com.au" && c.technique == "omission"));
        assert!(cands.iter().all(|c| !c.domain.starts_with("shop.")));
    }

    #[test]
    fn bare_public_suffix_yields_nothing() {
        assert!(generate_candidates("co.uk").is_empty());
    }

    // ---- per-technique budget ----------------------------------------------

    #[test]
    fn fair_shares_only_trims_buckets_above_an_equal_split() {
        // Small buckets keep everything; the big one absorbs the cut.
        assert_eq!(fair_shares(&[5, 500, 10], 100), vec![5, 85, 10]);
        // Under the cap, nothing is trimmed.
        assert_eq!(fair_shares(&[3, 4], 100), vec![3, 4]);
        // Two oversized buckets split what is left evenly.
        assert_eq!(fair_shares(&[2, 300, 300], 102), vec![2, 50, 50]);
        assert_eq!(fair_shares(&[], 10), Vec::<usize>::new());
    }

    #[test]
    fn every_technique_survives_the_cap() {
        // `paypalsecurelogin.com` used to keep 0 of its 13 homoglyphs (and no
        // bitsquats): they were generated after ~590 insertions and cut first.
        let cands = generate_candidates("paypalsecurelogin.com");
        assert_eq!(
            cands.len(),
            MAX_CANDIDATES,
            "long label still fills the cap"
        );
        for technique in [
            "omission",
            "transposition",
            "repetition",
            "replacement",
            "insertion",
            "bitsquat",
            "homoglyph",
            "tld-swap",
        ] {
            assert!(
                cands.iter().any(|c| c.technique == technique),
                "{technique} missing after the cap"
            );
        }
        let homoglyph_count = cands.iter().filter(|c| c.technique == "homoglyph").count();
        assert_eq!(homoglyph_count, 13, "all homoglyph variants are kept");
        // Only insertion (the bulk technique) is trimmed.
        let insertions = cands.iter().filter(|c| c.technique == "insertion").count();
        assert!(insertions < 26 * ("paypalsecurelogin".len() + 1));
    }

    // ---- ranking -------------------------------------------------------------

    fn lookalike(domain: &str, created: Option<&str>) -> RegisteredLookalike {
        RegisteredLookalike {
            domain: domain.to_string(),
            technique: "omission".to_string(),
            registrar: None,
            creation_date: created.map(|d| d.parse().expect("valid RFC 3339 date")),
            nameservers: Vec::new(),
        }
    }

    #[test]
    fn ranking_is_newest_first_with_undated_last() {
        let mut v = vec![
            lookalike("undated-b.com", None),
            lookalike("old.com", Some("2015-01-01T00:00:00Z")),
            lookalike("undated-a.com", None),
            lookalike("new.com", Some("2026-01-01T00:00:00Z")),
        ];
        rank_lookalikes(&mut v);
        let order: Vec<&str> = v.iter().map(|l| l.domain.as_str()).collect();
        assert_eq!(
            order,
            vec!["new.com", "old.com", "undated-a.com", "undated-b.com"]
        );
    }

    // ---- which lookups count as registered -----------------------------

    fn available_result(available: bool, confidence: &str, method: &str) -> LookupResult {
        LookupResult::Available {
            data: Box::new(crate::availability::AvailabilityResult {
                domain: "exmple.com".to_string(),
                available,
                confidence: confidence.to_string(),
                method: method.to_string(),
                details: None,
            }),
            rdap_error: String::new(),
            whois_error: String::new(),
            whois_data: None,
        }
    }

    fn cand() -> ConfusableCandidate {
        ConfusableCandidate {
            domain: "exmple.com".to_string(),
            technique: "omission".to_string(),
        }
    }

    #[test]
    fn registered_verdicts_from_the_availability_path_are_kept() {
        // A delegated apex behind a failed registry leg is registered; it
        // used to be dropped because its DomainInfo source is `Available`.
        let kept = lookalike_from_result(cand(), &available_result(false, "high", "dns_present"));
        assert_eq!(kept.map(|l| l.domain).as_deref(), Some("exmple.com"));
        assert!(
            lookalike_from_result(cand(), &available_result(false, "none", "inconclusive"))
                .is_some()
        );

        // Only an availability claim drops the candidate.
        assert!(lookalike_from_result(cand(), &available_result(true, "high", "rdap")).is_none());
        assert!(
            lookalike_from_result(cand(), &available_result(true, "medium", "dns_nxdomain"))
                .is_none()
        );
    }
}
