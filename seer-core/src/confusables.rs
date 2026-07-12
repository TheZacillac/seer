//! Typosquat / homoglyph look-alike generation and registration scoring.
//!
//! Given a domain, generates candidate look-alikes (typo permutations plus a
//! small ASCII-homoglyph map and common TLD swaps) and scores which candidates
//! are registered, ranking freshly-registered squats first. This is a
//! brand-protection / phishing-defense capability built entirely on primitives
//! seer already has (normalization, smart lookup, availability inference) — no
//! new protocol code.
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

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::dns::DnsPresence;
use crate::domain_info::{DomainInfo, DomainInfoSource};
use crate::error::Result;
use crate::lookup::SmartLookup;
use crate::validation::normalize_domain;

/// Upper bound on generated candidates, to keep the subsequent network scoring
/// bounded regardless of label length.
const MAX_CANDIDATES: usize = 600;

/// Concurrency for the cheap DNS presence pre-filter. DNS probes are far
/// lighter than a full RDAP+WHOIS race, so we fan them out wider than the
/// (registry-facing) full-lookup concurrency to keep the pre-filter fast.
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

/// Generates typo/homoglyph look-alike candidates for `domain`.
///
/// The final DNS label (the registrable label preceding the TLD) is permuted;
/// the rest of the name (any subdomains) and the TLD are preserved, except for
/// the dedicated `tld-swap` technique. Output is deduplicated, excludes the
/// input itself, and capped at [`MAX_CANDIDATES`].
pub fn generate_candidates(domain: &str) -> Vec<ConfusableCandidate> {
    let Ok(normalized) = normalize_domain(domain) else {
        return Vec::new();
    };
    let Some((prefix, tld)) = normalized.rsplit_once('.') else {
        return Vec::new();
    };
    // Permute only the leftmost label of the prefix (the registrable label),
    // keeping any deeper subdomain labels fixed.
    let (sub, label) = match prefix.rsplit_once('.') {
        Some((sub, label)) => (Some(sub), label),
        None => (None, prefix),
    };

    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::new();
    let mut push = |label_variant: String, technique: &str, out: &mut Vec<ConfusableCandidate>| {
        if label_variant.is_empty()
            || label_variant.starts_with('-')
            || label_variant.ends_with('-')
        {
            return;
        }
        let candidate = match sub {
            Some(sub) => format!("{sub}.{label_variant}.{tld}"),
            None => format!("{label_variant}.{tld}"),
        };
        if candidate != normalized && seen.insert(candidate.clone()) {
            out.push(ConfusableCandidate {
                domain: candidate,
                technique: technique.to_string(),
            });
        }
    };

    let chars: Vec<char> = label.chars().collect();

    // Omission: drop each character.
    for i in 0..chars.len() {
        let mut v = chars.clone();
        v.remove(i);
        push(v.into_iter().collect(), "omission", &mut out);
    }

    // Transposition: swap adjacent characters.
    for i in 0..chars.len().saturating_sub(1) {
        let mut v = chars.clone();
        v.swap(i, i + 1);
        push(v.into_iter().collect(), "transposition", &mut out);
    }

    // Repetition: double each character.
    for i in 0..chars.len() {
        let mut v = chars.clone();
        v.insert(i, chars[i]);
        push(v.into_iter().collect(), "repetition", &mut out);
    }

    // Adjacent-key replacement.
    for (i, &c) in chars.iter().enumerate() {
        for &n in keyboard_neighbors(c) {
            let mut v = chars.clone();
            v[i] = n;
            push(v.into_iter().collect(), "replacement", &mut out);
        }
    }

    // Insertion: insert each lowercase letter at every gap.
    for i in 0..=chars.len() {
        for n in b'a'..=b'z' {
            let mut v = chars.clone();
            v.insert(i, n as char);
            push(v.into_iter().collect(), "insertion", &mut out);
        }
    }

    // Bitsquatting: flip each bit of each byte; keep valid LDH results.
    for (i, &c) in chars.iter().enumerate() {
        if !c.is_ascii() {
            continue;
        }
        for bit in 0..7 {
            let flipped = (c as u8) ^ (1 << bit);
            let fc = flipped as char;
            if is_ldh(fc) && fc != c {
                let mut v = chars.clone();
                v[i] = fc;
                push(v.into_iter().collect(), "bitsquat", &mut out);
            }
        }
    }

    // Homoglyph substitution.
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
            push(variant, "homoglyph", &mut out);
        }
    }

    // TLD swap: keep the label, swap the TLD. Collected separately so the
    // cap below cannot drop them: label permutations grow with label length
    // (insertion alone is 26×(L+1)), and a plain tail truncation silently
    // discarded every tld-swap for ~16+ char labels.
    let mut swaps = Vec::new();
    for &swap in SWAP_TLDS {
        if swap != tld {
            let candidate = match sub {
                Some(sub) => format!("{sub}.{label}.{swap}"),
                None => format!("{label}.{swap}"),
            };
            if candidate != normalized && seen.insert(candidate.clone()) {
                swaps.push(ConfusableCandidate {
                    domain: candidate,
                    technique: "tld-swap".to_string(),
                });
            }
        }
    }

    // Budget the cap: tld-swaps (a dozen at most) always fit; the label
    // permutations absorb the truncation.
    out.truncate(MAX_CANDIDATES.saturating_sub(swaps.len()));
    out.extend(swaps);
    out
}

/// Whether a candidate survives the DNS presence pre-filter and warrants a
/// full registry lookup. `Absent` (NXDOMAIN) is treated as unregistered and
/// dropped; `Unknown` (a failed probe) is not evidence, so it is kept — this
/// mirrors the smart-lookup thin-fallback ladder's handling of a failed probe.
fn survives_prefilter(presence: DnsPresence) -> bool {
    !matches!(presence, DnsPresence::Absent)
}

/// Scores which `candidates` are registered.
///
/// Candidates are first pre-filtered by a cheap DNS presence probe: those that
/// return `NXDOMAIN` are unregistered and dropped without a registry lookup
/// (see the module docs). The survivors get a full smart lookup and are kept
/// when the merged [`DomainInfo`] reports a non-`Available` source.
///
/// Returns the ranked registered look-alikes together with the number of
/// candidates that passed the pre-filter and received a full lookup — the
/// accurate `candidates_checked` figure for the report.
///
/// The full lookups run up to `concurrency` at a time; the pre-filter probes
/// run at [`PREFILTER_CONCURRENCY`].
pub async fn score_candidates(
    lookup: &SmartLookup,
    candidates: Vec<ConfusableCandidate>,
    concurrency: usize,
) -> (Vec<RegisteredLookalike>, usize) {
    use futures::stream::{self, StreamExt};

    let concurrency = concurrency.max(1);

    // Pre-filter: probe DNS presence and drop NXDOMAIN candidates before any
    // registry query. A wider fan-out is fine here — DNS is far cheaper than a
    // full RDAP+WHOIS race.
    let prefilter_concurrency = concurrency.max(PREFILTER_CONCURRENCY);
    let survivors: Vec<ConfusableCandidate> = stream::iter(candidates)
        .map(|cand| async move {
            survives_prefilter(lookup.presence(&cand.domain).await).then_some(cand)
        })
        .buffer_unordered(prefilter_concurrency)
        .filter_map(|c| async move { c })
        .collect()
        .await;

    let candidates_checked = survivors.len();

    let mut registered: Vec<RegisteredLookalike> = stream::iter(survivors)
        .map(|cand| async move {
            let result = lookup.lookup(&cand.domain).await.ok()?;
            let info = DomainInfo::from_lookup_result(&result);
            if info.source == DomainInfoSource::Available {
                return None;
            }
            Some(RegisteredLookalike {
                domain: cand.domain,
                technique: cand.technique,
                registrar: info.registrar,
                creation_date: info.creation_date,
                nameservers: info.nameservers,
            })
        })
        .buffer_unordered(concurrency)
        .filter_map(|r| async move { r })
        .collect()
        .await;

    // Freshly-registered squats are the most actionable — sort newest first,
    // undated entries last.
    registered.sort_by(|a, b| match (b.creation_date, a.creation_date) {
        (Some(bd), Some(ad)) => bd.cmp(&ad),
        (Some(_), None) => std::cmp::Ordering::Less,
        (None, Some(_)) => std::cmp::Ordering::Greater,
        (None, None) => a.domain.cmp(&b.domain),
    });
    (registered, candidates_checked)
}

/// Generates look-alike candidates for `domain` and scores which are
/// registered, returning a ranked [`ConfusableReport`].
pub async fn find_confusables(
    lookup: &SmartLookup,
    domain: &str,
    concurrency: usize,
) -> Result<ConfusableReport> {
    let domain = normalize_domain(domain)?;
    let candidates = generate_candidates(&domain);
    let candidates_generated = candidates.len();
    let (registered, candidates_checked) = score_candidates(lookup, candidates, concurrency).await;
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
        let mut uniq = std::collections::HashSet::new();
        for c in &cands {
            assert!(uniq.insert(&c.domain), "duplicate candidate: {}", c.domain);
        }
    }

    #[test]
    fn preserves_subdomains_and_only_permutes_registrable_label() {
        let cands = generate_candidates("mail.example.com");
        // Every candidate (except tld-swaps) keeps the "mail." subdomain and
        // ".com" tld; the middle label is what varies.
        assert!(cands
            .iter()
            .any(|c| c.domain == "mail.xample.com" && c.technique == "omission"));
        assert!(cands
            .iter()
            .all(|c| c.domain.starts_with("mail.") || c.technique == "tld-swap"));
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
}
