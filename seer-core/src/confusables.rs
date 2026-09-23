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
/// The name is split at its registrable boundary using the Public Suffix
/// List: the brand label is the one immediately left of the ICANN public
/// suffix (`example` in `mail.example.co.uk`). That label is permuted; any
/// deeper subdomain labels and the suffix are preserved, except for the
/// dedicated `tld-swap` technique, which swaps the whole suffix
/// (`example.co.uk` → `example.com`). Output is deduplicated, excludes the
/// input itself, and capped at 600 candidates with the budget shared fairly
/// across techniques: each keeps an equal share (or all of its candidates, if
/// it has fewer), and a small technique's unused share passes to the larger
/// ones. A bare public suffix has no brand label and yields nothing.
pub fn generate_candidates(domain: &str) -> Vec<ConfusableCandidate> {
    let Ok(normalized) = normalize_domain(domain) else {
        return Vec::new();
    };
    let Some(tld) = crate::psl::public_suffix(&normalized) else {
        return Vec::new();
    };
    let Some(prefix) = normalized
        .strip_suffix(tld)
        .and_then(|p| p.strip_suffix('.'))
        .filter(|p| !p.is_empty())
    else {
        return Vec::new();
    };
    // Permute only the registrable label, keeping any deeper subdomain
    // labels fixed.
    let (sub, label) = match prefix.rsplit_once('.') {
        Some((sub, label)) => (Some(sub), label),
        None => (None, prefix),
    };

    // Rebuilds the full candidate name around a permuted label, rejecting
    // labels that are empty or start/end with a hyphen.
    let with_label = |variant: &str| -> Option<String> {
        if variant.is_empty() || variant.starts_with('-') || variant.ends_with('-') {
            return None;
        }
        Some(match sub {
            Some(sub) => format!("{sub}.{variant}.{tld}"),
            None => format!("{variant}.{tld}"),
        })
    };

    let mut seen = HashSet::new();
    // One bucket per technique, in generation order (which also decides
    // attribution when two techniques produce the same name).
    let mut buckets: Vec<Vec<ConfusableCandidate>> = Vec::new();
    let mut emit = |technique: &str, variants: Vec<String>| {
        let mut bucket = Vec::new();
        for variant in variants {
            if let Some(candidate) = with_label(&variant) {
                push_unique(&mut seen, &mut bucket, &normalized, candidate, technique);
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

    // Bitsquatting: flip each bit of each byte; keep valid LDH results.
    let mut bitsquats = Vec::new();
    for (i, &c) in chars.iter().enumerate() {
        if !c.is_ascii() {
            continue;
        }
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
            let candidate = match sub {
                Some(sub) => format!("{sub}.{label}.{swap}"),
                None => format!("{label}.{swap}"),
            };
            push_unique(&mut seen, &mut swaps, &normalized, candidate, "tld-swap");
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
            lookalike_from_result(cand, &result)
        })
        .buffer_unordered(concurrency)
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
        let mut uniq = HashSet::new();
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

        // Subdomains under a multi-label suffix stay fixed too.
        let cands = generate_candidates("shop.example.com.au");
        assert!(cands
            .iter()
            .any(|c| c.domain == "shop.xample.com.au" && c.technique == "omission"));
        assert!(cands
            .iter()
            .all(|c| c.domain.starts_with("shop.") || c.technique == "tld-swap"));
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
