//! Optional resolve-and-classify pass over enumerated subdomains.
//!
//! CT-log enumeration returns a flat name list with no signal about which
//! hosts are alive or hijackable. This stage resolves each name, marks it
//! live / dead / wildcard, and flags dangling CNAMEs that point at
//! takeover-prone providers — turning a name dump into an attack-surface
//! report. It reuses the existing [`DnsResolver`] and anti-SSRF path, plus the
//! provider table and host resolution of [`crate::takeover`] (the HTTP half of
//! takeover detection), so both surfaces agree on what is takeover-prone.
//!
//! Wildcard DNS is detected per level: each distinct parent of a classified
//! name (`dev.example.com` for `api.dev.example.com`) is probed once with a
//! fresh random sibling (`seer-probe-<hex>`, the label `seer dig` uses), so a
//! `*.dev.example.com` wildcard is caught as well as one at the apex, and a
//! zone cannot special-case a fixed probe name.

use std::collections::{BTreeSet, HashMap};

use serde::{Deserialize, Serialize};

use crate::dns::DnsResolver;
use crate::takeover::{resolve_host, truncate_to_cap};

/// What a random name directly under one parent resolved to, when it did:
/// the level has a wildcard. Only its CNAME target matters — a CDN-backed
/// wildcard rotates its addresses, so addresses are not compared.
#[derive(Debug, Clone, PartialEq, Eq)]
struct WildcardAnswer {
    cname: Option<String>,
}

/// Upper bound on the number of enumerated names that get resolved and
/// classified in a single pass. CT logs can return tens of thousands of names
/// for a large target, and each name issues two live DNS queries (A + CNAME);
/// the `concurrency` limit caps parallelism but not total work. 2000 names
/// (up to ~4000 queries) is a defensible ceiling that covers essentially every
/// real zone while bounding the DNS fan-out. Names beyond the cap are reported
/// as skipped rather than silently dropped. The public docs of
/// [`classify_subdomains`] and [`SubdomainClassification::names_skipped`]
/// state the value; keep them in step.
const MAX_CLASSIFY_NAMES: usize = 2000;

/// Liveness classification of a single subdomain.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubdomainStatus {
    /// Resolves, and is not explained by a wildcard at its level.
    Live,
    /// Does not resolve to any address.
    Dead,
    /// Resolves, but so does a random name at the same level (a zone
    /// wildcard) with the same CNAME target (or none), so it cannot be told
    /// apart from wildcard synthesis — probably not a distinct real host.
    Wildcard,
    /// The address lookup failed (timeout, SERVFAIL) rather than answering,
    /// so whether the name is live is unknown. Never treated as dangling.
    Unknown,
}

/// A subdomain annotated with resolution and takeover signal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifiedSubdomain {
    pub name: String,
    pub status: SubdomainStatus,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cname: Option<String>,
    /// The provider name when this is a dangling CNAME to a takeover-prone
    /// service (CNAME matches a fingerprint and the name does not resolve).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub takeover_risk: Option<String>,
}

/// The result of a classification pass over an enumerated subdomain list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubdomainClassification {
    pub domain: String,
    /// Whether a random nonexistent name answered at any probed level
    /// (wildcard DNS at the apex or below it).
    pub wildcard_detected: bool,
    pub subdomains: Vec<ClassifiedSubdomain>,
    /// Number of enumerated names dropped before classification because the
    /// input exceeded the 2000-name cap. Zero when nothing was capped.
    /// `#[serde(default)]` keeps older history files (without this field)
    /// deserializable.
    #[serde(default)]
    pub names_skipped: usize,
}

/// A CNAME target in comparable form.
fn cname_key(cname: Option<&str>) -> Option<String> {
    cname.map(|c| c.trim_end_matches('.').to_ascii_lowercase())
}

/// Classifies a single name given what a random sibling at its level
/// resolved to (`None`: no wildcard there). Pure given inputs.
///
/// Under a wildcard, a resolving name is `Wildcard` unless its CNAME target
/// differs from the wildcard's — an explicitly configured alias — in which
/// case it is `Live`. Addresses are deliberately not compared: a CDN-backed
/// wildcard answers from a rotating pool, so an exact-IP match read every
/// wildcard-synthesized name as live.
///
/// `provider` is the takeover-prone provider any hop of the name's CNAME
/// chain points at (`resolve_host` walks the chain), not just the first.
fn classify_one(
    name: String,
    addresses: Vec<String>,
    cname: Option<String>,
    provider: Option<&'static str>,
    lookup_failed: bool,
    wildcard: Option<&WildcardAnswer>,
) -> ClassifiedSubdomain {
    let status = if addresses.is_empty() && lookup_failed {
        // No answer is not the same as "no records": a timed-out lookup must
        // not be reported dead, nor flagged as a dangling takeover risk.
        SubdomainStatus::Unknown
    } else if addresses.is_empty() {
        SubdomainStatus::Dead
    } else {
        match wildcard {
            Some(w) if cname_key(cname.as_deref()) == cname_key(w.cname.as_deref()) => {
                SubdomainStatus::Wildcard
            }
            _ => SubdomainStatus::Live,
        }
    };

    // A dangling CNAME: points at a takeover-prone provider yet does not
    // resolve to any address.
    let takeover_risk = match status {
        SubdomainStatus::Dead => provider.map(str::to_string),
        _ => None,
    };

    ClassifiedSubdomain {
        name,
        status,
        addresses,
        cname,
        takeover_risk,
    }
}

/// The level a name's wildcard would sit at: its parent (`dev.example.com`
/// for `api.dev.example.com`).
fn parent_of(name: &str) -> Option<&str> {
    name.split_once('.').map(|(_, parent)| parent)
}

/// Probes each parent once with a fresh random sibling, up to `concurrency`
/// at a time. A parent maps to `Some` when its probe resolved (a wildcard at
/// that level); a probe that failed or found nothing is `None`.
async fn probe_parents(
    resolver: &DnsResolver,
    parents: BTreeSet<String>,
    concurrency: usize,
) -> HashMap<String, Option<WildcardAnswer>> {
    use futures::stream::{self, StreamExt};

    stream::iter(parents)
        .map(|parent| async move {
            let probe = format!("{}.{parent}", crate::dns::random_probe_label());
            let r = resolve_host(resolver, &probe).await;
            let answer = (!r.addresses.is_empty()).then_some(WildcardAnswer { cname: r.cname });
            (parent, answer)
        })
        .buffer_unordered(concurrency)
        .collect()
        .await
}

/// Resolves and classifies each name in `names` for `domain`, detecting
/// wildcard DNS at each name's level to suppress false-positive "live"
/// verdicts and flagging dangling CNAMEs to takeover-prone providers. At most
/// 2000 names are resolved; any beyond that are reported in
/// [`SubdomainClassification::names_skipped`]. Runs up to `concurrency`
/// resolutions at a time.
pub async fn classify_subdomains(
    resolver: &DnsResolver,
    domain: &str,
    mut names: Vec<String>,
    concurrency: usize,
) -> SubdomainClassification {
    use futures::stream::{self, StreamExt};

    // Cap total work: classify at most MAX_CLASSIFY_NAMES names (the caller has
    // already deduped/sorted them via `build_result`), keeping the first N and
    // reporting the remainder as skipped so the truncation is never silent.
    let names_skipped = truncate_to_cap(&mut names, MAX_CLASSIFY_NAMES);
    let concurrency = concurrency.max(1);

    // Probe every distinct level once (the apex for `api.example.com`,
    // `dev.example.com` for `api.dev.example.com`).
    let parents: BTreeSet<String> = names
        .iter()
        .filter_map(|n| parent_of(n))
        .map(str::to_string)
        .collect();
    let wildcards = probe_parents(resolver, parents, concurrency).await;
    let wildcard_detected = wildcards.values().any(Option::is_some);
    let wildcards = &wildcards;

    let mut subdomains: Vec<ClassifiedSubdomain> = stream::iter(names)
        .map(|name| async move {
            // `lookup_error` is set only when no address answered and a
            // lookup failed outright — exactly the "unknown" signal.
            let r = resolve_host(resolver, &name).await;
            let failed = r.lookup_error.is_some();
            let wildcard = parent_of(&name)
                .and_then(|p| wildcards.get(p))
                .and_then(Option::as_ref);
            let provider = r.provider.map(|(p, _)| p.provider);
            classify_one(name, r.addresses, r.cname, provider, failed, wildcard)
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    // Stable, useful order: takeover risks first, then live, then the rest,
    // alphabetical within each group.
    subdomains.sort_by(|a, b| {
        let rank = |s: &ClassifiedSubdomain| {
            if s.takeover_risk.is_some() {
                0
            } else if s.status == SubdomainStatus::Live {
                1
            } else {
                2
            }
        };
        rank(a).cmp(&rank(b)).then_with(|| a.name.cmp(&b.name))
    });

    SubdomainClassification {
        domain: domain.to_string(),
        wildcard_detected,
        subdomains,
        names_skipped,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::takeover::match_provider;

    /// `classify_one` with the provider of a one-hop chain, as
    /// `resolve_host` would report it.
    fn classify(
        name: String,
        addresses: Vec<String>,
        cname: Option<String>,
        lookup_failed: bool,
        wildcard: Option<&WildcardAnswer>,
    ) -> ClassifiedSubdomain {
        let provider = cname
            .as_deref()
            .and_then(match_provider)
            .map(|p| p.provider);
        classify_one(name, addresses, cname, provider, lookup_failed, wildcard)
    }

    /// Regression: only the first CNAME hop was matched, so
    /// `shop → edge.example.net → foo.herokudns.com` was never flagged.
    #[test]
    fn classify_flags_a_provider_deeper_in_the_chain() {
        let c = classify_one(
            "shop.example.com".to_string(),
            vec![],
            Some("edge.example.net".to_string()),
            Some("Heroku"),
            false,
            None,
        );
        assert_eq!(c.takeover_risk.as_deref(), Some("Heroku"));
    }

    /// Regression: classify used to keep its own provider table, which drifted
    /// from `seer takeover`'s (no Tumblr, Webflow, S3 website endpoints, ...,
    /// and `.cloudapp.net` mislabeled "Azure Cloud Service"). Every CNAME shape
    /// the takeover table knows must flag here, under the same provider name.
    #[test]
    fn classify_flags_every_takeover_provider() {
        let dangling = |cname: &str| {
            classify(
                "gone.example.com".to_string(),
                vec![],
                Some(cname.to_string()),
                false,
                None,
            )
            .takeover_risk
        };
        for p in crate::takeover::PROVIDERS {
            let suffixes = p.cname_suffixes.iter().map(|s| format!("gone{s}"));
            let infixes = p.cname_infixes.iter().map(|i| format!("gone{i}.example"));
            for cname in suffixes.chain(infixes) {
                assert_eq!(dangling(&cname).as_deref(), Some(p.provider), "{cname}");
            }
        }
        // An unrelated target and a bare provider apex are not takeover-prone.
        assert_eq!(dangling("cdn.example.com"), None);
        assert_eq!(dangling("github.io"), None);
    }

    #[test]
    fn classify_dead_cname_to_provider_is_takeover_risk() {
        let c = classify(
            "gone.example.com".to_string(),
            vec![], // does not resolve
            Some("gone.herokuapp.com".to_string()),
            false,
            None,
        );
        assert_eq!(c.status, SubdomainStatus::Dead);
        assert_eq!(c.takeover_risk.as_deref(), Some("Heroku"));
    }

    #[test]
    fn classify_failed_lookup_is_unknown_not_dangling() {
        // A timed-out lookup with a provider CNAME used to read as Dead + a
        // takeover risk; an unanswered query proves nothing.
        let c = classify(
            "slow.example.com".to_string(),
            vec![],
            Some("slow.herokuapp.com".to_string()),
            true,
            None,
        );
        assert_eq!(c.status, SubdomainStatus::Unknown);
        assert!(c.takeover_risk.is_none());
        // If the other family answered, the host is simply live.
        let c = classify(
            "v6.example.com".to_string(),
            vec!["2001:db8::1".to_string()],
            None,
            true,
            None,
        );
        assert_eq!(c.status, SubdomainStatus::Live);
    }

    #[test]
    fn classify_live_host_is_not_takeover_even_with_provider_cname() {
        // Resolves to an address → not dangling, so no takeover flag.
        let c = classify(
            "live.example.com".to_string(),
            vec!["203.0.113.5".to_string()],
            Some("live.herokuapp.com".to_string()),
            false,
            None,
        );
        assert_eq!(c.status, SubdomainStatus::Live);
        assert!(c.takeover_risk.is_none());
    }

    #[test]
    fn classify_under_a_wildcard_compares_presence_not_addresses() {
        // Regression: exact-IP equality read a CDN wildcard's rotating
        // addresses as distinct live hosts.
        let wildcard = WildcardAnswer { cname: None };
        let c = classify(
            "anything.example.com".to_string(),
            vec!["203.0.113.7".to_string()],
            None,
            false,
            Some(&wildcard),
        );
        assert_eq!(c.status, SubdomainStatus::Wildcard);

        // Same wildcard CNAME target (case/trailing dot aside): synthesized.
        let wildcard = WildcardAnswer {
            cname: Some("edge.cdn.test.".to_string()),
        };
        let c = classify(
            "x.example.com".to_string(),
            vec!["203.0.113.7".to_string()],
            Some("EDGE.cdn.test".to_string()),
            false,
            Some(&wildcard),
        );
        assert_eq!(c.status, SubdomainStatus::Wildcard);
    }

    #[test]
    fn classify_a_distinct_alias_under_a_wildcard_is_live() {
        // An explicitly configured CNAME the wildcard does not synthesize.
        let wildcard = WildcardAnswer { cname: None };
        let c = classify(
            "shop.example.com".to_string(),
            vec!["203.0.113.7".to_string()],
            Some("shops.myshopify.com".to_string()),
            false,
            Some(&wildcard),
        );
        assert_eq!(c.status, SubdomainStatus::Live);
        // No wildcard at the level: resolving is live.
        let c = classify(
            "real.example.com".to_string(),
            vec!["203.0.113.7".to_string()],
            None,
            false,
            None,
        );
        assert_eq!(c.status, SubdomainStatus::Live);
    }

    /// Regression: only the apex was probed, with a fixed label, so a
    /// `*.dev.example.com` wildcard went unnoticed and every name under it
    /// read Live. Each level is probed with its own random label.
    #[tokio::test]
    async fn wildcards_below_the_apex_are_detected() {
        use crate::dns::test_support::{
            a_rdata, mock_dns_resolver_default, spawn_mock_dns_fn, MockReply,
        };
        use hickory_resolver::proto::rr::RecordType as WireType;

        // The wildcard rotates its address on every answer.
        let mut rotation = 10u8;
        let port = spawn_mock_dns_fn(move |qname, qtype| {
            let in_dev = qname.ends_with(".dev.seer.test");
            match qtype {
                WireType::A if in_dev => {
                    rotation += 1;
                    MockReply::Answer(vec![a_rdata([192, 0, 2, rotation])])
                }
                WireType::A if qname == "www.seer.test" => {
                    MockReply::Answer(vec![a_rdata([192, 0, 2, 1])])
                }
                _ if in_dev || qname == "www.seer.test" => MockReply::NoData,
                _ => MockReply::NxDomain,
            }
        })
        .await;
        let report = classify_subdomains(
            &mock_dns_resolver_default(port),
            "seer.test",
            vec!["api.dev.seer.test".to_string(), "www.seer.test".to_string()],
            4,
        )
        .await;

        assert!(report.wildcard_detected);
        let status = |name: &str| {
            report
                .subdomains
                .iter()
                .find(|s| s.name == name)
                .map(|s| s.status)
        };
        assert_eq!(status("api.dev.seer.test"), Some(SubdomainStatus::Wildcard));
        assert_eq!(status("www.seer.test"), Some(SubdomainStatus::Live));
    }

    #[test]
    fn classify_cap_keeps_first_n_and_reports_skipped() {
        // Over the cap: keep exactly MAX_CLASSIFY_NAMES, report the overflow.
        let over = MAX_CLASSIFY_NAMES + 37;
        let mut names: Vec<String> = (0..over).map(|i| format!("h{i}.example.com")).collect();
        let skipped = truncate_to_cap(&mut names, MAX_CLASSIFY_NAMES);
        assert_eq!(names.len(), MAX_CLASSIFY_NAMES);
        assert_eq!(skipped, 37);
        // The first N (in the caller's already-sorted order) are the ones kept.
        assert_eq!(names[0], "h0.example.com");
    }

    #[test]
    fn classify_cap_is_noop_under_limit() {
        let mut names: Vec<String> = (0..10).map(|i| format!("h{i}.example.com")).collect();
        let skipped = truncate_to_cap(&mut names, MAX_CLASSIFY_NAMES);
        assert_eq!(names.len(), 10);
        assert_eq!(skipped, 0);
    }
}
