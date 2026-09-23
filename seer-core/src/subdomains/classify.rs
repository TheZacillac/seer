//! Optional resolve-and-classify pass over enumerated subdomains.
//!
//! CT-log enumeration returns a flat name list with no signal about which
//! hosts are alive or hijackable. This stage resolves each name, marks it
//! live / dead / wildcard, and flags dangling CNAMEs that point at
//! takeover-prone providers — turning a name dump into an attack-surface
//! report. It reuses the existing [`DnsResolver`] and anti-SSRF path, plus the
//! provider table and host resolution of [`crate::takeover`] (the HTTP half of
//! takeover detection), so both surfaces agree on what is takeover-prone.

use serde::{Deserialize, Serialize};

use crate::dns::DnsResolver;
use crate::takeover::{match_provider, resolve_host, truncate_to_cap};

/// Label prepended to the domain to probe for wildcard DNS. If this
/// almost-certainly-nonexistent name resolves, the zone has a wildcard record
/// and per-name "live" verdicts based on an A record alone are unreliable.
const WILDCARD_PROBE_LABEL: &str = "zzzz-seer-wildcard-probe-does-not-exist";

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
    /// Resolves to one or more addresses distinct from the wildcard set.
    Live,
    /// Does not resolve to any address.
    Dead,
    /// Only resolves via a zone wildcard (its addresses match the wildcard
    /// probe), so it is probably not a distinct real host.
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
    /// Whether the zone answers for a random nonexistent name (wildcard DNS).
    pub wildcard_detected: bool,
    pub subdomains: Vec<ClassifiedSubdomain>,
    /// Number of enumerated names dropped before classification because the
    /// input exceeded the 2000-name cap. Zero when nothing was capped.
    /// `#[serde(default)]` keeps older history files (without this field)
    /// deserializable.
    #[serde(default)]
    pub names_skipped: usize,
}

/// Classifies a single name given the wildcard address set (pure given inputs).
fn classify_one(
    name: String,
    addresses: Vec<String>,
    cname: Option<String>,
    lookup_failed: bool,
    wildcard_addrs: &[String],
) -> ClassifiedSubdomain {
    let status = if addresses.is_empty() && lookup_failed {
        // No answer is not the same as "no records": a timed-out lookup must
        // not be reported dead, nor flagged as a dangling takeover risk.
        SubdomainStatus::Unknown
    } else if addresses.is_empty() {
        SubdomainStatus::Dead
    } else if !wildcard_addrs.is_empty() && addresses.iter().all(|a| wildcard_addrs.contains(a)) {
        SubdomainStatus::Wildcard
    } else {
        SubdomainStatus::Live
    };

    // A dangling CNAME: points at a takeover-prone provider yet does not
    // resolve to any address.
    let takeover_risk = match (&cname, status) {
        (Some(target), SubdomainStatus::Dead) => {
            match_provider(target).map(|p| p.provider.to_string())
        }
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

/// Resolves and classifies each name in `names` for `domain`, detecting
/// wildcard DNS to suppress false-positive "live" verdicts and flagging
/// dangling CNAMEs to takeover-prone providers. At most 2000 names are
/// resolved; any beyond that are reported in
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

    // Probe for wildcard DNS once.
    let probe = format!("{WILDCARD_PROBE_LABEL}.{domain}");
    let wildcard_addrs = resolve_host(resolver, &probe).await.addresses;
    let wildcard_detected = !wildcard_addrs.is_empty();

    let concurrency = concurrency.max(1);
    let wildcard_addrs = std::sync::Arc::new(wildcard_addrs);

    let mut subdomains: Vec<ClassifiedSubdomain> = stream::iter(names)
        .map(|name| {
            let wildcard_addrs = wildcard_addrs.clone();
            async move {
                // `lookup_error` is set only when no address answered and a
                // lookup failed outright — exactly the "unknown" signal.
                let r = resolve_host(resolver, &name).await;
                let failed = r.lookup_error.is_some();
                classify_one(name, r.addresses, r.cname, failed, &wildcard_addrs)
            }
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

    /// Regression: classify used to keep its own provider table, which drifted
    /// from `seer takeover`'s (no Tumblr, Webflow, S3 website endpoints, ...,
    /// and `.cloudapp.net` mislabeled "Azure Cloud Service"). Every CNAME shape
    /// the takeover table knows must flag here, under the same provider name.
    #[test]
    fn classify_flags_every_takeover_provider() {
        let dangling = |cname: &str| {
            classify_one(
                "gone.example.com".to_string(),
                vec![],
                Some(cname.to_string()),
                false,
                &[],
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
        let c = classify_one(
            "gone.example.com".to_string(),
            vec![], // does not resolve
            Some("gone.herokuapp.com".to_string()),
            false,
            &[],
        );
        assert_eq!(c.status, SubdomainStatus::Dead);
        assert_eq!(c.takeover_risk.as_deref(), Some("Heroku"));
    }

    #[test]
    fn classify_failed_lookup_is_unknown_not_dangling() {
        // A timed-out lookup with a provider CNAME used to read as Dead + a
        // takeover risk; an unanswered query proves nothing.
        let c = classify_one(
            "slow.example.com".to_string(),
            vec![],
            Some("slow.herokuapp.com".to_string()),
            true,
            &[],
        );
        assert_eq!(c.status, SubdomainStatus::Unknown);
        assert!(c.takeover_risk.is_none());
        // If the other family answered, the host is simply live.
        let c = classify_one(
            "v6.example.com".to_string(),
            vec!["2001:db8::1".to_string()],
            None,
            true,
            &[],
        );
        assert_eq!(c.status, SubdomainStatus::Live);
    }

    #[test]
    fn classify_live_host_is_not_takeover_even_with_provider_cname() {
        // Resolves to an address → not dangling, so no takeover flag.
        let c = classify_one(
            "live.example.com".to_string(),
            vec!["203.0.113.5".to_string()],
            Some("live.herokuapp.com".to_string()),
            false,
            &[],
        );
        assert_eq!(c.status, SubdomainStatus::Live);
        assert!(c.takeover_risk.is_none());
    }

    #[test]
    fn classify_wildcard_addresses_are_marked_wildcard() {
        let wildcard = vec!["198.51.100.9".to_string()];
        let c = classify_one(
            "anything.example.com".to_string(),
            vec!["198.51.100.9".to_string()],
            None,
            false,
            &wildcard,
        );
        assert_eq!(c.status, SubdomainStatus::Wildcard);
    }

    #[test]
    fn classify_distinct_address_under_wildcard_is_live() {
        let wildcard = vec!["198.51.100.9".to_string()];
        let c = classify_one(
            "real.example.com".to_string(),
            vec!["203.0.113.7".to_string()],
            None,
            false,
            &wildcard,
        );
        assert_eq!(c.status, SubdomainStatus::Live);
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
