//! Optional resolve-and-classify pass over enumerated subdomains.
//!
//! CT-log enumeration returns a flat name list with no signal about which
//! hosts are alive or hijackable. This stage resolves each name, marks it
//! live / dead / wildcard, and flags dangling CNAMEs that point at
//! takeover-prone providers — turning a name dump into an attack-surface
//! report. It reuses the existing [`DnsResolver`] and anti-SSRF path; only the
//! resolution is async, while the takeover fingerprinting is pure and tested.

use serde::{Deserialize, Serialize};

use crate::dns::{DnsResolver, RecordData, RecordType};

/// Label prepended to the domain to probe for wildcard DNS. If this
/// almost-certainly-nonexistent name resolves, the zone has a wildcard record
/// and per-name "live" verdicts based on an A record alone are unreliable.
const WILDCARD_PROBE_LABEL: &str = "zzzz-seer-wildcard-probe-does-not-exist";

/// Curated CNAME-suffix → provider table for subdomain-takeover detection.
/// A dangling CNAME to one of these (whose target no longer resolves) is a
/// resource an attacker can often re-claim.
const TAKEOVER_FINGERPRINTS: &[(&str, &str)] = &[
    (".github.io", "GitHub Pages"),
    (".herokuapp.com", "Heroku"),
    (".herokudns.com", "Heroku"),
    (".s3.amazonaws.com", "AWS S3"),
    (".cloudfront.net", "AWS CloudFront"),
    (".azurewebsites.net", "Azure App Service"),
    (".cloudapp.net", "Azure Cloud Service"),
    (".trafficmanager.net", "Azure Traffic Manager"),
    (".blob.core.windows.net", "Azure Blob Storage"),
    (".ghost.io", "Ghost"),
    (".surge.sh", "Surge.sh"),
    (".bitbucket.io", "Bitbucket"),
    (".pantheonsite.io", "Pantheon"),
    (".readthedocs.io", "Read the Docs"),
    (".wpengine.com", "WP Engine"),
    (".zendesk.com", "Zendesk"),
    (".fastly.net", "Fastly"),
    (".netlify.app", "Netlify"),
    (".netlify.com", "Netlify"),
    (".myshopify.com", "Shopify"),
    (".statuspage.io", "Statuspage"),
    (".unbouncepages.com", "Unbounce"),
    (".helpscoutdocs.com", "Help Scout"),
    (".launchrock.com", "LaunchRock"),
];

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
}

/// Returns the takeover-prone provider for a CNAME target, or `None`.
///
/// The apex of a provider domain (e.g. `github.io` itself) does not match —
/// only a name *under* it — because the fingerprints carry a leading dot.
fn takeover_provider(cname: &str) -> Option<&'static str> {
    let c = cname.trim_end_matches('.').to_ascii_lowercase();
    TAKEOVER_FINGERPRINTS
        .iter()
        .find(|(suffix, _)| c.ends_with(suffix))
        .map(|(_, provider)| *provider)
}

fn extract_addresses(records: &[crate::dns::DnsRecord]) -> Vec<String> {
    records
        .iter()
        .filter_map(|r| match &r.data {
            RecordData::A { address } => Some(address.clone()),
            RecordData::AAAA { address } => Some(address.clone()),
            _ => None,
        })
        .collect()
}

fn extract_cname(records: &[crate::dns::DnsRecord]) -> Option<String> {
    records.iter().find_map(|r| match &r.data {
        RecordData::CNAME { target } => Some(target.clone()),
        _ => None,
    })
}

/// Classifies a single name given the wildcard address set (pure given inputs).
fn classify_one(
    name: String,
    addresses: Vec<String>,
    cname: Option<String>,
    wildcard_addrs: &[String],
) -> ClassifiedSubdomain {
    let status = if addresses.is_empty() {
        SubdomainStatus::Dead
    } else if !wildcard_addrs.is_empty() && addresses.iter().all(|a| wildcard_addrs.contains(a)) {
        SubdomainStatus::Wildcard
    } else {
        SubdomainStatus::Live
    };

    // A dangling CNAME: points at a takeover-prone provider yet does not
    // resolve to any address.
    let takeover_risk = match (&cname, status) {
        (Some(target), SubdomainStatus::Dead) => takeover_provider(target).map(str::to_string),
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

/// Resolves A/AAAA and CNAME for `name`.
async fn resolve_name(resolver: &DnsResolver, name: &str) -> (Vec<String>, Option<String>) {
    let (a, cname) = tokio::join!(
        Box::pin(resolver.resolve(name, RecordType::A, None)),
        Box::pin(resolver.resolve(name, RecordType::CNAME, None)),
    );
    let addresses = a.map(|r| extract_addresses(&r)).unwrap_or_default();
    let cname = cname.ok().and_then(|r| extract_cname(&r));
    (addresses, cname)
}

/// Resolves and classifies each name in `names` for `domain`, detecting
/// wildcard DNS to suppress false-positive "live" verdicts and flagging
/// dangling CNAMEs to takeover-prone providers. Runs up to `concurrency`
/// resolutions at a time.
pub async fn classify_subdomains(
    resolver: &DnsResolver,
    domain: &str,
    names: Vec<String>,
    concurrency: usize,
) -> SubdomainClassification {
    use futures::stream::{self, StreamExt};

    // Probe for wildcard DNS once.
    let probe = format!("{WILDCARD_PROBE_LABEL}.{domain}");
    let (wildcard_addrs, _) = resolve_name(resolver, &probe).await;
    let wildcard_detected = !wildcard_addrs.is_empty();

    let concurrency = concurrency.max(1);
    let wildcard_addrs = std::sync::Arc::new(wildcard_addrs);

    let mut subdomains: Vec<ClassifiedSubdomain> = stream::iter(names)
        .map(|name| {
            let wildcard_addrs = wildcard_addrs.clone();
            async move {
                let (addresses, cname) = resolve_name(resolver, &name).await;
                classify_one(name, addresses, cname, &wildcard_addrs)
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn takeover_provider_matches_known_suffixes() {
        assert_eq!(takeover_provider("myapp.herokuapp.com"), Some("Heroku"));
        assert_eq!(takeover_provider("foo.github.io"), Some("GitHub Pages"));
        assert_eq!(
            takeover_provider("bucket.s3.amazonaws.com."),
            Some("AWS S3")
        );
        // Unrelated CNAME target → no match.
        assert_eq!(takeover_provider("cdn.example.com"), None);
        // The provider apex itself is not a takeover (needs a label under it).
        assert_eq!(takeover_provider("github.io"), None);
    }

    #[test]
    fn classify_dead_cname_to_provider_is_takeover_risk() {
        let c = classify_one(
            "gone.example.com".to_string(),
            vec![], // does not resolve
            Some("gone.herokuapp.com".to_string()),
            &[],
        );
        assert_eq!(c.status, SubdomainStatus::Dead);
        assert_eq!(c.takeover_risk.as_deref(), Some("Heroku"));
    }

    #[test]
    fn classify_live_host_is_not_takeover_even_with_provider_cname() {
        // Resolves to an address → not dangling, so no takeover flag.
        let c = classify_one(
            "live.example.com".to_string(),
            vec!["203.0.113.5".to_string()],
            Some("live.herokuapp.com".to_string()),
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
            &wildcard,
        );
        assert_eq!(c.status, SubdomainStatus::Live);
    }
}
