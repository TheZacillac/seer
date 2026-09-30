//! Subdomain-takeover detection with HTTP fingerprint confirmation.
//!
//! A subdomain takeover happens when a DNS record still points at a
//! third-party service that has since been deprovisioned: the CNAME survives,
//! the resource behind it does not, and whoever claims that resource next
//! controls content on the victim's domain.
//!
//! [`crate::subdomains::classify_subdomains`] already surfaces the *DNS half*
//! of this signal — a dangling CNAME to a known provider whose name no longer
//! resolves. That check alone has a large blind spot, and it is the common
//! case: most providers answer for every name pointed at their shared
//! infrastructure, so a deprovisioned resource still resolves and still
//! returns HTTP 200/404 from the provider's edge. To DNS it looks perfectly
//! healthy; only the response *body* says "there is no site here".
//!
//! This module closes that gap by adding the HTTP half:
//!
//! 1. Resolve each candidate host's addresses and walk its CNAME chain (up
//!    to 8 hops, `MAX_CNAME_HOPS`).
//! 2. Match every hop against the provider table below — a vanity CNAME
//!    often points at the provider through an intermediate name. Hosts with
//!    no provider anywhere in the chain are [`TakeoverVerdict::Safe`] and are
//!    never fetched — the HTTP fan-out is bounded to plausible candidates.
//! 3. For a candidate that resolves, issue one SSRF-guarded GET (every
//!    redirect hop re-validated) and match the body against that provider's
//!    claim-page fingerprints. A match served with the status the provider's
//!    claim page uses (where known) is [`TakeoverVerdict::Vulnerable`],
//!    carrying the matched marker as evidence. The GET goes over HTTPS
//!    first; if that fails (an unclaimed custom domain is served under the
//!    *provider's* certificate, and S3 website endpoints speak plain HTTP
//!    only), it is made once more over `http://`. Evidence only counts when
//!    the answering URL is still on the probed host — a body reached through
//!    a cross-host redirect describes some other resource.
//! 4. A candidate that does not resolve at all is [`TakeoverVerdict::Potential`]:
//!    the classic dangling CNAME, unconfirmable over HTTP because nothing
//!    answers.
//! 5. A candidate that could not be checked — its address lookup failed, or
//!    it resolves but neither probe got a response — is
//!    [`TakeoverVerdict::Inconclusive`]: no signal either way, never a
//!    finding.
//!
//! The two verdicts are deliberately distinct. `Vulnerable` means seer read a
//! provider's own "unclaimed resource" page and is asserting a finding;
//! `Potential` means the DNS shape is suspicious but nothing confirmed it. A
//! pen-test report that conflates the two wastes the reader's time, so this
//! module never promotes a `Potential` to `Vulnerable` without body evidence.
//!
//! Non-intrusive by construction: one unauthenticated GET per candidate, no
//! crafted payloads, no attempt to actually claim anything. Fingerprint
//! matching is pure and unit-tested; only resolution and fetching are async.

use std::time::Duration;

use futures::stream::{self, StreamExt};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::dns::{DnsResolver, RecordData, RecordType};
use crate::error::Result;
use crate::http::GuardedFetcher;
use crate::validation::{normalize_domain, normalize_host};

/// Upper bound on hosts examined in one scan. Mirrors the cap in
/// [`crate::subdomains::classify_subdomains`]: CT logs can return tens of
/// thousands of names, and while `concurrency` bounds parallelism it does not
/// bound total work. Names beyond the cap are reported as skipped, never
/// silently dropped. The public docs of [`scan_takeover`] and
/// [`TakeoverReport::hosts_skipped`] state the value; keep them in step.
const MAX_TAKEOVER_HOSTS: usize = 2000;

/// Default per-hop HTTP timeout for a fingerprint probe, for callers with no
/// configured value of their own (the Python bindings). The CLI passes
/// `config.http_timeout()`.
pub const DEFAULT_TAKEOVER_TIMEOUT: Duration = Duration::from_secs(10);

/// CNAME hops followed from a host looking for a provider name. Real chains
/// are two or three hops; the cap bounds a looping or hostile one.
pub(crate) const MAX_CNAME_HOPS: usize = 8;

/// Body retained per probe. Every provider's unclaimed-resource page puts its
/// marker in the first few KB, and probes run `concurrency`-wide, so a tighter
/// cap than the shared default keeps peak memory proportional to the fan-out
/// rather than to what the slowest provider chooses to send.
const PROBE_BODY_LIMIT: usize = 32 * 1024;

/// A takeover-prone provider, its CNAME shapes, and the body markers its
/// "unclaimed resource" page returns.
pub(crate) struct ProviderFingerprint {
    pub(crate) provider: &'static str,
    /// CNAME suffixes, each with a leading dot so the provider's own apex
    /// (e.g. `github.io`) does not match — only a name *under* it. Matched
    /// with `ends_with`, which is deliberately strict: a `contains` match
    /// would also fire on an attacker-chosen target like
    /// `x.github.io.attacker.example`.
    pub(crate) cname_suffixes: &'static [&'static str],
    /// Interior fragments matched with `contains`, for providers whose
    /// endpoint embeds a variable component the suffix cannot cover — S3
    /// website endpoints carry the region in the middle
    /// (`bucket.s3-website-us-east-1.amazonaws.com`). Kept separate from
    /// `cname_suffixes` so the loose match is opt-in per provider rather than
    /// the default for all of them.
    pub(crate) cname_infixes: &'static [&'static str],
    /// Literal markers that appear in the provider's unclaimed-resource page.
    /// Matched case-insensitively. Empty means the provider has no body
    /// fingerprint stable enough to assert on, so only the DNS signal applies.
    body_markers: &'static [&'static str],
    /// HTTP statuses the unclaimed-resource page is served with, where known.
    /// A marker in a response with any other status (a live page quoting the
    /// text) is not evidence. Empty means not known: any status is accepted.
    claim_statuses: &'static [u16],
}

/// Curated provider fingerprints — the single source of truth for both this
/// module and the DNS-only takeover flag in
/// [`crate::subdomains::classify_subdomains`], so the two can never disagree
/// about a CNAME.
///
/// Every marker here is a string the provider itself serves for an unclaimed
/// or deprovisioned resource. Markers are chosen to be specific: a generic
/// `404 Not Found` would fire on any misconfigured host and turn this feature
/// into a false-positive generator, so providers whose error page is generic
/// carry no marker and rely on the DNS signal alone.
pub(crate) const PROVIDERS: &[ProviderFingerprint] = &[
    ProviderFingerprint {
        provider: "GitHub Pages",
        cname_suffixes: &[".github.io"],
        cname_infixes: &[],
        body_markers: &[
            "There isn't a GitHub Pages site here.",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
        claim_statuses: &[404],
    },
    ProviderFingerprint {
        provider: "Heroku",
        cname_suffixes: &[".herokuapp.com", ".herokudns.com", ".herokussl.com"],
        cname_infixes: &[],
        body_markers: &["No such app", "herokucdn.com/error-pages/no-such-app.html"],
        claim_statuses: &[404],
    },
    ProviderFingerprint {
        provider: "AWS S3",
        cname_suffixes: &[".s3.amazonaws.com"],
        cname_infixes: &[".s3-website"],
        body_markers: &["NoSuchBucket", "The specified bucket does not exist"],
        claim_statuses: &[404],
    },
    ProviderFingerprint {
        provider: "AWS CloudFront",
        cname_suffixes: &[".cloudfront.net"],
        // CloudFront's error page is generic ("Bad request"); DNS signal only.
        cname_infixes: &[],
        body_markers: &[],
        claim_statuses: &[],
    },
    ProviderFingerprint {
        provider: "Azure App Service",
        cname_suffixes: &[
            ".azurewebsites.net",
            ".cloudapp.net",
            ".cloudapp.azure.com",
            ".azureedge.net",
        ],
        cname_infixes: &[],
        body_markers: &["404 Web Site not found", "Error 404 - Web app not found"],
        claim_statuses: &[404],
    },
    ProviderFingerprint {
        provider: "Azure Traffic Manager",
        cname_suffixes: &[".trafficmanager.net"],
        cname_infixes: &[],
        body_markers: &[],
        claim_statuses: &[],
    },
    ProviderFingerprint {
        provider: "Azure Blob Storage",
        cname_suffixes: &[".blob.core.windows.net"],
        cname_infixes: &[],
        body_markers: &["The specified container does not exist"],
        claim_statuses: &[404],
    },
    ProviderFingerprint {
        provider: "Shopify",
        cname_suffixes: &[".myshopify.com"],
        cname_infixes: &[],
        body_markers: &[
            "Sorry, this shop is currently unavailable",
            "Only one step left!",
        ],
        claim_statuses: &[],
    },
    ProviderFingerprint {
        provider: "Fastly",
        cname_suffixes: &[".fastly.net"],
        cname_infixes: &[],
        body_markers: &["Fastly error: unknown domain"],
        claim_statuses: &[500],
    },
    ProviderFingerprint {
        provider: "Ghost",
        cname_suffixes: &[".ghost.io"],
        cname_infixes: &[],
        body_markers: &["The thing you were looking for is no longer here"],
        claim_statuses: &[],
    },
    ProviderFingerprint {
        provider: "Surge.sh",
        cname_suffixes: &[".surge.sh"],
        cname_infixes: &[],
        body_markers: &["project not found"],
        claim_statuses: &[404],
    },
    ProviderFingerprint {
        provider: "Bitbucket",
        cname_suffixes: &[".bitbucket.io"],
        cname_infixes: &[],
        body_markers: &["Repository not found"],
        claim_statuses: &[404],
    },
    ProviderFingerprint {
        provider: "Pantheon",
        cname_suffixes: &[".pantheonsite.io"],
        cname_infixes: &[],
        body_markers: &["The gods are wise, but do not know of the site which you seek"],
        claim_statuses: &[404],
    },
    ProviderFingerprint {
        provider: "Read the Docs",
        cname_suffixes: &[".readthedocs.io"],
        cname_infixes: &[],
        body_markers: &["unknown to Read the Docs"],
        claim_statuses: &[404],
    },
    ProviderFingerprint {
        provider: "WP Engine",
        cname_suffixes: &[".wpengine.com"],
        cname_infixes: &[],
        body_markers: &["The site you were looking for couldn't be found"],
        claim_statuses: &[],
    },
    ProviderFingerprint {
        provider: "Zendesk",
        cname_suffixes: &[".zendesk.com"],
        cname_infixes: &[],
        body_markers: &["Help Center Closed"],
        claim_statuses: &[],
    },
    ProviderFingerprint {
        provider: "Netlify",
        cname_suffixes: &[".netlify.app", ".netlify.com"],
        cname_infixes: &[],
        body_markers: &["Not Found - Request ID"],
        claim_statuses: &[404],
    },
    ProviderFingerprint {
        provider: "Statuspage",
        cname_suffixes: &[".statuspage.io"],
        cname_infixes: &[],
        body_markers: &[],
        claim_statuses: &[],
    },
    ProviderFingerprint {
        provider: "Unbounce",
        cname_suffixes: &[".unbouncepages.com"],
        cname_infixes: &[],
        body_markers: &["The requested URL was not found on this server"],
        claim_statuses: &[404],
    },
    ProviderFingerprint {
        provider: "Help Scout",
        cname_suffixes: &[".helpscoutdocs.com"],
        cname_infixes: &[],
        body_markers: &["No settings were found for this company"],
        claim_statuses: &[],
    },
    ProviderFingerprint {
        provider: "LaunchRock",
        cname_suffixes: &[".launchrock.com"],
        cname_infixes: &[],
        body_markers: &["It looks like you may have taken a wrong turn somewhere"],
        claim_statuses: &[],
    },
    ProviderFingerprint {
        provider: "Tumblr",
        cname_suffixes: &[".domains.tumblr.com"],
        cname_infixes: &[],
        body_markers: &["Whatever you were looking for doesn't currently exist at this address"],
        claim_statuses: &[404],
    },
    ProviderFingerprint {
        provider: "Webflow",
        cname_suffixes: &[".proxy-ssl.webflow.com", ".proxy.webflow.com"],
        cname_infixes: &[],
        body_markers: &["The page you are looking for doesn't exist or has been moved"],
        claim_statuses: &[404],
    },
    ProviderFingerprint {
        provider: "Intercom",
        cname_suffixes: &[".custom.intercom.help"],
        cname_infixes: &[],
        body_markers: &["This page is reserved for artistic dogs"],
        claim_statuses: &[],
    },
    ProviderFingerprint {
        provider: "UserVoice",
        cname_suffixes: &[".uservoice.com"],
        cname_infixes: &[],
        body_markers: &["This UserVoice subdomain is currently available"],
        claim_statuses: &[],
    },
    ProviderFingerprint {
        provider: "Wufoo",
        cname_suffixes: &[".wufoo.com"],
        cname_infixes: &[],
        body_markers: &["Profile not found"],
        claim_statuses: &[],
    },
    ProviderFingerprint {
        provider: "FeedPress",
        cname_suffixes: &[".redirect.feedpress.me"],
        cname_infixes: &[],
        body_markers: &["The feed has not been found"],
        claim_statuses: &[],
    },
];

/// Confidence in a takeover finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TakeoverVerdict {
    /// The provider's own unclaimed-resource page was served — confirmed by
    /// matching the response body against a provider fingerprint.
    Vulnerable,
    /// A dangling CNAME to a takeover-prone provider that does not resolve.
    /// Suspicious, but nothing answered to confirm it.
    Potential,
    /// A CNAME to a takeover-prone provider that could not be checked: its
    /// address lookup failed, or it resolves but the HTTP probe got no
    /// response. No signal either way — reported, but not a finding.
    Inconclusive,
    /// No takeover signal.
    Safe,
}

/// One host's takeover assessment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeoverFinding {
    pub host: String,
    pub verdict: TakeoverVerdict,
    /// The third-party service the CNAME points at, when recognized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cname: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub addresses: Vec<String>,
    /// The provider fingerprint that matched the response body. Present only
    /// on `Vulnerable` findings — this is the evidence for the claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    /// HTTP status returned by the probe, when one was made.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    /// Why no HTTP confirmation was attempted or why it failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub probe_note: Option<String>,
}

/// The result of a takeover scan over a set of hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TakeoverReport {
    pub domain: String,
    /// How many hosts were examined (after the cap).
    pub hosts_checked: usize,
    /// Hosts dropped because the input exceeded the 2000-host cap.
    #[serde(default)]
    pub hosts_skipped: usize,
    pub vulnerable: usize,
    pub potential: usize,
    /// Provider-CNAME hosts that could not be checked (see
    /// [`TakeoverVerdict::Inconclusive`]).
    #[serde(default)]
    pub inconclusive: usize,
    /// Hosts worth reporting (vulnerable, then potential, then inconclusive).
    /// Hosts with no takeover signal are counted but not listed — a clean
    /// host is noise in a findings report.
    pub findings: Vec<TakeoverFinding>,
    pub notes: Vec<String>,
}

impl TakeoverReport {
    /// True when the scan found anything actionable (a vulnerable or
    /// potential host; an inconclusive one is not a finding). Drives the
    /// CLI's check-style exit code.
    pub fn has_findings(&self) -> bool {
        self.vulnerable > 0 || self.potential > 0
    }
}

// --- Pure fingerprinting ------------------------------------------------

/// Returns the provider whose CNAME suffix matches `cname`, or `None`.
pub(crate) fn match_provider(cname: &str) -> Option<&'static ProviderFingerprint> {
    let c = cname.trim_end_matches('.').to_ascii_lowercase();
    PROVIDERS.iter().find(|p| {
        p.cname_suffixes.iter().any(|suffix| c.ends_with(suffix))
            || p.cname_infixes.iter().any(|infix| c.contains(infix))
    })
}

/// Returns the provider fingerprint marker found in `body`, or `None`.
///
/// Matching is case-insensitive because providers vary the casing of their
/// error copy across edges and over time.
fn match_body_marker(provider: &ProviderFingerprint, body: &str) -> Option<&'static str> {
    let haystack = body.to_ascii_lowercase();
    provider
        .body_markers
        .iter()
        .find(|marker| haystack.contains(&marker.to_ascii_lowercase()))
        .copied()
}

/// Whether `status` is one the provider's claim page is served with (any
/// status when that is not known).
fn claim_status_matches(provider: &ProviderFingerprint, status: u16) -> bool {
    provider.claim_statuses.is_empty() || provider.claim_statuses.contains(&status)
}

/// Truncates `hosts` to `cap` in place, returning how many were dropped. Pure
/// so a scan cap is unit-testable without a resolver; shared with the
/// subdomain classifier's cap.
pub(crate) fn truncate_to_cap(hosts: &mut Vec<String>, cap: usize) -> usize {
    let skipped = hosts.len().saturating_sub(cap);
    hosts.truncate(cap);
    skipped
}

/// Builds the advisory notes for a completed scan.
fn build_notes(
    vulnerable: usize,
    potential: usize,
    inconclusive: usize,
    hosts_skipped: usize,
) -> Vec<String> {
    let mut notes = Vec::new();

    if vulnerable > 0 {
        notes.push(format!(
            "{vulnerable} host(s) served a provider's unclaimed-resource page — an attacker \
             can likely claim these and host content on your domain. Remove the DNS record or \
             re-claim the resource."
        ));
    }
    if potential > 0 {
        notes.push(format!(
            "{potential} host(s) have a CNAME to a takeover-prone provider that does not \
             resolve, so nothing answered to confirm it either way. Verify each manually \
             before acting."
        ));
    }
    if inconclusive > 0 {
        notes.push(format!(
            "{inconclusive} host(s) with a takeover-prone provider CNAME could not be checked \
             (a DNS lookup or the HTTP probe failed — see each host's note); re-run to confirm."
        ));
    }
    if vulnerable == 0 && potential == 0 && inconclusive == 0 {
        notes.push("No takeover signals found.".to_string());
    }
    if hosts_skipped > 0 {
        notes.push(format!(
            "{hosts_skipped} host(s) exceeded the {MAX_TAKEOVER_HOSTS}-host scan cap and were \
             not examined."
        ));
    }

    notes
}

// --- Async scanning -----------------------------------------------------

/// DNS facts about one host.
pub(crate) struct HostResolution {
    /// A and AAAA addresses (IPv6-only hosts are alive too).
    pub(crate) addresses: Vec<String>,
    /// The host's own CNAME target (the first hop), when it has one.
    pub(crate) cname: Option<String>,
    /// The first hop of the CNAME chain that names a takeover-prone
    /// provider, with that provider.
    pub(crate) provider: Option<(&'static ProviderFingerprint, String)>,
    /// Set when no address was found *and* an address lookup failed outright
    /// (timeout, SERVFAIL) rather than answering NXDOMAIN/NODATA — "we could
    /// not tell", which must never be reported as "does not resolve".
    pub(crate) lookup_error: Option<String>,
}

/// The CNAME target of `name`, or `None` when it has none (or the lookup
/// failed — a chain walk simply stops there).
async fn cname_of(resolver: &DnsResolver, name: &str) -> Option<String> {
    let records = resolver.resolve(name, RecordType::CNAME, None).await.ok()?;
    records.into_iter().find_map(|r| match r.data {
        RecordData::CNAME { target } => Some(target),
        _ => None,
    })
}

/// Resolves the addresses of `host` and walks its CNAME chain for a provider.
pub(crate) async fn resolve_host(resolver: &DnsResolver, host: &str) -> HostResolution {
    let (a, aaaa, cname) = tokio::join!(
        Box::pin(resolver.resolve(host, RecordType::A, None)),
        Box::pin(resolver.resolve(host, RecordType::AAAA, None)),
        Box::pin(cname_of(resolver, host)),
    );

    let mut addresses = Vec::new();
    let mut lookup_error = None;
    for result in [a, aaaa] {
        match result {
            Ok(records) => addresses.extend(
                records
                    .iter()
                    .filter_map(|r| r.data.address().map(str::to_string)),
            ),
            // `resolve` maps NXDOMAIN/NODATA to an empty Ok, so an Err here is
            // a genuine failure to get an answer.
            Err(e) => lookup_error = Some(e.sanitized_message()),
        }
    }
    if !addresses.is_empty() {
        lookup_error = None;
    }

    // A resolver answers a CNAME query with one hop and does not chase it, so
    // the chain is walked here, one query per hop, until a hop names a
    // provider, the chain ends, it loops, or the hop cap is reached.
    let mut provider = None;
    let mut seen = std::collections::HashSet::new();
    let mut hop = cname.clone();
    for _ in 0..MAX_CNAME_HOPS {
        let Some(target) = hop.take() else { break };
        if let Some(p) = match_provider(&target) {
            provider = Some((p, target));
            break;
        }
        if !seen.insert(target.clone()) {
            break;
        }
        hop = cname_of(resolver, &target).await;
    }

    HostResolution {
        addresses,
        cname,
        provider,
        lookup_error,
    }
}

/// Turns a completed probe into a finding.
///
/// This is the step that decides `Vulnerable` vs `Safe`, so it is split out as
/// a pure function: the rule that a confirmed takeover requires a matched body
/// marker (never a mere status code, and never a provider match on its own),
/// served with the claim page's own status where that is known, is the
/// load-bearing claim of this module and is unit-tested directly.
fn finding_from_probe(
    host: String,
    provider: &ProviderFingerprint,
    cname: Option<String>,
    addresses: Vec<String>,
    response: &crate::http::FetchedResponse,
) -> TakeoverFinding {
    // The body only speaks for this host if this host served it. After a
    // cross-host redirect (a live app bouncing visitors to some *other*,
    // unclaimed resource on the same provider) a claim-page marker describes
    // that other resource, so it is not evidence here.
    let head = &response.head;
    let final_host = reqwest::Url::parse(&head.final_url)
        .ok()
        .as_ref()
        .and_then(crate::net::url_host)
        .map(|h| h.trim_end_matches('.').to_ascii_lowercase());
    let same_host = final_host.as_deref() == Some(host.trim_end_matches('.'));
    if !same_host {
        return TakeoverFinding {
            host,
            verdict: TakeoverVerdict::Safe,
            provider: Some(provider.provider.to_string()),
            cname,
            addresses,
            evidence: None,
            http_status: Some(head.status),
            probe_note: Some(format!(
                "redirected to {}; that response is not attributed to this host",
                final_host.as_deref().unwrap_or("another host")
            )),
        };
    }

    let marker = match_body_marker(provider, &response.body);
    // The claim-page text under another status is a page quoting it (a live
    // site, a help article), not the provider's unclaimed-resource response.
    let evidence = marker.filter(|_| claim_status_matches(provider, head.status));
    let verdict = if evidence.is_some() {
        TakeoverVerdict::Vulnerable
    } else {
        TakeoverVerdict::Safe
    };
    let probe_note = if marker.is_some() && evidence.is_none() {
        Some(format!(
            "claim-page text was served with HTTP {}, not the status {}'s unclaimed-resource \
             page uses; not treated as evidence",
            head.status, provider.provider
        ))
    } else if evidence.is_none() && provider.body_markers.is_empty() {
        // A provider we have no fingerprint for can never be confirmed here,
        // so say so rather than letting `Safe` imply it was checked.
        Some("provider has no reliable body fingerprint; verify this host manually".to_string())
    } else {
        None
    };

    TakeoverFinding {
        host,
        verdict,
        provider: Some(provider.provider.to_string()),
        cname,
        addresses,
        evidence: evidence.map(str::to_string),
        http_status: Some(head.status),
        probe_note,
    }
}

/// Assesses a single host: resolve, match the provider, and confirm over HTTP
/// when the host answers.
async fn check_host(
    resolver: &DnsResolver,
    fetcher: &GuardedFetcher,
    host: String,
) -> TakeoverFinding {
    let HostResolution {
        addresses,
        cname,
        provider,
        lookup_error,
    } = resolve_host(resolver, &host).await;

    // No CNAME, or a chain that names no provider we recognize: nothing to
    // claim. These hosts are never fetched, which is what keeps the HTTP
    // fan-out proportional to the number of plausible candidates rather than
    // to the size of the zone.
    let Some((provider, provider_cname)) = provider else {
        return TakeoverFinding {
            host,
            verdict: TakeoverVerdict::Safe,
            provider: None,
            cname,
            addresses,
            evidence: None,
            http_status: None,
            probe_note: None,
        };
    };

    // The finding names the hop that points at the provider.
    let cname = Some(provider_cname);

    // A provider CNAME that resolves to nothing is the classic dangling
    // record. Nothing answers, so HTTP cannot confirm it either way. A lookup
    // that *failed* is not evidence that the name is dangling: we could not
    // tell, so it is inconclusive.
    if addresses.is_empty() {
        let (verdict, probe_note) = match lookup_error {
            Some(e) => (
                TakeoverVerdict::Inconclusive,
                format!(
                    "CNAME points at a takeover-prone provider, but its address lookup failed \
                     ({e}); re-run to confirm"
                ),
            ),
            None => (
                TakeoverVerdict::Potential,
                "CNAME points at a takeover-prone provider but does not resolve".to_string(),
            ),
        };
        return TakeoverFinding {
            host,
            verdict,
            provider: Some(provider.provider.to_string()),
            cname,
            addresses,
            evidence: None,
            http_status: None,
            probe_note: Some(probe_note),
        };
    }

    // The host resolves — ask the provider's edge what it serves. HTTPS
    // first; an unclaimed custom domain is typically served under the
    // provider's own certificate (so validating TLS fails) and S3 website
    // endpoints have no HTTPS at all, so fall back to plain HTTP, where the
    // claim page is readable. Body markers do not depend on TLS trust.
    let https_err = match fetcher.get(&format!("https://{host}/")).await {
        Ok(response) => return finding_from_probe(host, provider, cname, addresses, &response),
        Err(e) => e,
    };
    match fetcher.get(&format!("http://{host}/")).await {
        Ok(response) => finding_from_probe(host, provider, cname, addresses, &response),
        Err(http_err) => {
            debug!(host = %host, https = %https_err, http = %http_err, "takeover probe failed");
            // A failed probe is not evidence of anything, and the host
            // resolves, so it is not dangling either: report it as unchecked
            // and say why — never upgrade a fetch failure into a finding.
            TakeoverFinding {
                host,
                verdict: TakeoverVerdict::Inconclusive,
                provider: Some(provider.provider.to_string()),
                cname,
                addresses,
                evidence: None,
                http_status: None,
                probe_note: Some(format!(
                    "HTTP probe failed over HTTPS ({}) and HTTP ({})",
                    https_err.sanitized_message(),
                    http_err.sanitized_message()
                )),
            }
        }
    }
}

/// Assembles a report from completed per-host findings. Pure, so ordering,
/// counting, and filtering are testable without any network.
fn build_report(
    domain: String,
    findings: Vec<TakeoverFinding>,
    hosts_skipped: usize,
) -> TakeoverReport {
    let hosts_checked = findings.len();
    let vulnerable = findings
        .iter()
        .filter(|f| f.verdict == TakeoverVerdict::Vulnerable)
        .count();
    let potential = findings
        .iter()
        .filter(|f| f.verdict == TakeoverVerdict::Potential)
        .count();
    let inconclusive = findings
        .iter()
        .filter(|f| f.verdict == TakeoverVerdict::Inconclusive)
        .count();

    // Report only actionable hosts, worst first, alphabetical within a band.
    let mut reported: Vec<TakeoverFinding> = findings
        .into_iter()
        .filter(|f| f.verdict != TakeoverVerdict::Safe)
        .collect();
    reported.sort_by(|a, b| {
        let rank = |v: TakeoverVerdict| match v {
            TakeoverVerdict::Vulnerable => 0,
            TakeoverVerdict::Potential => 1,
            TakeoverVerdict::Inconclusive => 2,
            TakeoverVerdict::Safe => 3,
        };
        rank(a.verdict)
            .cmp(&rank(b.verdict))
            .then_with(|| a.host.cmp(&b.host))
    });

    TakeoverReport {
        domain,
        hosts_checked,
        hosts_skipped,
        vulnerable,
        potential,
        inconclusive,
        notes: build_notes(vulnerable, potential, inconclusive, hosts_skipped),
        findings: reported,
    }
}

/// Scans `hosts` for subdomain-takeover exposure on `domain`.
///
/// Each host is resolved and, when its CNAME chain names a recognized
/// provider and the host answers, fetched once — over HTTPS, or over plain
/// HTTP when HTTPS fails — to confirm against that provider's
/// unclaimed-resource fingerprint. Hosts with no provider CNAME are never
/// fetched. At most 2000 hosts are examined.
///
/// # Arguments
/// * `resolver` - DNS resolver for the CNAME/address lookups
/// * `domain` - The apex the hosts belong to (reported, and normalized)
/// * `hosts` - Candidate hostnames (typically from CT-log enumeration)
/// * `concurrency` - Maximum simultaneous host checks
/// * `timeout` - Per-hop HTTP timeout for each probe (the CLI passes
///   `config.http_timeout()`; [`DEFAULT_TAKEOVER_TIMEOUT`] otherwise)
///
/// # Returns
/// * `Ok(TakeoverReport)` - the scan result, including a clean one
/// * `Err(SeerError::InvalidDomain)` - `domain` is not a valid domain
pub async fn scan_takeover(
    resolver: &DnsResolver,
    domain: &str,
    mut hosts: Vec<String>,
    concurrency: usize,
    timeout: Duration,
) -> Result<TakeoverReport> {
    let domain = normalize_domain(domain)?;
    // Hosts are probed exactly as named — `www` is the most commonly
    // CNAME'd host of all, so it must not collapse into the apex. Input that
    // doesn't normalize is kept verbatim and simply won't resolve.
    for host in &mut hosts {
        if let Ok(normalized) = normalize_host(host) {
            *host = normalized;
        }
    }
    let mut seen = std::collections::HashSet::new();
    hosts.retain(|h| seen.insert(h.clone()));
    let hosts_skipped = truncate_to_cap(&mut hosts, MAX_TAKEOVER_HOSTS);
    let concurrency = concurrency.max(1);

    let fetcher = GuardedFetcher::new()
        .with_timeout(timeout)
        .with_max_body(PROBE_BODY_LIMIT);

    let findings: Vec<TakeoverFinding> = stream::iter(hosts)
        .map(|host| {
            let fetcher = &fetcher;
            async move { check_host(resolver, fetcher, host).await }
        })
        .buffer_unordered(concurrency)
        .collect()
        .await;

    Ok(build_report(domain, findings, hosts_skipped))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(host: &str, verdict: TakeoverVerdict) -> TakeoverFinding {
        TakeoverFinding {
            host: host.to_string(),
            verdict,
            provider: Some("GitHub Pages".to_string()),
            cname: Some("x.github.io".to_string()),
            addresses: vec![],
            evidence: None,
            http_status: None,
            probe_note: None,
        }
    }

    #[test]
    fn provider_matching_by_cname_suffix() {
        assert_eq!(
            match_provider("myapp.herokuapp.com").map(|p| p.provider),
            Some("Heroku")
        );
        assert_eq!(
            match_provider("user.github.io.").map(|p| p.provider),
            Some("GitHub Pages")
        );
        assert_eq!(
            match_provider("BUCKET.S3.AMAZONAWS.COM").map(|p| p.provider),
            Some("AWS S3")
        );
        // Unrelated targets must not match.
        assert_eq!(match_provider("cdn.example.com").map(|p| p.provider), None);
    }

    #[test]
    fn provider_apex_alone_does_not_match() {
        // The suffixes carry a leading dot, so the provider's own apex is not
        // a takeover candidate — only a name under it.
        assert!(match_provider("github.io").is_none());
        assert!(match_provider("herokuapp.com").is_none());
    }

    #[test]
    fn body_markers_match_case_insensitively() {
        let gh = match_provider("x.github.io").expect("github provider");
        assert_eq!(
            match_body_marker(gh, "<h1>There isn't a GitHub Pages site here.</h1>"),
            Some("There isn't a GitHub Pages site here.")
        );
        // Providers vary casing across their edges.
        assert!(match_body_marker(gh, "THERE ISN'T A GITHUB PAGES SITE HERE.").is_some());
        // A real site's body must not match.
        assert_eq!(match_body_marker(gh, "<h1>Welcome to my blog</h1>"), None);
    }

    #[test]
    fn providers_without_markers_never_match_a_body() {
        let cf = match_provider("d123.cloudfront.net").expect("cloudfront provider");
        assert!(cf.body_markers.is_empty());
        // Even a body that looks like an error must not produce evidence for a
        // provider we deliberately have no fingerprint for.
        assert_eq!(match_body_marker(cf, "404 Not Found"), None);
    }

    #[test]
    fn suffix_match_is_anchored_at_the_end() {
        // A `contains` match would fire here and let an attacker-chosen CNAME
        // target impersonate a provider, then serve that provider's claim-page
        // text to manufacture a "confirmed" finding.
        assert!(match_provider("x.github.io.attacker.example").is_none());
        assert!(match_provider("app.herokuapp.com.evil.test").is_none());
    }

    #[test]
    fn s3_website_region_endpoints_match_via_infix() {
        // S3 website endpoints carry the region mid-name, so the suffix alone
        // cannot cover them — this is why the infix list exists.
        assert_eq!(
            match_provider("bucket.s3-website-us-east-1.amazonaws.com").map(|p| p.provider),
            Some("AWS S3")
        );
        assert_eq!(
            match_provider("bucket.s3-website.eu-west-2.amazonaws.com").map(|p| p.provider),
            Some("AWS S3")
        );
    }

    #[test]
    fn only_s3_opts_into_loose_infix_matching() {
        // The loose match must stay opt-in; if it spreads to other providers
        // the anchoring guarantee above quietly stops holding for them.
        for p in PROVIDERS {
            if p.provider != "AWS S3" {
                assert!(
                    p.cname_infixes.is_empty(),
                    "{} must not use infix matching without a documented reason",
                    p.provider
                );
            }
        }
    }

    #[test]
    fn every_fingerprint_suffix_is_dot_prefixed() {
        // A suffix without a leading dot would match the provider apex and any
        // domain merely ending in those characters (e.g. "evilgithub.io").
        for p in PROVIDERS {
            assert!(
                !p.cname_suffixes.is_empty(),
                "{} has no CNAME suffixes",
                p.provider
            );
            for suffix in p.cname_suffixes {
                assert!(
                    suffix.starts_with('.'),
                    "{} suffix {suffix:?} must start with a dot",
                    p.provider
                );
            }
        }
    }

    /// Synthetic probe response, so the confirmation rule is testable without
    /// DNS or HTTP.
    fn probe(host: &str, status: u16, body: &str) -> crate::http::FetchedResponse {
        crate::http::FetchedResponse {
            head: crate::http::ResponseHead {
                final_url: format!("https://{host}/"),
                status,
                headers: vec![],
                redirects: 0,
            },
            body: body.to_string(),
        }
    }

    #[test]
    fn matching_body_marker_confirms_vulnerable_with_evidence() {
        let gh = match_provider("gone.github.io").expect("github provider");
        let finding = finding_from_probe(
            "gone.example.com".to_string(),
            gh,
            Some("gone.github.io".to_string()),
            vec!["185.199.108.153".to_string()],
            &probe(
                "gone.example.com",
                404,
                "<h1>There isn't a GitHub Pages site here.</h1>",
            ),
        );
        assert_eq!(finding.verdict, TakeoverVerdict::Vulnerable);
        // The evidence is what makes the claim auditable.
        assert_eq!(
            finding.evidence.as_deref(),
            Some("There isn't a GitHub Pages site here.")
        );
        assert_eq!(finding.http_status, Some(404));
    }

    #[test]
    fn a_live_site_on_a_provider_cname_is_safe() {
        // The common false positive to avoid: a perfectly healthy site hosted
        // on a takeover-prone provider must NOT be reported.
        let gh = match_provider("user.github.io").expect("github provider");
        let finding = finding_from_probe(
            "blog.example.com".to_string(),
            gh,
            Some("user.github.io".to_string()),
            vec!["185.199.108.153".to_string()],
            &probe(
                "blog.example.com",
                200,
                "<html><body><h1>My Blog</h1></body></html>",
            ),
        );
        assert_eq!(finding.verdict, TakeoverVerdict::Safe);
        assert!(finding.evidence.is_none());
    }

    #[test]
    fn a_404_alone_never_confirms_a_takeover() {
        // Status codes are not evidence: plenty of live sites 404 their root.
        // Only a provider's own claim-page text confirms.
        let gh = match_provider("user.github.io").expect("github provider");
        let finding = finding_from_probe(
            "blog.example.com".to_string(),
            gh,
            Some("user.github.io".to_string()),
            vec!["185.199.108.153".to_string()],
            &probe("blog.example.com", 404, "<h1>Page not found</h1>"),
        );
        assert_eq!(finding.verdict, TakeoverVerdict::Safe);
    }

    #[test]
    fn marker_after_a_cross_host_redirect_is_not_evidence() {
        // A live, claimed app that redirects to a *different* unclaimed app on
        // the same provider must not make the probed host look claimable.
        let heroku = match_provider("app.herokuapp.com").expect("heroku provider");
        let mut response = probe("retired-app.herokuapp.com", 404, "No such app");
        response.head.redirects = 1;
        let finding = finding_from_probe(
            "app.example.com".to_string(),
            heroku,
            Some("app.herokuapp.com".to_string()),
            vec!["203.0.113.7".to_string()],
            &response,
        );
        assert_eq!(finding.verdict, TakeoverVerdict::Safe);
        assert!(finding.evidence.is_none());
        assert!(finding
            .probe_note
            .as_deref()
            .unwrap_or_default()
            .contains("retired-app.herokuapp.com"));

        // Same host over plain HTTP (the fallback path) still confirms.
        let mut plain = probe("app.example.com", 404, "No such app");
        plain.head.final_url = "http://App.Example.com./".to_string();
        let finding = finding_from_probe(
            "app.example.com".to_string(),
            heroku,
            Some("app.herokuapp.com".to_string()),
            vec!["203.0.113.7".to_string()],
            &plain,
        );
        assert_eq!(finding.verdict, TakeoverVerdict::Vulnerable);
    }

    #[test]
    fn fingerprintless_provider_says_it_could_not_confirm() {
        // CloudFront has no reliable body marker, so a Safe verdict there must
        // carry a note rather than implying the host was actually cleared.
        let cf = match_provider("d123.cloudfront.net").expect("cloudfront provider");
        let finding = finding_from_probe(
            "cdn.example.com".to_string(),
            cf,
            Some("d123.cloudfront.net".to_string()),
            vec!["203.0.113.9".to_string()],
            &probe("cdn.example.com", 403, "Bad request"),
        );
        assert_eq!(finding.verdict, TakeoverVerdict::Safe);
        assert!(
            finding
                .probe_note
                .as_deref()
                .unwrap_or_default()
                .contains("verify this host manually"),
            "got {:?}",
            finding.probe_note
        );
    }

    #[test]
    fn report_counts_and_orders_findings() {
        let findings = vec![
            finding("safe.example.com", TakeoverVerdict::Safe),
            finding("zeta.example.com", TakeoverVerdict::Potential),
            finding("beta.example.com", TakeoverVerdict::Vulnerable),
            finding("alpha.example.com", TakeoverVerdict::Potential),
        ];
        let report = build_report("example.com".to_string(), findings, 0);

        assert_eq!(report.hosts_checked, 4);
        assert_eq!(report.vulnerable, 1);
        assert_eq!(report.potential, 2);
        // Safe hosts are counted but not listed.
        assert_eq!(report.findings.len(), 3);
        assert_eq!(report.findings[0].host, "beta.example.com");
        // Potentials follow, alphabetically.
        assert_eq!(report.findings[1].host, "alpha.example.com");
        assert_eq!(report.findings[2].host, "zeta.example.com");
        assert!(report.has_findings());
    }

    #[test]
    fn clean_scan_reports_no_findings() {
        let findings = vec![
            finding("a.example.com", TakeoverVerdict::Safe),
            finding("b.example.com", TakeoverVerdict::Safe),
        ];
        let report = build_report("example.com".to_string(), findings, 0);
        assert_eq!(report.hosts_checked, 2);
        assert!(report.findings.is_empty());
        assert!(!report.has_findings());
        assert!(report
            .notes
            .iter()
            .any(|n| n.contains("No takeover signals")));
    }

    #[test]
    fn host_cap_truncates_and_reports_the_remainder() {
        let over = MAX_TAKEOVER_HOSTS + 15;
        let mut hosts: Vec<String> = (0..over).map(|i| format!("h{i}.example.com")).collect();
        let skipped = truncate_to_cap(&mut hosts, MAX_TAKEOVER_HOSTS);
        assert_eq!(hosts.len(), MAX_TAKEOVER_HOSTS);
        assert_eq!(skipped, 15);

        // The truncation must surface in the report's notes, never silently.
        let report = build_report("example.com".to_string(), vec![], skipped);
        assert!(report.notes.iter().any(|n| n.contains("scan cap")));
        assert_eq!(report.hosts_skipped, 15);
    }

    #[test]
    fn host_cap_is_a_noop_under_the_limit() {
        let mut hosts: Vec<String> = (0..5).map(|i| format!("h{i}.example.com")).collect();
        assert_eq!(truncate_to_cap(&mut hosts, MAX_TAKEOVER_HOSTS), 0);
        assert_eq!(hosts.len(), 5);
    }

    #[test]
    fn notes_distinguish_confirmed_from_unconfirmed() {
        let notes = build_notes(2, 3, 4, 0);
        // The confirmed finding must read as actionable...
        assert!(notes.iter().any(|n| n.contains("2 host(s) served")));
        // ...the unconfirmed one must say it needs manual verification...
        assert!(notes
            .iter()
            .any(|n| n.contains("3 host(s)") && n.contains("manually")));
        // ...and the unchecked ones must say they could not be checked.
        assert!(notes
            .iter()
            .any(|n| n.contains("4 host(s)") && n.contains("could not be checked")));
    }

    /// Regression: the claim-page text under a status the provider's claim
    /// page never uses (a live page quoting it) confirmed a takeover.
    #[test]
    fn a_marker_under_the_wrong_status_is_not_evidence() {
        let gh = match_provider("user.github.io").expect("github provider");
        let finding = finding_from_probe(
            "blog.example.com".to_string(),
            gh,
            Some("user.github.io".to_string()),
            vec!["185.199.108.153".to_string()],
            &probe(
                "blog.example.com",
                200,
                "<p>If you see \"There isn't a GitHub Pages site here.\" ...</p>",
            ),
        );
        assert_eq!(finding.verdict, TakeoverVerdict::Safe);
        assert!(finding.evidence.is_none());
        assert!(finding
            .probe_note
            .as_deref()
            .unwrap_or_default()
            .contains("HTTP 200"));

        // A provider with no known claim status accepts any status.
        let shopify = match_provider("shop.myshopify.com").expect("shopify provider");
        assert!(shopify.claim_statuses.is_empty());
        let finding = finding_from_probe(
            "shop.example.com".to_string(),
            shopify,
            Some("shop.myshopify.com".to_string()),
            vec!["203.0.113.7".to_string()],
            &probe(
                "shop.example.com",
                200,
                "Sorry, this shop is currently unavailable",
            ),
        );
        assert_eq!(finding.verdict, TakeoverVerdict::Vulnerable);
    }

    #[test]
    fn claim_statuses_are_error_statuses() {
        // A claim page is an error page; a 2xx/3xx entry would let a live
        // page's quoted text count as evidence again.
        for p in PROVIDERS {
            for status in p.claim_statuses {
                assert!(*status >= 400, "{}: {status}", p.provider);
            }
        }
    }

    #[test]
    fn inconclusive_hosts_are_listed_but_not_findings() {
        let findings = vec![
            finding("a.example.com", TakeoverVerdict::Inconclusive),
            finding("b.example.com", TakeoverVerdict::Safe),
        ];
        let report = build_report("example.com".to_string(), findings, 0);
        assert_eq!(report.inconclusive, 1);
        assert_eq!(report.potential, 0);
        assert_eq!(report.findings.len(), 1);
        assert!(!report.has_findings());
    }

    /// A scripted zone: `name`'s CNAME target, or no record.
    async fn chain_resolver(chain: &'static [(&'static str, &'static str)]) -> DnsResolver {
        use crate::dns::test_support::{
            cname_rdata, mock_dns_resolver_default, spawn_mock_dns_fn, MockReply,
        };
        use hickory_resolver::proto::rr::RecordType as WireType;

        let port = spawn_mock_dns_fn(move |name, rtype| {
            match chain.iter().find(|(from, _)| *from == name) {
                Some((_, to)) if rtype == WireType::CNAME => {
                    MockReply::Answer(vec![cname_rdata(to)])
                }
                _ => MockReply::NxDomain,
            }
        })
        .await;
        mock_dns_resolver_default(port)
    }

    /// Regression: only the first CNAME hop was matched, so a vanity CNAME
    /// pointing at the provider through an intermediate name was never
    /// checked.
    #[tokio::test]
    async fn a_provider_later_in_the_cname_chain_is_found() {
        let resolver = chain_resolver(&[
            ("docs.example.com", "docs.cdn.example.net"),
            ("docs.cdn.example.net", "gone.github.io"),
        ])
        .await;
        let r = resolve_host(&resolver, "docs.example.com").await;
        assert_eq!(r.cname.as_deref(), Some("docs.cdn.example.net."));
        let (provider, hop) = r.provider.expect("provider in the chain");
        assert_eq!(provider.provider, "GitHub Pages");
        assert_eq!(hop, "gone.github.io.");
    }

    #[tokio::test]
    async fn a_looping_cname_chain_ends() {
        let resolver = chain_resolver(&[
            ("a.example.com", "b.example.net"),
            ("b.example.net", "a.example.com"),
        ])
        .await;
        let r = resolve_host(&resolver, "a.example.com").await;
        assert!(r.provider.is_none());
    }
}
