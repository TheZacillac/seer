//! Assessments: what a domain exposes and how well it is protected.
//! Subdomains from CT logs, a two-domain diff, CAA, email posture, HTTP
//! security headers, the graded audit, takeover exposure and look-alike
//! domains. All keyed. Headers, audit and diff connect to the host named
//! in the path; core resolves, vets and pins every address itself.

use axum::response::Response;
use seer_core::validation::{normalize_domain, normalize_host};
use seer_core::{AuditOptions, SeerError};
use serde::Deserialize;

use crate::call::Call;
use crate::edge::{self, PathParams, QueryParams};
use crate::error::ApiError;

/// Query parameters of `GET /subdomains/{domain}`.
#[derive(Debug, Deserialize)]
pub struct SubdomainsQuery {
    /// `true`: resolve and classify each name (live, dead, wildcard) and
    /// flag dangling CNAMEs. Only `true` and `false` are accepted.
    resolve: Option<bool>,
    /// Fan-out width of the resolve pass (1 to 50, default 10).
    concurrency: Option<usize>,
}

/// `GET /subdomains/{domain}`: names seen in Certificate Transparency
/// logs; with `resolve=true`, each one resolved and classified.
pub async fn subdomains(
    call: Call,
    PathParams(domain): PathParams<String>,
    QueryParams(query): QueryParams<SubdomainsQuery>,
) -> Result<Response, ApiError> {
    edge::domain(&domain)?;
    let concurrency = edge::concurrency(query.concurrency)?;
    let name = normalize_domain(&domain)?;
    let clients = &call.state.clients;
    if query.resolve.unwrap_or(false) {
        // A different answer shape, so a different cache entry.
        call.respond(&[&name, "resolved"], async {
            let found = clients.subdomains.enumerate(&domain).await?;
            Ok::<_, SeerError>(
                seer_core::classify_subdomains(
                    &clients.dns,
                    &found.domain,
                    found.subdomains,
                    concurrency,
                )
                .await,
            )
        })
        .await
    } else {
        call.respond(&[&name, "names"], clients.subdomains.enumerate(&domain))
            .await
    }
}

/// `GET /diff/{domain_a}/{domain_b}`: registration, DNS and TLS side by
/// side. Each name is compared as the exact host (`www.` kept).
pub async fn diff(
    call: Call,
    PathParams((domain_a, domain_b)): PathParams<(String, String)>,
) -> Result<Response, ApiError> {
    edge::domain(&domain_a)?;
    edge::domain(&domain_b)?;
    edge::public_literal(&domain_a, 443).await?;
    edge::public_literal(&domain_b, 443).await?;
    let a = normalize_host(&domain_a)?;
    let b = normalize_host(&domain_b)?;
    call.respond(
        &[&a, &b],
        call.state.clients.differ.diff(&domain_a, &domain_b),
    )
    .await
}

/// `GET /caa/{domain}`: the CAA policy that applies to the exact host.
pub async fn caa(call: Call, PathParams(domain): PathParams<String>) -> Result<Response, ApiError> {
    edge::domain(&domain)?;
    let host = normalize_host(&domain)?;
    call.respond(
        &[&host],
        seer_core::caa::lookup_caa(&call.state.clients.dns, &domain, None),
    )
    .await
}

/// `GET /posture/{domain}`: SPF, DMARC, MTA-STS, BIMI and DANE.
pub async fn posture(
    call: Call,
    PathParams(domain): PathParams<String>,
) -> Result<Response, ApiError> {
    edge::domain(&domain)?;
    let name = normalize_domain(&domain)?;
    call.respond(
        &[&name],
        seer_core::lookup_email_posture(&call.state.clients.dns, &domain, None),
    )
    .await
}

/// `GET /headers/{domain}`: HTTP security headers, cookie flags and
/// version disclosure, from one HTTPS request to the host.
pub async fn headers(
    call: Call,
    PathParams(domain): PathParams<String>,
) -> Result<Response, ApiError> {
    edge::domain(&domain)?;
    edge::public_literal(&domain, 443).await?;
    let host = normalize_host(&domain)?;
    call.respond(
        &[&host],
        seer_core::audit_headers(&domain, call.state.clients.http_timeout),
    )
    .await
}

/// `GET /audit/{domain}`: the graded security audit. Around forty
/// outbound requests, so it is a heavy route with its own deadline.
pub async fn audit(
    call: Call,
    PathParams(domain): PathParams<String>,
) -> Result<Response, ApiError> {
    edge::domain(&domain)?;
    edge::public_literal(&domain, 443).await?;
    // The host is the finer of the two names an audit uses.
    let host = normalize_host(&domain)?;
    call.respond(
        &[&host],
        call.state
            .clients
            .auditor
            .audit(&domain, AuditOptions::default()),
    )
    .await
}

/// Query parameters of the scans that fan out over many hosts.
#[derive(Debug, Deserialize)]
pub struct FanOutQuery {
    /// Fan-out width (1 to 50, default 10).
    concurrency: Option<usize>,
}

/// `GET /takeover/{domain}`: every subdomain seen in CT logs, checked for
/// a CNAME to a provider that would let someone else claim it.
pub async fn takeover(
    call: Call,
    PathParams(domain): PathParams<String>,
    QueryParams(query): QueryParams<FanOutQuery>,
) -> Result<Response, ApiError> {
    edge::domain(&domain)?;
    let concurrency = edge::concurrency(query.concurrency)?;
    let name = normalize_domain(&domain)?;
    let clients = &call.state.clients;
    // `concurrency` is not part of the key: it changes how fast the answer
    // arrives, not the answer.
    call.respond(&[&name], async {
        let found = clients.subdomains.enumerate(&domain).await?;
        seer_core::scan_takeover(
            &clients.dns,
            &found.domain,
            found.subdomains,
            concurrency,
            clients.http_timeout,
        )
        .await
    })
    .await
}

/// `GET /confusables/{domain}`: registered look-alike domains.
pub async fn confusables(
    call: Call,
    PathParams(domain): PathParams<String>,
    QueryParams(query): QueryParams<FanOutQuery>,
) -> Result<Response, ApiError> {
    edge::domain(&domain)?;
    let concurrency = edge::concurrency(query.concurrency)?;
    let name = normalize_domain(&domain)?;
    call.respond(
        &[&name],
        seer_core::find_confusables(&call.state.clients.lookup, &domain, concurrency),
    )
    .await
}
