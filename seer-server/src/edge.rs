//! Checks a handler runs before calling core, and extractors whose
//! failures are JSON.
//!
//! These are edge checks only: length limits and token rules from
//! `seer_core::contract`, so junk gets a clear 400. Normalization and the
//! real SSRF gate stay in seer-core, which resolves, vets and pins every
//! address itself. [`public_literal`] exists to answer a reserved IP
//! *literal* with a 400 instead of the upstream failure core would report;
//! a hostname is never pre-checked, because answering differently for an
//! internal name than for a missing one would let callers probe which
//! internal names exist.

use std::net::IpAddr;

use axum::extract::{FromRequestParts, Path, Query};
use axum::http::request::Parts;
use seer_core::dns::NameserverSpec;
use seer_core::{contract, RecordType};
use serde::de::DeserializeOwned;

use crate::error::ApiError;

/// Path parameters, like Axum's `Path`, but a parameter that cannot be
/// decoded is this server's JSON 400 rather than a plain-text rejection.
pub struct PathParams<T>(pub T);

impl<S, T> FromRequestParts<S> for PathParams<T>
where
    S: Send + Sync,
    T: DeserializeOwned + Send,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Path::<T>::from_request_parts(parts, state).await {
            Ok(Path(value)) => Ok(Self(value)),
            Err(_) => Err(ApiError::invalid("Invalid path parameter")),
        }
    }
}

/// Query parameters, like Axum's `Query`, with a JSON 400 on failure.
pub struct QueryParams<T>(pub T);

impl<S, T> FromRequestParts<S> for QueryParams<T>
where
    S: Send + Sync,
    T: DeserializeOwned,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        match Query::<T>::from_request_parts(parts, state).await {
            Ok(Query(value)) => Ok(Self(value)),
            Err(_) => Err(ApiError::invalid("Invalid query string")),
        }
    }
}

/// A domain or host path parameter: present and within the length limit.
pub fn domain(value: &str) -> Result<(), ApiError> {
    let length = value.chars().count();
    if (1..=contract::DOMAIN_MAX_LENGTH).contains(&length) {
        Ok(())
    } else {
        Err(ApiError::invalid(format!(
            "domain must be 1 to {} characters",
            contract::DOMAIN_MAX_LENGTH
        )))
    }
}

/// A record-type path parameter: the edge token rule, then core's parser.
pub fn record_type(value: &str) -> Result<RecordType, ApiError> {
    if !contract::is_record_type_token(value) {
        return Err(ApiError::invalid(
            "record type must be uppercase letters and digits (e.g. A, AAAA, MX)",
        ));
    }
    Ok(value.parse::<RecordType>()?)
}

/// An optional `record_type` query parameter: `A` when absent, as
/// seer-api defaults it.
pub fn record_type_or_a(value: Option<&str>) -> Result<RecordType, ApiError> {
    record_type(value.unwrap_or("A"))
}

/// A TLD path parameter.
pub fn tld(value: &str) -> Result<(), ApiError> {
    if contract::is_tld_token(value) {
        Ok(())
    } else {
        Err(ApiError::invalid(
            "Invalid TLD: expected ASCII letters/digits/hyphens \
             (punycode allowed), optionally with a leading dot",
        ))
    }
}

/// An AS number path parameter.
pub fn asn(value: &str) -> Result<u32, ApiError> {
    value
        .parse::<u32>()
        .map_err(|_| ApiError::invalid("asn must be a number between 0 and 4294967295"))
}

/// Refuses `host` when it is an IP literal in a reserved range, in any
/// spelling core reduces to one (`127.0.0.1.`, `127.0.0.1:443`). Uses
/// core's one reserved-range policy, which resolves nothing for a literal.
/// Anything that is not a literal passes: core vets it when it connects.
pub async fn public_literal(host: &str, port: u16) -> Result<(), ApiError> {
    let literal = if host.parse::<IpAddr>().is_ok() {
        Some(host.to_string())
    } else {
        seer_core::validation::normalize_host(host)
            .ok()
            .filter(|normalized| normalized.parse::<IpAddr>().is_ok())
    };
    if let Some(literal) = literal {
        seer_core::net::validate_public_host(&literal, port).await?;
    }
    Ok(())
}

/// A user-supplied nameserver spec: within the length limit, and not a
/// reserved IP literal. A spec core cannot parse passes; core then rejects
/// it with its own message.
pub async fn nameserver(spec: &str) -> Result<(), ApiError> {
    if spec.chars().count() > contract::NAMESERVER_MAX_LENGTH {
        return Err(ApiError::invalid(format!(
            "nameserver must be at most {} characters",
            contract::NAMESERVER_MAX_LENGTH
        )));
    }
    if let Ok(parsed) = NameserverSpec::parse(spec) {
        public_literal(&parsed.host, parsed.port).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn a_missing_record_type_means_a() {
        assert_eq!(record_type_or_a(None).unwrap(), RecordType::A);
        assert_eq!(record_type_or_a(Some("MX")).unwrap(), RecordType::MX);
        let refused = record_type_or_a(Some("mx")).err().unwrap();
        assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    }
}
