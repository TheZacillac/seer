//! Who is calling, and what they may call.
//!
//! A request with no `Authorization` header is [`Caller::Anonymous`]; one
//! with the right bearer key is [`Caller::Keyed`]. A header that is present
//! but wrong is refused outright — it never falls back to anonymous, so a
//! misconfigured backend fails loudly instead of quietly getting less.

use subtle::ConstantTimeEq;

use crate::error::ApiError;

/// Who may call a route.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tier {
    /// Anyone, when the server is public.
    Public,
    /// Only callers with the API key.
    Keyed,
}

/// Who sent a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Caller {
    /// No `Authorization` header.
    Anonymous,
    /// Presented the API key.
    Keyed,
}

/// Works out who is calling from the `Authorization` header value (`None`
/// when the header is absent) and the configured key. The key comparison is
/// constant-time.
pub fn identify(authorization: Option<&str>, api_key: Option<&str>) -> Result<Caller, ApiError> {
    let Some(header) = authorization else {
        return Ok(Caller::Anonymous);
    };
    let token = header
        .split_once(' ')
        .filter(|(scheme, _)| scheme.eq_ignore_ascii_case("bearer"))
        .map(|(_, token)| token.trim());
    let matches = match (token, api_key) {
        (Some(token), Some(key)) if !token.is_empty() => {
            bool::from(token.as_bytes().ct_eq(key.as_bytes()))
        }
        _ => false,
    };
    if matches {
        Ok(Caller::Keyed)
    } else {
        Err(ApiError::unauthorized("Invalid API key"))
    }
}

/// Whether `caller` may use a route of `tier` on a server whose anonymous
/// tier is on (`public`) or off.
pub fn authorize(caller: Caller, tier: Tier, public: bool) -> Result<(), ApiError> {
    match (caller, tier) {
        (Caller::Keyed, _) => Ok(()),
        (Caller::Anonymous, _) if !public => Err(ApiError::unauthorized("API key required")),
        (Caller::Anonymous, Tier::Keyed) => {
            Err(ApiError::unauthorized("This endpoint requires an API key"))
        }
        (Caller::Anonymous, Tier::Public) => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::StatusCode;

    #[test]
    fn no_header_is_anonymous() {
        assert_eq!(identify(None, Some("k")), Ok(Caller::Anonymous));
        assert_eq!(identify(None, None), Ok(Caller::Anonymous));
    }

    #[test]
    fn the_right_key_is_keyed_whatever_the_scheme_case() {
        assert_eq!(identify(Some("Bearer k3y"), Some("k3y")), Ok(Caller::Keyed));
        assert_eq!(identify(Some("bearer k3y"), Some("k3y")), Ok(Caller::Keyed));
        assert_eq!(
            identify(Some("BEARER  k3y "), Some("k3y")),
            Ok(Caller::Keyed)
        );
    }

    #[test]
    fn a_present_but_wrong_header_is_refused_never_anonymous() {
        for header in ["Bearer wrong", "Bearer", "Bearer ", "k3y", "Basic k3y", ""] {
            let error = identify(Some(header), Some("k3y")).unwrap_err();
            assert_eq!(error.status(), StatusCode::UNAUTHORIZED, "{header:?}");
        }
    }

    #[test]
    fn any_key_is_wrong_when_none_is_configured() {
        let error = identify(Some("Bearer k3y"), None).unwrap_err();
        assert_eq!(error.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn a_keyed_caller_may_call_everything() {
        for tier in [Tier::Public, Tier::Keyed] {
            for public in [true, false] {
                assert_eq!(authorize(Caller::Keyed, tier, public), Ok(()));
            }
        }
    }

    #[test]
    fn an_anonymous_caller_gets_only_public_routes_on_a_public_server() {
        assert_eq!(authorize(Caller::Anonymous, Tier::Public, true), Ok(()));
        for (tier, public) in [
            (Tier::Keyed, true),
            (Tier::Public, false),
            (Tier::Keyed, false),
        ] {
            let error = authorize(Caller::Anonymous, tier, public).unwrap_err();
            assert_eq!(error.status(), StatusCode::UNAUTHORIZED);
        }
    }
}
