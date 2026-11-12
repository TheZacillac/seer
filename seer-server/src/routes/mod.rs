//! The route table: every operation the server exposes, in one place.
//!
//! [`routes`] is the single list of paths, tiers and handlers; the router,
//! the tier gate and the tests all read it. Handlers live in the sibling
//! modules by area and all have the same shape: edge checks, one seer-core
//! call, the result as JSON. Paths and JSON match seer-api's.

mod dns;
mod probes;
mod registration;

use axum::routing::get;

use crate::app::Route;

/// Every route the server exposes. The keyed-only operations (audit,
/// trace, propagation and the rest) join this table in the next release.
pub fn routes() -> Vec<Route> {
    vec![
        Route::public("/lookup/{domain}", get(registration::lookup)),
        Route::public("/whois/{domain}", get(registration::whois)),
        Route::public("/rdap/domain/{domain}", get(registration::rdap_domain)),
        Route::public("/rdap/ip/{ip}", get(registration::rdap_ip)),
        Route::public("/rdap/asn/{asn}", get(registration::rdap_asn)),
        Route::public("/availability/{domain}", get(registration::availability)),
        Route::public("/tld/", get(registration::tld_list)),
        Route::public("/tld/{tld}", get(registration::tld_info)),
        Route::public("/dns/{domain}/{record_type}", get(dns::dig)),
        Route::public("/ssl/{domain}", get(probes::ssl)),
        Route::public("/status/{domain}", get(probes::status)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::router;
    use crate::settings::Settings;
    use crate::state::Clients;
    use crate::test_support::{get, get_with_key};
    use crate::tier::Tier;
    use axum::http::StatusCode;
    use axum::Router;
    use seer_core::config::ServerConfig;
    use seer_core::SeerConfig;

    /// The real routes on a public server whose key is `k`.
    fn app() -> Router {
        let server = ServerConfig {
            public: true,
            ..ServerConfig::default()
        };
        let settings = Settings::new(&server, Some("k".to_string())).unwrap();
        router(
            settings,
            Clients::from_config(&SeerConfig::default()),
            routes(),
        )
    }

    #[test]
    fn the_table_is_exactly_the_public_routes() {
        // Making a route public, or adding one, is a deliberate edit here.
        let table: Vec<(&str, Tier)> = routes().iter().map(|r| (r.path, r.tier)).collect();
        assert_eq!(
            table,
            [
                ("/lookup/{domain}", Tier::Public),
                ("/whois/{domain}", Tier::Public),
                ("/rdap/domain/{domain}", Tier::Public),
                ("/rdap/ip/{ip}", Tier::Public),
                ("/rdap/asn/{asn}", Tier::Public),
                ("/availability/{domain}", Tier::Public),
                ("/tld/", Tier::Public),
                ("/tld/{tld}", Tier::Public),
                ("/dns/{domain}/{record_type}", Tier::Public),
                ("/ssl/{domain}", Tier::Public),
                ("/status/{domain}", Tier::Public),
            ]
        );
    }

    #[test]
    fn paths_are_unique() {
        let mut paths: Vec<&str> = routes().iter().map(|r| r.path).collect();
        let count = paths.len();
        paths.sort_unstable();
        paths.dedup();
        assert_eq!(paths.len(), count);
    }

    #[tokio::test]
    async fn the_tld_list_is_served_from_embedded_data() {
        let reply = get(&app(), "/tld/").await;
        assert_eq!(reply.status, StatusCode::OK);
        let tlds = reply.json.as_array().unwrap();
        assert!(tlds.iter().any(|tld| tld == "com"));
    }

    #[tokio::test]
    async fn a_junk_tld_is_a_400() {
        for path in ["/tld/-bad-", "/tld/co.uk", "/tld/a%20b"] {
            let reply = get(&app(), path).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{path}");
            assert!(reply.json["detail"]
                .as_str()
                .unwrap()
                .starts_with("Invalid TLD"));
        }
    }

    #[tokio::test]
    async fn an_overlong_domain_is_a_400() {
        let path = format!("/lookup/{}", "a".repeat(254));
        let reply = get(&app(), &path).await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn undecodable_path_is_a_json_400() {
        let reply = get(&app(), "/lookup/%FF").await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
        assert!(
            reply.json["detail"].is_string(),
            "must be a JSON detail body"
        );
    }

    #[tokio::test]
    async fn a_bad_record_type_is_a_400_before_any_query() {
        // Lowercase fails the edge token rule; ZZZ passes it and fails
        // core's parser. Neither sends a DNS query.
        for path in [
            "/dns/example.com/a",
            "/dns/example.com/ZZZ",
            "/dns/example.com/A-B",
        ] {
            let reply = get(&app(), path).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{path}");
        }
    }

    #[tokio::test]
    async fn choosing_a_nameserver_needs_the_key() {
        let reply = get(&app(), "/dns/example.com/A?nameserver=8.8.8.8").await;
        assert_eq!(reply.status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            reply.json["detail"],
            "Choosing a nameserver requires an API key"
        );
    }

    #[tokio::test]
    async fn a_reserved_nameserver_is_refused_for_keyed_callers_too() {
        for spec in ["127.0.0.1", "10.0.0.1:53", "tls://192.168.1.1"] {
            let path = format!("/dns/example.com/A?nameserver={spec}");
            let reply = get_with_key(&app(), &path, "k").await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{spec}");
        }
    }

    #[tokio::test]
    async fn an_overlong_nameserver_is_a_400() {
        let path = format!("/dns/example.com/A?nameserver={}", "a".repeat(513));
        let reply = get_with_key(&app(), &path, "k").await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn reserved_literals_are_refused_in_any_spelling() {
        // The host is the connect target on these routes. Core refuses the
        // address itself later; this is the clear 400, with no connection.
        for path in [
            "/ssl/127.0.0.1",
            "/ssl/127.0.0.1.",
            "/ssl/127.0.0.1:443",
            "/status/10.0.0.1",
            "/status/169.254.169.254",
            "/rdap/ip/192.168.1.1",
        ] {
            let reply = get(&app(), path).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{path}");
        }
    }

    #[tokio::test]
    async fn an_asn_must_be_a_32_bit_number() {
        for path in ["/rdap/asn/abc", "/rdap/asn/-1", "/rdap/asn/4294967296"] {
            let reply = get(&app(), path).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{path}");
            assert_eq!(
                reply.json["detail"],
                "asn must be a number between 0 and 4294967295"
            );
        }
    }

    #[tokio::test]
    #[ignore = "live network"]
    async fn live_lookup_and_dig_answer() {
        let lookup = get(&app(), "/lookup/example.com").await;
        assert_eq!(lookup.status, StatusCode::OK);
        let dig = get(&app(), "/dns/example.com/A").await;
        assert_eq!(dig.status, StatusCode::OK);
        assert_eq!(dig.json["status"], "NOERROR");
    }
}
