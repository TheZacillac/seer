//! The route table: every operation the server exposes, in one place.
//!
//! [`routes`] is the single list of paths, tiers and handlers; the router,
//! the tier gate and the tests all read it. Handlers live in the sibling
//! modules by area and all have the same shape: edge checks, then one
//! seer-core call handed to `Call::respond`, which caches, bounds and times
//! it. Paths and JSON match seer-api's.

mod assessment;
mod dns;
mod probes;
mod registration;

use axum::routing::get;
use seer_core::contract::CostClass::{Heavy, Light, Moderate, Standard};

use crate::app::Route;
use crate::state::Deadline;

/// Every route the server exposes. Each cost class is the one whose limit
/// seer-api declares on the same route. Routes built with `Route::keyed`
/// need the API key; the rest are open when the server is public.
pub fn routes() -> Vec<Route> {
    vec![
        Route::public("/lookup/{domain}", Standard, get(registration::lookup)),
        Route::public("/whois/{domain}", Standard, get(registration::whois)),
        Route::public(
            "/rdap/domain/{domain}",
            Standard,
            get(registration::rdap_domain),
        ),
        Route::public("/rdap/ip/{ip}", Standard, get(registration::rdap_ip)),
        Route::public("/rdap/asn/{asn}", Standard, get(registration::rdap_asn)),
        Route::public(
            "/availability/{domain}",
            Light,
            get(registration::availability),
        ),
        Route::public("/tld/", Standard, get(registration::tld_list)),
        Route::public("/tld/{tld}", Light, get(registration::tld_info)),
        Route::public("/dns/{domain}/{record_type}", Light, get(dns::dig)),
        Route::public("/ssl/{domain}", Standard, get(probes::ssl)),
        Route::public("/status/{domain}", Moderate, get(probes::status)),
        Route::keyed("/info/{domain}", Light, get(registration::info)),
        Route::keyed("/dnssec/{domain}", Light, get(dns::dnssec)),
        Route::keyed("/delegation/{domain}", Standard, get(dns::delegation)),
        Route::keyed(
            "/propagation/{domain}/{record_type}",
            Moderate,
            get(dns::propagation),
        ),
        Route::keyed("/dns/trace/{domain}", Heavy, get(dns::trace)),
        Route::keyed("/dns/compare/{domain}", Standard, get(dns::compare)),
        Route::keyed("/subdomains/{domain}", Heavy, get(assessment::subdomains)),
        Route::keyed(
            "/diff/{domain_a}/{domain_b}",
            Standard,
            get(assessment::diff),
        ),
        Route::keyed("/caa/{domain}", Light, get(assessment::caa)),
        Route::keyed("/posture/{domain}", Standard, get(assessment::posture)),
        Route::keyed("/headers/{domain}", Moderate, get(assessment::headers)),
        Route::keyed("/audit/{domain}", Heavy, get(assessment::audit)).within(Deadline::Audit),
        Route::keyed("/takeover/{domain}", Heavy, get(assessment::takeover)),
        Route::keyed("/confusables/{domain}", Heavy, get(assessment::confusables)),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::{assemble, router};
    use crate::settings::Settings;
    use crate::state::{AppState, Clients};
    use crate::test_support::{get, get_with_key};
    use crate::tier::{Caller, Tier};
    use axum::http::StatusCode;
    use axum::Router;
    use seer_core::config::ServerConfig;
    use seer_core::SeerConfig;
    use std::time::{Duration, Instant};

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
    fn only_these_routes_are_public() {
        // Making a route public is a deliberate edit here.
        let public: Vec<&str> = routes()
            .iter()
            .filter(|r| r.tier == Tier::Public)
            .map(|r| r.path)
            .collect();
        assert_eq!(
            public,
            [
                "/lookup/{domain}",
                "/whois/{domain}",
                "/rdap/domain/{domain}",
                "/rdap/ip/{ip}",
                "/rdap/asn/{asn}",
                "/availability/{domain}",
                "/tld/",
                "/tld/{tld}",
                "/dns/{domain}/{record_type}",
                "/ssl/{domain}",
                "/status/{domain}",
            ]
        );
    }

    /// One well-formed request per route. No test sends these to the
    /// network unless it is marked live.
    const SAMPLES: &[(&str, &str)] = &[
        ("/lookup/{domain}", "/lookup/example.com"),
        ("/whois/{domain}", "/whois/example.com"),
        ("/rdap/domain/{domain}", "/rdap/domain/example.com"),
        ("/rdap/ip/{ip}", "/rdap/ip/1.1.1.1"),
        ("/rdap/asn/{asn}", "/rdap/asn/13335"),
        ("/availability/{domain}", "/availability/example.com"),
        ("/tld/", "/tld/"),
        ("/tld/{tld}", "/tld/com"),
        ("/dns/{domain}/{record_type}", "/dns/example.com/A"),
        ("/ssl/{domain}", "/ssl/example.com"),
        ("/status/{domain}", "/status/example.com"),
        ("/info/{domain}", "/info/example.com"),
        ("/dnssec/{domain}", "/dnssec/example.com"),
        ("/delegation/{domain}", "/delegation/example.com"),
        (
            "/propagation/{domain}/{record_type}",
            "/propagation/example.com/A",
        ),
        ("/dns/trace/{domain}", "/dns/trace/example.com"),
        (
            "/dns/compare/{domain}",
            "/dns/compare/example.com?server_a=8.8.8.8&server_b=1.1.1.1",
        ),
        ("/subdomains/{domain}", "/subdomains/example.com"),
        (
            "/diff/{domain_a}/{domain_b}",
            "/diff/example.com/example.org",
        ),
        ("/caa/{domain}", "/caa/example.com"),
        ("/posture/{domain}", "/posture/example.com"),
        ("/headers/{domain}", "/headers/example.com"),
        ("/audit/{domain}", "/audit/example.com"),
        ("/takeover/{domain}", "/takeover/example.com"),
        ("/confusables/{domain}", "/confusables/example.com"),
    ];

    #[test]
    fn every_route_has_a_sample() {
        let mut table: Vec<&str> = routes().iter().map(|r| r.path).collect();
        let mut sampled: Vec<&str> = SAMPLES.iter().map(|(pattern, _)| *pattern).collect();
        table.sort_unstable();
        sampled.sort_unstable();
        assert_eq!(table, sampled);
    }

    #[tokio::test]
    async fn anonymous_callers_get_a_401_on_every_keyed_route() {
        let app = app();
        let keyed: Vec<&str> = routes()
            .iter()
            .filter(|r| r.tier == Tier::Keyed)
            .map(|r| r.path)
            .collect();
        assert!(!keyed.is_empty());
        for (pattern, uri) in SAMPLES {
            if keyed.contains(pattern) {
                let reply = get(&app, uri).await;
                assert_eq!(reply.status, StatusCode::UNAUTHORIZED, "{pattern}");
            }
        }
    }

    #[tokio::test]
    async fn every_route_waits_for_a_slot_and_leaves_none_held() {
        // Every slot is taken before any request is sent, so no lookup
        // starts and nothing here touches the network. A 503 from each
        // route proves its lookup runs inside `Call`: bounded, under the
        // deadline, and cancelled with it.
        let server = ServerConfig {
            public: true,
            ..ServerConfig::default()
        };
        let mut settings = Settings::new(&server, Some("k".to_string())).unwrap();
        settings.request_timeout = Duration::from_millis(100);
        settings.max_in_flight = 2;
        let mut clients = Clients::from_config(&SeerConfig::default());
        clients.audit_deadline = Duration::from_millis(100);
        let table = routes();
        let state = AppState::new(settings, clients, &table);
        let app = assemble(state.clone(), table);
        let heavy = state.permits.heavy_available();
        let _a = state.permits.acquire(Caller::Keyed, Light).await.unwrap();
        let _b = state.permits.acquire(Caller::Keyed, Light).await.unwrap();
        for (pattern, uri) in SAMPLES {
            let reply = get_with_key(&app, uri, "k").await;
            assert_eq!(
                reply.status,
                StatusCode::SERVICE_UNAVAILABLE,
                "{pattern} did not wait for a slot: {}",
                reply.json
            );
        }
        assert_eq!(state.permits.heavy_available(), heavy);
        assert_eq!(state.permits.available().0, 0);
        assert_eq!(state.per_client.clients(), 0);
    }

    #[tokio::test]
    async fn the_keyed_dns_routes_check_their_record_type() {
        for path in [
            "/dns/trace/example.com?record_type=a",
            "/dns/trace/example.com?record_type=ZZZ",
            "/dns/compare/example.com?server_a=8.8.8.8&server_b=1.1.1.1&record_type=A-B",
            "/propagation/example.com/a",
            "/propagation/example.com/ZZZ",
        ] {
            let reply = get_with_key(&app(), path, "k").await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{path}");
        }
    }

    #[tokio::test]
    async fn compare_refuses_reserved_and_missing_servers() {
        for query in [
            "",
            "?server_a=8.8.8.8",
            "?server_b=8.8.8.8",
            "?server_a=127.0.0.1&server_b=1.1.1.1",
            "?server_a=8.8.8.8&server_b=tls://192.168.1.1",
        ] {
            let path = format!("/dns/compare/example.com{query}");
            let reply = get_with_key(&app(), &path, "k").await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{query}");
        }
        let missing = get_with_key(&app(), "/dns/compare/example.com", "k").await;
        assert_eq!(missing.json["detail"], "server_a and server_b are required");
        let long = format!(
            "/dns/compare/example.com?server_a={}&server_b=1.1.1.1",
            "a".repeat(513)
        );
        assert_eq!(
            get_with_key(&app(), &long, "k").await.status,
            StatusCode::BAD_REQUEST
        );
    }

    #[tokio::test]
    async fn an_invalid_name_on_a_keyed_route_is_a_400_before_a_slot() {
        for path in [
            "/info/not_a_domain",
            "/dnssec/bad..host",
            "/delegation/-x-.com",
        ] {
            let reply = get_with_key(&app(), path, "k").await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{path}");
        }
        let long = format!("/info/{}", "a".repeat(254));
        assert_eq!(
            get_with_key(&app(), &long, "k").await.status,
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn only_the_audit_runs_under_the_audit_deadline() {
        let audit: Vec<&str> = routes()
            .iter()
            .filter(|r| r.deadline == Deadline::Audit)
            .map(|r| r.path)
            .collect();
        assert_eq!(audit, ["/audit/{domain}"]);
    }

    #[test]
    fn the_fan_outs_are_heavy() {
        // These take a slot from the small pool; seer-api limits the same
        // five at its heavy rate.
        let mut heavy: Vec<&str> = routes()
            .iter()
            .filter(|r| r.cost == Heavy)
            .map(|r| r.path)
            .collect();
        heavy.sort_unstable();
        assert_eq!(
            heavy,
            [
                "/audit/{domain}",
                "/confusables/{domain}",
                "/dns/trace/{domain}",
                "/subdomains/{domain}",
                "/takeover/{domain}",
            ]
        );
    }

    #[tokio::test]
    async fn a_concurrency_outside_1_to_50_is_a_400() {
        for route in ["/subdomains", "/takeover", "/confusables"] {
            for value in ["0", "51", "100000", "-1", "ten"] {
                let path = format!("{route}/example.com?concurrency={value}");
                let reply = get_with_key(&app(), &path, "k").await;
                assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{path}");
            }
        }
    }

    #[tokio::test]
    async fn resolve_must_be_true_or_false() {
        let reply = get_with_key(&app(), "/subdomains/example.com?resolve=maybe", "k").await;
        assert_eq!(reply.status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn reserved_literals_are_refused_on_the_keyed_probes() {
        // The host is a connect target on these routes.
        for path in [
            "/headers/127.0.0.1",
            "/headers/127.0.0.1:443",
            "/audit/10.0.0.1",
            "/diff/169.254.169.254/example.com",
            "/diff/example.com/192.168.1.1",
        ] {
            let reply = get_with_key(&app(), path, "k").await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{path}");
        }
    }

    #[tokio::test]
    async fn an_invalid_name_on_an_assessment_route_is_a_400_before_a_slot() {
        for path in [
            "/subdomains/not_a_domain",
            "/diff/example.com/bad..host",
            "/caa/bad..host",
            "/posture/-x-.com",
            "/headers/bad..host",
            "/audit/bad..host",
            "/takeover/not_a_domain",
            "/confusables/not_a_domain",
        ] {
            let reply = get_with_key(&app(), path, "k").await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{path}");
        }
    }

    #[tokio::test]
    #[ignore = "live network"]
    async fn live_every_keyed_route_answers() {
        let app = app();
        let keyed: Vec<&str> = routes()
            .iter()
            .filter(|r| r.tier == Tier::Keyed)
            .map(|r| r.path)
            .collect();
        for (pattern, uri) in SAMPLES {
            if keyed.contains(pattern) {
                let reply = get_with_key(&app, uri, "k").await;
                assert_eq!(reply.status, StatusCode::OK, "{pattern}: {}", reply.json);
            }
        }
    }

    #[tokio::test]
    #[ignore = "live network"]
    async fn live_a_request_dropped_mid_flight_holds_nothing() {
        // The spec's cancellation test, with real lookups in flight.
        let table = routes();
        let server = ServerConfig {
            public: true,
            ..ServerConfig::default()
        };
        let settings = Settings::new(&server, Some("k".to_string())).unwrap();
        let clients = Clients::from_config(&SeerConfig::default());
        let state = AppState::new(settings, clients, &table);
        let app = assemble(state.clone(), table);
        let full = (state.permits.available(), state.permits.heavy_available());
        for (pattern, uri) in SAMPLES {
            let request = tokio::spawn({
                let app = app.clone();
                async move { get_with_key(&app, uri, "k").await }
            });
            tokio::time::sleep(Duration::from_millis(50)).await;
            request.abort();
            let _ = request.await;
            assert_eq!(
                (state.permits.available(), state.permits.heavy_available()),
                full,
                "{pattern} left a slot held"
            );
        }
    }

    #[test]
    fn the_whole_table_is_snapshotted() {
        // Path, tier, cost class and deadline of every route: any change to what the
        // server exposes, or how it is limited, shows up in review.
        let table: String = routes()
            .iter()
            .map(|r| {
                let tier = format!("{:?}", r.tier);
                format!(
                    "{:<36} {tier:<7} {:<9} {:?}\n",
                    r.path,
                    r.cost.name(),
                    r.deadline
                )
            })
            .collect();
        insta::assert_snapshot!(table);
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
    async fn the_tld_list_is_cached_for_browsers_and_proxies() {
        let reply = get(&app(), "/tld/").await;
        assert_eq!(reply.status, StatusCode::OK);
        assert_eq!(reply.headers["cache-control"], "max-age=60");
        assert_eq!(reply.headers["content-type"], "application/json");
    }

    #[tokio::test]
    async fn an_invalid_name_is_a_400_before_the_cache_or_a_slot() {
        // Normalization for the cache key rejects these with core's own
        // message; nothing is looked up.
        for path in ["/lookup/not_a_domain", "/ssl/bad..host", "/whois/-x-.com"] {
            let reply = get(&app(), path).await;
            assert_eq!(reply.status, StatusCode::BAD_REQUEST, "{path}");
            assert_eq!(reply.headers["cache-control"], "no-store", "{path}");
        }
    }

    #[tokio::test]
    #[ignore = "live network"]
    async fn live_every_route_answers_and_repeats_from_the_cache() {
        let app = app();
        for path in [
            "/lookup/example.com",
            "/whois/example.com",
            "/rdap/domain/example.com",
            "/rdap/ip/1.1.1.1",
            "/rdap/asn/13335",
            "/availability/example.com",
            "/tld/",
            "/tld/com",
            "/dns/example.com/A",
            "/ssl/example.com",
            "/status/example.com",
        ] {
            let first = get(&app, path).await;
            assert_eq!(first.status, StatusCode::OK, "{path}: {}", first.json);
            let started = Instant::now();
            let second = get(&app, path).await;
            assert_eq!(second.json, first.json, "{path}");
            assert!(
                started.elapsed() < Duration::from_millis(50),
                "{path} was not served from the cache"
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
