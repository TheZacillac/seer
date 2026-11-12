//! Who the client is, behind a reverse proxy or not.
//!
//! The socket peer is the client unless it is a trusted proxy. Only then is
//! `X-Forwarded-For` read, and it is read from the right: a proxy appends
//! the address it saw, so the leftmost entries are whatever the client
//! chose to send. The same rule seer-api's `get_client_ip` applies.

use std::net::IpAddr;

use axum::http::HeaderMap;
use ipnet::IpNet;

/// The client's address: `peer`, unless `peer` is a trusted proxy and its
/// `X-Forwarded-For` (`forwarded`, see [`forwarded_for`]) names one.
///
/// Walks the forwarded list from the right, skipping blank and trusted
/// entries; the first other entry is the client as the innermost trusted
/// proxy saw it. If that entry is not an IP address, or there is none, the
/// answer is `peer` — never a value further left, which the client chose.
pub fn client_ip(peer: IpAddr, forwarded: &str, trusted: &[IpNet]) -> IpAddr {
    let is_trusted = |ip: &IpAddr| trusted.iter().any(|net| net.contains(ip));
    if !is_trusted(&peer) {
        return peer;
    }
    for entry in forwarded.rsplit(',') {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        match entry.parse::<IpAddr>() {
            Ok(ip) if is_trusted(&ip) => continue,
            Ok(ip) => return ip,
            Err(_) => return peer,
        }
    }
    peer
}

/// Every `X-Forwarded-For` header line, in order, joined with commas. A
/// proxy may add its hop as a separate line instead of extending the
/// existing one; reading only the first line would let the client's own
/// value win. A line that is not text contributes an empty entry.
pub fn forwarded_for(headers: &HeaderMap) -> String {
    headers
        .get_all("x-forwarded-for")
        .iter()
        .map(|value| value.to_str().unwrap_or(""))
        .collect::<Vec<_>>()
        .join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    fn ip(text: &str) -> IpAddr {
        text.parse().unwrap()
    }

    fn nets(entries: &[&str]) -> Vec<IpNet> {
        entries
            .iter()
            .map(|entry| {
                entry
                    .parse::<IpNet>()
                    .unwrap_or_else(|_| IpNet::from(ip(entry)))
            })
            .collect()
    }

    #[test]
    fn an_untrusted_peer_is_the_client_whatever_it_claims() {
        let trusted = nets(&["10.0.0.1"]);
        assert_eq!(
            client_ip(ip("203.0.113.9"), "198.51.100.1", &trusted),
            ip("203.0.113.9")
        );
        assert_eq!(client_ip(ip("203.0.113.9"), "", &[]), ip("203.0.113.9"));
    }

    #[test]
    fn a_trusted_peer_passes_on_the_address_it_appended() {
        let trusted = nets(&["10.0.0.1"]);
        // The client forged the first entry; the proxy appended the second.
        assert_eq!(
            client_ip(ip("10.0.0.1"), "1.2.3.4, 198.51.100.7", &trusted),
            ip("198.51.100.7")
        );
    }

    #[test]
    fn trusted_hops_are_skipped_from_the_right() {
        let trusted = nets(&["10.0.0.0/8"]);
        assert_eq!(
            client_ip(ip("10.0.0.1"), "198.51.100.7, 10.0.0.2, 10.0.0.3", &trusted),
            ip("198.51.100.7")
        );
    }

    #[test]
    fn blank_entries_are_skipped() {
        let trusted = nets(&["10.0.0.1"]);
        assert_eq!(
            client_ip(ip("10.0.0.1"), "198.51.100.7, , ", &trusted),
            ip("198.51.100.7")
        );
    }

    #[test]
    fn the_peer_is_used_when_the_header_gives_no_address() {
        let trusted = nets(&["10.0.0.0/8"]);
        // No header, every entry trusted, or the deciding entry is junk.
        for forwarded in ["", "10.0.0.2, 10.0.0.3", "198.51.100.7, not-an-ip"] {
            assert_eq!(
                client_ip(ip("10.0.0.1"), forwarded, &trusted),
                ip("10.0.0.1"),
                "{forwarded:?}"
            );
        }
    }

    #[test]
    fn every_forwarded_line_is_joined_in_order() {
        let mut headers = HeaderMap::new();
        headers.append("x-forwarded-for", HeaderValue::from_static("1.2.3.4"));
        headers.append("x-forwarded-for", HeaderValue::from_static("198.51.100.7"));
        assert_eq!(forwarded_for(&headers), "1.2.3.4,198.51.100.7");
        // A proxy that adds its own line must still win over the client's.
        let trusted = nets(&["10.0.0.1"]);
        assert_eq!(
            client_ip(ip("10.0.0.1"), &forwarded_for(&headers), &trusted),
            ip("198.51.100.7")
        );
        assert_eq!(forwarded_for(&HeaderMap::new()), "");
    }

    #[test]
    fn a_line_that_is_not_text_contributes_nothing() {
        let mut headers = HeaderMap::new();
        headers.append("x-forwarded-for", HeaderValue::from_bytes(b"\xff").unwrap());
        headers.append("x-forwarded-for", HeaderValue::from_static("198.51.100.7"));
        assert_eq!(forwarded_for(&headers), ",198.51.100.7");
    }
}
