use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::error::{Result, SeerError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RecordType {
    A,
    AAAA,
    CNAME,
    MX,
    NS,
    TXT,
    SOA,
    PTR,
    SRV,
    CAA,
    NAPTR,
    DNSKEY,
    DS,
    CDS,
    CDNSKEY,
    TLSA,
    SSHFP,
    HTTPS,
    SVCB,
    ANY,
}

impl RecordType {
    /// Every queryable record type, in the canonical order the CLI help,
    /// REPL tab-completion, and the MCP tool schema all present.
    ///
    /// Single source of truth: those surfaces used to hand-mirror this list
    /// and two of the three had drifted (NAPTR/TLSA/SSHFP were missing from
    /// the REPL completer and the MCP schema, so the types were queryable but
    /// undiscoverable). Render from this — never re-type the list.
    pub const ALL: &'static [RecordType] = &[
        RecordType::A,
        RecordType::AAAA,
        RecordType::CNAME,
        RecordType::MX,
        RecordType::NS,
        RecordType::TXT,
        RecordType::SOA,
        RecordType::PTR,
        RecordType::SRV,
        RecordType::CAA,
        RecordType::NAPTR,
        RecordType::DNSKEY,
        RecordType::DS,
        RecordType::CDS,
        RecordType::CDNSKEY,
        RecordType::TLSA,
        RecordType::SSHFP,
        RecordType::HTTPS,
        RecordType::SVCB,
        RecordType::ANY,
    ];

    /// The same list as `&'static str` names, for surfaces that need string
    /// slices directly (completion candidates, help text, JSON schemas).
    pub const ALL_NAMES: &'static [&'static str] = &[
        "A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "PTR", "SRV", "CAA", "NAPTR", "DNSKEY",
        "DS", "CDS", "CDNSKEY", "TLSA", "SSHFP", "HTTPS", "SVCB", "ANY",
    ];

    /// The canonical uppercase name. Exhaustive match, so adding a variant
    /// fails to compile here first — the prompt to also extend [`Self::ALL`].
    pub const fn as_str(&self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::CNAME => "CNAME",
            RecordType::MX => "MX",
            RecordType::NS => "NS",
            RecordType::TXT => "TXT",
            RecordType::SOA => "SOA",
            RecordType::PTR => "PTR",
            RecordType::SRV => "SRV",
            RecordType::CAA => "CAA",
            RecordType::NAPTR => "NAPTR",
            RecordType::DNSKEY => "DNSKEY",
            RecordType::DS => "DS",
            RecordType::CDS => "CDS",
            RecordType::CDNSKEY => "CDNSKEY",
            RecordType::TLSA => "TLSA",
            RecordType::SSHFP => "SSHFP",
            RecordType::HTTPS => "HTTPS",
            RecordType::SVCB => "SVCB",
            RecordType::ANY => "ANY",
        }
    }
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for RecordType {
    type Err = SeerError;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_uppercase().as_str() {
            "A" => Ok(RecordType::A),
            "AAAA" => Ok(RecordType::AAAA),
            "CNAME" => Ok(RecordType::CNAME),
            "MX" => Ok(RecordType::MX),
            "NS" => Ok(RecordType::NS),
            "TXT" => Ok(RecordType::TXT),
            "SOA" => Ok(RecordType::SOA),
            "PTR" => Ok(RecordType::PTR),
            "SRV" => Ok(RecordType::SRV),
            "CAA" => Ok(RecordType::CAA),
            "NAPTR" => Ok(RecordType::NAPTR),
            "DNSKEY" => Ok(RecordType::DNSKEY),
            "DS" => Ok(RecordType::DS),
            "CDS" => Ok(RecordType::CDS),
            "CDNSKEY" => Ok(RecordType::CDNSKEY),
            "TLSA" => Ok(RecordType::TLSA),
            "SSHFP" => Ok(RecordType::SSHFP),
            "HTTPS" => Ok(RecordType::HTTPS),
            "SVCB" => Ok(RecordType::SVCB),
            "ANY" | "*" => Ok(RecordType::ANY),
            _ => Err(SeerError::InvalidRecordType(s.to_string())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: RecordType,
    pub ttl: u32,
    pub data: RecordData,
}

/// One SvcParam of an HTTPS or SVCB record (RFC 9460), in presentation form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SvcParam {
    /// The RFC 9460 presentation name: `mandatory`, `alpn`,
    /// `no-default-alpn`, `port`, `ipv4hint`, `ech`, `ipv6hint`, or
    /// `key<N>` for a key without a registered name.
    pub key: String,
    /// The presentation value without surrounding quotes: a comma-separated
    /// list for list-valued keys (`h3,h2`, `192.0.2.1,192.0.2.2`), base64 for
    /// `ech`, and empty for a valueless key such as `no-default-alpn`.
    pub value: String,
}

impl fmt::Display for SvcParam {
    /// `key=value` as dig prints it: an `alpn` list is quoted, and a
    /// valueless key stands bare.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.value.is_empty() {
            f.write_str(&self.key)
        } else if self.key == "alpn" {
            write!(f, "{}=\"{}\"", self.key, self.value)
        } else {
            write!(f, "{}={}", self.key, self.value)
        }
    }
}

/// Writes HTTPS/SVCB RDATA the way dig prints it: priority, target name,
/// then each SvcParam (`1 . alpn="h3,h2" ipv4hint=192.0.2.1`). AliasMode
/// (priority 0, no params) reads `0 target.`.
fn write_svcb(
    f: &mut fmt::Formatter<'_>,
    priority: u16,
    target: &str,
    params: &[SvcParam],
) -> fmt::Result {
    write!(f, "{} {}", priority, target)?;
    for param in params {
        write!(f, " {}", param)?;
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "record_type", content = "value", rename_all = "UPPERCASE")]
#[allow(clippy::upper_case_acronyms)]
pub enum RecordData {
    A {
        address: String,
    },
    AAAA {
        address: String,
    },
    CNAME {
        target: String,
    },
    MX {
        preference: u16,
        exchange: String,
    },
    NS {
        nameserver: String,
    },
    TXT {
        text: String,
    },
    SOA {
        mname: String,
        rname: String,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },
    PTR {
        target: String,
    },
    SRV {
        priority: u16,
        weight: u16,
        port: u16,
        target: String,
    },
    CAA {
        flags: u8,
        tag: String,
        value: String,
    },
    DNSKEY {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        public_key: String,
    },
    DS {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: String,
    },
    /// Child DS (RFC 7344): the DS record a child zone asks its parent to
    /// publish. Same fields as [`RecordData::DS`]; `algorithm` 0 is the
    /// RFC 8078 delete request.
    CDS {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        /// Hex-encoded digest (uppercase).
        digest: String,
    },
    /// Child DNSKEY (RFC 7344). Same fields as [`RecordData::DNSKEY`];
    /// `algorithm` 0 is the RFC 8078 delete request.
    CDNSKEY {
        flags: u16,
        protocol: u8,
        algorithm: u8,
        /// Base64-encoded public key.
        public_key: String,
    },
    TLSA {
        cert_usage: u8,
        selector: u8,
        matching: u8,
        /// Hex-encoded certificate association data (uppercase).
        cert_data: String,
    },
    SSHFP {
        algorithm: u8,
        fingerprint_type: u8,
        /// Hex-encoded fingerprint (uppercase).
        fingerprint: String,
    },
    NAPTR {
        order: u16,
        preference: u16,
        flags: String,
        services: String,
        regexp: String,
        replacement: String,
    },
    /// HTTPS service binding (RFC 9460). `priority` 0 is AliasMode (`target`
    /// is an alias, no params); anything else is ServiceMode.
    HTTPS {
        priority: u16,
        /// The TargetName; `.` means the owner name itself.
        target: String,
        params: Vec<SvcParam>,
    },
    /// General service binding (RFC 9460), same shape as
    /// [`RecordData::HTTPS`].
    SVCB {
        priority: u16,
        /// The TargetName; `.` means the owner name itself.
        target: String,
        params: Vec<SvcParam>,
    },
    Unknown {
        raw: String,
    },
}

impl fmt::Display for RecordData {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordData::A { address } => write!(f, "{}", address),
            RecordData::AAAA { address } => write!(f, "{}", address),
            RecordData::CNAME { target } => write!(f, "{}", target),
            RecordData::MX {
                preference,
                exchange,
            } => write!(f, "{} {}", preference, exchange),
            RecordData::NS { nameserver } => write!(f, "{}", nameserver),
            RecordData::TXT { text } => write!(f, "\"{}\"", text),
            RecordData::SOA {
                mname,
                rname,
                serial,
                refresh,
                retry,
                expire,
                minimum,
            } => write!(
                f,
                "{} {} {} {} {} {} {}",
                mname, rname, serial, refresh, retry, expire, minimum
            ),
            RecordData::PTR { target } => write!(f, "{}", target),
            RecordData::SRV {
                priority,
                weight,
                port,
                target,
            } => write!(f, "{} {} {} {}", priority, weight, port, target),
            RecordData::CAA { flags, tag, value } => write!(f, "{} {} \"{}\"", flags, tag, value),
            RecordData::DNSKEY {
                flags,
                protocol,
                algorithm,
                public_key,
            } => write!(f, "{} {} {} {}", flags, protocol, algorithm, public_key),
            RecordData::DS {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => write!(f, "{} {} {} {}", key_tag, algorithm, digest_type, digest),
            RecordData::CDS {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => write!(f, "{} {} {} {}", key_tag, algorithm, digest_type, digest),
            RecordData::CDNSKEY {
                flags,
                protocol,
                algorithm,
                public_key,
            } => write!(f, "{} {} {} {}", flags, protocol, algorithm, public_key),
            RecordData::TLSA {
                cert_usage,
                selector,
                matching,
                cert_data,
            } => write!(f, "{} {} {} {}", cert_usage, selector, matching, cert_data),
            RecordData::SSHFP {
                algorithm,
                fingerprint_type,
                fingerprint,
            } => write!(f, "{} {} {}", algorithm, fingerprint_type, fingerprint),
            RecordData::NAPTR {
                order,
                preference,
                flags,
                services,
                regexp,
                replacement,
            } => write!(
                f,
                "{} {} \"{}\" \"{}\" \"{}\" {}",
                order, preference, flags, services, regexp, replacement
            ),
            RecordData::HTTPS {
                priority,
                target,
                params,
            }
            | RecordData::SVCB {
                priority,
                target,
                params,
            } => write_svcb(f, *priority, target, params),
            RecordData::Unknown { raw } => write!(f, "{}", raw),
        }
    }
}

impl RecordData {
    /// The address of an A or AAAA record; `None` for any other type.
    pub(crate) fn address(&self) -> Option<&str> {
        match self {
            RecordData::A { address } | RecordData::AAAA { address } => Some(address),
            _ => None,
        }
    }

    /// The record's value as an equality key for cross-server / cross-time
    /// comparison (compare, follow, propagation).
    ///
    /// Domain-name fields are ASCII-lowercased — DNS names compare
    /// case-insensitively (RFC 4343), and resolvers applying 0x20 query-name
    /// randomization return `NS1.EXAMPLE.COM.` and `ns1.example.com.` for the
    /// same record. Everything else is kept verbatim because it is
    /// case-SENSITIVE data: TXT strings, base64 DNSKEY key material, CAA
    /// values, NAPTR regexps, HTTPS/SVCB params. Folding those (as compare/follow used to) hid
    /// real changes; folding nothing (as propagation used to) reported
    /// spurious NS/CNAME inconsistencies. This is the one shared rule.
    ///
    /// The key is rendered through `Display` so its shape always matches the
    /// displayed value.
    pub(crate) fn comparison_key(&self) -> String {
        let mut folded = self.clone();
        match &mut folded {
            RecordData::CNAME { target }
            | RecordData::PTR { target }
            | RecordData::SRV { target, .. }
            | RecordData::HTTPS { target, .. }
            | RecordData::SVCB { target, .. } => target.make_ascii_lowercase(),
            RecordData::NS { nameserver } => nameserver.make_ascii_lowercase(),
            RecordData::MX { exchange, .. } => exchange.make_ascii_lowercase(),
            RecordData::SOA { mname, rname, .. } => {
                mname.make_ascii_lowercase();
                rname.make_ascii_lowercase();
            }
            RecordData::NAPTR { replacement, .. } => replacement.make_ascii_lowercase(),
            // RFC 8659 §4.1: property tags match case-insensitively; the
            // value is left alone.
            RecordData::CAA { tag, .. } => tag.make_ascii_lowercase(),
            RecordData::A { .. }
            | RecordData::AAAA { .. }
            | RecordData::TXT { .. }
            | RecordData::DNSKEY { .. }
            | RecordData::DS { .. }
            | RecordData::CDS { .. }
            | RecordData::CDNSKEY { .. }
            | RecordData::TLSA { .. }
            | RecordData::SSHFP { .. }
            | RecordData::Unknown { .. } => {}
        }
        folded.to_string()
    }
}

impl DnsRecord {
    pub fn format_short(&self) -> String {
        format!("{}", self.data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_record_type_from_str() {
        assert_eq!("A".parse::<RecordType>().unwrap(), RecordType::A);
        assert_eq!("aaaa".parse::<RecordType>().unwrap(), RecordType::AAAA);
        assert_eq!("MX".parse::<RecordType>().unwrap(), RecordType::MX);
        assert_eq!("*".parse::<RecordType>().unwrap(), RecordType::ANY);
        assert!("INVALID".parse::<RecordType>().is_err());
    }

    #[test]
    fn test_record_type_display() {
        assert_eq!(RecordType::A.to_string(), "A");
        assert_eq!(RecordType::AAAA.to_string(), "AAAA");
        assert_eq!(RecordType::MX.to_string(), "MX");
        assert_eq!(RecordType::SOA.to_string(), "SOA");
    }

    #[test]
    fn test_dns_record_format_short() {
        let record = DnsRecord {
            name: "example.com".to_string(),
            record_type: RecordType::A,
            ttl: 300,
            data: RecordData::A {
                address: "1.2.3.4".to_string(),
            },
        };
        assert_eq!(record.format_short(), "1.2.3.4");
    }

    #[test]
    fn test_record_data_display() {
        let mx = RecordData::MX {
            preference: 10,
            exchange: "mail.example.com".to_string(),
        };
        assert_eq!(format!("{}", mx), "10 mail.example.com");

        let txt = RecordData::TXT {
            text: "v=spf1 include:example.com".to_string(),
        };
        assert_eq!(format!("{}", txt), "\"v=spf1 include:example.com\"");

        let srv = RecordData::SRV {
            priority: 10,
            weight: 5,
            port: 443,
            target: "server.example.com".to_string(),
        };
        assert_eq!(format!("{}", srv), "10 5 443 server.example.com");
    }

    #[test]
    fn test_record_serialization_roundtrip() {
        let record = DnsRecord {
            name: "example.com".to_string(),
            record_type: RecordType::A,
            ttl: 300,
            data: RecordData::A {
                address: "1.2.3.4".to_string(),
            },
        };
        let json = serde_json::to_string(&record).unwrap();
        assert!(json.contains("\"A\""));
        assert!(json.contains("1.2.3.4"));
    }

    #[test]
    fn test_soa_display() {
        let soa = RecordData::SOA {
            mname: "ns1.example.com".to_string(),
            rname: "admin.example.com".to_string(),
            serial: 2024010101,
            refresh: 3600,
            retry: 900,
            expire: 604800,
            minimum: 86400,
        };
        let display = format!("{}", soa);
        assert!(display.contains("ns1.example.com"));
        assert!(display.contains("2024010101"));
    }

    #[test]
    fn test_naptr_display() {
        // dig-style: order preference "flags" "services" "regexp" replacement
        let naptr = RecordData::NAPTR {
            order: 100,
            preference: 50,
            flags: "s".to_string(),
            services: "http+N2L+N2C+N2R".to_string(),
            regexp: String::new(),
            replacement: "www.example.com.".to_string(),
        };
        assert_eq!(
            format!("{}", naptr),
            "100 50 \"s\" \"http+N2L+N2C+N2R\" \"\" www.example.com."
        );
    }

    #[test]
    fn comparison_key_folds_only_domain_name_fields() {
        let ns = |n: &str| RecordData::NS {
            nameserver: n.to_string(),
        };
        assert_eq!(
            ns("NS1.Example.COM.").comparison_key(),
            ns("ns1.example.com.").comparison_key()
        );
        let mx = RecordData::MX {
            preference: 10,
            exchange: "MX.Example.com.".to_string(),
        };
        assert_eq!(mx.comparison_key(), "10 mx.example.com.");
        let cname = RecordData::CNAME {
            target: "Edge.CDN.test.".to_string(),
        };
        assert_eq!(cname.comparison_key(), "edge.cdn.test.");

        // Case-sensitive payloads are compared verbatim: a TXT token or a
        // base64 key that changes only in case IS a different value.
        let txt = |t: &str| RecordData::TXT {
            text: t.to_string(),
        };
        assert_ne!(
            txt("verify=AbC").comparison_key(),
            txt("verify=abc").comparison_key()
        );
        let key = |k: &str| RecordData::DNSKEY {
            flags: 257,
            protocol: 3,
            algorithm: 13,
            public_key: k.to_string(),
        };
        assert_ne!(
            key("mdsswUyr3DPW").comparison_key(),
            key("MDSSWUYR3DPW").comparison_key()
        );
    }

    fn svc(key: &str, value: &str) -> SvcParam {
        SvcParam {
            key: key.to_string(),
            value: value.to_string(),
        }
    }

    #[test]
    fn https_display_mirrors_dig() {
        let https = RecordData::HTTPS {
            priority: 1,
            target: ".".to_string(),
            params: vec![
                svc("alpn", "h3,h2"),
                svc("ipv4hint", "104.16.132.229,104.16.133.229"),
            ],
        };
        assert_eq!(
            https.to_string(),
            "1 . alpn=\"h3,h2\" ipv4hint=104.16.132.229,104.16.133.229"
        );

        // Valueless keys stand bare; other values are never quoted.
        let svcb = RecordData::SVCB {
            priority: 2,
            target: "svc.example.net.".to_string(),
            params: vec![svc("no-default-alpn", ""), svc("port", "8443")],
        };
        assert_eq!(
            svcb.to_string(),
            "2 svc.example.net. no-default-alpn port=8443"
        );

        // AliasMode: priority 0 and the alias target, nothing else.
        let alias = RecordData::HTTPS {
            priority: 0,
            target: "pool.example.net.".to_string(),
            params: vec![],
        };
        assert_eq!(alias.to_string(), "0 pool.example.net.");
    }

    #[test]
    fn child_dnssec_records_display_like_their_parents() {
        let cds = RecordData::CDS {
            key_tag: 2371,
            algorithm: 13,
            digest_type: 2,
            digest: "ABCDEF01".to_string(),
        };
        assert_eq!(cds.to_string(), "2371 13 2 ABCDEF01");
        let cdnskey = RecordData::CDNSKEY {
            flags: 257,
            protocol: 3,
            algorithm: 13,
            public_key: "mdsswUyr3DPW".to_string(),
        };
        assert_eq!(cdnskey.to_string(), "257 3 13 mdsswUyr3DPW");
        // RFC 8078 delete request.
        let delete = RecordData::CDNSKEY {
            flags: 0,
            protocol: 3,
            algorithm: 0,
            public_key: "AA==".to_string(),
        };
        assert_eq!(delete.to_string(), "0 3 0 AA==");
    }

    #[test]
    fn comparison_key_folds_the_service_target_only() {
        let https = |target: &str, alpn: &str| RecordData::HTTPS {
            priority: 1,
            target: target.to_string(),
            params: vec![svc("alpn", alpn)],
        };
        assert_eq!(
            https("Svc.Example.NET.", "h2").comparison_key(),
            https("svc.example.net.", "h2").comparison_key()
        );
        // Params are opaque data: compared verbatim.
        assert_ne!(
            https(".", "H2").comparison_key(),
            https(".", "h2").comparison_key()
        );
        let cds = |digest: &str| RecordData::CDS {
            key_tag: 1,
            algorithm: 13,
            digest_type: 2,
            digest: digest.to_string(),
        };
        assert_ne!(cds("ABCD").comparison_key(), cds("abcd").comparison_key());
    }

    #[test]
    fn https_serializes_with_structured_params() {
        let record = DnsRecord {
            name: "example.com".to_string(),
            record_type: RecordType::HTTPS,
            ttl: 300,
            data: RecordData::HTTPS {
                priority: 1,
                target: ".".to_string(),
                params: vec![svc("alpn", "h2")],
            },
        };
        let json = serde_json::to_value(&record).unwrap();
        assert_eq!(json["record_type"], "HTTPS");
        assert_eq!(json["data"]["record_type"], "HTTPS");
        assert_eq!(json["data"]["value"]["priority"], 1);
        assert_eq!(json["data"]["value"]["target"], ".");
        assert_eq!(
            json["data"]["value"]["params"],
            serde_json::json!([{"key": "alpn", "value": "h2"}])
        );
        let back: DnsRecord = serde_json::from_value(json).unwrap();
        assert_eq!(back, record);
    }

    #[test]
    fn new_record_types_parse_by_name() {
        for (name, expected) in [
            ("https", RecordType::HTTPS),
            ("SVCB", RecordType::SVCB),
            ("cds", RecordType::CDS),
            ("CDNSKEY", RecordType::CDNSKEY),
        ] {
            assert_eq!(name.parse::<RecordType>().unwrap(), expected);
        }
        // ANY stays last, after the new types.
        assert_eq!(RecordType::ALL.last(), Some(&RecordType::ANY));
    }

    /// Drift guard for the three surfaces that render `RecordType::ALL`
    /// (CLI help, REPL completion, MCP tool schema). Adding a variant breaks
    /// `as_str`'s exhaustive match at compile time; this pins the count so the
    /// author must also extend `ALL`/`ALL_NAMES` rather than only `as_str`.
    #[test]
    fn all_is_complete() {
        assert_eq!(
            RecordType::ALL.len(),
            20,
            "new RecordType variant — add it to ALL and ALL_NAMES too"
        );
        assert_eq!(RecordType::ALL.len(), RecordType::ALL_NAMES.len());
    }

    /// `ALL`, `ALL_NAMES`, `as_str`, and `FromStr` must agree entry-for-entry:
    /// a name a surface advertises has to be one `from_str` actually accepts.
    #[test]
    fn all_names_match_and_round_trip() {
        for (rt, name) in RecordType::ALL.iter().zip(RecordType::ALL_NAMES) {
            assert_eq!(&rt.as_str(), name, "ALL/ALL_NAMES out of order");
            assert_eq!(
                name.parse::<RecordType>().expect("advertised name parses"),
                *rt
            );
        }
    }
}
