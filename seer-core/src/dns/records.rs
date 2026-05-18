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
    TLSA,
    SSHFP,
    ANY,
}

impl fmt::Display for RecordType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RecordType::A => write!(f, "A"),
            RecordType::AAAA => write!(f, "AAAA"),
            RecordType::CNAME => write!(f, "CNAME"),
            RecordType::MX => write!(f, "MX"),
            RecordType::NS => write!(f, "NS"),
            RecordType::TXT => write!(f, "TXT"),
            RecordType::SOA => write!(f, "SOA"),
            RecordType::PTR => write!(f, "PTR"),
            RecordType::SRV => write!(f, "SRV"),
            RecordType::CAA => write!(f, "CAA"),
            RecordType::NAPTR => write!(f, "NAPTR"),
            RecordType::DNSKEY => write!(f, "DNSKEY"),
            RecordType::DS => write!(f, "DS"),
            RecordType::TLSA => write!(f, "TLSA"),
            RecordType::SSHFP => write!(f, "SSHFP"),
            RecordType::ANY => write!(f, "ANY"),
        }
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
            "TLSA" => Ok(RecordType::TLSA),
            "SSHFP" => Ok(RecordType::SSHFP),
            "ANY" | "*" => Ok(RecordType::ANY),
            _ => Err(SeerError::InvalidRecordType(s.to_string())),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    pub record_type: RecordType,
    pub ttl: u32,
    pub data: RecordData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
            RecordData::Unknown { raw } => write!(f, "{}", raw),
        }
    }
}

impl DnsRecord {
    pub fn format_short(&self) -> String {
        format!("{}", self.data)
    }

    pub fn format_full(&self) -> String {
        format!(
            "{}\t{}\tIN\t{}\t{}",
            self.name, self.ttl, self.record_type, self.data
        )
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
    fn test_dns_record_format_full() {
        let record = DnsRecord {
            name: "example.com".to_string(),
            record_type: RecordType::A,
            ttl: 300,
            data: RecordData::A {
                address: "1.2.3.4".to_string(),
            },
        };
        assert_eq!(record.format_full(), "example.com\t300\tIN\tA\t1.2.3.4");
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
}
