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
#[serde(untagged)]
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
