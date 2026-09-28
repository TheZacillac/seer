//! Full DNS query results, as `dig` reports them.
//!
//! [`DnsStatus`] is the response code in dig's vocabulary (`NOERROR`,
//! `NXDOMAIN`, `SERVFAIL`, …). It is what separates "the name does not exist"
//! (NXDOMAIN) from "the name exists but has no records of this type"
//! (NOERROR with an empty answer, i.e. NODATA) — a distinction the
//! record-list API ([`crate::dns::DnsResolver::resolve`]) folds away.

use std::fmt;
use std::str::FromStr;

use hickory_resolver::proto::op::ResponseCode;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::SeerError;

/// A DNS response code, named as `dig` prints it.
///
/// Serializes as that name (`"NOERROR"`, `"NXDOMAIN"`, …). Codes without a
/// dedicated variant keep their numeric value in [`DnsStatus::Other`] and
/// render as their standard mnemonic (`FORMERR`, `NOTIMP`, `BADVERS`, …), or
/// `RCODE<n>` for an unassigned code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DnsStatus {
    /// `NOERROR`: the query succeeded. With no answers this is NODATA.
    NoError,
    /// `NXDOMAIN`: the name does not exist.
    NxDomain,
    /// `SERVFAIL`: the server could not answer (often a DNSSEC or upstream
    /// failure).
    ServFail,
    /// `REFUSED`: the server declined to answer.
    Refused,
    /// Any other response code, by its numeric value.
    Other(u16),
}

impl DnsStatus {
    /// Whether the query succeeded (`NOERROR`), with or without answers.
    pub fn is_success(self) -> bool {
        self == DnsStatus::NoError
    }

    /// The numeric response code.
    pub fn code(self) -> u16 {
        match self {
            DnsStatus::NoError => 0,
            DnsStatus::ServFail => 2,
            DnsStatus::NxDomain => 3,
            DnsStatus::Refused => 5,
            DnsStatus::Other(code) => code,
        }
    }

    /// Builds the status for a numeric response code.
    pub fn from_code(code: u16) -> Self {
        match code {
            0 => DnsStatus::NoError,
            2 => DnsStatus::ServFail,
            3 => DnsStatus::NxDomain,
            5 => DnsStatus::Refused,
            other => DnsStatus::Other(other),
        }
    }
}

/// Standard mnemonics for the codes without a dedicated variant (RFC 6895
/// registry). Code 16 is both BADVERS and BADSIG; like dig, report BADVERS.
const OTHER_MNEMONICS: &[(u16, &str)] = &[
    (1, "FORMERR"),
    (4, "NOTIMP"),
    (6, "YXDOMAIN"),
    (7, "YXRRSET"),
    (8, "NXRRSET"),
    (9, "NOTAUTH"),
    (10, "NOTZONE"),
    (16, "BADVERS"),
    (17, "BADKEY"),
    (18, "BADTIME"),
    (19, "BADMODE"),
    (20, "BADNAME"),
    (21, "BADALG"),
    (22, "BADTRUNC"),
    (23, "BADCOOKIE"),
];

impl fmt::Display for DnsStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DnsStatus::NoError => f.write_str("NOERROR"),
            DnsStatus::NxDomain => f.write_str("NXDOMAIN"),
            DnsStatus::ServFail => f.write_str("SERVFAIL"),
            DnsStatus::Refused => f.write_str("REFUSED"),
            DnsStatus::Other(code) => match OTHER_MNEMONICS.iter().find(|(c, _)| c == code) {
                Some((_, name)) => f.write_str(name),
                None => write!(f, "RCODE{code}"),
            },
        }
    }
}

impl FromStr for DnsStatus {
    type Err = SeerError;

    /// Parses the names [`Display`](fmt::Display) produces, case-insensitively.
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let upper = s.trim().to_ascii_uppercase();
        let status = match upper.as_str() {
            "NOERROR" => DnsStatus::NoError,
            "NXDOMAIN" => DnsStatus::NxDomain,
            "SERVFAIL" => DnsStatus::ServFail,
            "REFUSED" => DnsStatus::Refused,
            other => {
                if let Some((code, _)) = OTHER_MNEMONICS.iter().find(|(_, name)| *name == other) {
                    DnsStatus::Other(*code)
                } else if let Some(code) = other
                    .strip_prefix("RCODE")
                    .and_then(|n| n.parse::<u16>().ok())
                {
                    DnsStatus::from_code(code)
                } else {
                    return Err(SeerError::InvalidInput(format!("unknown DNS status: {s}")));
                }
            }
        };
        Ok(status)
    }
}

impl From<ResponseCode> for DnsStatus {
    fn from(code: ResponseCode) -> Self {
        DnsStatus::from_code(u16::from(code))
    }
}

impl Serialize for DnsStatus {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for DnsStatus {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_names_match_dig() {
        assert_eq!(DnsStatus::NoError.to_string(), "NOERROR");
        assert_eq!(DnsStatus::NxDomain.to_string(), "NXDOMAIN");
        assert_eq!(DnsStatus::ServFail.to_string(), "SERVFAIL");
        assert_eq!(DnsStatus::Refused.to_string(), "REFUSED");
        assert_eq!(DnsStatus::Other(1).to_string(), "FORMERR");
        assert_eq!(DnsStatus::Other(4).to_string(), "NOTIMP");
        assert_eq!(DnsStatus::Other(16).to_string(), "BADVERS");
        assert_eq!(DnsStatus::Other(3000).to_string(), "RCODE3000");
    }

    #[test]
    fn status_maps_every_hickory_code_by_value() {
        assert_eq!(DnsStatus::from(ResponseCode::NoError), DnsStatus::NoError);
        assert_eq!(DnsStatus::from(ResponseCode::NXDomain), DnsStatus::NxDomain);
        assert_eq!(DnsStatus::from(ResponseCode::ServFail), DnsStatus::ServFail);
        assert_eq!(DnsStatus::from(ResponseCode::Refused), DnsStatus::Refused);
        assert_eq!(DnsStatus::from(ResponseCode::NotImp), DnsStatus::Other(4));
        assert_eq!(
            DnsStatus::from(ResponseCode::Unknown(3000)),
            DnsStatus::Other(3000)
        );
    }

    #[test]
    fn status_round_trips_through_its_name() {
        for code in [0u16, 1, 2, 3, 4, 5, 6, 9, 16, 23, 3000] {
            let status = DnsStatus::from_code(code);
            assert_eq!(status.to_string().parse::<DnsStatus>().unwrap(), status);
            assert_eq!(status.code(), code);
        }
        assert_eq!(
            "nxdomain".parse::<DnsStatus>().unwrap(),
            DnsStatus::NxDomain
        );
        assert!("NOPE".parse::<DnsStatus>().is_err());
    }

    #[test]
    fn status_serializes_as_its_name() {
        assert_eq!(
            serde_json::to_string(&DnsStatus::NxDomain).unwrap(),
            "\"NXDOMAIN\""
        );
        assert_eq!(
            serde_json::from_str::<DnsStatus>("\"SERVFAIL\"").unwrap(),
            DnsStatus::ServFail
        );
    }
}
