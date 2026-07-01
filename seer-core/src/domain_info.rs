use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::lookup::LookupResult;
use crate::rdap::RdapResponse;
use crate::whois::WhoisResponse;

/// Indicates which protocol sources contributed to a `DomainInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainInfoSource {
    /// Both RDAP and WHOIS data were available.
    Both,
    /// Only RDAP data was available.
    Rdap,
    /// Only WHOIS data was available.
    Whois,
    /// Neither protocol returned data; the domain may be available.
    Available,
}

impl std::fmt::Display for DomainInfoSource {
    /// Render the same lowercase form serde uses, so JSON output and any
    /// non-JSON sink (CSV, logs) carry identical strings.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            DomainInfoSource::Both => "both",
            DomainInfoSource::Rdap => "rdap",
            DomainInfoSource::Whois => "whois",
            DomainInfoSource::Available => "available",
        };
        f.write_str(s)
    }
}

/// Number of days before expiration at which a domain is flagged as
/// "expiring soon" by [`ExpiryStatus`]. Mirrors common registrar grace
/// windows and the watchlist's near-expiry alerting.
const EXPIRING_SOON_DAYS: i64 = 30;

/// A coarse lifecycle band for a domain's registration, derived from its
/// expiration date and EPP status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExpiryStatus {
    /// Registered and not near expiry.
    Active,
    /// Within [`EXPIRING_SOON_DAYS`] of the expiration date.
    ExpiringSoon,
    /// Past the expiration date (may still be recoverable — see `Redemption`).
    Expired,
    /// In the post-expiry redemption grace period (recoverable by the registrant).
    Redemption,
    /// Scheduled for deletion back to the available pool.
    PendingDelete,
}

impl std::fmt::Display for ExpiryStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ExpiryStatus::Active => "active",
            ExpiryStatus::ExpiringSoon => "expiring-soon",
            ExpiryStatus::Expired => "expired",
            ExpiryStatus::Redemption => "redemption",
            ExpiryStatus::PendingDelete => "pending-delete",
        };
        f.write_str(s)
    }
}

/// A decoded EPP/RDAP domain status code paired with a plain-English meaning.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusDescription {
    /// The status code as reported by the registry (e.g. `clientTransferProhibited`).
    pub code: String,
    /// A human-readable description of what the code means.
    pub description: String,
}

/// Normalizes an EPP or RDAP status token to a comparison key.
///
/// WHOIS reports EPP camelCase (`clientTransferProhibited`) while RDAP reports
/// space-separated lowercase (`client transfer prohibited`); both collapse to
/// the same key here so [`describe_epp_status`] and `derive_expiry_status`
/// handle either source. Any trailing ` (URL)` an RDAP server appends is
/// dropped because only alphanumerics survive the filter.
fn normalize_status_key(code: &str) -> String {
    code.chars()
        .take_while(|c| *c != '(')
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Decodes a domain status code (EPP or RDAP form) into a plain-English
/// description, or `None` if the code is unrecognized.
pub fn describe_epp_status(code: &str) -> Option<&'static str> {
    let desc = match normalize_status_key(code).as_str() {
        "ok" | "active" => "no restrictions (standard registered state)",
        "inactive" => "no nameservers delegated",
        "addperiod" => "recently registered (add grace period)",
        "autorenewperiod" => "recently auto-renewed (grace period)",
        "renewperiod" => "recently renewed (grace period)",
        "transferperiod" => "recently transferred (grace period)",
        "redemptionperiod" => "recently expired, recoverable (redemption period)",
        "pendingrestore" => "restore requested from redemption",
        "pendingcreate" => "creation requested, pending",
        "pendingdelete" => "scheduled for deletion",
        "pendingrenew" => "renewal requested, pending",
        "pendingtransfer" => "transfer requested, pending",
        "pendingupdate" => "update requested, pending",
        "clientdeleteprohibited" => "deletion locked (by registrar)",
        "clienthold" => "resolution suspended (by registrar)",
        "clientrenewprohibited" => "renewal locked (by registrar)",
        "clienttransferprohibited" => "transfer locked (by registrar)",
        "clientupdateprohibited" => "updates locked (by registrar)",
        "serverdeleteprohibited" => "deletion locked (by registry)",
        "serverhold" => "resolution suspended (by registry)",
        "serverrenewprohibited" => "renewal locked (by registry)",
        "servertransferprohibited" => "transfer locked (by registry)",
        "serverupdateprohibited" => "updates locked (by registry)",
        _ => return None,
    };
    Some(desc)
}

/// Derives a coarse [`ExpiryStatus`] band from the days-until-expiration and the
/// domain's status codes. Status codes take priority: a `pendingDelete` or
/// `redemptionPeriod` state describes the lifecycle better than the raw date.
fn derive_expiry_status(
    days_until_expiration: Option<i64>,
    status: &[String],
) -> Option<ExpiryStatus> {
    let has = |needle: &str| status.iter().any(|s| normalize_status_key(s) == needle);
    if has("pendingdelete") {
        return Some(ExpiryStatus::PendingDelete);
    }
    if has("redemptionperiod") {
        return Some(ExpiryStatus::Redemption);
    }
    let days = days_until_expiration?;
    Some(if days < 0 {
        ExpiryStatus::Expired
    } else if days <= EXPIRING_SOON_DAYS {
        ExpiryStatus::ExpiringSoon
    } else {
        ExpiryStatus::Active
    })
}

/// A flat, merged view of domain registration data from RDAP and WHOIS.
///
/// RDAP fields take priority when both sources are present; WHOIS fills gaps.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainInfo {
    pub domain: String,
    pub source: DomainInfoSource,

    // Registration
    pub registrar: Option<String>,
    pub registrant: Option<String>,
    pub organization: Option<String>,

    // Dates
    pub creation_date: Option<DateTime<Utc>>,
    pub expiration_date: Option<DateTime<Utc>>,
    pub updated_date: Option<DateTime<Utc>>,

    // DNS
    pub nameservers: Vec<String>,
    pub status: Vec<String>,
    pub dnssec: Option<String>,

    // Registrant contact
    pub registrant_email: Option<String>,
    pub registrant_phone: Option<String>,
    pub registrant_address: Option<String>,
    pub registrant_country: Option<String>,

    // Admin contact
    pub admin_name: Option<String>,
    pub admin_organization: Option<String>,
    pub admin_email: Option<String>,
    pub admin_phone: Option<String>,

    // Tech contact
    pub tech_name: Option<String>,
    pub tech_organization: Option<String>,
    pub tech_email: Option<String>,
    pub tech_phone: Option<String>,

    // Protocol metadata
    pub whois_server: Option<String>,
    pub rdap_url: Option<String>,

    // Registrar object detail (from the RDAP registrar entity)
    /// ICANN-required registrar abuse contact email (for takedown reports).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registrar_abuse_email: Option<String>,
    /// Registrar abuse contact phone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registrar_abuse_phone: Option<String>,
    /// IANA Registrar ID (uniquely identifies the registrar).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registrar_iana_id: Option<String>,
    /// Registrar URL (the `about` link on the registrar entity).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registrar_url: Option<String>,

    /// Availability verdict: `"available"` / `"likely_available"` / `"unknown"`
    /// when derived from a `LookupResult::Available`. `None` otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub availability_verdict: Option<String>,

    // --- Derived lifecycle fields (computed at construction) ---
    /// Days until the registration expires (negative if already past),
    /// computed from `expiration_date`. `None` when the date is unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days_until_expiration: Option<i64>,
    /// Age of the registration in days, computed from `creation_date`.
    /// `None` when the creation date is unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_age_days: Option<i64>,
    /// Coarse lifecycle band derived from the expiry date and status codes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiry_status: Option<ExpiryStatus>,
    /// Plain-English decodings of recognized `status` codes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub status_descriptions: Vec<StatusDescription>,
}

impl DomainInfo {
    /// Constructs a `DomainInfo` by merging optional RDAP and WHOIS data.
    ///
    /// For each field, RDAP is tried first; WHOIS fills any remaining gaps.
    /// For vector fields (nameservers, status), RDAP is used if non-empty, else WHOIS.
    pub fn from_sources(
        domain: &str,
        rdap: Option<&RdapResponse>,
        whois: Option<&WhoisResponse>,
    ) -> Self {
        let source = match (rdap.is_some(), whois.is_some()) {
            (true, true) => DomainInfoSource::Both,
            (true, false) => DomainInfoSource::Rdap,
            (false, true) => DomainInfoSource::Whois,
            (false, false) => DomainInfoSource::Available,
        };

        // Helper: try RDAP extraction first, then WHOIS field
        macro_rules! rdap_or_whois {
            ($rdap_expr:expr, $whois_field:ident) => {
                $rdap_expr.or_else(|| whois.and_then(|w| w.$whois_field.clone()))
            };
        }

        // --- Registration ---
        let registrar = rdap_or_whois!(rdap.and_then(|r| r.get_registrar()), registrar);
        let registrant = rdap_or_whois!(rdap.and_then(|r| r.get_registrant()), registrant);
        let organization = rdap_or_whois!(
            rdap.and_then(|r| r.get_registrant_organization()),
            organization
        );

        // --- Dates ---
        let creation_date = rdap
            .and_then(|r| r.creation_date())
            .or_else(|| whois.and_then(|w| w.creation_date));
        let expiration_date = rdap
            .and_then(|r| r.expiration_date())
            .or_else(|| whois.and_then(|w| w.expiration_date));
        let updated_date = rdap
            .and_then(|r| r.last_updated())
            .or_else(|| whois.and_then(|w| w.updated_date));

        // --- DNS (vec fields: RDAP if non-empty, else WHOIS) ---
        let rdap_ns = rdap.map(|r| r.nameserver_names()).unwrap_or_default();
        let nameservers = if !rdap_ns.is_empty() {
            rdap_ns
        } else {
            whois.map(|w| w.nameservers.clone()).unwrap_or_default()
        };

        let rdap_status = rdap.map(|r| r.status.clone()).unwrap_or_default();
        let status = if !rdap_status.is_empty() {
            rdap_status
        } else {
            whois.map(|w| w.status.clone()).unwrap_or_default()
        };

        // DNSSEC: RDAP secure_dns.delegation_signed -> "signed"/"unsigned", else WHOIS
        let dnssec = rdap
            .and_then(|r| r.secure_dns.as_ref())
            .and_then(|sd| sd.delegation_signed)
            .map(|signed| {
                if signed {
                    "signed".to_string()
                } else {
                    "unsigned".to_string()
                }
            })
            .or_else(|| whois.and_then(|w| w.dnssec.clone()));

        // --- Registrant contact ---
        let rdap_registrant_contact = rdap.and_then(|r| r.get_registrant_contact());
        let registrant_email = rdap_registrant_contact
            .as_ref()
            .and_then(|c| c.email.clone())
            .or_else(|| whois.and_then(|w| w.registrant_email.clone()));
        let registrant_phone = rdap_registrant_contact
            .as_ref()
            .and_then(|c| c.phone.clone())
            .or_else(|| whois.and_then(|w| w.registrant_phone.clone()));
        let registrant_address = rdap_registrant_contact
            .as_ref()
            .and_then(|c| c.address.clone())
            .or_else(|| whois.and_then(|w| w.registrant_address.clone()));
        let registrant_country = rdap_registrant_contact
            .as_ref()
            .and_then(|c| c.country.clone())
            .or_else(|| whois.and_then(|w| w.registrant_country.clone()));

        // --- Admin contact ---
        let rdap_admin_contact = rdap.and_then(|r| r.get_admin_contact());
        let admin_name = rdap_admin_contact
            .as_ref()
            .and_then(|c| c.name.clone())
            .or_else(|| whois.and_then(|w| w.admin_name.clone()));
        let admin_organization = rdap_admin_contact
            .as_ref()
            .and_then(|c| c.organization.clone())
            .or_else(|| whois.and_then(|w| w.admin_organization.clone()));
        let admin_email = rdap_admin_contact
            .as_ref()
            .and_then(|c| c.email.clone())
            .or_else(|| whois.and_then(|w| w.admin_email.clone()));
        let admin_phone = rdap_admin_contact
            .as_ref()
            .and_then(|c| c.phone.clone())
            .or_else(|| whois.and_then(|w| w.admin_phone.clone()));

        // --- Tech contact ---
        let rdap_tech_contact = rdap.and_then(|r| r.get_tech_contact());
        let tech_name = rdap_tech_contact
            .as_ref()
            .and_then(|c| c.name.clone())
            .or_else(|| whois.and_then(|w| w.tech_name.clone()));
        let tech_organization = rdap_tech_contact
            .as_ref()
            .and_then(|c| c.organization.clone())
            .or_else(|| whois.and_then(|w| w.tech_organization.clone()));
        let tech_email = rdap_tech_contact
            .as_ref()
            .and_then(|c| c.email.clone())
            .or_else(|| whois.and_then(|w| w.tech_email.clone()));
        let tech_phone = rdap_tech_contact
            .as_ref()
            .and_then(|c| c.phone.clone())
            .or_else(|| whois.and_then(|w| w.tech_phone.clone()));

        // --- Protocol metadata ---
        let rdap_url = rdap.and_then(|r| {
            r.links
                .iter()
                .find(|l| l.rel.as_deref() == Some("self"))
                .and_then(|l| l.href.clone())
        });

        let whois_server = whois
            .map(|w| w.whois_server.clone())
            .filter(|s| !s.is_empty());

        // Registrar object detail is RDAP-only structured data (abuse contact,
        // IANA ID, URL). WHOIS carries no equivalently structured fields.
        let registrar_detail = rdap.and_then(|r| r.get_registrar_detail());
        let registrar_abuse_email = registrar_detail
            .as_ref()
            .and_then(|d| d.abuse_email.clone());
        let registrar_abuse_phone = registrar_detail
            .as_ref()
            .and_then(|d| d.abuse_phone.clone());
        let registrar_iana_id = registrar_detail.as_ref().and_then(|d| d.iana_id.clone());
        let registrar_url = registrar_detail.as_ref().and_then(|d| d.url.clone());

        let mut info = DomainInfo {
            domain: domain.to_string(),
            source,
            registrar,
            registrant,
            organization,
            creation_date,
            expiration_date,
            updated_date,
            nameservers,
            status,
            dnssec,
            registrant_email,
            registrant_phone,
            registrant_address,
            registrant_country,
            admin_name,
            admin_organization,
            admin_email,
            admin_phone,
            tech_name,
            tech_organization,
            tech_email,
            tech_phone,
            whois_server,
            rdap_url,
            registrar_abuse_email,
            registrar_abuse_phone,
            registrar_iana_id,
            registrar_url,
            availability_verdict: None,
            days_until_expiration: None,
            domain_age_days: None,
            expiry_status: None,
            status_descriptions: Vec::new(),
        };
        info.compute_lifecycle(Utc::now());
        info
    }

    /// Populates the computed lifecycle fields (`days_until_expiration`,
    /// `domain_age_days`, `expiry_status`, `status_descriptions`) relative to
    /// `now`. Pure given `now`, so it is unit-testable with a fixed clock.
    fn compute_lifecycle(&mut self, now: DateTime<Utc>) {
        self.days_until_expiration = self.expiration_date.map(|e| (e - now).num_days());
        self.domain_age_days = self.creation_date.map(|c| (now - c).num_days());
        self.expiry_status = derive_expiry_status(self.days_until_expiration, &self.status);
        self.status_descriptions = self
            .status
            .iter()
            .filter_map(|code| {
                describe_epp_status(code).map(|d| StatusDescription {
                    code: code.clone(),
                    description: d.to_string(),
                })
            })
            .collect();
    }

    /// Constructs a `DomainInfo` from a `LookupResult`, extracting RDAP and WHOIS
    /// data from whatever variant is present.
    pub fn from_lookup_result(result: &LookupResult) -> Self {
        match result {
            LookupResult::Rdap {
                data,
                whois_fallback,
            } => Self::from_sources(
                data.domain_name().unwrap_or("unknown"),
                Some(data),
                whois_fallback.as_ref(),
            ),
            LookupResult::Whois {
                data,
                rdap_fallback,
                ..
            } => Self::from_sources(
                &data.domain,
                rdap_fallback.as_ref().map(|b| b.as_ref()),
                Some(data),
            ),
            LookupResult::Available { data, .. } => {
                let mut info = Self::from_sources(&data.domain, None, None);
                info.source = DomainInfoSource::Available;
                info.availability_verdict = Some(data.verdict().to_string());
                info
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a test RdapResponse with registrar entity, events, nameserver,
    /// secure_dns, and a self link via JSON deserialization.
    fn make_test_rdap() -> RdapResponse {
        serde_json::from_value(serde_json::json!({
            "objectClassName": "domain",
            "ldhName": "example.com",
            "status": ["active"],
            "events": [
                {
                    "eventAction": "registration",
                    "eventDate": "2020-01-15T00:00:00Z"
                },
                {
                    "eventAction": "expiration",
                    "eventDate": "2025-01-15T00:00:00Z"
                },
                {
                    "eventAction": "last changed",
                    "eventDate": "2024-06-01T12:00:00Z"
                }
            ],
            "entities": [
                {
                    "objectClassName": "entity",
                    "roles": ["registrar"],
                    "vcardArray": [
                        "vcard",
                        [
                            ["version", {}, "text", "4.0"],
                            ["fn", {}, "text", "RDAP Registrar LLC"]
                        ]
                    ]
                }
            ],
            "nameservers": [
                {
                    "objectClassName": "nameserver",
                    "ldhName": "ns1.rdap-example.com"
                }
            ],
            "secureDns": {
                "delegationSigned": true,
                "dsData": [],
                "keyData": []
            },
            "links": [
                {
                    "rel": "self",
                    "href": "https://rdap.example.com/domain/example.com"
                }
            ]
        }))
        .expect("test RDAP JSON should deserialize")
    }

    /// Build a test WhoisResponse with all fields populated.
    fn make_test_whois() -> WhoisResponse {
        use chrono::TimeZone;
        WhoisResponse {
            domain: "example.com".to_string(),
            registrar: Some("WHOIS Registrar Inc.".to_string()),
            registrant: Some("John Doe".to_string()),
            organization: Some("Example Corp".to_string()),
            registrant_email: Some("john@example.com".to_string()),
            registrant_phone: Some("+1.5551234567".to_string()),
            registrant_address: Some("123 Main St".to_string()),
            registrant_country: Some("US".to_string()),
            admin_name: Some("Admin Person".to_string()),
            admin_organization: Some("Admin Org".to_string()),
            admin_email: Some("admin@example.com".to_string()),
            admin_phone: Some("+1.5559876543".to_string()),
            tech_name: Some("Tech Person".to_string()),
            tech_organization: Some("Tech Org".to_string()),
            tech_email: Some("tech@example.com".to_string()),
            tech_phone: Some("+1.5555555555".to_string()),
            creation_date: Some(Utc.with_ymd_and_hms(2019, 6, 1, 0, 0, 0).unwrap()),
            expiration_date: Some(Utc.with_ymd_and_hms(2024, 6, 1, 0, 0, 0).unwrap()),
            updated_date: Some(Utc.with_ymd_and_hms(2023, 12, 15, 0, 0, 0).unwrap()),
            nameservers: vec![
                "ns1.whois-example.com".to_string(),
                "ns2.whois-example.com".to_string(),
            ],
            status: vec!["clientTransferProhibited".to_string()],
            dnssec: Some("signedDelegation".to_string()),
            whois_server: "whois.example.com".to_string(),
            raw_response: "raw whois data".to_string(),
        }
    }

    #[test]
    fn test_from_sources_both() {
        let rdap = make_test_rdap();
        let whois = make_test_whois();
        let info = DomainInfo::from_sources("example.com", Some(&rdap), Some(&whois));

        assert_eq!(info.source, DomainInfoSource::Both);
        assert_eq!(info.domain, "example.com");

        // RDAP takes priority for registrar
        assert_eq!(info.registrar.as_deref(), Some("RDAP Registrar LLC"));

        // RDAP has no registrant entity, so WHOIS fills in
        assert_eq!(info.registrant.as_deref(), Some("John Doe"));
        assert_eq!(info.organization.as_deref(), Some("Example Corp"));

        // RDAP dates take priority
        assert!(info.creation_date.is_some());
        assert_eq!(
            info.creation_date.unwrap().to_rfc3339(),
            "2020-01-15T00:00:00+00:00"
        );
        assert_eq!(
            info.expiration_date.unwrap().to_rfc3339(),
            "2025-01-15T00:00:00+00:00"
        );
        assert_eq!(
            info.updated_date.unwrap().to_rfc3339(),
            "2024-06-01T12:00:00+00:00"
        );

        // RDAP nameservers non-empty, so used
        assert_eq!(info.nameservers, vec!["ns1.rdap-example.com"]);

        // RDAP status non-empty, so used
        assert_eq!(info.status, vec!["active"]);

        // DNSSEC from RDAP secure_dns
        assert_eq!(info.dnssec.as_deref(), Some("signed"));

        // Contacts: RDAP has no registrant/admin/tech contact entities, so WHOIS fills
        assert_eq!(info.registrant_email.as_deref(), Some("john@example.com"));
        assert_eq!(info.registrant_phone.as_deref(), Some("+1.5551234567"));
        assert_eq!(info.registrant_address.as_deref(), Some("123 Main St"));
        assert_eq!(info.registrant_country.as_deref(), Some("US"));
        assert_eq!(info.admin_name.as_deref(), Some("Admin Person"));
        assert_eq!(info.admin_organization.as_deref(), Some("Admin Org"));
        assert_eq!(info.admin_email.as_deref(), Some("admin@example.com"));
        assert_eq!(info.admin_phone.as_deref(), Some("+1.5559876543"));
        assert_eq!(info.tech_name.as_deref(), Some("Tech Person"));
        assert_eq!(info.tech_organization.as_deref(), Some("Tech Org"));
        assert_eq!(info.tech_email.as_deref(), Some("tech@example.com"));
        assert_eq!(info.tech_phone.as_deref(), Some("+1.5555555555"));

        // Protocol metadata
        assert_eq!(info.whois_server.as_deref(), Some("whois.example.com"));
        assert_eq!(
            info.rdap_url.as_deref(),
            Some("https://rdap.example.com/domain/example.com")
        );
    }

    #[test]
    fn test_from_sources_whois_only() {
        let whois = make_test_whois();
        let info = DomainInfo::from_sources("example.com", None, Some(&whois));

        assert_eq!(info.source, DomainInfoSource::Whois);
        assert_eq!(info.registrar.as_deref(), Some("WHOIS Registrar Inc."));
        assert_eq!(info.registrant.as_deref(), Some("John Doe"));
        assert_eq!(info.organization.as_deref(), Some("Example Corp"));
        assert_eq!(
            info.creation_date.unwrap().to_rfc3339(),
            "2019-06-01T00:00:00+00:00"
        );
        assert_eq!(
            info.expiration_date.unwrap().to_rfc3339(),
            "2024-06-01T00:00:00+00:00"
        );
        assert_eq!(
            info.updated_date.unwrap().to_rfc3339(),
            "2023-12-15T00:00:00+00:00"
        );
        assert_eq!(
            info.nameservers,
            vec!["ns1.whois-example.com", "ns2.whois-example.com"]
        );
        assert_eq!(info.status, vec!["clientTransferProhibited"]);
        assert_eq!(info.dnssec.as_deref(), Some("signedDelegation"));
        assert_eq!(info.registrant_email.as_deref(), Some("john@example.com"));
        assert_eq!(info.admin_name.as_deref(), Some("Admin Person"));
        assert_eq!(info.tech_email.as_deref(), Some("tech@example.com"));
        assert_eq!(info.whois_server.as_deref(), Some("whois.example.com"));
        assert!(info.rdap_url.is_none());
    }

    #[test]
    fn test_from_sources_rdap_only() {
        let rdap = make_test_rdap();
        let info = DomainInfo::from_sources("example.com", Some(&rdap), None);

        assert_eq!(info.source, DomainInfoSource::Rdap);
        assert_eq!(info.registrar.as_deref(), Some("RDAP Registrar LLC"));
        // No registrant entity in our test RDAP, no WHOIS to fall back to
        assert!(info.registrant.is_none());
        assert!(info.organization.is_none());
        assert!(info.creation_date.is_some());
        assert!(info.expiration_date.is_some());
        assert!(info.updated_date.is_some());
        assert_eq!(info.nameservers, vec!["ns1.rdap-example.com"]);
        assert_eq!(info.status, vec!["active"]);
        assert_eq!(info.dnssec.as_deref(), Some("signed"));
        // No contact entities in RDAP test data
        assert!(info.registrant_email.is_none());
        assert!(info.admin_name.is_none());
        assert!(info.tech_email.is_none());
        assert!(info.whois_server.is_none());
        assert_eq!(
            info.rdap_url.as_deref(),
            Some("https://rdap.example.com/domain/example.com")
        );
    }

    #[test]
    fn test_from_sources_neither() {
        let info = DomainInfo::from_sources("available.com", None, None);

        assert_eq!(info.source, DomainInfoSource::Available);
        assert_eq!(info.domain, "available.com");
        assert!(info.registrar.is_none());
        assert!(info.registrant.is_none());
        assert!(info.organization.is_none());
        assert!(info.creation_date.is_none());
        assert!(info.expiration_date.is_none());
        assert!(info.updated_date.is_none());
        assert!(info.nameservers.is_empty());
        assert!(info.status.is_empty());
        assert!(info.dnssec.is_none());
        assert!(info.registrant_email.is_none());
        assert!(info.admin_name.is_none());
        assert!(info.tech_email.is_none());
        assert!(info.whois_server.is_none());
        assert!(info.rdap_url.is_none());
    }

    #[test]
    fn test_from_lookup_result_rdap_variant() {
        let rdap = make_test_rdap();
        let whois = make_test_whois();
        let result = LookupResult::Rdap {
            data: Box::new(rdap),
            whois_fallback: Some(whois),
        };

        let info = DomainInfo::from_lookup_result(&result);
        assert_eq!(info.source, DomainInfoSource::Both);
        assert_eq!(info.domain, "example.com");
        assert_eq!(info.registrar.as_deref(), Some("RDAP Registrar LLC"));
        // WHOIS fills gaps
        assert_eq!(info.registrant.as_deref(), Some("John Doe"));
    }

    #[test]
    fn test_from_lookup_result_whois_variant() {
        let whois = make_test_whois();
        let result = LookupResult::Whois {
            data: whois,
            rdap_error: Some("RDAP failed".to_string()),
            rdap_fallback: None,
        };

        let info = DomainInfo::from_lookup_result(&result);
        assert_eq!(info.source, DomainInfoSource::Whois);
        assert_eq!(info.domain, "example.com");
        assert_eq!(info.registrar.as_deref(), Some("WHOIS Registrar Inc."));
        assert!(info.rdap_url.is_none());
    }

    #[test]
    fn from_sources_populates_registrar_detail() {
        let rdap: RdapResponse = serde_json::from_value(serde_json::json!({
            "objectClassName": "domain",
            "ldhName": "example.com",
            "entities": [{
                "objectClassName": "entity",
                "roles": ["registrar"],
                "publicIds": [{"type": "IANA Registrar ID", "identifier": "292"}],
                "links": [{"rel": "about", "href": "https://registrar.example"}],
                "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
                "entities": [{
                    "objectClassName": "entity",
                    "roles": ["abuse"],
                    "vcardArray": ["vcard", [
                        ["email", {}, "text", "abuse@registrar.example"],
                        ["tel", {}, "text", "+1.5551230000"]
                    ]]
                }]
            }]
        }))
        .unwrap();
        let info = DomainInfo::from_sources("example.com", Some(&rdap), None);
        assert_eq!(info.registrar_iana_id.as_deref(), Some("292"));
        assert_eq!(
            info.registrar_url.as_deref(),
            Some("https://registrar.example")
        );
        assert_eq!(
            info.registrar_abuse_email.as_deref(),
            Some("abuse@registrar.example")
        );
        assert_eq!(info.registrar_abuse_phone.as_deref(), Some("+1.5551230000"));
    }

    #[test]
    fn describe_epp_status_decodes_known_codes() {
        assert_eq!(
            describe_epp_status("clientTransferProhibited"),
            Some("transfer locked (by registrar)")
        );
        // RDAP space-separated form maps to the same description.
        assert_eq!(
            describe_epp_status("client transfer prohibited"),
            Some("transfer locked (by registrar)")
        );
        assert_eq!(
            describe_epp_status("serverHold"),
            Some("resolution suspended (by registry)")
        );
        assert_eq!(
            describe_epp_status("redemptionPeriod"),
            Some("recently expired, recoverable (redemption period)")
        );
        // A trailing RDAP URL annotation is ignored.
        assert_eq!(
            describe_epp_status("client hold (https://example.com/info)"),
            Some("resolution suspended (by registrar)")
        );
        assert_eq!(describe_epp_status("totally unknown code"), None);
    }

    #[test]
    fn derive_expiry_status_bands_by_days_and_codes() {
        // Status codes win over the date math.
        assert_eq!(
            derive_expiry_status(Some(200), &["pendingDelete".into()]),
            Some(ExpiryStatus::PendingDelete)
        );
        assert_eq!(
            derive_expiry_status(Some(200), &["redemptionPeriod".into()]),
            Some(ExpiryStatus::Redemption)
        );
        // Date bands.
        assert_eq!(
            derive_expiry_status(Some(365), &[]),
            Some(ExpiryStatus::Active)
        );
        assert_eq!(
            derive_expiry_status(Some(30), &[]),
            Some(ExpiryStatus::ExpiringSoon)
        );
        assert_eq!(
            derive_expiry_status(Some(0), &[]),
            Some(ExpiryStatus::ExpiringSoon)
        );
        assert_eq!(
            derive_expiry_status(Some(-5), &[]),
            Some(ExpiryStatus::Expired)
        );
        // Unknown date with no informative codes → None.
        assert_eq!(derive_expiry_status(None, &["ok".into()]), None);
    }

    #[test]
    fn compute_lifecycle_uses_fixed_clock() {
        use chrono::TimeZone;
        // make_test_whois: creation 2019-06-01, expiration 2024-06-01,
        // status clientTransferProhibited.
        let whois = make_test_whois();
        let mut info = DomainInfo::from_sources("example.com", None, Some(&whois));
        let now = Utc.with_ymd_and_hms(2024, 1, 1, 0, 0, 0).unwrap();
        info.compute_lifecycle(now);

        let expected_days = (Utc.with_ymd_and_hms(2024, 6, 1, 0, 0, 0).unwrap() - now).num_days();
        assert_eq!(info.days_until_expiration, Some(expected_days));
        assert!(info.days_until_expiration.unwrap() > 0);
        assert!(info.domain_age_days.unwrap() > 0);
        // ~152 days out (>30) → Active.
        assert_eq!(info.expiry_status, Some(ExpiryStatus::Active));
        // clientTransferProhibited is decoded.
        assert_eq!(info.status_descriptions.len(), 1);
        assert_eq!(info.status_descriptions[0].code, "clientTransferProhibited");
        assert_eq!(
            info.status_descriptions[0].description,
            "transfer locked (by registrar)"
        );
    }

    #[test]
    fn test_serialization_round_trip() {
        let rdap = make_test_rdap();
        let whois = make_test_whois();
        let info = DomainInfo::from_sources("example.com", Some(&rdap), Some(&whois));

        let json = serde_json::to_string_pretty(&info).expect("serialize");
        let deserialized: DomainInfo = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.domain, info.domain);
        assert_eq!(deserialized.source, info.source);
        assert_eq!(deserialized.registrar, info.registrar);
        assert_eq!(deserialized.registrant, info.registrant);
        assert_eq!(deserialized.organization, info.organization);
        assert_eq!(deserialized.creation_date, info.creation_date);
        assert_eq!(deserialized.expiration_date, info.expiration_date);
        assert_eq!(deserialized.updated_date, info.updated_date);
        assert_eq!(deserialized.nameservers, info.nameservers);
        assert_eq!(deserialized.status, info.status);
        assert_eq!(deserialized.dnssec, info.dnssec);
        assert_eq!(deserialized.registrant_email, info.registrant_email);
        assert_eq!(deserialized.admin_name, info.admin_name);
        assert_eq!(deserialized.tech_email, info.tech_email);
        assert_eq!(deserialized.whois_server, info.whois_server);
        assert_eq!(deserialized.rdap_url, info.rdap_url);

        // Verify source serializes as lowercase
        assert!(json.contains("\"source\": \"both\""));
    }
}
