use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::error::{Result, SeerError};

/// RDAP response for domain, IP, or ASN lookups.
/// Follows RFC 7483 (JSON Responses for RDAP).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RdapResponse {
    #[serde(default)]
    pub object_class_name: Option<String>,

    #[serde(default)]
    pub handle: Option<String>,

    #[serde(default)]
    pub ldh_name: Option<String>,

    #[serde(default)]
    pub unicode_name: Option<String>,

    #[serde(default)]
    pub status: Vec<String>,

    #[serde(default)]
    pub events: Vec<RdapEvent>,

    #[serde(default)]
    pub entities: Vec<RdapEntity>,

    #[serde(default)]
    pub nameservers: Vec<RdapNameserver>,

    #[serde(default)]
    pub secure_dns: Option<SecureDns>,

    #[serde(default)]
    pub links: Vec<RdapLink>,

    #[serde(default)]
    pub remarks: Vec<RdapRemark>,

    #[serde(default)]
    pub notices: Vec<RdapNotice>,

    #[serde(default)]
    pub port43: Option<String>,

    // IP-specific fields
    #[serde(default)]
    pub start_address: Option<String>,

    #[serde(default)]
    pub end_address: Option<String>,

    #[serde(default)]
    pub ip_version: Option<String>,

    #[serde(default)]
    pub name: Option<String>,

    #[serde(default)]
    #[serde(rename = "type")]
    pub network_type: Option<String>,

    #[serde(default)]
    pub country: Option<String>,

    #[serde(default)]
    pub parent_handle: Option<String>,

    // ASN-specific fields
    #[serde(default)]
    pub start_autnum: Option<u32>,

    #[serde(default)]
    pub end_autnum: Option<u32>,

    // Raw JSON for extended data
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// An event in the lifecycle of an RDAP object (registration, expiration, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RdapEvent {
    pub event_action: String,
    #[serde(default)]
    pub event_date: Option<String>,
    #[serde(default)]
    pub event_actor: Option<String>,
}

impl RdapEvent {
    pub fn parsed_date(&self) -> Option<DateTime<Utc>> {
        // RFC 9083 mandates strict RFC 3339, but registries are as sloppy
        // with RDAP dates as with WHOIS, so reuse the tolerant shared parser
        // instead of a bare `.parse()` that silently drops anything but
        // strict RFC 3339 (e.g. date-only or space-separated datetimes).
        crate::whois::parse_date(self.event_date.as_ref()?)
    }
}

/// An entity associated with an RDAP object (registrar, registrant, admin, tech contact).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RdapEntity {
    #[serde(default)]
    pub object_class_name: Option<String>,

    #[serde(default)]
    pub handle: Option<String>,

    #[serde(default)]
    pub roles: Vec<String>,

    #[serde(default)]
    pub public_ids: Vec<PublicId>,

    #[serde(default)]
    pub vcard_array: Option<serde_json::Value>,

    #[serde(default)]
    pub entities: Vec<RdapEntity>,

    #[serde(default)]
    pub remarks: Vec<RdapRemark>,

    #[serde(default)]
    pub links: Vec<RdapLink>,

    #[serde(default)]
    pub events: Vec<RdapEvent>,

    #[serde(default)]
    pub status: Vec<String>,
}

impl RdapEntity {
    pub fn get_name(&self) -> Option<String> {
        if let Some(vcard) = &self.vcard_array {
            if let Some(arr) = vcard.as_array() {
                if arr.len() > 1 {
                    if let Some(props) = arr[1].as_array() {
                        for prop in props {
                            if let Some(prop_arr) = prop.as_array() {
                                if prop_arr.len() >= 4 && prop_arr[0].as_str() == Some("fn") {
                                    return prop_arr[3].as_str().map(String::from);
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    pub fn get_organization(&self) -> Option<String> {
        if let Some(vcard) = &self.vcard_array {
            if let Some(arr) = vcard.as_array() {
                if arr.len() > 1 {
                    if let Some(props) = arr[1].as_array() {
                        for prop in props {
                            if let Some(prop_arr) = prop.as_array() {
                                if prop_arr.len() >= 4 && prop_arr[0].as_str() == Some("org") {
                                    // org value can be a string or array
                                    if let Some(org_str) = prop_arr[3].as_str() {
                                        return Some(org_str.to_string());
                                    } else if let Some(org_arr) = prop_arr[3].as_array() {
                                        // org is often ["Company Name", "Department"]
                                        if let Some(first) = org_arr.first() {
                                            if let Some(org_str) = first.as_str() {
                                                return Some(org_str.to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    pub fn get_email(&self) -> Option<String> {
        if let Some(vcard) = &self.vcard_array {
            if let Some(arr) = vcard.as_array() {
                if arr.len() > 1 {
                    if let Some(props) = arr[1].as_array() {
                        for prop in props {
                            if let Some(prop_arr) = prop.as_array() {
                                if prop_arr.len() >= 4 && prop_arr[0].as_str() == Some("email") {
                                    return prop_arr[3].as_str().map(String::from);
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    pub fn get_phone(&self) -> Option<String> {
        if let Some(vcard) = &self.vcard_array {
            if let Some(arr) = vcard.as_array() {
                if arr.len() > 1 {
                    if let Some(props) = arr[1].as_array() {
                        for prop in props {
                            if let Some(prop_arr) = prop.as_array() {
                                if prop_arr.len() >= 4 && prop_arr[0].as_str() == Some("tel") {
                                    if let Some(phone) = prop_arr[3].as_str() {
                                        return Some(phone.to_string());
                                    } else if let Some(phone_obj) = prop_arr[3].as_object() {
                                        // Sometimes phone is {"uri": "tel:+1234567890"}
                                        if let Some(uri) = phone_obj.get("uri") {
                                            if let Some(uri_str) = uri.as_str() {
                                                return Some(
                                                    uri_str.trim_start_matches("tel:").to_string(),
                                                );
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    pub fn get_address(&self) -> Option<String> {
        if let Some(vcard) = &self.vcard_array {
            if let Some(arr) = vcard.as_array() {
                if arr.len() > 1 {
                    if let Some(props) = arr[1].as_array() {
                        for prop in props {
                            if let Some(prop_arr) = prop.as_array() {
                                if prop_arr.len() >= 4 && prop_arr[0].as_str() == Some("adr") {
                                    // adr is usually an array: [pobox, ext, street, city, state, postal, country]
                                    if let Some(adr_arr) = prop_arr[3].as_array() {
                                        let parts: Vec<String> = adr_arr
                                            .iter()
                                            .filter_map(|v| v.as_str())
                                            .filter(|s| !s.is_empty())
                                            .map(String::from)
                                            .collect();
                                        if !parts.is_empty() {
                                            return Some(parts.join(", "));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    pub fn get_country(&self) -> Option<String> {
        if let Some(vcard) = &self.vcard_array {
            if let Some(arr) = vcard.as_array() {
                if arr.len() > 1 {
                    if let Some(props) = arr[1].as_array() {
                        for prop in props {
                            if let Some(prop_arr) = prop.as_array() {
                                // Check for country in adr field (index 6)
                                if prop_arr.len() >= 4 && prop_arr[0].as_str() == Some("adr") {
                                    if let Some(adr_arr) = prop_arr[3].as_array() {
                                        if let Some(country) = adr_arr.get(6) {
                                            if let Some(country_str) = country.as_str() {
                                                if !country_str.is_empty() {
                                                    return Some(country_str.to_string());
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }
}

/// A public identifier for an RDAP entity (e.g., IANA Registrar ID).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicId {
    #[serde(rename = "type")]
    pub id_type: String,
    pub identifier: String,
}

/// A nameserver associated with a domain in RDAP.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RdapNameserver {
    #[serde(default)]
    pub object_class_name: Option<String>,

    #[serde(default)]
    pub ldh_name: Option<String>,

    #[serde(default)]
    pub unicode_name: Option<String>,

    #[serde(default)]
    pub ip_addresses: Option<IpAddresses>,

    #[serde(default)]
    pub status: Vec<String>,

    #[serde(default)]
    pub links: Vec<RdapLink>,
}

/// IPv4 and IPv6 addresses associated with a nameserver.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpAddresses {
    #[serde(default)]
    pub v4: Vec<String>,
    #[serde(default)]
    pub v6: Vec<String>,
}

/// DNSSEC information for a domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecureDns {
    #[serde(default)]
    pub delegation_signed: Option<bool>,
    #[serde(default)]
    pub ds_data: Vec<DsData>,
    #[serde(default)]
    pub key_data: Vec<KeyData>,
}

/// DNSSEC DS (Delegation Signer) record data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsData {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: String,
}

/// DNSSEC key data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyData {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub public_key: String,
}

/// A link to related RDAP resources.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdapLink {
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub rel: Option<String>,
    #[serde(default)]
    pub href: Option<String>,
    #[serde(default)]
    #[serde(rename = "type")]
    pub media_type: Option<String>,
}

/// A remark or note attached to an RDAP object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdapRemark {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Vec<String>,
    #[serde(default)]
    pub links: Vec<RdapLink>,
}

/// A notice from the RDAP server (terms of service, rate limiting, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdapNotice {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Vec<String>,
    #[serde(default)]
    pub links: Vec<RdapLink>,
}

impl RdapResponse {
    /// Maximum number of keys permitted in `extra` (the serde-flatten
    /// catch-all map). Chosen to be well above legitimate RDAP responses
    /// (typical responses have <20 top-level keys; RFC 7483 defines ~25
    /// canonical fields) while still blocking pathological attacker payloads
    /// that pack the 10MB body cap full of distinct keys.
    const MAX_EXTRA_KEYS: usize = 1024;

    /// Maximum serialized size (in bytes) of the `extra` map. Bounds the
    /// total heap cost of attacker-controlled JSON values regardless of
    /// whether the attack is wide (many keys) or deep (nested arrays/
    /// objects). 512KB is far larger than any field we care about preserving
    /// for round-tripping, yet small enough to be a meaningful guardrail
    /// against the 10MB body-cap ceiling.
    const MAX_EXTRA_BYTES: usize = 512 * 1024;

    /// Maximum nesting depth for `RdapEntity.entities`. Real-world RDAP
    /// responses nest at most 2–3 levels (domain → registrar → abuse
    /// contact). 16 is comfortably above any legitimate response and
    /// small enough to keep recursive walks well clear of the Rust
    /// stack-overflow cliff — an adversarial RDAP payload could otherwise
    /// drive `get_registrar`/`get_entity_by_role` and future recursive
    /// walkers to a stack-overflow abort.
    const MAX_ENTITY_DEPTH: usize = 16;

    /// Recursively verifies that `entities` nesting stays within
    /// `MAX_ENTITY_DEPTH`. `depth` is the current walker depth, starting
    /// at 0 for the top-level `RdapResponse.entities` slice.
    ///
    /// Uses `>=` rather than `>` so that exactly `MAX_ENTITY_DEPTH` levels
    /// of entity nesting are accepted and `MAX_ENTITY_DEPTH + 1` are
    /// rejected — matching the documented intent of the constant.
    ///
    /// NOTE (#61): this only walks the *typed* `entities` tree. The
    /// `#[serde(flatten)] extra` map and `vcard_array` hold arbitrary
    /// `serde_json::Value`s whose nesting depth is bounded solely by
    /// serde_json's default 128-level recursion limit. That default is
    /// load-bearing here — do NOT call `serde_json`'s
    /// `disable_recursion_limit()` on the RDAP deserialization path, or deeply
    /// nested attacker JSON could exhaust the stack.
    fn walk_depth(entities: &[RdapEntity], depth: usize) -> Result<()> {
        if depth >= Self::MAX_ENTITY_DEPTH {
            return Err(SeerError::RdapError(format!(
                "RDAP entities exceed max nesting depth {}",
                Self::MAX_ENTITY_DEPTH
            )));
        }
        for e in entities {
            Self::walk_depth(&e.entities, depth + 1)?;
        }
        Ok(())
    }

    /// Bound attacker-controlled data in `extra` (the `#[serde(flatten)]`
    /// catch-all field) after deserialization.
    ///
    /// Even with the 10MB body cap applied during streaming, a malicious RDAP
    /// server can pack the body with millions of unknown keys or deeply-
    /// nested `serde_json::Value` trees, causing heap exhaustion in the
    /// resulting `serde_json::Map`. This guard rejects such responses before
    /// they propagate further into the application.
    pub fn validate_size(&self) -> Result<()> {
        if self.extra.len() > Self::MAX_EXTRA_KEYS {
            return Err(SeerError::RdapError(format!(
                "RDAP response has {} extra keys (max {})",
                self.extra.len(),
                Self::MAX_EXTRA_KEYS
            )));
        }
        let serialized = serde_json::to_vec(&self.extra)
            .map_err(|e| SeerError::RdapError(format!("serialize extra: {}", e)))?;
        if serialized.len() > Self::MAX_EXTRA_BYTES {
            return Err(SeerError::RdapError(format!(
                "RDAP extra payload {} bytes (max {})",
                serialized.len(),
                Self::MAX_EXTRA_BYTES
            )));
        }
        Ok(())
    }

    /// Full post-deserialization validation of a `RdapResponse`. Wraps
    /// the existing `validate_size` size/width check with a recursive
    /// entity-nesting depth check to prevent adversarial responses from
    /// driving recursion to a stack-overflow abort.
    pub fn validate(&self) -> Result<()> {
        self.validate_size()?;
        Self::walk_depth(&self.entities, 0)?;
        Ok(())
    }

    pub fn domain_name(&self) -> Option<&str> {
        self.ldh_name.as_deref().or(self.unicode_name.as_deref())
    }

    pub fn get_registrar(&self) -> Option<String> {
        for entity in &self.entities {
            if entity.roles.iter().any(|r| r == "registrar") {
                return entity.get_name().or_else(|| entity.handle.clone());
            }
        }
        None
    }

    pub fn get_registrant(&self) -> Option<String> {
        for entity in &self.entities {
            if entity.roles.iter().any(|r| r == "registrant") {
                return entity.get_name().or_else(|| entity.handle.clone());
            }
        }
        None
    }

    pub fn get_registrant_organization(&self) -> Option<String> {
        for entity in &self.entities {
            if entity.roles.iter().any(|r| r == "registrant") {
                if let Some(org) = entity.get_organization() {
                    // Filter out redacted values
                    let org_lower = org.to_lowercase();
                    if !org_lower.contains("redacted") && !org.is_empty() {
                        return Some(org);
                    }
                }
            }
        }
        None
    }

    pub fn creation_date(&self) -> Option<DateTime<Utc>> {
        self.events
            .iter()
            .find(|e| e.event_action == "registration")
            .and_then(|e| e.parsed_date())
    }

    pub fn expiration_date(&self) -> Option<DateTime<Utc>> {
        self.events
            .iter()
            .find(|e| e.event_action == "expiration")
            .and_then(|e| e.parsed_date())
    }

    pub fn last_updated(&self) -> Option<DateTime<Utc>> {
        self.events
            .iter()
            .find(|e| {
                e.event_action == "last changed" || e.event_action == "last update of RDAP database"
            })
            .and_then(|e| e.parsed_date())
    }

    pub fn nameserver_names(&self) -> Vec<String> {
        self.nameservers
            .iter()
            .filter_map(|ns| ns.ldh_name.clone().or_else(|| ns.unicode_name.clone()))
            .collect()
    }

    pub fn is_dnssec_signed(&self) -> bool {
        self.secure_dns
            .as_ref()
            .map(|s| s.delegation_signed.unwrap_or(false))
            .unwrap_or(false)
    }

    /// Returns an entity by its role.
    pub fn get_entity_by_role(&self, role: &str) -> Option<&RdapEntity> {
        self.entities
            .iter()
            .find(|e| e.roles.iter().any(|r| r == role))
    }

    /// Returns all contact information for a specific role.
    pub fn get_contact_info(&self, role: &str) -> Option<ContactInfo> {
        let entity = self.get_entity_by_role(role)?;
        Some(ContactInfo {
            name: entity.get_name(),
            organization: entity.get_organization(),
            email: entity.get_email(),
            phone: entity.get_phone(),
            address: entity.get_address(),
            country: entity.get_country(),
        })
    }

    pub fn get_admin_contact(&self) -> Option<ContactInfo> {
        self.get_contact_info("administrative")
    }

    pub fn get_tech_contact(&self) -> Option<ContactInfo> {
        self.get_contact_info("technical")
    }

    pub fn get_billing_contact(&self) -> Option<ContactInfo> {
        self.get_contact_info("billing")
    }

    pub fn get_registrant_contact(&self) -> Option<ContactInfo> {
        self.get_contact_info("registrant")
    }
}

/// Contact information extracted from RDAP entity.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ContactInfo {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

impl ContactInfo {
    /// Checks if the contact has any non-redacted information.
    ///
    /// Returns true only when at least one field carries genuine (present,
    /// non-empty, non-redacted) data. A per-field positive check is required:
    /// negating a redaction predicate is unsound because an absent (`None`)
    /// field is trivially "not redacted", which would let a contact whose only
    /// populated field is redacted still report as having info.
    pub fn has_info(&self) -> bool {
        let is_real = |s: &Option<String>| {
            s.as_ref().is_some_and(|v| {
                let lower = v.to_lowercase();
                !v.is_empty() && !lower.contains("redacted") && !lower.contains("data protected")
            })
        };

        is_real(&self.name)
            || is_real(&self.organization)
            || is_real(&self.email)
            || is_real(&self.phone)
            || is_real(&self.address)
            || is_real(&self.country)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn has_info_suppresses_redacted_only_contacts() {
        // A contact whose only populated field is redacted must NOT report as
        // having info — otherwise the formatter renders "REDACTED FOR PRIVACY".
        let redacted = ContactInfo {
            organization: Some("REDACTED FOR PRIVACY".to_string()),
            ..Default::default()
        };
        assert!(!redacted.has_info());

        // "Data Protected" is also treated as redacted.
        let protected = ContactInfo {
            name: Some("Data Protected".to_string()),
            ..Default::default()
        };
        assert!(!protected.has_info());

        // Empty-string field is not "info".
        let empty = ContactInfo {
            email: Some(String::new()),
            ..Default::default()
        };
        assert!(!empty.has_info());

        // Fully absent -> no info.
        assert!(!ContactInfo::default().has_info());

        // A genuine value -> has info, even if other fields are None/redacted.
        let real = ContactInfo {
            organization: Some("REDACTED FOR PRIVACY".to_string()),
            name: Some("Acme Corp".to_string()),
            ..Default::default()
        };
        assert!(real.has_info());
    }

    #[test]
    fn validate_size_accepts_normal_response() {
        let mut resp = RdapResponse::default();
        resp.extra.insert("notices".into(), Value::Array(vec![]));
        assert!(resp.validate_size().is_ok());
    }

    #[test]
    fn parsed_date_accepts_non_strict_rfc3339_forms() {
        // RFC 9083 mandates RFC 3339, but real registries emit looser forms.
        // parsed_date() must recover date-only and space-separated datetimes
        // (the shared WHOIS date parser already handles these) instead of
        // dropping the date and making the domain look date-less.
        use chrono::Datelike;
        let date_only = RdapEvent {
            event_action: "registration".to_string(),
            event_date: Some("2020-01-15".to_string()),
            event_actor: None,
        };
        let d = date_only.parsed_date().expect("date-only should parse");
        assert_eq!((d.year(), d.month(), d.day()), (2020, 1, 15));

        // Strict RFC 3339 must still work.
        let strict = RdapEvent {
            event_action: "registration".to_string(),
            event_date: Some("2020-01-15T10:30:00Z".to_string()),
            event_actor: None,
        };
        assert_eq!(strict.parsed_date().expect("rfc3339").year(), 2020);
    }

    #[test]
    fn validate_size_rejects_too_many_keys() {
        let mut resp = RdapResponse::default();
        for i in 0..=RdapResponse::MAX_EXTRA_KEYS {
            resp.extra.insert(format!("k{}", i), Value::Null);
        }
        let err = resp.validate_size().unwrap_err();
        assert!(err.to_string().contains("extra keys"));
    }

    #[test]
    fn validate_size_rejects_oversized_payload() {
        let mut resp = RdapResponse::default();
        // One giant value
        let big_str: String = "x".repeat(RdapResponse::MAX_EXTRA_BYTES + 1024);
        resp.extra.insert("blob".into(), Value::String(big_str));
        let err = resp.validate_size().unwrap_err();
        assert!(err.to_string().contains("bytes"));
    }

    /// Builds an `RdapEntity` chain `depth` levels deep. Each entity nests
    /// the next in its `entities` vec, terminating with an empty leaf.
    fn nested_entity(depth: usize) -> RdapEntity {
        let mut e = RdapEntity {
            object_class_name: Some("entity".to_string()),
            handle: None,
            roles: vec![],
            public_ids: vec![],
            vcard_array: None,
            entities: vec![],
            remarks: vec![],
            links: vec![],
            events: vec![],
            status: vec![],
        };
        if depth > 0 {
            e.entities.push(nested_entity(depth - 1));
        }
        e
    }

    #[test]
    fn validate_accepts_shallow_nesting() {
        // 3-deep chain: well within legitimate RDAP usage.
        let mut resp = RdapResponse::default();
        resp.entities.push(nested_entity(3));
        assert!(
            resp.validate().is_ok(),
            "legitimate shallow nesting must be accepted"
        );
    }

    #[test]
    fn validate_accepts_at_max_depth() {
        // The walker treats `depth >= MAX_ENTITY_DEPTH` as a violation, so
        // a chain whose empty leaf is reached at `depth = MAX - 1` is the
        // largest accepted form. `nested_entity(n)` produces a chain
        // whose empty leaf is reached at `depth = n + 1`, so the
        // largest-accepted input is `nested_entity(MAX_ENTITY_DEPTH - 2)`
        // — which yields a chain of exactly `MAX_ENTITY_DEPTH - 1` levels.
        let mut resp = RdapResponse::default();
        resp.entities
            .push(nested_entity(RdapResponse::MAX_ENTITY_DEPTH - 2));
        assert!(
            resp.validate().is_ok(),
            "nesting of MAX_ENTITY_DEPTH - 1 levels must be accepted"
        );
    }

    #[test]
    fn validate_rejects_at_max_depth() {
        // `nested_entity(MAX_ENTITY_DEPTH - 1)` terminates at walker
        // depth = MAX_ENTITY_DEPTH, which now trips the `>=` guard.
        // This matches the constant's documented limit: exactly
        // `MAX_ENTITY_DEPTH` levels of nesting are rejected.
        let mut resp = RdapResponse::default();
        resp.entities
            .push(nested_entity(RdapResponse::MAX_ENTITY_DEPTH - 1));
        let err = resp.validate().unwrap_err();
        assert!(err.to_string().contains("max nesting depth"));
    }

    #[test]
    fn validate_rejects_deeply_nested_entities() {
        // 20-deep chain: comfortably past the 16-level cap.
        let mut resp = RdapResponse::default();
        resp.entities.push(nested_entity(20));
        let err = resp.validate().unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("max nesting depth"),
            "expected depth error, got: {}",
            msg
        );
    }

    #[test]
    fn validate_also_enforces_size_constraints() {
        // validate() must still catch extra-key overflow the way
        // validate_size() does; this guards against future refactors that
        // skip the size leg.
        let mut resp = RdapResponse::default();
        for i in 0..=RdapResponse::MAX_EXTRA_KEYS {
            resp.extra.insert(format!("k{}", i), Value::Null);
        }
        let err = resp.validate().unwrap_err();
        assert!(err.to_string().contains("extra keys"));
    }
}
