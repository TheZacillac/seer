use chrono::{DateTime, Utc};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::error::{Result, SeerError};

/// Deserializes an optional member leniently: a value that doesn't fit `T`
/// yields `None` instead of failing the whole RDAP response. Registries are
/// sloppy with the less-used members (`secureDNS`, nameserver glue, …), and
/// one malformed sub-object must not cost the registrar/dates/status that
/// parsed fine.
fn lenient_option<'de, D, T>(deserializer: D) -> std::result::Result<Option<T>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    let value = Value::deserialize(deserializer)?;
    Ok(serde_json::from_value(value).ok())
}

/// Deserializes a JSON array element by element, dropping elements that
/// don't fit `T` (and treating a non-array as empty) rather than failing the
/// whole response.
fn lenient_vec<'de, D, T>(deserializer: D) -> std::result::Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: DeserializeOwned,
{
    Ok(match Value::deserialize(deserializer)? {
        Value::Array(items) => items
            .into_iter()
            .filter_map(|item| serde_json::from_value(item).ok())
            .collect(),
        _ => Vec::new(),
    })
}

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

    /// DNSSEC delegation data. RFC 9083 spells the member `secureDNS` (all
    /// caps "DNS"), which the struct-wide camelCase rule would have mapped to
    /// `secureDns` — a key no real server sends, so DNSSEC state silently
    /// never parsed. Renamed explicitly; the camelCase spelling is still
    /// accepted as an alias. Lenient: a malformed object yields `None`.
    #[serde(
        rename = "secureDNS",
        alias = "secureDns",
        default,
        deserialize_with = "lenient_option"
    )]
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
    pub extra: serde_json::Map<String, Value>,
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
    pub vcard_array: Option<Value>,

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

/// Trims `s`, returning `None` when nothing is left. Redacted jCard values
/// are commonly empty strings (`["fn", {}, "text", ""]`); treating them as
/// absent lets callers fall back to the handle or to WHOIS instead of
/// rendering a blank field.
fn non_empty_text(s: &str) -> Option<String> {
    let t = s.trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// Strips a leading (case-insensitive) `tel:` URI scheme from a phone value.
fn strip_tel_scheme(s: &str) -> &str {
    let t = s.trim();
    match t.get(..4) {
        Some(scheme) if scheme.eq_ignore_ascii_case("tel:") => t.get(4..).unwrap_or(""),
        _ => t,
    }
}

/// Collects the non-empty text of one structured jCard component, which is
/// either a string or (for multi-valued components such as a multi-line
/// street) an array of strings.
fn push_component_text(component: &Value, out: &mut Vec<String>) {
    match component {
        Value::String(s) => out.extend(non_empty_text(s)),
        Value::Array(items) => out.extend(
            items
                .iter()
                .filter_map(Value::as_str)
                .filter_map(non_empty_text),
        ),
        _ => {}
    }
}

impl RdapEntity {
    /// Iterates this entity's jCard properties named `name`
    /// (`[name, params, type, value, ...]`), skipping malformed entries.
    fn vcard_props<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a [Value]> + 'a {
        self.vcard_array
            .as_ref()
            .and_then(Value::as_array)
            .and_then(|arr| arr.get(1))
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_array)
            .filter(move |prop| prop.len() >= 4 && prop[0].as_str() == Some(name))
            .map(Vec::as_slice)
    }

    /// The entity handle, unless it is blank.
    fn non_empty_handle(&self) -> Option<String> {
        self.handle.as_deref().and_then(non_empty_text)
    }

    /// Display name (`fn`). A redacted, empty `fn` reads as absent.
    pub fn get_name(&self) -> Option<String> {
        self.vcard_props("fn")
            .find_map(|prop| prop[3].as_str().and_then(non_empty_text))
    }

    pub fn get_organization(&self) -> Option<String> {
        self.vcard_props("org").find_map(|prop| match &prop[3] {
            Value::String(s) => non_empty_text(s),
            // org is often ["Company Name", "Department"]
            Value::Array(parts) => parts
                .first()
                .and_then(Value::as_str)
                .and_then(non_empty_text),
            _ => None,
        })
    }

    pub fn get_email(&self) -> Option<String> {
        self.vcard_props("email")
            .find_map(|prop| prop[3].as_str().and_then(non_empty_text))
    }

    /// Phone number, with any `tel:` URI scheme removed — the common
    /// `["tel", {...}, "uri", "tel:+1.2083895740"]` form must render as the
    /// bare number, same as the `text` form.
    pub fn get_phone(&self) -> Option<String> {
        self.vcard_props("tel").find_map(|prop| match &prop[3] {
            Value::String(s) => non_empty_text(strip_tel_scheme(s)),
            // Sometimes phone is {"uri": "tel:+1234567890"}
            Value::Object(obj) => obj
                .get("uri")
                .and_then(Value::as_str)
                .and_then(|uri| non_empty_text(strip_tel_scheme(uri))),
            _ => None,
        })
    }

    /// Postal address as one comma-joined line. Components may themselves be
    /// arrays (a multi-line street:
    /// `["", "", ["2155 E. GoDaddy Way", "", ""], "Tempe", ...]`), which are
    /// flattened. Falls back to the `label` parameter (a pre-formatted
    /// address) when every component is empty.
    pub fn get_address(&self) -> Option<String> {
        self.vcard_props("adr").find_map(|prop| {
            let mut parts = Vec::new();
            // adr is [pobox, ext, street, locality, region, postal code, country]
            if let Some(components) = prop[3].as_array() {
                for component in components {
                    push_component_text(component, &mut parts);
                }
            }
            if parts.is_empty() {
                prop[1]
                    .get("label")
                    .and_then(Value::as_str)
                    .map(|label| {
                        label
                            .lines()
                            .filter_map(non_empty_text)
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .filter(|s| !s.is_empty())
            } else {
                Some(parts.join(", "))
            }
        })
    }

    /// Country from the address: the country-name component (index 6) when
    /// present, else the RFC 8605 `cc` parameter (`["adr", {"cc": "US"}, ...]`),
    /// which RFC 8605 servers often send *instead of* the component.
    pub fn get_country(&self) -> Option<String> {
        self.vcard_props("adr").find_map(|prop| {
            let mut country = Vec::new();
            if let Some(component) = prop[3].as_array().and_then(|c| c.get(6)) {
                push_component_text(component, &mut country);
            }
            country.into_iter().next().or_else(|| {
                prop[1]
                    .get("cc")
                    .and_then(Value::as_str)
                    .and_then(non_empty_text)
            })
        })
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

    /// Glue addresses. Lenient (see [`lenient_ip_addresses`]): some
    /// registries (NASK, .pl) send an array of `{"v4": [...]}` objects rather
    /// than the RFC 9083 object, and that must not fail the whole response.
    #[serde(default, deserialize_with = "lenient_ip_addresses")]
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

impl IpAddresses {
    /// Appends the string entries of `obj`'s `v4`/`v6` arrays, skipping
    /// anything that isn't a string.
    fn extend_from_object(&mut self, obj: &serde_json::Map<String, Value>) {
        let strings = |key: &str| -> Vec<String> {
            obj.get(key)
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default()
        };
        self.v4.extend(strings("v4"));
        self.v6.extend(strings("v6"));
    }
}

/// Deserializes `ipAddresses` leniently. RFC 9083 specifies an object
/// (`{"v4": [...], "v6": [...]}`), but NASK (.pl) sends an *array* of such
/// objects; those are merged. Any other shape yields `None` — glue addresses
/// are never worth failing the whole response over.
fn lenient_ip_addresses<'de, D>(
    deserializer: D,
) -> std::result::Result<Option<IpAddresses>, D::Error>
where
    D: Deserializer<'de>,
{
    let mut out = IpAddresses {
        v4: Vec::new(),
        v6: Vec::new(),
    };
    match Value::deserialize(deserializer)? {
        Value::Object(obj) => {
            out.extend_from_object(&obj);
            Ok(Some(out))
        }
        Value::Array(items) => {
            for obj in items.iter().filter_map(Value::as_object) {
                out.extend_from_object(obj);
            }
            Ok((!out.v4.is_empty() || !out.v6.is_empty()).then_some(out))
        }
        _ => Ok(None),
    }
}

/// DNSSEC information for a domain.
///
/// Every member is lenient: a `delegationSigned` of the wrong type reads as
/// unknown, and a malformed `dsData`/`keyData` entry is dropped on its own
/// rather than taking the whole response down with it.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SecureDns {
    #[serde(default, deserialize_with = "lenient_option")]
    pub delegation_signed: Option<bool>,
    #[serde(default, deserialize_with = "lenient_vec")]
    pub ds_data: Vec<DsData>,
    #[serde(default, deserialize_with = "lenient_vec")]
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
                return entity.get_name().or_else(|| entity.non_empty_handle());
            }
        }
        None
    }

    /// Extracts structured registrar object detail — ICANN abuse contact, IANA
    /// registrar ID, and registrar URL — from the `registrar` entity.
    ///
    /// These fields are already carried by the RDAP response (the abuse contact
    /// as a nested `abuse`-role entity per RFC 9083, the IANA ID in
    /// `public_ids`, the URL in `links`) but `get_registrar` collapses the
    /// entity to just a name. Returns `None` when there is no registrar entity
    /// or it carries none of these fields.
    pub fn get_registrar_detail(&self) -> Option<RegistrarDetail> {
        let entity = self.get_entity_by_role("registrar")?;

        // IANA Registrar ID from public_ids (RFC 7484 uses the type string
        // "IANA Registrar ID"; match loosely on "iana" for registry variance).
        let iana_id = entity
            .public_ids
            .iter()
            .find(|p| p.id_type.to_lowercase().contains("iana"))
            .map(|p| p.identifier.clone());

        // Registrar URL: prefer a link with rel="about", else the first http(s)
        // href on the entity.
        let url = entity
            .links
            .iter()
            .find(|l| l.rel.as_deref() == Some("about"))
            .and_then(|l| l.href.clone())
            .or_else(|| {
                entity
                    .links
                    .iter()
                    .find_map(|l| l.href.clone().filter(|h| h.starts_with("http")))
            });

        // Abuse contact: the nested entity with role "abuse".
        let (abuse_email, abuse_phone) = entity
            .entities
            .iter()
            .find(|e| e.roles.iter().any(|r| r == "abuse"))
            .map(|a| (a.get_email(), a.get_phone()))
            .unwrap_or((None, None));

        let detail = RegistrarDetail {
            abuse_email,
            abuse_phone,
            iana_id,
            url,
        };
        if detail.is_empty() {
            None
        } else {
            Some(detail)
        }
    }

    pub fn get_registrant(&self) -> Option<String> {
        for entity in &self.entities {
            if entity.roles.iter().any(|r| r == "registrant") {
                return entity.get_name().or_else(|| entity.non_empty_handle());
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

    /// When the domain object itself last changed (the RFC 9083
    /// `last changed` event).
    ///
    /// Deliberately ignores `last update of RDAP database`: that is the
    /// registry's database-snapshot time, not a change to this domain, and it
    /// is ~now on every response. Several registries (CentralNic, Google)
    /// list it *before* `last changed`, so matching either event took the DB
    /// timestamp and every such domain showed "Updated: today". A domain
    /// without a `last changed` event reports `None`, letting callers fall
    /// back to WHOIS's updated date instead.
    pub fn last_updated(&self) -> Option<DateTime<Utc>> {
        self.events
            .iter()
            .find(|e| e.event_action == "last changed")
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

/// Structured registrar object detail extracted from the RDAP `registrar`
/// entity: the ICANN abuse contact, IANA registrar ID, and registrar URL.
///
/// All three are already present in RDAP responses but discarded by
/// [`RdapResponse::get_registrar`], which returns only the registrar name.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RegistrarDetail {
    /// ICANN-required abuse contact email (from the nested `abuse` entity).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abuse_email: Option<String>,
    /// Abuse contact phone (from the nested `abuse` entity).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub abuse_phone: Option<String>,
    /// IANA Registrar ID (uniquely identifies the registrar for correlation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iana_id: Option<String>,
    /// Registrar URL (the `about` link on the registrar entity).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

impl RegistrarDetail {
    /// True when no field carries data (used to collapse an empty detail to
    /// `None`).
    pub fn is_empty(&self) -> bool {
        self.abuse_email.is_none()
            && self.abuse_phone.is_none()
            && self.iana_id.is_none()
            && self.url.is_none()
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
    fn get_registrar_detail_extracts_abuse_iana_url() {
        let resp: RdapResponse = serde_json::from_value(serde_json::json!({
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

        let detail = resp.get_registrar_detail().expect("registrar detail");
        assert_eq!(detail.iana_id.as_deref(), Some("292"));
        assert_eq!(detail.url.as_deref(), Some("https://registrar.example"));
        assert_eq!(
            detail.abuse_email.as_deref(),
            Some("abuse@registrar.example")
        );
        assert_eq!(detail.abuse_phone.as_deref(), Some("+1.5551230000"));
    }

    #[test]
    fn get_registrar_detail_none_without_registrar() {
        // No registrar entity at all.
        assert!(RdapResponse::default().get_registrar_detail().is_none());

        // Registrar entity present but carrying none of the detail fields.
        let resp: RdapResponse = serde_json::from_value(serde_json::json!({
            "entities": [{"objectClassName": "entity", "roles": ["registrar"],
                "vcardArray": ["vcard", [["fn", {}, "text", "Bare Registrar"]]]}]
        }))
        .unwrap();
        assert!(resp.get_registrar_detail().is_none());
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

    // ---- secureDNS (RFC 9083 key spelling + leniency) ----------------------

    #[test]
    fn secure_dns_parses_the_rfc9083_key() {
        // RFC 9083 and every real server spell it `secureDNS`; the
        // struct-wide camelCase rule used to expect `secureDns`, so DNSSEC
        // state never parsed and silently landed in `extra`.
        let resp: RdapResponse = serde_json::from_value(serde_json::json!({
            "objectClassName": "domain",
            "ldhName": "example.com",
            "secureDNS": {
                "delegationSigned": true,
                "dsData": [{"keyTag": 370, "algorithm": 13, "digestType": 2, "digest": "BE74"}]
            }
        }))
        .unwrap();
        assert!(resp.is_dnssec_signed());
        let sd = resp.secure_dns.as_ref().expect("secureDNS parsed");
        assert_eq!(sd.ds_data.len(), 1);
        assert_eq!(sd.ds_data[0].key_tag, 370);
        assert!(!resp.extra.contains_key("secureDNS"));
        // Round-trips under the RFC spelling.
        let json = serde_json::to_string(&resp).unwrap();
        assert!(json.contains("\"secureDNS\""), "{json}");
    }

    #[test]
    fn secure_dns_still_accepts_camel_case_alias() {
        let resp: RdapResponse = serde_json::from_value(serde_json::json!({
            "secureDns": {"delegationSigned": true}
        }))
        .unwrap();
        assert!(resp.is_dnssec_signed());
    }

    #[test]
    fn malformed_secure_dns_members_do_not_fail_the_response() {
        // A malformed dsData entry is dropped on its own; the good one and
        // the rest of the response survive.
        let resp: RdapResponse = serde_json::from_value(serde_json::json!({
            "ldhName": "example.com",
            "status": ["active"],
            "secureDNS": {
                "delegationSigned": true,
                "dsData": [
                    {"keyTag": "not-a-number", "algorithm": 13},
                    {"keyTag": 1, "algorithm": 8, "digestType": 2, "digest": "AA"}
                ],
                "keyData": [{"flags": 257}]
            }
        }))
        .unwrap();
        let sd = resp.secure_dns.as_ref().expect("secureDNS parsed");
        assert!(resp.is_dnssec_signed());
        assert_eq!(sd.ds_data.len(), 1);
        assert_eq!(sd.ds_data[0].key_tag, 1);
        assert!(sd.key_data.is_empty());

        // A secureDNS of the wrong type is just "unknown".
        let resp: RdapResponse = serde_json::from_value(serde_json::json!({
            "ldhName": "example.com",
            "secureDNS": "yes"
        }))
        .unwrap();
        assert!(resp.secure_dns.is_none());
        assert_eq!(resp.ldh_name.as_deref(), Some("example.com"));
    }

    // ---- nameserver ipAddresses leniency (NASK array form) -----------------

    #[test]
    fn ip_addresses_array_form_is_merged_not_fatal() {
        // NASK (.pl) sends an array of {"v4": [...]} objects; this used to
        // fail the whole RdapResponse (`seer rdap wp.pl`).
        let resp: RdapResponse = serde_json::from_value(serde_json::json!({
            "ldhName": "wp.pl",
            "nameservers": [{
                "objectClassName": "nameserver",
                "ldhName": "ns1.wp.pl",
                "ipAddresses": [{"v4": ["212.77.102.200"]}, {"v6": ["2a02:598::200"]}]
            }]
        }))
        .unwrap();
        assert_eq!(resp.nameserver_names(), vec!["ns1.wp.pl"]);
        let ips = resp.nameservers[0]
            .ip_addresses
            .as_ref()
            .expect("merged glue");
        assert_eq!(ips.v4, vec!["212.77.102.200"]);
        assert_eq!(ips.v6, vec!["2a02:598::200"]);
    }

    #[test]
    fn ip_addresses_object_form_and_garbage() {
        let resp: RdapResponse = serde_json::from_value(serde_json::json!({
            "nameservers": [
                {"ldhName": "ns1.example.com", "ipAddresses": {"v4": ["192.0.2.1"]}},
                {"ldhName": "ns2.example.com", "ipAddresses": "bogus"}
            ]
        }))
        .unwrap();
        let first = resp.nameservers[0].ip_addresses.as_ref().expect("object");
        assert_eq!(first.v4, vec!["192.0.2.1"]);
        assert!(first.v6.is_empty());
        assert!(resp.nameservers[1].ip_addresses.is_none());
    }

    // ---- last_updated ------------------------------------------------------

    #[test]
    fn last_updated_ignores_the_rdap_database_timestamp() {
        use chrono::Datelike;
        // CentralNic/Google list the DB-snapshot event first; it must not
        // masquerade as the domain's own update date.
        let resp: RdapResponse = serde_json::from_value(serde_json::json!({
            "events": [
                {"eventAction": "last update of RDAP database", "eventDate": "2026-09-22T10:00:00Z"},
                {"eventAction": "last changed", "eventDate": "2024-03-01T00:00:00Z"}
            ]
        }))
        .unwrap();
        assert_eq!(resp.last_updated().expect("last changed").year(), 2024);

        let db_only: RdapResponse = serde_json::from_value(serde_json::json!({
            "events": [
                {"eventAction": "last update of RDAP database", "eventDate": "2026-09-22T10:00:00Z"}
            ]
        }))
        .unwrap();
        assert!(db_only.last_updated().is_none());
    }

    // ---- vCard extraction --------------------------------------------------

    fn entity_with_vcard(roles: &[&str], handle: Option<&str>, props: Value) -> RdapEntity {
        serde_json::from_value(serde_json::json!({
            "objectClassName": "entity",
            "roles": roles,
            "handle": handle,
            "vcardArray": ["vcard", props]
        }))
        .unwrap()
    }

    #[test]
    fn redacted_empty_vcard_values_read_as_absent() {
        let e = entity_with_vcard(
            &["registrant"],
            None,
            serde_json::json!([
                ["version", {}, "text", "4.0"],
                ["fn", {}, "text", ""],
                ["org", {}, "text", ""],
                ["email", {}, "text", "  "]
            ]),
        );
        assert_eq!(e.get_name(), None);
        assert_eq!(e.get_organization(), None);
        assert_eq!(e.get_email(), None);

        // With no name and no handle, the registrant is absent (so the WHOIS
        // fallback in DomainInfo can fill it) rather than Some("").
        let resp = RdapResponse {
            entities: vec![e],
            ..Default::default()
        };
        assert_eq!(resp.get_registrant(), None);

        // An empty fn falls through to a real handle.
        let with_handle = entity_with_vcard(
            &["registrar"],
            Some("REG-1"),
            serde_json::json!([["fn", {}, "text", ""]]),
        );
        let resp = RdapResponse {
            entities: vec![with_handle],
            ..Default::default()
        };
        assert_eq!(resp.get_registrar().as_deref(), Some("REG-1"));
    }

    #[test]
    fn get_phone_strips_tel_uri_scheme() {
        let e = entity_with_vcard(
            &["abuse"],
            None,
            serde_json::json!([["tel", {"type": ["voice", "work"]}, "uri", "tel:+1.2083895740"]]),
        );
        assert_eq!(e.get_phone().as_deref(), Some("+1.2083895740"));

        let text_form = entity_with_vcard(
            &["abuse"],
            None,
            serde_json::json!([["tel", {}, "text", "+1.5551230000"]]),
        );
        assert_eq!(text_form.get_phone().as_deref(), Some("+1.5551230000"));
    }

    #[test]
    fn get_address_flattens_nested_street_components() {
        let e = entity_with_vcard(
            &["registrant"],
            None,
            serde_json::json!([[
                "adr",
                {},
                "text",
                [
                    "",
                    "",
                    ["2155 E. GoDaddy Way", "", ""],
                    "Tempe",
                    "AZ",
                    "85284",
                    "US"
                ]
            ]]),
        );
        assert_eq!(
            e.get_address().as_deref(),
            Some("2155 E. GoDaddy Way, Tempe, AZ, 85284, US")
        );
        assert_eq!(e.get_country().as_deref(), Some("US"));
    }

    #[test]
    fn get_country_uses_rfc8605_cc_parameter() {
        let e = entity_with_vcard(
            &["registrant"],
            None,
            serde_json::json!([[
                "adr", {"cc": "DE"}, "text",
                ["", "", "", "Berlin", "", "", ""]
            ]]),
        );
        assert_eq!(e.get_country().as_deref(), Some("DE"));
        assert_eq!(e.get_address().as_deref(), Some("Berlin"));
    }
}
