use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        self.event_date.as_ref()?.parse().ok()
    }
}

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
                                if prop_arr.len() >= 4 {
                                    if prop_arr[0].as_str() == Some("fn") {
                                        return prop_arr[3].as_str().map(String::from);
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
                                if prop_arr.len() >= 4 {
                                    if prop_arr[0].as_str() == Some("email") {
                                        return prop_arr[3].as_str().map(String::from);
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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PublicId {
    #[serde(rename = "type")]
    pub id_type: String,
    pub identifier: String,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpAddresses {
    #[serde(default)]
    pub v4: Vec<String>,
    #[serde(default)]
    pub v6: Vec<String>,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DsData {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyData {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub public_key: String,
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RdapRemark {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Vec<String>,
    #[serde(default)]
    pub links: Vec<RdapLink>,
}

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
            .find(|e| e.event_action == "last changed" || e.event_action == "last update of RDAP database")
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
}
