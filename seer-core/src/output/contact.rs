//! One display path for registration contacts.
//!
//! WHOIS and [`DomainInfo`] keep contacts as flat `registrant_*`/`admin_*`/
//! `tech_*` fields while RDAP builds a [`ContactInfo`] per entity role. Both
//! are viewed through [`Contact`], so each formatter renders every source
//! with a single contact routine instead of one hand-written copy per source.

use crate::domain_info::DomainInfo;
use crate::rdap::{ContactInfo, RdapResponse};
use crate::whois::WhoisResponse;

/// The contact roles WHOIS and RDAP share, in render order. Headings read
/// `"<role> Contact"`; RDAP's extra billing role is rendered separately.
pub(super) const ROLES: [&str; 3] = ["Registrant", "Admin", "Tech"];

/// Borrowed display fields of one contact.
#[derive(Clone, Copy)]
pub(super) struct Contact<'a> {
    pub name: &'a Option<String>,
    pub organization: &'a Option<String>,
    pub email: &'a Option<String>,
    pub phone: &'a Option<String>,
    pub address: &'a Option<String>,
    pub country: &'a Option<String>,
}

impl<'a> Contact<'a> {
    /// A contact with no fields; renders nothing.
    pub const EMPTY: Contact<'static> = Contact {
        name: &None,
        organization: &None,
        email: &None,
        phone: &None,
        address: &None,
        country: &None,
    };

    /// Every field of an RDAP contact. Empty when there is no contact or it
    /// holds nothing but redaction placeholders ([`ContactInfo::has_info`]).
    pub fn rdap(contact: Option<&'a ContactInfo>) -> Self {
        match contact {
            Some(c) if c.has_info() => Contact {
                name: &c.name,
                organization: &c.organization,
                email: &c.email,
                phone: &c.phone,
                address: &c.address,
                country: &c.country,
            },
            _ => Contact::EMPTY,
        }
    }

    /// This contact without name/organization, for a registrant block whose
    /// formatter prints those as the top-level Registrant/Organization lines.
    pub fn without_identity(self) -> Self {
        Contact {
            name: &None,
            organization: &None,
            ..self
        }
    }

    /// `(label, field)` pairs in display order.
    pub fn fields(&self) -> [(&'static str, &'a Option<String>); 6] {
        [
            ("Name", self.name),
            ("Organization", self.organization),
            ("Email", self.email),
            ("Phone", self.phone),
            ("Address", self.address),
            ("Country", self.country),
        ]
    }

    pub fn is_empty(&self) -> bool {
        self.fields().iter().all(|(_, field)| field.is_none())
    }
}

/// RDAP's contacts for [`ROLES`], in order. Owned because the RDAP getters
/// build each [`ContactInfo`] on demand; view them with [`Contact::rdap`].
pub(super) fn rdap_contacts(data: &RdapResponse) -> [Option<ContactInfo>; 3] {
    [
        data.get_registrant_contact(),
        data.get_admin_contact(),
        data.get_tech_contact(),
    ]
}

/// Views of [`rdap_contacts`], with every field.
pub(super) fn rdap_views(contacts: &[Option<ContactInfo>; 3]) -> [Contact<'_>; 3] {
    contacts.each_ref().map(|c| Contact::rdap(c.as_ref()))
}

/// Contacts of a source that stores them as flat fields, for [`ROLES`] in
/// order. The registrant view has no name/organization: those are the
/// source's top-level `registrant`/`organization` fields.
pub(super) trait FlatContacts {
    fn contacts(&self) -> [Contact<'_>; 3];
}

// `WhoisResponse` and `DomainInfo` spell their contact fields identically.
macro_rules! impl_flat_contacts {
    ($($source:ty),+) => {$(
        impl FlatContacts for $source {
            fn contacts(&self) -> [Contact<'_>; 3] {
                [
                    Contact {
                        email: &self.registrant_email,
                        phone: &self.registrant_phone,
                        address: &self.registrant_address,
                        country: &self.registrant_country,
                        ..Contact::EMPTY
                    },
                    Contact {
                        name: &self.admin_name,
                        organization: &self.admin_organization,
                        email: &self.admin_email,
                        phone: &self.admin_phone,
                        ..Contact::EMPTY
                    },
                    Contact {
                        name: &self.tech_name,
                        organization: &self.tech_organization,
                        email: &self.tech_email,
                        phone: &self.tech_phone,
                        ..Contact::EMPTY
                    },
                ]
            }
        }
    )+};
}

impl_flat_contacts!(WhoisResponse, DomainInfo);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rdap_view_is_empty_for_redacted_only_contact() {
        let redacted = ContactInfo {
            name: Some("REDACTED FOR PRIVACY".to_string()),
            ..Default::default()
        };
        assert!(Contact::rdap(Some(&redacted)).is_empty());
        assert!(Contact::rdap(None).is_empty());
    }

    #[test]
    fn without_identity_keeps_only_contact_details() {
        let identity_only = ContactInfo {
            name: Some("Jane".to_string()),
            organization: Some("Example LLC".to_string()),
            ..Default::default()
        };
        let view = Contact::rdap(Some(&identity_only));
        assert!(!view.is_empty());
        assert!(view.without_identity().is_empty());
    }
}
