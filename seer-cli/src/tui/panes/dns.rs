//! Records lens runtime state. The record type and nameserver are options
//! (`options::RECORDS`); what remains is the IP the RDAP "IP" query reuses.

/// The last A address a Records or Status result resolved, for RDAP's IP query.
#[derive(Default)]
pub struct DnsState {
    pub resolved_ip: Option<String>,
}
