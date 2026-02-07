use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::time::Duration;

use hickory_resolver::config::{NameServerConfig, Protocol, ResolverConfig, ResolverOpts};
use hickory_resolver::proto::rr::rdata::CAA;
use hickory_resolver::proto::rr::RecordType as HickoryRecordType;
use hickory_resolver::TokioAsyncResolver;
use tracing::{debug, instrument};

use super::records::{DnsRecord, RecordData, RecordType};
use crate::error::{Result, SeerError};
use crate::validation::normalize_domain;

/// Default timeout for DNS queries (5 seconds).
/// DNS is typically fast; longer timeouts indicate network issues or unreachable servers.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// DNS resolver for querying various record types.
///
/// Uses Google DNS (8.8.8.8) by default, but supports custom nameservers.
#[derive(Debug, Clone)]
pub struct DnsResolver {
    timeout: Duration,
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsResolver {
    /// Creates a new DNS resolver with default settings.
    pub fn new() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
        }
    }

    /// Sets the timeout for DNS queries.
    ///
    /// The default is 5 seconds, which is sufficient for most DNS queries.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn create_resolver(&self, nameserver: Option<&str>) -> Result<TokioAsyncResolver> {
        let mut opts = ResolverOpts::default();
        opts.timeout = self.timeout;
        opts.attempts = 2;
        opts.use_hosts_file = false;

        let config = if let Some(ns) = nameserver {
            let ip: IpAddr = ns
                .parse()
                .map_err(|_| SeerError::DnsError(format!("invalid nameserver IP: {}", ns)))?;

            let socket_addr = SocketAddr::new(ip, 53);
            let ns_config = NameServerConfig::new(socket_addr, Protocol::Udp);

            let mut config = ResolverConfig::new();
            config.add_name_server(ns_config);
            config
        } else {
            ResolverConfig::google()
        };

        Ok(TokioAsyncResolver::tokio(config, opts))
    }

    /// Resolves DNS records for a domain.
    ///
    /// # Arguments
    /// * `domain` - The domain name to query
    /// * `record_type` - The type of DNS record to look up (A, AAAA, MX, etc.)
    /// * `nameserver` - Optional custom nameserver IP; uses Google DNS if None
    #[instrument(skip(self), fields(domain = %domain, record_type = %record_type))]
    pub async fn resolve(
        &self,
        domain: &str,
        record_type: RecordType,
        nameserver: Option<&str>,
    ) -> Result<Vec<DnsRecord>> {
        let resolver = self.create_resolver(nameserver)?;
        let domain = normalize_domain(domain)?;

        debug!(nameserver = nameserver.unwrap_or("system"), "Resolving DNS");

        match record_type {
            RecordType::A => self.resolve_a(&resolver, &domain).await,
            RecordType::AAAA => self.resolve_aaaa(&resolver, &domain).await,
            RecordType::CNAME => self.resolve_cname(&resolver, &domain).await,
            RecordType::MX => self.resolve_mx(&resolver, &domain).await,
            RecordType::NS => self.resolve_ns(&resolver, &domain).await,
            RecordType::TXT => self.resolve_txt(&resolver, &domain).await,
            RecordType::SOA => self.resolve_soa(&resolver, &domain).await,
            RecordType::PTR => self.resolve_ptr(&resolver, &domain).await,
            RecordType::SRV => Err(SeerError::DnsError(
                "SRV records require service name format: _service._proto.name".to_string(),
            )),
            RecordType::CAA => self.resolve_caa(&resolver, &domain).await,
            RecordType::DNSKEY => self.resolve_dnskey(&resolver, &domain).await,
            RecordType::DS => self.resolve_ds(&resolver, &domain).await,
            RecordType::ANY => self.resolve_any(&resolver, &domain).await,
            _ => Err(SeerError::DnsError(format!(
                "Record type {} not implemented",
                record_type
            ))),
        }
    }

    /// Resolves SRV records for a service.
    ///
    /// # Arguments
    /// * `service` - The service name (e.g., "http", "ldap")
    /// * `protocol` - The protocol (e.g., "tcp", "udp")
    /// * `domain` - The domain name
    /// * `nameserver` - Optional custom nameserver IP
    pub async fn resolve_srv(
        &self,
        service: &str,
        protocol: &str,
        domain: &str,
        nameserver: Option<&str>,
    ) -> Result<Vec<DnsRecord>> {
        // Validate service and protocol to prevent DNS query injection
        if !is_valid_srv_label(service) {
            return Err(SeerError::DnsError(format!(
                "invalid SRV service name: {}",
                service
            )));
        }
        if !is_valid_srv_label(protocol) {
            return Err(SeerError::DnsError(format!(
                "invalid SRV protocol name: {}",
                protocol
            )));
        }

        let resolver = self.create_resolver(nameserver)?;
        let query_name = format!("_{}._{}.{}", service, protocol, domain);

        let response = resolver
            .srv_lookup(&query_name)
            .await
            .map_err(|e| SeerError::DnsError(format!("SRV lookup failed: {}", e)))?;

        let records = response
            .iter()
            .map(|srv| DnsRecord {
                name: query_name.clone(),
                record_type: RecordType::SRV,
                ttl: response
                    .as_lookup()
                    .record_iter()
                    .next()
                    .map(|r| r.ttl())
                    .unwrap_or(0),
                data: RecordData::SRV {
                    priority: srv.priority(),
                    weight: srv.weight(),
                    port: srv.port(),
                    target: srv.target().to_string(),
                },
            })
            .collect();

        Ok(records)
    }

    async fn resolve_a(
        &self,
        resolver: &TokioAsyncResolver,
        domain: &str,
    ) -> Result<Vec<DnsRecord>> {
        let response = resolver
            .ipv4_lookup(domain)
            .await
            .map_err(|e| SeerError::DnsError(format!("A lookup failed: {}", e)))?;

        let ttl = response
            .as_lookup()
            .record_iter()
            .next()
            .map(|r| r.ttl())
            .unwrap_or(0);

        let records = response
            .iter()
            .map(|addr| DnsRecord {
                name: domain.to_string(),
                record_type: RecordType::A,
                ttl,
                data: RecordData::A {
                    address: addr.to_string(),
                },
            })
            .collect();

        Ok(records)
    }

    async fn resolve_aaaa(
        &self,
        resolver: &TokioAsyncResolver,
        domain: &str,
    ) -> Result<Vec<DnsRecord>> {
        let response = resolver
            .ipv6_lookup(domain)
            .await
            .map_err(|e| SeerError::DnsError(format!("AAAA lookup failed: {}", e)))?;

        let ttl = response
            .as_lookup()
            .record_iter()
            .next()
            .map(|r| r.ttl())
            .unwrap_or(0);

        let records = response
            .iter()
            .map(|addr| DnsRecord {
                name: domain.to_string(),
                record_type: RecordType::AAAA,
                ttl,
                data: RecordData::AAAA {
                    address: addr.to_string(),
                },
            })
            .collect();

        Ok(records)
    }

    async fn resolve_cname(
        &self,
        resolver: &TokioAsyncResolver,
        domain: &str,
    ) -> Result<Vec<DnsRecord>> {
        let response = resolver
            .lookup(domain, HickoryRecordType::CNAME)
            .await
            .map_err(|e| SeerError::DnsError(format!("CNAME lookup failed: {}", e)))?;

        let records = response
            .record_iter()
            .filter_map(|record| {
                if let Some(rdata) = record.data() {
                    if let Some(cname) = rdata.as_cname() {
                        return Some(DnsRecord {
                            name: domain.to_string(),
                            record_type: RecordType::CNAME,
                            ttl: record.ttl(),
                            data: RecordData::CNAME {
                                target: cname.0.to_string(),
                            },
                        });
                    }
                }
                None
            })
            .collect();

        Ok(records)
    }

    async fn resolve_mx(
        &self,
        resolver: &TokioAsyncResolver,
        domain: &str,
    ) -> Result<Vec<DnsRecord>> {
        let response = resolver
            .mx_lookup(domain)
            .await
            .map_err(|e| SeerError::DnsError(format!("MX lookup failed: {}", e)))?;

        let ttl = response
            .as_lookup()
            .record_iter()
            .next()
            .map(|r| r.ttl())
            .unwrap_or(0);

        let mut records: Vec<DnsRecord> = response
            .iter()
            .map(|mx| DnsRecord {
                name: domain.to_string(),
                record_type: RecordType::MX,
                ttl,
                data: RecordData::MX {
                    preference: mx.preference(),
                    exchange: mx.exchange().to_string(),
                },
            })
            .collect();

        records.sort_by_key(|r| {
            if let RecordData::MX { preference, .. } = &r.data {
                *preference
            } else {
                0
            }
        });

        Ok(records)
    }

    async fn resolve_ns(
        &self,
        resolver: &TokioAsyncResolver,
        domain: &str,
    ) -> Result<Vec<DnsRecord>> {
        let response = resolver
            .ns_lookup(domain)
            .await
            .map_err(|e| SeerError::DnsError(format!("NS lookup failed: {}", e)))?;

        let ttl = response
            .as_lookup()
            .record_iter()
            .next()
            .map(|r| r.ttl())
            .unwrap_or(0);

        let records = response
            .iter()
            .map(|ns| DnsRecord {
                name: domain.to_string(),
                record_type: RecordType::NS,
                ttl,
                data: RecordData::NS {
                    nameserver: ns.0.to_string(),
                },
            })
            .collect();

        Ok(records)
    }

    async fn resolve_txt(
        &self,
        resolver: &TokioAsyncResolver,
        domain: &str,
    ) -> Result<Vec<DnsRecord>> {
        let response = resolver
            .txt_lookup(domain)
            .await
            .map_err(|e| SeerError::DnsError(format!("TXT lookup failed: {}", e)))?;

        let ttl = response
            .as_lookup()
            .record_iter()
            .next()
            .map(|r| r.ttl())
            .unwrap_or(0);

        let records = response
            .iter()
            .map(|txt| {
                let text = txt
                    .iter()
                    .map(|data| String::from_utf8_lossy(data).to_string())
                    .collect::<Vec<_>>()
                    .join("");

                DnsRecord {
                    name: domain.to_string(),
                    record_type: RecordType::TXT,
                    ttl,
                    data: RecordData::TXT { text },
                }
            })
            .collect();

        Ok(records)
    }

    async fn resolve_soa(
        &self,
        resolver: &TokioAsyncResolver,
        domain: &str,
    ) -> Result<Vec<DnsRecord>> {
        let response = resolver
            .soa_lookup(domain)
            .await
            .map_err(|e| SeerError::DnsError(format!("SOA lookup failed: {}", e)))?;

        let ttl = response
            .as_lookup()
            .record_iter()
            .next()
            .map(|r| r.ttl())
            .unwrap_or(0);

        let records = response
            .iter()
            .map(|soa| DnsRecord {
                name: domain.to_string(),
                record_type: RecordType::SOA,
                ttl,
                data: RecordData::SOA {
                    mname: soa.mname().to_string(),
                    rname: soa.rname().to_string(),
                    serial: soa.serial(),
                    refresh: soa.refresh().try_into().unwrap_or(0),
                    retry: soa.retry().try_into().unwrap_or(0),
                    expire: soa.expire().try_into().unwrap_or(0),
                    minimum: soa.minimum(),
                },
            })
            .collect();

        Ok(records)
    }

    async fn resolve_ptr(
        &self,
        resolver: &TokioAsyncResolver,
        query: &str,
    ) -> Result<Vec<DnsRecord>> {
        // If it's an IP address, convert to reverse DNS format
        let query = if let Ok(ip) = IpAddr::from_str(query) {
            reverse_dns_name(&ip)
        } else {
            query.to_string()
        };

        let response = resolver
            .lookup(&query, HickoryRecordType::PTR)
            .await
            .map_err(|e| SeerError::DnsError(format!("PTR lookup failed: {}", e)))?;

        let records = response
            .record_iter()
            .filter_map(|record| {
                if let Some(rdata) = record.data() {
                    if let Some(ptr) = rdata.as_ptr() {
                        return Some(DnsRecord {
                            name: query.clone(),
                            record_type: RecordType::PTR,
                            ttl: record.ttl(),
                            data: RecordData::PTR {
                                target: ptr.0.to_string(),
                            },
                        });
                    }
                }
                None
            })
            .collect();

        Ok(records)
    }

    async fn resolve_caa(
        &self,
        resolver: &TokioAsyncResolver,
        domain: &str,
    ) -> Result<Vec<DnsRecord>> {
        let response = resolver
            .lookup(domain, HickoryRecordType::CAA)
            .await
            .map_err(|e| SeerError::DnsError(format!("CAA lookup failed: {}", e)))?;

        let records = response
            .record_iter()
            .filter_map(|record| {
                if let Some(rdata) = record.data() {
                    if let Some(caa) = rdata.as_caa() {
                        let (flags, tag, value) = parse_caa(caa);
                        return Some(DnsRecord {
                            name: domain.to_string(),
                            record_type: RecordType::CAA,
                            ttl: record.ttl(),
                            data: RecordData::CAA { flags, tag, value },
                        });
                    }
                }
                None
            })
            .collect();

        Ok(records)
    }

    async fn resolve_dnskey(
        &self,
        resolver: &TokioAsyncResolver,
        domain: &str,
    ) -> Result<Vec<DnsRecord>> {
        use hickory_resolver::proto::rr::RData as HickoryRData;

        let response = resolver
            .lookup(domain, HickoryRecordType::DNSKEY)
            .await
            .map_err(|e| SeerError::DnsError(format!("DNSKEY lookup failed: {}", e)))?;

        let records = response
            .record_iter()
            .filter_map(|record| {
                if let Some(HickoryRData::DNSSEC(dnssec_rdata)) = record.data() {
                    if let Some(dnskey) = dnssec_rdata.as_dnskey() {
                        use base64::{engine::general_purpose::STANDARD, Engine};
                        let public_key = STANDARD.encode(dnskey.public_key());
                        return Some(DnsRecord {
                            name: domain.to_string(),
                            record_type: RecordType::DNSKEY,
                            ttl: record.ttl(),
                            data: RecordData::DNSKEY {
                                flags: dnskey.flags(),
                                protocol: 3, // Protocol is always 3 for DNSSEC (RFC 4034)
                                algorithm: u8::from(dnskey.algorithm()),
                                public_key,
                            },
                        });
                    }
                }
                None
            })
            .collect();

        Ok(records)
    }

    async fn resolve_ds(
        &self,
        resolver: &TokioAsyncResolver,
        domain: &str,
    ) -> Result<Vec<DnsRecord>> {
        use hickory_resolver::proto::rr::RData as HickoryRData;

        let response = resolver
            .lookup(domain, HickoryRecordType::DS)
            .await
            .map_err(|e| SeerError::DnsError(format!("DS lookup failed: {}", e)))?;

        let records = response
            .record_iter()
            .filter_map(|record| {
                if let Some(HickoryRData::DNSSEC(dnssec_rdata)) = record.data() {
                    if let Some(ds) = dnssec_rdata.as_ds() {
                        let digest = ds
                            .digest()
                            .iter()
                            .map(|b| format!("{:02X}", b))
                            .collect::<String>();
                        return Some(DnsRecord {
                            name: domain.to_string(),
                            record_type: RecordType::DS,
                            ttl: record.ttl(),
                            data: RecordData::DS {
                                key_tag: ds.key_tag(),
                                algorithm: u8::from(ds.algorithm()),
                                digest_type: u8::from(ds.digest_type()),
                                digest,
                            },
                        });
                    }
                }
                None
            })
            .collect();

        Ok(records)
    }

    async fn resolve_any(
        &self,
        resolver: &TokioAsyncResolver,
        domain: &str,
    ) -> Result<Vec<DnsRecord>> {
        let mut all_records = Vec::new();

        // Query common record types
        let record_types = [
            RecordType::A,
            RecordType::AAAA,
            RecordType::MX,
            RecordType::NS,
            RecordType::TXT,
            RecordType::SOA,
            RecordType::CAA,
        ];

        for record_type in record_types {
            match self.resolve_type(resolver, domain, record_type).await {
                Ok(records) => all_records.extend(records),
                Err(_) => continue, // Skip record types that don't exist
            }
        }

        Ok(all_records)
    }

    async fn resolve_type(
        &self,
        resolver: &TokioAsyncResolver,
        domain: &str,
        record_type: RecordType,
    ) -> Result<Vec<DnsRecord>> {
        match record_type {
            RecordType::A => self.resolve_a(resolver, domain).await,
            RecordType::AAAA => self.resolve_aaaa(resolver, domain).await,
            RecordType::CNAME => self.resolve_cname(resolver, domain).await,
            RecordType::MX => self.resolve_mx(resolver, domain).await,
            RecordType::NS => self.resolve_ns(resolver, domain).await,
            RecordType::TXT => self.resolve_txt(resolver, domain).await,
            RecordType::SOA => self.resolve_soa(resolver, domain).await,
            RecordType::CAA => self.resolve_caa(resolver, domain).await,
            RecordType::DNSKEY => self.resolve_dnskey(resolver, domain).await,
            RecordType::DS => self.resolve_ds(resolver, domain).await,
            _ => Err(SeerError::DnsError("unsupported record type".to_string())),
        }
    }
}

// Domain normalization is now handled by the shared validation module

fn reverse_dns_name(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(addr) => {
            let octets = addr.octets();
            format!(
                "{}.{}.{}.{}.in-addr.arpa",
                octets[3], octets[2], octets[1], octets[0]
            )
        }
        IpAddr::V6(addr) => {
            let segments = addr.segments();
            // 32 hex nibbles + 31 dots + ".ip6.arpa" (9) = 72 chars
            let mut result = String::with_capacity(72);
            let mut first = true;
            for segment in segments.iter().rev() {
                for shift in [0, 4, 8, 12] {
                    if !first {
                        result.push('.');
                    }
                    first = false;
                    let nibble = (segment >> shift) & 0xF;
                    result.push(char::from_digit(nibble as u32, 16).unwrap());
                }
            }
            result.push_str(".ip6.arpa");
            result
        }
    }
}

fn parse_caa(caa: &CAA) -> (u8, String, String) {
    let flags = if caa.issuer_critical() { 128 } else { 0 };
    let tag = caa.tag().as_str().to_string();
    let value = caa.value().to_string();
    (flags, tag, value)
}

/// Validates SRV service/protocol labels (alphanumeric and hyphens only, no dots)
fn is_valid_srv_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}
