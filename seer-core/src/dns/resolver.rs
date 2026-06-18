//! DNS resolution over hickory-resolver.
//!
//! Retry boundary (deliberate): unlike the WHOIS/RDAP clients, this module
//! does NOT wrap queries in [`crate::retry::RetryPolicy`]. hickory-resolver
//! already performs its own retransmission (`opts.attempts` below) against
//! the configured nameserver within the per-query timeout; stacking an outer
//! retry loop on top would multiply worst-case latency without improving
//! resolution odds. If a retry knob is ever needed here, tune
//! `ResolverOpts::attempts` rather than adding a wrapper.

use std::net::IpAddr;
use std::str::FromStr;
use std::time::Duration;

use hickory_resolver::config::{NameServerConfig, ResolveHosts, ResolverConfig, GOOGLE};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::NetError;
use hickory_resolver::proto::dnssec::PublicKey;
use hickory_resolver::proto::rr::rdata::CAA;
use hickory_resolver::proto::rr::{RData as HickoryRData, RecordType as HickoryRecordType};
use hickory_resolver::TokioResolver;
use tracing::{debug, instrument};

use super::records::{DnsRecord, RecordData, RecordType};
use crate::error::{Result, SeerError};
use crate::validation::normalize_domain;

/// Convert a DNS lookup result, treating "no records found" as an empty vec
/// rather than an error. This is correct DNS behavior — the absence of a
/// record type for a domain is a valid response (NODATA), not a failure.
fn dns_lookup_or_empty<T>(
    result: std::result::Result<T, NetError>,
    record_type: &str,
) -> Result<Option<T>> {
    match result {
        Ok(response) => Ok(Some(response)),
        Err(e) if e.is_no_records_found() => Ok(None),
        Err(e) => Err(SeerError::DnsError(format!(
            "{} lookup failed: {}",
            record_type, e
        ))),
    }
}

/// Default timeout for DNS queries (5 seconds).
/// DNS is typically fast; longer timeouts indicate network issues or unreachable servers.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);

/// Build a TokioResolver pre-configured with the given upstream config and
/// our standard options (timeout, retries, no hosts-file consultation).
///
/// Build only fails when TLS configuration construction fails; we don't
/// enable TLS features in seer-core so `expect` is safe here and is the
/// cleanest expression of that invariant.
fn build_resolver(config: ResolverConfig, timeout: Duration) -> TokioResolver {
    let mut builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
    {
        let opts = builder.options_mut();
        opts.timeout = timeout;
        opts.attempts = 2;
        opts.use_hosts_file = ResolveHosts::Never;
    }
    builder
        .build()
        .expect("hickory resolver build is infallible without TLS features")
}

/// DNS resolver for querying various record types.
///
/// Uses Google DNS (8.8.8.8) by default, but supports custom nameservers.
/// The default resolver is cached and reused across queries to avoid
/// repeated initialization overhead.
#[derive(Clone)]
pub struct DnsResolver {
    timeout: Duration,
    /// Cached default resolver (Google DNS). Reused across all queries
    /// that don't specify a custom nameserver.
    default_resolver: TokioResolver,
}

impl std::fmt::Debug for DnsResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DnsResolver")
            .field("timeout", &self.timeout)
            .finish()
    }
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
            default_resolver: build_resolver(ResolverConfig::udp_and_tcp(&GOOGLE), DEFAULT_TIMEOUT),
        }
    }

    /// Sets the timeout for DNS queries.
    ///
    /// The default is 5 seconds, which is sufficient for most DNS queries.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self.default_resolver = build_resolver(ResolverConfig::udp_and_tcp(&GOOGLE), timeout);
        self
    }

    async fn create_custom_resolver(&self, nameserver: &str) -> Result<TokioResolver> {
        // Accept either a literal IP or a hostname. For hostnames, resolve
        // via the default (Google DNS) hickory resolver so we do not depend
        // on the OS resolver — that is the same fallback principle as the
        // SSL probe fix: when the local system resolver is broken (split
        // DNS, broken router, container netns), hickory still reaches the
        // public name servers and the user-supplied authoritative server
        // is still usable.
        let ips: Vec<IpAddr> = if let Ok(ip) = nameserver.parse::<IpAddr>() {
            vec![ip]
        } else {
            let response = self
                .default_resolver
                .lookup_ip(nameserver)
                .await
                .map_err(|e| {
                    SeerError::DnsError(format!(
                        "failed to resolve nameserver hostname {}: {}",
                        nameserver, e
                    ))
                })?;
            let resolved: Vec<IpAddr> = response.iter().collect();
            if resolved.is_empty() {
                return Err(SeerError::DnsError(format!(
                    "nameserver {} did not resolve to any addresses",
                    nameserver
                )));
            }
            resolved
        };

        // SSRF protection: reject private/reserved IPs — whether supplied
        // literally or returned by name resolution. Without this, a
        // hostname under attacker control could point at internal infra.
        for ip in &ips {
            if let Some(reason) = crate::validation::describe_reserved_ip(ip) {
                return Err(SeerError::DnsError(format!(
                    "nameserver {} blocked: {}",
                    nameserver, reason
                )));
            }
        }

        // Build a config with all resolved IPs as upstream nameservers.
        // In hickory 0.26, NameServerConfig::udp(IpAddr) builds a
        // ConnectionConfig with the default DNS port (53) for us, so we
        // no longer need to construct a SocketAddr explicitly.
        let mut config = ResolverConfig::from_parts(None, vec![], vec![]);
        for ip in ips {
            config.add_name_server(NameServerConfig::udp(ip));
        }

        Ok(build_resolver(config, self.timeout))
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
        // Reuse the cached default resolver when no custom nameserver is specified
        let custom_resolver;
        let resolver = if let Some(ns) = nameserver {
            custom_resolver = self.create_custom_resolver(ns).await?;
            &custom_resolver
        } else {
            &self.default_resolver
        };
        let domain = prepare_query(domain, record_type)?;

        debug!(nameserver = nameserver.unwrap_or("system"), "Resolving DNS");

        match record_type {
            RecordType::A => self.resolve_a(resolver, &domain).await,
            RecordType::AAAA => self.resolve_aaaa(resolver, &domain).await,
            RecordType::CNAME => self.resolve_cname(resolver, &domain).await,
            RecordType::MX => self.resolve_mx(resolver, &domain).await,
            RecordType::NS => self.resolve_ns(resolver, &domain).await,
            RecordType::TXT => self.resolve_txt(resolver, &domain).await,
            RecordType::SOA => self.resolve_soa(resolver, &domain).await,
            RecordType::PTR => self.resolve_ptr(resolver, &domain).await,
            RecordType::SRV => match parse_srv_query(&domain) {
                // dig-style `_service._proto.name` queries resolve directly.
                Some((service, protocol, name)) => {
                    self.resolve_srv_core(resolver, &service, &protocol, &name)
                        .await
                }
                // A bare domain isn't a valid SRV query — surface a usage hint
                // as an input error (permanent), not a transient DNS failure.
                None => Err(SeerError::InvalidInput(
                    "SRV records require service name format: _service._proto.name".to_string(),
                )),
            },
            RecordType::CAA => self.resolve_caa(resolver, &domain).await,
            RecordType::DNSKEY => self.resolve_dnskey(resolver, &domain).await,
            RecordType::DS => self.resolve_ds(resolver, &domain).await,
            RecordType::TLSA => self.resolve_tlsa(resolver, &domain).await,
            RecordType::SSHFP => self.resolve_sshfp(resolver, &domain).await,
            RecordType::NAPTR => self.resolve_naptr(resolver, &domain).await,
            RecordType::ANY => self.resolve_any(resolver, &domain).await,
        }
    }

    /// Resolves SRV records for a service.
    ///
    /// # Arguments
    /// * `service` - The service name (e.g., "http", "ldap")
    /// * `protocol` - The protocol (e.g., "tcp", "udp")
    /// * `domain` - The domain name
    /// * `nameserver` - Optional custom nameserver IP
    #[instrument(skip(self), fields(domain = %domain, service = %service, protocol = %protocol))]
    pub async fn resolve_srv(
        &self,
        service: &str,
        protocol: &str,
        domain: &str,
        nameserver: Option<&str>,
    ) -> Result<Vec<DnsRecord>> {
        let custom_resolver;
        let resolver = if let Some(ns) = nameserver {
            custom_resolver = self.create_custom_resolver(ns).await?;
            &custom_resolver
        } else {
            &self.default_resolver
        };
        self.resolve_srv_core(resolver, service, protocol, domain)
            .await
    }

    /// Core SRV resolution against an already-built resolver. Validates the
    /// service/protocol labels (DNS query-injection guard) then queries
    /// `_service._proto.domain`. Shared by the public [`resolve_srv`] entry
    /// point and the `dig`-style SRV path in [`resolve`]. Label-validation
    /// failures are [`SeerError::InvalidInput`] — they are caller mistakes, not
    /// transient DNS failures, so they must not be advertised as retryable.
    async fn resolve_srv_core(
        &self,
        resolver: &TokioResolver,
        service: &str,
        protocol: &str,
        domain: &str,
    ) -> Result<Vec<DnsRecord>> {
        if !is_valid_srv_label(service) {
            return Err(SeerError::InvalidInput(format!(
                "invalid SRV service name: {}",
                service
            )));
        }
        if !is_valid_srv_label(protocol) {
            return Err(SeerError::InvalidInput(format!(
                "invalid SRV protocol name: {}",
                protocol
            )));
        }

        let query_name = format!("_{}._{}.{}", service, protocol, domain);

        let Some(response) = dns_lookup_or_empty(
            resolver.lookup(&query_name, HickoryRecordType::SRV).await,
            "SRV",
        )?
        else {
            return Ok(vec![]);
        };

        let records = response
            .answers()
            .iter()
            .filter_map(|record| {
                if let HickoryRData::SRV(srv) = &record.data {
                    Some(DnsRecord {
                        name: query_name.clone(),
                        record_type: RecordType::SRV,
                        ttl: record.ttl,
                        data: RecordData::SRV {
                            priority: srv.priority,
                            weight: srv.weight,
                            port: srv.port,
                            target: srv.target.to_string(),
                        },
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(records)
    }

    async fn resolve_a(&self, resolver: &TokioResolver, domain: &str) -> Result<Vec<DnsRecord>> {
        let Some(response) =
            dns_lookup_or_empty(resolver.lookup(domain, HickoryRecordType::A).await, "A")?
        else {
            return Ok(vec![]);
        };

        let records = response
            .answers()
            .iter()
            .filter_map(|record| {
                if let HickoryRData::A(addr) = &record.data {
                    Some(DnsRecord {
                        name: domain.to_string(),
                        record_type: RecordType::A,
                        ttl: record.ttl,
                        data: RecordData::A {
                            address: addr.0.to_string(),
                        },
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(records)
    }

    async fn resolve_aaaa(&self, resolver: &TokioResolver, domain: &str) -> Result<Vec<DnsRecord>> {
        let Some(response) = dns_lookup_or_empty(
            resolver.lookup(domain, HickoryRecordType::AAAA).await,
            "AAAA",
        )?
        else {
            return Ok(vec![]);
        };

        let records = response
            .answers()
            .iter()
            .filter_map(|record| {
                if let HickoryRData::AAAA(addr) = &record.data {
                    Some(DnsRecord {
                        name: domain.to_string(),
                        record_type: RecordType::AAAA,
                        ttl: record.ttl,
                        data: RecordData::AAAA {
                            address: addr.0.to_string(),
                        },
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(records)
    }

    async fn resolve_cname(
        &self,
        resolver: &TokioResolver,
        domain: &str,
    ) -> Result<Vec<DnsRecord>> {
        let Some(response) = dns_lookup_or_empty(
            resolver.lookup(domain, HickoryRecordType::CNAME).await,
            "CNAME",
        )?
        else {
            return Ok(vec![]);
        };

        let records = response
            .answers()
            .iter()
            .filter_map(|record| {
                if let HickoryRData::CNAME(cname) = &record.data {
                    Some(DnsRecord {
                        name: domain.to_string(),
                        record_type: RecordType::CNAME,
                        ttl: record.ttl,
                        data: RecordData::CNAME {
                            target: cname.0.to_string(),
                        },
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(records)
    }

    async fn resolve_mx(&self, resolver: &TokioResolver, domain: &str) -> Result<Vec<DnsRecord>> {
        let Some(response) =
            dns_lookup_or_empty(resolver.lookup(domain, HickoryRecordType::MX).await, "MX")?
        else {
            return Ok(vec![]);
        };

        let mut records: Vec<DnsRecord> = response
            .answers()
            .iter()
            .filter_map(|record| {
                if let HickoryRData::MX(mx) = &record.data {
                    Some(DnsRecord {
                        name: domain.to_string(),
                        record_type: RecordType::MX,
                        ttl: record.ttl,
                        data: RecordData::MX {
                            preference: mx.preference,
                            exchange: mx.exchange.to_string(),
                        },
                    })
                } else {
                    None
                }
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

    async fn resolve_ns(&self, resolver: &TokioResolver, domain: &str) -> Result<Vec<DnsRecord>> {
        let Some(response) =
            dns_lookup_or_empty(resolver.lookup(domain, HickoryRecordType::NS).await, "NS")?
        else {
            return Ok(vec![]);
        };

        let records = response
            .answers()
            .iter()
            .filter_map(|record| {
                if let HickoryRData::NS(ns) = &record.data {
                    Some(DnsRecord {
                        name: domain.to_string(),
                        record_type: RecordType::NS,
                        ttl: record.ttl,
                        data: RecordData::NS {
                            nameserver: ns.0.to_string(),
                        },
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(records)
    }

    async fn resolve_txt(&self, resolver: &TokioResolver, domain: &str) -> Result<Vec<DnsRecord>> {
        let Some(response) =
            dns_lookup_or_empty(resolver.lookup(domain, HickoryRecordType::TXT).await, "TXT")?
        else {
            return Ok(vec![]);
        };

        let records = response
            .answers()
            .iter()
            .filter_map(|record| {
                if let HickoryRData::TXT(txt) = &record.data {
                    let text = txt
                        .txt_data
                        .iter()
                        .map(|data| String::from_utf8_lossy(data).to_string())
                        .collect::<Vec<_>>()
                        .join("");

                    Some(DnsRecord {
                        name: domain.to_string(),
                        record_type: RecordType::TXT,
                        ttl: record.ttl,
                        data: RecordData::TXT { text },
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(records)
    }

    async fn resolve_soa(&self, resolver: &TokioResolver, domain: &str) -> Result<Vec<DnsRecord>> {
        let Some(response) =
            dns_lookup_or_empty(resolver.lookup(domain, HickoryRecordType::SOA).await, "SOA")?
        else {
            return Ok(vec![]);
        };

        let records = response
            .answers()
            .iter()
            .filter_map(|record| {
                if let HickoryRData::SOA(soa) = &record.data {
                    Some(DnsRecord {
                        name: domain.to_string(),
                        record_type: RecordType::SOA,
                        ttl: record.ttl,
                        data: RecordData::SOA {
                            mname: soa.mname.to_string(),
                            rname: soa.rname.to_string(),
                            serial: soa.serial,
                            // hickory models refresh/retry/expire as i32, but
                            // they are unsigned 32-bit wire intervals. A value
                            // >= 2^31 arrives as a negative i32; `try_into()`
                            // would fail and zero it out, hiding the real
                            // (large) value. `as u32` reinterprets the bits to
                            // the correct unsigned value instead.
                            refresh: soa.refresh as u32,
                            retry: soa.retry as u32,
                            expire: soa.expire as u32,
                            minimum: soa.minimum,
                        },
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(records)
    }

    async fn resolve_ptr(&self, resolver: &TokioResolver, query: &str) -> Result<Vec<DnsRecord>> {
        // If it's an IP address, convert to reverse DNS format
        let query = if let Ok(ip) = IpAddr::from_str(query) {
            reverse_dns_name(&ip)
        } else {
            query.to_string()
        };

        let Some(response) =
            dns_lookup_or_empty(resolver.lookup(&query, HickoryRecordType::PTR).await, "PTR")?
        else {
            return Ok(vec![]);
        };

        let records = response
            .answers()
            .iter()
            .filter_map(|record| {
                if let HickoryRData::PTR(ptr) = &record.data {
                    Some(DnsRecord {
                        name: query.clone(),
                        record_type: RecordType::PTR,
                        ttl: record.ttl,
                        data: RecordData::PTR {
                            target: ptr.0.to_string(),
                        },
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(records)
    }

    async fn resolve_caa(&self, resolver: &TokioResolver, domain: &str) -> Result<Vec<DnsRecord>> {
        let Some(response) =
            dns_lookup_or_empty(resolver.lookup(domain, HickoryRecordType::CAA).await, "CAA")?
        else {
            return Ok(vec![]);
        };

        let records = response
            .answers()
            .iter()
            .filter_map(|record| {
                if let HickoryRData::CAA(caa) = &record.data {
                    let (flags, tag, value) = parse_caa(caa);
                    Some(DnsRecord {
                        name: domain.to_string(),
                        record_type: RecordType::CAA,
                        ttl: record.ttl,
                        data: RecordData::CAA { flags, tag, value },
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(records)
    }

    async fn resolve_dnskey(
        &self,
        resolver: &TokioResolver,
        domain: &str,
    ) -> Result<Vec<DnsRecord>> {
        use hickory_resolver::proto::dnssec::rdata::DNSSECRData;

        let Some(response) = dns_lookup_or_empty(
            resolver.lookup(domain, HickoryRecordType::DNSKEY).await,
            "DNSKEY",
        )?
        else {
            return Ok(vec![]);
        };

        let records = response
            .answers()
            .iter()
            .filter_map(|record| {
                if let HickoryRData::DNSSEC(DNSSECRData::DNSKEY(dnskey)) = &record.data {
                    use base64::{engine::general_purpose::STANDARD, Engine};
                    let public_key_buf = dnskey.public_key();
                    let public_key = STANDARD.encode(public_key_buf.public_bytes());
                    Some(DnsRecord {
                        name: domain.to_string(),
                        record_type: RecordType::DNSKEY,
                        ttl: record.ttl,
                        data: RecordData::DNSKEY {
                            flags: dnskey.flags(),
                            // Protocol is always 3 for DNSSEC (RFC 4034)
                            protocol: 3,
                            algorithm: u8::from(public_key_buf.algorithm()),
                            public_key,
                        },
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(records)
    }

    async fn resolve_ds(&self, resolver: &TokioResolver, domain: &str) -> Result<Vec<DnsRecord>> {
        use hickory_resolver::proto::dnssec::rdata::DNSSECRData;

        let Some(response) =
            dns_lookup_or_empty(resolver.lookup(domain, HickoryRecordType::DS).await, "DS")?
        else {
            return Ok(vec![]);
        };

        let records = response
            .answers()
            .iter()
            .filter_map(|record| {
                if let HickoryRData::DNSSEC(DNSSECRData::DS(ds)) = &record.data {
                    let digest = ds
                        .digest()
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<String>();
                    Some(DnsRecord {
                        name: domain.to_string(),
                        record_type: RecordType::DS,
                        ttl: record.ttl,
                        data: RecordData::DS {
                            key_tag: ds.key_tag(),
                            algorithm: u8::from(ds.algorithm()),
                            digest_type: u8::from(ds.digest_type()),
                            digest,
                        },
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(records)
    }

    async fn resolve_tlsa(&self, resolver: &TokioResolver, domain: &str) -> Result<Vec<DnsRecord>> {
        // TLSA queries are how DANE clients discover the certificate
        // association data for a TLS endpoint. The convention is
        // `_<port>._<proto>.<host>` (e.g. `_443._tcp.example.com`); seer
        // does not enforce the label shape because TLSA is also used for
        // other transports.
        let Some(response) = dns_lookup_or_empty(
            resolver.lookup(domain, HickoryRecordType::TLSA).await,
            "TLSA",
        )?
        else {
            return Ok(vec![]);
        };

        let records = response
            .answers()
            .iter()
            .filter_map(|record| {
                if let HickoryRData::TLSA(tlsa) = &record.data {
                    let cert_data = tlsa
                        .cert_data
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<String>();
                    Some(DnsRecord {
                        name: domain.to_string(),
                        record_type: RecordType::TLSA,
                        ttl: record.ttl,
                        data: RecordData::TLSA {
                            cert_usage: u8::from(tlsa.cert_usage),
                            selector: u8::from(tlsa.selector),
                            matching: u8::from(tlsa.matching),
                            cert_data,
                        },
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(records)
    }

    async fn resolve_sshfp(
        &self,
        resolver: &TokioResolver,
        domain: &str,
    ) -> Result<Vec<DnsRecord>> {
        let Some(response) = dns_lookup_or_empty(
            resolver.lookup(domain, HickoryRecordType::SSHFP).await,
            "SSHFP",
        )?
        else {
            return Ok(vec![]);
        };

        let records = response
            .answers()
            .iter()
            .filter_map(|record| {
                if let HickoryRData::SSHFP(sshfp) = &record.data {
                    let fingerprint = sshfp
                        .fingerprint
                        .iter()
                        .map(|b| format!("{:02X}", b))
                        .collect::<String>();
                    Some(DnsRecord {
                        name: domain.to_string(),
                        record_type: RecordType::SSHFP,
                        ttl: record.ttl,
                        data: RecordData::SSHFP {
                            algorithm: u8::from(sshfp.algorithm),
                            fingerprint_type: u8::from(sshfp.fingerprint_type),
                            fingerprint,
                        },
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(records)
    }

    async fn resolve_naptr(
        &self,
        resolver: &TokioResolver,
        domain: &str,
    ) -> Result<Vec<DnsRecord>> {
        let Some(response) = dns_lookup_or_empty(
            resolver.lookup(domain, HickoryRecordType::NAPTR).await,
            "NAPTR",
        )?
        else {
            return Ok(vec![]);
        };

        let records = response
            .answers()
            .iter()
            .filter_map(|record| {
                if let HickoryRData::NAPTR(naptr) = &record.data {
                    Some(DnsRecord {
                        name: domain.to_string(),
                        record_type: RecordType::NAPTR,
                        ttl: record.ttl,
                        // flags/services/regexp are DNS <character-string>s
                        // (raw bytes); they are conventionally ASCII, so a
                        // lossy decode is a faithful, panic-free rendering.
                        data: RecordData::NAPTR {
                            order: naptr.order,
                            preference: naptr.preference,
                            flags: String::from_utf8_lossy(&naptr.flags).into_owned(),
                            services: String::from_utf8_lossy(&naptr.services).into_owned(),
                            regexp: String::from_utf8_lossy(&naptr.regexp).into_owned(),
                            replacement: naptr.replacement.to_string(),
                        },
                    })
                } else {
                    None
                }
            })
            .collect();

        Ok(records)
    }

    async fn resolve_any(&self, resolver: &TokioResolver, domain: &str) -> Result<Vec<DnsRecord>> {
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

        // Track whether any sub-query actually succeeded (an empty answer
        // for an existing domain still counts as success). If every type
        // errored — e.g. the resolver is unreachable — surface that error
        // rather than returning an empty set that reads as "no records".
        let mut any_ok = false;
        let mut last_err = None;
        for record_type in record_types {
            match self.resolve_type(resolver, domain, record_type).await {
                Ok(records) => {
                    any_ok = true;
                    all_records.extend(records);
                }
                Err(e) => last_err = Some(e),
            }
        }

        match last_err {
            Some(e) if !any_ok => Err(e),
            _ => Ok(all_records),
        }
    }

    async fn resolve_type(
        &self,
        resolver: &TokioResolver,
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

/// Whether a domain appears to exist in the public DNS. Used as a
/// corroborating availability signal when registry data (RDAP/WHOIS) is
/// inconclusive — e.g. a thin/blocked WHOIS body and an RDAP failure that is
/// not an authoritative 404.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsPresence {
    /// The apex returned NS records — the domain is delegated and exists.
    Present,
    /// NXDOMAIN / empty answer — the domain has no DNS presence.
    Absent,
    /// The DNS query itself failed; presence is unknown.
    Unknown,
}

/// Maps an apex NS lookup result to a [`DnsPresence`]. Pure so the mapping is
/// unit-testable without a live resolver. `resolve(.., NS, ..)` already folds
/// NXDOMAIN/NODATA into `Ok(vec![])` (see `dns_lookup_or_empty`), so an empty
/// `Ok` is the "no presence" signal and an `Err` is a genuine query failure.
fn classify_ns_presence(result: &Result<Vec<DnsRecord>>) -> DnsPresence {
    match result {
        Ok(records) if records.is_empty() => DnsPresence::Absent,
        Ok(_) => DnsPresence::Present,
        Err(_) => DnsPresence::Unknown,
    }
}

impl DnsResolver {
    /// Probes whether a domain has any DNS presence by querying its apex NS
    /// records. A registered, delegated domain returns NS records; an
    /// unregistered domain returns NXDOMAIN (an empty record set).
    ///
    /// This is a heuristic, not proof: a registered-but-undelegated domain
    /// also has no NS records, so callers should treat
    /// [`DnsPresence::Absent`] as "likely available" (medium confidence).
    pub async fn presence(&self, domain: &str) -> DnsPresence {
        classify_ns_presence(&self.resolve(domain, RecordType::NS, None).await)
    }
}

// Domain normalization is now handled by the shared validation module

/// Prepares the query string for a DNS lookup.
///
/// PTR queries may be given a raw IP literal. IPv6 literals in particular must
/// NOT pass through [`normalize_domain`]: its trailing-`:port` strip heuristic
/// truncates the final hextet (e.g. `::1111` → dropped) and the remaining `:`
/// separators then fail character validation, so IPv6 reverse lookups errored
/// out with "Invalid domain name" before ever reaching `resolve_ptr`. For PTR
/// queries we therefore detect an IP literal up front and pass it through in
/// canonical form; everything else (domains, and PTR queries given a
/// reverse-DNS name such as `1.1.1.1.in-addr.arpa`) is normalized as usual.
fn prepare_query(domain: &str, record_type: RecordType) -> Result<String> {
    if record_type == RecordType::PTR {
        if let Ok(ip) = IpAddr::from_str(domain.trim()) {
            return Ok(ip.to_string());
        }
    }
    normalize_domain(domain)
}

/// Parses a `dig`-style SRV query name of the form `_service._proto.name` into
/// its `(service, protocol, name)` parts, with the leading underscores
/// stripped. Returns `None` when the input is not in that shape — e.g. a bare
/// domain with no service/proto labels — so callers can surface a usage hint.
fn parse_srv_query(name: &str) -> Option<(String, String, String)> {
    let mut parts = name.splitn(3, '.');
    let service = parts.next()?.strip_prefix('_')?;
    let protocol = parts.next()?.strip_prefix('_')?;
    let rest = parts.next()?;
    if service.is_empty() || protocol.is_empty() || rest.is_empty() {
        return None;
    }
    Some((service.to_string(), protocol.to_string(), rest.to_string()))
}

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
                    result
                        .push(char::from_digit(nibble as u32, 16).expect("nibble is always 0-15"));
                }
            }
            result.push_str(".ip6.arpa");
            result
        }
    }
}

fn parse_caa(caa: &CAA) -> (u8, String, String) {
    // hickory 0.26: CAA fields are public. `issuer_critical` and `tag` are
    // plain fields; `value` is a `Vec<u8>` because RFC 8659 permits binary
    // values for unknown property types. For seer's reporting purposes the
    // common tags (issue/issuewild/iodef) are always UTF-8, so a lossy
    // conversion preserves prior behavior without panicking on the rare
    // binary case.
    let flags = if caa.issuer_critical { 128 } else { 0 };
    let tag = caa.tag.clone();
    let value = String::from_utf8_lossy(&caa.value).to_string();
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

#[cfg(test)]
mod tests {
    //! Unit tests for the pure helpers and public surface of the DNS
    //! resolver. Tests that would exercise the hickory wire protocol
    //! are covered by live-network tests marked `#[ignore]` in the
    //! sibling modules (`dns/dnssec.rs`, `dns/follow.rs`). Deeper
    //! coverage of `resolve_*` paths would require a hickory mock,
    //! which is out of scope for this module.
    //
    // TODO: mock hickory resolver for full path coverage.

    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // --- RecordType::from_str edge cases -----------------------------

    #[test]
    fn record_type_from_str_accepts_lowercase() {
        assert_eq!(RecordType::from_str("a").unwrap(), RecordType::A);
        assert_eq!(RecordType::from_str("mx").unwrap(), RecordType::MX);
        assert_eq!(RecordType::from_str("cname").unwrap(), RecordType::CNAME);
        assert_eq!(RecordType::from_str("dnskey").unwrap(), RecordType::DNSKEY);
    }

    #[test]
    fn record_type_from_str_accepts_mixed_case() {
        assert_eq!(RecordType::from_str("Mx").unwrap(), RecordType::MX);
        assert_eq!(RecordType::from_str("cNaMe").unwrap(), RecordType::CNAME);
    }

    #[test]
    fn record_type_from_str_rejects_whitespace_padded() {
        // No trim is done inside from_str; leading/trailing whitespace
        // must currently cause a parse error so callers don't pass
        // malformed labels through.
        assert!(RecordType::from_str(" A").is_err());
        assert!(RecordType::from_str("A ").is_err());
        assert!(RecordType::from_str("\tA\n").is_err());
    }

    #[test]
    fn record_type_from_str_rejects_unknown() {
        assert!(RecordType::from_str("NOTAREAL").is_err());
        assert!(RecordType::from_str("A1").is_err());
        assert!(RecordType::from_str("").is_err());
    }

    #[test]
    fn record_type_from_str_accepts_star_as_any() {
        assert_eq!(RecordType::from_str("*").unwrap(), RecordType::ANY);
        assert_eq!(RecordType::from_str("ANY").unwrap(), RecordType::ANY);
        assert_eq!(RecordType::from_str("any").unwrap(), RecordType::ANY);
    }

    // --- is_valid_srv_label ------------------------------------------

    #[test]
    fn srv_label_accepts_alphanumeric_and_hyphen() {
        assert!(is_valid_srv_label("http"));
        assert!(is_valid_srv_label("ldap-tls"));
        assert!(is_valid_srv_label("a1"));
        assert!(is_valid_srv_label("tcp"));
    }

    #[test]
    fn srv_label_rejects_empty() {
        assert!(!is_valid_srv_label(""));
    }

    #[test]
    fn srv_label_rejects_leading_or_trailing_hyphen() {
        assert!(!is_valid_srv_label("-http"));
        assert!(!is_valid_srv_label("http-"));
        assert!(!is_valid_srv_label("-"));
    }

    #[test]
    fn srv_label_rejects_dots() {
        // Dots would let an attacker construct `_service._tcp.evil.com.target`
        // and pivot the query to a different domain.
        assert!(!is_valid_srv_label("http.evil"));
        assert!(!is_valid_srv_label("a.b"));
    }

    #[test]
    fn srv_label_rejects_special_chars() {
        assert!(!is_valid_srv_label("http evil"));
        assert!(!is_valid_srv_label("http/evil"));
        assert!(!is_valid_srv_label("http\0"));
        assert!(!is_valid_srv_label("http\n"));
    }

    #[test]
    fn srv_label_rejects_over_63_chars() {
        let too_long = "a".repeat(64);
        assert!(!is_valid_srv_label(&too_long));
        let exactly_63 = "a".repeat(63);
        assert!(is_valid_srv_label(&exactly_63));
    }

    // --- classify_ns_presence ----------------------------------------

    #[test]
    fn classify_ns_presence_absent_on_empty_ok() {
        // resolve(.., NS) folds NXDOMAIN/NODATA into Ok(vec![]).
        let r: Result<Vec<DnsRecord>> = Ok(vec![]);
        assert_eq!(classify_ns_presence(&r), DnsPresence::Absent);
    }

    #[test]
    fn classify_ns_presence_present_on_records() {
        let rec = DnsRecord {
            name: "example.test.".to_string(),
            record_type: RecordType::NS,
            ttl: 3600,
            data: RecordData::NS {
                nameserver: "ns1.example.net.".to_string(),
            },
        };
        let r: Result<Vec<DnsRecord>> = Ok(vec![rec]);
        assert_eq!(classify_ns_presence(&r), DnsPresence::Present);
    }

    #[test]
    fn classify_ns_presence_unknown_on_error() {
        let r: Result<Vec<DnsRecord>> = Err(SeerError::DnsError("servfail".to_string()));
        assert_eq!(classify_ns_presence(&r), DnsPresence::Unknown);
    }

    // --- reverse_dns_name --------------------------------------------

    #[test]
    fn reverse_dns_name_formats_ipv4_correctly() {
        let ip: IpAddr = Ipv4Addr::new(192, 0, 2, 1).into();
        assert_eq!(reverse_dns_name(&ip), "1.2.0.192.in-addr.arpa");
    }

    #[test]
    fn reverse_dns_name_formats_ipv6_correctly() {
        // ::1 (loopback) → 32 nibbles of 0 followed by ...0.0.0.1 reversed.
        let ip: IpAddr = Ipv6Addr::LOCALHOST.into();
        let name = reverse_dns_name(&ip);
        assert!(
            name.ends_with(".ip6.arpa"),
            "must end with .ip6.arpa; got: {}",
            name
        );
        // The first nibble (most-reversed position) must be 1 (from ::1 low bit).
        assert!(
            name.starts_with("1."),
            "expected '1.' prefix, got: {}",
            name
        );
        // 32 nibbles + 31 dots + ".ip6.arpa" (9 chars) = 72.
        assert_eq!(name.len(), 72);
    }

    // --- DnsResolver construction ------------------------------------

    #[test]
    fn resolver_new_has_default_timeout() {
        let r = DnsResolver::new();
        assert_eq!(r.timeout, DEFAULT_TIMEOUT);
    }

    #[test]
    fn resolver_with_timeout_overrides_default() {
        let custom = Duration::from_secs(42);
        let r = DnsResolver::new().with_timeout(custom);
        assert_eq!(r.timeout, custom);
    }

    #[test]
    fn resolver_default_matches_new() {
        let a = DnsResolver::default();
        let b = DnsResolver::new();
        assert_eq!(a.timeout, b.timeout);
    }

    // --- create_custom_resolver validation ---------------------------

    #[tokio::test]
    async fn custom_resolver_rejects_invalid_input() {
        // After hostname support was added, a string that is neither a
        // valid IP nor a resolvable hostname should fail with a clear
        // "failed to resolve" error rather than panicking or hanging.
        // We pick a name that is *syntactically* impossible to resolve.
        let r = DnsResolver::new();
        let err = r.create_custom_resolver("..").await.unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("dns resolution failed") || msg.contains("invalid"),
            "expected resolution failure, got: {}",
            msg
        );
    }

    #[tokio::test]
    async fn custom_resolver_rejects_private_ipv4() {
        // SSRF defense: private / reserved ranges must be blocked even
        // when passed as a literal IP rather than a hostname.
        let r = DnsResolver::new();
        for reserved in ["127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254"] {
            let err = r.create_custom_resolver(reserved).await.unwrap_err();
            let msg = err.to_string().to_lowercase();
            assert!(
                msg.contains("blocked") || msg.contains("reserved"),
                "reserved IP {} must be rejected, got error: {}",
                reserved,
                msg
            );
        }
    }

    #[tokio::test]
    async fn custom_resolver_rejects_loopback_ipv6() {
        let r = DnsResolver::new();
        let err = r.create_custom_resolver("::1").await.unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("blocked") || msg.contains("reserved"),
            "::1 must be rejected, got error: {}",
            msg
        );
    }

    #[tokio::test]
    async fn custom_resolver_accepts_public_ipv4() {
        // A known public resolver IP must be acceptable.
        let r = DnsResolver::new();
        let result = r.create_custom_resolver("8.8.8.8").await;
        assert!(
            result.is_ok(),
            "8.8.8.8 must be accepted as a public nameserver, got: {:?}",
            result.err()
        );
    }

    // --- SRV query validation (integration between helper + resolver) ----

    #[tokio::test]
    async fn resolve_srv_rejects_invalid_service_label() {
        let r = DnsResolver::new();
        // With_dot service name would construct a malformed DNS query.
        let result = r.resolve_srv("http.evil", "tcp", "example.com", None).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string().to_lowercase();
        assert!(
            msg.contains("invalid srv service"),
            "expected SRV service validation error, got: {}",
            msg
        );
    }

    #[tokio::test]
    async fn resolve_srv_rejects_invalid_protocol_label() {
        let r = DnsResolver::new();
        let result = r.resolve_srv("http", "tcp.evil", "example.com", None).await;
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string().to_lowercase();
        assert!(
            msg.contains("invalid srv protocol"),
            "expected SRV protocol validation error, got: {}",
            msg
        );
    }

    // --- Normalization applied before resolution ---------------------

    #[tokio::test]
    async fn resolve_normalizes_uppercase_domain_input() {
        // We can't hit the network in unit tests, but we can at least
        // assert that normalization rejects clearly-invalid input
        // before any network call is made. Domains with a leading `.`
        // are rejected by the normalizer.
        let r = DnsResolver::new();
        let result = r.resolve(".bad.example", RecordType::A, None).await;
        assert!(result.is_err(), "leading-dot domain must be rejected");
    }

    // --- SRV record -------------------------------------------------

    // --- SRV via dig-style names (parse_srv_query) -------------------

    #[test]
    fn parse_srv_query_extracts_service_proto_and_name() {
        assert_eq!(
            parse_srv_query("_sip._tcp.example.com"),
            Some((
                "sip".to_string(),
                "tcp".to_string(),
                "example.com".to_string()
            ))
        );
    }

    #[test]
    fn parse_srv_query_keeps_multilabel_domain() {
        assert_eq!(
            parse_srv_query("_sip._tcp.sip.voice.google.com"),
            Some((
                "sip".to_string(),
                "tcp".to_string(),
                "sip.voice.google.com".to_string()
            ))
        );
    }

    #[test]
    fn parse_srv_query_rejects_bare_domain() {
        assert_eq!(parse_srv_query("example.com"), None);
    }

    #[test]
    fn parse_srv_query_rejects_missing_proto_label() {
        // Second label must be an `_proto` label.
        assert_eq!(parse_srv_query("_sip.example.com"), None);
    }

    #[tokio::test]
    async fn resolve_rejects_bare_domain_for_srv_as_input_error() {
        // A bare domain (no _service._proto labels) cannot be an SRV query.
        // This is a usage/input error — NOT a transient DNS failure — so it
        // must surface as InvalidInput (which maps to a permanent, non-retryable
        // signal across the Python/MCP boundary), and still carry the hint.
        let r = DnsResolver::new();
        let err = r
            .resolve("example.com", RecordType::SRV, None)
            .await
            .expect_err("bare-domain SRV must error");
        assert!(
            matches!(err, SeerError::InvalidInput(_)),
            "bare-domain SRV should be an input error, got: {err:?}"
        );
        assert!(err.to_string().contains("_service._proto"));
    }

    #[tokio::test]
    #[ignore = "live network"]
    async fn resolve_srv_via_dig_style_name_returns_records() {
        // _caldavs._tcp.google.com is a long-standing public SRV record
        // (CalDAV discovery → calendar.google.com:443).
        let r = DnsResolver::new();
        let records = r
            .resolve("_caldavs._tcp.google.com", RecordType::SRV, None)
            .await
            .expect("dig-style SRV lookup should succeed");
        assert!(!records.is_empty(), "expected SRV records");
        assert!(records.iter().all(|r| r.record_type == RecordType::SRV));
    }

    #[tokio::test]
    #[ignore = "live network"]
    async fn resolve_naptr_returns_records() {
        // sip2sip.info publishes stable NAPTR records for SIP discovery.
        let r = DnsResolver::new();
        let records = r
            .resolve("sip2sip.info", RecordType::NAPTR, None)
            .await
            .expect("NAPTR lookup should succeed");
        assert!(!records.is_empty(), "expected NAPTR records");
        assert!(records.iter().all(|r| r.record_type == RecordType::NAPTR));
    }

    // --- prepare_query: PTR must accept raw IP literals (incl. IPv6) --

    #[test]
    fn prepare_query_passes_ipv6_literal_through_for_ptr() {
        // Regression: normalize_domain's port-strip heuristic mangled IPv6
        // literals (the trailing `:1111` group looks like a `:port`), so IPv6
        // reverse lookups failed with "Invalid domain name" before ever
        // reaching resolve_ptr. PTR queries for IP literals must bypass domain
        // normalization.
        let out = prepare_query("2606:4700:4700::1111", RecordType::PTR).unwrap();
        assert_eq!(out, "2606:4700:4700::1111");
    }

    #[test]
    fn prepare_query_passes_ipv6_loopback_through_for_ptr() {
        let out = prepare_query("::1", RecordType::PTR).unwrap();
        assert_eq!(out, "::1");
    }

    #[test]
    fn prepare_query_passes_ipv4_literal_through_for_ptr() {
        let out = prepare_query("8.8.8.8", RecordType::PTR).unwrap();
        assert_eq!(out, "8.8.8.8");
    }

    #[test]
    fn prepare_query_normalizes_non_ip_ptr_names() {
        // A reverse-DNS name (not an IP literal) still gets normalized.
        let out = prepare_query("1.1.1.1.in-addr.arpa", RecordType::PTR).unwrap();
        assert_eq!(out, "1.1.1.1.in-addr.arpa");
    }

    #[test]
    fn prepare_query_normalizes_domains_for_non_ptr() {
        let out = prepare_query("HTTPS://WWW.Example.com/path", RecordType::A).unwrap();
        assert_eq!(out, "example.com");
    }
}
