#![warn(missing_docs)]
//! # porkbun-api
//!
//! this crate provides an async implementation of [porkbun](https://porkbun.com)'s domain management [api](https://porkbun.com/api/json/v3/documentation).
//! It provides a transport-agnostic [Client], and a [DefaultTransport] based on hyper suitable for use in tokio-based applications.
//!
//! ## example
//!
//! ```
//! #[tokio::main]
//! async fn main() -> porkbun_api::Result<()> {
//!     let api_key = porkbun_api::ApiKey::new("secret", "api_key");
//!     let client = porkbun_api::Client::new(api_key);
//!
//!     let domain = &client.domains().await?[0].domain;
//!     let subdomain = Some("my.ip");
//!     let my_ip = client.ping().await?;
//!     let record = CreateOrEditDnsRecord::A_or_AAAA(subdomain, my_ip);
//!     let id = client.create(domain, record).await?;
//!     println!("added record {id}");
//!     client.delete(domain, &id).await?;
//!     println!("removed record {id}");
//!     Ok(())
//! }
//! ```
//!
//! ## Features
//!
//! - `default-client` enabled by default. Includes a default transport layer implementation for the [Client]. This can be disabled if you are implementing your own.
//!
//! ## known issues with the porkbun api
//!
//! Hostnames are a subset of DNS names. `🦆.example.com` is a valid DNS name for example, but it is not a valid hostname.
//! The porkbun api _will_ let you set an entry for `🦆.example.com`, but if you then try to query it, it will be returned as `??.example.com`. This is an issue with the porkbun servers.
//!
//! Also, the porkbun api server can also be quite slow, sometimes taking several seconds before it accepts an api call. Keep this in mind when integrating this library within a larger application.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
mod serde_util;

pub mod transport;
#[cfg(feature = "default-client")]
use transport::DefaultTransport;
use transport::MakeRequest;
mod error;
pub use error::Error;
use error::{ApiErrorMessage, ApiResponse, ErrorImpl};
mod uri;

use chrono::NaiveDateTime;
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Body, Bytes},
    Request, StatusCode, Uri,
};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    collections::HashMap,
    fmt::Display,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

/// Holds the credentials needed to access the API
#[derive(Deserialize, Serialize, Clone)]
pub struct ApiKey {
    secretapikey: String,
    apikey: String,
}

impl ApiKey {
    /// Creates a new [ApiKey] from the given API secret and API key.
    pub fn new(secret: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            secretapikey: secret.into(),
            apikey: api_key.into(),
        }
    }
}

/// Valid DNS record types
#[allow(missing_docs)]
#[derive(Clone, Copy, Deserialize, Serialize, Debug, PartialEq, Eq)]
pub enum DnsRecordType {
    A,
    MX,
    CNAME,
    ALIAS,
    TXT,
    NS,
    AAAA,
    SRV,
    TLSA,
    CAA,
    HTTPS,
    SVCB,
}

impl Display for DnsRecordType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::A => "A",
            Self::MX => "MX",
            Self::CNAME => "CNAME",
            Self::ALIAS => "ALIAS",
            Self::TXT => "TXT",
            Self::NS => "NS",
            Self::AAAA => "AAAA",
            Self::SRV => "SRV",
            Self::TLSA => "TLSA",
            Self::CAA => "CAA",
            Self::HTTPS => "HTTPS",
            Self::SVCB => "SVCB",
        })
    }
}

/// create, or edit with a DNS record with a domain/id pair
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct CreateOrEditDnsRecord<'a> {
    /// The subdomain for the record being created, not including the domain itself. Leave blank to create a record on the root domain. Use * to create a wildcard record.
    #[serde(rename = "name")]
    pub subdomain: Option<&'a str>,
    /// The type of record that should be created
    #[serde(rename = "type")]
    pub record_type: DnsRecordType,
    /// The answer content for the record.
    pub content: Cow<'a, str>,
    /// The time to live in seconds for the record. The minimum and the default is 600 seconds.
    pub ttl: Option<u64>,
    /// The priority of the record for those that support it.
    //these get returned as strings, might be we can set these to non-standard values?
    pub prio: u32,
    // you'd expect a comment field here, but its missing from the api 🥲
    // doesn't seem to be notes, note, or comments
    //todo: ask if there is an api? the web interface seems to use a different api. including one with bulk mgmt
}

impl<'a> CreateOrEditDnsRecord<'a> {
    /// Makes a new [CreateOrEditDnsRecord] for the given subdomain, with the given record type and content.
    pub fn new(
        subdomain: Option<&'a str>,
        record_type: DnsRecordType,
        content: impl Into<Cow<'a, str>>,
    ) -> Self {
        Self {
            subdomain,
            record_type,
            content: content.into(),
            ttl: None,
            prio: 0,
        }
    }
    /// Makes a new [CreateOrEditDnsRecord]  for creating an A-record for the given subdomain, with the given IP address as a response.
    #[allow(non_snake_case)]
    pub fn A(subdomain: Option<&'a str>, ip: Ipv4Addr) -> Self {
        Self::new(subdomain, DnsRecordType::A, Cow::Owned(ip.to_string()))
    }
    /// Makes a new [CreateOrEditDnsRecord] for creating an AAAA-record for the given subdomain, with the given IP address as a response.
    #[allow(non_snake_case)]
    pub fn AAAA(subdomain: Option<&'a str>, ip: Ipv6Addr) -> Self {
        Self::new(subdomain, DnsRecordType::AAAA, Cow::Owned(ip.to_string()))
    }
    /// Makes a new [CreateOrEditDnsRecord] for creating an A- or AAAA-record (depending on the value of the ip address) for the given subdomain, with the given IP address as a response.
    #[allow(non_snake_case)]
    pub fn A_or_AAAA(subdomain: Option<&'a str>, ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(my_ip) => Self::A(subdomain, my_ip),
            IpAddr::V6(my_ip) => Self::AAAA(subdomain, my_ip),
        }
    }

    /// Set the time-to-live for this record.
    /// The minimum and the default is 600 seconds. Any value less than 600 seconds will be rounded up.
    #[must_use]
    pub fn with_ttl(self, ttl: Option<Duration>) -> Self {
        Self {
            ttl: ttl.as_ref().map(Duration::as_secs),
            ..self
        }
    }

    /// Set the priority for this record, for records that support it.
    #[must_use]
    pub fn with_priority(self, prio: u32) -> Self {
        Self { prio, ..self }
    }
}

//create, or edit with a domain/subdomain/type in the url.
// maybe we want to merge this with the CreateOrEditDnsRecord into a single struct with an enum for giving identifier as either
// a domain/id pair or domain/subdomain/type and picking the appropriate url/body in the client
// #[derive(Serialize)]
// struct EditDnsRecordByDomainTypeSubdomain<'a> {
//     pub content: &'a str,
//     /// The time to live in seconds for the record. The minimum and the default is 600 seconds.
//     pub ttl: Option<u32>,
//     pub prio: Option<u32>,
// }

//might be an integer actually but sometimes sends a string
// so we opt to store it as a string just in case it can start with
// a '0'
// todo: ask about this
#[derive(Deserialize, Debug)]
struct EntryId {
    #[serde(with = "serde_util::string_or_int")]
    id: String,
}

/// A DNS entry for a domain, returned by the API
#[derive(Deserialize, Debug)]
pub struct DnsEntry {
    /// the unique ID of this entry
    #[serde(with = "serde_util::string_or_int")]
    pub id: String,
    /// the full name of the entry, e.g. `_atproto.example.com`
    pub name: String,
    /// the type of record, e.g. A or TXT.
    #[serde(rename = "type")]
    pub record_type: DnsRecordType,
    /// the content of this record.
    pub content: String,
    /// the time-to-live of this record
    //string in docs
    #[serde(with = "serde_util::u64_from_string_or_int")]
    pub ttl: u64,
    /// The priority of this record
    //string in docs
    #[serde(default, with = "serde_util::u64_from_string_or_int")]
    pub prio: u64,
    /// Any notes set for this record.
    /// Note that you can not set these from the API itself, you have to do so with the management console on the websiter.
    pub notes: Option<String>,
}

#[derive(Deserialize, Debug)]
struct DnsRecordsByDomainOrIDResponse {
    records: Vec<DnsEntry>,
}

/// The default pricing for the registration, renewal and transfer of a given TLD.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Pricing {
    /// the registration price.
    pub registration: String,
    /// the renewal price.
    pub renewal: String,
    /// the transfer price.
    pub transfer: String,
    /// A field indicating that his is a "special" domain, and if so what kind.
    /// Currently this only valid version seems to be ["handshake"](https://porkbun.com/handshake)
    ///
    /// This field is undocumented by porkbun, but I included it anyways to let people filter out these TLDs.
    //todo: ask
    //undocumented field, helps filter out stupid handshake domains
    pub special_type: TldType,
}

impl Pricing {
    /// returns true if this is a normal ICANN/IANA TLDs like .com, .engineering or .gay
    pub fn is_icann(&self) -> bool {
        self.special_type.is_icann()
    }
}

/// Describes what registry a TLD belongs to.
#[derive(Debug)]
pub enum TldType {
    /// The normal ICANN/IANA TLDs like .com, .engineering or .gay
    /// you probably want one of these
    Normal,
    /// An [experimental blockchain protocol](https://porkbun.com/handshake).
    Handshake,
    /// An unknown registery.
    ///
    /// at the time of writting, porkbun only supports ICANN and Handshake, but this variant exists for future-proofing.
    Other(String),
}

impl TldType {
    /// returns true if this is a normal ICANN/IANA TLDs like .com, .engineering or .gay
    pub fn is_icann(&self) -> bool {
        if let Self::Normal = self {
            true
        } else {
            false
        }
    }
}

impl<'de> Deserialize<'de> for TldType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let string_value = Option::<String>::deserialize(deserializer)?;
        Ok(match string_value {
            None => Self::Normal,
            Some(s) => {
                if s.eq_ignore_ascii_case("handshake") {
                    Self::Handshake
                } else {
                    Self::Other(s)
                }
            }
        })
    }
}

#[derive(Deserialize, Debug)]
struct DomainPricingResponse {
    //tld-to-pricing
    pricing: HashMap<String, Pricing>,
}

#[derive(Serialize, Deserialize)]
struct UpdateNameServers {
    ns: Vec<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DomainListAll {
    /// An index to start at when retrieving the domains, defaults to 0. To get all domains increment by 1000 until you receive an empty array.
    start: usize,
    /// should be "yes"
    #[serde(default, with = "serde_util::yesno")]
    include_labels: bool,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct DomainListAllResponse {
    domains: Vec<DomainInfo>,
}

/// A domain registration returned by the API server
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DomainInfo {
    /// The registered domain, including the TLD
    pub domain: String,
    // usually ACTIVE or..
    /// The status of the domain. "ACTIVE" if active,
    pub status: String,
    /// the TLD of the domain
    pub tld: String,
    /// The date-time this domain was created
    // ask: what is the TZ of this?
    #[serde(with = "serde_util::datetime")]
    pub create_date: NaiveDateTime,
    /// The date-time this domain will expire
    #[serde(with = "serde_util::datetime")]
    pub expire_date: NaiveDateTime,
    /// whether the security lock has been turned on or not
    // docs say these are "1", probably booleans?
    #[serde(with = "serde_util::stringoneintzero")]
    pub security_lock: bool,
    #[serde(with = "serde_util::stringoneintzero")]
    /// whether whois privacy has been turned on or not
    pub whois_privacy: bool,
    /// whether auto-renewal is enabled or not
    // docs say this is a bool, is a string
    #[serde(with = "serde_util::stringoneintzero")]
    pub auto_renew: bool,
    /// whether this is an external domain or not
    #[serde(with = "serde_util::stringoneintzero")]
    pub not_local: bool,
    /// Any labels that have been assigned to this domain from the web interface
    #[serde(default)]
    pub labels: Vec<Label>,
}

/// A label added to a domain.
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Label {
    /// The unique ID of the label
    #[serde(deserialize_with = "serde_util::string_or_int::deserialize")]
    pub id: String,
    /// the name of the label
    pub title: String,
    /// the color of the label (used in the web interface)
    pub color: String,
}

// #[derive(Serialize, Deserialize, Debug)]
// #[serde(rename_all = "camelCase")]
// pub struct DomainAddForwardUrl {
//     #[serde(skip_serializing_if = "Option::is_none")]
//     pub subdomain: Option<String>,
//     pub location: String,
//     #[serde(rename = "type")]
//     pub forward_type: ForwardType,
//     #[serde(with = "serde_util::yesno")]
//     pub include_path: bool,
//     #[serde(with = "serde_util::yesno")]
//     pub wildcard: bool,
// }

// #[derive(Deserialize, Serialize, Debug)]
// #[serde(rename_all = "lowercase")]
// pub enum ForwardType {
//     Temporary,
//     Permanent,
// }

// #[derive(Deserialize, Debug)]
// #[serde(rename_all = "camelCase")]
// struct GetUrlForwardingResponse {
//     forwards: Vec<Forward>,
// }

// #[derive(Deserialize, Debug)]
// #[serde(rename_all = "camelCase")]
// pub struct Forward {
//     #[serde(deserialize_with = "serde_util::string_or_int::deserialize")]
//     pub id: String,
//     #[serde(flatten)]
//     pub forward: DomainAddForwardUrl,
// }

// #[derive(Deserialize, Debug)]
// #[serde(rename_all = "lowercase")]
// pub struct SslBundle {
//     pub certificate_chain: String,
//     pub private_key: String,
//     pub public_key: String,
// }

#[derive(Serialize)]
struct WithApiKeys<'a, T: Serialize> {
    #[serde(flatten)]
    api_key: &'a ApiKey,
    #[serde(flatten)]
    inner: T,
}

/// A client for interfacing with the Porkbun API servers
pub struct Client<P: MakeRequest> {
    inner: P,
    api_key: ApiKey,
}

#[cfg(feature = "default-client")]
impl Client<DefaultTransport> {
    /// creates a new client using the supplied api key and the default transport implementation.
    ///
    /// if you wish to change the transport layer, or you're not using tokio,  use [`new_with_transport`](Client::new_with_transport)
    pub fn new(api_key: ApiKey) -> Self {
        Client::new_with_transport(api_key, DefaultTransport::default())
    }
}

impl<T> Client<T>
where
    T: MakeRequest,
    <T::Body as Body>::Error: Into<T::Error>,
{
    /// creates a new client using the supplied api key and transport.
    ///
    /// if you don't care about the implementation details of the transport, consider using [`new`](Client::new) which uses a default implementation.
    pub fn new_with_transport(api_key: ApiKey, transport: T) -> Self {
        Self {
            inner: transport,
            api_key,
        }
    }
    async fn post<D: for<'a> Deserialize<'a>>(
        &self,
        uri: Uri,
        body: Full<Bytes>,
    ) -> Result<D, Error<T::Error>> {
        let request = Request::post(uri).body(body).unwrap(); //both uri and body are known at this point
        let resp = self
            .inner
            .request(request)
            .await
            .map_err(ErrorImpl::TransportError)?;
        let (head, body) = resp.into_parts();
        let bytes = body
            .collect()
            .await
            .map_err(|e| ErrorImpl::TransportError(e.into()))?
            .to_bytes();
        let result = std::result::Result::<_, ApiErrorMessage>::from(
            serde_json::from_slice::<ApiResponse<_>>(&bytes)
                .map_err(|e| ErrorImpl::DeserializationError(e))?,
        );

        match (head.status, result) {
            (StatusCode::OK, Ok(x)) => Ok(x),
            (status, maybe_message) => Err((status, maybe_message.err()).into()),
        }
    }
    async fn post_with_api_key<S: Serialize, D: for<'a> Deserialize<'a>>(
        &self,
        uri: Uri,
        body: S,
    ) -> Result<D, Error<T::Error>> {
        let with_api_key = WithApiKeys {
            api_key: &self.api_key,
            inner: body,
        };
        let json =
            serde_json::to_string(&with_api_key).map_err(|e| ErrorImpl::SerializationError(e))?;
        let body = http_body_util::Full::new(Bytes::from(json));
        self.post(uri, body).await
    }

    /// pings the api servers returning your ip address.
    pub async fn ping(&self) -> Result<IpAddr, Error<T::Error>> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct PingResponse {
            your_ip: IpAddr,
        }
        let ping: PingResponse = self.post_with_api_key(uri::ping(), ()).await?;
        Ok(ping.your_ip)
    }

    /// Get a mapping of available TLDs to their pricing structure, filtered to only include ICANN TLDs.
    /// This method does not require authentication, and it will work with any [ApiKey].
    pub async fn icann_domain_pricing(
        &self,
    ) -> Result<impl Iterator<Item = (String, Pricing)>, Error<T::Error>> {
        let resp: DomainPricingResponse = self.post(uri::domain_pricing(), Full::default()).await?;
        Ok(resp.pricing.into_iter().filter(|(_, v)| v.is_icann()))
    }

    /// Get a mapping of available TLDs to their pricing structure.
    /// This method does not require authentication, and it will work with any [ApiKey].
    ///
    /// This method includes all TLDs, including special ones like handshake domains.
    /// If you only want ICANN TLDs, and you probably do, use [icann_domain_pricing](Client::icann_domain_pricing) instead.
    pub async fn domain_pricing(&self) -> Result<HashMap<String, Pricing>, Error<T::Error>> {
        let resp: DomainPricingResponse = self.post(uri::domain_pricing(), Full::default()).await?;
        Ok(resp.pricing)
    }

    /// Updates the nameservers for a particular domain
    pub async fn update_nameservers(
        &self,
        domain: &str,
        name_servers: Vec<String>,
    ) -> Result<(), Error<T::Error>> {
        self.post_with_api_key(
            uri::update_name_servers(domain)?,
            UpdateNameServers { ns: name_servers },
        )
        .await
    }

    /// Gets the configured nameservers for a particular domain
    pub async fn nameservers(&self, domain: &str) -> Result<Vec<String>, Error<T::Error>> {
        let resp: UpdateNameServers = self
            .post_with_api_key(uri::get_name_servers(domain)?, ())
            .await?;
        Ok(resp.ns)
    }

    async fn list_domains(&self, offset: usize) -> Result<Vec<DomainInfo>, Error<T::Error>> {
        let resp: DomainListAllResponse = self
            .post_with_api_key(
                uri::domain_list_all(),
                DomainListAll {
                    start: offset,
                    include_labels: true,
                },
            )
            .await?;
        Ok(resp.domains)
    }

    /// get all the domains associated with this account
    pub async fn domains(&self) -> Result<Vec<DomainInfo>, Error<T::Error>> {
        let mut all = self.list_domains(0).await?;
        let mut last_len = all.len();
        // if paginated by 1000, we could probably get away with checking if equal to 1000 and skipping the final check
        while last_len != 0 {
            let next = self.list_domains(all.len()).await?;
            last_len = next.len();
            all.extend(next.into_iter());
        }
        Ok(all)
    }

    // pub async fn add_url_forward(&mut self, domain: &str, cmd: DomainAddForwardUrl) -> Result<()> {
    //     self.post_with_api_key(uri::add_url_forward(domain)?, cmd)
    //         .await
    // }

    // pub async fn get_url_forward(&mut self, domain: &str) -> Result<Vec<Forward>> {
    //     let resp: GetUrlForwardingResponse = self
    //         .post_with_api_key(uri::get_url_forward(domain)?, ())
    //         .await?;
    //     Ok(resp.forwards)
    // }

    // pub async fn delete_url_forward(&mut self, domain: &str, id: &str) -> Result<()> {
    //     self.post_with_api_key(uri::delete_url_forward(domain, id)?, ())
    //         .await
    // }

    /// Create a new DNS record for the given domain.
    /// Will fail if there already exists a record with the same name and type.
    pub async fn create(
        &self,
        domain: &str,
        cmd: CreateOrEditDnsRecord<'_>,
    ) -> Result<String, Error<T::Error>> {
        let resp: EntryId = self
            .post_with_api_key(uri::create_dns_record(domain)?, cmd)
            .await?;
        Ok(resp.id)
    }

    /// Edits an existing DNS record for a given domain, by its unique ID.
    /// IDs can be discovered by first calling [get_all](Client::get_all).
    pub async fn edit(
        &self,
        domain: &str,
        id: &str,
        cmd: CreateOrEditDnsRecord<'_>,
    ) -> Result<(), Error<T::Error>> {
        self.post_with_api_key(uri::edit_dns_record(domain, id)?, cmd)
            .await
    }

    // async fn edit_dns_record_for(
    //     &mut self,
    //     domain: &str,
    //     record_type: DnsRecordType,
    //     subdomain: Option<&str>,
    //     cmd: EditDnsRecordByDomainTypeSubdomain<'_>,
    // ) -> Result<()> {
    //     self.post_with_api_key(
    //         uri::edit_dns_record_for(domain, record_type, subdomain)?,
    //         cmd,
    //     )
    //     .await
    // }

    // async fn delete_dns_record_for(
    //     &mut self,
    //     domain: &str,
    //     record_type: DnsRecordType,
    //     subdomain: Option<&str>,
    // ) -> Result<()> {
    //     self.post_with_api_key(
    //         uri::delete_dns_record_for(domain, record_type, subdomain)?,
    //         (),
    //     )
    //     .await
    // }

    /// Deletes an existing DNS record for a given domain, by its unique ID.
    /// IDs can be discovered by first calling [get_all](Client::get_all).
    pub async fn delete(&self, domain: &str, id: &str) -> Result<(), Error<T::Error>> {
        self.post_with_api_key(uri::delete_dns_record_by_id(domain, id)?, ())
            .await
    }

    /// Gets all the DNS records for a given domain
    pub async fn get_all(&self, domain: &str) -> Result<Vec<DnsEntry>, Error<T::Error>> {
        let rsp: DnsRecordsByDomainOrIDResponse = self
            .post_with_api_key(uri::get_dns_record_by_domain_and_id(domain, None)?, ())
            .await?;
        Ok(rsp.records)
    }

    /// Gets a single DNS record for a given domain, by its unique ID.
    pub async fn get_single(
        &self,
        domain: &str,
        id: &str,
    ) -> Result<Option<DnsEntry>, Error<T::Error>> {
        let rsp: DnsRecordsByDomainOrIDResponse = self
            .post_with_api_key(uri::get_dns_record_by_domain_and_id(&domain, Some(id))?, ())
            .await?;
        let rsp = rsp.records.into_iter().next();
        Ok(rsp)
    }
    // async fn get_dns_record_for(
    //     &mut self,
    //     domain: &str,
    //     record_type: DnsRecordType,
    //     subdomain: Option<&str>,
    // ) -> Result<Vec<DnsEntry>> {
    //     let rsp: DnsRecordsByDomainOrIDResponse = self
    //         .post_with_api_key(uri::get_dns_record_for(domain, record_type, subdomain)?, ())
    //         .await?;
    //     Ok(rsp.records)
    // }

    // async fn get_ssl_bundle(&mut self, domain: &str) -> Result<SslBundle> {
    //     self.post_with_api_key(uri::get_ssl_bundle(domain)?, ())
    //         .await
    // }
}
