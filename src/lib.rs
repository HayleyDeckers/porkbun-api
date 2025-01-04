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
//! ## known issues
//!
//! Hostnames are a subset of DNS names. `🦆.example.com` is a valid DNS name for example, but it is not a valid hostname.
//! The porkbun api _will_ let you set an entry for  `🦆.example.com`, but if you then try to query it, it will be returned as `??.example.com`. This can obvious lead to breakage.
//!
//! The porkbun api server can also be quite slow, sometimes taking several seconds before it accepts an api call. Keep this in mind when integrating this library within a larger application.

#![cfg_attr(docsrs, feature(doc_auto_cfg))]
mod serde_util;

#[cfg(feature = "default-client")]
mod transport;
#[cfg(feature = "default-client")]
pub use transport::DefaultTransport;
mod uri;

use chrono::NaiveDateTime;
use http_body_util::{BodyExt, Full};
use hyper::{
    body::{Body, Bytes},
    Request, Response, StatusCode, Uri,
};
use serde::{Deserialize, Serialize};
use std::{
    borrow::Cow,
    collections::HashMap,
    fmt::Display,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

pub trait MakeRequest: Sized {
    type Body: Body;
    type Error: std::error::Error + Send + Sync + 'static;
    fn request(
        &self,
        request: Request<Full<Bytes>>,
    ) -> impl Future<Output = std::result::Result<Response<Self::Body>, Self::Error>>;
}

#[derive(Deserialize, Serialize, Clone)]
pub struct ApiKey {
    secretapikey: String,
    apikey: String,
}

impl ApiKey {
    pub fn new(secret: impl Into<String>, api_key: impl Into<String>) -> Self {
        Self {
            secretapikey: secret.into(),
            apikey: api_key.into(),
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct ApiError {
    message: String,
}

impl Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(f)
    }
}

impl std::error::Error for ApiError {}

#[derive(Deserialize, Debug)]
#[serde(tag = "status", rename_all = "UPPERCASE")]
enum ApiResponse<T> {
    Success(T),
    Error(ApiError),
}

impl<T> From<ApiResponse<T>> for std::result::Result<T, ApiError> {
    fn from(value: ApiResponse<T>) -> Self {
        match value {
            ApiResponse::Success(s) => Ok(s),
            ApiResponse::Error(e) => Err(e),
        }
    }
}

#[derive(Debug)]
pub enum Error {
    ApiError {
        status: StatusCode,
        error: Option<ApiError>,
    },
    TransportError(Box<dyn std::error::Error + Send + Sync + 'static>),
    SerializationError(serde_json::Error),
    DeserializationError(serde_json::Error),
    InvalidUri(hyper::http::uri::InvalidUri),
}

impl From<(StatusCode, ApiError)> for Error {
    fn from(value: (StatusCode, ApiError)) -> Self {
        Self::ApiError {
            status: value.0,
            error: Some(value.1),
        }
    }
}

impl From<hyper::http::uri::InvalidUri> for Error {
    fn from(value: hyper::http::uri::InvalidUri) -> Self {
        Self::InvalidUri(value)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiError { status, error } => {
                if let Some(error) = error {
                    f.write_fmt(format_args!("[{status}] {error}"))
                } else {
                    f.write_fmt(format_args!("Invalid status code {status}"))
                }
            }
            Self::DeserializationError(_) => f.write_str("failed to deserialize response"),
            Self::SerializationError(_) => f.write_str("failed to serialize request"),
            Self::TransportError(_) => f.write_str("failed to send request or recieve response"),
            Self::InvalidUri(_) => f.write_str("invalid uri"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ApiError { .. } => None,
            Self::TransportError(t) => Some(t.as_ref()),
            Self::SerializationError(s) | Self::DeserializationError(s) => Some(s),
            Self::InvalidUri(u) => Some(u),
        }
    }
}

pub type Result<T> = ::std::result::Result<T, Error>;

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

//create, or edit with a domain/id pair
#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct CreateOrEditDnsRecord<'a> {
    /// The subdomain for the record being created, not including the domain itself. Leave blank to create a record on the root domain. Use * to create a wildcard record.
    #[serde(rename = "name")]
    pub subdomain: Option<&'a str>,
    #[serde(rename = "type")]
    pub record_type: DnsRecordType,
    pub content: Cow<'a, str>,
    /// The time to live in seconds for the record. The minimum and the default is 600 seconds.
    pub ttl: Option<u64>,
    //these get returned as strings, might be we can set these to non-standard values?
    pub prio: u32,
    // you'd expect a comment field here, but its missing from the api 🥲
    // doesn't seem to be notes, note, or comments
    //todo: ask if there is an api? the web interface seems to use a different api. including one with bulk mgmt
}

impl<'a> CreateOrEditDnsRecord<'a> {
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
    #[allow(non_snake_case)]
    pub fn A(subdomain: Option<&'a str>, ip: Ipv4Addr) -> Self {
        Self::new(subdomain, DnsRecordType::A, Cow::Owned(ip.to_string()))
    }
    #[allow(non_snake_case)]
    pub fn AAAA(subdomain: Option<&'a str>, ip: Ipv6Addr) -> Self {
        Self::new(subdomain, DnsRecordType::AAAA, Cow::Owned(ip.to_string()))
    }
    #[allow(non_snake_case)]
    pub fn A_or_AAAA(subdomain: Option<&'a str>, ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(my_ip) => Self::A(subdomain, my_ip),
            IpAddr::V6(my_ip) => Self::AAAA(subdomain, my_ip),
        }
    }

    #[must_use]
    pub fn with_ttl(self, ttl: Option<Duration>) -> Self {
        Self {
            ttl: ttl.as_ref().map(Duration::as_secs),
            ..self
        }
    }

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

#[derive(Deserialize, Debug)]
pub struct DnsEntry {
    #[serde(with = "serde_util::string_or_int")]
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: DnsRecordType,
    pub content: String,
    //string in docs
    #[serde(with = "serde_util::u64_from_string_or_int")]
    pub ttl: u64,
    //string in docs
    #[serde(default, with = "serde_util::u64_from_string_or_int")]
    pub prio: u64,
    pub notes: Option<String>,
}

#[derive(Deserialize, Debug)]
struct DnsRecordsByDomainOrIDResponse {
    records: Vec<DnsEntry>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct PingResponse {
    your_ip: IpAddr,
}
#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum SpecialType {
    Handshake,
    //todo: ask about other known values
    Other(String),
}

//undocumented
// #[derive(Deserialize, Debug)]
// pub struct Coupon {
//     pub amount: usize,
//     pub code: String,
//     #[serde(default, with = "serde_util::yesno")]
//     pub first_year_only: bool,
//     pub max_per_user: Option<usize>,
//     pub r#type: Option<String>,
// }

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Pricing {
    pub registration: String,
    pub renewal: String,
    pub transfer: String,
    //todo: ask
    //undocumented field, helps filter out stupid handshake domains
    pub special_type: Option<SpecialType>,
    // undocumented, todo: ask
    // pub coupons: Vec<Coupon>,
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
    domains: Vec<DomainListAllDomain>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DomainListAllDomain {
    pub domain: String,
    // usually ACTIVE or..
    pub status: String,
    pub tld: String,
    // ask: what is the TZ of this?
    #[serde(with = "serde_util::datetime")]
    pub create_date: NaiveDateTime,
    #[serde(with = "serde_util::datetime")]
    pub expire_date: NaiveDateTime,
    // docs say these are "1", probably booleans?
    #[serde(with = "serde_util::stringoneintzero")]
    pub security_lock: bool,
    #[serde(with = "serde_util::stringoneintzero")]
    pub whois_privacy: bool,
    // docs say this is a bool, is a string
    #[serde(with = "serde_util::stringoneintzero")]
    pub auto_renew: bool,
    #[serde(with = "serde_util::stringoneintzero")]
    pub not_local: bool,
    #[serde(default)]
    pub labels: Vec<Label>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Label {
    #[serde(deserialize_with = "serde_util::string_or_int::deserialize")]
    pub id: String,
    pub title: String,
    pub color: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DomainAddForwardUrl {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subdomain: Option<String>,
    pub location: String,
    #[serde(rename = "type")]
    pub forward_type: ForwardType,
    #[serde(with = "serde_util::yesno")]
    pub include_path: bool,
    #[serde(with = "serde_util::yesno")]
    pub wildcard: bool,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "lowercase")]
pub enum ForwardType {
    Temporary,
    Permanent,
}

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

#[derive(Clone)]
pub struct Client<P: MakeRequest> {
    inner: P,
    api_key: ApiKey,
}

#[cfg(feature = "default-client")]
// #[doc(cfg(feature = "macros"))]
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
    <T::Body as Body>::Error: std::error::Error + Send + Sync + 'static,
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
    async fn post<D: for<'a> Deserialize<'a>>(&self, uri: Uri, body: Full<Bytes>) -> Result<D> {
        let request = Request::post(uri).body(body).unwrap(); //both uri and body are known at this point
        let resp = self
            .inner
            .request(request)
            .await
            .map_err(|e| Error::TransportError(e.into()))?;
        let (head, body) = resp.into_parts();
        let bytes = body
            .collect()
            .await
            .map_err(|e| Error::TransportError(e.into()))?
            .to_bytes();
        let result = std::result::Result::<_, ApiError>::from(
            serde_json::from_slice::<ApiResponse<_>>(&bytes)
                .map_err(|e| Error::DeserializationError(e))?,
        );

        match (head.status, result) {
            (status, Err(error)) => Err(Error::ApiError {
                status,
                error: Some(error),
            }),
            (StatusCode::OK, Ok(x)) => Ok(x),
            (status, Ok(_)) => Err(Error::ApiError {
                status,
                error: None,
            }),
        }
    }
    async fn post_with_api_key<S: Serialize, D: for<'a> Deserialize<'a>>(
        &self,
        uri: Uri,
        body: S,
    ) -> Result<D> {
        let with_api_key = WithApiKeys {
            api_key: &self.api_key,
            inner: body,
        };
        let json =
            serde_json::to_string(&with_api_key).map_err(|e| Error::SerializationError(e))?;
        let body = http_body_util::Full::new(Bytes::from(json));
        self.post(uri, body).await
    }

    /// pings the api servers returning your ip address.
    pub async fn ping(&self) -> Result<IpAddr> {
        let ping: PingResponse = self.post_with_api_key(uri::ping(), ()).await?;
        Ok(ping.your_ip)
    }

    ///
    //note: does not require authentication, can probably be a get?
    pub async fn domain_pricing(&self) -> Result<HashMap<String, Pricing>> {
        let resp: DomainPricingResponse = self.post(uri::domain_pricing(), Full::default()).await?;
        Ok(resp.pricing)
    }

    pub async fn update_nameservers(&self, domain: &str, name_servers: Vec<String>) -> Result<()> {
        self.post_with_api_key(
            uri::update_name_servers(domain)?,
            UpdateNameServers { ns: name_servers },
        )
        .await
    }
    pub async fn nameservers(&self, domain: &str) -> Result<Vec<String>> {
        let resp: UpdateNameServers = self
            .post_with_api_key(uri::get_name_servers(domain)?, ())
            .await?;
        Ok(resp.ns)
    }

    async fn list_domains(&self, offset: usize) -> Result<Vec<DomainListAllDomain>> {
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

    pub async fn domains(&self) -> Result<Vec<DomainListAllDomain>> {
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

    pub async fn create(&self, domain: &str, cmd: CreateOrEditDnsRecord<'_>) -> Result<String> {
        let resp: EntryId = self
            .post_with_api_key(uri::create_dns_record(domain)?, cmd)
            .await?;
        Ok(resp.id)
    }

    pub async fn edit(&self, domain: &str, id: &str, cmd: CreateOrEditDnsRecord<'_>) -> Result<()> {
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

    pub async fn delete(&self, domain: &str, id: &str) -> Result<()> {
        self.post_with_api_key(uri::delete_dns_record_by_id(domain, id)?, ())
            .await
    }

    pub async fn get_all(&self, domain: &str) -> Result<Vec<DnsEntry>> {
        let rsp: DnsRecordsByDomainOrIDResponse = self
            .post_with_api_key(uri::get_dns_record_by_domain_and_id(domain, None)?, ())
            .await?;
        Ok(rsp.records)
    }

    pub async fn get_single(&self, domain: &str, id: &str) -> Result<Option<DnsEntry>> {
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
