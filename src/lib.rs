mod serde_util;
mod uri;

use anyhow::Result;
use http_body_util::BodyExt;
use hyper::{body::Bytes, header::HeaderValue, Request, StatusCode, Uri};
use hyper_tls::HttpsConnector;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client as HyperClient},
    rt::TokioExecutor,
};
use serde::{Deserialize, Serialize};
use std::{
    cell::OnceCell,
    collections::HashMap,
    fmt::Display,
    future::Future,
    net::{IpAddr, Ipv4Addr},
};

#[derive(Deserialize, Serialize)]
pub struct ApiKey {
    secretapikey: String,
    apikey: String,
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

impl<T> From<ApiResponse<T>> for Result<T, ApiError> {
    fn from(value: ApiResponse<T>) -> Self {
        match value {
            ApiResponse::Success(s) => Ok(s),
            ApiResponse::Error(e) => Err(e),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
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
#[derive(Serialize)]
pub struct CreateOrEditDnsRecord {
    /// The subdomain for the record being created, not including the domain itself. Leave blank to create a record on the root domain. Use * to create a wildcard record.
    #[serde(rename = "name")]
    pub subdomain: Option<String>,
    #[serde(rename = "type")]
    pub record_type: DnsRecordType,
    pub content: String,
    /// The time to live in seconds for the record. The minimum and the default is 600 seconds.
    pub ttl: Option<u32>,
    //these get returned as strings, might be we can set these to non-standard values?
    pub prio: Option<u32>,
    //comment?
}

//create, or edit with a domain/subdomain/type in the url.
// maybe we want to merge this with the CreateOrEditDnsRecord into a single struct with an enum for giving identifier as either
// a domain/id pair or domain/subdomain/type and picking the appropriate url/body in the client
#[derive(Serialize)]
pub struct EditDnsRecordByDomainTypeSubdomain {
    pub content: String,
    /// The time to live in seconds for the record. The minimum and the default is 600 seconds.
    pub ttl: Option<u32>,
    pub prio: Option<u32>,
}

//might be an integer actually but sometimes sends a string
// so we opt to store it as a string just in case it can start with
// a '0'
#[derive(Serialize, Deserialize, Debug)]
pub struct EntryId {
    #[serde(deserialize_with = "serde_util::string_or_int::deserialize")]
    id: String,
}

#[derive(Deserialize, Debug)]
pub struct DnsEntry {
    #[serde(deserialize_with = "serde_util::string_or_int::deserialize")]
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: DnsRecordType,
    pub content: String,
    //string in docs
    pub ttl: Option<String>,
    //string in docs
    pub prio: Option<String>,
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
    Other(String),
}

// #[derive(Deserialize, Debug)]
// #[serde(deny_unknown_fields)]
// //undocumented
// pub struct Coupon {
//     pub amount: usize,
//     pub code: String,
//     #[serde(default, with = "yesno")]
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
    //undocumented field, helps filter out stupid handshake domains
    pub special_type: Option<SpecialType>,
    // undocumented
    // pub coupons: Vec<Coupon>,
}

#[derive(Deserialize, Debug)]
struct DomainPricingResponse {
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
pub struct DomainListAllResponse {
    domains: Vec<DomainListAllDomain>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DomainListAllDomain {
    pub domain: String,
    // usually ACTIVE or..
    pub status: String,
    pub tld: String,
    // 2018-08-20 17:52:51
    // todo: use a dateformat here
    pub create_date: String,
    pub expire_date: String,
    // docs say these are "1", probably booleans?
    // "1" on success, 0 on false?
    #[serde(with = "serde_util::stringoneintzero")]
    pub security_lock: bool,
    #[serde(with = "serde_util::stringoneintzero")]
    pub whois_privacy: bool,
    //these are probably bools
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
    //number in the example
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

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct GetUrlForwardingResponse {
    forwards: Vec<Forward>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Forward {
    #[serde(deserialize_with = "serde_util::string_or_int::deserialize")]
    pub id: String,
    #[serde(flatten)]
    pub forward: DomainAddForwardUrl,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub struct SslBundle {
    pub certificate_chain: String,
    pub private_key: String,
    pub public_key: String,
}

#[derive(Serialize)]
struct WithApiKeys<'a, T: Serialize> {
    #[serde(flatten)]
    api_key: &'a ApiKey,
    #[serde(flatten)]
    inner: T,
}

pub struct Client<P: Post> {
    inner: P,
    api_key: ApiKey,
}

impl Client<DefaultTransport> {
    pub fn new(api_key: ApiKey) -> Self {
        Self::new_with_transport(api_key, DefaultTransport::new())
    }
}

impl<P: Post> Client<P> {
    fn new_with_transport(api_key: ApiKey, transport: P) -> Self {
        Self {
            inner: transport,
            api_key,
        }
    }
    async fn post_with_api_key<T: Serialize, D: for<'a> Deserialize<'a>>(
        &self,
        uri: Uri,
        body: T,
    ) -> Result<D> {
        let with_api_key = WithApiKeys {
            api_key: &self.api_key,
            inner: body,
        };
        self.inner.post(uri, with_api_key).await
    }

    pub async fn ping(&self) -> Result<IpAddr> {
        let ping: PingResponse = self.post_with_api_key(uri::ping(), ()).await?;
        Ok(ping.your_ip)
    }

    pub async fn ping_v4(&self) -> Result<Ipv4Addr> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct PingV4Response {
            your_ip: Ipv4Addr,
            //nxForwardedFor is returned here too?
        }
        let ping: PingV4Response = self.post_with_api_key(uri::ping_v4(), ()).await?;
        Ok(ping.your_ip)
    }

    //note: does not require authentication
    pub async fn domain_pricing(&self) -> Result<HashMap<String, Pricing>> {
        let resp: DomainPricingResponse = self.inner.post(uri::domain_pricing(), ()).await?;
        Ok(resp.pricing)
    }

    pub async fn update_ns_for_domain(
        &self,
        domain: &str,
        name_servers: Vec<String>,
    ) -> Result<()> {
        self.post_with_api_key(
            uri::update_name_servers(domain)?,
            UpdateNameServers { ns: name_servers },
        )
        .await
    }
    pub async fn get_ns_for_domain(&self, domain: &str) -> Result<Vec<String>> {
        let resp: UpdateNameServers = self
            .post_with_api_key(uri::get_name_servers(domain)?, ())
            .await?;
        Ok(resp.ns)
    }

    pub async fn list_domains(&self, offset: usize) -> Result<Vec<DomainListAllDomain>> {
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

    pub async fn list_all_domains(&self) -> Result<Vec<DomainListAllDomain>> {
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

    pub async fn add_url_forward(&self, domain: &str, cmd: DomainAddForwardUrl) -> Result<()> {
        self.post_with_api_key(uri::add_url_forward(domain)?, cmd)
            .await
    }

    pub async fn get_url_forward(&self, domain: &str) -> Result<Vec<Forward>> {
        let resp: GetUrlForwardingResponse = self
            .post_with_api_key(uri::get_url_forward(domain)?, ())
            .await?;
        Ok(resp.forwards)
    }

    // should we type this?
    pub async fn delete_url_forward(&self, domain: &str, id: &str) -> Result<()> {
        self.post_with_api_key(uri::delete_url_forward(domain, id)?, ())
            .await
    }

    pub async fn make_dns_record(
        &self,
        domain: &str,
        cmd: CreateOrEditDnsRecord,
    ) -> Result<String> {
        let resp: EntryId = self
            .post_with_api_key(uri::create_dns_record(domain)?, cmd)
            .await?;
        Ok(resp.id)
    }

    pub async fn edit_dns_record(
        &self,
        domain: &str,
        id: &str,
        cmd: CreateOrEditDnsRecord,
    ) -> Result<()> {
        self.post_with_api_key(uri::edit_dns_record(domain, id)?, cmd)
            .await
    }
    pub async fn edit_dns_record_for(
        &self,
        domain: &str,
        record_type: DnsRecordType,
        subdomain: Option<&str>,
        cmd: EditDnsRecordByDomainTypeSubdomain,
    ) -> Result<()> {
        self.post_with_api_key(
            uri::edit_dns_record_for(domain, record_type, subdomain)?,
            cmd,
        )
        .await
    }

    pub async fn delete_dns_record_for(
        &self,
        domain: &str,
        record_type: DnsRecordType,
        subdomain: Option<&str>,
    ) -> Result<()> {
        self.post_with_api_key(
            uri::delete_dns_record_for(domain, record_type, subdomain)?,
            (),
        )
        .await
    }

    pub async fn delete_dns_record_by_id(&self, domain: &str, id: &str) -> Result<()> {
        self.post_with_api_key(uri::delete_dns_record_by_id(domain, id)?, ())
            .await
    }

    pub async fn get_dns_record_by_domain_and_id(
        &self,
        domain: &str,
        id: Option<&str>,
    ) -> Result<Vec<DnsEntry>> {
        let rsp: DnsRecordsByDomainOrIDResponse = self
            .post_with_api_key(uri::get_dns_record_by_domain_and_id(domain, id)?, ())
            .await?;
        Ok(rsp.records)
    }
    pub async fn get_dns_record_for(
        &self,
        domain: &str,
        record_type: DnsRecordType,
        subdomain: Option<&str>,
    ) -> Result<Vec<DnsEntry>> {
        let rsp: DnsRecordsByDomainOrIDResponse = self
            .post_with_api_key(uri::get_dns_record_for(domain, record_type, subdomain)?, ())
            .await?;
        Ok(rsp.records)
    }

    pub async fn get_ssl_bundle(&self, domain: &str) -> Result<SslBundle> {
        self.post_with_api_key(uri::get_ssl_bundle(domain)?, ())
            .await
    }
}

pub struct DefaultTransport {
    hyper: HyperClient<hyper_tls::HttpsConnector<HttpConnector>, http_body_util::Full<Bytes>>,
    session: OnceCell<HeaderValue>,
}

impl DefaultTransport {
    pub(crate) fn new() -> Self {
        Self {
            hyper: HyperClient::builder(TokioExecutor::new()).build(HttpsConnector::new()),
            session: OnceCell::new(),
        }
    }
}

/// interface trait for the transport layer
pub trait Post {
    fn post<T: Serialize, D: for<'a> Deserialize<'a>>(
        &self,
        uri: Uri,
        body: T,
    ) -> impl Future<Output = Result<D>>;
}

impl Post for DefaultTransport {
    async fn post<T: Serialize, D: for<'a> Deserialize<'a>>(&self, uri: Uri, body: T) -> Result<D> {
        let json = serde_json::to_string(&body)?;
        // println!("posting to {uri} with {json}");
        let body_bytes = http_body_util::Full::new(Bytes::from(json));

        let req = if let Some(cookie) = self.session.get() {
            // println!("adding cookie {cookie:?}");
            Request::post(uri.clone()).header(hyper::header::COOKIE, cookie)
        } else {
            Request::post(uri.clone())
        }
        .body(body_bytes)?;
        //todo: handle 404/504 etc
        let resp = loop {
            let resp = self.hyper.request(req.clone()).await?;
            if resp.status() != StatusCode::SERVICE_UNAVAILABLE {
                break resp;
            } else {
                // println!("received 502, trying again...");
            }
        };
        if self.session.get().is_none() {
            if let Some(Ok(cookie)) = resp
                .headers()
                .get(hyper::header::SET_COOKIE)
                .map(HeaderValue::to_str)
            {
                let value = cookie.split_once(';').unwrap().0;
                self.session
                    .set(HeaderValue::from_str(value).unwrap())
                    .unwrap()
            }
        }
        let bytes = resp.into_body().collect().await?.to_bytes();
        // let rsp_body = std::str::from_utf8(&bytes)?;
        // println!("{rsp_body}");
        Result::<_, ApiError>::from(serde_json::from_slice::<ApiResponse<_>>(&bytes)?)
            .map_err(|e| anyhow::anyhow!(e))
    }
}
