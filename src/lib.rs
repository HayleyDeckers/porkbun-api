use anyhow::Result;
use http_body_util::BodyExt;
use hyper::{
    body::{Bytes, Incoming},
    Request, Response, Uri,
};
use hyper_tls::HttpsConnector;
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client as HyperClient},
    rt::TokioExecutor,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    fmt::Display,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
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

#[derive(Deserialize, Serialize, Debug)]
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
}

#[derive(Serialize)]
pub struct CreateDnsRecord {
    #[serde(rename = "name")]
    pub subdomain: Option<String>,
    #[serde(rename = "type")]
    pub record_type: DnsRecordType,
    pub content: String,
}

#[derive(Deserialize, Debug)]
pub struct CreateDnsRecordResponse {
    // this id is a string in the example docs, but the api returns an integer
    pub id: Option<u128>,
}

#[derive(Deserialize, Debug)]
pub struct DnsEntry {
    id: String,
    #[serde(rename = "name")]
    pub subdomain: Option<String>,
    #[serde(rename = "type")]
    pub record_type: DnsRecordType,
    pub content: String,
}

#[derive(Deserialize, Debug)]
pub struct DnsRecordsByDomainOrIDResponse {
    pub records: Vec<DnsEntry>,
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

#[derive(Deserialize, Debug)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
//undocumented
struct Coupon {
    amount: usize,
    code: String,
    #[serde(default, with = "yesno")]
    first_year_only: bool,
    max_per_user: Option<usize>,
    r#type: Option<String>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Pricing {
    registration: String,
    renewal: String,
    transfer: String,
    //undocumented field, helps filter out stupid handshake responses
    pub special_type: Option<SpecialType>,
}

#[derive(Deserialize, Debug)]
struct DomainPricingResponse {
    pricing: HashMap<String, Pricing>,
}

#[derive(Serialize, Deserialize)]
struct UpdateNameServers {
    ns: Vec<String>,
}

mod yesno {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &bool, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match value {
            true => "yes",
            // value of not-yes not documented
            false => "false",
        })
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<bool, D::Error>
    where
        D: Deserializer<'de>,
    {
        let yesno = String::deserialize(deserializer)?;
        if yesno == "yes" {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

mod stringoneintzero {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(value: &bool, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            true => serializer.serialize_str("1"),
            false => serializer.serialize_i32(0),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<bool, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize, Debug)]
        #[serde(untagged)]
        enum PossibleValues {
            Stringy(String),
            Inty(i64),
        }
        let str_or_int = PossibleValues::deserialize(deserializer)?;
        match &str_or_int {
            PossibleValues::Stringy(x) if x == "1" => Ok(true),
            PossibleValues::Inty(0) => Ok(false),
            x => Err(serde::de::Error::custom(&format!("invalid value {x:?}"))),
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DomainListAll {
    /// An index to start at when retrieving the domains, defaults to 0. To get all domains increment by 1000 until you receive an empty array.
    start: usize,
    /// should be "yes"
    #[serde(default, with = "yesno")]
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
    domain: String,
    status: String,
    // 2018-08-20 17:52:51
    create_date: String,
    expire_date: String,
    // docs say these are "1", probably booleans?
    // "1" on success, 0 on false?
    #[serde(with = "stringoneintzero")]
    security_lock: bool,
    #[serde(with = "stringoneintzero")]
    whois_privacy: bool,
    //these are probably bools
    // docs say this is a bool, is a string
    #[serde(with = "stringoneintzero")]
    auto_renew: bool,
    #[serde(with = "stringoneintzero")]
    not_local: bool,
    #[serde(default)]
    labels: Vec<Label>,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
struct Label {
    //number in the example
    id: String,
    title: String,
    color: String,
}

#[derive(Serialize)]
struct WithApiKeys<'a, T: Serialize> {
    #[serde(flatten)]
    api_keys: &'a ApiKey,
    #[serde(flatten)]
    inner: T,
}

mod uri {
    pub const fn ping() -> &'static str {
        "https://api.porkbun.com/api/json/v3/ping"
    }

    // note: the docs say
    // > The dedicated IPv4 hostname is api-ipv4.porkbun.com, use this instead of porkbun.com.
    // which would yield api.api-ipv4.porkbun.com but that's obviously wrong so we don't do that
    pub const fn ping_v4() -> &'static str {
        "https://api-ipv4.porkbun.com/api/json/v3/ping"
    }

    // this can be a get instead of post?
    pub const fn domain_pricing() -> &'static str {
        "https://api.porkbun.com/api/json/v3/pricing/get"
    }

    pub fn update_name_servers(domain: &str) -> Result<hyper::Uri, hyper::http::uri::InvalidUri> {
        hyper::Uri::try_from(&format!(
            "https://api.porkbun.com/api/json/v3/domain/updateNs/{domain}"
        ))
    }

    pub fn get_name_servers(domain: &str) -> Result<hyper::Uri, hyper::http::uri::InvalidUri> {
        hyper::Uri::try_from(&format!(
            "https://api.porkbun.com/api/json/v3/domain/getNs/{domain}"
        ))
    }

    pub fn domain_list_all() -> hyper::Uri {
        hyper::Uri::from_static("https://api.porkbun.com/api/json/v3/domain/listAll")
    }

    pub fn create_dns_record(domain: &str) -> Result<hyper::Uri, hyper::http::uri::InvalidUri> {
        hyper::Uri::try_from(&format!(
            "https://api.porkbun.com/api/json/v3/dns/create/{domain}"
        ))
    }

    pub fn delete_dns_record_by_id(
        domain: &str,
        id: u128,
    ) -> Result<hyper::Uri, hyper::http::uri::InvalidUri> {
        hyper::Uri::try_from(&format!(
            "https://api.porkbun.com/api/json/v3/dns/delete/{domain}/{id}"
        ))
    }

    pub fn get_dns_record_by_domain_and_id(
        domain: &str,
        id: Option<u128>,
    ) -> Result<hyper::Uri, hyper::http::uri::InvalidUri> {
        if let Some(id) = id {
            hyper::Uri::try_from(&format!(
                "https://api.porkbun.com/api/json/v3/dns/retrieve/{domain}/{id}"
            ))
        } else {
            hyper::Uri::try_from(&format!(
                "https://api.porkbun.com/api/json/v3/dns/retrieve/{domain}"
            ))
        }
    }
}

#[derive(Clone)]
pub struct Client {
    inner: ClientInner,
}

impl Client {
    pub fn new(api_key: ApiKey) -> Self {
        Self {
            inner: ClientInner::new(Arc::new(api_key)),
        }
    }

    pub async fn ping(&self) -> Result<IpAddr> {
        let resp = self
            .inner
            .post_with_api_keys(hyper::Uri::from_static(uri::ping()), ())
            .await?;
        let bytes = resp.into_body().collect().await?.to_bytes();
        let ping: PingResponse =
            Result::<_, ApiError>::from(serde_json::from_slice::<ApiResponse<_>>(&bytes)?)?;
        Ok(ping.your_ip)
    }

    pub async fn ping_v4(&self) -> Result<Ipv4Addr> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct PingV4Response {
            your_ip: Ipv4Addr,
            //nxForwardedFor is returned here too?
        }
        let resp = self
            .inner
            .post_with_api_keys(hyper::Uri::from_static(uri::ping_v4()), ())
            .await?;
        let bytes = resp.into_body().collect().await?.to_bytes();
        let ping: PingV4Response =
            Result::<_, ApiError>::from(serde_json::from_slice::<ApiResponse<_>>(&bytes)?)?;
        Ok(ping.your_ip)
    }

    //note: does not require authentication
    pub async fn domain_pricing(&self) -> Result<HashMap<String, Pricing>> {
        let resp = self
            .inner
            .post(hyper::Uri::from_static(uri::domain_pricing()), ())
            .await?;
        let bytes = resp.into_body().collect().await?.to_bytes();
        let resp: DomainPricingResponse =
            Result::<_, ApiError>::from(serde_json::from_slice::<ApiResponse<_>>(&bytes)?)?;
        Ok(resp.pricing)
    }

    pub async fn update_ns_for_domain(
        &self,
        domain: &str,
        name_servers: Vec<String>,
    ) -> Result<()> {
        let resp = self
            .inner
            .post_with_api_keys(
                uri::update_name_servers(domain)?,
                UpdateNameServers { ns: name_servers },
            )
            .await?;
        let bytes = resp.into_body().collect().await?.to_bytes();
        let resp = Result::<(), ApiError>::from(serde_json::from_slice::<ApiResponse<_>>(&bytes)?)?;
        Ok(resp)
    }
    pub async fn get_ns_for_domain(&self, domain: &str) -> Result<Vec<String>> {
        let resp = self
            .inner
            .post_with_api_keys(uri::get_name_servers(domain)?, ())
            .await?;
        let bytes = resp.into_body().collect().await?.to_bytes();
        let body = std::str::from_utf8(&bytes)?;
        println!("{body}");
        let resp: UpdateNameServers =
            Result::<_, ApiError>::from(serde_json::from_slice::<ApiResponse<_>>(&bytes)?)?;
        Ok(resp.ns)
    }

    pub async fn list_domains(&self, offset: usize) -> Result<Vec<DomainListAllDomain>> {
        let resp = self
            .inner
            .post_with_api_keys(
                uri::domain_list_all(),
                DomainListAll {
                    start: offset,
                    include_labels: true,
                },
            )
            .await?;
        let bytes = resp.into_body().collect().await?.to_bytes();
        let body = std::str::from_utf8(&bytes)?;
        println!("{body}");
        let resp: DomainListAllResponse =
            Result::<_, ApiError>::from(serde_json::from_slice::<ApiResponse<_>>(&bytes)?)?;
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

    pub async fn make_dns_record(
        &self,
        domain: &str,
        cmd: CreateDnsRecord,
    ) -> Result<CreateDnsRecordResponse> {
        let resp = self
            .inner
            .post_with_api_keys(uri::create_dns_record(domain)?, cmd)
            .await?;
        let bytes = resp.into_body().collect().await?.to_bytes();
        let body = std::str::from_utf8(&bytes)?;
        println!("{body}");
        Result::<_, ApiError>::from(serde_json::from_slice::<ApiResponse<_>>(&bytes)?)
            .map_err(|e| anyhow::anyhow!(e))
    }

    pub async fn delete_dns_record_by_id(&self, domain: &str, id: u128) -> Result<()> {
        let resp = self
            .inner
            .post_with_api_keys(uri::delete_dns_record_by_id(domain, id)?, ())
            .await?;
        let bytes = resp.into_body().collect().await?.to_bytes();
        let body = std::str::from_utf8(&bytes)?;
        println!("{body}");
        Result::<_, ApiError>::from(serde_json::from_slice::<ApiResponse<_>>(&bytes)?)
            .map_err(|e| anyhow::anyhow!(e))
    }

    pub async fn get_dns_record_by_domain_and_id(
        &self,
        domain: &str,
        id: Option<u128>,
    ) -> Result<DnsRecordsByDomainOrIDResponse> {
        let resp = self
            .inner
            .post(uri::get_dns_record_by_domain_and_id(domain, id)?, ())
            .await?;
        let bytes = resp.into_body().collect().await?.to_bytes();
        let body = std::str::from_utf8(&bytes)?;
        println!("{body}");
        Result::<_, ApiError>::from(serde_json::from_slice::<ApiResponse<_>>(&bytes)?)
            .map_err(|e| anyhow::anyhow!(e))
    }
}

#[derive(Clone)]
struct ClientInner {
    api_keys: Arc<ApiKey>,
    hyper: HyperClient<hyper_tls::HttpsConnector<HttpConnector>, http_body_util::Full<Bytes>>,
}

impl ClientInner {
    pub(crate) fn new(api_keys: Arc<ApiKey>) -> Self {
        Self {
            api_keys,
            hyper: HyperClient::builder(TokioExecutor::new()).build(HttpsConnector::new()),
        }
    }

    pub(crate) async fn post<T: Serialize>(&self, uri: Uri, body: T) -> Result<Response<Incoming>> {
        let req = Request::post(uri).body(http_body_util::Full::new(Bytes::from(
            serde_json::to_string(&body).unwrap(),
        )))?;
        //todo: handle 404/504 etc
        self.hyper
            .request(req)
            .await
            .map_err(|e| anyhow::anyhow!(e))
    }

    pub(crate) async fn post_with_api_keys<T: Serialize>(
        &self,
        uri: Uri,
        body: T,
    ) -> Result<Response<Incoming>> {
        let with_api_keys = WithApiKeys {
            api_keys: &self.api_keys,
            inner: body,
        };
        self.post(uri, with_api_keys).await
    }
}
