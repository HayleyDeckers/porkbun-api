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
use std::{fmt::Display, net::IpAddr, sync::Arc};

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
pub struct PingResponse {
    your_ip: IpAddr,
}
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DeleteDnsRecordByIdResponse {}

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

    pub async fn delete_dns_record_by_id(
        &self,
        domain: &str,
        id: u128,
    ) -> Result<DeleteDnsRecordByIdResponse> {
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
