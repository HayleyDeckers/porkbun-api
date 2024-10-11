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
use std::sync::Arc;

#[derive(Deserialize, Serialize)]
pub struct ApiKey {
    secretapikey: String,
    apikey: String,
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

#[derive(Deserialize, Serialize)]
pub struct CreateDnsRecord {
    #[serde(rename = "name")]
    pub subdomain: Option<String>,
    #[serde(rename = "type")]
    pub record_type: DnsRecordType,
    pub content: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct CreateDnsRecordResponse {
    status: String,
    // this id is a string in the example docs, but the api returns an integer
    pub id: Option<u128>,
    message: Option<String>,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct DnsEntry {
    id: String,
    #[serde(rename = "name")]
    pub subdomain: Option<String>,
    #[serde(rename = "type")]
    pub record_type: DnsRecordType,
    pub content: String,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct DnsRecordsByDomainOrIDResponse {
    status: String,
    message: Option<String>,
    pub records: Vec<DnsEntry>,
}

#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct PingResponse {
    status: String,
    your_ip: Option<String>,
    message: Option<String>,
}
#[derive(Deserialize, Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DeleteDnsRecordByIdResponse {
    status: String,
    message: Option<String>,
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
    inner: Arc<ClientInner>,
}

impl Client {
    pub fn new(api_key: ApiKey) -> Self {
        Self {
            inner: Arc::new(ClientInner::new(api_key)),
        }
    }

    pub async fn ping(&self) -> Result<PingResponse> {
        let resp = self
            .inner
            .post_with_api_keys(
                hyper::Uri::from_static(uri::ping()),
                Some(&self.inner.api_keys),
            )
            .await?;
        let bytes = resp.into_body().collect().await?.to_bytes();
        serde_json::from_slice(&bytes).map_err(|e| anyhow::anyhow!(e))
    }

    pub async fn make_dns_record(
        &self,
        domain: &str,
        cmd: CreateDnsRecord,
    ) -> Result<CreateDnsRecordResponse> {
        let resp = self
            .inner
            .post_with_api_keys(
                uri::create_dns_record(domain)?,
                Some(WithApiKeys {
                    api_keys: &self.inner.api_keys,
                    inner: cmd,
                }),
            )
            .await?;
        let bytes = resp.into_body().collect().await?.to_bytes();
        let body = std::str::from_utf8(&bytes)?;
        println!("{body}");
        serde_json::from_slice(body.as_bytes()).map_err(|e| anyhow::anyhow!(e))
    }

    pub async fn delete_dns_record_by_id(
        &self,
        domain: &str,
        id: u128,
    ) -> Result<DeleteDnsRecordByIdResponse> {
        let resp = self
            .inner
            .post_with_api_keys(
                uri::delete_dns_record_by_id(domain, id)?,
                Some(&self.inner.api_keys),
            )
            .await?;
        let bytes = resp.into_body().collect().await?.to_bytes();
        let body = std::str::from_utf8(&bytes)?;
        println!("{body}");
        serde_json::from_slice(body.as_bytes()).map_err(|e| anyhow::anyhow!(e))
    }

    pub async fn get_dns_record_by_domain_and_id(
        &self,
        domain: &str,
        id: Option<u128>,
    ) -> Result<DnsRecordsByDomainOrIDResponse> {
        let resp = self
            .inner
            .post_with_api_keys(
                uri::get_dns_record_by_domain_and_id(domain, id)?,
                Some(&self.inner.api_keys),
            )
            .await?;
        let bytes = resp.into_body().collect().await?.to_bytes();
        let body = std::str::from_utf8(&bytes)?;
        println!("{body}");
        serde_json::from_slice(body.as_bytes()).map_err(|e| anyhow::anyhow!(e))
    }
}

struct ClientInner {
    api_keys: ApiKey,
    hyper: HyperClient<hyper_tls::HttpsConnector<HttpConnector>, http_body_util::Full<Bytes>>,
}

impl ClientInner {
    pub(crate) fn new(api_keys: ApiKey) -> Self {
        Self {
            api_keys,
            hyper: HyperClient::builder(TokioExecutor::new()).build(HttpsConnector::new()),
        }
    }

    pub(crate) async fn post_with_api_keys<T: Serialize>(
        &self,
        uri: Uri,
        body: Option<T>,
    ) -> Result<Response<Incoming>> {
        let req = Request::post(uri).body(
            body.map(|b| {
                http_body_util::Full::new(Bytes::from(serde_json::to_string(&b).unwrap()))
            })
            .unwrap_or_default(),
        )?;
        self.hyper
            .request(req)
            .await
            .map_err(|e| anyhow::anyhow!(e))
    }
}
