use crate::DnsRecordType;
use hyper::{http::uri::InvalidUri, Uri};
pub(crate) fn ping() -> Uri {
    Uri::from_static("https://api.porkbun.com/api/json/v3/ping")
}

// this can be a get instead of post?
pub(crate) fn domain_pricing() -> Uri {
    Uri::from_static("https://api.porkbun.com/api/json/v3/pricing/get")
}

pub(crate) fn update_name_servers(domain: &str) -> Result<Uri, InvalidUri> {
    Uri::try_from(format!(
        "https://api.porkbun.com/api/json/v3/domain/updateNs/{domain}"
    ))
}

pub(crate) fn get_name_servers(domain: &str) -> Result<Uri, InvalidUri> {
    Uri::try_from(format!(
        "https://api.porkbun.com/api/json/v3/domain/getNs/{domain}"
    ))
}

pub(crate) fn domain_list_all() -> hyper::Uri {
    hyper::Uri::from_static("https://api.porkbun.com/api/json/v3/domain/listAll")
}

pub(crate) fn add_url_forward(domain: &str) -> Result<Uri, InvalidUri> {
    Uri::try_from(format!(
        "https://api.porkbun.com/api/json/v3/domain/addUrlForward/{domain}"
    ))
}

pub(crate) fn get_url_forward(domain: &str) -> Result<Uri, InvalidUri> {
    Uri::try_from(format!(
        "https://api.porkbun.com/api/json/v3/domain/getUrlForwarding/{domain}"
    ))
}

pub(crate) fn delete_url_forward(domain: &str, record_id: &str) -> Result<Uri, InvalidUri> {
    Uri::try_from(format!(
        "https://api.porkbun.com/api/json/v3/domain/deleteUrlForward/{domain}/{record_id}"
    ))
}

pub(crate) fn create_dns_record(domain: &str) -> Result<Uri, InvalidUri> {
    Uri::try_from(format!(
        "https://api.porkbun.com/api/json/v3/dns/create/{domain}"
    ))
}

pub(crate) fn edit_dns_record(domain: &str, id: &str) -> Result<Uri, InvalidUri> {
    Uri::try_from(format!(
        "https://api.porkbun.com/api/json/v3/dns/edit/{domain}/{id}"
    ))
}

pub(crate) fn delete_dns_record_by_id(domain: &str, id: &str) -> Result<Uri, InvalidUri> {
    Uri::try_from(format!(
        "https://api.porkbun.com/api/json/v3/dns/delete/{domain}/{id}"
    ))
}

pub(crate) fn get_dns_record_by_domain_and_id(
    domain: &str,
    id: Option<&str>,
) -> Result<Uri, InvalidUri> {
    if let Some(id) = id {
        Uri::try_from(format!(
            "https://api.porkbun.com/api/json/v3/dns/retrieve/{domain}/{id}"
        ))
    } else {
        Uri::try_from(format!(
            "https://api.porkbun.com/api/json/v3/dns/retrieve/{domain}"
        ))
    }
}

pub(crate) fn get_ssl_bundle(domain: &str) -> Result<Uri, InvalidUri> {
    Uri::try_from(format!(
        "https://api.porkbun.com/api/json/v3/ssl/retrieve/{domain}"
    ))
}
