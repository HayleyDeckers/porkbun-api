// use crate::DnsRecordType;
//todo: re-export and use http crate
use hyper::{http::uri::InvalidUri, Uri};
pub fn ping() -> Uri {
    Uri::from_static("https://api.porkbun.com/api/json/v3/ping")
}

// this can be a get instead of post?
pub fn domain_pricing() -> Uri {
    Uri::from_static("https://api.porkbun.com/api/json/v3/pricing/get")
}

pub fn update_name_servers(domain: &str) -> Result<Uri, InvalidUri> {
    Uri::try_from(format!(
        "https://api.porkbun.com/api/json/v3/domain/updateNs/{domain}"
    ))
}

pub fn get_name_servers(domain: &str) -> Result<Uri, InvalidUri> {
    Uri::try_from(format!(
        "https://api.porkbun.com/api/json/v3/domain/getNs/{domain}"
    ))
}

pub fn domain_list_all() -> hyper::Uri {
    hyper::Uri::from_static("https://api.porkbun.com/api/json/v3/domain/listAll")
}

// pub fn add_url_forward(domain: &str) -> Result<Uri, InvalidUri> {
//     Uri::try_from(format!(
//         "https://api.porkbun.com/api/json/v3/domain/addUrlForward/{domain}"
//     ))
// }

// pub fn get_url_forward(domain: &str) -> Result<Uri, InvalidUri> {
//     Uri::try_from(format!(
//         "https://api.porkbun.com/api/json/v3/domain/getUrlForwarding/{domain}"
//     ))
// }

// pub fn delete_url_forward(domain: &str, record_id: &str) -> Result<Uri, InvalidUri> {
//     Uri::try_from(format!(
//         "https://api.porkbun.com/api/json/v3/domain/deleteUrlForward/{domain}/{record_id}"
//     ))
// }

pub fn create_dns_record(domain: &str) -> Result<Uri, InvalidUri> {
    Uri::try_from(format!(
        "https://api.porkbun.com/api/json/v3/dns/create/{domain}"
    ))
}

pub fn edit_dns_record(domain: &str, id: &str) -> Result<Uri, InvalidUri> {
    Uri::try_from(format!(
        "https://api.porkbun.com/api/json/v3/dns/edit/{domain}/{id}"
    ))
}

// pub fn edit_dns_record_for(
//     domain: &str,
//     record_type: DnsRecordType,
//     subdomain: Option<&str>,
// ) -> Result<Uri, InvalidUri> {
//     Uri::try_from(if let Some(subdomain) = subdomain {
//         format!(
//             "https://api.porkbun.com/api/json/v3/dns/editByNameType/{domain}/{record_type}/{subdomain}"
//         )
//     } else {
//         format!("https://api.porkbun.com/api/json/v3/dns/editByNameType/{domain}/{record_type}")
//     })
// }

pub fn delete_dns_record_by_id(domain: &str, id: &str) -> Result<Uri, InvalidUri> {
    Uri::try_from(format!(
        "https://api.porkbun.com/api/json/v3/dns/delete/{domain}/{id}"
    ))
}

// pub fn delete_dns_record_for(
//     domain: &str,
//     record_type: DnsRecordType,
//     subdomain: Option<&str>,
// ) -> Result<Uri, InvalidUri> {
//     Uri::try_from(if let Some(subdomain) = subdomain {
//         format!(
//             "https://api.porkbun.com/api/json/v3/dns/deleteByNameType/{domain}/{record_type}/{subdomain}"
//         )
//     } else {
//         format!("https://api.porkbun.com/api/json/v3/dns/deleteByNameType/{domain}/{record_type}")
//     })
// }

pub fn get_dns_record_by_domain_and_id(domain: &str, id: Option<&str>) -> Result<Uri, InvalidUri> {
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

// pub fn get_dns_record_for(
//     domain: &str,
//     record_type: DnsRecordType,
//     subdomain: Option<&str>,
// ) -> Result<Uri, InvalidUri> {
//     Uri::try_from(if let Some(subdomain) = subdomain {
//         format!(
//             "https://api.porkbun.com/api/json/v3/dns/retrieveByNameType/{domain}/{record_type}/{subdomain}"
//         )
//     } else {
//         format!("https://api.porkbun.com/api/json/v3/dns/retrieveByNameType/{domain}/{record_type}")
//     })
// }

// pub fn get_ssl_bundle(domain: &str) -> Result<Uri, InvalidUri> {
//     Uri::try_from(format!(
//         "https://api.porkbun.com/api/json/v3/ssl/retrieve/{domain}"
//     ))
// }
