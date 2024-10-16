use porkbun_api::{CreateOrEditDnsRecord, DnsRecordType};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let file = std::fs::File::open("secrets/api_key.json")?;
    let api_key = serde_json::from_reader(file)?;
    let client = porkbun_api::Client::new(api_key);

    let domain = &client.list_domains(0).await?[0].domain;

    let id = client
        .make_dns_record(
            domain,
            CreateOrEditDnsRecord {
                subdomain: Some("porkbun-api".to_owned()),
                record_type: DnsRecordType::TXT,
                content: "🦆".to_owned(),
                ttl: None,
                prio: None,
            },
        )
        .await?;
    client.delete_dns_record_by_id(domain, &id).await?;
    Ok(())
}
