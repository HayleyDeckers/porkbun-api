use porkbun_api::{CreateOrEditDnsRecord, DnsEntry, DnsRecordType};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let file = std::fs::File::open("secrets/api_key.json")?;
    let api_key = serde_json::from_reader(file)?;
    let client = porkbun_api::Client::new(api_key);

    let domain = &client.list_domains(0).await?[0].domain;
    println!("\nbefore:");
    for txt_record in client
        .get_dns_record_by_domain_and_id(domain, None)
        .await?
        .into_iter()
        .filter(|domain| domain.record_type == DnsRecordType::TXT)
    {
        println!("{txt_record:?}");
    }
    //try naming one with an emoji like 🐖 and then deleting 🦆
    // might fail to build the uri?
    let id = client
        .make_dns_record(
            domain,
            CreateOrEditDnsRecord {
                subdomain: Some("porkbun-api".to_owned()),
                record_type: DnsRecordType::TXT,
                content: "oink oink 🐖".to_owned(),
                ttl: None,
                prio: None,
            },
        )
        .await?;
    println!("\nadded:");
    for txt_record in client
        .get_dns_record_by_domain_and_id(&domain, None)
        .await?
        .into_iter()
        .filter(|domain| domain.record_type == DnsRecordType::TXT)
    {
        println!("{txt_record:?}");
    }
    client.delete_dns_record_by_id(domain, &id).await?;
    println!("\ndeleted:");
    for txt_record in client
        .get_dns_record_by_domain_and_id(domain, None)
        .await?
        .into_iter()
        .filter(|domain| domain.record_type == DnsRecordType::TXT)
    {
        println!("{txt_record:?}");
    }
    Ok(())
}
