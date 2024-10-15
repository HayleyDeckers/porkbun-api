use porkbun_api::DnsEntry;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let file = std::fs::File::open("secrets/api_key.json")?;
    let api_key = serde_json::from_reader(file)?;
    let client = porkbun_api::Client::new(api_key);

    let domains = client.list_all_domains().await?;
    for domain_info in domains {
        let domain = &domain_info.domain;
        println!("--- {domain} ---");
        let dns: Vec<porkbun_api::DnsEntry> =
            client.get_dns_record_by_domain_and_id(domain, None).await?;
        println!("found {} dns records", dns.len());
        for DnsEntry {
            name,
            record_type,
            content,
            ttl,
            prio,
            notes,
            ..
        } in dns
        {
            println!("  {record_type}\t{name}\t{content}\t{ttl:?} {prio:?} {notes:?}");
        }
    }

    Ok(())
}
