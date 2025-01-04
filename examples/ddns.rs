use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use porkbun_api::{ApiKey, CreateOrEditDnsRecord, DefaultTransport, DnsRecordType};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let force_ipv4 = false;
    let file = std::fs::File::open("secrets/api_key.json")?;
    let api_key: ApiKey = serde_json::from_reader(file)?;
    let client =
        porkbun_api::Client::new_with_transport(api_key.clone(), DefaultTransport::new(force_ipv4));

    let domain = "fckn.gay";
    let subdomain = Some("laptop");

    let fqdn = if let Some(subdomain) = subdomain {
        format!("{subdomain}.{domain}")
    } else {
        domain.to_owned()
    };
    println!("setting up {fqdn}...");
    let existing_entries = client.get_all(domain).await?;

    // fetch our ip
    // let my_ip = client.ping().await?;
    // for privacy reasons, we comment this out and use localhost in this example.
    let my_ip: IpAddr = IpAddr::V6(Ipv6Addr::LOCALHOST);

    //we could also delete existing entries, or update them but unfortunately the porbun api will throw an error if you try to update/delete/edit a non-existant entry,
    // and error out if you create a new entry that already exists.
    let new_entry = CreateOrEditDnsRecord::A_or_AAAA(subdomain, my_ip);
    if let Some(existing) = existing_entries
        .iter()
        .find(|e| e.record_type == new_entry.record_type && e.name.eq_ignore_ascii_case(&fqdn))
    {
        if existing.content == new_entry.content {
            println!("identical entry, skipping.");
        } else {
            println!("updating {}", existing.id);
            client.edit(domain, &existing.id, new_entry).await?;
        }
    } else {
        println!("making new record {new_entry:?}");
        client.create(domain, new_entry).await?;
    }
    // if the ip we got was ip6, explicitly fetch ipv4 too and update that
    if my_ip.is_ipv6() {
        //again, we use localhost in the example for privacy
        // let my_ip = porkbun_api::Client::new_with_transport(api_key, DefaultTransport::new(true))
        //     .ping()
        //     .await?;
        let my_ip = Ipv4Addr::LOCALHOST;
        let new_entry = CreateOrEditDnsRecord::A(subdomain, my_ip);
        if let Some(existing) = existing_entries
            .iter()
            .find(|e| e.record_type == new_entry.record_type && e.name.eq_ignore_ascii_case(&fqdn))
        {
            if existing.content == new_entry.content {
                println!("identical entry, skipping.");
            } else {
                println!("updating {}", existing.id);
                client.edit(domain, &existing.id, new_entry).await?;
            }
        } else {
            println!("making new record {new_entry:?}");
            client.create(domain, new_entry).await?;
        }
    } else {
        //we originally got an ip4 adress, meaning we don't have ipv6 connectivity now and we should delete the old entry if it exists.
        if let Some(old) = existing_entries
            .iter()
            .find(|e| e.record_type == DnsRecordType::AAAA && e.name.eq_ignore_ascii_case(&fqdn))
        {
            println!("deleting old AAAA record");
            client.delete(domain, &old.id).await?;
        }
    }
    Ok(())
}
