use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use porkbun_api::{CreateOrEditDnsRecord, DnsRecordType};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let file = std::fs::File::open("secrets/api_key.json")?;
    let api_key = serde_json::from_reader(file)?;
    let client = porkbun_api::Client::new(api_key);

    let domain = "fckn.gay";
    let subdomain = Some("laptop");

    let fqdn = if let Some(subdomain) = subdomain {
        format!("{subdomain}.{domain}")
    } else {
        domain.to_owned()
    };
    println!("setting up {fqdn}...");
    let existing_entries = client.get_dns_record_by_domain_and_id(domain, None).await?;

    // fetch our ip
    // let my_ip = client.ping().await?;
    // for privacy reasons, we comment this out and use localhost in this example.
    let my_ip = IpAddr::V6(Ipv6Addr::LOCALHOST);

    //we could also delete existing entries, or update them but unfortunately the porbun api will throw an error if you try to update/delete/edit a non-existant entry,
    // and error out if you create a new entry that already exists.
    let record_type = if my_ip.is_ipv6() {
        DnsRecordType::AAAA
    } else {
        DnsRecordType::A
    };
    let new_entry = CreateOrEditDnsRecord {
        subdomain,
        record_type,
        content: &my_ip.to_string(),
        ttl: None,
        prio: None,
    };
    if let Some(existing) = existing_entries
        .iter()
        .find(|e| e.record_type == record_type && e.name.eq_ignore_ascii_case(&fqdn))
    {
        if existing.content == new_entry.content {
            println!("identical entry, skipping.");
        } else {
            println!("updating {}", existing.id);
            client
                .edit_dns_record(domain, &existing.id, new_entry)
                .await?;
        }
    } else {
        println!("making new record {new_entry:?}");
        client.make_dns_record(domain, new_entry).await?;
    }
    // if the ip we got was ip6, explicitly fetch ipv4 too and update that
    if my_ip.is_ipv6() {
        //again, we use localhost in the example for privacy
        // let my_ip = client.ping_v4().await?;
        let my_ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let record_type = DnsRecordType::A;
        let new_entry = CreateOrEditDnsRecord {
            subdomain,
            record_type,
            content: &my_ip.to_string(),
            ttl: None,
            prio: None,
        };
        if let Some(existing) = existing_entries
            .iter()
            .find(|e| e.record_type == record_type && e.name.eq_ignore_ascii_case(&fqdn))
        {
            if existing.content == new_entry.content {
                println!("identical entry, skipping.");
            } else {
                println!("updating {}", existing.id);
                client
                    .edit_dns_record(domain, &existing.id, new_entry)
                    .await?;
            }
        } else {
            println!("making new record {new_entry:?}");
            client.make_dns_record(domain, new_entry).await?;
        }
    } else {
        //we originally got an ip4 adress, meaning we don't have ipv6 connectivity now and we should delete the old entry if it exists.
        if let Some(old) = existing_entries
            .iter()
            .find(|e| e.record_type == DnsRecordType::AAAA && e.name.eq_ignore_ascii_case(&fqdn))
        {
            println!("deleting old AAAA record");
            client.delete_dns_record_by_id(domain, &old.id).await?;
        }
    }
    Ok(())
}
