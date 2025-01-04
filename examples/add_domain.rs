use porkbun_api::{Client, CreateOrEditDnsRecord};
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let file = std::fs::File::open("secrets/api_key.json")?;
    let api_key = serde_json::from_reader(file)?;
    let client = Client::new(api_key);

    let domain = &client.domains().await?[0].domain;
    let subdomain = Some("my.ip");
    let my_ip = client.ping().await?;
    let record = CreateOrEditDnsRecord::A_or_AAAA(subdomain, my_ip);
    let id = client.create(domain, record).await?;
    println!("added record {id}");
    client.delete(domain, &id).await?;
    println!("removed record {id}");
    Ok(())
}
