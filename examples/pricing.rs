#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let file = std::fs::File::open("secrets/api_key.json")?;
    let api_key = serde_json::from_reader(file)?;
    let client = porkbun_api::Client::new(api_key);
    println!("TLD: registration / renewal / transfer\n-------");
    for (tld, pricing) in client.icann_domain_pricing().await? {
        println!(
            "{tld}: {} / {} / {}",
            pricing.registration, pricing.renewal, pricing.transfer
        );
    }
    Ok(())
}
