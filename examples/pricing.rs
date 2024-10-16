use porkbun_api::SpecialType;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let file = std::fs::File::open("secrets/api_key.json")?;
    let api_key = serde_json::from_reader(file)?;
    let client = porkbun_api::Client::new(api_key);
    println!("TLD: registration / renewal / transfer\n-------");
    for (tld, pricing) in client.domain_pricing().await? {
        if let Some(SpecialType::Handshake) = pricing.special_type {
            continue;
        }
        println!(
            "{tld}: {} / {} / {}",
            pricing.registration, pricing.renewal, pricing.transfer
        );
    }
    Ok(())
}
