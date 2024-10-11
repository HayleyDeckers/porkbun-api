#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let file = std::fs::File::open("secrets/api_key.json")?;
    let api_key = serde_json::from_reader(file)?;
    let client = porkbun_api::Client::new(api_key);
    let ping_response = client.ping().await?;
    println!("{ping_response:#?}");
    let ping_response = client.ping_v4().await?;
    println!("{ping_response:#?}");
    Ok(())
}
