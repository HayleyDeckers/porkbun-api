#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let file = std::fs::File::open("secrets/api_key.json")?;
    let api_key: porkbun_api::ApiKey = serde_json::from_reader(file)?;
    let client = porkbun_api::Client::new(api_key.clone());
    let ping_response = client.ping().await?;
    println!("{ping_response:#?}");
    let client2 = porkbun_api::Client::new_with_transport(
        api_key,
        porkbun_api::transport::DefaultTransport::new(true),
    );
    let ping_response = client2.ping().await?;
    println!("{ping_response:#?}");
    Ok(())
}
