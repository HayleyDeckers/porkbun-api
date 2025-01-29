#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let file = std::fs::File::open("secrets/api_key.json")?;
    let api_key = serde_json::from_reader(file)?;
    let mut client = porkbun_api::Client::new(api_key);

    println!("{:#?}", client.get_ssl_bundle("fckn.gay").await?);

    Ok(())
}
