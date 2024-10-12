use std::collections::HashMap;

use porkbun_api::SpecialType;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let file = std::fs::File::open("secrets/api_key.json")?;
    let api_key = serde_json::from_reader(file)?;
    let client = porkbun_api::Client::new(api_key);
    let resp = client.list_all_domains().await?;
    // let resp = client.get_ns_for_domain("fckn.gay".into()).await?;
    println!("{resp:#?}");
    // let resp = client
    //     .domain_pricing()
    //     .await?
    //     .into_iter()
    //     .filter(|price| !matches!(price.1.special_type, Some(SpecialType::Handshake)))
    //     .collect::<HashMap<_, _>>();
    // println!("{resp:#?}");
    let ping_response = client.ping().await?;
    println!("{ping_response:#?}");
    let ping_response = client.ping_v4().await?;
    println!("{ping_response:#?}");
    Ok(())
}
