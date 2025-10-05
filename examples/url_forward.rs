use porkbun_api::{Client, Forward};
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let file = std::fs::File::open("secrets/api_key.json")?;
    let api_key = serde_json::from_reader(file)?;
    let client = Client::new(api_key);

    let domain = &client.domains().await?[0].domain;

    let cmd = Forward::new(Some("url_forward"), "example.com");
    client.add_url_forward(domain, cmd).await?;
    let url_forwards = client.get_url_forwards(domain).await?;
    for url in url_forwards {
        println!("{:#?}", url);
        let id = &url.id;
        client.delete_url_forward(domain, id).await?;
        println!("removed url forward {id}");
    }

    Ok(())
}
