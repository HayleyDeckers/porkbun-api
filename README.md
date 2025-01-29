
# porbun-api 🐖

[![Docs.rs][docs-badge]][docs-url]
[![Crates.io][crates-badge]][crates-url]
[![MIT licensed][mit-badge]][mit-url]

this crate provides an async implementation of [porkbun](https://porkbun.com)'s domain management [api](https://porkbun.com/api/json/v3/documentation).
It provides a transport-agnostic [Client], and a [DefaultTransport] based on hyper suitable for use in tokio-based applications.

[docs-badge]: [https://img.shields.io/docsrs/porkbun-api]
[docs-url]: [https://docs.rs/porkbun-api]
[crates-badge]: https://img.shields.io/crates/v/porkbun-api.svg
[crates-url]: https://crates.io/crates/porkbun-api
[mit-badge]: https://img.shields.io/badge/license-MIT-blue.svg
[mit-url]: https://github.com/HayleyDeckers/porkbun-api/blob/master/LICENSE

## Example

```rust,no_run
#[tokio::main]
async fn main() -> porkbun_api::Result<()> {
    let api_key = porkbun_api::ApiKey::new("secret", "api_key");
    let client = porkbun_api::Client::new(api_key);
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
```

## License

This project is licensed under the [MIT license].

[MIT license]: https://github.com/HayleyDeckers/porkbun-api/blob/master/LICENSE

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this project by you, shall be licensed as MIT, without any additional
terms or conditions.
