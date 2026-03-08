//! Shows how to add HTTP-level tracing by wrapping the default transport.
//!
//! The `porkbun-api` crate instruments its public API methods (when the
//! `tracing` feature is enabled) but intentionally leaves HTTP-level
//! request/response tracing to the consumer. This example demonstrates how
//! to add it by implementing [`MakeRequest`] around [`DefaultTransport`].
//!
//! Run with:
//! ```sh
//! RUST_LOG="http_tracing=trace,porkbun_api=trace,info" cargo run --example http_tracing --features tracing
//! ```

use http_body_util::Full;
use hyper::{
    body::{Bytes, Incoming},
    Request, Response,
};
use porkbun_api::{
    transport::{DefaultTransport, DefaultTransportError, MakeRequest},
    ApiKey, Client,
};
use tracing::Instrument;

struct TracedTransport(DefaultTransport);

impl MakeRequest for TracedTransport {
    type Body = Incoming;
    type Error = DefaultTransportError;

    async fn request(
        &self,
        request: Request<Full<Bytes>>,
    ) -> Result<Response<Incoming>, DefaultTransportError> {
        let span = tracing::info_span!(
            "http.request",
            http.method = %request.method(),
            http.url = %request.uri(),
            http.status_code = tracing::field::Empty,
        );
        async {
            // add RUSLOG="http_tracing=trace" to the environment to see these trace logs
            tracing::trace!("making request");
            let response = self.0.request(request).await;
            if let Ok(ref resp) = response {
                tracing::Span::current().record("http.status_code", resp.status().as_u16());
            }
            tracing::trace!("completed request");
            response
        }
        .instrument(span)
        .await
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let file = std::fs::File::open("secrets/api_key.json")?;
    let api_key: ApiKey = serde_json::from_reader(file)?;

    let transport = TracedTransport(DefaultTransport::default());
    let client = Client::new_with_transport(api_key, transport);

    let ip = client.ping().await?;
    println!("Your IP: {ip}");

    let domains = client.domains().await?;
    println!("Domains: {domains:#?}");

    Ok(())
}
