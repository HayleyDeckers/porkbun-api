use crate::MakeRequest;
use cookie::Cookie;
use http_body_util::Full;
use hyper::client::conn::http2::Builder as Http2Builder;
use hyper::{
    body::{Bytes, Incoming},
    client::conn::http2::SendRequest,
    header::{HeaderValue, COOKIE},
    Request, Response, StatusCode,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::ClientConfig;
use std::{
    error::Error,
    fmt::Display,
    future::Future,
    sync::{Arc, OnceLock},
    time::Duration,
};
use tokio::{net::TcpStream, sync::Mutex};
use tokio_rustls::TlsConnector;

struct Http2Only {
    force_ipv4: bool,
    config: Arc<ClientConfig>,
    send: tokio::sync::Mutex<Option<SendRequest<Full<Bytes>>>>,
}

impl Http2Only {
    async fn make_connection(&self) -> SendRequest<Full<Bytes>> {
        let arc_config = self.config.clone();
        let server_name = if self.force_ipv4 {
            "api-ipv4.porkbun.com"
        } else {
            "api.porkbun.com"
        }
        .try_into()
        .unwrap();
        let tokio_tls_connecto = TlsConnector::from(arc_config);
        let tcp = TcpStream::connect(if self.force_ipv4 {
            "api-ipv4.porkbun.com:443"
        } else {
            "api.porkbun.com:443"
        })
        .await
        .map_err(|e| crate::Error::TransportError(e.into()))
        .unwrap();
        let connection = tokio_tls_connecto.connect(server_name, tcp).await.unwrap();
        let hyper_io = TokioIo::new(connection);

        let (send, conn) = Http2Builder::new(TokioExecutor::new())
            .handshake(hyper_io)
            .await
            .map_err(|e| crate::Error::TransportError(e.into()))
            .unwrap();
        tokio::spawn(conn);
        send
    }
    pub fn new(force_ipv4: bool) -> Self {
        use rustls_platform_verifier::BuilderVerifierExt;

        let mut config = rustls::ClientConfig::builder()
            .with_platform_verifier()
            .with_no_client_auth();
        config.alpn_protocols = vec![b"h2".into()];
        let config = Arc::new(config);

        Self {
            force_ipv4,
            config,
            send: Mutex::new(None),
        }
    }
}

impl Default for Http2Only {
    fn default() -> Self {
        Self::new(false)
    }
}

impl MakeRequest for Http2Only {
    type Body = Incoming;
    type Error = hyper::Error;
    fn request(
        &self,
        request: Request<Full<Bytes>>,
    ) -> impl Future<Output = Result<Response<Self::Body>, Self::Error>> {
        async {
            let mut lock = self.send.lock().await;
            if lock.is_none() {
                let conn = self.make_connection().await;
                *lock = Some(conn)
            }
            lock.as_mut().unwrap().send_request(request).await
        }
    }
}

#[derive(Clone)]
pub struct Retry502<T: MakeRequest> {
    inner: T,
}

impl<T: MakeRequest> Retry502<T> {
    fn wrapping(inner: T) -> Self {
        Self { inner }
    }
}

#[derive(Debug)]
pub enum RetryError<E> {
    Inner(E),
    TimedOut,
}

impl<E: Display> Display for RetryError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Inner(e) => e.fmt(f),
            Self::TimedOut => f.write_str("timed out"),
        }
    }
}

impl<E: Error> Error for RetryError<E> {}

impl<T: MakeRequest> MakeRequest for Retry502<T> {
    type Body = T::Body;
    type Error = RetryError<T::Error>;
    async fn request(
        &self,
        request: Request<Full<Bytes>>,
    ) -> Result<Response<Self::Body>, Self::Error> {
        let sleep_time = Duration::from_millis(250);
        //would be better if this was a timeout wrapper
        let max_sleep = 10;
        let mut slept = 0;

        let resp = loop {
            let resp = self
                .inner
                .request(request.clone())
                .await
                .map_err(RetryError::Inner)?;
            if resp.status() != StatusCode::SERVICE_UNAVAILABLE {
                break resp;
            } else {
                if slept >= max_sleep {
                    return Err(RetryError::TimedOut);
                } else {
                    slept += 1;
                    tokio::time::sleep(sleep_time).await
                }
            }
        };
        Ok(resp)
    }
}

struct TrackSession<T> {
    inner: T,
    session: OnceLock<HeaderValue>,
}

impl<T: MakeRequest> TrackSession<T> {
    fn wrapping(inner: T) -> Self {
        Self {
            inner,
            session: OnceLock::new(),
        }
    }
}

impl<T: MakeRequest> MakeRequest for TrackSession<T> {
    type Body = T::Body;
    type Error = T::Error;
    async fn request(
        &self,
        mut request: Request<Full<Bytes>>,
    ) -> Result<Response<Self::Body>, Self::Error> {
        if let Some(session) = self.session.get() {
            request.headers_mut().append(COOKIE, session.clone());
        }
        match self.inner.request(request).await {
            Ok(resp) => {
                if let Some(cookie) = resp
                    .headers()
                    .get_all(hyper::header::SET_COOKIE)
                    .iter()
                    .filter_map(|hv| hv.to_str().ok().map(|c| Cookie::parse(c).ok()).flatten())
                    .find(|c| c.name() == "BUNSESSION2")
                {
                    if let Ok(hv) = HeaderValue::from_str(&cookie.to_string()) {
                        let _ = self.session.set(hv);
                    }
                }
                Ok(resp)
            }
            x => x,
        }
    }
}

/// A default implementation of the http stack. Requests need to be made from within a tokio runtime.
///
/// This version currently respects the `BUNSESSION2` cookie send by the api server
/// and will retry requests if it receives a response with a 502 statuscode every 250ms, up to a maximum of 10 times.
///
/// this implementation is subject to change in a minor release.
pub struct DefaultTransport(Retry502<TrackSession<Http2Only>>);

impl Default for DefaultTransport {
    fn default() -> Self {
        Self(Retry502::wrapping(TrackSession::wrapping(
            Http2Only::default(),
        )))
    }
}

impl DefaultTransport {
    /// creates a new instance of this transport.
    /// if `force_ipv4` is set to true, it will connect to `api-ipv4.porbun.com` instead of `api.porkbun.com`, forcing the ping command to return an IPv4 address.
    pub fn new(force_ipv4: bool) -> Self {
        Self(Retry502::wrapping(TrackSession::wrapping(Http2Only::new(
            force_ipv4,
        ))))
    }
}

#[derive(Debug)]
pub struct DefaultTransportError(RetryError<hyper::Error>);

impl Display for DefaultTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl Error for DefaultTransportError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.0.source()
    }
}

impl MakeRequest for DefaultTransport {
    type Body = Incoming;
    type Error = DefaultTransportError;
    async fn request(
        &self,
        request: Request<Full<Bytes>>,
    ) -> Result<Response<Self::Body>, Self::Error> {
        self.0.request(request).await.map_err(DefaultTransportError)
    }
}
