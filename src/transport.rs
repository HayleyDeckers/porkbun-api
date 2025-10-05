//! HTTP transport layer traits and implementations
use http_body_util::Full;
use hyper::body::Body;
use hyper::{body::Bytes, Request, Response};

use std::future::Future;

/// A trait representing an HTTP request-response action. This trait needs to be implemented by a type in order to be used as a transport layer by the [Client](crate::Client).
pub trait MakeRequest: Sized {
    /// The HTTP body type of the returned response.
    /// In order for a type to be useable as a transport layer for the [Client](crate::Client)
    /// `Body::Error` has to implement `Into<Self::Error>`.
    type Body: Body;
    /// The error type this interface can return
    type Error: std::error::Error + Send + Sync + 'static;
    /// Perform an HTTP request, returning a response asynchronously.
    fn request(
        &self,
        request: Request<Full<Bytes>>,
    ) -> impl Future<Output = std::result::Result<Response<Self::Body>, Self::Error>>;
}

#[cfg(feature = "default-client")]
mod default_impl {
    use super::MakeRequest;
    use cookie::time::OffsetDateTime;
    use cookie::{Cookie, CookieJar};
    use http_body_util::Full;
    use hyper::client::conn::http2::Builder as Http2Builder;
    use hyper::{
        body::{Bytes, Incoming},
        client::conn::http2::SendRequest,
        Request, Response, StatusCode,
    };
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use rustls::ClientConfig;
    use std::{
        error::Error,
        fmt::{Debug, Display},
        sync::Arc,
        time::Duration,
    };
    use tokio::{
        net::TcpStream,
        sync::{Mutex, RwLock},
    };
    use tokio_rustls::TlsConnector;

    struct Http2Only {
        force_ipv4: bool,
        config: Arc<ClientConfig>,
        send: tokio::sync::Mutex<Option<SendRequest<Full<Bytes>>>>,
    }

    impl Http2Only {
        async fn make_connection(&self) -> Result<SendRequest<Full<Bytes>>, DefaultTransportError> {
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
            .map_err(DefaultTransportErrorImpl::ConnectionError)?;
            let connection = tokio_tls_connecto
                .connect(server_name, tcp)
                .await
                .map_err(DefaultTransportErrorImpl::ConnectionError)?;
            let hyper_io = TokioIo::new(connection);

            let (send, conn) = Http2Builder::new(TokioExecutor::new())
                .handshake(hyper_io)
                .await?;
            tokio::spawn(conn);
            Ok(send)
        }
        pub fn new(force_ipv4: bool) -> Self {
            use rustls_platform_verifier::BuilderVerifierExt;

            let mut config = rustls::ClientConfig::builder()
                .with_platform_verifier()
                .expect("Failed to create platform verifier")
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
        type Error = DefaultTransportError;
        async fn request(
            &self,
            request: Request<Full<Bytes>>,
        ) -> Result<Response<Self::Body>, Self::Error> {
            let mut lock = self.send.lock().await;
            if lock.is_none() || lock.as_ref().is_some_and(|l| l.is_closed()) {
                let conn = self.make_connection().await?;
                *lock = Some(conn)
            }
            let sender = lock.as_mut().unwrap();
            sender.ready().await?;
            sender
                .send_request(request)
                .await
                .map_err(DefaultTransportError::from)
        }
    }

    #[derive(Clone)]
    struct Retry502<T: MakeRequest> {
        inner: T,
    }

    impl<T: MakeRequest> Retry502<T> {
        fn wrapping(inner: T) -> Self {
            Self { inner }
        }
    }

    impl<E, T: MakeRequest<Error = E>> MakeRequest for Retry502<T>
    where
        DefaultTransportError: From<E>,
    {
        type Body = T::Body;
        type Error = DefaultTransportError;
        async fn request(
            &self,
            request: Request<Full<Bytes>>,
        ) -> Result<Response<Self::Body>, Self::Error> {
            let sleep_time = Duration::from_millis(250);
            //would be better if this was a timeout wrapper
            let max_sleep = 10;
            let mut slept = 0;

            let resp = loop {
                let resp = self.inner.request(request.clone()).await?;
                if resp.status() != StatusCode::SERVICE_UNAVAILABLE {
                    break resp;
                } else if slept >= max_sleep {
                    return Err(DefaultTransportError(DefaultTransportErrorImpl::RetryError));
                } else {
                    slept += 1;
                    tokio::time::sleep(sleep_time).await
                }
            };
            Ok(resp)
        }
    }

    /// A structure that tracks cookies for requests and responses.
    ///
    /// This structure manages cookies according to [RFC 6265](https://datatracker.ietf.org/doc/html/rfc6265).
    /// it is not fully compliant (it doesn't check the secure flag, doesn't purge expired entries)
    /// but should be good enough for just talking to porkbun.
    pub struct TrackCookies<T> {
        inner: T,
        cookie_jar: RwLock<CookieJar>,
    }

    impl<T> TrackCookies<T> {
        /// Creates a new `TrackCookies` instance.
        pub fn wrapping(inner: T) -> Self {
            Self {
                inner,
                cookie_jar: RwLock::new(CookieJar::new()),
            }
        }

        /// Checks if a cookie is valid for the given request.
        fn is_cookie_valid_for_request(cookie: &Cookie, request: &Request<Full<Bytes>>) -> bool {
            // Check domain
            if let Some(domain) = cookie.domain() {
                if !request.uri().host().unwrap_or("").ends_with(domain) {
                    return false;
                }
            }
            // Check path
            if let Some(path) = cookie.path() {
                if !request.uri().path().starts_with(path) {
                    return false;
                }
            }
            // Check if the cookie is expired
            if let Some(expires) = cookie.expires_datetime() {
                if expires <= OffsetDateTime::now_utc() {
                    return false;
                }
            }
            true
        }
    }
    impl<T: MakeRequest> MakeRequest for TrackCookies<T> {
        type Body = T::Body;
        type Error = T::Error;
        /// Makes a request, adding cookies to the request and extracting cookies from the response.
        async fn request(
            &self,
            mut request: Request<Full<Bytes>>,
        ) -> Result<Response<T::Body>, T::Error> {
            // Add cookies to the request
            let cookie_header = {
                let jar = self.cookie_jar.read().await;
                jar.iter()
                    .filter(|cookie| Self::is_cookie_valid_for_request(cookie, &request))
                    .map(|c| {
                        let (name, value) = c.name_value_trimmed();
                        format!("{name}={value}")
                    })
                    .collect::<Vec<_>>()
                    .join("; ")
            };

            if !cookie_header.is_empty() {
                request
                    .headers_mut()
                    .insert(hyper::header::COOKIE, cookie_header.parse().unwrap());
            }

            let response = self.inner.request(request).await?;

            // parse_encoded, parse_split_encoded
            let cookies = response
                .headers()
                .get_all(hyper::header::SET_COOKIE)
                .iter()
                .filter_map(|h| h.to_str().ok())
                .filter_map(|s| Cookie::parse(s).ok())
                .collect::<Vec<_>>();

            // Extract cookies from the response
            if !cookies.is_empty() {
                let mut jar = self.cookie_jar.write().await;
                for cookie in cookies {
                    jar.add(cookie.into_owned());
                }
            }

            Ok(response)
        }
    }

    /// A default implementation of the http stack. Requests need to be made from within a tokio runtime.
    ///
    /// This version currently respects the `BUNSESSION2` cookie send by the api server
    /// and will retry requests if it receives a response with a 502 statuscode every 250ms, up to a maximum of 10 times.
    ///
    /// this implementation is subject to change in a minor release.
    pub struct DefaultTransport(Retry502<TrackCookies<Http2Only>>);

    impl Default for DefaultTransport {
        fn default() -> Self {
            Self(Retry502::wrapping(TrackCookies::wrapping(
                Http2Only::default(),
            )))
        }
    }

    impl DefaultTransport {
        /// creates a new instance of this transport.
        /// if `force_ipv4` is set to true, it will connect to `api-ipv4.porbun.com` instead of `api.porkbun.com`, forcing the ping command to return an IPv4 address.
        pub fn new(force_ipv4: bool) -> Self {
            Self(Retry502::wrapping(TrackCookies::wrapping(Http2Only::new(
                force_ipv4,
            ))))
        }
    }

    #[allow(clippy::enum_variant_names)]
    #[derive(Debug)]
    enum DefaultTransportErrorImpl {
        ConnectionError(std::io::Error),
        RetryError,
        HttpError(hyper::Error),
    }

    impl From<hyper::Error> for DefaultTransportErrorImpl {
        fn from(value: hyper::Error) -> Self {
            Self::HttpError(value)
        }
    }

    /// The error type returned by [DefaultTransport]
    pub struct DefaultTransportError(DefaultTransportErrorImpl);

    impl Debug for DefaultTransportError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            Debug::fmt(&self.0, f)
        }
    }

    impl<T> From<T> for DefaultTransportError
    where
        T: Into<DefaultTransportErrorImpl>,
    {
        fn from(value: T) -> Self {
            Self(value.into())
        }
    }

    impl Error for DefaultTransportError {
        fn source(&self) -> Option<&(dyn Error + 'static)> {
            match &self.0 {
                DefaultTransportErrorImpl::ConnectionError(e) => Some(e),
                DefaultTransportErrorImpl::HttpError(e) => Some(e),
                DefaultTransportErrorImpl::RetryError => None,
            }
        }
    }

    impl Display for DefaultTransportError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(match self.0 {
                DefaultTransportErrorImpl::ConnectionError(_) => "Failed to connect to endpoint",
                DefaultTransportErrorImpl::HttpError(_) => "HTTP protocol error",
                DefaultTransportErrorImpl::RetryError => {
                    "Server took to many tries to reply with a non-502 statuscode"
                }
            })
        }
    }

    impl MakeRequest for DefaultTransport {
        type Body = Incoming;
        type Error = DefaultTransportError;
        async fn request(
            &self,
            request: Request<Full<Bytes>>,
        ) -> Result<Response<Self::Body>, Self::Error> {
            self.0.request(request).await
        }
    }
}

#[cfg(feature = "default-client")]
pub use default_impl::*;
