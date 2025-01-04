use hyper::http::{uri::InvalidUri, StatusCode};
use serde::Deserialize;
use serde_json::Error as JsonError;
use std::fmt::Display;

#[derive(Deserialize, Debug)]
pub(crate) struct ApiErrorMessage {
    message: String,
}

impl Display for ApiErrorMessage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.message.fmt(f)
    }
}

impl std::error::Error for ApiErrorMessage {}

#[derive(Deserialize, Debug)]
#[serde(tag = "status", rename_all = "UPPERCASE")]
pub(crate) enum ApiResponse<T> {
    Success(T),
    Error(ApiErrorMessage),
}

impl<T> From<ApiResponse<T>> for std::result::Result<T, ApiErrorMessage> {
    fn from(value: ApiResponse<T>) -> Self {
        match value {
            ApiResponse::Success(s) => Ok(s),
            ApiResponse::Error(e) => Err(e),
        }
    }
}

/// The error returned when the upstream API server returns an error
#[derive(Debug)]
pub(crate) struct ApiError {
    status: StatusCode,
    error: Option<ApiErrorMessage>,
}

impl Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Self { status, error } = self;
        if let Some(error) = error {
            f.write_fmt(format_args!("[{status}] {error}"))
        } else {
            f.write_fmt(format_args!("Invalid status code {status}"))
        }
    }
}

#[derive(Debug)]
pub(crate) enum ErrorImpl<T: std::error::Error + Send + Sync + 'static> {
    ApiError(ApiError),
    TransportError(T),
    SerializationError(JsonError),
    DeserializationError(JsonError),
    InvalidUri(InvalidUri),
}

impl<T: std::error::Error + Send + Sync + 'static> From<(StatusCode, Option<ApiErrorMessage>)>
    for ErrorImpl<T>
{
    fn from(value: (StatusCode, Option<ApiErrorMessage>)) -> Self {
        Self::ApiError(ApiError {
            status: value.0,
            error: value.1,
        })
    }
}

impl<T: std::error::Error + Send + Sync + 'static> From<hyper::http::uri::InvalidUri>
    for ErrorImpl<T>
{
    fn from(value: hyper::http::uri::InvalidUri) -> Self {
        Self::InvalidUri(value)
    }
}

impl<T: std::error::Error + Send + Sync + 'static> Display for ErrorImpl<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ApiError(api_error) => api_error.fmt(f),
            Self::DeserializationError(_) => f.write_str("failed to deserialize response"),
            Self::SerializationError(_) => f.write_str("failed to serialize request"),
            Self::TransportError(_) => f.write_str("failed to send request or recieve response"),
            Self::InvalidUri(_) => f.write_str("invalid uri"),
        }
    }
}

impl<T: std::error::Error + Send + Sync + 'static> std::error::Error for ErrorImpl<T> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ApiError { .. } => None,
            Self::TransportError(t) => Some(t),
            Self::SerializationError(s) | Self::DeserializationError(s) => Some(s),
            Self::InvalidUri(u) => Some(u),
        }
    }
}

pub struct Error<T: std::error::Error + Send + Sync + 'static>(ErrorImpl<T>);

impl<T: std::error::Error + Send + Sync + 'static> Error<T> {
    pub fn as_transport_error(&self) -> Option<&T> {
        if let ErrorImpl::TransportError(e) = &self.0 {
            Some(e)
        } else {
            None
        }
    }

    pub fn into_transport_error(self) -> Option<T> {
        if let ErrorImpl::TransportError(e) = self.0 {
            Some(e)
        } else {
            None
        }
    }
}

impl<T: std::error::Error + Send + Sync + 'static> std::fmt::Debug for Error<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(&self.0, f)
    }
}

impl<T: std::error::Error + Send + Sync + 'static> Display for Error<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

impl<T: std::error::Error + Send + Sync + 'static> std::error::Error for Error<T> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

impl<E: std::error::Error + Send + Sync + 'static, T> From<T> for Error<E>
where
    T: Into<ErrorImpl<E>>,
{
    fn from(value: T) -> Self {
        Self(value.into())
    }
}
