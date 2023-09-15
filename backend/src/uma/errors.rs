//! https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#rfc.section.6
//! https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#errors
//! If a request is successfully authenticated, but is invalid for another reason,
//! the authorization server produces an error response by supplying a JSON-encoded object
//! with the following members in the body of the HTTP response.

use std::borrow::Cow;

use http::{Response, StatusCode};
use oxiri::Iri;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct ErrorMessage {
    /// [NO-SPEC] REQUIRED. HTTP status code for responses carrying this error message.
    #[serde(skip_serializing)]
    pub status_code: StatusCode,

    /// REQUIRED except as noted. A single error code. Values for this parameter are defined throughout this specification.
    #[serde(rename = "error")]
    pub error_code: Cow<'static, str>,

    /// OPTIONAL. Human-readable text providing additional information.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_description: Option<Cow<'static, str>>,

    /// OPTIONAL. A URI identifying a human-readable web page with information about the error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_uri: Option<Iri<String>>,
}

// use the following when const_convert feature is back:  fn f<'a>(s: impl Into<Cow<'a, str>>) -> Cow<'a, str> {
impl ErrorMessage {
    pub const fn new(
        status_code: StatusCode,
        error_code: Cow<'static, str>,
        error_description: Option<Cow<'static, str>>,
        error_uri: Option<Iri<String>>,
    ) -> Self {
        Self {
            status_code,
            error_code: error_code,
            error_description,
            error_uri,
        }
    }
}

const DEFAULT: ErrorMessage = ErrorMessage::new(
    StatusCode::INTERNAL_SERVER_ERROR,
    Cow::Borrowed("internal_server_error"),
    Some(Cow::Borrowed(
        "Something went wrong. Could not create a more specific error.",
    )),
    None,
);

impl Default for ErrorMessage {
    fn default() -> Self {
        DEFAULT
    }
}

impl From<ErrorMessage> for Response<ErrorMessage> {
    fn from(msg: ErrorMessage) -> Response<ErrorMessage> {
        return Response::builder()
            .status(msg.status_code)
            .header("Content-Type", "application/json")
            .header("Cache-Control", "no-store")
            .body(msg)
            .unwrap_or_default();
    }
}

/// If the request to the resource registration endpoint is incorrect, then the authorization server instead responds as follows (see Section 6 for information about error messages):
pub enum ResourceRegistrationFailure {
    /// If the referenced resource cannot be found, the authorization server MUST respond with an HTTP 404 (Not Found) status code and MAY respond with a not_found error code.
    ResourceNotFound,

    /// If the resource server request used an unsupported HTTP method, the authorization server MUST respond with the HTTP 405 (Method Not Allowed) status code and MAY respond with an unsupported_method_type error code.
    UnsupportedMethod,

    /// If the request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed, the authorization server MUST respond with the HTTP 400 (Bad Request) status code and MAY respond with an invalid_request error code.
    InvalidRequest,
}

pub const RESOURCE_NOT_FOUND: ErrorMessage = ErrorMessage::new(
    StatusCode::NOT_FOUND,
    Cow::Borrowed("not_found"),
    Some(Cow::Borrowed("The referenced resource could be found.")),
    None,
);

pub const UNSUPPORTED_METHOD_TYPE: ErrorMessage = ErrorMessage::new(
    StatusCode::NOT_FOUND,
    Cow::Borrowed("unsupported_method_type"),
    Some(Cow::Borrowed(
        "The request used an unsupported HTTP method.",
    )),
    None,
);

pub const INVALID_REQUEST: ErrorMessage = ErrorMessage::new(
  StatusCode::BAD_REQUEST,
  Cow::Borrowed("invalid_request"), 
  Some(Cow::Borrowed("The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed.")), 
  None
);
