//! https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#rfc.section.5
//! https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#introspection-endpoint
//!
//! When the client makes a resource request accompanied by an RPT, the resource server needs to determine whether the RPT is active and, if so, its associated permissions. Depending on the nature of the RPT and operative caching parameters, the resource server MAY take any of the following actions as appropriate to determine the RPT's status:

//! - Introspect the RPT at the authorization server using the OAuth token introspection endpoint (defined in [RFC7662] and this section) that is part of the protection API. The authorization server's response contains an extended version of the introspection response. If the authorization server supports this specification's version of the token introspection endpoint, it MUST declare the endpoint in its discovery document (see Section 2) and support this extended version of the response.
//! - Use a cached copy of the token introspection response if allowed (see Section 4 of [RFC7662]).
//! - Validate the RPT locally if it is self-contained.

//! The use of the token introspection endpoint is illustrated in Figure 4, with a request and a success response shown.
//! 
//! <figure>
//! <pre>
//! 
//!                authorization              resource
//! client             server                  server
//!   |                  |                       |
//!   |Resource request with RPT                 |
//!   |----------------------------------------->|
//!   |                  |                       |
//!   |                  |*PROTECTION API:       |
//!   |                  |*Introspection endpoint|
//!   |                  |                       |
//!   |                  |*Request to introspect |
//!   |                  |token (POST)           |
//!   |                  |<----------------------|
//!   |                  |*Response with token   |
//!   |                  |introspection object   |
//!   |                  |---------------------->|
//!   |                  |                       |
//!   |Protected resource                        |
//!   |<-----------------------------------------|
//! 
//! </pre>
//! <figcaption>Figure 4: Token Introspection Endpoint: Request and Success Response</figcaption>
//! </figure>
//! 
//! The authorization server MAY support both UMA-extended and non-UMA introspection requests and responses.
//!

use crate::storage::KeyValueStore;
use http::{Method, Request, Response, StatusCode};
use oxiri::Iri;
use serde::Serialize;
use std::borrow::Cow;
use std::{ops::Deref, result};
use uuid::Uuid;

use super::errors::{ErrorMessage, INVALID_REQUEST, RESOURCE_NOT_FOUND, UNSUPPORTED_METHOD_TYPE};
use super::federation::ResourceDescription;
use super::permission::PermissionRequest;

// https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#rfc.section.5.1
// https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#token-introspection

// Note: In order for the resource server to know which authorization server, PAT (representing a resource owner), and endpoint to use in making the token introspection API call, it may need to interpret the client's resource request.
//
// Because an RPT is an access token, if the resource server chooses to supply a token type hint, it would use a token_type_hint of access_token.

// https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#rfc.section.5.1.1
// https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#uma-bearer-token-profile


/// The authorization server's response to the resource server MUST use [RFC7662], responding with a JSON object with the structure dictated by that specification, extended as follows.
///
/// If the introspection object's active parameter has a Boolean value of true, then the object MUST NOT contain a scope parameter, and MUST contain an extension parameter named permissions that contains an array of objects, each one (representing a single permission) containing these parameters:
#[derive(Debug, Serialize, Clone/*, Copy */)]
pub struct SuccessfulResponse<'sr> {

    /// REQUIRED. REQUIRED. A string that uniquely identifies the protected resource, access to which has been granted to this client on behalf of this requesting party. The identifier MUST correspond to a resource that was previously registered as protected.
    pub resource_id: &'sr str,

    /// REQUIRED. An array referencing zero or more strings representing scopes to which access was granted for this resource. Each string MUST correspond to a scope that was registered by this resource server for the referenced resource.
    pub resource_scopes: Vec<&'sr str>,

    /// OPTIONAL. Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this permission will expire. If the token-level exp value pre-dates a permission-level exp value, the token-level value takes precedence.
    exp: Option<i64>,

    /// OPTIONAL. Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating when this permission was originally issued. If the token-level iat value post-dates a permission-level iat value, the token-level value takes precedence.
    iat: Option<i64>,

    /// OPTIONAL. Integer timestamp, measured in the number of seconds since January 1 1970 UTC, indicating the time before which this permission is not valid. If the token-level nbf value post-dates a permission-level nbf value, the token-level value takes precedence.
    nbf: Option<i64>,

}

fn catch_errors<T>(result: http::Result<Response<T>>) -> Result<T> {
    return result.map_err(|error: http::Error| {
        // log error
        return ErrorMessage::default().into();
    });
}

type AccessTokenStore = dyn KeyValueStore<Key = String, Value = ResourceDescription>;
type Result<T> = result::Result<Response<T>, Response<ErrorMessage>>;

///
// pub async fn introspect_token<'sr>(
//     store: &'sr mut ResourceDescriptionStore,
//     request: Request<PermissionRequest<'_>>,
// ) -> Result<SuccessfulResponse<'sr>> {
//     if (request.method() != Method::POST) {
//         return Err(UNSUPPORTED_METHOD_TYPE.into());
//     }

//     let id = request.into_body();

//     // ...

//     let ticket = Uuid::new_v4().to_string();

//     let response = Response::builder()
//         .status(StatusCode::CREATED)
//         .body(SuccessfulResponse::new(&id, None, None));

//     return catch_errors(response);
// }


#[cfg(test)]
mod tests {

    use super::*;

    // assert! assert_eq! assert_ne! #[should_panic(expected = "panic msg")] -> Result<(), String> ?

    #[test]
    fn test() {

        // assert!( result.contains("Carol"), "Greeting did not contain name, value was `{}`", result );

        // POST /introspect HTTP/1.1
        // Host: as.example.com
        // Authorization: Bearer 204c69636b6c69
        // ...
        // token=sbjsbhs(/SSJHBSUSSJHVhjsgvhsgvshgsv

        // HTTP/1.1 200 OK
        // Content-Type: application/json
        // Cache-Control: no-store
        // ...

        // {  
        // "active":true,
        // "exp":1256953732,
        // "iat":1256912345,
        // "permissions":[  
        //     {  
        //         "resource_id":"112210f47de98100",
        //         "resource_scopes":[  
        //             "view",
        //             "http://photoz.example.com/dev/actions/print"
        //         ],
        //         "exp":1256953732
        //     }
        // ]
        // }


    }



}
