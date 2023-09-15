//! https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#rfc.section.4
//! https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#permission-endpoint
//!
//! The permission endpoint defines a means for the resource server to request one or more permissions (resource identifiers and corresponding scopes) with the authorization server on the client's behalf, and to receive a permission ticket in return, in order to respond as indicated in Section 3.2 of [UMAGrant]. The resource server uses this endpoint on the following occasions:
//! 
//! - After the client's initial resource request without an access token
//! - After the client's resource request that was accompanied by an invalid RPT or a valid RPT that had insufficient permissions associated with it
//! 
//! The use of the permission endpoint is illustrated in Figure 3, with a request and a success response shown.
//! 
//! <figure>
//! <pre>
//! 
//!                authorization            resource
//! client             server                server
//!   |                  |                     |
//!   |Request resource (no or insufficient    |
//!   |access token)     |                     |
//!   |--------------------------------------->|
//!   |                  |                     |
//!   |                  |*PROTECTION API:     |
//!   |                  |*Permission endpoint |
//!   |                  |                     |
//!   |                  |*Request permissions |
//!   |                  |(POST)               |
//!   |                  |<--------------------|
//!   |                  |*201 Created with    |
//!   |                  |permission ticket    |
//!   |                  |-------------------->|
//!   |                  |                     |
//!   |401 response with permission ticket,    |
//!   |authz server location                   |
//!   |<---------------------------------------|
//!
//! </pre>
//! <figcaption>Figure 3: Permission Endpoint: Request and Success Response</figcaption>
//! </figure>
//! 

//! The PAT provided in the API request enables the authorization server to map the resource server's request to the appropriate resource owner. It is only possible to request permissions for access to the resources of a single resource owner, protected by a single authorization server, at a time.

//! In its response, the authorization server returns a permission ticket for the resource server to give to the client that represents the same permissions that the resource server requested.

//! The process of choosing what permissions to request from the authorization server may require interpretation and mapping of the client's resource request. The resource server SHOULD request a set of permissions with scopes that is reasonable for the client's resource request. The resource server MAY request multiple permissions, and any permission MAY have zero scopes associated with it. Requesting multiple permissions might be appropriate, for example, in cases where the resource server expects the requesting party to need access to several related resources if they need access to any one of the resources (see Section 3.3.4 of [UMAGrant] for an example). Requesting a permission with no scopes might be appropriate, for example, in cases where an access attempt involves an API call that is ambiguous without further context (role-based scopes such as user and admin could have this ambiguous quality, and an explicit client request for a particular scope at the token endpoint later can clarify the desired access). The resource server SHOULD document its intended pattern of permission requests in order to assist the client in pre-registering for and requesting appropriate scopes at the authorization server. See [UMA-Impl] for a discussion of permission request patterns.

//! Note: In order for the resource server to know which authorization server to approach for the permission ticket and on which resource owner's behalf (enabling a choice of permission endpoint and PAT), it needs to derive the necessary information using cues provided by the structure of the API where the resource request was made, rather than by an access token. Commonly, this information can be passed through the URI, headers, or body of the client's request. Alternatively, the entire interface could be dedicated to the use of a single resource owner and protected by a single authorization server.

// [short sentence explaining what it is]
// 
// [more detailed explanation]
// 
// [at least one code example that users can copy/paste to try it]
// 
// [even more advanced explanations if necessary]
// 
// use titles as # Panics and # Examples


use crate::storage::KeyValueStore;
use http::{Method, Request, Response, StatusCode};
use oxiri::Iri;
use serde::Serialize;
use std::borrow::Cow;
use std::{ops::Deref, result};
use uuid::Uuid;

use super::errors::{ErrorMessage, INVALID_REQUEST, RESOURCE_NOT_FOUND, UNSUPPORTED_METHOD_TYPE};
use super::federation::ResourceDescription;

// https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#rfc.section.4.1


/// The resource server uses the POST method at the permission endpoint. The body of the HTTP request message contains a JSON object for requesting a permission for single resource identifier, or an array of one or more objects for requesting permissions for a corresponding number of resource identifiers. The object format in both cases is derived from the resource description format specified in Section 3.1; it has the following parameters:
#[derive(Debug, Serialize, Clone/*, Copy*/)]
pub struct Permission<'p> {

    /// REQUIRED. The identifier for a resource to which the resource server is requesting a permission on behalf of the client. The identifier MUST correspond to a resource that was previously registered.
    pub resource_id: &'p str,

    /// REQUIRED. An array referencing zero or more identifiers of scopes to which the resource server is requesting access for this resource on behalf of the client. Each scope identifier MUST correspond to a scope that was previously registered by this resource server for the referenced resource.
    pub resource_scopes: Vec<&'p str>,

}

impl<'p> Permission<'p> {
    pub fn new(
        resource_id: &'p str,
        resource_scopes: Vec<&'p str>,
    ) -> Self {
        Self {
            resource_id,
            resource_scopes,
        }
    }
}

pub type PermissionRequest<'pr> = Vec<Permission<'pr>>; // !! or single object

// https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#rfc.section.4.2

/// If the authorization server is successful in creating a permission ticket in response to the resource server's request, it responds with an HTTP 201 (Created) status code and includes the ticket parameter in the JSON-formatted body. Regardless of whether the request contained one or multiple permissions, only a single permission ticket is returned.
#[derive(Debug, Serialize, Clone/*, Copy*/)]
pub struct PermissionTicket<'pt> {

    /// REQUIRED. The identifier for a resource to which the resource server is requesting a permission on behalf of the client. The identifier MUST correspond to a resource that was previously registered.
    pub ticket: &'pt str,

    /// REQUIRED. An array referencing zero or more identifiers of scopes to which the resource server is requesting access for this resource on behalf of the client. Each scope identifier MUST correspond to a scope that was previously registered by this resource server for the referenced resource.
    pub permissions: Vec<Permission<'pt>>,

}

#[derive(Debug, Serialize, Clone/*, Copy*/)]
pub struct SuccessfulResponse<'sr> { pub ticket: &'sr str  }

impl<'sr> SuccessfulResponse<'sr> {
    pub fn new( ticket: &'sr str ) -> Self { Self { ticket } }
}

// https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#rfc.section.4.3

pub const INVALID_RESOURCE_ID: ErrorMessage = ErrorMessage::new(
    StatusCode::BAD_REQUEST,
    Cow::Borrowed("invalid_resource_id"),
    Some(Cow::Borrowed(
        "At least one of the provided resource identifiers was not found at the authorization server.",
    )),
    None,
);

pub const INVALID_SCOPE: ErrorMessage = ErrorMessage::new(
    StatusCode::BAD_REQUEST,
    Cow::Borrowed("invalid_scope"),
    Some(Cow::Borrowed(
        "At least one of the scopes included in the request was not registered previously by this resource server for the referenced resource.",
    )),
    None,
);

fn catch_errors<T>(result: http::Result<Response<T>>) -> Result<T> {
    return result.map_err(|error: http::Error| {
        // log error
        return ErrorMessage::default().into();
    });
}

type ResourceDescriptionStore = dyn KeyValueStore<Key = String, Value = ResourceDescription>;
type PermissionTicketStore<'pts> = dyn KeyValueStore<Key = String, Value = Vec<Permission<'pts>>>;
type Result<T> = result::Result<Response<T>, Response<ErrorMessage>>;

///
pub async fn request_permission_ticket<'sr>(
    store: &'sr mut PermissionTicketStore<'sr>,
    request: Request<PermissionRequest<'sr>>,
) -> Result<SuccessfulResponse<'sr>> {
    if (request.method() != Method::POST) {
        return Err(UNSUPPORTED_METHOD_TYPE.into());
    }

    let permission_request = request.into_body();

    // ...
    let granted_permissions = permission_request;
    // ...

    let ticket = Uuid::new_v4().to_string();
    let ticket = store.set(ticket, granted_permissions);

    let response = Response::builder()
        .status(StatusCode::CREATED)
        .body(SuccessfulResponse::new(ticket));

    return catch_errors(response);
}


#[cfg(test)]
mod tests {

    use super::*;

    // assert! assert_eq! assert_ne! #[should_panic(expected = "panic msg")] -> Result<(), String> ?

    #[test]
    fn test() {

        // assert!( result.contains("Carol"), "Greeting did not contain name, value was `{}`", result );

        // POST /perm HTTP/1.1
        // Content-Type: application/json
        // Host: as.example.com
        // Authorization: Bearer 204c69636b6c69
        // ...
        //
        // {  
        // "resource_id":"112210f47de98100",
        // "resource_scopes":[  
        //     "view",
        //     "http://photoz.example.com/dev/actions/print"
        // ]
        // }

        // HTTP/1.1 201 Created
        // Content-Type: application/json
        // ...

        // {  
        // "ticket":"016f84e8-f9b9-11e0-bd6f-0021cc6004de"
        // }


    }


        // POST /perm HTTP/1.1
        // Content-Type: application/json
        // Host: as.example.com
        // Authorization: Bearer 204c69636b6c69
        // ...
        //
        // [  
        // {  
        //     "resource_id":"7b727369647d",
        //     "resource_scopes":[  
        //         "view",
        //         "crop",
        //         "lightbox"
        //     ]
        // },
        // {  
        //     "resource_id":"7b72736964327d",
        //     "resource_scopes":[  
        //         "view",
        //         "layout",
        //         "print"
        //     ]
        // },
        // {  
        //     "resource_id":"7b72736964337d",
        //     "resource_scopes":[  
        //         "http://www.example.com/scopes/all"
        //     ]
        // }
        // ]

}
