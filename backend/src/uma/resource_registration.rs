//! https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#rfc.section.3
//! https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#resource-registration-endpoint
//!
//! The API available at the resource registration endpoint enables the resource server to put resources under the
//! protection of an authorization server on behalf of the resource owner and manage them over time. Protection of a
//! resource at the authorization server begins on successful registration and ends on successful deregistration.
//!
//! The resource server uses a RESTful API at the authorization server's resource registration endpoint to create, read,
//! update, and delete resource descriptions, along with retrieving lists of such descriptions. The descriptions consist
//! of JSON documents that are maintained as web resources at the authorization server. (Note carefully the similar but
//! distinct senses in which the word "resource" is used in this section.)
//! 
//! Figure 2 illustrates the resource registration API operations, with requests and success responses shown.
//! 
//! <figure>
//! <pre>
//! 
//! authorization              resource         resource
//!     server                  server           owner
//!       |                       |                |
//!       |*PROTECTION API:       |                |
//!       |*Resource registration |                |
//!       |endpoint/API           |                |
//!       |                       |                |
//!       |*Create resource (POST)|                |
//!       |<----------------------|                |
//!       |*201 Created with      |                |
//!       |resource ID            |                |
//!       |---------------------->|                |
//!       |                       |                |
//!       |Set policy conditions (anytime          |
//!       |before deletion/deregistration)         |
//!       |<- - - - - - - - - - - - - - - - - - - -|
//!       |                       |                |
//!       |*Read (GET) with       |                |
//!       |resource ID            |                |
//!       |<----------------------|                |
//!       |*200 OK with resource  |                |
//!       |representation         |                |
//!       |---------------------->|                |
//!       |*Update (PUT) with     |                |
//!       |resource ID            |                |
//!       |<----------------------|                |
//!       |*200 OK with resource  |                |
//!       |ID                     |                |
//!       |---------------------->|                |
//!       |*List (GET)            |                |
//!       |<----------------------|                |
//!       |*200 OK with list of   |                |
//!       |resource IDs           |                |
//!       |---------------------->|                |
//!       |*Delete (DELETE) with  |                |
//!       |resource ID            |                |
//!       |<----------------------|                |
//!       |*200 OK or 204 No      |                |
//!       |Content                |                |
//!       |---------------------->|                |
//!
//! </pre>
//! <figcaption>Figure 2: Resource Registration Endpoint and API: Requests and Success Responses</figcaption>
//! </figure>
//!
//! The resource server MAY protect any subset of the resource owner's resources using different authorization servers
//! or other means entirely, or to protect some resources and not others. Additionally, the choice of protection regimes
//! MAY be made explicitly by the resource owner or implicitly by the resource server. Any such partitioning by the
//! resource server or owner is outside the scope of this specification.
//!
//! The resource server MAY register a single resource for protection that, from its perspective, has multiple parts, or
//! has dynamic elements such as the capacity for querying or filtering, or otherwise has internal complexity. The
//! resource server alone is responsible for maintaining any required mappings between internal representations and the
//! resource identifiers and scopes known to the authorization server.
//!
//! Note: The resource server is responsible for managing the process and timing of registering resources, maintaining
//! the registration of resources, and deregistering resources at the authorization server. Motivations for updating a
//! resource might include, for example, new scopes added to a new API version or resource owner actions at a resource
//! server that result in new resource description text. See [UMA-Impl] for a discussion of initial resource
//! registration timing options.
//! 
//! 
//! 

// https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#rfc.section.3.2
// https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#reg-api

use crate::storage::KeyValueStore;
use http::{Method, Request, Response, StatusCode};
use oxiri::Iri;
use serde::Serialize;
use std::{ops::Deref, result};
use uuid::Uuid;

use super::errors::{ErrorMessage, INVALID_REQUEST, RESOURCE_NOT_FOUND, UNSUPPORTED_METHOD_TYPE};
use super::federation::ResourceDescription;

/// The authorization server MUST support the following five registration options and MUST require a valid PAT for
/// access to them; any other operations are undefined by this specification. Here, rreguri stands for the resource
/// registration endpoint and _id stands for the authorization server-assigned identifier for the web resource
/// corresponding to the resource at the time it was created, included within the URL returned in the Location header.
/// Each operation is defined in its own section below.
///
/// - Create resource description: POST rreguri/
/// - Read resource description: GET rreguri/_id
/// - Update resource description: PUT rreguri/_id
/// - Delete resource description: DELETE rreguri/_id
/// - List resource descriptions: GET rreguri/

/// Within the JSON body of a successful response, the authorization server includes common parameters, possibly in
/// addition to method-specific parameters, as follows:
#[derive(Debug, Serialize, Clone, Copy)]
pub struct SuccessfulResponse<'sr> {
    /// REQUIRED (except for the Delete and List methods). A string value repeating the authorization server-defined
    /// identifier for the web resource corresponding to the resource. Its appearance in the body makes it readily
    /// available as an identifier for various protected resource management tasks.
    pub _id: &'sr str,

    /// OPTIONAL. A URI that allows the resource server to redirect an end-user resource owner to a specific user
    /// interface within the authorization server where the resource owner can immediately set or modify access policies
    /// subsequent to the resource registration action just completed. The authorization server is free to choose the
    /// targeted user interface, for example, in the case of a deletion action, enabling the resource server to direct the
    /// end-user to a policy-setting interface for an overall "folder" resource formerly "containing" the deleted resource
    /// (a relationship the authorization server is not aware of), to enable adjustment of related policies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_access_policy_uri: Option<Iri<&'sr str>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub resource_description: Option<&'sr ResourceDescription>,
}

impl<'sr> SuccessfulResponse<'sr> {
    pub fn new(
        _id: &'sr str,
        user_access_policy_uri: Option<Iri<&'sr str>>,
        resource_description: Option<&'sr ResourceDescription>,
    ) -> Self {
        Self {
            _id,
            user_access_policy_uri,
            resource_description,
        }
    }
}

impl<'sr> Deref for SuccessfulResponse<'sr> {
    type Target = Option<&'sr ResourceDescription>;

    fn deref(&self) -> &Self::Target {
        return &self.resource_description;
    }
}

fn catch_errors<T>(result: http::Result<Response<T>>) -> Result<T> {
    return result.map_err(|error: http::Error| {
        // log error
        return ErrorMessage::default().into();
    });
}

type ResourceDescriptionStore = dyn KeyValueStore<Key = String, Value = ResourceDescription>;
type Result<T> = result::Result<Response<T>, Response<ErrorMessage>>;

/// https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#rfc.section.3.2.1
/// https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#create-rreg

/// Adds a new resource description to the authorization server using the POST method. If the request is successful, the
/// resource is thereby registered and the authorization server MUST respond with an HTTP 201 status message that
/// includes a Location header and an _id parameter.

pub async fn create_resource_registration<'sr>(
    store: &'sr mut ResourceDescriptionStore,
    request: Request<ResourceDescription>,
) -> Result<SuccessfulResponse<'sr>> {
    if (request.method() != Method::POST) {
        return Err(UNSUPPORTED_METHOD_TYPE.into());
    }

    let id = Uuid::new_v4().to_string();
    let id = store.set(id, request.into_body());

    let response = Response::builder()
        .status(StatusCode::CREATED)
        .body(SuccessfulResponse::new(&id, None, None));

    return catch_errors(response);
}

/// https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#rfc.section.3.2.2
/// https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#read-rreg
///
/// Reads a previously registered resource description using the GET method. If the request is successful, the
/// authorization server MUST respond with an HTTP 200 status message that includes a body containing the referenced
/// resource description, along with an _id parameter.

pub async fn read_resource_registration<'sr>(
    store: &'sr mut ResourceDescriptionStore,
    request: &'sr Request<!>,
) -> Result<SuccessfulResponse<'sr>> {
    if (request.method() != Method::GET) {
        return Err(UNSUPPORTED_METHOD_TYPE.into());
    }

    let id = request.uri().path().trim_start_matches("/");

    match store.get(&id.to_string()) {
        Some(description) => {
            let response = Response::builder()
                .status(StatusCode::OK)
                .body(SuccessfulResponse::new(id.clone(), None, Some(description)));
            return catch_errors(response);
        }
        None => return Err(RESOURCE_NOT_FOUND.into()),
    }
}

/// https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#rfc.section.3.2.3
/// https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#update-resource-set
///
/// Updates a previously registered resource description, by means of a complete replacement of the previous resource
/// description, using the PUT method. If the request is successful, the authorization server MUST respond with an HTTP
/// 200 status message that includes an _id parameter.
pub async fn update_resource_registration<'sr>(
    store: &'sr mut ResourceDescriptionStore,
    request: Request<ResourceDescription>,
) -> Result<SuccessfulResponse<'sr>> {
    if (request.method() != Method::PUT) {
        return Err(UNSUPPORTED_METHOD_TYPE.into());
    }

    let id = request.uri().path().trim_start_matches("/");
    let id = store.set(id.to_string(), request.into_body());

    let response = Response::builder()
        .status(StatusCode::OK)
        .body(SuccessfulResponse::new(&id, None, None));

    return catch_errors(response);
}

/// https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#rfc.section.3.2.4
/// https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#delete-rreg
///
/// Deletes a previously registered resource description using the DELETE method. If the request is successful, the
/// resource is thereby deregistered and the authorization server MUST respond with an HTTP 200 or 204 status message.
pub async fn delete_resource_registration<'sr>(
    store: &'sr mut ResourceDescriptionStore,
    request: &'sr Request<!>,
) -> Result<SuccessfulResponse<'sr>> {
    if (request.method() != Method::DELETE) {
        return Err(UNSUPPORTED_METHOD_TYPE.into());
    }

    let id = request.uri().path().trim_start_matches("/");

    match store.del(&id.to_string()) {
        Some(_) => {
            let response = Response::builder()
                .status(StatusCode::NO_CONTENT)
                .body(SuccessfulResponse::new(id, None, None));
            return catch_errors(response);
        }
        None => return Err(RESOURCE_NOT_FOUND.into()),
    }
}

/// https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#rfc.section.3.2.5
/// https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#list-rreg
///
/// Lists all previously registered resource identifiers for this resource owner using the GET method. The authorization
/// server MUST return the list in the form of a JSON array of _id string values.
///
/// The resource server can use this method as a first step in checking whether its understanding of protected resources
/// is in full synchronization with the authorization server's understanding.
pub async fn list_resource_registration<'it>(
    store: &'it mut ResourceDescriptionStore,
    request: &'it Request<!>,
) -> Result<Box<dyn Iterator<Item = &'it String> + 'it>> {
    if (request.method() != Method::GET) {
        return Err(UNSUPPORTED_METHOD_TYPE.into());
    }
    if (request.uri().path() != "/") {
        return Err(INVALID_REQUEST.into());
    }

    let keys = store.list();

    let response = Response::builder().status(StatusCode::OK).body(keys);

    return catch_errors(response);
}

#[cfg(test)]
mod tests {

    use super::*;

    // assert! assert_eq! assert_ne! #[should_panic(expected = "panic msg")] -> Result<(), String> ?

    #[test]
    fn test() {

        // assert!( result.contains("Carol"), "Greeting did not contain name, value was `{}`", result );

        // POST /rreg/ HTTP/1.1 Content-Type: application/json
        // Authorization: Bearer MHg3OUZEQkZBMjcx
        // ...
        // {  
        //   "resource_scopes":[  
        //       "read-public",
        //       "post-updates",
        //       "read-private",
        //       "http://www.example.com/scopes/all"
        //   ],
        //   "icon_uri":"http://www.example.com/icons/sharesocial.png",
        //   "name":"Tweedl Social Service",
        //   "type":"http://www.example.com/rsrcs/socialstream/140-compatible"
        // }

        // HTTP/1.1 201 Created
        // Content-Type: application/json
        // Location: /rreg/KX3A-39WE
        // ...
        // {  
        //   "_id":"KX3A-39WE",
        //   "user_access_policy_uri":"http://as.example.com/rs/222/resource/KX3A-39WE/policy"
        // }

    }

    // GET /rreg/KX3A-39WE HTTP/1.1
    // Authorization: Bearer MHg3OUZEQkZBMjcx
    // ...

    // HTTP/1.1 200 OK
    // Content-Type: application/json
    // ...
    // {  
    //   "_id":"KX3A-39WE",
    //   "resource_scopes":[  
    //       "read-public",
    //       "post-updates",
    //       "read-private",
    //       "http://www.example.com/scopes/all"
    //   ],
    //   "icon_uri":"http://www.example.com/icons/sharesocial.png",
    //   "name":"Tweedl Social Service",
    //   "type":"http://www.example.com/rsrcs/socialstream/140-compatible"
    // }

    // PUT /rreg/9UQU-DUWW HTTP/1.1
    // Content-Type: application/json
    // Authorization: Bearer 204c69636b6c69
    // ...
    // {  
    //   "resource_scopes":[  
    //       "http://photoz.example.com/dev/scopes/view",
    //       "public-read"
    //   ],
    //   "description":"Collection of digital photographs",
    //   "icon_uri":"http://www.example.com/icons/sky.png",
    //   "name":"Photo Album",
    //   "type":"http://www.example.com/rsrcs/photoalbum"
    // }

    // HTTP/1.1 200 OK
    // ...
    // {  
    //   "_id":"9UQU-DUWW"
    // }

    // DELETE /rreg/9UQU-DUWW
    // Authorization: Bearer 204c69636b6c69
    // ...

    // HTTP/1.1 204 No content
    // ...

    // GET /rreg/ HTTP/1.1
    // Authorization: Bearer 204c69636b6c69
    // ...

    // HTTP/1.1 200 OK
    // ...
    // [  
    //   "KX3A-39WE",
    //   "9UQU-DUWW"
    // ]

}
