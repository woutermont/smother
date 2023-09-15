//! This specification extends and complements [UMAGrant] to loosely couple, or federate, its authorization process. This enables multiple resource servers operating in different domains to communicate with a single authorization server operating in yet another domain that acts on behalf of a resource owner. A service ecosystem can thus automate resource protection, and the resource owner can monitor and control authorization grant rules through the authorization server over time. Further, authorization grants can increase and decrease at the level of individual resources and scopes.
//!
//! Building on the example provided in the introduction in [UMAGrant], bank customer (resource owner) Alice has a bank account service (resource server), a cloud file system (different resource server hosted elsewhere), and a dedicated sharing management service (authorization server) hosted by the bank. She can manage access to her various protected resources by spouse Bob, accounting professional Charline, financial information aggregation company DecideAccount, and neighbor Erik (requesting parties), all using different client applications. Her bank accounts and her various files and folders are protected resources, and she can use the same sharing management service to monitor and control different scopes of access to them by these different parties, such as viewing, editing, or printing files and viewing account data or accessing payment functions.
//!
//! This specification, together with [UMAGrant], constitutes UMA 2.0. This specification is OPTIONAL to use with the UMA grant.
//!
//! This specification is designed for use with HTTP [RFC2616], and for interoperability and security in the context of loosely coupled services and applications operated by independent parties in independent domains. The use of UMA over any protocol other than HTTP is undefined. In such circumstances, it is RECOMMENDED to define profiles or extensions to achieve interoperability among independent implementations (see Section 4 of [UMAGrant]).
//!
//! The authorization server MUST use TLS protection over its protection API endpoints, as governed by [BCP195], which discusses deployment and adoption characteristics of different TLS versions.
//!
//! The authorization server MUST use OAuth and require a valid PAT to secure its protection API endpoints. The authorization server and the resource server (as an OAuth client) MUST support bearer usage of the PAT, as defined in [RFC6750]. All examples in this specification show the use of bearer-style PATs in this format.
//!
//! As defined in [UMAGrant], the resource owner -- the entity here authorizing PAT issuance -- MAY be an end-user (natural person) or a non-human entity treated as a person for limited legal purposes (legal person), such as a corporation. A PAT is unique to a resource owner, resource server used for resource management, and authorization server used for protection of those resources. The issuance of the PAT represents the authorization of the resource owner for the resource server to use the authorization server for protecting those resources.
//!
//! Different grant types for PAT issuance might be appropriate for different types of resource owners; for example, the client credentials grant is useful in the case of an organization acting as a resource owner, whereas an interactive grant type is typically more appropriate for capturing the approval of an end-user resource owner. Where an identity token is desired in addition to an access token, it is RECOMMENDED to use [OIDCCore] in addition.
//!
//! Federation of authorization for the UMA grant delivers a conceptual separation of responsibility and authority:
//!
//! The resource owner can control access to resources residing at multiple resource servers from a single authorization server, by virtue of authorizing PAT issuance for each resource server. Any one resource server MAY be operated by a party different from the one operating the authorization server.
//! The resource server defines the boundaries of resources and the scopes available to each resource, and interprets how clients' resource requests map to permission requests, by virtue of being the publisher of the API being protected and using the protection API to communicate to the authorization server.
//! The resource owner works with the authorization server to configure policy conditions (authorization grant rules), which the authorization server executes in the process of issuing access tokens. The authorization process makes use of claims gathered from the requesting party and client in order to satisfy all operative operative policy conditions.
//! The separation of authorization decision making and authorization enforcement is similar to the architectural separation often used in enterprises between policy decision points and policy enforcement points. However, the resource server MAY apply additional authorization controls beyond those imposed by the authorization server. For example, even if an RPT provides sufficient permissions for a particular case, the resource server can choose to bar access based on its own criteria.
//!
//! Practical control of access among loosely coupled parties typically requires more than just messaging protocols. It is outside the scope of this specification to define more than the technical contract between UMA-conforming entities. Laws may govern authorization-granting relationships. It is RECOMMENDED for the resource owner, authorization server, and resource server to establish agreements about which parties are responsible for establishing and maintaining authorization grant rules and other authorization rules on a legal or contractual level, and parties operating entities claiming to be UMA-conforming should provide documentation of rights and obligations between and among them. See Section 4 of [UMAGrant] for more information.
//!
//! Except for PAT issuance, the resource owner-resource server and resource owner-authorization server interfaces -- including the setting of policy conditions -- are outside the scope of this specification (see Section 8 and Section 6.1 of [UMAGrant] for privacy considerations). Some elements of the protection API enable the building of user interfaces for policy condition setting (for example, see Section 3.2, which can be used in concert with user interaction for resource protection and sharing and offers an end-user redirection mechanism for policy interactions).
//!
//! Note: The resource server typically requires access to at least the permission and token introspection endpoints when an end-user resource owner is not available ("offline" access). Thus, the authorization server needs to manage the PAT in a way that ensures this outcome. [UMA-Impl] discusses ways the resource server can enhance its error handling when the PAT is invalid.
//!
//! The protection API defines the following endpoints:
//!
//! Resource registration endpoint as defined in Section 3. The API available at this endpoint provides a means for the resource server to put resources under the protection of an authorization server on behalf of the resource owner and manage them over time.
//! Permission endpoint as defined in Section 4. This endpoint provides a means for the resource server to request a set of one or more permissions on behalf of the client based on the client's resource request when that request is unaccompanied by an access token or is accompanied by an RPT that is insufficient for access to that resource.
//! OPTIONAL token introspection endpoint as defined in [RFC7662] and as extended in Section 5. This endpoint provides a means for the resource server to introspect the RPT.
//! Use of these endpoints assumes that the resource server has acquired OAuth client credentials from the authorization server by static or dynamic means, and has a valid PAT. Note: Although the resource identifiers that appear in permission and token introspection request messages could sufficiently identify the resource owner, the PAT is still required because it represents the resource owner's authorization to use the protection API, as noted in Section 1.3.
//!
//! The authorization server MUST declare its protection API endpoints in the discovery document (see Section 2).
//!
//! A permission is (requested or granted) authorized access to a particular resource with some number of scopes bound to that resource. The concept of permissions is used in authorization assessment, results calculation, and RPT issuance in [UMAGrant]. This concept takes on greater significance in relation to the protection API.
//!
//! The resource server's resource registration operations at the authorization server result in a set of resource owner-specific resource identifiers. When the client makes a resource request that is unaccompanied by an access token or its resource request fails, the resource server is responsible for interpreting that request and mapping it to a choice of authorization server, resource owner, resource identifier(s), and set of scopes for each identifier, in order to request one or more permissions -- resource identifiers and a set of scopes -- and obtain a permission ticket on the client's behalf. Finally, when the client has made a resource request accompanied by an RPT and token introspection is in use, the returned token introspection object reveals the structure of permissions, potentially including expiration of individual permissions.

use either::Either;
use oxiri::Iri;
use serde::Serialize;
use std::ops::Deref;

use crate::oauth::discovery::AuthorizationServerMetadata as OauthASM;

/// This specification makes use of the authorization server discovery document structure and endpoint defined in [UMAGrant]. The resource server uses this discovery document to discover the endpoints it needs.
///
/// In addition to the metadata defined in that specification and [OAuthMeta], this specification defines the following metadata for inclusion in the discovery document.
///
/// The authorization server SHOULD document any profiled or extended features it supports explicitly, ideally by supplying the URI identifying each UMA profile and extension as an uma_profiles_supported metadata array value (defined in [UMAGrant]), and by using extension metadata to indicate specific usage details as necessary.
///
/// Following are additional requirements related to metadata: introspection_endpoint; If the authorization server supports token introspection as defined in this specification, it MUST supply this metadata value (defined in [OAuthMeta]).
pub struct AuthorizationServerMetadata {
    oauth: OauthASM,

    /// REQUIRED. The endpoint URI at which the resource server requests permissions on the client's behalf.
    pub permission_endpoint: Iri<String>,

    /// REQUIRED. The endpoint URI at which the resource server registers resources to put them under authorization manager protection.
    pub resource_registration_endpoint: Iri<String>,
}

impl Deref for AuthorizationServerMetadata {
    type Target = OauthASM;
    fn deref(&self) -> &Self::Target {
        &self.oauth
    }
}

/// The API presented by the authorization server to the resource server, defined in this specification. This API is OAuth-protected.
pub struct ProtectionApi;

/// An [RFC6749] access token with the scope uma_protection, used by the resource server as a client of the authorization server's protection API. The resource owner involved in the UMA grant is the same entity taking on the role of the resource owner authorizing issuance of the PAT.
pub struct ProtectionApiAccessToken; // PAT

/// https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#rfc.section.3.1
/// https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#resource-set-desc
///
/// A resource description is a JSON document that describes the characteristics of a resource sufficiently for an authorization server to protect it. A resource description has the following parameters:
#[derive(Debug, Serialize, Clone)]
pub struct ResourceDescription {
  
    pub _id: &'static str,

    /// REQUIRED. An array of strings, serving as scope identifiers, indicating the available scopes for this resource. Any of the strings MAY be either a plain string or a URI.
    pub resource_scopes: Vec<String>,

    /// OPTIONAL. A human-readable string describing the resource at length. The authorization server MAY use this description in any user interface it presents to a resource owner, for example, for resource protection monitoring or policy setting. The value of this parameter MAY be internationalized, as described in Section 2.2 of [RFC7591].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// OPTIONAL. A URI for a graphic icon representing the resource. The authorization server MAY use the referenced icon in any user interface it presents to a resource owner, for example, for resource protection monitoring or policy setting.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon_uri: Option<Either<Iri<String>, String>>,

    /// OPTIONAL. A human-readable string naming the resource. The authorization server MAY use this name in any user interface it presents to a resource owner, for example, for resource protection monitoring or policy setting. The value of this parameter MAY be internationalized, as described in Section 2.2 of [RFC7591].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// OPTIONAL. A string identifying the semantics of the resource. For example, if the resource is an identity claim that leverages standardized claim semantics for "verified email address", the value of this parameter could be an identifying URI for this claim. The authorization server MAY use this information in processing information about the resource or displaying information about it in any user interface it presents to a resource owner.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub r#type: Option<String>,
}

/// https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#rfc.section.3.1.1
/// https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-federated-authz-2.0.html#scope-desc
///
/// A scope description is a JSON document that describes the characteristics of a scope sufficiently for an authorization server to protect the resource with this available scope.
///
/// While a scope URI appearing in a resource description (see Section 3.1) MAY resolve to a scope description document, and thus scope description documents are possible to standardize and reference publicly, the authorization server is not expected to resolve scope description details at resource registration time or at any other run-time requirement. The resource server and authorization server are presumed to have negotiated any required interpretation of scope handling out of band.
///
/// A scope description has the following parameters:
pub struct ScopeDescription {
    /// OPTIONAL. A human-readable string describing the resource at length. The authorization server MAY use this description in any user interface it presents to a resource owner, for example, for resource protection monitoring or policy setting. The value of this parameter MAY be internationalized, as described in Section 2.2 of [RFC7591].
    pub description: Option<String>,

    /// OPTIONAL. A URI for a graphic icon representing the scope. The authorization server MAY use the referenced icon in any user interface it presents to a resource owner, for example, for resource protection monitoring or policy setting.
    pub icon_uri: Iri<String>,

    /// OPTIONAL. A human-readable string naming the scope. The authorization server MAY use this name in any user interface it presents to a resource owner, for example, for resource protection monitoring or policy setting. The value of this parameter MAY be internationalized, as described in Section 2.2 of [RFC7591].
    pub name: Option<String>,
}
