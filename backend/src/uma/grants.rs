//! This specification defines an extension OAuth 2.0 [RFC6749] grant. The grant enhances OAuth capabilities in the following ways:
//!
//! The resource owner authorizes protected resource access to clients used by entities that are in a requesting party role. This enables party-to-party authorization, rather than authorization of application access alone.
//! The authorization server and resource server interact with the client and requesting party in a way that is asynchronous with respect to resource owner interactions. This lets a resource owner configure an authorization server with authorization grant rules (policy conditions) at will, rather than authorizing access token issuance synchronously just after authenticating.
//! For example, bank customer (resource owner) Alice with a bank account service (resource server) can use a sharing management service (authorization server) hosted by the bank to manage access to her various protected resources by spouse Bob, accounting professional Charline, and and financial information aggregation company Decide Account, all using different client applications. Each of her bank accounts is a protected resource, and two different scopes of access she can control on them are viewing account data and accessing payment functions.
//!
//! An OPTIONAL second specification, [UMAFedAuthz], defines a means for an UMA-enabled authorization server and resource server to be loosely coupled, or federated, in a resource owner context. This specification, together with [UMAFedAuthz], constitutes UMA 2.0.

use std::ops::Deref;

use crate::oauth::discovery::AuthorizationServerMetadata as OauthASM;
use oxiri::Iri;

impl Deref for AuthorizationServerMetadata {
    type Target = OauthASM;
    fn deref(&self) -> &Self::Target {
        &self.oauth
    }
}

/// https://docs.kantarainitiative.org/uma/wg/rec-oauth-uma-grant-2.0.html#as-config
///
/// The authorization server supplies metadata in a discovery document to declare its endpoints. The client uses this discovery document to discover these endpoints for use in the flows defined in Section 3.
///
/// The authorization server MUST make a discovery document available. The structure of the discovery document MUST conform to that defined in [OAuthMeta]. The discovery document MUST be available at an endpoint formed by concatenating the string /.well-known/uma2-configuration to the issuer metadata value defined in [OAuthMeta], using the well-known URI syntax and semantics defined in [RFC5785]. In addition to the metadata defined in [OAuthMeta], this specification defines the following metadata for inclusion in the discovery document:
pub struct AuthorizationServerMetadata {
    oauth: OauthASM,

    /// OPTIONAL. A static endpoint URI at which the authorization server declares that it interacts with end-user requesting parties to gather claims. If the authorization server also provides a claims interaction endpoint URI as part of its redirect_user hint in a need_info response to a client on authorization failure (see Section 3.3.6), that value overrides this metadata value. Providing the static endpoint URI is useful for enabling interactive claims gathering prior to any pushed-claims flows taking place, for example, for gathering authorization for subsequent claim pushing (see Section 3.3.2).
    pub claims_interaction_endpoint: Iri<String>,

    ///OPTIONAL. UMA profiles and extensions supported by this authorization server. The value is an array of string values, where each string value is a URI identifying an UMA profile or extension. As discussed in Section 4, an authorization server supporting a profile or extension related to UMA SHOULD supply the specification's identifying URI (if any) here.
    pub uma_profiles_supported: Vec<String>,

    ///OPTIONAL. Array of one or more claims redirection URIs. If the authorization server supports dynamic client registration, it MUST allow client applications to register claims_redirect_uri metadata, as defined in Section 3.3.2, using the following metadata field:
    pub claims_redirect_uris: Vec<Iri<String>>,
}

/// An entity capable of granting access to a protected resource, the "user" in User-Managed Access.
/// The resource owner MAY be an end-user (natural person) or MAY be a non-human entity treated as a person
/// for limited legal purposes (legal person), such as a corporation.
pub struct ResourceOwner;

/// A natural or legal person that uses a client to seek access to a protected resource.
/// The requesting party may or may not be the same party as the resource owner.
pub struct RequestingParty;

///An application that is capable of making requests for protected resources
/// with the resource owner's authorization and on the requesting party's behalf.
pub struct Client;

/// A server that hosts resources on a resource owner's behalf and is capable of accepting and responding
/// to requests for protected resources.
pub struct ResourceServer;

/// A server that protects, on a resource owner's behalf, resources hosted at a resource server.
pub struct AuthorizationServer;

/// An OAuth access token associated with the UMA grant.
/// An RPT is unique to a requesting party, client, authorization server, resource server, and resource owner.
pub struct RequestingPartyToken;

/// Authorized access to a particular resource with some number of scopes bound to that resource.
/// A permission ticket represents some number of requested permissions.
/// An RPT represents some number of granted permissions.
/// Permissions are part of the authorization server's process and are opaque to the client.
pub struct Permission;

/// A correlation handle representing requested permissions that is created and maintained by the authorization server,
/// initially passed to the client by the resource server, and presented by the client at the token endpoint
/// and during requesting party redirects.
pub struct PermissionTicket;

/// A statement of the value or values of one or more attributes of an entity.
/// The authorization server typically needs to collect and assess one or more claims
/// of the requesting party or client against policy conditions as part of protecting a resource.
///
/// The two methods available for UMA claims collection are claims pushing and interactive claims gathering.
///
/// Note: Claims collection might involve authentication for unique user identification,
/// but depending on policy conditions might additionally or instead involve the collection of
/// non-uniquely identifying attributes, authorization for some action (for example, see Section 3.3.3),
/// or other statements of agreement.
pub struct Claim;

/// A package of claims provided directly by the client to the authorization server through claims pushing.
pub struct ClaimToken;

/// A correlation handle issued by an authorization server that represents a set of claims
/// collected during one authorization process, available for a client to use in attempting
/// to optimize a future authorization process.
pub struct PersistedClaimsToken;

/// The process through which the authorization server determines whether it should issue an RPT to the client
/// on the requesting party's behalf, based on a variety of inputs.
/// A key component of the process is authorization assessment. (See Section 1.3.1.)
fn authorizationProcess() -> () {}

/// Claims pushing by a client is defined in Section 3.3.1, and interactive claims gathering with an end-user requesting party is defined in Section 3.3.2.
fn claimsCollection() -> () {}
fn claimsPushing() -> () {}
fn claimsGathering() -> () {}

/// Authorization assessment involves the authorization server assembling and evaluating policy conditions,
/// scopes, claims, and any other relevant information sourced outside of UMA claims collection flows,
/// in order to mitigate access authorization risk.
fn authorizationAssessment() -> () {}

/// The authorization server either returns a success code (as defined in Section 3.3.5),
/// an RPT, and an optional PCT, or an error code (as defined in Section 3.3.6).
/// If the error code is need_info or request_submitted, the authorization server provides a permission ticket,
/// giving the client an opportunity to continue within the same authorization process
/// (including engaging in further claims collection).
fn authorizationResultsDetermination() -> () {}
