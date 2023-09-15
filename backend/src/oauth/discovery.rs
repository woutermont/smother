//! This specification defines a metadata format that an OAuth 2.0 client
//! can use to obtain the information needed to interact with an OAuth
//! 2.0 authorization server, including its endpoint locations and
//! authorization server capabilities.
//! https://datatracker.ietf.org/doc/html/draft-ietf-oauth-discovery-08

//! This specification generalizes the metadata format defined by "OpenID
//! Connect Discovery 1.0" [OpenID.Discovery] in a way that is compatible
//! with OpenID Connect Discovery, while being applicable to a wider set
//! of OAuth 2.0 use cases.  This is intentionally parallel to the way
//! that the "OAuth 2.0 Dynamic Client Registration Protocol" [RFC7591]
//! specification generalized the dynamic client registration mechanisms
//! defined by "OpenID Connect Dynamic Client Registration 1.0"
//! [OpenID.Registration] in a way that was compatible with it.

//! The metadata for an authorization server is retrieved from a well-
//! known location as a JSON [RFC7159] document, which declares its
//! endpoint locations and authorization server capabilities.  This
//! process is described in Section 3.

//! This metadata can either be communicated in a self-asserted fashion
//! by the server origin via HTTPS or as a set of signed metadata values
//! represented as claims in a JSON Web Token (JWT) [JWT].  In the JWT
//! case, the issuer is vouching for the validity of the data about the
//! authorization server.  This is analogous to the role that the
//! Software Statement plays in OAuth Dynamic Client Registration
//! [RFC7591].

//! The means by which the client chooses an authorization server is out
//! of scope.  In some cases, its issuer identifier may be manually
//! configured into the client.  In other cases, it may be dynamically
//! discovered, for instance, through the use of WebFinger [RFC7033], as
//! described in Section 2 of "OpenID Connect Discovery 1.0"
//! [OpenID.Discovery].

//! TODO: api implementation in https://datatracker.ietf.org/doc/html/draft-ietf-oauth-discovery-08#section-3
//! as well as further chapters of the specification yet to be implemented

use oxiri::Iri;

/// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-discovery-08#section-2
///
/// Authorization servers can have metadata describing their configuration.
/// The following authorization server metadata values are used by this specification
/// and are registered in the IANA "OAuth Authorization Server Metadata" registry established in Section 7.1.
///
/// Additional authorization server metadata parameters MAY also be used.
/// Some are defined by other specifications, such as OpenID Connect Discovery 1.0 [OpenID.Discovery].
pub struct AuthorizationServerMetadata {
    // REQUIRED.  The authorization server's issuer identifier, which is
    // a URL that uses the "https" scheme and has no query or fragment
    // components.  This is the location where ".well-known" RFC 5785
    // [RFC5785] resources containing information about the authorization
    // server are published.  Using these well-known resources is
    // described in Section 3.  The issuer identifier is used to prevent
    // authorization server mix-up attacks, as described in "OAuth 2.0
    // Mix-Up Mitigation" [I-D.ietf-oauth-mix-up-mitigation].
    pub issuer: Iri<String>,

    // URL of the authorization server's authorization endpoint
    // [RFC6749].  This is REQUIRED unless no grant types are supported
    // that use the authorization endpoint.
    pub authorization_endpoint: Iri<String>,

    // URL of the authorization server's token endpoint [RFC6749].  This
    // is REQUIRED unless only the implicit grant type is supported.
    pub token_endpoint: Iri<String>,

    // OPTIONAL.  URL of the authorization server's JWK Set [JWK]
    // document.  The referenced document contains the signing key(s) the
    // client uses to validate signatures from the authorization server.
    // This URL MUST use the "https" scheme.  The JWK Set MAY also
    // contain the server's encryption key(s), which are used by clients
    // to encrypt requests to the server.  When both signing and
    // encryption keys are made available, a "use" (public key use)
    // parameter value is REQUIRED for all keys in the referenced JWK Set
    // to indicate each key's intended usage.
    pub jwks_uri: Option<Iri<String>>,

    // OPTIONAL.  URL of the authorization server's OAuth 2.0 Dynamic
    // Client Registration endpoint [RFC7591].
    pub registration_endpoint: Option<Iri<String>>,

    // RECOMMENDED.  JSON array containing a list of the OAuth 2.0
    // [RFC6749] "scope" values that this authorization server supports.
    // Servers MAY choose not to advertise some supported scope values
    // even when this parameter is used.
    pub scopes_supported: Option<Vec<String>>,

    // REQUIRED.  JSON array containing a list of the OAuth 2.0
    // "response_type" values that this authorization server supports.
    // The array values used are the same as those used with the
    // "response_types" parameter defined by "OAuth 2.0 Dynamic Client
    // Registration Protocol" [RFC7591].
    pub response_types_supported: Vec<String>,

    // OPTIONAL.  JSON array containing a list of the OAuth 2.0
    // "response_mode" values that this authorization server supports, as
    // specified in OAuth 2.0 Multiple Response Type Encoding Practices
    // [OAuth.Responses].  If omitted, the default is "["query",
    // "fragment"]".  The response mode value "form_post" is also defined
    // in OAuth 2.0 Form Post Response Mode [OAuth.Post].
    pub response_modes_supported: Option<Vec<String>>,

    // OPTIONAL.  JSON array containing a list of the OAuth 2.0 grant
    // type values that this authorization server supports.  The array
    // values used are the same as those used with the "grant_types"
    // parameter defined by "OAuth 2.0 Dynamic Client Registration
    // Protocol" [RFC7591].  If omitted, the default value is
    // "["authorization_code", "implicit"]".
    pub grant_types_supported: Option<Vec<String>>,

    // OPTIONAL.  JSON array containing a list of client authentication
    // methods supported by this token endpoint.  Client authentication
    // method values are used in the "token_endpoint_auth_method"
    // parameter defined in Section 2 of [RFC7591].  If omitted, the
    // default is "client_secret_basic" -- the HTTP Basic Authentication
    // Scheme specified in Section 2.3.1 of OAuth 2.0 [RFC6749].
    pub token_endpoint_auth_methods_supported: Option<Vec<String>>,

    // OPTIONAL.  JSON array containing a list of the JWS signing
    // algorithms ("alg" values) supported by the token endpoint for the
    // signature on the JWT [JWT] used to authenticate the client at the
    // token endpoint for the "private_key_jwt" and "client_secret_jwt"
    // authentication methods.  This metadata entry MUST be present if
    // either of these authentication methods are specified in the
    // "token_endpoint_auth_methods_supported" entry.  No default
    // algorithms are implied if this entry is omitted.  Servers SHOULD
    // support "RS256".  The value "none" MUST NOT be used.
    pub token_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    // OPTIONAL.  URL of a page containing human-readable information
    // that developers might want or need to know when using the
    // authorization server.  In particular, if the authorization server
    // does not support Dynamic Client Registration, then information on
    // how to register clients needs to be provided in this
    // documentation.
    pub service_documentation: Option<Iri<String>>,

    // OPTIONAL.  Languages and scripts supported for the user interface,
    // represented as a JSON array of BCP47 [RFC5646] language tag
    // values.  If omitted, the set of supported languages and scripts is
    // unspecified.
    pub ui_locales_supported: Option<Vec<String>>,

    // OPTIONAL.  URL that the authorization server provides to the
    // person registering the client to read about the authorization
    // server's requirements on how the client can use the data provided
    // by the authorization server.  The registration process SHOULD
    // display this URL to the person registering the client if it is
    // given.  As described in Section 5, despite the identifier
    // "op_policy_uri", appearing to be OpenID-specific, its usage in
    // this specification is actually referring to a general OAuth 2.0
    // feature that is not specific to OpenID Connect.
    pub op_policy_uri: Option<Iri<String>>,

    // OPTIONAL.  URL that the authorization server provides to the
    // person registering the client to read about the authorization
    // server's terms of service.  The registration process SHOULD
    // display this URL to the person registering the client if it is
    // given.  As described in Section 5, despite the identifier
    // "op_tos_uri", appearing to be OpenID-specific, its usage in this
    // specification is actually referring to a general OAuth 2.0 feature
    // that is not specific to OpenID Connect.
    pub op_tos_uri: Option<Iri<String>>,

    // OPTIONAL.  URL of the authorization server's OAuth 2.0 revocation
    // endpoint [RFC7009].
    pub revocation_endpoint: Option<Iri<String>>,

    // OPTIONAL.  JSON array containing a list of client authentication
    // methods supported by this revocation endpoint.  The valid client
    // authentication method values are those registered in the IANA
    // "OAuth Token Endpoint Authentication Methods" registry
    // [IANA.OAuth.Parameters].  If omitted, the default is
    // "client_secret_basic" -- the HTTP Basic Authentication Scheme
    // specified in Section 2.3.1 of OAuth 2.0 [RFC6749].
    pub revocation_endpoint_auth_methods_supported: Option<Vec<String>>,

    // OPTIONAL.  JSON array containing a list of the JWS signing
    // algorithms ("alg" values) supported by the revocation endpoint for
    // the signature on the JWT [JWT] used to authenticate the client at
    // the revocation endpoint for the "private_key_jwt" and
    // "client_secret_jwt" authentication methods.  This metadata entry
    // MUST be present if either of these authentication methods are
    // specified in the "revocation_endpoint_auth_methods_supported"
    // entry.  No default algorithms are implied if this entry is
    // omitted.  The value "none" MUST NOT be used.
    pub revocation_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    // OPTIONAL.  URL of the authorization server's OAuth 2.0
    // introspection endpoint [RFC7662].
    pub introspection_endpoint: Option<Iri<String>>,

    // OPTIONAL.  JSON array containing a list of client authentication
    // methods supported by this introspection endpoint.  The valid
    // client authentication method values are those registered in the
    // IANA "OAuth Token Endpoint Authentication Methods" registry
    // [IANA.OAuth.Parameters] or those registered in the IANA "OAuth
    // Access Token Types" registry [IANA.OAuth.Parameters].  (These
    // values are and will remain distinct, due to Section 7.2.)  If
    // omitted, the set of supported authentication methods MUST be
    // determined by other means.
    pub introspection_endpoint_auth_methods_supported: Option<Vec<String>>,

    // OPTIONAL.  JSON array containing a list of the JWS signing
    // algorithms ("alg" values) supported by the introspection endpoint
    // for the signature on the JWT [JWT] used to authenticate the client
    // at the introspection endpoint for the "private_key_jwt" and
    // "client_secret_jwt" authentication methods.  This metadata entry
    // MUST be present if either of these authentication methods are
    // specified in the "introspection_endpoint_auth_methods_supported"
    // entry.  No default algorithms are implied if this entry is
    // omitted.  The value "none" MUST NOT be used.
    pub introspection_endpoint_auth_signing_alg_values_supported: Option<Vec<String>>,

    // OPTIONAL.  JSON array containing a list of PKCE [RFC7636] code
    // challenge methods supported by this authorization server.  Code
    // challenge method values are used in the "code_challenge_method"
    // parameter defined in Section 4.3 of [RFC7636].  The valid code
    // challenge method values are those registered in the IANA "PKCE
    // Code Challenge Methods" registry [IANA.OAuth.Parameters].  If
    // omitted, the authorization server does not support PKCE.
    pub code_challenge_methods_supported: Option<Vec<String>>,
}

// https://datatracker.ietf.org/doc/html/draft-ietf-oauth-discovery-08#section-2.1
//
// In addition to JSON elements, metadata values MAY also be provided as
// a "signed_metadata" value, which is a JSON Web Token (JWT) [JWT] that
// asserts metadata values about the authorization server as a bundle.
// A set of claims that can be used in signed metadata are defined in
// Section 2.  The signed metadata MUST be digitally signed or MACed
// using JSON Web Signature (JWS) [JWS] and MUST contain an "iss"
// (issuer) claim denoting the party attesting to the claims in the
// signed metadata.  Consumers of the metadata MAY ignore the signed
// metadata if they do not support this feature.  If the consumer of the
// metadata supports signed metadata, metadata values conveyed in the
// signed metadata MUST take precedence over the corresponding values
// conveyed using plain JSON elements.
//
// Signed metadata is included in the authorization server metadata JSON
// object using this OPTIONAL member:

//  signed_metadata
//     A JWT containing metadata values about the authorization server as
//     claims.  This is a string value consisting of the entire signed
//     JWT.  A "signed_metadata" metadata value SHOULD NOT appear as a
//     claim in the JWT.
