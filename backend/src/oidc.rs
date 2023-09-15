
use std::time::{SystemTime, UNIX_EPOCH};

use futures::{TryFutureExt, try_join, future::ready, FutureExt};
use jwt_compact::{UntrustedToken, jwk::JsonWebKey};
use no_way::{jwk::{JWKSet, JWK}, jws::Unverified, Json};
use oxiri::Iri;
use serde::{Deserialize, Serialize};
use serde_json::{from_str as from_json, Value};
use thiserror::Error;

#[derive(Debug, Deserialize)]
struct Cnf {
  jkt: String
}

#[derive(Debug, Deserialize)]
struct AccessToken {
  webid: Iri<String>,
  iss: Iri<String>,
  sub: String,
  aud: Vec<String>,
  azp: Iri<String>,
  nbf: Option<i64>,
  iat: i64,
  exp: i64,
  cnf: Cnf,
}

#[derive(Debug, Deserialize)]
struct IssuerConfig {
  jwks_uri: Iri<String>,
}

#[derive(Debug, Deserialize)]
struct WebidDoc {
  issuers: Vec<Iri<String>>,
}

// Of the signature and MAC algorithms specified in JSON Web Algorithms
// [JWA], only HMAC SHA-256 ("HS256") and "none" MUST be implemented by
// conforming JWT implementations.  It is RECOMMENDED that
// implementations also support RSASSA-PKCS1-v1_5 with the SHA-256 hash
// algorithm ("RS256") and ECDSA using the P-256 curve and the SHA-256
// hash algorithm ("ES256").  Support for other algorithms and key sizes
// is OPTIONAL.

// Support for encrypted JWTs is OPTIONAL. 

async fn authenticate(token_str: &str) -> Result<(), AuthError> {

  let token = from_json::<Unverified<Json<AccessToken>>>(&token_str).map_err(AuthError::InvalidToken)?;

  if !token..aud.iter().any(|s| s == &"solid") { return Err(AuthError::InvalidAudience) }
  if !token.aud.iter().any(|s| s == &token.azp) { return Err(AuthError::InvalidAudience) }

  verify_times(&token).await?;

  let webid_doc = get_webid_doc(&token.webid).and_then(
    |doc| ready(doc.issuers.contains(&token.iss).then_some(doc).ok_or(AuthError::IssuerNotAllowed))
  );
  
  let jwks = verify_signature(&token);

  // SHOULD also check client_id document / webid

  let (webid_doc, jwks) = try_join!(webid_doc, jwks)?;

  Ok(())

}

async fn verify_times(&AccessToken {iat, exp, nbf, ..}: &AccessToken) -> Result<(), AuthError> {

  let now = time::OffsetDateTime::now_utc().unix_timestamp();

  if iat > now { return Err(AuthError::TokenIssuedInFuture) }
  if exp < now { return Err(AuthError::TokenExpired) }
  if let Some(nbf) = nbf { if nbf > now { return Err(AuthError::TokenNotYetValid) } }

  Ok(())

}

async fn verify_signature(token: &AccessToken) -> Result<(), AuthError> {

  let jwks = get_issuer_jwks(&token.iss).await?;

  let jwk = jwks.iter().find(|jwk| jwk.specified.common.key_id == token.).ok_or(AuthError::NoMatchingJwk)?;

  let mut token = UntrustedToken::new(token_str);

  token.validate_signature_with_key(jwk)?;

  Ok(())

}

const well_known: &'static str = ".well-known/openid-configuration";

async fn get_issuer_jwks(issuer: &Iri<String>) -> Result<Vec<JWK>, AuthError> {
  
  let client = reqwest::Client::new();

  let cfg_uri =  issuer.trim_end_matches('/').to_owned() + well_known;
  
  let IssuerConfig { jwks_uri, ..} = client.get(cfg_uri)
    .send().map_err(AuthError::NoIssuerConfig).await?
    .json::<IssuerConfig>().map_err(AuthError::InvalidIssuerConfig).await?;
    
  let JWKSet { keys } = client.get(jwks_uri.as_str())
    .send().map_err(AuthError::NoJwks).await?
    .json::<JWKSet>().map_err(AuthError::InvalidJwks).await?;

  Ok(keys)

}

async fn get_webid_doc(webid: &Iri<String>) -> Result<WebidDoc, AuthError> {
  
  let client = reqwest::Client::new();
  
  let WebidDoc { jwks_uri, ..} = client.get(cfg_uri)
    .send().map_err(AuthError::NoIssuerConfig).await?
    .json::<IssuerConfig>().map_err(AuthError::InvalidIssuerConfig).await?;
    
  let jwks = client.get(jwks_uri.as_str())
    .send().map_err(AuthError::NoJwks).await?
    .json::<Vec<JsonWebKey>>().map_err(AuthError::InvalidJwks).await?;

  Ok(jwks)

}

#[derive(Error, Debug)]
enum AuthError {
    #[error("Invalid access token")]
    InvalidToken(#[source] serde_json::Error),
    #[error("Token audience does not include solid and client_id")]
    InvalidAudience,
    #[error("Token is issued in the future")]
    TokenIssuedInFuture,
    #[error("Token is expired")]
    TokenExpired,
    #[error("Invalid is not yet valid")]
    TokenNotYetValid,
    #[error("Cannot retrieve issuer configuration")]
    NoIssuerConfig(#[source] reqwest::Error),
    #[error("Issuer configuration is invalid")]
    InvalidIssuerConfig(#[source] reqwest::Error),
    #[error("Cannot retrieve jwks_uri from issuer configuration")]
    NoJwksUri,
    #[error("Cannot retrieve jwk set from jwks_uri")]
    NoJwks(#[source] reqwest::Error),
    #[error("Jwk set is invalid")]
    InvalidJwks(#[source] reqwest::Error),
    IssuerNotAllowed,
}