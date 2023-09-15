

use async_stream::stream;
use axum::body::StreamBody;
use axum::extract::{BodyStream, DefaultBodyLimit, Path, Query};
use axum::http::HeaderMap;
use axum::routing::MethodRouter;
use axum::{Extension, Router, Server};
use futures::stream::Stream;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tower::ServiceBuilder;
use tower_http::cors::{preflight_request_headers, Any, CorsLayer};
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() {
    let trace_layer = TraceLayer::new_for_http();

    // https://docs.rs/tower-http/0.4.0/tower_http/trace/index.html
    let limit_layer = DefaultBodyLimit::max(1024);

    let cors_layer = CorsLayer::new()
        .allow_credentials(true)
        .allow_headers(Any)
        .allow_methods(Any)
        .allow_origin(Any)
        .expose_headers(Any)
        .max_age(Duration::from_secs(60 * 60 * 24))
        .vary(Vec::from_iter(preflight_request_headers()));

    // Other interesting tower layers are retry, timeout, limit, metrics, request_id and validate_request

    let layers = ServiceBuilder::new()
        .layer(trace_layer)
        .layer(cors_layer)
        .layer(limit_layer);

    let router = Router::new()
        .route(
            "/",
            MethodRouter::new(), // .get(get_root)
        )
        .route(
            "/*path",
            MethodRouter::new(), // .get(get_resource)
                                 // .put(put_resource)
                                 // .post(post_resource)
                                 // .delete(delete_resource)
        );

    let address = SocketAddr::from(([127, 0, 0, 1], 3000));

    Server::bind(&address)
        .serve(router.layer(layers).into_make_service())
        .await
        .unwrap();
}
