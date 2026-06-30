use axum::{
    extract::{Request, State},
    http::{HeaderValue, header},
    middleware::Next,
    response::Response,
};

use crate::AppState;

const CONTENT_SECURITY_POLICY: &str =
    "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'";
const REFERRER_POLICY: &str = "same-origin";
const HSTS_POLICY: &str = "max-age=31536000; includeSubDomains";

pub async fn middleware(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static(REFERRER_POLICY),
    );

    if state.secure_cookies {
        headers.insert(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static(HSTS_POLICY),
        );
    }

    response
}
