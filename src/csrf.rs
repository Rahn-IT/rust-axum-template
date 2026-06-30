use axum::{
    extract::{self, State},
    http::{Method, header},
    middleware::Next,
    response::{IntoResponse, Response},
};
use url::Url;

use crate::{AppState, error::AppError};

pub async fn middleware(
    State(state): State<AppState>,
    request: extract::Request,
    next: Next,
) -> Response {
    if let Err(err) = verify_request_source(&state, &request) {
        return err.into_response();
    }

    next.run(request).await
}

fn verify_request_source(state: &AppState, request: &extract::Request) -> Result<(), AppError> {
    if request.method() == Method::GET {
        return Ok(());
    }

    let headers = request.headers();

    if let Some(origin) = headers.get(header::ORIGIN) {
        return verify_source_header(origin.to_str().ok(), &state.public_origin, "Origin");
    }

    if let Some(referer) = headers.get(header::REFERER) {
        return verify_source_header(referer.to_str().ok(), &state.public_origin, "Referer");
    }

    Err(AppError::forbidden(
        "Cross-site protection requires an Origin or Referer header.",
    ))
}

fn verify_source_header(
    header_value: Option<&str>,
    public_origin: &str,
    header_name: &str,
) -> Result<(), AppError> {
    let Some(header_value) = header_value else {
        return Err(AppError::forbidden(format!(
            "{header_name} header is not valid UTF-8."
        )));
    };

    let parsed = Url::parse(header_value).map_err(|_| {
        AppError::forbidden(format!("{header_name} header is not a valid absolute URL."))
    })?;
    let request_origin = parsed.origin().ascii_serialization();

    if request_origin == public_origin {
        Ok(())
    } else {
        Err(AppError::forbidden(format!(
            "{header_name} header does not match the configured public origin."
        )))
    }
}
