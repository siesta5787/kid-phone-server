//! Serves the service worker script dynamically (rather than as a static
//! file) so `crate::APP_VERSION` gets baked into its bytes on every
//! request - the browser's own update-detection works by byte-diffing a
//! refetched `/sw.js` against the installed one. Deliberately minimal: this
//! only exists to satisfy PWA installability, it does not cache pages for
//! offline use (this app handles session cookies and device bearer
//! tokens - offline browsing isn't a stated need and isn't worth the added
//! complexity/risk). See `templates/sw.js`.

use askama::Template;
use axum::http::header;
use axum::response::IntoResponse;

#[derive(Template)]
#[template(path = "sw.js", escape = "none")]
struct ServiceWorkerTemplate<'a> {
    app_version: &'a str,
}

pub async fn serve_sw() -> impl IntoResponse {
    let body = ServiceWorkerTemplate {
        app_version: crate::APP_VERSION,
    }
    .render()
    .expect("sw.js template is static and always renders");

    (
        [
            (
                header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            ),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
}
