//! A `reqwest::ClientBuilder` factory for this server's own outbound HTTPS calls (GitHub Releases
//! API, blocklist feed downloads) that compiles Mozilla's root CA list into the binary via
//! `webpki-roots`, instead of reqwest's default of reading the OS's certificate store off disk at
//! runtime (`rustls-platform-verifier`, e.g. `/etc/ssl/certs` on Linux). That default silently
//! requires the target system to have a `ca-certificates` package installed - easy to miss on a
//! bare DietPi image - even though every other native dependency this binary needs (SQLite, TLS
//! itself) is already statically compiled in. Trade-off: the root list is now frozen at build
//! time, so a root CA rotation needs a rebuild+redeploy to pick up, same as any other dependency
//! bump - acceptable here since this project already ships releases regularly.

use std::sync::{Arc, LazyLock};

static ROOT_STORE: LazyLock<Arc<rustls::RootCertStore>> = LazyLock::new(|| {
    let mut store = rustls::RootCertStore::empty();
    store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(store)
});

pub fn client_builder() -> reqwest::ClientBuilder {
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(ROOT_STORE.clone())
        .with_no_client_auth();
    reqwest::Client::builder().tls_backend_preconfigured(Some(tls_config))
}
