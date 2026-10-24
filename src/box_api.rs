//! Talking to the Box this server runs on (github.com/siesta5787/pi2zeroserver).
//!
//! On a Box, the operating system, Tailscale and this app itself are updated
//! by the Box (signed, with automatic rollback), not by this app. The Box
//! starts this app with `BOX_API_SOCKET` pointing at a Unix socket that only
//! this app's user can open; plain HTTP over it, JSON bodies, no login (file
//! permissions are the access control). See the Box's docs/box-api.md.
//!
//! Without `BOX_API_SOCKET` (e.g. `cargo run` on a laptop, or an older plain
//! Raspberry Pi OS install) there's nothing to talk to, and the Software
//! updates page just says so.

use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Where the Box's API is, if this server runs on a Box
pub fn socket() -> Option<String> {
    std::env::var("BOX_API_SOCKET")
        .ok()
        .filter(|s| !s.is_empty())
}

/// One request over the socket; (status code, body). HTTP/1.0, so the Box
/// closes the connection when it's done and reading to the end is enough.
async fn request(socket: &str, method: &str, path: &str) -> Result<(u16, String), String> {
    let exchange = async {
        let mut stream = tokio::net::UnixStream::connect(socket).await?;
        let request = format!("{method} {path} HTTP/1.0\r\nHost: box\r\nContent-Length: 0\r\n\r\n");
        stream.write_all(request.as_bytes()).await?;
        let mut response = String::new();
        stream.read_to_string(&mut response).await?;
        Ok::<_, std::io::Error>(response)
    };
    let response = tokio::time::timeout(std::time::Duration::from_secs(20), exchange)
        .await
        .map_err(|_| "the Box didn't answer".to_string())?
        .map_err(|e| format!("couldn't reach the Box: {e}"))?;
    let (head, body) = response.split_once("\r\n\r\n").unwrap_or((&response, ""));
    let code = head
        .split(' ')
        .nth(1)
        .and_then(|c| c.parse().ok())
        .unwrap_or(0);
    Ok((code, body.to_string()))
}

/// Progress of an app or Tailscale update: `idle`, `checking`, `downloading`
/// (`version`, `percent`), `installing` (`version`), `updated` (`version`),
/// `up_to_date` (`version`), or `failed` (`error`)
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Progress {
    pub state: String,
    pub version: Option<String>,
    pub percent: Option<u8>,
    pub error: Option<String>,
}

impl Progress {
    pub fn busy(&self) -> bool {
        matches!(
            self.state.as_str(),
            "checking" | "downloading" | "installing"
        )
    }
}

/// A system update: `idle`, `running` (`percent`, `step`), `installed`
/// (waiting for a restart), or `failed` (`error`; nothing changed)
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Install {
    pub state: String,
    pub percent: Option<u8>,
    pub step: Option<String>,
    pub error: Option<String>,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Os {
    pub version: String,
    pub latest: Option<String>,
    pub update_available: bool,
    pub testing: bool,
    pub install: Install,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct App {
    pub version: Option<String>,
    pub latest: Option<String>,
    pub update_available: bool,
    pub testing: bool,
    pub check_error: Option<String>,
    pub progress: Progress,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Tailscale {
    pub version: Option<String>,
    pub backend_state: Option<String>,
    pub dns_name: Option<String>,
    pub progress: Progress,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct AutoUpdates {
    pub enabled: bool,
    pub timezone: Option<String>,
    pub testing: bool,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct LastNight {
    pub date: String,
    pub summary: String,
}

/// `GET /v1/status`. Every field is optional on our side, so an older or
/// newer Box that reports a little more or less still works.
#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Status {
    pub os: Os,
    pub app: App,
    pub tailscale: Tailscale,
    /// Unix time of the last successful check
    pub checked_at: Option<i64>,
    pub check_error: Option<String>,
    pub checking: bool,
    /// A system update is installed and waits for a restart
    pub restart_needed: bool,
    pub auto_updates: Option<AutoUpdates>,
    pub last_night: Option<LastNight>,
}

impl Status {
    /// Something is in progress, so the page should refresh itself
    pub fn busy(&self) -> bool {
        self.checking
            || self.os.install.state == "running"
            || self.app.progress.busy()
            || self.tailscale.progress.busy()
    }
}

pub async fn status() -> Result<Status, String> {
    status_at(&socket().ok_or("not running on a Box")?).await
}

async fn status_at(socket: &str) -> Result<Status, String> {
    let (code, body) = request(socket, "GET", "/v1/status").await?;
    if code != 200 {
        return Err(format!("the Box answered {code}"));
    }
    serde_json::from_str(&body).map_err(|e| format!("the Box's answer didn't make sense: {e}"))
}

/// The Box actions this app can ask for
#[derive(Clone, Copy, Debug)]
pub enum Action {
    /// Look for updates now
    Check,
    /// Install the system update (into the Box's spare copy; takes effect after a restart)
    InstallSystem,
    /// Install this app's newest release; the Box restarts this app onto it
    UpdateApp,
    /// Update Tailscale if there's a newer release
    UpdateTailscale,
    /// Restart the whole Box
    Restart,
}

impl Action {
    fn path(self) -> &'static str {
        match self {
            Action::Check => "/v1/check",
            Action::InstallSystem => "/v1/os/install",
            Action::UpdateApp => "/v1/app/update",
            Action::UpdateTailscale => "/v1/tailscale/update",
            Action::Restart => "/v1/restart",
        }
    }
}

/// Starts an action; a sentence for the page saying what happened
pub async fn start(action: Action) -> String {
    match socket() {
        Some(socket) => start_at(&socket, action).await,
        None => "This server isn't running on a Box.".to_string(),
    }
}

async fn start_at(socket: &str, action: Action) -> String {
    let started = match action {
        Action::Check => "Checking for updates…",
        Action::InstallSystem => {
            "Installing the system update. You can keep using the app meanwhile."
        }
        Action::UpdateApp => {
            "Updating the app. It restarts by itself; this page comes back in about a minute."
        }
        Action::UpdateTailscale => {
            "Checking for a newer Tailscale and installing it if there is one…"
        }
        Action::Restart => "The Box is restarting. This page comes back in a minute or two.",
    };
    match request(socket, "POST", action.path()).await {
        Ok((202, _)) => started.to_string(),
        Ok((409, _)) => "That's already in progress.".to_string(),
        Ok((404, _)) => "There's nothing to install yet. Check for updates first.".to_string(),
        Ok((code, body)) => format!("The Box answered {code}: {}", body.trim()),
        Err(e) => format!("Couldn't ask the Box: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_a_box_status() {
        let json = r#"{
            "os": {"version": "0.50", "latest": "0.51", "update_available": true, "testing": false,
                   "install": {"state": "running", "percent": 40, "step": "Copying"}},
            "app": {"version": "0.18.6", "latest": "0.19.0", "update_available": true, "testing": false,
                    "check_error": null, "progress": {"state": "idle"}},
            "tailscale": {"version": "1.104.1", "backend_state": "Running", "dns_name": "box.tail1.ts.net",
                          "progress": {"state": "up_to_date", "version": "1.104.1"}},
            "checked_at": 1792468800, "check_error": null, "checking": false, "restart_needed": false,
            "auto_updates": {"enabled": true, "timezone": "America/New_York", "testing": false},
            "last_night": {"date": "2026-10-24", "summary": "Nothing new."},
            "something_newer": 1
        }"#;
        let s: Status = serde_json::from_str(json).unwrap();
        assert_eq!(s.os.install.percent, Some(40));
        assert_eq!(s.app.latest.as_deref(), Some("0.19.0"));
        assert_eq!(s.tailscale.progress.state, "up_to_date");
        assert!(s.busy(), "a system install is running");
        assert_eq!(
            s.auto_updates.unwrap().timezone.as_deref(),
            Some("America/New_York")
        );
        // An older Box, with less in it
        let old: Status =
            serde_json::from_str(r#"{"os": {"version": "2026.10.20.0316-gcdbc7c3"}}"#).unwrap();
        assert!(!old.busy() && old.auto_updates.is_none());
    }

    #[tokio::test]
    async fn talks_http_over_the_socket() {
        let dir = std::env::temp_dir().join(format!("box-api-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("api.sock");
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).unwrap();
        tokio::spawn(async move {
            for _ in 0..2 {
                let (mut s, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 1024];
                let n = s.read(&mut buf).await.unwrap();
                let req = String::from_utf8_lossy(&buf[..n]).to_string();
                let reply = if req.starts_with("GET /v1/status ") {
                    "HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"os\":{\"version\":\"0.50\"}}"
                } else {
                    "HTTP/1.0 409 Conflict\r\n\r\nalready running"
                };
                s.write_all(reply.as_bytes()).await.unwrap();
            }
        });
        let socket = path.to_str().unwrap();
        assert_eq!(status_at(socket).await.unwrap().os.version, "0.50");
        assert_eq!(
            start_at(socket, Action::Check).await,
            "That's already in progress."
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
