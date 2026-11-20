// Live progress for slow things on the parent site:
// 1. Upload forms marked data-upload-progress are sent with XMLHttpRequest so the page can show how
//    much has been uploaded and roughly how long is left, then "checking" while the server reads
//    the APK. The server's reply (the app page, with any error) then replaces this page.
// 2. The device page's Apps list (data-install-status-url) polls the phone's reported install
//    progress and updates the status labels in place - "Downloading 45% from Google Play · about
//    6 min left", then "Installing…" - instead of the page sitting on "Not installed". An app
//    already on the phone shows "Updating 45%…", then "Installed" again.

function megabytes(bytes) {
    return (bytes / 1048576).toFixed(bytes < 10485760 ? 1 : 0) + " MB";
}

function timeLeft(seconds) {
    if (!isFinite(seconds) || seconds <= 0) return "";
    if (seconds < 60) return "less than a minute left";
    return "about " + Math.round(seconds / 60) + " min left";
}

document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!form.matches("form[data-upload-progress]")) return;
    event.preventDefault();
    const status = form.querySelector(".upload-status");
    const bar = form.querySelector(".upload-bar");
    const button = form.querySelector("button[type=submit]");
    button.disabled = true;
    status.hidden = false;
    bar.hidden = false;
    status.textContent = "Starting upload…";
    const started = Date.now();
    const xhr = new XMLHttpRequest();
    xhr.open("POST", form.action);
    xhr.upload.onprogress = (e) => {
        if (!e.lengthComputable) {
            status.textContent = "Uploading… " + megabytes(e.loaded);
            return;
        }
        const percent = Math.floor((e.loaded * 100) / e.total);
        bar.value = percent;
        const elapsed = (Date.now() - started) / 1000;
        const left = e.loaded > 0 && elapsed > 3 ? timeLeft((elapsed * (e.total - e.loaded)) / e.loaded) : "";
        status.textContent = "Uploading… " + percent + "% (" + megabytes(e.loaded) + " of " +
            megabytes(e.total) + ")" + (left ? " · " + left : "");
    };
    xhr.upload.onload = () => {
        bar.removeAttribute("value");
        status.textContent = "Uploaded - checking the APK on the server…";
    };
    xhr.onload = () => {
        document.open();
        document.write(xhr.responseText);
        document.close();
    };
    xhr.onerror = () => {
        status.textContent = "The upload failed - check the connection and try again.";
        button.disabled = false;
    };
    xhr.send(new FormData(form));
});

(function pollInstallStatus() {
    const list = document.querySelector("[data-install-status-url]");
    if (!list) return;
    const url = list.dataset.installStatusUrl;
    const firstSeen = {};
    let tracked = {};

    function shouldPoll() {
        return list.querySelector("[data-awaiting=true], [data-installing=true]") !== null;
    }

    async function tick() {
        if (!shouldPoll()) return;
        try {
            const response = await fetch(url, { credentials: "same-origin" });
            if (!response.ok) return;
            const apps = (await response.json()).apps || {};
            let reload = false;
            list.querySelectorAll(".app-status[data-tracked-app-id]").forEach((label) => {
                const id = label.dataset.trackedAppId;
                const entry = apps[id];
                if (!entry) {
                    // It was installing and the phone stopped reporting: finished (or gave up) -
                    // reload once to show the real state from the phone's latest report.
                    if (tracked[id]) reload = true;
                    return;
                }
                if (entry.failed) {
                    if (label.dataset.failed !== "true") reload = true;
                    return;
                }
                const update = label.dataset.update === "true";
                if (update && entry.percent >= 100) {
                    // The update's downloaded and handed to Android.
                    if (tracked[id]) label.textContent = "Installed";
                    delete tracked[id];
                    label.dataset.installing = "false";
                    return;
                }
                tracked[id] = true;
                label.dataset.installing = "true";
                if (entry.percent >= 100) {
                    label.textContent = "Installing…";
                    return;
                }
                const now = Date.now() / 1000;
                const seen = firstSeen[id] || (firstSeen[id] = { t: now, p: entry.percent });
                const gained = entry.percent - seen.p;
                const left = gained > 0 ? timeLeft(((now - seen.t) * (100 - entry.percent)) / gained) : "";
                label.textContent = (update ? "Updating " : "Downloading ") + entry.percent + "%" +
                    (entry.source || "") + (left ? " · " + left : "");
            });
            if (reload) location.reload();
        } catch (e) {
            // Server busy or offline for a moment - try again next tick.
        }
    }

    tick();
    setInterval(tick, 4000);
})();
