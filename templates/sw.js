// Service worker — templated so `{{ app_version }}` is baked into the
// script's own bytes on every request, which is what makes the browser's
// update-detection actually fire (it byte-diffs a refetched /sw.js against
// the installed one).
//
// Deliberately minimal: this exists only to satisfy PWA installability
// criteria (a registered service worker with an install/activate/fetch
// lifecycle). It does NOT cache pages or assets for offline use - this app
// handles admin session cookies and device bearer tokens, and offline
// browsing of the admin console isn't a stated need, so there's no upside
// to the added complexity/risk of an offline cache here.
const VERSION = "{{ app_version }}";

self.addEventListener("install", () => {
    self.skipWaiting();
});

self.addEventListener("activate", (event) => {
    event.waitUntil(self.clients.claim());
});

// No fetch handler at all - every request passes straight through to the
// network untouched, exactly as if this service worker didn't exist.
