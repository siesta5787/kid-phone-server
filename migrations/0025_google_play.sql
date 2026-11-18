-- Google Play as a third tracked_apps source (source_type = 'play'), next to
-- 'github' and 'manual'. The package name is required for these (it's how
-- the app is looked up on Play). Releases still go through the same review
-- step and the same device API - see src/play.rs and handlers::google_play.
--
-- The server signs in to Play with the parent's spare Google account. Only
-- the long-lived AAS token is kept (never a password): it's swapped for a
-- short-lived AUTH token on each login. signin_window_until_ms is the
-- parent's "Sign in using a phone" window - the only time a device may hand
-- the server a sign-in code (POST /api/devices/play-signin). Singleton row.
CREATE TABLE play_settings (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    email TEXT,
    aas_token TEXT,
    signed_in_at TEXT,
    signin_window_until_ms INTEGER,
    -- The account email typed when the window was opened - kept apart from
    -- `email` so a working sign-in isn't overwritten until the new one works.
    signin_email TEXT,
    last_error TEXT,
    last_ok_at TEXT
);
INSERT INTO play_settings (id) VALUES (1);

-- Why the last automatic or "Check now" update check failed (NULL once one
-- succeeds) - so a problem like "this app comes in several pieces" stays
-- visible on the app's page instead of only in the server log.
ALTER TABLE tracked_apps ADD COLUMN last_check_error TEXT;
