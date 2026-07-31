-- Require Tailscale to stay connected, and (once set up) force a specific
-- exit node - pushed to the device via Android's Managed App Restrictions
-- for com.tailscale.ipn (ForceEnabled / ExitNodeID keys). NULL/empty exit
-- node ID means no exit node is enforced yet.
ALTER TABLE device_policy ADD COLUMN require_tailscale INTEGER NOT NULL DEFAULT 0;
ALTER TABLE device_policy ADD COLUMN tailscale_exit_node_id TEXT;
