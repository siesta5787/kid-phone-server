-- Phase D (client) retired the standalone Tailscale app entirely - tsnet is
-- embedded directly and the always-on VPN is now the launcher's own
-- KidVpnService, neither of which reads require_tailscale/tailscale_exit_node_id
-- any more (see kids-launcher-mdm's CLAUDE.md). Drop both; nothing references
-- them going forward.
ALTER TABLE device_policy DROP COLUMN require_tailscale;
ALTER TABLE device_policy DROP COLUMN tailscale_exit_node_id;

-- Per-device on/off for the on-device DNS filter's VPN piece (KidVpnService).
-- Defaults to enabled (1) so every existing/new device keeps filtering
-- unless a parent explicitly turns it off for that kid - see AppEnforcer's
-- (client) applyVpnRestrictions for how this actually stops/starts the VPN.
ALTER TABLE device_policy ADD COLUMN vpn_filter_enabled INTEGER NOT NULL DEFAULT 1;

-- dns_filter_settings.enabled used to turn the (now-retired) live DNS server
-- on/off network-wide. There's no live server left to enable/disable - each
-- device's own vpn_filter_enabled above is what that job now belongs to.
ALTER TABLE dns_filter_settings DROP COLUMN enabled;
