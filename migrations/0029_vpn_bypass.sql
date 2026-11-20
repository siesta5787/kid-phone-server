-- Apps on this device that skip the launcher's on-device content filter
-- (VPN) - a JSON array of package names, NULL = none. For apps that refuse
-- to work while a VPN is running (launcher v0.57.0+ leaves them out of the
-- VPN entirely, so Android tells them there's no VPN). Their traffic isn't
-- filtered. Set from the device page.
ALTER TABLE device_policy ADD COLUMN vpn_bypass_json TEXT;
