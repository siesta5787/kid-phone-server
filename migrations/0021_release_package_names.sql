-- kids-launcher-mdm (v0.50.0) and kids-mdm-browser (v0.03) stopped shipping their debug variants:
-- installed package names lost the ".debug" applicationIdSuffix. tracked_apps.package_name is only
-- auto-backfilled when empty (device_api::status), and allowlists store exact package names, so
-- rewrite both to the new names rather than leaving every re-provisioned phone mismatched.
UPDATE tracked_apps SET package_name = 'com.kidslauncher.mdm'
    WHERE package_name = 'com.kidslauncher.mdm.debug';
UPDATE tracked_apps SET package_name = 'com.kidsmdm.browser'
    WHERE package_name = 'com.kidsmdm.browser.debug';

UPDATE device_policy SET allowlist_json =
    REPLACE(REPLACE(allowlist_json,
        '"com.kidslauncher.mdm.debug"', '"com.kidslauncher.mdm"'),
        '"com.kidsmdm.browser.debug"', '"com.kidsmdm.browser"')
    WHERE allowlist_json LIKE '%.debug"%';
