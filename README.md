# Protected WordPress Uploads

Access-control layer for sensitive uploaded files.

## Portfolio edition

This repository is a sanitized portfolio edition of a completed WordPress project. Client domains, credentials, cached data, logs, and third-party vendor bundles have been removed or replaced with configuration fields.

## Installation

1. Copy the plugin directory into `wp-content/plugins/`.
2. Activate it from **Plugins** in wp-admin.
3. Configure required credentials, endpoints, feed URLs, or provider settings in the plugin's WordPress settings page.
4. Test on staging before production use.

## Security

No client credentials are committed. Store credentials in WordPress settings, environment-aware configuration, or a secrets manager; rotate any credentials previously used in a client environment.

## Verification

The PHP source has been linted after sanitization. Runtime behavior still depends on the documented WordPress, WooCommerce, and third-party provider setup for the chosen deployment.
