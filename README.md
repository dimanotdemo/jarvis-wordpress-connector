# JARVIS WordPress Connector

A ~10-minute, one-file install that lets JARVIS read a WordPress site's
plugin/theme/core update state — and, under policy, apply updates — without
SSH and without a third-party SaaS.

## What it is

A small plugin that registers two secured REST routes:

| Method | Route | Purpose |
|--------|-------|---------|
| `GET`  | `/wp-json/jarvis/v1/state`    | Normalized plugin/theme/core update snapshot + comment counts |
| `POST` | `/wp-json/jarvis/v1/update`   | Apply a single update (`plugin` / `theme` / `core`) |
| `GET`  | `/wp-json/jarvis/v1/comments` | Comment moderation queue (`status`, `page`, `per_page`) |
| `POST` | `/wp-json/jarvis/v1/comment`  | Moderate one comment (`approve`/`spam`/`trash`/`delete`/…) |

Every request must carry a shared secret in the `X-JARVIS-Secret` header. With
no secret configured, the routes return `503` and refuse to run — they are
never open.

The artifact is **`jarvis-connector.zip`** in this folder.

## Install (normal upload — recommended)

This is the familiar WordPress plugin-upload flow. No SFTP needed.

1. In wp-admin go to **Plugins → Add New → Upload Plugin**.
2. Choose **`jarvis-connector.zip`** and click **Install Now**, then **Activate**.
3. **Set the shared secret.** Generate one (`openssl rand -hex 32`, or any long
   random string) and add this line to `wp-config.php` (above
   `/* That's all, stop editing! */`):
   ```php
   define( 'JARVIS_CONNECTOR_SECRET', 'PASTE_THE_SECRET_HERE' );
   ```
   *(Alternative: a `JARVIS_CONNECTOR_SECRET` environment variable.)*
4. **Link in JARVIS.** On the project overview → **Configure → Integrations →
   WordPress**, paste the **site URL** and the **same secret**.

> The secret step still needs one line in `wp-config.php`. If you'd rather set
> it from the WordPress dashboard (zero file access), JARVIS can ship a version
> with a Settings page — ask and we'll add it.

### Verify (optional)
```bash
curl -s https://example.org/wp-json/jarvis/v1/state \
  -H "X-JARVIS-Secret: PASTE_THE_SECRET_HERE" | head
```
JSON with `connector_version` + a `plugins` array means it's working. `403` =
wrong secret; `503` = secret not set.

## Install (must-use plugin — advanced)

If you want the connector to be **un-deactivatable** (can't be turned off from
wp-admin), install it as a must-use plugin instead: copy
`jarvis-connector/jarvis-connector.php` to `wp-content/mu-plugins/` (create the
folder if needed). MU-plugins load automatically and don't appear in the normal
Plugins list. This route needs SFTP/file-manager access.

## Security notes

- Always serve over **HTTPS** — the secret travels in a request header.
- The secret is stored **encrypted** (AES-256-GCM) on the JARVIS side.
- **Rotate** by changing the value in both `wp-config.php` and the JARVIS link.
- The secret compare is constant-time (`hash_equals`) to avoid timing leaks.

## Updating the connector

Re-upload a newer `jarvis-connector.zip` (WordPress will offer to replace the
existing plugin), or replace the file if you installed it as an MU-plugin. The
`connector_version` field in `/state` lets JARVIS detect an out-of-date
connector and prompt for an upgrade.

## Vulnerability scanning (optional but recommended)

JARVIS flags plugins/themes/core with known CVEs using the **WPScan** vulnerability
database — but only when a token is configured. Without it, update tracking still
works, but nothing is ever marked *vulnerable* (and the card shows "vuln scan off"
so a clean list isn't mistaken for a clean bill).

To enable:
1. Register at <https://wpscan.com/register/> (free tier: 25 requests/day).
2. Copy the API token from your WPScan profile.
3. Add it to JARVIS's `.env.local`:
   ```
   WPSCAN_API_TOKEN=your-token-here
   ```
4. Restart JARVIS. The next sync enriches plugins, themes, and core with
   severity-ranked vulnerability data; vulnerable components become urgent tasks.

## Read-only fallback (no connector)

If you can't install a plugin at all, JARVIS also supports a read-only tier
using a WordPress **Application Password** (Users → Profile → Application
Passwords, WP 5.6+). This lists plugins and versions but **cannot trigger
updates** — core REST has no update-apply endpoint. The connector is required
for the auto-patch / approve-major update flow.

## Support

Questions about the connector? Reach out to **Dima** at
[d@bernasovskiy.com](mailto:d@bernasovskiy.com).
