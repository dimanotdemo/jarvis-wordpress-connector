<?php
/**
 * Plugin Name: JARVIS Connector
 * Description: Secured REST endpoints so JARVIS can read plugin/theme/core
 *              update state and (under policy) apply updates.
 * Version:     1.6.0
 * Author:      Dima
 * Author URI:  mailto:d@bernasovskiy.com
 * Update URI:  https://github.com/dimanotdemo/jarvis-wordpress-connector
 *
 * SUPPORT: Questions about this connector? Reach out to Dima at
 * d@bernasovskiy.com.
 *
 * SELF-UPDATE: this plugin checks its own GitHub releases and offers an
 * in-place update through the normal WordPress "update available" flow — so
 * JARVIS (or a one-click update in wp-admin) upgrades it like any other
 * plugin. No re-uploading the zip by hand after the first install. See the
 * self-update section near the bottom of this file. (Regular-plugin installs
 * only — must-use plugins don't participate in the update transient.)
 *
 * INSTALL (normal upload): Plugins → Add New → Upload Plugin → choose the zip
 * → Install Now → Activate. On activation the plugin AUTO-GENERATES a shared
 * secret and shows it under Settings → JARVIS Connector. Copy the secret +
 * site URL into JARVIS. No wp-config.php editing, no SFTP.
 *
 * AUTH: every request must carry the shared secret in the X-JARVIS-Secret
 * header. The secret is resolved in this order:
 *   1. JARVIS_CONNECTOR_SECRET constant in wp-config.php (advanced override)
 *   2. JARVIS_CONNECTOR_SECRET environment variable
 *   3. the auto-generated value stored in the `jarvis_connector_secret` option
 *      (the default — managed from the Settings page)
 * If none exist, the endpoints return 503 and refuse to run — never open.
 *
 * Routes (all under /wp-json/jarvis/v1):
 *   GET  /state    → normalized plugin/theme/core update state + comment counts
 *   POST /update   → { type, slug, plugin_file?, target_version? } apply one update
 *   GET  /comments → { status?, page?, per_page? } moderation queue
 *   POST /comment  → { comment_id, action } moderate one comment
 *   POST /plugin   → { action, plugin_file?, slug?, activate? }
 *                    activate|deactivate|delete an installed plugin, or
 *                    install a new one from wp.org by slug
 *   POST /theme    → { action, slug } activate (switch) | delete a theme
 *   GET  /integrity → core file checksum check (modified/missing core files)
 *
 * /state also reports `environment` (php/mysql/cron) + `security` flags.
 *
 * No external dependencies; uses only core WordPress upgrade APIs.
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Never run outside WordPress.
}

if ( ! defined( 'JARVIS_CONNECTOR_VERSION' ) ) {
	define( 'JARVIS_CONNECTOR_VERSION', '1.6.0' );
}

const JARVIS_CONNECTOR_OPTION = 'jarvis_connector_secret';

// Self-update source: a public GitHub repo whose Releases carry the connector
// zip. "owner/repo" — override with a JARVIS_CONNECTOR_REPO constant if you
// fork it. The asset must be named jarvis-connector.zip.
if ( ! defined( 'JARVIS_CONNECTOR_REPO' ) ) {
	define( 'JARVIS_CONNECTOR_REPO', 'dimanotdemo/jarvis-wordpress-connector' );
}
const JARVIS_CONNECTOR_ASSET = 'jarvis-connector.zip';

/**
 * Resolve the configured shared secret, or null when unconfigured.
 * Order: wp-config constant → env var → stored option.
 */
function jarvis_connector_secret() {
	if ( defined( 'JARVIS_CONNECTOR_SECRET' ) && JARVIS_CONNECTOR_SECRET ) {
		return (string) JARVIS_CONNECTOR_SECRET;
	}
	$env = getenv( 'JARVIS_CONNECTOR_SECRET' );
	if ( $env ) {
		return (string) $env;
	}
	$opt = get_option( JARVIS_CONNECTOR_OPTION );
	return $opt ? (string) $opt : null;
}

/**
 * Return the stored secret, generating + persisting one if absent. No-op
 * when a constant/env secret is in force (those take precedence; we don't
 * want a dangling unused option). Returns the effective secret.
 */
function jarvis_connector_ensure_secret() {
	if ( ( defined( 'JARVIS_CONNECTOR_SECRET' ) && JARVIS_CONNECTOR_SECRET ) || getenv( 'JARVIS_CONNECTOR_SECRET' ) ) {
		return jarvis_connector_secret();
	}
	$existing = get_option( JARVIS_CONNECTOR_OPTION );
	if ( $existing ) {
		return (string) $existing;
	}
	$generated = wp_generate_password( 64, false, false ); // 64 alphanumeric chars
	update_option( JARVIS_CONNECTOR_OPTION, $generated, false );
	return $generated;
}

// Generate the secret the moment the plugin is activated (normal install).
register_activation_hook( __FILE__, 'jarvis_connector_ensure_secret' );

// MU-plugins don't fire activation hooks — ensure on admin load as a backstop.
add_action( 'admin_init', function () {
	if ( current_user_can( 'manage_options' ) ) {
		jarvis_connector_ensure_secret();
	}
} );

/**
 * Permission callback for every JARVIS route. Constant-time compare so the
 * check doesn't leak the secret length/prefix via timing.
 */
function jarvis_connector_authorize( WP_REST_Request $request ) {
	$configured = jarvis_connector_secret();
	if ( ! $configured ) {
		return new WP_Error(
			'jarvis_not_configured',
			'No connector secret configured on this site.',
			array( 'status' => 503 )
		);
	}
	$provided = (string) $request->get_header( 'x-jarvis-secret' );
	if ( ! $provided || ! hash_equals( $configured, $provided ) ) {
		return new WP_Error(
			'jarvis_forbidden',
			'Invalid or missing X-JARVIS-Secret.',
			array( 'status' => 403 )
		);
	}
	return true;
}

add_action( 'rest_api_init', function () {
	register_rest_route( 'jarvis/v1', '/state', array(
		'methods'             => 'GET',
		'callback'            => 'jarvis_connector_state',
		'permission_callback' => 'jarvis_connector_authorize',
	) );

	register_rest_route( 'jarvis/v1', '/update', array(
		'methods'             => 'POST',
		'callback'            => 'jarvis_connector_update',
		'permission_callback' => 'jarvis_connector_authorize',
		'args'                => array(
			'type'           => array( 'required' => true ),  // 'plugin' | 'theme' | 'core'
			'slug'           => array( 'required' => false ),
			'plugin_file'    => array( 'required' => false ),
			'target_version' => array( 'required' => false ),
		),
	) );

	register_rest_route( 'jarvis/v1', '/comments', array(
		'methods'             => 'GET',
		'callback'            => 'jarvis_connector_comments',
		'permission_callback' => 'jarvis_connector_authorize',
		'args'                => array(
			'status'   => array( 'required' => false ),  // 'hold'|'approve'|'spam'|'trash'|'all'
			'page'     => array( 'required' => false ),
			'per_page' => array( 'required' => false ),
		),
	) );

	register_rest_route( 'jarvis/v1', '/comment', array(
		'methods'             => 'POST',
		'callback'            => 'jarvis_connector_comment',
		'permission_callback' => 'jarvis_connector_authorize',
		'args'                => array(
			'comment_id' => array( 'required' => true ),
			// approve|unapprove|spam|unspam|trash|untrash|delete
			'action'     => array( 'required' => true ),
		),
	) );

	register_rest_route( 'jarvis/v1', '/plugin', array(
		'methods'             => 'POST',
		'callback'            => 'jarvis_connector_plugin_manage',
		'permission_callback' => 'jarvis_connector_authorize',
		'args'                => array(
			'action'      => array( 'required' => true ),  // activate|deactivate|delete|install
			'plugin_file' => array( 'required' => false ), // for activate/deactivate/delete
			'slug'        => array( 'required' => false ), // resolves plugin_file, or wp.org slug for install
			'activate'    => array( 'required' => false ), // install: activate after installing
		),
	) );

	register_rest_route( 'jarvis/v1', '/theme', array(
		'methods'             => 'POST',
		'callback'            => 'jarvis_connector_theme_manage',
		'permission_callback' => 'jarvis_connector_authorize',
		'args'                => array(
			'action' => array( 'required' => true ),  // activate|delete
			'slug'   => array( 'required' => true ),  // stylesheet
		),
	) );

	register_rest_route( 'jarvis/v1', '/integrity', array(
		'methods'             => 'GET',
		'callback'            => 'jarvis_connector_integrity',
		'permission_callback' => 'jarvis_connector_authorize',
	) );
} );

// Never let a CDN/cache store our responses. /state is a live snapshot — a
// cached copy (e.g. Cloudflare "cache everything") silently feeds JARVIS stale
// versions and triggers phantom "already at latest" re-applies. We can't force
// an aggressive edge rule to honor these, but for caches that respect origin
// headers it keeps the response uncacheable. (JARVIS also cache-busts every
// request with a unique query param as the reliable belt-and-suspenders.)
add_filter( 'rest_post_dispatch', function ( $response, $server, $request ) {
	if ( $request instanceof WP_REST_Request && 0 === strpos( (string) $request->get_route(), '/jarvis/v1' ) ) {
		$response->header( 'Cache-Control', 'no-store, no-cache, must-revalidate, max-age=0' );
		$response->header( 'CDN-Cache-Control', 'no-store' );
		$response->header( 'Cloudflare-CDN-Cache-Control', 'no-store' );
	}
	return $response;
}, 10, 3 );

// ─── Admin settings page ──────────────────────────────────────────────

add_action( 'admin_menu', function () {
	add_options_page(
		'JARVIS Connector',
		'JARVIS Connector',
		'manage_options',
		'jarvis-connector',
		'jarvis_connector_settings_page'
	);
} );

function jarvis_connector_settings_page() {
	if ( ! current_user_can( 'manage_options' ) ) {
		return;
	}

	$using_constant = ( defined( 'JARVIS_CONNECTOR_SECRET' ) && JARVIS_CONNECTOR_SECRET ) || getenv( 'JARVIS_CONNECTOR_SECRET' );
	$notice         = '';

	// Handle "regenerate secret".
	if ( isset( $_POST['jarvis_regenerate'] ) && check_admin_referer( 'jarvis_regen', 'jarvis_regen_nonce' ) ) {
		if ( $using_constant ) {
			$notice = '<div class="notice notice-warning"><p>Secret is fixed by a wp-config constant or environment variable — regenerate from there.</p></div>';
		} else {
			update_option( JARVIS_CONNECTOR_OPTION, wp_generate_password( 64, false, false ), false );
			$notice = '<div class="notice notice-success"><p>New secret generated. Paste it into JARVIS again to reconnect.</p></div>';
		}
	}

	$secret   = jarvis_connector_ensure_secret();
	$site_url = get_site_url();
	?>
	<div class="wrap">
		<h1>JARVIS Connector</h1>
		<?php echo $notice; // phpcs:ignore WordPress.Security.EscapeOutput.OutputNotEscaped — static strings above ?>
		<p>Paste these two values into JARVIS under
			<strong>Project → Configure → Integrations → WordPress</strong>.</p>

		<table class="form-table" role="presentation">
			<tr>
				<th scope="row"><label for="jarvis-url">Site URL</label></th>
				<td>
					<input id="jarvis-url" type="text" class="regular-text code" readonly
						value="<?php echo esc_attr( $site_url ); ?>" onclick="this.select()" />
					<button type="button" class="button" onclick="jarvisCopy('jarvis-url')">Copy</button>
				</td>
			</tr>
			<tr>
				<th scope="row"><label for="jarvis-secret">Shared secret</label></th>
				<td>
					<input id="jarvis-secret" type="text" class="regular-text code" readonly
						value="<?php echo esc_attr( $secret ); ?>" onclick="this.select()"
						style="width:32em;" />
					<button type="button" class="button" onclick="jarvisCopy('jarvis-secret')">Copy</button>
					<?php if ( $using_constant ) : ?>
						<p class="description">Defined by a wp-config constant / environment variable.</p>
					<?php else : ?>
						<p class="description">Auto-generated and stored on this site. Keep it secret.</p>
					<?php endif; ?>
				</td>
			</tr>
		</table>

		<?php if ( ! $using_constant ) : ?>
			<form method="post">
				<?php wp_nonce_field( 'jarvis_regen', 'jarvis_regen_nonce' ); ?>
				<button type="submit" name="jarvis_regenerate" value="1" class="button button-secondary"
					onclick="return confirm('Generate a new secret? JARVIS will need the new value to reconnect.');">
					Regenerate secret
				</button>
			</form>
		<?php endif; ?>

		<hr style="margin-top:2em;" />
		<p class="description">
			Questions about this connector? Reach out to <strong>Dima</strong> at
			<a href="mailto:d@bernasovskiy.com">d@bernasovskiy.com</a>.
		</p>

		<script>
			function jarvisCopy(id) {
				var el = document.getElementById(id);
				el.select();
				navigator.clipboard.writeText(el.value);
			}
		</script>
	</div>
	<?php
}

// ─── REST: state ──────────────────────────────────────────────────────

/**
 * GET /jarvis/v1/state
 *
 * Forces a fresh update check, then returns a normalized snapshot of
 * plugins, themes, and core straight from WordPress's own update
 * transients — exactly what wp-admin would show.
 */
function jarvis_connector_state() {
	if ( ! function_exists( 'get_plugins' ) ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}
	require_once ABSPATH . 'wp-admin/includes/update.php';

	// Drop any cached plugin list + update transient first, so get_plugins()
	// re-reads file headers and the update check is genuinely fresh. Without
	// this, a persistent object cache (Redis/Memcached) can report a
	// just-applied update as still pending.
	wp_clean_plugins_cache( true );

	wp_update_plugins();
	wp_update_themes();
	wp_version_check();

	$all_plugins    = get_plugins();
	$plugin_updates = get_plugin_updates();
	$auto_updates   = (array) get_site_option( 'auto_update_plugins', array() );

	$plugins = array();
	foreach ( $all_plugins as $file => $data ) {
		$slug = dirname( $file );
		if ( '.' === $slug ) {
			$slug = preg_replace( '/\.php$/', '', basename( $file ) );
		}
		$update = isset( $plugin_updates[ $file ] ) ? $plugin_updates[ $file ]->update : null;

		$plugins[] = array(
			'slug'              => $slug,
			'plugin_file'       => $file,
			'name'              => isset( $data['Name'] ) ? $data['Name'] : $slug,
			'installed_version' => isset( $data['Version'] ) ? $data['Version'] : null,
			'latest_version'    => $update && isset( $update->new_version ) ? $update->new_version : ( isset( $data['Version'] ) ? $data['Version'] : null ),
			'update_available'  => (bool) $update,
			'is_active'         => is_plugin_active( $file ),
			'auto_update'       => in_array( $file, $auto_updates, true ),
		);
	}

	$theme_updates  = get_theme_updates();
	$active_theme   = get_stylesheet(); // the active theme's stylesheet
	$parent_theme   = get_template();   // its parent (for child themes)
	$themes         = array();
	foreach ( wp_get_themes() as $stylesheet => $theme ) {
		$update      = isset( $theme_updates[ $stylesheet ] ) ? $theme_updates[ $stylesheet ]->update : null;
		$new_version = ( is_array( $update ) && isset( $update['new_version'] ) ) ? $update['new_version'] : null;
		$themes[]    = array(
			'slug'              => $stylesheet,
			'name'              => $theme->get( 'Name' ),
			'installed_version' => $theme->get( 'Version' ),
			'latest_version'    => $new_version ? $new_version : $theme->get( 'Version' ),
			'update_available'  => (bool) $update,
			// Active = the running theme OR the parent of an active child theme
			// (deleting either would break the site).
			'is_active'         => ( $stylesheet === $active_theme || $stylesheet === $parent_theme ),
		);
	}

	$core_updates      = get_core_updates();
	$core_latest       = ( is_array( $core_updates ) && ! empty( $core_updates ) && isset( $core_updates[0]->current ) )
		? $core_updates[0]->current
		: get_bloginfo( 'version' );
	$core_update_avail = ( is_array( $core_updates ) && ! empty( $core_updates ) && isset( $core_updates[0]->response ) && 'upgrade' === $core_updates[0]->response );

	// Comment counts — cheap (one COUNT(*) GROUP BY behind the cache). Lets
	// JARVIS badge "N to moderate" without listing every comment.
	$comment_counts = wp_count_comments();
	$comments       = array(
		'pending'  => (int) $comment_counts->moderated,
		'approved' => (int) $comment_counts->approved,
		'spam'     => (int) $comment_counts->spam,
		'trash'    => (int) $comment_counts->trash,
		'total'    => (int) $comment_counts->total_comments,
	);

	return new WP_REST_Response( array(
		'connector_version' => JARVIS_CONNECTOR_VERSION,
		'wp_version'        => get_bloginfo( 'version' ),
		'site_url'          => get_site_url(),
		'checked_at'        => gmdate( 'c' ),
		'core'              => array(
			'installed_version' => get_bloginfo( 'version' ),
			'latest_version'    => $core_latest,
			'update_available'  => $core_update_avail,
		),
		'plugins'           => $plugins,
		'themes'            => $themes,
		'comments'          => $comments,
		'environment'       => jarvis_connector_environment(),
		'security'          => jarvis_connector_security_flags(),
	), 200 );
}

/** Runtime environment snapshot — cheap, always returned with /state. JARVIS
 *  decides what's an issue (e.g. EOL PHP), the connector just reports facts. */
function jarvis_connector_environment() {
	$cron_overdue = 0;
	$crons = function_exists( '_get_cron_array' ) ? _get_cron_array() : array();
	if ( is_array( $crons ) ) {
		$now = time();
		foreach ( $crons as $ts => $hooks ) {
			if ( (int) $ts < $now - 300 ) {
				$cron_overdue += is_array( $hooks ) ? count( $hooks ) : 1;
			}
		}
	}
	return array(
		'php_version'     => PHP_VERSION,
		'mysql_version'   => function_exists( 'get_database_version' ) ? get_database_version() : null,
		'memory_limit'    => ini_get( 'memory_limit' ),
		'is_multisite'    => is_multisite(),
		'https'           => is_ssl() || 0 === stripos( (string) get_option( 'siteurl' ), 'https://' ),
		'wp_cron_disabled' => defined( 'DISABLE_WP_CRON' ) && DISABLE_WP_CRON,
		'cron_overdue'    => $cron_overdue,
	);
}

/** Security-relevant configuration flags. Booleans only — JARVIS turns these
 *  into severity-ranked findings so the rules live in one place. */
function jarvis_connector_security_flags() {
	if ( ! function_exists( 'get_users' ) ) {
		require_once ABSPATH . 'wp-includes/user.php';
	}
	// Is there a user literally named "admin"? (classic brute-force target)
	$admin_named = get_users( array( 'login' => 'admin', 'number' => 1, 'fields' => 'ID' ) );

	return array(
		'wp_debug'                 => defined( 'WP_DEBUG' ) && WP_DEBUG,
		'file_edit_disabled'       => defined( 'DISALLOW_FILE_EDIT' ) && DISALLOW_FILE_EDIT,
		'file_mods_disabled'       => defined( 'DISALLOW_FILE_MODS' ) && DISALLOW_FILE_MODS,
		'xmlrpc_enabled'           => (bool) apply_filters( 'xmlrpc_enabled', true ),
		'search_engine_visible'    => '1' === (string) get_option( 'blog_public', '1' ),
		'admin_user_exists'        => ! empty( $admin_named ),
		'users_can_register'       => (bool) get_option( 'users_can_register' ),
		'auto_update_core_enabled' => function_exists( 'wp_is_auto_update_enabled_for_type' ) ? wp_is_auto_update_enabled_for_type( 'core' ) : null,
	);
}

// ─── REST: update ─────────────────────────────────────────────────────

/**
 * POST /jarvis/v1/update
 *
 * Applies a single plugin/theme/core update using the core Upgrader. JARVIS
 * owns the policy decision (auto patch/minor vs approve major); this just
 * executes and reports back a 3-way result.
 */
function jarvis_connector_update( WP_REST_Request $request ) {
	$type = (string) $request->get_param( 'type' );

	require_once ABSPATH . 'wp-admin/includes/file.php';
	require_once ABSPATH . 'wp-admin/includes/misc.php';
	require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';
	if ( ! function_exists( 'get_plugins' ) ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}
	require_once ABSPATH . 'wp-admin/includes/update.php';

	$skin = new WP_Ajax_Upgrader_Skin();

	if ( 'plugin' === $type ) {
		$plugin_file = (string) $request->get_param( 'plugin_file' );
		if ( ! $plugin_file ) {
			$slug = (string) $request->get_param( 'slug' );
			foreach ( array_keys( get_plugins() ) as $file ) {
				if ( dirname( $file ) === $slug ) {
					$plugin_file = $file;
					break;
				}
			}
		}
		if ( ! $plugin_file ) {
			return new WP_Error( 'jarvis_bad_request', 'plugin_file or resolvable slug required', array( 'status' => 400 ) );
		}

		wp_update_plugins();
		$before   = get_plugins();
		$prev     = isset( $before[ $plugin_file ]['Version'] ) ? $before[ $plugin_file ]['Version'] : null;

		// The upgrader deactivates an active plugin to swap files and does NOT
		// reactivate it on its own. Capture the prior state so we can restore
		// it after the upgrade (incl. network-active on multisite).
		$was_active  = is_plugin_active( $plugin_file );
		$was_network = is_multisite() && is_plugin_active_for_network( $plugin_file );

		$upgrader = new Plugin_Upgrader( $skin );
		$result   = $upgrader->upgrade( $plugin_file );

		// Restore the active state (silent = no redirects/output). Safe even on
		// a failed upgrade — it just re-activates the still-installed plugin.
		if ( $was_active && ! is_plugin_active( $plugin_file ) ) {
			activate_plugin( $plugin_file, '', $was_network, true );
		}

		// Bust the plugin + update caches so a follow-up /state reflects the
		// new version immediately (object caches otherwise serve stale headers
		// and a stale update_plugins transient → the update looks un-applied).
		wp_clean_plugins_cache( true );

		return jarvis_connector_upgrade_response( $type, $plugin_file, $prev, $result, $skin, $request );
	}

	if ( 'theme' === $type ) {
		$slug = (string) $request->get_param( 'slug' );
		if ( ! $slug ) {
			return new WP_Error( 'jarvis_bad_request', 'slug required', array( 'status' => 400 ) );
		}
		wp_update_themes();
		$upgrader = new Theme_Upgrader( $skin );
		$result   = $upgrader->upgrade( $slug );
		return jarvis_connector_upgrade_response( $type, $slug, null, $result, $skin, $request );
	}

	if ( 'core' === $type ) {
		wp_version_check();
		$updates = get_core_updates();
		if ( empty( $updates ) || ! isset( $updates[0] ) || 'upgrade' !== $updates[0]->response ) {
			return new WP_REST_Response( array( 'ok' => true, 'status' => 'already_current', 'type' => 'core' ), 200 );
		}
		$upgrader = new Core_Upgrader( $skin );
		$result   = $upgrader->upgrade( $updates[0] );
		return jarvis_connector_upgrade_response( 'core', 'core', get_bloginfo( 'version' ), $result, $skin, $request );
	}

	return new WP_Error( 'jarvis_bad_request', "Unknown type '$type' (expected plugin|theme|core)", array( 'status' => 400 ) );
}

/**
 * Normalize an Upgrader result into a 3-way response: applied | already
 * current | error. JARVIS treats "already current" as success (idempotent).
 */
/** Read the currently-installed version straight from disk, for the response. */
function jarvis_connector_installed_version( $type, $target ) {
	if ( 'plugin' === $type ) {
		if ( ! function_exists( 'get_plugins' ) ) {
			require_once ABSPATH . 'wp-admin/includes/plugin.php';
		}
		wp_clean_plugins_cache( false );
		$plugins = get_plugins();
		return isset( $plugins[ $target ]['Version'] ) ? $plugins[ $target ]['Version'] : null;
	}
	if ( 'theme' === $type ) {
		$theme = wp_get_theme( $target );
		return $theme->exists() ? $theme->get( 'Version' ) : null;
	}
	return get_bloginfo( 'version' ); // core
}

function jarvis_connector_upgrade_response( $type, $target, $prev_version, $result, $skin, WP_REST_Request $request ) {
	$errors     = $skin->get_errors();
	$has_errors = is_wp_error( $errors ) && $errors->has_errors();

	// "Already at the latest version" is NOT a failure — it's the idempotent
	// already-current case (the file is already at/above target). WordPress
	// surfaces it as an upgrader error ('up_to_date' / a "latest version"
	// message); treat it as success so JARVIS reconciles the snapshot instead
	// of logging a phantom failure and re-attempting forever.
	$up_to_date = ( false === $result || null === $result );
	if ( $has_errors ) {
		$code = $errors->get_error_code();
		$msg  = (string) $errors->get_error_message();
		if (
			'up_to_date' === $code
			|| false !== stripos( $msg, 'latest version' )
			|| false !== stripos( $msg, 'up to date' )
			|| false !== stripos( $msg, 'no update' )
		) {
			$up_to_date = true;
		} else {
			return new WP_REST_Response( array(
				'ok' => false, 'status' => 'error', 'type' => $type, 'target' => $target,
				'error' => $msg,
			), 200 );
		}
	}

	if ( ! $up_to_date && is_wp_error( $result ) ) {
		return new WP_REST_Response( array(
			'ok' => false, 'status' => 'error', 'type' => $type, 'target' => $target,
			'error' => $result->get_error_message(),
		), 200 );
	}

	if ( $up_to_date ) {
		return new WP_REST_Response( array(
			'ok'          => true,
			'status'      => 'already_current',
			'type'        => $type,
			'target'      => $target,
			'new_version' => jarvis_connector_installed_version( $type, $target ),
		), 200 );
	}

	return new WP_REST_Response( array(
		'ok'             => true,
		'status'         => 'applied',
		'type'           => $type,
		'target'         => $target,
		'prev_version'   => $prev_version,
		'new_version'    => jarvis_connector_installed_version( $type, $target ),
		'target_version' => $request->get_param( 'target_version' ),
	), 200 );
}

// ─── REST: comments ───────────────────────────────────────────────────

/**
 * GET /jarvis/v1/comments
 *
 * A normalized, paginated list of comments for the moderation queue. Defaults
 * to the moderation hold ('hold') since that's the actionable set; pass
 * status=all|approve|spam|trash to widen. Content is excerpted server-side so
 * the payload stays small and JARVIS never has to render raw HTML.
 */
function jarvis_connector_comments( WP_REST_Request $request ) {
	$status   = (string) $request->get_param( 'status' );
	$page     = max( 1, (int) $request->get_param( 'page' ) );
	$per_page = (int) $request->get_param( 'per_page' );
	if ( $per_page < 1 || $per_page > 100 ) {
		$per_page = 50;
	}

	// Map JARVIS-facing status → get_comments() 'status' arg.
	$status_map = array(
		'hold'    => 'hold',
		'approve' => 'approve',
		'spam'    => 'spam',
		'trash'   => 'trash',
		'all'     => 'all',
	);
	$wp_status = isset( $status_map[ $status ] ) ? $status_map[ $status ] : 'hold';

	$query = array(
		'status'  => $wp_status,
		'number'  => $per_page,
		'offset'  => ( $page - 1 ) * $per_page,
		'orderby' => 'comment_date_gmt',
		'order'   => 'DESC',
		'type'    => 'comment', // exclude pingbacks/trackbacks
	);

	$total = (int) get_comments( array_merge( $query, array( 'count' => true, 'number' => 0, 'offset' => 0 ) ) );
	$rows  = get_comments( $query );

	$comments = array();
	foreach ( $rows as $c ) {
		$post_id = (int) $c->comment_post_ID;
		$comments[] = array(
			'id'           => (int) $c->comment_ID,
			'post_id'      => $post_id,
			'post_title'   => $post_id ? html_entity_decode( get_the_title( $post_id ) ) : '',
			'author'       => $c->comment_author,
			'author_email' => $c->comment_author_email,
			'author_url'   => $c->comment_author_url,
			'content'      => wp_trim_words( wp_strip_all_tags( $c->comment_content ), 60, '…' ),
			'date_gmt'     => $c->comment_date_gmt,
			'status'       => wp_get_comment_status( $c ),
			'link'         => get_comment_link( $c ),
		);
	}

	return new WP_REST_Response( array(
		'status'   => $wp_status,
		'page'     => $page,
		'per_page' => $per_page,
		'total'    => $total,
		'comments' => $comments,
	), 200 );
}

/**
 * POST /jarvis/v1/comment
 *
 * Moderate a single comment. JARVIS owns the decision; this executes it via
 * core's own moderation functions and reports the resulting status back.
 */
function jarvis_connector_comment( WP_REST_Request $request ) {
	$comment_id = (int) $request->get_param( 'comment_id' );
	$action     = (string) $request->get_param( 'action' );

	$comment = get_comment( $comment_id );
	if ( ! $comment ) {
		return new WP_Error( 'jarvis_not_found', "Comment $comment_id not found", array( 'status' => 404 ) );
	}

	$ok = false;
	switch ( $action ) {
		case 'approve':
			$ok = wp_set_comment_status( $comment_id, 'approve' );
			break;
		case 'unapprove':
			$ok = wp_set_comment_status( $comment_id, 'hold' );
			break;
		case 'spam':
			$ok = (bool) wp_spam_comment( $comment_id );
			break;
		case 'unspam':
			$ok = (bool) wp_unspam_comment( $comment_id );
			break;
		case 'trash':
			$ok = (bool) wp_trash_comment( $comment_id );
			break;
		case 'untrash':
			$ok = (bool) wp_untrash_comment( $comment_id );
			break;
		case 'delete':
			$ok = (bool) wp_delete_comment( $comment_id, true ); // force = bypass trash
			break;
		default:
			return new WP_Error( 'jarvis_bad_request', "Unknown action '$action'", array( 'status' => 400 ) );
	}

	if ( ! $ok ) {
		return new WP_REST_Response( array(
			'ok' => false, 'status' => 'error', 'comment_id' => $comment_id, 'action' => $action,
			'error' => 'Moderation action failed',
		), 200 );
	}

	$new_status = 'delete' === $action ? 'deleted' : wp_get_comment_status( $comment_id );

	return new WP_REST_Response( array(
		'ok'         => true,
		'comment_id' => $comment_id,
		'action'     => $action,
		'status'     => $new_status,
	), 200 );
}

// ─── REST: plugin management ──────────────────────────────────────────

/** Resolve a plugin_file ("dir/file.php") from a bare slug ("dir"). */
function jarvis_connector_resolve_plugin_file( $slug ) {
	if ( ! function_exists( 'get_plugins' ) ) {
		require_once ABSPATH . 'wp-admin/includes/plugin.php';
	}
	foreach ( array_keys( get_plugins() ) as $file ) {
		if ( dirname( $file ) === $slug || $file === $slug ) {
			return $file;
		}
	}
	return '';
}

/** True if the given plugin_file is THIS connector — we never let JARVIS
 *  deactivate or delete the very plugin that gives it access. */
function jarvis_connector_is_self( $plugin_file ) {
	return $plugin_file && plugin_basename( __FILE__ ) === $plugin_file;
}

/**
 * POST /jarvis/v1/plugin
 *
 * Lifecycle management for installed plugins + installing new ones from
 * wp.org. activate/deactivate/delete take a plugin_file (or resolvable slug);
 * install takes a wp.org slug. Risky directions (activate, install+activate)
 * are health-gated: if the site goes down we auto-deactivate to self-heal and
 * report an error rather than leaving a fatal live.
 */
function jarvis_connector_plugin_manage( WP_REST_Request $request ) {
	$action = (string) $request->get_param( 'action' );

	require_once ABSPATH . 'wp-admin/includes/file.php';
	require_once ABSPATH . 'wp-admin/includes/misc.php';
	require_once ABSPATH . 'wp-admin/includes/plugin.php';
	require_once ABSPATH . 'wp-admin/includes/class-wp-upgrader.php';

	$fail = function ( $msg, $status = 200 ) use ( $action ) {
		return new WP_REST_Response( array( 'ok' => false, 'status' => 'error', 'action' => $action, 'error' => $msg ), $status );
	};

	// ── install (wp.org slug) ──
	if ( 'install' === $action ) {
		$slug = sanitize_key( (string) $request->get_param( 'slug' ) );
		if ( ! $slug ) {
			return $fail( 'slug required for install', 400 );
		}
		require_once ABSPATH . 'wp-admin/includes/plugin-install.php';
		$info = plugins_api( 'plugin_information', array( 'slug' => $slug, 'fields' => array( 'sections' => false ) ) );
		if ( is_wp_error( $info ) || empty( $info->download_link ) ) {
			return $fail( 'Plugin "' . $slug . '" not found on WordPress.org' );
		}
		$skin     = new WP_Ajax_Upgrader_Skin();
		$upgrader = new Plugin_Upgrader( $skin );
		$result   = $upgrader->install( $info->download_link );
		$errors   = $skin->get_errors();
		if ( is_wp_error( $errors ) && $errors->has_errors() ) {
			return $fail( $errors->get_error_message() );
		}
		if ( is_wp_error( $result ) || ! $result ) {
			return $fail( is_wp_error( $result ) ? $result->get_error_message() : 'Install failed' );
		}
		$plugin_file = $upgrader->plugin_info(); // "dir/file.php"
		$activated   = false;
		if ( $plugin_file && $request->get_param( 'activate' ) ) {
			$err = activate_plugin( $plugin_file );
			if ( is_wp_error( $err ) ) {
				return $fail( 'Installed, but activation failed: ' . $err->get_error_message() );
			}
			$health = jarvis_connector_health_after_activation( $plugin_file );
			if ( $health ) {
				return $fail( $health );
			}
			$activated = true;
		}
		wp_clean_plugins_cache( true );
		return new WP_REST_Response( array(
			'ok' => true, 'status' => 'installed', 'action' => $action,
			'slug' => $slug, 'plugin_file' => $plugin_file, 'active' => $activated,
		), 200 );
	}

	// ── activate / deactivate / delete (existing plugin) ──
	$plugin_file = (string) $request->get_param( 'plugin_file' );
	if ( ! $plugin_file ) {
		$plugin_file = jarvis_connector_resolve_plugin_file( (string) $request->get_param( 'slug' ) );
	}
	if ( ! $plugin_file ) {
		return $fail( 'plugin_file or resolvable slug required', 400 );
	}
	if ( jarvis_connector_is_self( $plugin_file ) ) {
		return $fail( 'Refusing to ' . $action . ' the JARVIS connector itself — that would sever access.' );
	}

	if ( 'activate' === $action ) {
		$err = activate_plugin( $plugin_file );
		if ( is_wp_error( $err ) ) {
			return $fail( $err->get_error_message() );
		}
		$health = jarvis_connector_health_after_activation( $plugin_file );
		if ( $health ) {
			return $fail( $health );
		}
		return new WP_REST_Response( array( 'ok' => true, 'status' => 'activated', 'action' => $action, 'plugin_file' => $plugin_file, 'active' => true ), 200 );
	}

	if ( 'deactivate' === $action ) {
		deactivate_plugins( $plugin_file, true ); // silent
		return new WP_REST_Response( array( 'ok' => true, 'status' => 'deactivated', 'action' => $action, 'plugin_file' => $plugin_file, 'active' => false ), 200 );
	}

	if ( 'delete' === $action ) {
		if ( is_plugin_active( $plugin_file ) ) {
			deactivate_plugins( $plugin_file, true );
		}
		$result = delete_plugins( array( $plugin_file ) );
		if ( is_wp_error( $result ) ) {
			return $fail( $result->get_error_message() );
		}
		if ( false === $result || null === $result ) {
			return $fail( 'Delete failed (filesystem not writable?)' );
		}
		wp_clean_plugins_cache( true );
		return new WP_REST_Response( array( 'ok' => true, 'status' => 'deleted', 'action' => $action, 'plugin_file' => $plugin_file ), 200 );
	}

	return $fail( "Unknown action '$action' (expected activate|deactivate|delete|install)", 400 );
}

/**
 * After activating a plugin, confirm the front-end still loads. A fatal in a
 * just-activated plugin would otherwise white-screen the site; if we detect it,
 * deactivate the plugin to self-heal and return the error string. Returns null
 * when healthy.
 */
function jarvis_connector_health_after_activation( $plugin_file ) {
	$res  = wp_remote_get( home_url( '/' ), array( 'timeout' => 15, 'redirection' => 1, 'headers' => array( 'User-Agent' => 'JARVIS-Connector/' . JARVIS_CONNECTOR_VERSION ) ) );
	$code = is_wp_error( $res ) ? 0 : (int) wp_remote_retrieve_response_code( $res );
	// 5xx (or no response) after activation = the new plugin likely fataled.
	if ( is_wp_error( $res ) || $code >= 500 ) {
		deactivate_plugins( $plugin_file, true );
		return 'Activation took the site down (' . ( $code ?: 'no response' ) . ') — reverted (deactivated) to recover.';
	}
	return null;
}

// ─── REST: theme management ───────────────────────────────────────────

/**
 * POST /jarvis/v1/theme — activate (switch to) or delete a theme by stylesheet.
 * The active theme can't be deleted (WP refuses); switching themes is the
 * recoverable analog of plugin activate.
 */
function jarvis_connector_theme_manage( WP_REST_Request $request ) {
	$action = (string) $request->get_param( 'action' );
	$slug   = (string) $request->get_param( 'slug' );
	require_once ABSPATH . 'wp-admin/includes/file.php';
	require_once ABSPATH . 'wp-admin/includes/misc.php';

	$theme = wp_get_theme( $slug );
	if ( ! $theme->exists() ) {
		return new WP_REST_Response( array( 'ok' => false, 'status' => 'error', 'action' => $action, 'error' => "Theme '$slug' not found" ), 200 );
	}

	if ( 'activate' === $action ) {
		switch_theme( $slug );
		$health = jarvis_connector_health_after_activation( '' ); // generic homepage probe
		if ( $health ) {
			return new WP_REST_Response( array( 'ok' => false, 'status' => 'error', 'action' => $action, 'error' => $health ), 200 );
		}
		return new WP_REST_Response( array( 'ok' => true, 'status' => 'activated', 'action' => $action, 'slug' => $slug ), 200 );
	}

	if ( 'delete' === $action ) {
		if ( get_stylesheet() === $slug || get_template() === $slug ) {
			return new WP_REST_Response( array( 'ok' => false, 'status' => 'error', 'action' => $action, 'error' => 'Cannot delete the active theme.' ), 200 );
		}
		$result = delete_theme( $slug );
		if ( is_wp_error( $result ) || ! $result ) {
			return new WP_REST_Response( array( 'ok' => false, 'status' => 'error', 'action' => $action, 'error' => is_wp_error( $result ) ? $result->get_error_message() : 'Delete failed' ), 200 );
		}
		return new WP_REST_Response( array( 'ok' => true, 'status' => 'deleted', 'action' => $action, 'slug' => $slug ), 200 );
	}

	return new WP_REST_Response( array( 'ok' => false, 'status' => 'error', 'action' => $action, 'error' => "Unknown action '$action' (expected activate|delete)" ), 200 );
}

// ─── REST: core file integrity ────────────────────────────────────────

/**
 * GET /jarvis/v1/integrity — verify core files against the official wp.org
 * checksums for this exact version + locale. Surfaces MODIFIED or MISSING core
 * files (a strong "is this site tampered with?" signal). On-demand (hashes
 * every core file), not part of /state.
 */
function jarvis_connector_integrity() {
	require_once ABSPATH . 'wp-admin/includes/update.php';
	global $wp_version, $wp_local_package;
	$locale    = isset( $wp_local_package ) ? $wp_local_package : 'en_US';
	$checksums = get_core_checksums( $wp_version, $locale );
	if ( ! is_array( $checksums ) ) {
		// Some locales only have en_US checksums — retry once.
		$checksums = get_core_checksums( $wp_version, 'en_US' );
	}
	if ( ! is_array( $checksums ) ) {
		return new WP_REST_Response( array( 'ok' => false, 'available' => false, 'error' => 'Checksums unavailable for ' . $wp_version ), 200 );
	}

	$modified = array();
	$missing  = array();
	foreach ( $checksums as $file => $expected ) {
		// wp-content is user/site territory (themes, plugins, uploads) — only
		// verify actual core files.
		if ( 0 === strpos( $file, 'wp-content/' ) ) {
			continue;
		}
		$path = ABSPATH . $file;
		if ( ! file_exists( $path ) ) {
			$missing[] = $file;
			continue;
		}
		if ( md5_file( $path ) !== $expected ) {
			$modified[] = $file;
		}
	}

	return new WP_REST_Response( array(
		'ok'           => true,
		'available'    => true,
		'wp_version'   => $wp_version,
		'modified'     => array_values( $modified ),
		'missing'      => array_values( $missing ),
		'clean'        => empty( $modified ) && empty( $missing ),
		'checked_at'   => gmdate( 'c' ),
	), 200 );
}

// ─── Self-update from GitHub Releases ─────────────────────────────────
//
// Lets the connector upgrade itself in place through WordPress's normal
// plugin-update machinery: we inject our own "update available" entry when a
// newer release exists on GitHub, and hand WP the release zip to install.
// JARVIS's existing /update flow (or a one-click in wp-admin) then applies it —
// so after the first install the zip never has to be re-uploaded by hand.
//
// The GitHub API call is cached for 6h so update checks don't hammer the
// unauthenticated rate limit (60/hr per IP). Only relevant for regular-plugin
// installs; must-use plugins don't run through the update transient.

/** Fetch + cache the latest GitHub release. Returns ['version','zip'] or null. */
function jarvis_connector_latest_release( $force = false ) {
	$cache_key = 'jarvis_connector_latest_release';
	if ( ! $force ) {
		$cached = get_site_transient( $cache_key );
		if ( false !== $cached ) {
			return is_array( $cached ) ? $cached : null;
		}
	}

	$url = 'https://api.github.com/repos/' . JARVIS_CONNECTOR_REPO . '/releases/latest';
	$res = wp_remote_get( $url, array(
		'timeout' => 10,
		'headers' => array(
			'Accept'     => 'application/vnd.github+json',
			'User-Agent' => 'JARVIS-Connector/' . JARVIS_CONNECTOR_VERSION,
		),
	) );

	$result = null;
	if ( ! is_wp_error( $res ) && 200 === (int) wp_remote_retrieve_response_code( $res ) ) {
		$body = json_decode( wp_remote_retrieve_body( $res ), true );
		if ( is_array( $body ) && ! empty( $body['tag_name'] ) ) {
			$version = ltrim( (string) $body['tag_name'], 'vV' );
			$zip     = '';
			foreach ( (array) ( $body['assets'] ?? array() ) as $asset ) {
				if ( isset( $asset['name'], $asset['browser_download_url'] ) && JARVIS_CONNECTOR_ASSET === $asset['name'] ) {
					$zip = (string) $asset['browser_download_url'];
					break;
				}
			}
			// Fall back to the auto-generated source zip if no named asset.
			if ( ! $zip && ! empty( $body['zipball_url'] ) ) {
				$zip = (string) $body['zipball_url'];
			}
			if ( $zip ) {
				$result = array( 'version' => $version, 'zip' => $zip );
			}
		}
	}

	// Cache success for 6h; cache a miss for 1h so a transient GitHub hiccup
	// doesn't suppress checks for long.
	set_site_transient( $cache_key, $result ? $result : array( 'miss' => true ), $result ? 6 * HOUR_IN_SECONDS : HOUR_IN_SECONDS );
	return $result;
}

/** Inject an update entry into the plugins transient when GitHub has a newer
 *  release than what's installed. */
function jarvis_connector_check_update( $transient ) {
	if ( ! is_object( $transient ) ) {
		return $transient;
	}
	$latest = jarvis_connector_latest_release();
	if ( ! $latest || empty( $latest['version'] ) ) {
		return $transient;
	}

	$basename = plugin_basename( __FILE__ );
	if ( version_compare( $latest['version'], JARVIS_CONNECTOR_VERSION, '>' ) ) {
		$update = (object) array(
			'slug'        => dirname( $basename ),
			'plugin'      => $basename,
			'new_version' => $latest['version'],
			'package'     => $latest['zip'],
			'url'         => 'https://github.com/' . JARVIS_CONNECTOR_REPO,
		);
		$transient->response[ $basename ] = $update;
		unset( $transient->no_update[ $basename ] );
	} else {
		// Current — record under no_update so WP shows it as up to date.
		$transient->no_update[ $basename ] = (object) array(
			'slug'        => dirname( $basename ),
			'plugin'      => $basename,
			'new_version' => JARVIS_CONNECTOR_VERSION,
			'package'     => '',
			'url'         => 'https://github.com/' . JARVIS_CONNECTOR_REPO,
		);
	}
	return $transient;
}
add_filter( 'pre_set_site_transient_update_plugins', 'jarvis_connector_check_update' );

/** Provide the "View details" payload so the plugins screen doesn't 404 when a
 *  user clicks through to the connector's update info. */
function jarvis_connector_plugins_api( $result, $action, $args ) {
	if ( 'plugin_information' !== $action || empty( $args->slug ) ) {
		return $result;
	}
	if ( dirname( plugin_basename( __FILE__ ) ) !== $args->slug ) {
		return $result;
	}
	$latest = jarvis_connector_latest_release();
	$version = ( $latest && ! empty( $latest['version'] ) ) ? $latest['version'] : JARVIS_CONNECTOR_VERSION;
	return (object) array(
		'name'          => 'JARVIS Connector',
		'slug'          => $args->slug,
		'version'       => $version,
		'author'        => 'JARVIS',
		'homepage'      => 'https://github.com/' . JARVIS_CONNECTOR_REPO,
		'download_link' => ( $latest && ! empty( $latest['zip'] ) ) ? $latest['zip'] : '',
		'sections'      => array(
			'description' => 'Secured REST endpoints so JARVIS can read update state, apply updates, and moderate comments.',
		),
	);
}
add_filter( 'plugins_api', 'jarvis_connector_plugins_api', 10, 3 );

/** After WP installs the GitHub zip, its folder may be named after the repo/tag
 *  (e.g. jarvis-wordpress-connector-1.4.0) instead of "jarvis-connector". Rename
 *  it back so the plugin path stays stable and WP reactivates the right file. */
function jarvis_connector_fix_update_folder( $source, $remote_source, $upgrader, $hook_extra = array() ) {
	if ( empty( $hook_extra['plugin'] ) || plugin_basename( __FILE__ ) !== $hook_extra['plugin'] ) {
		return $source;
	}
	global $wp_filesystem;
	$desired = trailingslashit( $remote_source ) . 'jarvis-connector';
	if ( $source === $desired ) {
		return $source;
	}
	if ( $wp_filesystem && $wp_filesystem->move( $source, $desired, true ) ) {
		return trailingslashit( $desired );
	}
	return $source;
}
add_filter( 'upgrader_source_selection', 'jarvis_connector_fix_update_folder', 10, 4 );
