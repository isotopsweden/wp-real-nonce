<?php

namespace Isotop;

class Wp_Real_Nonce {

	const NONCE_TABLE_NAME = 'real_nonces';

	/**
	 * @var Wp_Real_Nonce
	 */
	protected static $instance;

	/**
	 * @var array
	 */
	protected static $verified_nonces = [];

	/**
	 * Wp_Real_Nonce constructor.
	 */
	public function __construct() {
		$this->create_nonce_table();

		add_action( 'plugins_loaded', [ $this, 'add_job' ] );
		add_action( 'shutdown', [ $this, 'delete_verified_nonces' ] );
		add_action( 'real_nonce_flush_old', [ $this, 'delete_old_nonces' ] );
	}

	/**
	 * @return Wp_Real_Nonce
	 */
	public static function instance() {
		if ( ! isset( static::$instance ) ) {
			static::$instance = new static;
		}

		return static::$instance;
	}

	/**
	 * Creates a cryptographic token tied to a specific action, user, user session,
	 * and window of time.
	 *
	 * @param string|int $action Scalar value to add context to the nonce.
	 *
	 * @return string The token.
	 */
	public static function create_nonce( $action = - 1 ) {
		$tick  = wp_nonce_tick();
		$nonce = static::generate_nonce( $action, $tick );
		static::save_nonce( $nonce, $tick );

		return $nonce;
	}

	/**
	 * Verify that correct nonce was used with time limit.
	 *
	 * The user is given an amount of time to use the token, so therefore, since the
	 * UID and $action remain the same, the independent variable is the time.
	 *
	 * @param string     $nonce  Nonce that was used in the form to verify
	 * @param string|int $action Should give context to what is taking place and be the same when nonce was created.
	 *
	 * @return false|int False if the nonce is invalid, 1 if the nonce is valid and generated between
	 *                   0-12 hours ago, 2 if the nonce is valid and generated between 12-24 hours ago.
	 */
	public static function verify_nonce( $nonce, $action = - 1 ) {
		$return = false;

		$nonce = (string) $nonce;

		$current_tick = wp_nonce_tick();

		$expected = static::generate_nonce( $action, $current_tick );

		if ( hash_equals( $expected, $nonce ) && static::nonce_exists( $nonce ) ) {
			$return = 1;
		}

		$expected = static::generate_nonce( $action, $current_tick - 1 );
		if ( hash_equals( $expected, $nonce ) && static::nonce_exists( $nonce ) ) {
			$return = 2;
		}

		if ( $return ) {
			if ( ! in_array( static::$verified_nonces ) ) {
				static::$verified_nonces[] = $nonce;
			}
		} else {
			$user  = wp_get_current_user();
			$token = wp_get_session_token();

			/**
			 * Fires when nonce verification fails.
			 *
			 * @since 4.4.0
			 *
			 * @param string     $nonce  The invalid nonce.
			 * @param string|int $action The nonce action.
			 * @param WP_User    $user   The current user object.
			 * @param string     $token  The user's session token.
			 */
			do_action( 'wp_verify_nonce_failed', $nonce, $action, $user, $token );
		}

		return $return;
	}

	/**
	 * Generate nonce
	 *
	 * @param string|int $action The nonce action.
	 * @param int        $tick   Nonce lifespan
	 *
	 * @return string The token.
	 */
	protected static function generate_nonce( $action = - 1, $tick = 0 ) {
		$user = wp_get_current_user();
		$uid  = (int) $user->ID;
		if ( ! $uid ) {
			/** This filter is documented in wp-includes/pluggable.php */
			$uid = apply_filters( 'nonce_user_logged_out', $uid, $action );
		}

		$token = wp_get_session_token();

		return substr( wp_hash( $tick . '|' . $action . '|' . $uid . '|' . $token, 'nonce' ), - 12, 10 );
	}

	/**
	 * Save the nonce to databse
	 *
	 * @param string $nonce The token
	 * @param int    $tick  Nonce lifespan
	 */
	protected static function save_nonce( $nonce, $tick ) {
		global $wpdb;
		$tablename = $wpdb->prefix . static::NONCE_TABLE_NAME;

		$wpdb->query(
			$wpdb->prepare(
				"INSERT IGNORE INTO `${tablename}` (`id`, `tick`) VALUES (%s, %d)",
				$nonce,
				$tick
			)
		);
	}

	/**
	 * Check if nonce exists in database
	 *
	 * @param string $nonce The token
	 *
	 * @return bool
	 */
	protected static function nonce_exists( $nonce ) {
		global $wpdb;

		$tablename = $wpdb->prefix . static::NONCE_TABLE_NAME;
		$result    = $wpdb->get_var(
			$wpdb->prepare(
				"SELECT `id` FROM `${tablename}` WHERE `id` = %s LIMIT 1;",
				$nonce
			)
		);

		return (bool) $result;
	}

	/**
	 * Delete old nonces
	 */
	public function delete_old_nonces() {
		global $wpdb;
		$tablename = $wpdb->prefix . static::NONCE_TABLE_NAME;

		$current_tick = wp_nonce_tick();
		$old_tick     = $current_tick - 2;

		$wpdb->query(
			$wpdb->prepare(
				"DELETE FROM `${tablename}` WHERE `tick` <= %d;",
				$old_tick
			)
		);
	}

	/**
	 * Add cronjob to remove old nonces
	 */
	public function add_job() {
		if ( ! wp_next_scheduled( 'real_nonce_flush_old' ) ) {
			wp_schedule_event( time(), 'twicedaily', 'real_nonce_flush_old' );
		}
	}

	/**
	 * Delete used nonces
	 */
	public function delete_verified_nonces() {
		if ( ! empty( static::$verified_nonces ) ) {
			global $wpdb;
			$tablename = $wpdb->prefix . static::NONCE_TABLE_NAME;

			foreach ( static::$verified_nonces as $nonce ) {
				$wpdb->delete(
					$tablename,
					[
						'id' => $nonce
					]
				);
			}
		}
	}

	/**
	 * Create nonce db table
	 */
	protected function create_nonce_table() {
		$table_version     = 1;
		$installed_version = intval( get_option( '_real_nonce_table_version', 0 ) );

		if ( $installed_version !== $table_version ) {
			global $wpdb;

			$sql = sprintf(
				'CREATE TABLE `%1$s` (
				  `id` VARCHAR(191) NOT NULL DEFAULT \'\',
				  `tick` INT(11) UNSIGNED NOT NULL,
				  PRIMARY KEY (`id`)
				) %2$s;',
				$wpdb->prefix . static::NONCE_TABLE_NAME,
				$wpdb->get_charset_collate()
			);

			require_once ABSPATH . 'wp-admin/includes/upgrade.php';
			dbDelta( $sql );

			update_option( '_real_nonce_table_version', $table_version );
		}
	}
}

Wp_Real_Nonce::instance();