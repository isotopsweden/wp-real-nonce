<?php
use Isotop\Wp_Real_Nonce;

if ( ! function_exists( 'wp_verify_nonce' ) ) :
	/**
	 * Verify that correct nonce was used with time limit.
	 *
	 * The user is given an amount of time to use the token, so therefore, since the
	 * UID and $action remain the same, the independent variable is the time.
	 *
	 * @since 2.0.3
	 *
	 * @param string     $nonce  Nonce that was used in the form to verify
	 * @param string|int $action Should give context to what is taking place and be the same when nonce was created.
	 *
	 * @return false|int False if the nonce is invalid, 1 if the nonce is valid and generated between
	 *                   0-12 hours ago, 2 if the nonce is valid and generated between 12-24 hours ago.
	 */
	function wp_verify_nonce( $nonce, $action = - 1 ) {
		return Wp_Real_Nonce::verify_nonce( $nonce, $action );
	}
endif;

if ( ! function_exists( 'wp_create_nonce' ) ) :
	/**
	 * Creates a cryptographic token tied to a specific action, user, user session,
	 * and window of time.
	 *
	 * @since 2.0.3
	 * @since 4.0.0 Session tokens were integrated with nonce creation
	 *
	 * @param string|int $action Scalar value to add context to the nonce.
	 *
	 * @return string The token.
	 */
	function wp_create_nonce( $action = - 1 ) {
		return Wp_Real_Nonce::create_nonce( $action );
	}
endif;