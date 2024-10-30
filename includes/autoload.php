<?php
/**
 * Autoload register function
 *
 * @package miniorange-radius-client/includes/src
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

spl_autoload_register(
	function( $class ) {
		$parts = explode( '\\', $class );
		if ( count( $parts ) === 1 ) {
			switch ( $class ) {
				case 'Crypt_CHAP':
				case 'Crypt_CHAP_MD5':
				case 'Crypt_CHAP_MSv1':
				case 'Crypt_CHAP_MSv2':
					require __DIR__ . '/lib/class-crypt-chap.php';
					break;
			}
		} elseif ( count( $parts ) > 2 ) {
			if ( 'Dapphp' === $parts[0] && 'Radius' === $parts[1] ) {
				if ( 'Radius' === $parts[2] ) {
					require_once __DIR__ . '/src/class-' . strtolower( $parts[2] ) . '.php';
				}
			}
		}
	}
);
