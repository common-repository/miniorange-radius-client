<?php
/** Contains database functions
 *
 * @package         miniOrange Radius Client
 * @license     http://www.gnu.org/copyleft/gpl.html GNU/GPL, see LICENSE.php
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}
if ( ! class_exists( 'Mo_Rad_Database' ) ) {
	/**
	 * This library is miniOrange Authentication Service.
	 * Contains Request Calls to Customer service.
	 **/
	class Mo_Rad_Database {
		/**
		 * Create session
		 *
		 * @return string
		 */
		public function create_session() {
			$session_id = self::random_str( 20 );
			$this->insert_user_login_session( $session_id );
			$key                = get_site_option( 'mo2f_encryption_key' );
			$session_id_encrypt = self::encrypt_data( $session_id, $key );
			return $session_id_encrypt;
		}
		/**
		 * Geneerate random string
		 *
		 * @param int    $length - length of the string.
		 * @param string $keyspace - set of characters.
		 * @return string
		 */
		public function random_str( $length, $keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ' ) {
			$random_string     = '';
			$characters_length = strlen( $keyspace );
			for ( $i = 0; $i < $length; $i++ ) {
				$random_string .= $keyspace[ wp_rand( 0, $characters_length - 1 ) ];
			}
			return $random_string;

		}

		/**
		 * Insert user session
		 *
		 * @param [type] $session_id - encrypted session id.
		 * @return void
		 */
		public function insert_user_login_session( $session_id ) {
			$user = wp_get_current_user();
			add_user_meta( $user->ID, 'mo2f_session_id', $session_id );
		}
		/**
		 * Set transient value
		 *
		 * @param string  $session_id - encrypted session id.
		 * @param string  $key - key value.
		 * @param string  $value - value.
		 * @param integer $expiration - expiration time.
		 * @return void
		 */
		public static function mo_rad_set_transient( $session_id, $key, $value, $expiration = 300 ) {
			set_transient( $session_id . $key, $value, $expiration );
			$transient_array         = get_site_option( $session_id );
			$transient_array[ $key ] = $value;
			update_site_option( $session_id, $transient_array );
		}
		/**
		 * Get transient value
		 *
		 * @param string $session_id - encrypted session id.
		 * @param string $key - key value.
		 * @return string|boolean
		 */
		public static function mo_rad_get_transient( $session_id, $key ) {
				$transient_value = get_transient( $session_id . $key );
			if ( ! $transient_value ) {
				$transient_array = get_site_option( $session_id );
				$transient_value = isset( $transient_array[ $key ] ) ? $transient_array[ $key ] : null;
			}
			return $transient_value;

		}
		/**
		 * It will help to encrypt the data in aes
		 *
		 * @param string $data It will pass the data of the value .
		 * @param string $key  It will pass the key of the value .
		 * @return string .
		 */
		public static function encrypt_data( $data, $key ) {
			$plaintext      = $data;
			$cipher         = 'AES-128-CBC';
			$ivlen          = openssl_cipher_iv_length( $cipher );
			$iv             = openssl_random_pseudo_bytes( $ivlen );
			$ciphertext_raw = openssl_encrypt( $plaintext, $cipher, $key, $options = OPENSSL_RAW_DATA, $iv );
			$hmac           = hash_hmac( 'sha256', $ciphertext_raw, $key, $as_binary = true );
			$ciphertext     = base64_encode( $iv . $hmac . $ciphertext_raw ); //phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_encode -- Not using for obfuscation
			return $ciphertext;
		}

		/**
		 * It will unset the session value
		 *
		 * @param object $variables .
		 * @return void
		 */
		public static function unset_session_variables( $variables ) {
			if ( 'array' === gettype( $variables ) ) {
				foreach ( $variables as $variable ) {
					if ( isset( $_SESSION[ $variable ] ) ) {
						unset( $_SESSION[ $variable ] );
					}
				}
			} else {
				if ( isset( $_SESSION[ $variables ] ) ) {
					unset( $_SESSION[ $variables ] );
				}
			}
		}

		/*
		Returns Random string with length provided in parameter.

		*/
		/**
		 * This function will help to decrypt the data .
		 *
		 * @param string $data It will carry the data .
		 * @param string $key It will carry the key .
		 * @return string
		 */
		public static function decrypt_data( $data, $key ) {
			$c                  = base64_decode( $data ); //phpcs:ignore WordPress.PHP.DiscouragedPHPFunctions.obfuscation_base64_decode -- Not using for obfuscation
			$cipher             = 'AES-128-CBC';
			$ivlen              = openssl_cipher_iv_length( $cipher );
			$iv                 = substr( $c, 0, $ivlen );
			$hmac               = substr( $c, $ivlen, $sha2len = 32 );
			$ciphertext_raw     = substr( $c, $ivlen + $sha2len );
			$original_plaintext = openssl_decrypt( $ciphertext_raw, $cipher, $key, $options = OPENSSL_RAW_DATA, $iv );
			$calcmac            = hash_hmac( 'sha256', $ciphertext_raw, $key, $as_binary = true );
			$decrypted_text     = '';
			if ( is_string( $hmac ) && is_string( $calcmac ) ) {
				if ( hash_equals( $hmac, $calcmac ) ) {
					$decrypted_text = $original_plaintext;
				}
			}

			return $decrypted_text;
		}


	}
}
