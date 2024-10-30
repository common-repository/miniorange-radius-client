<?php
/**
 * PSR-4 compatibility with class-crypt-chap.php
 *
 * @package miniorange-radius-client/includes/lib/Crypt/CHAP
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

if ( class_exists( 'Crypt_CHAP_MD5' ) ) {
	/**
	 * Class Crypt_CHAP_MD5
	 */
	class Crypt_CHAP_MD5 extends Crypt_CHAP {

		/**
		 * Generates the response.
		 *
		 * CHAP-MD5 uses MD5-Hash for generating the response. The Hash consists
		 * of the chapid, the plaintext password and the challenge.
		 *
		 * @return string
		 */
		public function challenge_response() {
			return pack( 'H*', md5( pack( 'C', $this->chapid ) . $this->password . $this->challenge ) );
		}
	}
}

/**
 * Including file class-crypt-chap.php
 */
require_once __DIR__ . '/../../class-crypt-chap.php';
