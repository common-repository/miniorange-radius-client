<?php
/**
 * PSR-4 compatibility with class-crypt-chap.php
 *
 * @package miniorange-radius-client/includes/lib/Crypt/CHAP
 */

/**
 * Class Crypt_CHAP_MSv2
 *
 * Generate MS-CHAPv2 Packets. This version of MS-CHAP uses a 16 Bytes authenticator
 * challenge and a 16 Bytes peer Challenge. LAN-Manager responses no longer exists
 * in this version. The challenge is already a SHA1 challenge hash of both challenges
 * and of the username.
 *
 * @package Crypt_CHAP
 */
class Crypt_CHAP_MSv2 extends Crypt_CHAP_MSv1 {

	/**
	 * The username
	 *
	 * @var  string
	 */
	public $username = null;

	/**
	 * The 16 Bytes random binary peer challenge
	 *
	 * @var  string
	 */
	public $peer_challenge = null;

	/**
	 * The 16 Bytes random binary authenticator challenge
	 *
	 * @var  string
	 */
	public $auth_challenge = null;

	/**
	 * Constructor
	 *
	 * Generates the 16 Bytes peer and authentication challenge
	 *
	 * @return void
	 */
	public function __construct() {
		parent::__construct();
		$this->generate_challenge( 'peer_challenge', 16 );
		$this->generate_challenge( 'auth_challenge', 16 );
	}

	/**
	 * Generates a hash from the NT-HASH.
	 *
	 * @access public
	 * @param  string $nthash The NT-HASH.
	 * @return string
	 */
	public function ntPasswordHashHash( $nthash ) {
		return pack( 'H*', hash( 'md4', $nthash ) );
	}

	/**
	 * Generates the challenge hash from the peer and the authenticator challenge and
	 * the username. SHA1 is used for this, but only the first 8 Bytes are used.
	 *
	 * @access public
	 * @return string
	 */
	public function challenge_hash() {
		return substr( pack( 'H*', hash( 'sha1', $this->peer_challenge . $this->auth_challenge . $this->username ) ), 0, 8 );
	}

	/**
	 * Generates the response.
	 *
	 * @access public
	 * @return string
	 */
	public function challenge_response() {
		$this->challenge = $this->challenge_hash();
		return $this->challenge_response();
	}
}

/**
 * Including file class-crypt-chap.php
 */
require_once __DIR__ . '/../../class-crypt-chap.php';
