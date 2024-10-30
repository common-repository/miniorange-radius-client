<?php
/**
 * Copyright (c) 2002-2010, Michael Bretterklieber <michael@bretterklieber.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The names of the authors may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE,
 * EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This code cannot simply be copied and put under the GNU Public License or
 * any other GPL-like (LGPL, GPL2) License.
 *
 *   $Id: CHAP.php 302857 2010-08-28 21:12:59Z mbretter $
 *
 * This version of CHAP.php has been modified by Drew Phillips for dapphp/radius.
 * Modifications remove the PEAR dependency, change from PHP4 OOP to PHP5, and
 * mcrypt functions have been replaced with openssl_* functions.
 *
 * Changes are all commented inline throughout the source.
 *
 *   $Id: class-crypt-chap.php 2.5.2 2018-01-25  03:30:29Z dapphp $
 *
 * @package miniorange-radius-client/includes/lib
 */

/**
 * Classes for generating packets for various CHAP Protocols:
 * CHAP-MD5: RFC1994
 * MS-CHAPv1: RFC2433
 * MS-CHAPv2: RFC2759
 *
 * @package Crypt_CHAP
 * @author  Michael Bretterklieber <michael@bretterklieber.com>
 * @access  public
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

if ( ! class_exists( 'Crypt_CHAP' ) ) {
	/**
	 * Class Crypt_CHAP
	 *
	 * Abstract base class for CHAP
	 *
	 * @package Crypt_CHAP
	 */
	class Crypt_CHAP /*extends PEAR // removed for dapphp/radius */ {

		/**
		 * Random binary challenge
		 *
		 * @var  string
		 */
		public $challenge = null;

		/**
		 * Binary response
		 *
		 * @var  string
		 */
		public $response = null;

		/**
		 * User password
		 *
		 * @var  string
		 */
		public $password = null;

		/**
		 * Id of the authentication request. Should incremented after every request.
		 *
		 * @var  integer
		 */
		public $chapid = 1;

		/**
		 * Constructor
		 *
		 * Generates a random challenge
		 *
		 * @return void
		 */
		public function __construct() {
			$this->generate_challenge();
		}

		/**
		 * Generates a random binary challenge
		 *
		 * @param  string  $varname  Name of the property.
		 * @param  integer $size     Size of the challenge in Bytes.
		 * @return string
		 */
		public function generate_challenge( $varname = 'challenge', $size = 8 ) {
			$this->$varname = '';
			for ( $i = 0; $i < $size; $i++ ) {
				$this->$varname .= pack( 'C', 1 + wp_rand() % 255 );
			}
			return $this->$varname;
		}

		/**
		 * Generates the response. Overwrite this.
		 *
		 * @return void
		 */
		public function challenge_response() {   }

	}
}
