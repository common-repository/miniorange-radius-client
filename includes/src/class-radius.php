<?php
/**
 * Contains calls regarding RADIUS
 *
 * @package miniorange-radius-client/includes/src
 */

/*********************************************************************
 *
 * Pure PHP radius class
 *
 * This Radius class is a radius client implementation in pure PHP
 * following the RFC 2865 rules (http://www.ietf.org/rfc/rfc2865.txt)
 *
 * This class works with at least the following RADIUS servers:
 *  - Authenex Strong Authentication System (ASAS) with two-factor authentication
 *  - FreeRADIUS, a free Radius server implementation for Linux and *nix environments
 *  - Microsoft Radius server IAS
 *  - Microsoft Windows Server 2016 (Network Policy Server)
 *  - Microsoft Windows Server 2012 R2 (Network Policy Server)
 *  - Mideye RADIUS server (http://www.mideye.com)
 *  - Radl, a free Radius server for Windows
 *  - RSA SecurID
 *  - VASCO Middleware 3.0 server
 *  - WinRadius, Windows Radius server (free for 5 users)
 *  - ZyXEL ZyWALL OTP (Authenex ASAS branded by ZyXEL, cheaper)
 *
 *
 * LICENCE
 *
 *   Copyright (c) 2008, SysCo systemes de communication sa
 *   SysCo (tm) is a trademark of SysCo systemes de communication sa
 *   (http://www.sysco.ch/)
 *   All rights reserved.
 *
 *   Copyright (c) 2016, Drew Phillips
 *   (https://drew-phillips.com)
 *
 *   This file is part of the Pure PHP radius class
 *
 *   Pure PHP radius class is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public License as
 *   published by the Free Software Foundation, either version 3 of the License,
 *   or (at your option) any later version.
 *
 *   Pure PHP radius class is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Lesser General Public License for more details.
 *
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with Pure PHP radius class.
 *   If not, see <http://www.gnu.org/licenses/>.
 *
 * @author: SysCo/al
 * @author: Drew Phillips <drew@drew-phillips.com>
 * @since CreationDate: 2008-01-04
 * @copyright (c) 2016 by Drew Phillips
 * @version 2.5.1
 * @link http://developer.sysco.ch/php/
 * @link developer@sysco.ch
 * @link https://github.com/dapphp/radius
 * @link drew@drew-phillips.com
 */
namespace Dapphp\Radius;

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

if ( ! class_exists( 'Radius' ) ) {

	/**
	 * A pure PHP RADIUS client implementation.
	 *
	 * Originally created by SysCo/al based on radius.class.php v1.2.2
	 * Modified for PHP5 & PHP7 compatibility by Drew Phillips
	 * Switched from using ext/sockets to streams.
	 */
	class Radius {
		/**
		 * Access-Request packet type identifier
		 */
		const TYPE_ACCESS_REQUEST = 1;
		/**
		 * Access-Accept packet type identifier
		 */
		const TYPE_ACCESS_ACCEPT = 2;
		/**
		 * Access-Reject packet type identifier
		 */
		const TYPE_ACCESS_REJECT = 3;
		/**
		 * Accounting-Request packet type identifier
		 */
		const TYPE_ACCOUNTING_REQUEST  = 4;
		const TYPE_ACCOUNTING_RESPONSE = 5;
		/**
		 * Accounting-Response packet type identifier
		 */
		/**
		 * Access-Challenge packet type identifier
		 */
		const TYPE_ACCESS_CHALLENGE = 11;
		/**
		 * Reserved packet type
		 */
		const TYPE_RESERVED = 255;
		/**
		 * RADIUS server hostname or IP address
		 *
		 * @var string
		 */
		protected $server;
		/**
		 * Shared secret with the RADIUS server
		 *
		 * @var string
		 */
		protected $secret;
		/**
		 * RADIUS suffix (default is '')
		 *
		 * @var string
		 */
		protected $suffix;
		/**
		 * Timeout for receiving UDP response packets (default = 5 seconds)
		 *
		 * @var int
		 */
		protected $timeout;
		/**
		 * Authentication port (default = 1812)
		 *
		 * @var int
		 */
		protected $authenticationPort; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.PropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.	
		/**
		 * Accounting port (default = 1813)
		 *
		 * @var int
		 */
		protected $accountingPort; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.PropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.	
		/**
		 * Network Access Server (client) IP Address
		 *
		 * @var string
		 */
		protected $nasIpAddress; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.PropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
		/**
		 * NAS port. Physical port of the NAS authenticating the user
		 *
		 * @var string
		 */
		protected $nasPort; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.PropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.	
		/**
		 * Encrypted password, as described in RFC 2865
		 *
		 * @var string
		 */
		protected $encryptedPassword; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.PropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.	
		/**
		 * Request-Authenticator, 16 octets random number
		 *
		 * @var int
		 */
		protected $requestAuthenticator; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.PropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
		/**
		 * Request-Authenticator from the response
		 *
		 * @var int
		 */
		protected $responseAuthenticator; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.PropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
		/**
		 * Username to send to the RADIUS server
		 *
		 * @var string
		 */
		protected $username;
		/**
		 * Password for authenticating with the RADIUS server (before encryption)
		 *
		 * @var string
		 */
		protected $password;
		/**
		 * The CHAP identifier for CHAP-Password attributes
		 *
		 * @var int
		 */
		protected $chapIdentifier; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.PropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
		/**
		 * Identifier field for the packet to be sent
		 *
		 * @var string
		 */
		protected $identifierToSend; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.PropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
		/**
		 * Identifier field for the received packet
		 *
		 * @var string
		 */
		protected $identifierReceived; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.PropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
		/**
		 * RADIUS packet type (1=Access-Request, 2=Access-Accept, etc)
		 *
		 * @var int
		 */
		protected $radiusPacket; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.PropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
		/**
		 * Packet type received in response from RADIUS server
		 *
		 * @var int
		 */
		protected $radiusPacketReceived; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.PropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
		/**
		 * List of RADIUS attributes to send
		 *
		 * @var array
		 */
		protected $attributesToSend; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.PropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
		/**
		 * List of attributes received in response
		 *
		 * @var array
		 */
		protected $attributesReceived; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.PropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
		/**
		 * Whether or not to enable debug output
		 *
		 * @var bool
		 */
		protected $debug;
		/**
		 * RADIUS attributes info array
		 *
		 * @var array
		 */
		protected $attributesInfo; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.PropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
		/**
		 * RADIUS packet codes info array
		 *
		 * @var array
		 */
		protected $radiusPackets; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.PropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
		/**
		 * The error code from the last operation
		 *
		 * @var int
		 */
		protected $errorCode; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.PropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
		/**
		 * The error message from the last operation
		 *
		 * @var string
		 */
		protected $errorMessage; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.PropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.

		/**
		 * Radius constructor.
		 *
		 * @param string $radius_host          The RADIUS server hostname or IP address.
		 * @param string $shared_secret        The RADIUS server shared secret.
		 * @param string $radius_suffix        The username suffix to use when authenticating.
		 * @param number $timeout             The timeout (in seconds) to wait for RADIUS responses.
		 * @param number $authentication_port  The port for authentication requests (default = 1812).
		 * @param number $accounting_port      The port for accounting requests (default = 1813).
		 */
		public function __construct(
		$radius_host = '127.0.0.1',
		$shared_secret = '',
		$radius_suffix = '',
		$timeout = 5,
		$authentication_port = 1812,
		$accounting_port = 1813
		) {
			$this->radiusPackets      = array();// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->radiusPackets[1]   = 'Access-Request'; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->radiusPackets[2]   = 'Access-Accept'; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->radiusPackets[3]   = 'Access-Reject'; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->radiusPackets[4]   = 'Accounting-Request'; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->radiusPackets[5]   = 'Accounting-Response'; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->radiusPackets[11]  = 'Access-Challenge'; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->radiusPackets[12]  = 'Status-Server (experimental)'; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->radiusPackets[13]  = 'Status-Client (experimental)'; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->radiusPackets[255] = 'Reserved'; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo     = array(); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[1]  = array( 'User-Name', 'S' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[2]  = array( 'User-Password', 'S' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[3]  = array( 'CHAP-Password', 'S' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.// Type (1) / Length (1) / CHAP Ident (1) / String.
			$this->attributesInfo[4]  = array( 'NAS-IP-Address', 'A' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[5]  = array( 'NAS-Port', 'I' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[6]  = array( 'Service-Type', 'I' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[7]  = array( 'Framed-Protocol', 'I' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[8]  = array( 'Framed-IP-Address', 'A' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[9]  = array( 'Framed-IP-Netmask', 'A' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[10] = array( 'Framed-Routing', 'I' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[11] = array( 'Filter-Id', 'T' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[12] = array( 'Framed-MTU', 'I' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[13] = array( 'Framed-Compression', 'I' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[14] = array( 'Login-IP-Host', 'A' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[15] = array( 'Login-service', 'I' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[16] = array( 'Login-TCP-Port', 'I' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[17] = array( '(unassigned)', '' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[18] = array( 'Reply-Message', 'T' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[19] = array( 'Callback-Number', 'S' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[20] = array( 'Callback-Id', 'S' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[21] = array( '(unassigned)', '' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[22] = array( 'Framed-Route', 'T' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[23] = array( 'Framed-IPX-Network', 'I' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[24] = array( 'State', 'S' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[25] = array( 'Class', 'S' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[26] = array( 'Vendor-Specific', 'S' );  // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here. // Type (1) / Length (1) / Vendor-Id (4) / Vendor type (1) / Vendor length (1) / Attribute-Specific..
			$this->attributesInfo[27] = array( 'Session-Timeout', 'I' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[28] = array( 'Idle-Timeout', 'I' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[29] = array( 'Termination-Action', 'I' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[30] = array( 'Called-Station-Id', 'S' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[31] = array( 'Calling-Station-Id', 'S' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[32] = array( 'NAS-Identifier', 'S' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[33] = array( 'Proxy-State', 'S' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[34] = array( 'Login-LAT-Service', 'S' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[35] = array( 'Login-LAT-Node', 'S' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[36] = array( 'Login-LAT-Group', 'S' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[37] = array( 'Framed-AppleTalk-Link', 'I' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[38] = array( 'Framed-AppleTalk-Network', 'I' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[39] = array( 'Framed-AppleTalk-Zone', 'S' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[60] = array( 'CHAP-Challenge', 'S' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[61] = array( 'NAS-Port-Type', 'I' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[62] = array( 'Port-Limit', 'I' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[63] = array( 'Login-LAT-Port', 'S' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[76] = array( 'Prompt', 'I' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[79] = array( 'EAP-Message', 'S' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesInfo[80] = array( 'Message-Authenticator', 'S' ); // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->identifierToSend   = -1; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->chapIdentifier     = 1; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->generate_request_authenticator()
			->set_server( $radius_host )
			->set_secret( $shared_secret )
			->set_authentication_port( $authentication_port )
			->set_accounting_port( $accounting_port )
			->set_timeout( $timeout )
			->set_radius_suffix( $radius_suffix );
			$this->clear_error()
			->clear_data_to_send()
			->clear_data_received();
		}
		/**
		 * Returns a string of the last error message and code, if any.
		 *
		 * @return string The last error message and code, or an empty string if no error set.
		 */
		public function get_last_error() {
			if ( 0 < $this->errorCode ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				return $this->errorMessage . ' (' . $this->errorCode . ')';// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			} else {
				return '';
			}
		}
		/**
		 * Get the code of the last error.
		 *
		 * @return number  The error code
		 */
		public function get_error_code() {
			return $this->errorCode;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
		}
		/**
		 * Get the message of the last error.
		 *
		 * @return string  The last error message
		 */
		public function get_error_message() {
			return $this->errorMessage;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
		}
		/**
		 * Enable or disable debug (console) output.
		 *
		 * @param bool $enabled  boolean true to enable debugging, anything else to disable it.
		 *
		 * @return \Dapphp\Radius\Radius
		 */
		public function set_debug( $enabled = true ) {
			$this->debug = ( true === $enabled );

			return $this;
		}
		/**
		 * Set the hostname or IP address of the RADIUS server to send requests to.
		 *
		 * @param string $host_or_ip  The hostname or IP address of the RADIUS server.
		 * @return \Dapphp\Radius\Radius
		 */
		public function set_server( $host_or_ip ) {
			$this->server = gethostbyname( $host_or_ip );

			return $this;
		}
		/**
		 * Set the RADIUS shared secret between the client and RADIUS server.
		 *
		 * @param string $secret  The shared secret.
		 * @return \Dapphp\Radius\Radius
		 */
		public function set_secret( $secret ) {
			$this->secret = $secret;

			return $this;
		}
		/**
		 * Gets the currently set RADIUS shared secret.
		 *
		 * @return string  The shared secret
		 */
		public function get_secret() {
			return $this->secret;
		}
		/**
		 * Set the username suffix for authentication (e.g. '.ppp').
		 * This must be set before setting the username.
		 *
		 * @param string $suffix  The RADIUS user suffix (e.g. .ppp).
		 * @return \Dapphp\Radius\Radius
		 */
		public function set_radius_suffix( $suffix ) {
			$this->suffix = $suffix;

			return $this;
		}
		/**
		 * Set the username to authenticate as with the RADIUS server.
		 * If the username does not contain the '@' character, then the RADIUS suffix
		 * will be appended to the username.
		 *
		 * @param string $username  The username for authentication.
		 * @return \Dapphp\Radius\Radius
		 */
		public function set_username( $username = '' ) {
			if ( false === strpos( $username, '@' ) ) {
				$username .= $this->suffix;
			}
			$this->username = $username;
			$this->set_attribute( 1, $this->username );

			return $this;
		}
		/**
		 * Get the authentication username for RADIUS requests.
		 *
		 * @return string  The username for authentication
		 */
		public function get_username() {
			return $this->username;
		}
		/**
		 * Set the User-Password for PAP authentication.
		 * Do not use this if you will be using CHAP-MD5, MS-CHAP v1 or MS-CHAP v2 passwords.
		 *
		 * @param string $password  The plain text password for authentication.
		 * @return \Dapphp\Radius\Radius
		 */
		public function set_password( $password ) {
			$this->password     = $password;
			$encrypted_password = $this->get_encrypted_password( $password, $this->get_secret(), $this->get_request_authenticator() );
			$this->set_attribute( 2, $encrypted_password );

			return $this;
		}
		/**
		 * Get the plaintext password for authentication.
		 *
		 * @return string  The authentication password
		 */
		public function get_password() {
			return $this->password;
		}
		/**
		 * Get a RADIUS encrypted password from a plaintext password, shared secret, and request authenticator.
		 * This method should generally not need to be called directly.
		 *
		 * @param mixed  $password The plain text password.
		 * @param string $secret   The RADIUS shared secret.
		 * @param string $request_authenticator  16 byte request authenticator.
		 * @return string  The encrypted password
		 */
		public function get_encrypted_password( $password, $secret, $request_authenticator ) {
			$encrypted_password = '';
			$padded_password    = $password;
			if ( 0 !== ( strlen( $password ) % 16 ) ) {
				$padded_password .= str_repeat( chr( 0 ), ( 16 - strlen( $password ) % 16 ) );
			}
			$previous               = $request_authenticator;
			$padded_password_length = strlen( $padded_password );
			for ( $i = 0; $i < ( $padded_password_length / 16 ); ++$i ) {
				$temp     = md5( $secret . $previous );
				$previous = '';
				for ( $j = 0; $j <= 15; ++$j ) {
					$value1     = ord( substr( $padded_password, ( $i * 16 ) + $j, 1 ) );
					$value2     = hexdec( substr( $temp, 2 * $j, 2 ) );
					$xor_result = $value1 ^ $value2;
					$previous  .= chr( $xor_result );
				}
				$encrypted_password .= $previous;
			}
			return $encrypted_password;
		}
		/**
		 * Set whether a Message-Authenticator attribute (80) should be included in the request.
		 * Note: Some servers (e.g. Microsoft NPS) may be configured to require all packets contain this.
		 *
		 * @param bool $include  Boolean true to include in packets, false otherwise.
		 * @return \Dapphp\Radius\Radius
		 */
		public function set_include_message_authenticator( $include = true ) {
			if ( $include ) {
				$this->set_attribute( 80, str_repeat( "\x00", 16 ) );
			} else {
				$this->remove_attribute( 80 );
			}

			return $this;
		}
		/**
		 * Sets the next sequence number that will be used when sending packets.
		 * There is generally no need to call this method directly.
		 *
		 * @param int $next_id  The CHAP packet identifier number.
		 * @return \Dapphp\Radius\Radius
		 */
		public function set_chap_id( $next_id ) {
			$this->chapIdentifier = (int) $next_id;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.

			return $this;
		}
		/**
		 * Get the CHAP ID and increment the counter.
		 *
		 * @return number  The CHAP identifier for the next packet
		 */
		public function get_chap_id() {
			$id = $this->chapIdentifier;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->chapIdentifier++;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			return $id;
		}
		/**
		 * Set the CHAP password (for CHAP authentication).
		 *
		 * @param string $password  The plaintext password to hash using CHAP.
		 * @return \Dapphp\Radius\Radius
		 */
		public function set_chap_password( $password ) {
			$chap_id  = $this->get_chap_id();
			$chap_md5 = $this->get_chap_password( $password, $chap_id, $this->get_request_authenticator() );
			$this->set_attribute( 3, pack( 'C', $chap_id ) . $chap_md5 );

			return $this;
		}
		/**
		 * Generate a CHAP password.  There is generally no need to call this method directly.
		 *
		 * @param string $password  The password to hash using CHAP.
		 * @param int    $chap_id    The CHAP packet ID.
		 * @param string $request_authenticator  The request authenticator value.
		 * @return string The hashed CHAP password
		 */
		public function get_chap_password( $password, $chap_id, $request_authenticator ) {
			return md5( pack( 'C', $chap_id ) . $password . $request_authenticator, true );
		}
		/**
		 * Set the MS-CHAP password in the RADIUS packet (for authentication using MS-CHAP passwords)
		 *
		 * @param string $password  The plaintext password.
		 * @param string $challenge The CHAP challenge.
		 * @return \Dapphp\Radius\Radius
		 */
		public function set_ms_chap_password( $password, $challenge = null ) {
			$chap           = new \Crypt_CHAP_MSv1();
			$chap->chapid   = wp_rand( 1, 255 );
			$chap->password = $password;
			if ( is_null( $challenge ) ) {
				$chap->generate_challenge();
			} else {
				$chap->challenge = $challenge;
			}
			$response = "\x00\x01" . str_repeat( "\0", 24 ) . $chap->ntChallengeResponse();
			$this->set_include_message_authenticator();
			$this->set_vendor_specific_attribute( VendorId::MICROSOFT, 11, $chap->challenge );
			$this->set_vendor_specific_attribute( VendorId::MICROSOFT, 1, $response );

			return $this;
		}
		/**
		 * Sets the Network Access Server (NAS) IP address (the RADIUS client IP).
		 *
		 * @param string $host_or_ip  The hostname or IP address of the RADIUS client.
		 * @return \Dapphp\Radius\Radius
		 */
		public function set_nas_ip_address( $host_or_ip = '' ) {
			if ( 0 < strlen( $host_or_ip ) ) {
				$this->nasIpAddress = gethostbyname( $host_or_ip );// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			} else {
				$host_or_ip = php_uname( 'n' );
				if ( empty( $host_or_ip ) ) {
					$host_or_ip = ( isset( $server['HTTP_HOST'] ) ) ? sanitize_text_field( $server['HTTP_HOST'] ) : '';
				}
				if ( empty( $host_or_ip ) ) {
					$host_or_ip = ( isset( $server['SERVER_ADDR'] ) ) ? sanitize_text_field( $server['SERVER_ADDR'] ) : '0.0.0.0';
				}
				$this->nasIpAddress = gethostbyname( $host_or_ip );// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			}
			$this->set_attribute( 4, $this->nasIpAddress );// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.

			return $this;
		}
		/**
		 * Get the currently set NAS IP address
		 *
		 * @return string  The NAS hostname or IP
		 */
		public function get_nas_ip_address() {
			return $this->nasIpAddress;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
		}
		/**
		 * Set the physical port number of the NAS which is authenticating the user.
		 *
		 * @param number $port  The NAS port.
		 * @return \Dapphp\Radius\Radius
		 */
		public function set_nas_port( $port = 0 ) {
			$this->nasPort = intval( $port );// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->set_attribute( 5, $this->nasPort );// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.

			return $this;
		}
		/**
		 * Get the NAS port attribute
		 *
		 * @return string
		 */
		public function get_nas_port() {
			return $this->nasPort;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
		}
		/**
		 * Set the timeout (in seconds) after which we'll give up waiting for a response from the RADIUS server.
		 *
		 * @param number $timeout  The timeout (in seconds) for waiting for RADIUS responses.
		 * @return \Dapphp\Radius\Radius
		 */
		public function set_timeout( $timeout = 5 ) {
			if ( intval( $timeout ) > 0 ) {
				$this->timeout = intval( $timeout );
			}

			return $this;
		}
		/**
		 * Get the current timeout value for RADIUS response packets.
		 *
		 * @return number  The timeout
		 */
		public function get_timeout() {
			return $this->timeout;
		}
		/**
		 * Set the port number used by the RADIUS server for authentication (default = 1812).
		 *
		 * @param number $port  The port for sending Access-Request packets.
		 * @return \Dapphp\Radius\Radius
		 */
		public function set_authentication_port( $port ) {
			if ( ( intval( $port ) > 0 ) && ( intval( $port ) < 65536 ) ) {
				$this->authenticationPort = intval( $port );// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			}

			return $this;
		}
		/**
		 * Get the port number used for authentication
		 *
		 * @return number  The RADIUS auth port
		 */
		public function get_authentication_port() {
			return $this->authenticationPort;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
		}
		/**
		 * Set the port number used by the RADIUS server for accounting (default = 1813)
		 *
		 * @param number $port  The port for sending Accounting request packets.
		 * @return \Dapphp\Radius\Radius
		 */
		public function set_accounting_port( $port ) {
			if ( ( intval( $port ) > 0 ) && ( intval( $port ) < 65536 ) ) {
				$this->accountingPort = intval( $port );// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			}

			return $this;
		}
		/**
		 * Returns the raw wire data of the last received RADIUS packet.
		 *
		 * @return string  The raw packet data of the last RADIUS response
		 */
		public function get_response_packet() {
			return $this->radiusPacketReceived;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
		}
		/**
		 * Alias of Radius::getAttribute()
		 *
		 * @param int $type  The attribute ID to get.
		 * @return NULL|string NULL if no such attribute was set in the response packet, or the data of that attribute
		 */
		public function get_received_attribute( $type ) {
			return $this->get_attribute( $type );
		}
		/**
		 * Returns an array of all attributes from the last received RADIUS packet.
		 *
		 * @return array  Array of received attributes.  Each entry is an array with $attr[0] = attribute ID, $attr[1] = data
		 */
		public function get_received_attributes() {
			return $this->attributesReceived;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
		}
		/**
		 * For debugging purposes.  Print the attributes from the last received packet as a readble string
		 *
		 * @return string  The RADIUS packet attributes in human readable format
		 */
		public function get_readable_received_attributes() {
			$attributes = '';
			if ( isset( $this->attributesReceived ) ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				foreach ( $this->attributesReceived as $received_attr ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
					$info        = $this->get_attributes_info( $received_attr[0] );
					$attributes .= sprintf( '%s: ', $info[0] );
					if ( 26 === $received_attr[0] ) {
						$vendor_arr = $this->decode_vendor_specific_content( $received_attr[1] );
						foreach ( $vendor_arr as $vendor ) {
							$attributes .= sprintf(
								'Vendor-Id: %s, Vendor-type: %s, Attribute-specific: %s',
								$vendor[0],
								$vendor[1],
								$vendor[2]
							);
						}
					} else {
						$attribues = $received_attr[1];
					}
					$attributes .= "<br>\n";
				}
			}
			return $attributes;
		}
		/**
		 * Get the value of an attribute from the last received RADIUS response packet.
		 *
		 * @param int $type    The attribute ID to get.
		 * @return NULL|string NULL if no such attribute was set in the response packet, or the data of that attribute
		 */
		public function get_attribute( $type ) {
			$value = null;
			if ( is_array( $this->attributesReceived ) ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				foreach ( $this->attributesReceived as $attr ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
					if ( intval( $type ) === $attr[0] ) {
						$value = $attr[1];
						break;
					}
				}
			}
			return $value;
		}
		/**
		 * Gets the name of a RADIUS packet from the numeric value.
		 * This is only used for debugging functions
		 *
		 * @param number $info_index  The packet type number.
		 * @return mixed|string
		 */
		public function get_radius_packet_info( $info_index ) {
			if ( isset( $this->radiusPackets[ intval( $info_index ) ] ) ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				return $this->radiusPackets[ intval( $info_index ) ];// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			} else {
				return '';
			}
		}
		/**
		 * Gets the info about a RADIUS attribute identifier such as the attribute name and data type.
		 * This is used internally for encoding packets and debug output.
		 *
		 * @param number $info_index  The RADIUS packet attribute number.
		 * @return array 2 element array with Attibute-Name and Data Type
		 */
		public function get_attributes_info( $info_index ) {
			if ( isset( $this->attributesInfo[ intval( $info_index ) ] ) ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				return $this->attributesInfo[ intval( $info_index ) ];// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			} else {
				return array( '', '' );
			}
		}
		/**
		 * Set an arbitrary RADIUS attribute to be sent in the next packet.
		 *
		 * @param int   $type  The number of the RADIUS attribute.
		 * @param mixed $value  The value of the attribute.
		 * @return \Dapphp\Radius\Radius
		 */
		public function set_attribute( $type, $value ) {
			$index = -1;
			if ( is_array( $this->attributesToSend ) ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				foreach ( $this->attributesToSend as $i => $attr ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
					if ( is_array( $attr ) ) {
						$tmp = $attr[0];
					} else {
						$tmp = $attr;
					}
					if ( isset( $tmp ) && ord( substr( $tmp, 0, 1 ) ) === $type ) {
						$index = $i;
						break;
					}
				}
			}
			$temp = null;
			if ( isset( $this->attributesInfo[ $type ] ) ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				switch ( $this->attributesInfo[ $type ][1] ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
					case 'T':
						// Text, 1-253 octets containing UTF-8 encoded ISO 10646 characters (RFC 2279).
						$temp = chr( $type ) . chr( 2 + strlen( $value ) ) . $value;
						break;
					case 'S':
						// String, 1-253 octets containing binary data (values 0 through 255 decimal, inclusive).
						$temp = chr( $type ) . chr( 2 + strlen( $value ) ) . $value;
						break;
					case 'A':
						// Address, 32 bit value, most significant octet first.
						$ip = explode( '.', $value );
						if ( count( $ip ) === 4 ) {
							$temp = chr( $type ) . chr( 6 ) . chr( $ip[0] ) . chr( $ip[1] ) . chr( $ip[2] ) . chr( $ip[3] );
						} else {
							$ip = explode( '.', '127.0.0.1' );
						}
						$temp = chr( $type ) . chr( 6 ) . chr( $ip[0] ) . chr( $ip[1] ) . chr( $ip[2] ) . chr( $ip[3] );
						break;
					case 'I':
						// Integer, 32 bit unsigned value, most significant octet first.
						$temp = chr( $type ) . chr( 6 ) .
						chr( ( $value / ( 256 * 256 * 256 ) ) % 256 ) .
						chr( ( $value / ( 256 * 256 ) ) % 256 ) .
						chr( ( $value / ( 256 ) ) % 256 ) .
						chr( $value % 256 );
						break;
					case 'D':
						// Time, 32 bit unsigned value, most significant octet first -- seconds since 00:00:00 UTC, January 1, 1970. (not used in this RFC).
						$temp = null;
						break;
					default:
						$temp = null;
				}
			}
			if ( $index > -1 ) {
				if ( 26 === $type ) { // vendor specific.
					$this->attributesToSend[ $index ][] = $temp;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
					$action                             = 'Added';
				} else {
					$this->attributesToSend[ $index ] = $temp;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
					$action                           = 'Modified';
				}
			} else {
				$this->attributesToSend[] = ( 26 === $type /* vendor specific */ ) ? array( $temp ) : $temp;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				$action                   = 'Added';
			}
			$info = $this->get_attributes_info( $type );
			$this->debug_info( "{$action} Attribute {$type} ({$info[0]}), format {$info[1]}, value <em>{$value}</em>" );

			return $this;
		}
		/**
		 * Get one or all set attributes to send
		 *
		 * @param int|null $type  RADIUS attribute type, or null for all.
		 * @return mixed array of attributes to send, or null if specific attribute not found.
		 */
		public function get_attributes_to_send( $type = null ) {
			if ( is_array( $this->attributesToSend ) ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				if ( null === $type ) {
					return $this->attributesToSend;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				} else {
					foreach ( $this->attributesToSend as $i => $attr ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
						if ( is_array( $attr ) ) {
							$tmp = $attr[0];
						} else {
							$tmp = $attr;
						}
						if ( ord( substr( $tmp, 0, 1 ) ) === $type ) {
							return $this->decode_attribute( substr( $tmp, 2 ), $type );
						}
					}
					return null;
				}
			}
			return array();
		}
		/**
		 * Adds a vendor specific attribute to the RADIUS packet
		 *
		 * @param number $vendor_id  The RADIUS vendor ID.
		 * @param int    $attribute_type  The attribute number of the vendor specific attribute.
		 * @param mixed  $attribute_value The data for the attribute.
		 * @return \Dapphp\Radius\Radius
		 */
		public function set_vendor_specific_attribute( $vendor_id, $attribute_type, $attribute_value ) {
			$data  = pack( 'N', $vendor_id );
			$data .= chr( $attribute_type );
			$data .= chr( 2 + strlen( $attribute_value ) );
			$data .= $attribute_value;
			$this->set_attribute( 26, $data );

			return $this;
		}
		/**
		 * Remove an attribute from a RADIUS packet
		 *
		 * @param number $type  The attribute number to remove.
		 * @return \Dapphp\Radius\Radius
		 */
		public function remove_attribute( $type ) {
			$index = -1;
			if ( is_array( $this->attributesToSend ) ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				foreach ( $this->attributesToSend as $i => $attr ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
					if ( is_array( $attr ) ) {
						$tmp = $attr[0];
					} else {
						$tmp = $attr;
					}
					if ( ord( substr( $tmp, 0, 1 ) ) === $type ) {
						unset( $this->attributesToSend[ $i ] );// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
						break;
					}
				}
			}

			return $this;
		}
		/**
		 * Clear all attributes to send so the next packet contains no attributes except ones added after calling this function.
		 *
		 * @return \Dapphp\Radius\Radius
		 */
		public function reset_attributes() {
			$this->attributesToSend = null;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.

			return $this;
		}
		/**
		 * Remove vendor specific attributes from the request.
		 *
		 * @return \Dapphp\Radius\Radius
		 */
		public function reset_vendor_specific_attributes() {
			$this->remove_attribute( 26 );

			return $this;
		}
		/**
		 * Decodes a vendor specific attribute in a response packet
		 *
		 * @param string $raw_value  The raw packet attribute data as seen on the wire.
		 * @return array  Array of vendor specific attributes in the response packet
		 */
		public function decode_vendor_specific_content( $raw_value ) {
			$result           = array();
			$offset           = 0;
			$vendor_id        = ( ord( substr( $raw_value, 0, 1 ) ) * 256 * 256 * 256 ) +
			( ord( substr( $raw_value, 1, 1 ) ) * 256 * 256 ) +
			( ord( substr( $raw_value, 2, 1 ) ) * 256 ) +
			ord( substr( $raw_value, 3, 1 ) );
			$offset          += 4;
			$raw_value_length = strlen( $raw_value );
			while ( $offset < $raw_value_length ) {
				$vendor_type        = ( ord( substr( $raw_value, 0 + $offset, 1 ) ) );
				$vendor_length      = ( ord( substr( $raw_value, 1 + $offset, 1 ) ) );
				$attribute_specific = substr( $raw_value, 2 + $offset, $vendor_length );
				$result[]           = array( $vendor_id, $vendor_type, $attribute_specific );
				$offset            += $vendor_length;
			}
			return $result;
		}
		/**
		 * Issue an Access-Request packet to the RADIUS server.
		 *
		 * @param string $username  Username to authenticate as.
		 * @param string $password  Password to authenticate with using PAP.
		 * @param number $timeout   The timeout (in seconds) to wait for a response packet.
		 * @param string $state     The state of the request (default is Service-Type=1).
		 * @return boolean          true if the server sent an Access-Accept packet, false otherwise
		 */
		public function access_request( $username = '', $password = '', $timeout = 0, $state = null ) {
			$this->clear_data_received()
			->clear_error()
			->set_packet_type( self::TYPE_ACCESS_REQUEST );
			if ( 0 < strlen( $username ) ) {
				$this->set_username( $username );
			}
			if ( 0 < strlen( $password ) ) {
				$this->set_password( $password );
			}
			if ( null !== $state ) {
				$this->set_attribute( 24, $state );
			} else {
				$this->set_attribute( 6, 1 ); // 1=Login
			}
			if ( intval( $timeout ) > 0 ) {
				$this->set_timeout( $timeout );
			}
			$packet_data = $this->generate_radius_packet();
			$conn        = $this->send_radius_request( $packet_data );
			if ( ! $conn ) {
				$this->debug_info(
					sprintf(
						'Failed to send packet to %s; error: %s',
						$this->server,
						$this->get_error_message()
					)
				);

					return false;
			}
			$received_packet = $this->read_radius_response( $conn );
			fclose( $conn ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_fclose -- Sending packet using UDP. Cannot use FileHandling functions here.
			if ( ! $received_packet ) {
				$this->debug_info(
					sprintf(
						'Error receiving response packet from %s; error: %s',
						$this->server,
						$this->get_error_message()
					)
				);

				return false;
			}
			if ( ! $this->parse_radius_response_packet( $received_packet ) ) {
				$this->debug_info(
					sprintf(
						'Bad RADIUS response from %s; error: %s',
						$this->server,
						$this->get_error_message()
					)
				);
				return false;
			}
			if ( self::TYPE_ACCESS_REJECT === $this->radiusPacketReceived ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				$this->errorCode    = 3;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				$this->errorMessage = 'Access rejected';// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			}
			return ( self::TYPE_ACCESS_ACCEPT === ( $this->radiusPacketReceived ) );// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
		}
		/**
		 * Perform an accessRequest against a list of servers.  Each server must
		 * share the same RADIUS secret.  This is useful if you have more than one
		 * RADIUS server.  This function tries each server until it receives an
		 * Access-Accept or Access-Reject response.  That is, it will try more than
		 * one server in the event of a timeout or other failure.
		 *
		 * @see \Dapphp\Radius\Radius::accessRequest()
		 *
		 * @param array  $server_list  Array of servers to authenticate against.
		 * @param string $username    Username to authenticate as.
		 * @param string $password    Password to authenticate with using PAP.
		 * @param number $timeout     The timeout (in seconds) to wait for a response packet.
		 * @param string $state       The state of the request (default is Service-Type=1).
		 *
		 * @return boolean true if the server sent an Access-Accept packet, false otherwise
		 */
		public function access_request_list( $server_list, $username = '', $password = '', $timeout = 0, $state = null ) {
			if ( ! is_array( $server_list ) ) {
				$this->errorCode    = 127;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				$this->errorMessage = sprintf(// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
					'server list passed to accessRequestl must be array; %s given',
					gettype( $server_list )
				);
				return false;
			}
			foreach ( $server_list as $server ) {
				$this->set_server( $server );
				$result = $this->access_request( $username, $password, $timeout, $state );
				if ( true === $result ) {
					break; // success.
				} elseif ( $this->get_error_code() === self::TYPE_ACCESS_REJECT ) {
					break; // access rejected.
				}
			}
			return $result;
		}
		/**
		 * Authenticate using EAP-MSCHAP v2.  This is a 4-way authentication
		 * process that sends an Access-Request, receives an Access-Challenge,
		 * responsds with an Access-Request, and finally sends an Access-Request with
		 * an EAP success packet if the last Access-Challenge was a success.
		 *
		 * Windows Server NPS: EAP Type: MS-CHAP v2
		 *
		 * @param string $username  The username to authenticate as.
		 * @param string $password  The plain text password that will be hashed using MS-CHAPv2.
		 * @return boolean          true if negotiation resulted in an Access-Accept packet, false otherwise
		 */
		public function access_request_eap_ms_chap_v2( $username, $password ) {
			/*
			* RADIUS EAP MSCHAPv2 Process:
			* > RADIUS ACCESS_REQUEST w/ EAP identity packet
			* < ACCESS_CHALLENGE w/ MSCHAP challenge encapsulated in EAP request
			*   CHAP packet contains auth_challenge value
			*   Calculate encrypted password based on challenge for response
			* > ACCESS_REQUEST w/ MSCHAP challenge response, peer_challenge &
			*   encrypted password encapsulated in an EAP response packet
			* < ACCESS_CHALLENGE w/ MSCHAP success or failure in EAP packet.
			* > ACCESS_REQUEST w/ EAP success packet if challenge was accepted
			*
			*/
			$attributes = $this->get_attributes_to_send();
			$this->clear_data_to_send()
			->clear_error()
			->set_packet_type( self::TYPE_ACCESS_REQUEST );
			$this->attributesToSend = $attributes;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$eap_packet             = EAPPacket::identity( $username );
			$this->set_username( $username )
			->set_attribute( 79, $eap_packet )
			->set_include_message_authenticator();
			$this->access_request();
			if ( $this->errorCode ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				return false;
			} elseif ( self::TYPE_ACCESS_CHALLENGE !== $this->radiusPacketReceived ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				$this->errorCode    = 102;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				$this->errorMessage = 'Access-Request did not get Access-Challenge response';// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				return false;
			}
			$state = $this->get_received_attribute( 24 );
			$eap   = $this->get_received_attribute( 79 );
			if ( null === $eap ) {
				$this->errorCode    = 102;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				$this->errorMessage = 'EAP packet missing from MSCHAP v2 access response';// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				return false;
			}
			$eap = EAPPacket::from_string( $eap );
			if ( EAPPacket::TYPE_EAP_MS_AUTH !== $eap->type ) {
				$this->errorCode    = 102;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				$this->errorMessage = 'EAP type is not EAP_MS_AUTH in access response';// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				return false;
			}
			$chap_packet = MsChapV2Packet::from_string( $eap->data );
			if ( ! $chap_packet || MsChapV2Packet::OPCODE_CHALLENGE !== $chap_packet->opcode ) {
				$this->errorCode    = 102;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				$this->errorMessage = 'MSCHAP v2 access response packet missing challenge';// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				return false;
			}
			$challenge                  = $chap_packet->challenge;
			$chap_id                    = $chap_packet->ms_chap_id;
			$ms_chap_v2                 = new \Crypt_CHAP_MSv2();
			$ms_chap_v2->username       = $username;
			$ms_chap_v2->password       = $password;
			$ms_chap_v2->chapid         = $chap_packet->ms_chap_id;
			$ms_chap_v2->auth_challenge = $challenge;
			$response                   = $ms_chap_v2->challenge_response();
			$chap_packet->opcode        = MsChapV2Packet::OPCODE_RESPONSE;
			$chap_packet->response      = $response;
			$chap_packet->name          = $username;
			$chap_packet->challenge     = $ms_chap_v2->peer_challenge;
			$eap_packet                 = EAPPacket::mschapv2( $chap_packet, $chap_id );
			$this->clear_data_to_send()
			->set_packet_type( self::TYPE_ACCESS_REQUEST )
			->set_username( $username )
			->set_attribute( 79, $eap_packet )
			->set_include_message_authenticator();
			$resp = $this->access_request( null, null, 0, $state );
			if ( $this->errorCode ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				return false;
			}
			$eap = $this->get_received_attribute( 79 );
			if ( null === $eap ) {
				$this->errorCode    = 102;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				$this->errorMessage = 'EAP packet missing from MSCHAP v2 challenge response';// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				return false;
			}
			$eap = EAPPacket::from_string( $eap );
			if ( EAPPacket::TYPE_EAP_MS_AUTH !== $eap->type ) {
				$this->errorCode    = 102;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				$this->errorMessage = 'EAP type is not EAP_MS_AUTH in access response';// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				return false;
			}
			$chap_packet = MsChapV2Packet::from_string( $eap->data );
			if ( MsChapV2Packet::OPCODE_SUCCESS !== $chap_packet->opcode ) {
				$this->errorCode = 3;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				$err             = ( ! empty( $chap_packet->response ) ) ? $chap_packet->response : 'General authentication failure';
				if ( preg_match( '/E=(\d+)/', $chap_packet->response, $err ) ) {
					switch ( $err[1] ) {
						case '691':
							$err = 'Authentication failure, username or password incorrect.';
							break;
						case '646':
							$err = 'Authentication failure, restricted logon hours.';
							break;
						case '647':
							$err = 'Account disabled';
							break;
						case '648':
							$err = 'Password expired';
							break;
						case '649':
							$err = 'No dial in permission';
							break;
					}
				}
				$this->errorMessage = $err;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				return false;
			}
			// got a success response - send success acknowledgement.
			$state               = $this->get_received_attribute( 24 );
			$chap_packet         = new MsChapV2Packet();
			$chap_packet->opcode = MsChapV2Packet::OPCODE_SUCCESS;
			$eap_packet          = EAPPacket::mschapv2( $chap_packet, $chap_id + 1 );
			$this->clear_data_to_send()
			->set_packet_type( self::TYPE_ACCESS_REQUEST )
			->set_username( $username )
			->set_attribute( 79, $eap_packet )
			->set_include_message_authenticator();
			$resp = $this->access_request( null, null, 0, $state );
			if ( true !== $resp ) {
				return false;
			} else {
				return true;
			}
		}
		/**
		 * Perform a EAP-MSCHAP v2 4-way authentication against a list of servers.
		 * Each server must share the same RADIUS secret.
		 *
		 * @see \Dapphp\Radius\Radius::accessRequestEapMsChapV2()
		 * @see \Dapphp\Radius\Radius::accessRequestList()
		 *
		 * @param array  $server_list Array of servers to authenticate against.
		 * @param string $username  The username to authenticate as.
		 * @param string $password  The plain text password that will be hashed using MS-CHAPv2.
		 * @return boolean          true if negotiation resulted in an Access-Accept packet, false otherwise
		 */
		public function access_request_eap_ms_chap_v2_list( $server_list, $username, $password ) {
			if ( ! is_array( $server_list ) ) {
				$this->errorCode    = 127;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				$this->errorMessage = sprintf(// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
					'server list passed to accessRequestl must be array; %s given',
					gettype( $server_list )
				);
				return false;
			}
			foreach ( $server_list as $server ) {
				$this->set_server( $server );
				$result = $this->access_request_eap_ms_chap_v2( $username, $password );
				if ( true === $result ) {
					break; // success.
				} elseif ( $this->get_error_code() === self::TYPE_ACCESS_REJECT ) {
					break; // access rejected.
				}
			}
			return $result;
		}
		/**
		 * Send a RADIUS packet over the wire using UDP.
		 *
		 * @param string $packet_data  The raw, complete, RADIUS packet to send.
		 * @return boolean|resource   false if the packet failed to send, or a socket resource on success
		 */
		private function send_radius_request( $packet_data ) {
			$packet_len = strlen( $packet_data );
			$conn       = fsockopen( 'udp://' . $this->server, $this->authenticationPort, $errno, $errstr ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_fsockopen,WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Sending packet using UDP. Cannot use FileHandling functions here -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			if ( ! $conn ) {
				$this->errorCode    = $errno;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				$this->errorMessage = $errstr;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				return false;
			}
			$sent = fwrite( $conn, $packet_data ); // phpcs:ignore WordPress.WP.AlternativeFunctions.file_system_read_fwrite -- Sending packet using UDP. Cannot use FileHandling functions here.
			if ( ! $sent || $packet_len !== $sent ) {
				$this->errorCode    = 55; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here. // CURLE_SEND_ERROR.
				$this->errorMessage = 'Failed to send UDP packet';// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				return false;
			}
			if ( $this->debug ) {
				$this->debug_info(
					sprintf(
						'<b>Packet type %d (%s) sent to %s</b>',
						$this->radiusPacket, // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
						$this->get_radius_packet_info( $this->radiusPacket ), // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
						$this->server
					)
				);
				foreach ( $this->attributesToSend as $attrs ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
					if ( ! is_array( $attrs ) ) {
						$attrs = array( $attrs );
					}
					foreach ( $attrs as $attr ) {
						$attr_info = $this->get_attributes_info( ord( substr( $attr, 0, 1 ) ) );
						$this->debug_info(
							sprintf(
								'Attribute %d (%s), length (%d), format %s, value <em>%s</em>',
								ord( substr( $attr, 0, 1 ) ),
								$attr_info[0],
								ord( substr( $attr, 1, 1 ) ) - 2,
								$attr_info[1],
								$this->decode_attribute( substr( $attr, 2 ), ord( substr( $attr, 0, 1 ) ) )
							)
						);
					}
				}
			}
			return $conn;
		}
		/**
		 * Wait for a UDP response packet and read using a timeout.
		 *
		 * @param resource $conn  The connection resource returned by fsockopen.
		 * @return boolean|string false on failure, or the RADIUS response packet
		 */
		private function read_radius_response( $conn ) {
			stream_set_blocking( $conn, false );
			$read                   = array( $conn );
			$write                  = null;
			$except                 = null;
			$received_packet        = '';
			$packet_len             = null;
			$elapsed                = 0;
			$received_packet_length = strlen( $received_packet );
			do {
				// Loop until the entire packet is read.  Even with small packets,
				// not all data might get returned in one read on a non-blocking stream.
				$t0      = microtime( true );
				$changed = stream_select( $read, $write, $except, $this->timeout );
				$t1      = microtime( true );
				if ( $changed > 0 ) {
					$data = fgets( $conn, 1024 );
					// Try to read as much data from the stream in one pass until 4
					// bytes are read.  Once we have 4 bytes, we can determine the
					// length of the RADIUS response to know when to stop reading.
					if ( ! $data ) {
						// recv could fail due to ICMP destination unreachable.
						$this->errorCode    = 56; // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.// CURLE_RECV_ERROR.
						$this->errorMessage = 'Failure with receiving network data';// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
						return false;
					}
					$received_packet .= $data;
					if ( strlen( $received_packet ) < 4 ) {
						// not enough data to get the size.
						// this will probably never happen.
						continue;
					}
					if ( null === $packet_len ) {
						// first pass - decode the packet size from response.
						$packet_len = unpack( 'n', substr( $received_packet, 2, 2 ) );
						$packet_len = (int) array_shift( $packet_len );
						if ( $packet_len < 4 || $packet_len > 65507 ) {
							$this->errorCode    = 102;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
							$this->errorMessage = "Bad packet size in RADIUS response.  Got {$packet_len}";// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
							return false;
						}
					}
				} elseif ( false === $changed ) {
					$this->errorCode    = 2;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
					$this->errorMessage = 'stream_select returned false';// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
					return false;
				} else {
					$this->errorCode    = 28;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here. // CURLE_OPERATION_TIMEDOUT.
					$this->errorMessage = 'Timed out while waiting for RADIUS response';// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
					return false;
				}
				$elapsed += ( $t1 - $t0 );
			} while ( $elapsed < $this->timeout && $received_packet_length < $packet_len );
			return $received_packet;
		}
		/**
		 * Parse a response packet and do some basic validation.
		 *
		 * @param string $packet  The raw RADIUS response packet.
		 * @return boolean  true if the packet was decoded, false otherwise.
		 */
		private function parse_radius_response_packet( $packet ) {
			$this->radiusPacketReceived = intval( ord( substr( $packet, 0, 1 ) ) );// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->debug_info(
				sprintf(
					'<b>Packet type %d (%s) received</b>',
					$this->radiusPacketReceived, // phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
					$this->get_radius_packet_info( $this->get_response_packet() )
				)
			);
			if ( $this->radiusPacketReceived > 0 ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				$this->identifierReceived    = intval( ord( substr( $packet, 1, 1 ) ) );// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				$packet_len_rx               = unpack( 'n', substr( $packet, 2, 2 ) );
				$packet_len_rx               = array_shift( $packet_len_rx );
				$this->responseAuthenticator = bin2hex( substr( $packet, 4, 16 ) );// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				if ( $packet_len_rx > 20 ) {
					$attr_content = substr( $packet, 20 );
				} else {
					$attr_content = '';
				}
				$auth_check = md5(
					substr( $packet, 0, 4 ) .
					$this->get_request_authenticator() .
					$attr_content .
					$this->get_secret()
				);
				if ( $auth_check !== $this->responseAuthenticator ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
					$this->errorCode    = 101;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
					$this->errorMessage = 'Response authenticator in received packet did not match expected value';// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
					return false;
				}
				$attr_content_length = strlen( $attr_content );
				while ( $attr_content_length > 2 ) {
					$attr_type      = intval( ord( substr( $attr_content, 0, 1 ) ) );
					$attr_length    = intval( ord( substr( $attr_content, 1, 1 ) ) );
					$attr_value_raw = substr( $attr_content, 2, $attr_length - 2 );
					$attr_content   = substr( $attr_content, $attr_length );
					$attr_value     = $this->decode_attribute( $attr_value_raw, $attr_type );
					$attr           = $this->get_attributes_info( $attr_type );
					if ( 26 === $attr_type ) {
						$vendor_arr = $this->decode_vendor_specific_content( $attr_value );
						foreach ( $vendor_arr as $vendor ) {
							$this->debug_info(
								sprintf(
									'Attribute %d (%s), length %d, format %s, Vendor-Id: %d, Vendor-type: %s, Attribute-specific: %s',
									$attr_type,
									$attr[0],
									$attr_length - 2,
									$attr[1],
									$vendor[0],
									$vendor[1],
									$vendor[2]
								)
							);
						}
					} else {
						$this->debug_info(
							sprintf(
								'Attribute %d (%s), length %d, format %s, value <em>%s</em>',
								$attr_type,
								$attr[0],
								$attr_length - 2,
								$attr[1],
								$attr_value
							)
						);
					}
					$this->attributesReceived[] = array( $attr_type, $attr_value );// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				}
			} else {
				$this->errorCode    = 100;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				$this->errorMessage = 'Invalid response packet received';// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				return false;
			}
			return true;
		}
		/**
		 * Generate a RADIUS packet based on the set attributes and properties.
		 * Generally, there is no need to call this function.  Use one of the accessRequest* functions.
		 *
		 * @return string  The RADIUS packet
		 */
		public function generate_radius_packet() {
			$has_authenticator = false;
			$attr_content      = '';
			$len               = 0;
			$offset            = null;
			foreach ( $this->attributesToSend as $i => $attr ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				$len = strlen( $attr_content );
				if ( is_array( $attr ) ) {
					// vendor specific (could have multiple attributes).
					$attr_content .= implode( '', $attr );
				} else {
					if ( isset( $attr[0] ) && ord( $attr[0] ) === 80 ) {
						// If Message-Authenticator is set, note offset so it can be updated.
						$has_authenticator = true;
						$offset            = $len + 2; // current length + type(1) + length(1).
					}
					$attr_content .= $attr;
				}
			}
			$attr_len                  = strlen( $attr_content );
			$get_request_authenticator = null !== $this->get_request_authenticator() && ! empty( $this->get_request_authenticator() ) ? $this->get_request_authenticator() : '';
			$packet_len                = 4; // Radius packet code + Identifier + Length high + Length low.
			$packet_len               += strlen( $get_request_authenticator ); // Request-Authenticator.
			$packet_len               += $attr_len; // Attributes.
			$packet_data               = chr( $this->radiusPacket );// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$packet_data              .= pack( 'C', $this->get_next_identifier() );
			$packet_data              .= pack( 'n', $packet_len );
			$packet_data              .= $this->get_request_authenticator();
			$packet_data              .= $attr_content;
			if ( $has_authenticator && ! is_null( $offset ) ) {
				$message_authenticator        = hash_hmac( 'md5', $packet_data, $this->secret, true );
				$message_authenticator_length = strlen( $message_authenticator );
				// calculate packet hmac, replace hex 0's with actual hash.
				for ( $i = 0; $i < $message_authenticator_length; ++$i ) {
					$packet_data[ 20 + $offset + $i ] = $message_authenticator[ $i ];
				}
			}
			return $packet_data;
		}
		/**
		 * Set the RADIUS packet identifier that will be used for the next request
		 *
		 * @param number $identifier_to_send  The packet identifier to send.
		 * @return \Dapphp\Radius\Radius
		 */
		public function set_next_identifier( $identifier_to_send = 0 ) {
			$id                     = (int) $identifier_to_send;
			$this->identifierToSend = $id - 1;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.

			return $this;
		}
		/**
		 * Increment the packet identifier and return the number number
		 *
		 * @return number  The radius packet id
		 */
		public function get_next_identifier() {
			$this->identifierToSend = ( ( $this->identifierToSend + 1 ) % 256 );// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			return $this->identifierToSend;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
		}
		/**
		 * Adds random number to request
		 *
		 * @return \Dapphp\Radius\Radius
		 */
		private function generate_request_authenticator() {
			$this->requestAuthenticator = '';// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			for ( $c = 0; $c <= 15; ++$c ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				$this->requestAuthenticator .= chr( wp_rand( 1, 255 ) );// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			}

			return $this;
		}
		/**
		 * Set the request authenticator for the packet.  This is for testing only.
		 * There is no need to ever call this function.
		 *
		 * @param string $request_authenticator  The 16 octet request identifier.
		 * @return boolean|\Dapphp\Radius\Radius
		 */
		public function set_request_authenticator( $request_authenticator ) {
			if ( 16 !== strlen( $request_authenticator ) ) {
				return false;
			}
			$this->requestAuthenticator = $request_authenticator;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.

			return $this;
		}
		/**
		 * Get the value of the request authenticator used in request packets
		 *
		 * @return string  16 octet request authenticator
		 */
		public function get_request_authenticator() {
			return $this->requestAuthenticator;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
		}
		/**
		 * Get the value of the request authenticator used in request packets
		 *
		 * @var \Dapphp\Radius\Radius
		 */
		protected function clear_data_to_send() {
			$this->radiusPacket     = 0;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesToSend = null;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.

			return $this;
		}
		/**
		 * Clear received data.
		 *
		 * @var \Dapphp\Radius\Radius
		 */
		protected function clear_data_received() {
			$this->radiusPacketReceived = 0;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->attributesReceived   = null;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.

			return $this;
		}
		/**
		 * Set Packet type.
		 *
		 * @param number $type - type of packet.
		 * @return \Dapphp\Radius\Radius
		 */
		public function set_packet_type( $type ) {
			$this->radiusPacket = $type;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.

			return $this;
		}
		/**
		 * Clear error.
		 *
		 * @return \Dapphp\Radius\Radius
		 */
		private function clear_error() {
			$this->errorCode    = 0;// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
			$this->errorMessage = '';// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.

			return $this;
		}
		/**
		 * Debug function
		 *
		 * @param string $message - $message to be logged.
		 * @var \Dapphp\Radius\Radius        */
		protected function debug_info( $message ) {
			if ( $this->debug ) {
				$msg  = gmdate( 'Y-m-d H:i:s' ) . ' DEBUG: ';
				$msg .= $message;
				$msg .= "<br>\n";
				if ( php_sapi_name() === 'cli' ) {
					$msg = wp_strip_all_tags( $msg );
				}
				echo esc_html( $msg );
				flush();
			}
		}
		/**
		 * Decode Attributes
		 *
		 * @param string $raw_value - raw_value.
		 * @param string $attribute_format - attribute_format.
		 * @return mixed String|null
		 */
		private function decode_attribute( $raw_value, $attribute_format ) {
			$value = null;
			if ( isset( $this->attributesInfo[ $attribute_format ] ) ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
				switch ( $this->attributesInfo[ $attribute_format ][1] ) {// phpcs:ignore WordPress.NamingConventions.ValidVariableName.UsedPropertyNotSnakeCase -- Data is getting handled on cloud. Hence cannot follow naming convention here.
					case 'T':
						$value = $raw_value;
						break;
					case 'S':
						$value = $raw_value;
						break;
					case 'A':
						$value = ord( substr( $raw_value, 0, 1 ) ) . '.' .
						ord( substr( $raw_value, 1, 1 ) ) . '.' .
						ord( substr( $raw_value, 2, 1 ) ) . '.' .
						ord( substr( $raw_value, 3, 1 ) );
						break;
					case 'I':
						$value = ( ord( substr( $raw_value, 0, 1 ) ) * 256 * 256 * 256 ) +
						( ord( substr( $raw_value, 1, 1 ) ) * 256 * 256 ) +
						( ord( substr( $raw_value, 2, 1 ) ) * 256 ) +
						ord( substr( $raw_value, 3, 1 ) );
						break;
					case 'D':
						$value = null;
						break;
					default:
						$value = null;
				}
			}
			return $value;
		}
	}
}
