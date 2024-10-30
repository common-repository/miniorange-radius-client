<?php
/** Copyright (C) 2015  miniOrange
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 * @package         miniOrange Radius Client
 * @license     http://www.gnu.org/copyleft/gpl.html GNU/GPL, see LICENSE.php
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}
if ( ! class_exists( 'Mo_Radius_Customer' ) ) {
	/**
	 * This library is miniOrange Authentication Service.
	 * Contains Request Calls to Customer service.
	 **/
	class Mo_Radius_Customer {


		/**
		 * Email id of user.
		 *
		 * @var $email string.
		 */
		public $email;
		/**
		 * Phone number of user.
		 *
		 * @var int.
		 */
		public $phone;
		/**
		 * Default Customer key of user.
		 *
		 * @var string
		 */
		private $default_customer_key = '16555';
		/**
		 * Default API key.
		 *
		 * @var string
		 */
		private $default_api_key = 'fFd2XcvTGDemZvbw1bcUesNJWEqKbbUq';
		/**
		 * Function to add the customer on miniOrange idp.
		 *
		 * @return string
		 */
		public function create_customer() {
			$url         = get_option( 'host_name' ) . '/moas/rest/customer/add';
			$this->email = get_option( 'mo_radius_admin_email' );
			$this->phone = get_option( 'mo_radius_admin_phone' );
			$password    = get_option( 'password' );
			$first_name  = get_option( 'mo_radius_admin_fname' );
			$last_name   = get_option( 'mo_radius_admin_lname' );
			$company     = get_option( 'mo_radius_admin_company' );

			$fields       = array(
				'companyName'    => $company,
				'areaOfInterest' => 'WP Radius Client',
				'firstname'      => $first_name,
				'lastname'       => $last_name,
				'email'          => $this->email,
				'phone'          => $this->phone,
				'password'       => $password,
			);
			$field_string = wp_json_encode( $fields );
			$headers      = array(
				'Content-Type'  => 'application/json',
				'charset'       => 'UTF-8',
				'Authorization' => 'Basic',
			);
			$response     = $this->make_curl_call( $url, $field_string, $headers );
			return $response;
		}

		/**
		 * Function to get customer key of user.
		 *
		 * @return string
		 */
		public function get_customer_key() {
			$url   = get_option( 'host_name' ) . '/moas/rest/customer/key';
			$email = get_option( 'mo_radius_admin_email' );

			$password = get_option( 'password' );

			$fields       = array(
				'email'    => $email,
				'password' => $password,
			);
			$field_string = wp_json_encode( $fields );

			$headers = array(
				'Content-Type'  => 'application/json',
				'charset'       => 'UTF-8',
				'Authorization' => 'Basic',
			);

			$content = $this->make_curl_call( $url, $field_string, $headers );
			return $content;
		}

		/**
		 * Function to raise support query.
		 *
		 * @param string $email Email id of customer to be sent to the query.
		 * @param int    $phone Phone number of customer to be sent to the query.
		 * @param string $query Query raised by the customer.
		 * @return boolean
		 */
		public function submit_contact_us( $email, $phone, $query ) {
			global $current_user;
			$query        = '[WP Radius Client - V ' . MORAD_VERSION . ']: ' . $query;
			$fields       = array(
				'firstName' => $current_user->user_firstname,
				'lastName'  => $current_user->user_lastname,
				'company'   => sanitize_text_field( isset( $_SERVER['SERVER_NAME'] ) ? wp_unslash( $_SERVER['SERVER_NAME'] ) : '' ),
				'email'     => $email,
				'ccEmail'   => '2fasupport@xecurify.com',
				'phone'     => $phone,
				'query'     => $query,
			);
			$field_string = wp_json_encode( $fields );
			$headers      = array(
				'Content-Type'  => 'application/json',
				'charset'       => 'UTF-8',
				'Authorization' => 'Basic',
			);

			$url          = get_option( 'host_name' ) . '/moas/rest/customer/contact-us';
			$field_string = wp_json_encode( $fields );

			$content = $this->make_curl_call( $url, $field_string, $headers );
			return true;
		}

		/**
		 * Function to send otp to the user via miniOrange service.
		 *
		 * @return string
		 */
		public function send_otp_token() {
			$url          = get_option( 'host_name' ) . '/moas/api/auth/challenge';
			$customer_key = $this->default_customer_key;
			$api_key      = $this->default_api_key;

			$username = get_option( 'mo_radius_admin_email' );

			/* Current time in milliseconds since midnight, January 1, 1970 UTC. */
			$current_time_in_millis = round( microtime( true ) * 1000 );
			$current_time_in_millis = number_format( $current_time_in_millis, 0, '', '' );

			/* Creating the Hash using SHA-512 algorithm */
			$string_to_hash = $customer_key . $current_time_in_millis . $api_key;
			$hash_value     = hash( 'sha512', $string_to_hash );

			$customer_key_header  = 'Customer-Key=> ' . $customer_key;
			$timestamp_header     = 'Timestamp=> ' . $current_time_in_millis;
			$authorization_header = 'Authorization=> ' . $hash_value;

			$fields       = array(
				'customerKey' => $customer_key,
				'email'       => $username,
				'authType'    => 'EMAIL',
			);
			$field_string = wp_json_encode( $fields );
			$headers      = array( 'Content-Type=> application/json', $customer_key_header, $timestamp_header, $authorization_header );
			$content      = $this->make_curl_call( $url, $field_string, $headers );
			return $content;
		}

		/**
		 * Get current Timestamp
		 *
		 * @return int
		 */
		public function get_timestamp() {
			$current_time_in_millis = round( microtime( true ) * 1000 );
			$current_time_in_millis = number_format( $current_time_in_millis, 0, '', '' );

			return $current_time_in_millis;
		}

		/**
		 * Function to validate the otp token.
		 *
		 * @param string $transaction_id Transaction id which is used to validate the sent otp token.
		 * @param string $otp_token OTP token received by user.
		 * @return string
		 */
		public function validate_otp_token( $transaction_id, $otp_token ) {
			$url = get_option( 'host_name' ) . '/moas/api/auth/validate';

			$customer_key = $this->default_customer_key;
			$api_key      = $this->default_api_key;

			$username = get_option( 'mo_radius_admin_email' );

			/* Current time in milliseconds since midnight, January 1, 1970 UTC. */
			$current_time_in_millis = round( microtime( true ) * 1000 );
			$current_time_in_millis = number_format( $current_time_in_millis, 0, '', '' );

			/* Creating the Hash using SHA-512 algorithm */
			$string_to_hash = $customer_key . $current_time_in_millis . $api_key;
			$hash_value     = hash( 'sha512', $string_to_hash );

			$customer_key_header  = 'Customer-Key=> ' . $customer_key;
			$timestamp_header     = 'Timestamp=> ' . $current_time_in_millis;
			$authorization_header = 'Authorization=> ' . $hash_value;

			$fields = '';

			// *check for otp over sms/email
			$fields = array(
				'txId'  => $transaction_id,
				'token' => $otp_token,
			);

			$field_string = wp_json_encode( $fields );

			$headers = array( 'Content-Type=> application/json', $customer_key_header, $timestamp_header, $authorization_header );
			$content = $this->make_curl_call( $url, $field_string, $headers );
			return $content;
		}

		/**
		 * Function to check if customer exists or not.
		 *
		 * @return string
		 */
		public function check_customer() {
			$url          = get_option( 'host_name' ) . '/moas/rest/customer/check-if-exists';
			$email        = get_option( 'mo_radius_admin_email' );
			$fields       = array(
				'email' => $email,
			);
			$field_string = wp_json_encode( $fields );

			$headers = array(
				'Content-Type'  => 'application/json',
				'charset'       => 'UTF-8',
				'Authorization' => 'Basic',
			);

			$response = $this->make_curl_call( $url, $field_string );
			return $response;
		}

		/**
		 * The api function will be called for curl
		 *
		 * @param string $url - remote call URL.
		 * @param string $fields - fields.
		 * @param array  $http_header_array - header array.
		 * @return string
		 */
		public function make_curl_call( $url, $fields, $http_header_array = array(
			'Content-Type'  => 'application/json',
			'charset'       => 'UTF-8',
			'Authorization' => 'Basic',
		) ) {

			if ( gettype( $fields ) !== 'string' ) {
				$fields = wp_json_encode( $fields );
			}

			$args = array(
				'method'      => 'POST',
				'body'        => $fields,
				'timeout'     => '5',
				'redirection' => '5',
				'sslverify'   => true,
				'httpversion' => '1.0',
				'blocking'    => true,
				'headers'     => $http_header_array,
			);

			$response = $this->mo_radius_wp_remote_post( $url, $args );
			return $response;
		}
		/**
		 * This function perform remote calls using 'wp_remote_post'.
		 *
		 * @param string $url - url.
		 * @param array  $args - arguments.
		 * @return mixed
		 */
		public function mo_radius_wp_remote_post( $url, $args = array() ) {
			$response = wp_remote_post( $url, $args );
			if ( ! is_wp_error( $response ) ) {
				return $response['body'];
			} else {
				$message = 'Please enable curl extension.';

				return wp_json_encode(
					array(
						'status'  => 'ERROR',
						'message' => $message,
					)
				);
			}
		}
	}
}
