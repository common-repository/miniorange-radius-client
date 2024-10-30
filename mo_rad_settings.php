<?php //phpcs:ignore WordPress.Files.FileName.NotHyphenatedLowercase, WordPress.Files.FileName.InvalidClassFileName  -- Could not change its file name as it would create issue for the customers while updating the plugin.
//phpcs:ignore WPShield_Standard.Security.DisallowBrandAndImproperPluginName.ImproperPluginName -- Could not change its file name as it would create issue for the customers while updating the plugin.
/**
 * Main plugin settings file for miniOrange Radius plugin
 *
 * @package miniOrange Radius Client
 */

/**
 * Plugin Name: Radius client (Radius login)
 * Plugin URI: https://xecurify.com
 * Description: Radius client plugin allows login or authentication with Radius Server
 * Version: 2.2
 * Author: miniOrange
 * Author URI: https://xecurify.com
 * License: MIT/Expat
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

require 'mo-rad-settings-page.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'autoload.php';
require_once __DIR__ . DIRECTORY_SEPARATOR . 'includes' . DIRECTORY_SEPARATOR . 'class-mo-rad-database.php';
require 'class-mo-radius-customer.php';
define( 'MORAD_VERSION', '2.2' );

if ( ! class_exists( 'Mo_Rad_Client_Class' ) ) {
	/**
	 * Main class file
	 *
	 * @package  miniorange-radius-client
	 */
	class Mo_Rad_Client_Class {

		/**
		 * Constructor Class
		 */
		public function __construct() {
			add_action( 'admin_menu', array( $this, 'mo_radius_menu' ) );
			add_action( 'admin_init', array( $this, 'miniorange_radius_save_settings' ) );
			add_action( 'admin_enqueue_scripts', array( $this, 'mo_radius_plugin_settings_style' ) );
			add_action( 'admin_enqueue_scripts', array( $this, 'mo_radius_plugin_settings_script' ) );
			register_activation_hook( __FILE__, array( $this, 'mo_radius_activate' ) );
			register_deactivation_hook( __FILE__, array( $this, 'mo_radius_deactivate' ) );
			remove_action( 'admin_notices', array( $this, 'mo_radius_success_message' ) );
			remove_action( 'admin_notices', array( $this, 'mo_radius_error_message' ) );

			if ( (int) get_option( 'mo_radius_enable_login' ) === 1 ) {
				remove_filter( 'authenticate', 'wp_authenticate_username_password', 20, 3 );
				add_filter( 'authenticate', array( $this, 'mo_rad_login' ), 20, 3 );
			}
		}

		/**
		 * Prompts success message
		 *
		 * @return void
		 */
		public function mo_radius_success_message() {
			$class   = 'error';
			$message = get_option( 'mo_rad_message' );
			echo "<div class='" . esc_attr( $class ) . "'> <p>" . esc_html( $message ) . '</p></div>';
		}
		/**
		 * Prompts error message
		 *
		 * @return void
		 */
		public function mo_radius_error_message() {
			$class   = 'updated';
			$message = get_option( 'mo_rad_message' );
			echo "<div class='" . esc_attr( $class ) . "'><p>" . esc_html( $message ) . '</p></div>';
		}

		/**
		 * Calls after activation hook
		 *
		 * @return void
		 */
		public function mo_radius_activate() {
			update_option( 'host_name', 'https://login.xecurify.com' );
		}

		/**
		 * Calls after deactivate hook
		 *
		 * @return void
		 */
		public function mo_radius_deactivate() {
			delete_option( 'mo_rad_message' );
			delete_option( 'host_name' );
			delete_option( 'mo_radius_admin_customer_key' );
			delete_option( 'mo_radius_admin_api_key' );
			delete_option( 'customer_token' );
			delete_option( 'password' );
			delete_option( 'verify_customer' );
			delete_option( 'new_registration' );
			delete_option( 'mo_oauth_show_mo_radius_server_message' );
			delete_option( 'mo_radius_admin_email' );
			delete_option( 'mo_radius_server_name' );
			delete_option( 'mo_radius_server_host' );
			delete_option( 'mo_radius_server_port' );
			delete_option( 'mo_radius_shared_secret' );
			delete_option( 'mo_radius_auth_scheme' );
			delete_option( 'mo_radius_find_user_by' );
			delete_option( 'mo_radius_auto_create_user' );
			delete_option( 'mo_radius_enable_login' );
		}

		/**
		 * Add miniOrange plugin to the menu.
		 *
		 * @return void
		 */
		public function mo_radius_menu() {

			$acc_tab_name = 'Account Setup';
			if ( mo_radius_is_customer_registered() ) {
				$acc_tab_name = 'User Profile';
			}
			$tab_name = $acc_tab_name;
			if ( isset( $_GET['page'] ) && 'mo_radius_settings' === sanitize_text_field( wp_unslash( $_GET['page'] ) ) ) { //phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Reading GET parameter from the URL for checking the tab name, doesn't require nonce verification.
				$tab_name = 'Configure Radius';
			}
			if ( isset( $_GET['page'] ) && 'mo_radius_support' === sanitize_text_field( wp_unslash( $_GET['page'] ) ) ) { //phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Reading GET parameter from the URL for checking the tab name, doesn't require nonce verification.
				$tab_name = 'Support';
			}
			if ( isset( $_GET['page'] ) && 'mo_radius_licence' === sanitize_text_field( wp_unslash( $_GET['page'] ) ) ) { //phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Reading GET parameter from the URL for checking the tab name, doesn't require nonce verification.
				$tab_name = 'Upgrade Plan';
			}
			add_menu_page( 'miniOrange Radius Client' . __( 'Configure Radius', 'mo_radius_setting' ), 'miniOrange Radius Client', 'administrator', 'mo_radius_setting', array( $this, 'mo_radius_login_options' ), plugin_dir_url( __FILE__ ) . 'resource/images/xecurify.png' );
			add_submenu_page( 'mo_radius_setting', $tab_name . ' - miniOrange Radius Client', 'Configure Radius', 'administrator', 'mo_radius_settings', array( $this, 'mo_radius_login_options' ) );
			add_submenu_page( 'mo_radius_setting', $tab_name . ' - miniOrange Radius Client', 'Support', 'administrator', 'mo_radius_support', array( $this, 'mo_radius_login_options' ) );
			add_submenu_page( 'mo_radius_setting', $tab_name . ' - miniOrange Radius Client', 'Upgrade Plan', 'administrator', 'mo_radius_licence', array( $this, 'mo_radius_login_options' ) );
			add_submenu_page( 'mo_radius_setting', $acc_tab_name . ' - miniOrange Radius Client', $acc_tab_name, 'administrator', 'mo_radius_account_setup', array( $this, 'mo_radius_login_options' ) );
			remove_submenu_page( 'mo_radius_setting', 'mo_radius_setting' );
		}

		/**
		 * Display Login options
		 *
		 * @return void
		 */
		public function mo_radius_login_options() {
			mo_radius_register();
		}

		/**
		 * Enqueues CSS files
		 *
		 * @return void
		 */
		public function mo_radius_plugin_settings_style() {
			wp_enqueue_style( 'mo_radius_admin_settings_style', plugins_url( 'resource/css/style_settings.min.css', __FILE__ ), '', MORAD_VERSION );
			wp_enqueue_style( 'mo_radius_phone_style', plugins_url( 'resource/css/phone.min.css', __FILE__ ), '', MORAD_VERSION );
		}

		/**
		 * Enqueues plugin JS files
		 *
		 * @return void
		 */
		public function mo_radius_plugin_settings_script() {
			wp_enqueue_script( 'jquery' );
			wp_enqueue_script( 'mo_radius_phone_script', plugins_url( 'resource/js/phone.min.js', __FILE__ ), '', MORAD_VERSION, false );
		}

		/**
		 * Shows success notice message
		 *
		 * @return void
		 */
		private function mo_radius_show_success_message() {
			remove_action( 'admin_notices', array( $this, 'mo_radius_success_message' ) );
			add_action( 'admin_notices', array( $this, 'mo_radius_error_message' ) );
		}

		/**
		 * Shows error notice message
		 *
		 * @return void
		 */
		private function mo_radius_show_error_message() {
			remove_action( 'admin_notices', array( $this, 'mo_radius_error_message' ) );
			add_action( 'admin_notices', array( $this, 'mo_radius_success_message' ) );
		}

		/**
		 * Save account miniOrange account related settings
		 *
		 * @return void|error
		 */
		public function miniorange_radius_save_settings() {

			if ( current_user_can( 'manage_options' ) && isset( $_POST['option'] ) ) {

				$obj        = new Mo_Rad_Database();
				$session_id = $obj->create_session();
				$nonce      = isset( $_POST['mo_radius_general_nonce'] ) ? sanitize_key( $_POST['mo_radius_general_nonce'] ) : '';
				if ( ! wp_verify_nonce( $nonce, 'mo-radius-general-nonce' ) ) {
					$error = new WP_Error();
					$error->add( 'empty_username', __( '<strong>ERROR</strong>: Invalid Request.' ) );
					return $error;
				}
				if ( 'mo_oauth_mo_radius_server_message' === sanitize_text_field( wp_unslash( $_POST['option'] ) ) ) {
					update_option( 'mo_oauth_show_mo_radius_server_message', 1 );
					return;
				} elseif ( 'mo_radius_register_customer' === sanitize_text_field( wp_unslash( $_POST['option'] ) ) ) {
					$email            = '';
					$password         = '';
					$confirm_password = '';
					$fname            = '';
					$lname            = '';
					$company          = '';
					if ( empty( $_POST['email'] ) || empty( $_POST['password'] ) || empty( $_POST['confirmPassword'] ) ) {
						update_option( 'mo_rad_message', 'All the fields are required. Please enter valid entries.' );
						$this->mo_radius_show_error_message();
						return;
					} elseif ( strlen( $_POST['password'] ) < 8 || strlen( $_POST['confirmPassword'] ) < 8 ) { //phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Password should not be sanitized.
						update_option( 'mo_rad_message', 'Choose a password with minimum length 8.' );
						$this->mo_radius_show_error_message();
						return;
					} else {
						$email            = sanitize_email( wp_unslash( $_POST['email'] ) );
						$password         = $_POST['password']; //phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Password should not be sanitized.
						$confirm_password = $_POST['confirmPassword']; //phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Password should not be sanitized.
						$fname            = isset( $_POST['fname'] ) ? sanitize_text_field( wp_unslash( $_POST['fname'] ) ) : '';
						$lname            = isset( $_POST['lname'] ) ? sanitize_text_field( wp_unslash( $_POST['lname'] ) ) : '';
						$company          = isset( $_POST['company'] ) ? sanitize_text_field( wp_unslash( $_POST['company'] ) ) : '';
					}

					update_option( 'mo_radius_admin_email', $email );
					update_option( 'mo_radius_admin_fname', $fname );
					update_option( 'mo_radius_admin_lname', $lname );
					update_option( 'mo_radius_admin_company', $company );

					if ( strcmp( $password, $confirm_password ) === 0 ) {
						update_option( 'password', $password );
						$customer = new Mo_Radius_Customer();
						$content  = json_decode( $customer->check_customer(), true );
						if ( strcasecmp( $content['status'], 'CUSTOMER_NOT_FOUND' ) === 0 ) {
							$content = json_decode( $customer->send_otp_token(), true );
							if ( strcasecmp( $content['status'], 'SUCCESS' ) === 0 ) {
								update_option( 'mo_rad_message', ' A one time passcode is sent to ' . get_option( 'mo_radius_admin_email' ) . '. Please enter the OTP here to verify your email.' );
								Mo_Rad_Database::mo_rad_set_transient( $session_id, 'mo_radius_transactionId', sanitize_text_field( wp_unslash( $content['txId'] ) ), 600 );
								update_option( 'mo_radius_registration_status', 'MO_OTP_DELIVERED_SUCCESS' );
								$this->mo_radius_show_success_message();
							} else {
								update_option( 'mo_rad_message', 'There was an error in sending email. Please click on Resend OTP to try again.' );
								update_option( 'mo_radius_registration_status', 'MO_OTP_DELIVERED_FAILURE' );
								$this->mo_radius_show_error_message();
							}
						} else {
							$this->mo_radius_get_current_customer();
						}
					} else {
						update_option( 'mo_rad_message', 'Passwords do not match.' );
						delete_option( 'verify_customer' );
						$this->mo_radius_show_error_message();
					}
				} elseif ( isset( $_POST['option'] ) && 'mo_radius_validate_otp' === sanitize_text_field( wp_unslash( $_POST['option'] ) ) ) {
					// validation and sanitization.
					$otp_token = '';
					if ( empty( $_POST['mo_radius_otp_token'] ) ) {
						update_option( 'mo_rad_message', 'Please enter a value in OTP field.' );
						update_option( 'mo_radius_registration_status', 'MO_OTP_VALIDATION_FAILURE' );
						$this->mo_radius_show_error_message();
						return;
					} else {
						$otp_token = sanitize_text_field( wp_unslash( $_POST['mo_radius_otp_token'] ) );
					}

					$customer       = new Mo_Radius_Customer();
					$transaction_id = Mo_Rad_Database::mo_rad_get_transient( $session_id, 'mo_radius_transactionId' );
					$content        = json_decode( $customer->validate_otp_token( $transaction_id, $otp_token ), true );
					if ( strcasecmp( $content['status'], 'SUCCESS' ) === 0 ) {
						$this->create_customer();
					} else {
						update_option( 'mo_rad_message', 'Invalid one time passcode. Please enter a valid OTP.' );
						update_option( 'mo_radius_registration_status', 'MO_OTP_VALIDATION_FAILURE' );
						$this->mo_radius_show_error_message();
					}
				} elseif ( 'mo_radius_verify_customer' === sanitize_text_field( wp_unslash( $_POST['option'] ) ) ) {
					// validation and sanitization.
					$nonce = isset( $_POST['mo_radius_general_nonce'] ) ? sanitize_key( $_POST['mo_radius_general_nonce'] ) : '';
					if ( ! wp_verify_nonce( $nonce, 'mo-radius-general-nonce' ) ) {
						$error = new WP_Error();
						$error->add( 'empty_username', __( '<strong>ERROR</strong>: Invalid Request.' ) );
						return $error;
					}

					$email    = '';
					$password = '';
					if ( empty( $_POST['email'] ) || empty( $_POST['password'] ) ) {
						update_option( 'mo_rad_message', 'All the fields are required. Please enter valid entries.' );
						$this->mo_radius_show_error_message();
						return;
					} else {
						$email    = isset( $_POST['email'] ) ? sanitize_email( wp_unslash( $_POST['email'] ) ) : '';
						$password = isset( $_POST['password'] ) ? $_POST['password'] : ''; //phpcs:ignore WordPress.Security.ValidatedSanitizedInput.InputNotSanitized, WordPress.Security.ValidatedSanitizedInput.MissingUnslash -- Password should not be sanitized.
					}

					update_option( 'mo_radius_admin_email', $email );
					update_option( 'password', $password );
					$customer     = new Mo_Radius_Customer();
					$content      = $customer->get_customer_key();
					$customer_key = json_decode( $content, true );
					if ( json_last_error() === JSON_ERROR_NONE ) {
						update_option( 'mo_radius_admin_customer_key', $customer_key['id'] );
						update_option( 'mo_radius_admin_api_key', $customer_key['apiKey'] );
						update_option( 'customer_token', $customer_key['token'] );
						delete_option( 'password' );
						update_option( 'mo_rad_message', 'Customer retrieved successfully' );
						delete_option( 'verify_customer' );
						$this->mo_radius_show_success_message();
					} else {
						update_option( 'mo_rad_message', 'Invalid username or password. Please try again.' );
						$this->mo_radius_show_error_message();
					}
				} elseif ( 'mo_radius_add_app' === sanitize_text_field( wp_unslash( $_POST['option'] ) ) ) {
					$radius_name          = isset( $_POST['mo_radius_server_name'] ) ? stripslashes( sanitize_text_field( wp_unslash( $_POST['mo_radius_server_name'] ) ) ) : '';
					$radius_host          = isset( $_POST['mo_radius_server_host'] ) ? stripslashes( sanitize_text_field( wp_unslash( $_POST['mo_radius_server_host'] ) ) ) : '';
					$radius_port          = isset( $_POST['mo_radius_server_port'] ) ? stripslashes( sanitize_text_field( wp_unslash( $_POST['mo_radius_server_port'] ) ) ) : '';
					$radius_shared_secret = isset( $_POST['mo_radius_shared_secret'] ) ? stripslashes( sanitize_key( $_POST['mo_radius_shared_secret'] ) ) : '';
					$auth_scheme          = isset( $_POST['mo_radius_auth_scheme'] ) ? stripslashes( sanitize_text_field( wp_unslash( $_POST['mo_radius_auth_scheme'] ) ) ) : '';
					$find_user_by         = isset( $_POST['mo_radius_find_user_by'] ) ? stripslashes( sanitize_text_field( wp_unslash( $_POST['mo_radius_find_user_by'] ) ) ) : '';
					$auto_create          = isset( $_POST['mo_radius_auto_create_user'] ) ? stripslashes( sanitize_text_field( wp_unslash( $_POST['mo_radius_auto_create_user'] ) ) ) : '';
					update_option( 'mo_radius_server_name', $radius_name );
					update_option( 'mo_radius_server_host', $radius_host );
					update_option( 'mo_radius_server_port', $radius_port );
					update_option( 'mo_radius_shared_secret', $radius_shared_secret );
					update_option( 'mo_radius_auth_scheme', $auth_scheme );
					update_option( 'mo_radius_find_user_by', $find_user_by );
					update_option( 'mo_radius_auto_create_user', $auto_create );

					update_option( 'mo_radius_enable_login', isset( $_POST['mo_radius_enable_login'] ) ? sanitize_text_field( wp_unslash( $_POST['mo_radius_enable_login'] ) ) : 0 );

					update_option( 'mo_rad_message', 'Your settings were saved' );
					$this->mo_radius_show_success_message();
				} elseif ( 'mo_radius_resend_otp' === sanitize_text_field( wp_unslash( $_POST['option'] ) ) ) {
					$customer = new Mo_Radius_Customer();
					$content  = json_decode( $customer->send_otp_token(), true );
					if ( strcasecmp( $content['status'], 'SUCCESS' ) === 0 ) {
						update_option( 'mo_rad_message', ' A one time passcode is sent to ' . get_option( 'mo_radius_admin_email' ) . ' again. Please check if you got the otp and enter it here.' );
						Mo_Rad_Database::mo_rad_set_transient( $session_id, 'mo_radius_transactionId', sanitize_text_field( wp_unslash( $content['txId'] ) ), 600 );
						update_option( 'mo_radius_registration_status', 'MO_OTP_DELIVERED_SUCCESS' );
						$this->mo_radius_show_success_message();
					} else {
						update_option( 'mo_rad_message', 'There was an error in sending email. Please click on Resend OTP to try again.' );
						update_option( 'mo_radius_registration_status', 'MO_OTP_DELIVERED_FAILURE' );
						$this->mo_radius_show_error_message();
					}
				} elseif ( 'mo_radius_change_email' === sanitize_text_field( wp_unslash( $_POST['option'] ) ) ) {
					update_option( 'mo_radius_registration_status', '' );
				} elseif ( 'mo_radius_validate_test' === sanitize_text_field( wp_unslash( $_POST['option'] ) ) ) {
					$mo_radius_username = isset( $_POST['mo_radius_username'] ) ? stripslashes( sanitize_text_field( wp_unslash( $_POST['mo_radius_username'] ) ) ) : '';
					$mo_radius_password = isset( $_POST['mo_radius_password'] ) ? stripslashes( sanitize_text_field( wp_unslash( $_POST['mo_radius_password'] ) ) ) : '';
					$response           = $this->mo_radius_validate_login_data( $mo_radius_username, $mo_radius_password );
					if ( $response ) {
						update_option( 'mo_rad_message', 'Radius client configured successfully' );
						$this->mo_radius_show_success_message();
					} else {
						update_option( 'mo_rad_message', 'Username or password is Incorrect' );
						$this->mo_radius_show_error_message();
					}
				} elseif ( isset( $_POST['option'] ) && 'mo_radius_contact_us' === sanitize_text_field( wp_unslash( $_POST['option'] ) ) ) { // Help me or support.
					$query = '';
					if ( empty( sanitize_email( wp_unslash( $_POST['mo_radius_contact_us_email'] ) ) ) || empty( sanitize_text_field( wp_unslash( $_POST['mo_radius_contact_us_query'] ) ) ) ) {
						update_site_option( 'mo_rad_message', 'Please submit your query with email' );
						$this->mo_radius_show_error_message();
						return;
					} else {
						$query      = isset( $_POST['mo_radius_contact_us_query'] ) ? sanitize_text_field( wp_unslash( $_POST['mo_radius_contact_us_query'] ) ) : '';
						$email      = isset( $_POST['mo_radius_contact_us_email'] ) ? sanitize_email( wp_unslash( $_POST['mo_radius_contact_us_email'] ) ) : '';
						$phone      = isset( $_POST['mo_radius_contact_us_phone'] ) ? sanitize_text_field( wp_unslash( $_POST['mo_radius_contact_us_phone'] ) ) : '';
						$contact_us = new Mo_Radius_Customer();
						$submited   = json_decode( $contact_us->submit_contact_us( $email, $phone, $query ), true );
						if ( json_last_error() === JSON_ERROR_NONE ) {
							if ( is_array( $submited ) && array_key_exists( 'status', $submited ) && 'ERROR' === $submited['status'] ) {
								update_site_option( 'mo_rad_message', $submited['message'] );
								$this->mo_radius_show_error_message();
							} else {
								if ( false === $submited ) {
									update_site_option( 'mo_rad_message', 'Your query could not be submitted. Please try again.' );
									$this->mo_radius_show_error_message();
								} else {
									update_site_option( 'mo_rad_message', 'Thanks for getting in touch! We shall get back to you shortly.' );
									$this->mo_radius_show_success_message();
								}
							}
						}
					}
				}
			}
		}

		/**
		 * Validate Login using radius
		 *
		 * @param object $user - WordPress user object.
		 * @param string $username - WordPress username.
		 * @param string $password - WordPress password.
		 * @return object
		 */
		public function mo_rad_login( $user, $username, $password ) {
			if ( empty( $username ) || empty( $password ) ) {

				$error = new WP_Error();

				if ( empty( $username ) ) { // No email.
					$error->add( 'empty_username', __( '<strong>ERROR</strong>: Email field is empty.' ) );
				}

				if ( empty( $password ) ) {
					$error->add( 'empty_password', __( '<strong>ERROR</strong>: Password field is empty.' ) );
				}
				return $error;
			}

			/**
			 * Validate Login data using Radius
			 */
			$response = $this->mo_radius_validate_login_data( $username, $password );
			$user     = false;
			if ( $response ) {
				$find_user_by = get_option( 'mo_radius_find_user_by' );
				$exists       = $find_user_by . '_exists';
				$attr         = get_option( 'mo_radius_find_user_by' ) === 'username' ? 'login' : get_option( 'mo_radius_find_user_by' );
				if ( $exists( $username ) ) {
					$user = get_user_by( $attr, $username );
				}
				if ( get_option( 'mo_radius_auto_create_user' ) === 'allowed' && ! $user ) {
					$random_password = wp_generate_password( 10, false );
					if ( is_email( $username ) ) {
						$user_id = wp_create_user( $username, $random_password, $username );
					} else {
						$user_id = wp_create_user( $username, $random_password );
					}
					$user = get_user_by( 'login', $username );
				}
			}
			return $user;
		}

		/**
		 * Validate Login data using Radius
		 *
		 * @param string $username - WordPress username.
		 * @param string $password - WordPress password.
		 * @return mixed
		 */
		public function mo_radius_validate_login_data( $username, $password ) {
			$auth_scheme          = get_option( 'mo_radius_auth_scheme' );
			$response             = false;
			$radius_host          = get_option( 'mo_radius_server_host' ) ? get_option( 'mo_radius_server_host' ) : '';
			$radius_port          = get_option( 'mo_radius_server_port' ) ? get_option( 'mo_radius_server_port' ) : '';
			$radius_shared_secret = get_option( 'mo_radius_shared_secret' ) ? get_option( 'mo_radius_shared_secret' ) : '';
			$radius               = new \Dapphp\Radius\Radius();
			if ( isset( $_SERVER['SERVER_ADDR'] ) ) {
				$radius->set_server( $radius_host )->set_secret( $radius_shared_secret )->set_authentication_port( $radius_port )->set_nas_ip_address( sanitize_text_field( wp_unslash( $_SERVER['SERVER_ADDR'] ) ) )->set_attribute( 32, 'miniorange-wordpress' );
			}
			$response = $radius->access_request( $username, $password );
			return $response;
		}

		/**
		 * Get API key and token of miniOrange account
		 *
		 * @return void
		 */
		public function mo_radius_get_current_customer() {
			$customer     = new Mo_Radius_Customer();
			$content      = $customer->get_customer_key();
			$customer_key = json_decode( $content, true );
			if ( json_last_error() === JSON_ERROR_NONE ) {
				update_option( 'mo_radius_admin_customer_key', $customer_key['id'] );
				update_option( 'mo_radius_admin_api_key', $customer_key['apiKey'] );
				update_option( 'customer_token', $customer_key['token'] );
				update_option( 'password', '' );
				update_option( 'mo_rad_message', 'Customer retrieved successfully' );
				delete_option( 'verify_customer' );
				delete_option( 'new_registration' );
				$this->mo_radius_show_success_message();
			} else {
				update_option( 'mo_rad_message', 'You already have an account with xecurify. Please enter a valid password.' );
				update_option( 'verify_customer', 'true' );
				delete_option( 'new_registration' );
				$this->mo_radius_show_error_message();
			}
		}

		/**
		 * Create a user in miniOrange
		 *
		 * @return void
		 */
		public function create_customer() {
			$customer     = new Mo_Radius_Customer();
			$customer_key = json_decode( $customer->create_customer(), true );
			if ( strcasecmp( $customer_key['status'], 'CUSTOMER_USERNAME_ALREADY_EXISTS' ) === 0 ) {
				$this->mo_radius_get_current_customer();
				delete_option( 'mo_radius_new_customer' );
			} elseif ( strcasecmp( $customer_key['status'], 'SUCCESS' ) === 0 ) {
				update_option( 'mo_radius_admin_customer_key', $customer_key['id'] );
				update_option( 'mo_radius_admin_api_key', $customer_key['apiKey'] );
				update_option( 'customer_token', $customer_key['token'] );
				update_option( 'password', '' );
				update_option( 'mo_rad_message', 'Registered successfully.' );
				update_option( 'mo_radius_registration_status', 'MO_OAUTH_REGISTRATION_COMPLETE' );
				update_option( 'mo_radius_new_customer', 1 );
				delete_option( 'verify_customer' );
				delete_option( 'new_registration' );
				$this->mo_radius_show_success_message();
			}
		}
	}
}

new Mo_Rad_Client_Class();
