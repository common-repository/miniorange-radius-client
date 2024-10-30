<?php
/**
 * Called upon deletion of the plugin
 *
 * @package miniorange-radius-client
 */

if ( ! defined( 'WP_UNINSTALL_PLUGIN' ) ) {
	exit();
}

	delete_option( 'mo_radius_message' );
	delete_option( 'host_name' );
	delete_option( 'mo_radius_admin_customer_key' );
	delete_option( 'mo_radius_admin_api_key' );
	delete_option( 'customer_token' );
	delete_option( 'password' );
	delete_option( 'mo_rad_message' );
	delete_option( 'verify_customer' );
	delete_option( 'new_registration' );
	delete_option( 'mo_oauth_show_mo_radius_server_message' );
	delete_option( 'mo_radius_enable_login' );
