<?php
/**
 * Contains UI for Radius configuration Settings page
 *
 * @package miniorange-radius-client
 */

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}

/**
 * Display Radius configuration Settings page
 *
 * @return void
 */
function mo_radius_register() {
	$currenttab = isset( $_GET['page'] ) ? sanitize_text_field( wp_unslash( $_GET['page'] ) ) : ''; //phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Reading GET parameter from the URL for checking the tab name, doesn't require nonce verification.
	?>
	<div style="margin-right: 10px; 
	<?php
	if ( 'mo_radius_settings' !== $currenttab ) {
		echo 'width: 75%;';
	}
	?>
	">
		<?php
		if ( ! get_option( 'mo_oauth_show_mo_radius_server_message' ) ) {
			?>
			<form name="f" method="post" action="" id="mo_radius_server_form">
				<input type="hidden" name="option" value="mo_oauth_mo_radius_server_message" />
				<input type="hidden" name="mo_radius_general_nonce" value="<?php echo esc_attr( wp_create_nonce( 'mo-radius-general-nonce' ) ); ?>" />
				<div class="notice notice-info" style="padding-right: 38px;position: relative;">
					<h4>Secure your WordPress site with 2FA on top of single sign-on using miniOrange On-Premise IDP. You can also protect any VPN, Remote Desktop, Windows with 2FA using our <a href="http://idp.xecurify.com/" target="_blank">Cloud Service/On-Premise Module</a>.</h4>
					<button type="button" class="notice-dismiss" id="mo_radius_server"><span class="screen-reader-text">Dismiss this notice.</span>
					</button>
				</div>
			</form>
			<?php
		}
		?>
		<div id="tab">
			<h2 class="nav-tab-wrapper">
				<?php
				$tab_array = array(
					'mo_radius_settings'      => 'Configure Radius',
					'mo_radius_support'       => 'Support',
					'mo_radius_licence'       => 'Upgrade Plan',
					'mo_radius_account_setup' => mo_radius_is_customer_registered() ? 'User Profile' : 'Account Setup',
				);
				foreach ( $tab_array as $tab_name => $display_name ) {
					echo "
					<a class='nav-tab";
					if ( $tab_name === $currenttab ) {
						echo " nav-tab-active'";
					} else {
						echo "'";
					}
					echo ' href="' . esc_attr( 'admin.php?page=' . $tab_name ) . '">' . esc_attr( $display_name ) . '</a>';
				}
				?>
			</h2>
		</div>

		<?php
		if ( 'mo_radius_account_setup' === $currenttab ) {
			$tab = isset( $_GET['tab'] ) ? sanitize_text_field( wp_unslash( $_GET['tab'] ) ) : '';//phpcs:ignore WordPress.Security.NonceVerification.Recommended -- Reading GET parameter from the URL for checking the tab name, doesn't require nonce verification.
			if ( mo_radius_is_customer_registered() ) {
				mo_radius_show_user_profile_page();
			} elseif ( 'login_page' === $tab ) {
				mo_radius_show_verify_password_page();
			} elseif ( get_option( 'mo_radius_registration_status' ) === 'MO_OTP_DELIVERED_SUCCESS' || get_option( 'mo_radius_registration_status' ) === 'MO_OTP_VALIDATION_FAILURE' ) {
				mo_radius_show_otp_verification();
			} elseif ( ! mo_radius_is_customer_registered() ) {
				delete_option( 'password_mismatch' );
				mo_radius_show_new_registration_page();
			}
		} elseif ( 'mo_radius_settings' === $currenttab ) {
			mo_radius_apps_config();
		} elseif ( 'mo_radius_support' === $currenttab ) {
			mo_radius_support();
		} elseif ( 'mo_radius_licence' === $currenttab ) {
			mo_radius_licencing_page();
		}
		?>
	</div>
	<?php
}

/**
 * Save seetings regarding radius App.
 *
 * @return void
 */
function mo_radius_apps_config() {
	global $current_user;
	$email                = get_option( 'mo_radius_admin_email' ) ? get_option( 'mo_radius_admin_email' ) : $current_user->data->user_email;
	$radius_name          = get_option( 'mo_radius_server_name' ) ? get_option( 'mo_radius_server_name' ) : '';
	$radius_host          = get_option( 'mo_radius_server_host' ) ? get_option( 'mo_radius_server_host' ) : '';
	$radius_port          = get_option( 'mo_radius_server_port' ) ? get_option( 'mo_radius_server_port' ) : '';
	$radius_shared_secret = get_option( 'mo_radius_shared_secret' ) ? get_option( 'mo_radius_shared_secret' ) : '';
	$auth_scheme          = get_option( 'mo_radius_auth_scheme' ) ? get_option( 'mo_radius_auth_scheme' ) : 'PAP';
	$find_user_by         = get_option( 'mo_radius_find_user_by' ) ? get_option( 'mo_radius_find_user_by' ) : 'username';
	$auto_create          = get_option( 'mo_radius_auto_create_user' ) ? get_option( 'mo_radius_auto_create_user' ) : 'allowed';
	?>
	<div class="mo_table_layout">
		<div id="toggle2" class="panel_toggle">
			<h3>Configure Application</h3>
		</div>
		<form id="form-common" name="form-common" method="post" action="">
		<input type="hidden" name="mo_radius_general_nonce" value="<?php echo esc_attr( wp_create_nonce( 'mo-radius-general-nonce' ) ); ?>" />
			<input type="hidden" name="option" value="mo_radius_add_app" />
			<table class="mo_settings_table">
				<tr>
					<td colspan="2" style="padding-left: 15px;">
						<input type="checkbox" name="mo_radius_enable_login" value="1" <?php checked( (int) get_option( 'mo_radius_enable_login' ) === 1 ); ?> /> <strong>Enable Radius login</strong>
					</td>
				</tr>
				<tr>
					<td colspan="2" style="padding-left: 15px;">
						Enabling Radius login will protect your login page by your configured Radius server. Please test if radius login works with your administrator account in another browser or private windows first as <span style="color:red">your default WordPress login will stop working.</span><br><br>
					</td>

				</tr>

				<tr>
					<td><strong>
							<span class="mo_rad_font_color_asterisk">*</span>Radius Name:
						</strong></td>
					<td><input class="mo_table_textbox" required="" type="text" name="mo_radius_server_name" value="<?php echo esc_attr( $radius_name ); ?>" placeholder="Radius server name"></td>
				</tr>

				<tr>
					<td><strong>
							<span class="mo_rad_font_color_asterisk">*</span>Radius Server IP / Host:
						</strong></td>
					<td><input class="mo_table_textbox" required="" type="text" name="mo_radius_server_host" value="<?php echo esc_attr( $radius_host ); ?>" placeholder="Radius server host or IP"></td>
				</tr>

				<tr>
					<td><strong>
							<span class="mo_rad_font_color_asterisk">*</span>Radius Port:
						</strong></td>
					<td><input class="mo_table_textbox" required="" type="text" name="mo_radius_server_port" value="<?php echo esc_attr( $radius_port ); ?>" placeholder="Radius port number e.g. 1812"></td>
				</tr>

				<tr>
					<td><strong>
							<span class="mo_rad_font_color_asterisk">*</span>Shared Secret:
						</strong></td>
					<td><input class="mo_table_textbox" required="" type="password" name="mo_radius_shared_secret" value="<?php echo esc_attr( $radius_shared_secret ); ?>" placeholder="Shared secret"></td>
				</tr>


				<tr>
					<td>&nbsp;</td>
					<td></td>
				</tr>

				<tr>
					<td><strong>
							<span class="mo_rad_font_color_asterisk">*</span>Authentication Scheme:
						</strong></td>
					<td>
						<table style="width:100%">
							<tr>
								<td style="min-width:30%"><input class="mo_table_textbox" 
								<?php
								if ( 'PAP' === $auth_scheme ) {
									echo 'checked';
								}
								?>
								type="radio" name="mo_radius_auth_scheme" value="PAP"> PAP Authentication</td>
								<td><input class="mo_table_textbox" disabled type="radio" name="mo_radius_auth_scheme" value=""> CHAP-MD5 Authentication <span class="mo_red">[premium]</span></td>
							</tr>
							<tr>
								<td><input class="mo_table_textbox" disabled type="radio" name="mo_radius_auth_scheme" value=""> MSCHAP v1 Authentication <span class="mo_red">[premium]</span></td>
								<td><input class="mo_table_textbox" disabled type="radio" name="mo_radius_auth_scheme" value=""> EAP-MSCHAP v2 Authentication <span class="mo_red">[premium]</span></td>
							</tr>
						</table>
					</td>
				</tr>


				<tr>
					<td>&nbsp;</td>
					<td></td>
				</tr>

				<tr>
					<td><strong>
							<span class="mo_rad_font_color_asterisk">*</span>Attribute Mapping:
						</strong></td>
					<td>
						<input class="mo_table_textbox" 
						<?php
						if ( 'username' === $find_user_by ) {
							echo 'checked';
						}
						?>
						type="radio" name="mo_radius_find_user_by" value="username"> Username &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
						<input class="mo_table_textbox" 
						<?php
						if ( 'email' === $find_user_by ) {
							echo 'checked';
						}
						?>
						type="radio" name="mo_radius_find_user_by" value="email"> Email &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
						<input class="mo_table_textbox" disabled type="radio" name="mo_radius_find_user_by" value=""> Both <span class="mo_red">[premium]</span>
						<br>Radius username will be matched with WordPress username or email or both.
					</td>
				</tr>


				<tr>
					<td>&nbsp;</td>
					<td></td>
				</tr>

				<tr>
					<td><strong>
							<span class="mo_rad_font_color_asterisk">*</span>Auto Create Users:
						</strong></td>
					<td>
						<input class="mo_table_textbox" 
						<?php
						if ( 'allowed' === $auto_create ) {
							echo 'checked';
						}
						?>
						type="radio" name="mo_radius_auto_create_user" value="allowed"> Allowed &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
						<input class="mo_table_textbox" 
						<?php
						if ( 'notallowed' === $auto_create ) {
							echo 'checked';
						}
						?>
						type="radio" name="mo_radius_auto_create_user" value="notallowed"> Not Allowed
						<br>If you enable this, we will auto create users for successful authentications if users not already exist in WordPress.
					</td>
				</tr>



				<tr>
					<td>&nbsp;</td>
					<td></td>
				</tr>

				<tr>
					<td>&nbsp;</td>
					<td>
						<input type="submit" name="submit" value="Save settings" class="button button-primary button-large" />
						<input type="button" name="test" id="radius_test_config" value="Test configuration" class="button button-primary button-large" />
					</td>
				</tr>
			</table>
		</form>
		<div hidden="hidden" id="radius_test_config_view" class="mo_radius_test_backdrop">
			<div class="mo_radius_test">
				<h3>Test Radius Configuration</h3>
				<div>
					<form method="post" action="">
					<input type="hidden" name="mo_radius_general_nonce" value="<?php echo esc_attr( wp_create_nonce( 'mo-radius-general-nonce' ) ); ?>" />
						<input type="hidden" name="option" value="mo_radius_validate_test">
						<table class="mo_radius_test_table">
							<tbody>
								<tr>
									<td>
										Radius Username or Email:
									</td>
									<td><input type="text" name="mo_radius_username" value="<?php echo esc_attr( $email ); ?>"></td>
								</tr>
								<tr>
									<td>
										Radius Password:
									</td>
									<td><input type="password" name="mo_radius_password" style="width: 80%;"></td>
								</tr>
								<tr>
									<td></td>
									<td>
										<input type="submit" name="validate" value="Validate" class="button button-primary">
										<input type="button" name="close" id="radius_test_config_close" value="Close" class="button button-primary" style="float: right;margin-right: 100px;">
									</td>
								</tr>
							</tbody>
						</table>
					</form>
				</div>
			</div>
		</div>
		<script type="text/javascript">
			if (jQuery('input[name="mo_radius_server_name"]').val() == '' || jQuery('input[name="mo_radius_server_host"]').val() == '' || jQuery('input[name="mo_radius_server_port"]').val() == '' || jQuery('input[name="mo_radius_shared_secret"]').val() == '') {
				jQuery('#radius_test_config').attr('disabled', 'disabled');
			}
			jQuery('#radius_test_config').click(function() {
				jQuery('#radius_test_config_view').show();
			})
			jQuery('#radius_test_config_close').click(function() {
				jQuery('#radius_test_config_view').hide();
			})
		</script>
		<br>
		<p>If you need any support/have specific feature request, please submit a query using support form or reach us at <b><a href="mailto:info@xecurify.com">info@xecurify.com</a></b>.</p>
	</div>
	<?php

}

/**
 * Check if customer is registered on miniOrange.
 *
 * @return int
 */
function mo_radius_is_customer_registered() {
	$email        = get_option( 'mo_radius_admin_email' );
	$customer_key = get_option( 'mo_radius_admin_customer_key' );
	if ( ! $email || ! $customer_key || ! is_numeric( trim( $customer_key ) ) ) {
		return 0;
	} else {
		return 1;
	}
}

/**
 * Display miniOrange account registration page.
 *
 * @return void
 */
function mo_radius_show_new_registration_page() {
	update_option( 'new_registration', 'true' );
	$server_name = isset( $_SERVER['SERVER_NAME'] ) ? sanitize_text_field( wp_unslash( $_SERVER['SERVER_NAME'] ) ) : '';
	global $current_user;
	$email = get_option( 'mo_radius_admin_email' ) ? get_option( 'mo_radius_admin_email' ) : $current_user->data->user_email;
	?>
	<form name="f" method="post" action="">
		<input type="hidden" name="option" value="mo_radius_register_customer" />
		<input type="hidden" name="mo_radius_general_nonce" value="<?php echo esc_attr( wp_create_nonce( 'mo-radius-general-nonce' ) ); ?>" />
		<div class="mo_table_layout">
			<div id="toggle1" class="panel_toggle">
				<h3>Register with miniOrange</h3>
			</div>
			<div id="panel1">
				<p>Please enter a valid Email ID that you have access to.
				</p>
				<table class="mo_settings_table">
					<tr>
						<td><b>
								<span class="mo_rad_font_color_asterisk">*</span>Email:
							</b></td>
						<td><input class="mo_table_textbox" type="email" name="email" required placeholder="person@example.com" value="<?php echo esc_attr( $email ); ?>" />
						</td>
					</tr>
					<tr class="hidden">
						<td><b>
								<span class="mo_rad_font_color_asterisk">*</span>Website/Company Name:
							</b></td>
						<td><input class="mo_table_textbox" type="text" name="company" required placeholder="Enter website or company name" value="<?php echo esc_attr( $server_name ); ?>" /></td>
					</tr>
					<tr class="hidden">
						<td><b>&nbsp;&nbsp;First Name:</b></td>
						<td><input class="" type="text" name="fname" placeholder="Enter first name" value="<?php echo esc_attr( $current_user->user_firstname ); ?>" /></td>
					</tr>
					<tr class="hidden">
						<td><b>&nbsp;&nbsp;Last Name:</b></td>
						<td><input class="" type="text" name="lname" placeholder="Enter last name" value="<?php echo esc_attr( $current_user->user_lastname ); ?>" /></td>
					</tr>

					<tr class="hidden">
						<td><b>&nbsp;&nbsp;Phone number :</b></td>
						<td><input class="mo_table_textbox" type="text" name="phone" pattern="[\+]?([0-9]{1,4})?\s?([0-9]{7,12})?" id="phone" title="Phone with country code eg. +1xxxxxxxxxx" placeholder="Phone with country code eg. +1xxxxxxxxxx" value="<?php echo esc_attr( get_option( 'mo_radius_admin_phone' ) ); ?>" />
							This is an optional field. We will contact you only if you need support.</td>
					</tr>
					</tr>
					<tr class="hidden">
						<td></td>
						<td>We will call only if you need support.</td>
					</tr>
					<tr>
						<td><b>
								<span class="mo_rad_font_color_asterisk">*</span>Password:
							</b></td>
						<td><input class="mo_table_textbox" required type="password" name="password" placeholder="Choose your password (Min. length 8)" /></td>
					</tr>
					<tr>
						<td><b>
								<span class="mo_rad_font_color_asterisk">*</span>Confirm Password:
							</b></td>
						<td><input class="mo_table_textbox" required type="password" name="confirmPassword" placeholder="Confirm your password" /></td>
					</tr>
					<tr>
						<td>&nbsp;</td>
						<td><br /><input type="submit" name="submit" value="Register" style="width:100px;" class="button button-primary button-large" /></td>
					</tr>
					<tr>
						<td></td>
						<td>
							<p><b>Already have an account? <a href="admin.php?page=mo_radius_account_setup&amp;tab=login_page">Login Here</a></b></p>
						</td>
					</tr>
				</table>

			</div>
		</div>
	</form>
	<script>
		jQuery("#phone").mo_radius_intlTelInput();
	</script>
	<?php
}

/**
 * Display verify miniOrange password page.
 *
 * @return void
 */
function mo_radius_show_verify_password_page() {
	global $current_user;
	$email = get_option( 'mo_radius_admin_email' ) ? get_option( 'mo_radius_admin_email' ) : $current_user->data->user_email;
	?>
	<form name="f" method="post" action="">
		<input type="hidden" name="option" value="mo_radius_verify_customer" />
		<input type="hidden" name="mo_radius_general_nonce" value="<?php echo esc_attr( wp_create_nonce( 'mo-radius-general-nonce' ) ); ?>" />
		<div class="mo_table_layout">
			<div id="toggle1" class="panel_toggle">
				<h3>Login with miniOrange</h3>
			</div>
			<div id="panel1">
				</p>
				<table class="mo_settings_table">
					<tr>
						<td><b>
								<span class="mo_rad_font_color_asterisk">*</span>Email:
							</b></td>
						<td><input class="mo_table_textbox" type="email" name="email" required placeholder="person@example.com" value="<?php echo esc_attr( $email ); ?>" /></td>
					</tr>
					<tr>
						<td><b>
								<span class="mo_rad_font_color_asterisk">*</span>Password:
							</b></td>
						<td><input class="mo_table_textbox" required type="password" name="password" placeholder="Choose your password" /></td>
					</tr>
					<tr>
						<td></td>
						<td><br>
							<div class="mo_table_textbox">
								<div style="display: inline-table; width: 50%;"><input type="submit" name="submit" value="Login" class="button button-primary button-large" /></div>
								<div style="display: inline-table; width: 50%;"><b>Forgot your password? <a target="_blank" href="<?php echo esc_url( get_option( 'host_name' ) . '/moas/idp/resetpassword' ); ?>">Reset Password</a></b></div>
							</div>
						</td>
					</tr>
					<tr>
						<td></td>
						<td>
							<p><b>Don't have account? <a href="admin.php?page=mo_radius_account_setup">Register Here</a></b></p>
						</td>
					</tr>
				</table>
			</div>
		</div>
	</form>
	<?php
}

/**
 * Display miniOrnage user Profile page
 *
 * @return void
 */
function mo_radius_show_user_profile_page() {
	?>
	<form name="f" method="post" action="">
		<div class="mo_table_layout">
			<div id="toggle1" class="panel_toggle">
				<h3>Your Profile</h3>
				<p>Your profile details are given below.</p>
			</div>
			<div id="panel2" class="mo_radius_div_profile">
				</p>
				<table border="1" class="mo_radius_table_profile">
					<tbody>
						<tr>
							<td><b>Email:</b></td>
							<td><?php echo esc_html( get_option( 'mo_radius_admin_email' ) ); ?></td>
						</tr>
						<tr>
							<td><b>Customer Key:</b></td>
							<td><?php echo esc_html( get_option( 'mo_radius_admin_customer_key' ) ); ?></td>
						</tr>
						<tr>
							<td colspan="2"><b>Forgot your password? <a target="_blank" href="<?php echo esc_url( get_option( 'host_name' ) . '/moas/idp/resetpassword' ); ?>">Reset Password</a></b></td>
						</tr>
					</tbody>
				</table>
				<p>If you are facing any issues, please submit a query using support form or reach us at <b><a href="mailto:info@xecurify.com">info@xecurify.com</a></b>.</p>
			</div>
		</div>
	</form>
	<?php
}

/**
 * Display OTP verifiation page
 *
 * @return void
 */
function mo_radius_show_otp_verification() {
	?>
	<form name="f" method="post" id="otp_form" action="">
		<input type="hidden" name="option" value="mo_radius_validate_otp" />
		<input type="hidden" name="mo_radius_general_nonce" value="<?php echo esc_attr( wp_create_nonce( 'mo-radius-general-nonce' ) ); ?>" />
		<div class="mo_table_layout">
			<div id="panel5">
				<table class="mo_settings_table">
					<h3>Verify Your Email</h3>
					<tr>
						<td><b>
								<span class="mo_rad_font_color_asterisk">*</span>Enter OTP:
							</b></td>
						<td><input class="mo_table_textbox" autofocus="true" type="text" name="mo_radius_otp_token" required placeholder="Enter OTP" style="width:61%;" pattern="[0-9]{6,8}" />
							&nbsp;&nbsp;<a style="cursor:pointer;" onclick="document.getElementById('mo_radius_resend_otp_form').submit();">Resend OTP</a></td>
					</tr>
					<tr>
						<td>&nbsp;</td>
						<td><br /><input type="submit" name="submit" value="Validate OTP" class="button button-primary button-large" />
							&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;
							<input type="button" name="back-button" id="mo_radius_back_button" onclick="document.getElementById('mo_radius_change_email_form').submit();" value="Back" class="button button-primary button-large" />
						</td>
					</tr>
				</table>
			</div>
		</div>
	</form>
	<form name="f" id="mo_radius_resend_otp_form" method="post" action="">
		<input type="hidden" name="mo_radius_general_nonce" value="<?php echo esc_attr( wp_create_nonce( 'mo-radius-general-nonce' ) ); ?>" />
		<input type="hidden" name="option" value="mo_radius_resend_otp" />
	</form>
	<form id="mo_radius_change_email_form" method="post" action="">
		<input type="hidden" name="mo_radius_general_nonce" value="<?php echo esc_attr( wp_create_nonce( 'mo-radius-general-nonce' ) ); ?>" />
		<input type="hidden" name="option" value="mo_radius_change_email" />
	</form>
	<?php
}

/**
 * Display Support form.
 *
 * @return void
 */
function mo_radius_support() {
	global $current_user;
	$email = get_option( 'mo_radius_admin_email' ) ? get_option( 'mo_radius_admin_email' ) : $current_user->data->user_email;
	?>
	<div class="mo_table_layout">
		<h3>Support</h3>
		<p>Need any help? Just send us a query so we can help you.</p>
		<form method="post" action="">
			<input type="hidden" name="mo_radius_general_nonce" value="<?php echo esc_attr( wp_create_nonce( 'mo-radius-general-nonce' ) ); ?>" />
			<input type="hidden" name="option" value="mo_radius_contact_us" />
			<table class="mo_radius_support_table">
				<tr>
					<td><input type="email" class="mo_radius_table_contact" required placeholder="Enter your Email" name="mo_radius_contact_us_email" value="<?php echo esc_attr( $email ); ?>"></td>
				</tr>
				<tr>
					<td><input type="tel" id="contact_us_phone" placeholder="Enter your phone number with country code (+1)" class="mo_radius_table_contact" name="mo_radius_contact_us_phone"></td>
				</tr>
				<tr>
					<td><textarea class="mo_radius_table_contact" onkeypress="mo_radius_valid_query(this)" onkeyup="mo_radius_valid_query(this)" placeholder="Write your query here" onblur="mo_radius_valid_query(this)" required name="mo_radius_contact_us_query" rows="4" style="resize: vertical;"></textarea></td>
				</tr>
			</table>
			<br>
			<input type="submit" name="submit" value="Submit Query" style="width:110px;" class="button button-primary button-large" />
		</form>
		<p>If you need any help/want custom features in the plugin, submit a request using support form or just drop an email to <b><a href="mailto:info@xecurify.com">info@xecurify.com</a></b>.</p>
	</div>
	<script>
		jQuery("#contact_us_phone").mo_radius_intlTelInput({
			// initialCountry:
		});

		function mo_radius_valid_query(f) {
			!(/^[a-zA-Z?,.\(\)\/@ 0-9]*$/).test(f.value) ? f.value = f.value.replace(/[^a-zA-Z?,.\(\)\/@ 0-9]/, '') : null;
		}

		function moSharingSizeValidate(e) {
			var t = parseInt(e.value.trim());
			t > 60 ? e.value = 60 : 10 > t && (e.value = 10)
		}

		function moSharingSpaceValidate(e) {
			var t = parseInt(e.value.trim());
			t > 50 ? e.value = 50 : 0 > t && (e.value = 0)
		}

		function moLoginSizeValidate(e) {
			var t = parseInt(e.value.trim());
			t > 60 ? e.value = 60 : 20 > t && (e.value = 20)
		}

		function moLoginSpaceValidate(e) {
			var t = parseInt(e.value.trim());
			t > 60 ? e.value = 60 : 0 > t && (e.value = 0)
		}

		function moLoginWidthValidate(e) {
			var t = parseInt(e.value.trim());
			t > 1000 ? e.value = 1000 : 140 > t && (e.value = 140)
		}

		function moLoginHeightValidate(e) {
			var t = parseInt(e.value.trim());
			t > 50 ? e.value = 50 : 35 > t && (e.value = 35)
		}
	</script>
	<?php
}

/**
 * Display Licensing plans
 *
 * @return void
 */
function mo_radius_licencing_page() {
	?>
	<div class="mo_table_layout">
		<h3>Licencing Plan</h3>
		<table border="1" class="mo_radius_table_licence mo_radius_table_profile">
			<thead>
				<tr>
					<th>
						<p style="font-size: medium;">Feature\Plan</p>
					</th>
					<th>
						<p style="font-size: medium;">Free Plan <span style="background-color: #FFFFFF; color: #00bd00;">(Active plan)</span></p>
					</th>
					<th>
						<p style="font-size: medium;">Premium Plan</p>
					</th>
				</tr>
			</thead>
			<tbody>
				<tr>
					<td><b>Pricing</b></td>
					<td style="text-align: center;">
						<p>It is free to use.</p>
						<p><b>Price: $0</b></p>
					</td>
					<td style="text-align: center;">
						<p>You can purchase our premium plan here to avail the premium features.</p>
						<p><b>Price: $249</b></p>
						<button class="button button-primary button-large" onclick="mo_radius_upgrade('wp_radius_client_premium')" 
						<?php
						if ( ! mo_radius_is_customer_registered() ) {
							echo 'disabled';
						}
						?>
																																	>Upgrade to premium</button>
					</td>
				</tr>
				<tr>
					<td><b>Supported Authentication Protocols</b></td>
					<td>
						<ul>
							<li>PAP Authentication</li>
						</ul>
					</td>
					<td>
						<ul>
							<li>PAP Authentication</li>
							<li>CHAP-MD5 Authentication</li>
							<li>MSCHAP v1 Authentication</li>
							<li>EAP-MSCHAP v2 Authentication</li>
						</ul>
					</td>
				</tr>
				<tr>
					<td><b>Attribute mapping for authentication</b></td>
					<td>
						<ul>
							<li>Username</li>
							<li>Email</li>
						</ul>
					</td>
					<td>
						<ul>
							<li>Username</li>
							<li>Email</li>
							<li>Both(Username and Email)</li>
						</ul>
					</td>
				</tr>
			</tbody>
		</table>
		<form>
			<input type="hidden" name="">
		</form>
		<p>
		<dl>
			<dt>
				<b>The acronyms for Radius Authentication Protocol types:</b>
			</dt>
			<dd>
				<div><b>PAP:</b> Password authentication protocol</div>
				<div><b>CHAP:</b> Challenge-Handshake Authentication Protocol</div>
				<div><b>MSCHAP:</b> Microsoft Challenge Handshake Authentication Protocol</div>
				<div><b>EAP-MSCHAP:</b> Extensible Authentication Protocol Microsoft Challenge Handshake Authentication Protocol</div>
			</dd>
		</dl>
		</p>
		<hr>
		<div>
			<h2>Refund Policy</h2>
			<p class="mo2f_licensing_plans_ol">At miniOrange, we want to ensure you would be 100% happy with your purchase. If the premium plugin you purchased is not working as advertised and you've attempted to resolve any issues with our support team, which couldn't get resolved then we will refund the whole amount within 10 days of the purchase.
			</p>
		</div>
		<hr>
		<div>
			<h2>Contact Us</h2>
			<p class="mo2f_licensing_plans_ol">If you have any doubts regarding the licensing plans, submit a query using support form or you can mail us at <b><a href="mailto:info@xecurify.com"><i>info@xecurify.com</i></a></b>.
			</p>
		</div>
		<form class="mo_radius_display_none" id="mo_dashboard_login" action="<?php echo esc_url( get_option( 'host_name' ) . '/moas/login' ); ?>" target="_blank" method="post">
			<input type="hidden" name="username" value="<?php echo esc_attr( get_option( 'mo_radius_admin_email' ) ); ?>" />
			<input type="hidden" id="redirectUrl" name="redirectUrl" value="<?php echo esc_url( get_option( 'host_name' ) . '/moas/initializepayment' ); ?>" />
			<?php wp_nonce_field(); ?>
			<input type="hidden" name="requestOrigin" id="requestOrigin" />
		</form>
	</div>
	<script type="text/javascript">
		function mo_radius_upgrade(plantype) {
			jQuery('#requestOrigin').val(plantype);
			jQuery('#mo_dashboard_login').submit();
		}
	</script>
<?php }
?>
