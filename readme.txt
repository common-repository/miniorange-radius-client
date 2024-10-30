=== RADIUS Client (RADIUS Login) ===
Contributors: cyberlord92,radiusclient
Tags: radius, radius server, access, remote login, authentication, radius client, radius authentication, radius 2fa, two factor authentication with radius, tfa radius, freeradius, login with freeradius, openvpn, cisco anyconnect, jumpcloud, login into jumpcloud, login into techradius, login into routerOS, authenticateMyWIFI 
Requires at least: 3.0.1
Tested up to: 6.2
Stable tag: 2.2
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html

RADIUS Client or RADIUS Login plugin allows users to login with any RADIUS Server such as freeRadius, jumpCloud, tinyRadius, and etc. 

== Description ==

RADIUS (Remote Authentication Dial-In User Service) Client or RADIUS Login plugin allows users to login with any RADIUS Server. We support radius authentication schemes like PAP, CHAP (MD5), MS CHAP V1, EAP-MSCHAP v2 and other schemes on request.
RADIUS Client plugin also allows you to invoke multi factor authentication (mfa/2fa) using RADIUS Server. You can also configure and use miniOrange as a RADIUS server with MFA.
RADIUS Client plugin supports both ACCESS/REJECT and CHALLENGE RESPONSES. In this way you can use all type of Second factor methods.
RADIUS Client supports all types of Attribute import.

== Radius Servers we Support ==

* freeRadius
* jumpCloud
* routerOS
* techRouter 
* tinyRadius
* AuthenticateMyWiFi
* ClearBox
* FoxPass
* Acess Points

= FREE VERSION FEATURES =

*	Supports login with any 3rd party RADIUS server or custom RADIUS server 
*	Option to allow/deny Auto Register Users- Automatic user registration after login if the user is not already registered with your site
*   Allow login with WordPress Username, Email or both for existing users.
*   Supports Authentication scheme - PAP Authentication

= PREMIUM FEATURES =

*	All the Free Version Features
*	Login Widget- Use Widgets to easily integrate the login link with your WordPress site
*	Support for Authentication Schemes - PAP Authentication, CHAP-MD5 Authentication, MSCHAP v1 Authentication, EAP-MSCHAP v2 Authentication

= RADIUS Servers support :- =

The plugin works with the following RADIUS Servers:
*	Microsoft Windows Network Policy Server (NPS Server)
*   Free RADIUS 2 and above
*	Tiny RADIUS

= What is RADIUS? =
Remote Authentication Dial-In User Service (RADIUS) is a client/server(networking) protocol,operating on port 1812 that provides centralized Authentication, Authorization, and Accounting (AAA or Triple A) management for users who connect and use a network service. It enables remote access servers to communicate with a server to authenticate users and authorize their access to the requested system or service.

= RADIUS Client =
The RADIUS client is typically a NAS ( Network Access Server ) which is responsible for passing user information to designated RADIUS servers, and then based on the response which is returned, authenticates or rejects login to the user.

= RADIUS Server =
RADIUS servers are responsible for receiving user connection requests, authenticating the user, and then returning all configuration information necessary for the client to authenticate the user. A RADIUS server can act as a proxy client to other RADIUS servers or other kinds of authentication servers.

= Authentication Protocols =
The RADIUS server checks that the information is correct using authentication schemes such as PAP, CHAP, MS-CHAP, MS-CHAPv2, EAP, EAP-TLS, EAP-TTLS and EAP-PEAP.

= Security =
Transactions between the client and RADIUS accounting server are authenticated through the use of a shared secret, which is never sent over the network.

= Popular RADIUS Clients miniOrange integrates with: =

*Palo Alto
The users enter their AD credentials to log in to Palo Alto, the RADIUS Client, and after the username/password validation, an One Time Passcode is sent to the user's mobile number. The user enters the One Time passcode received, which is validated by miniOrange to gain/deny access to the user.

*OpenVPN
The users enter their AD credentials and the 2FA code ( Software Token ) to log in to OpenVPN, the RADIUS Client, and after the username/password validation, are prompted for the 2-factor authentication. Post validation of 2nd factor, users are logged in to OpenVPN.

*FortiNet
The users enter their AD credentials to log in to FortiNet, and after the username/password validation, an push notification is sent to the user's mobile, that he needs to accept to get logged in to AWS.

*AWS AD Connector

*Citrix

If you do not find your radius server listed here, please contact us on info@xecurify.com

Secure your WordPress site with 2FA on top of single sign-on using miniOrange On-Premise IDP. You can also protect any VPN, Remote Desktop, Windows with 2FA using our <a href="http://idp.xecurify.com/" target="_blank">Cloud Service/On-Premise Module</a>.


== Installation ==

= From your WordPress dashboard =
1. Visit `Plugins > Add New`.
2. Search for `RADIUS Client`. Find and Install `RADIUS Client (RADIUS Login)`.
3. Activate the plugin from your Plugins page.

= From WordPress.org =
1. Download RADIUS Client (RADIUS Login) plugin.
2. Unzip and upload the `miniorange-radius-client.zip` directory to your `/wp-content/plugins/` directory.
3. Activate RADIUS Client (RADIUS Login) from your Plugins page.


== Frequently Asked Questions ==
= I am not able to configure the RADIUS authentication =
Please email us at info@xecurify.com or <a href="http://xecurify.com/contact" target="_blank">Contact us</a>

= For any other query/problem/request =
Please email us at info@xecurify.com or <a href="http://xecurify.com/contact" target="_blank">Contact us</a>. 

= I want to sync my users or groups from LDAP/Active Directory(AD) =
You can use our another plugin for this use case. Click here to <a href="https://wordpress.org/plugins/ldap-login-for-intranet-sites/" target="_blank">Checkout our plugin</a>

= I want to use LDAP protocol to authenticate user instead of RADIUS protocol =
You can use our another plugin for this use case. Click here to <a href="https://wordpress.org/plugins/ldap-login-for-intranet-sites/" target="_blank">Checkout our plugin</a>


== Screenshots ==
1. RADIUS Server Settings and other configuration

== Changelog ==

= 2.2 =
* PHPCS Fixes

= 2.1.7 =
* Added sanitizations in required places
* Changed classname in class-customer.php

= 2.1.6 =
* Changed plugin name
* Added escaping and sanitizations in required places
* Replaced all CURL calls with WordPress API functions

= 2.1.5 =
* Compatibility with WordPress version 6.0

= 2.1.4 =
* Compatibility with WordPress version 5.1.8
* Allows to use without registration.
* Added support form
* Test Radius Authentication
* New Licensing Page(Easy to Upgrade)

= 2.1.3 =
* Compatibility with WordPress version 5.2.3
* Allows to use without registration.
* Added support form
* Test Radius Authentication
* New Licensing Page(Easy to Upgrade)

= 2.1.2 =
* Compatibility with WordPress version 5.2

= 2.1.1 =
*   UI changes

= 1.1.0 =
*   Compatibility with WordPress version 5.1

= 1.0.0 =
*	this is the first release.

== Upgrade Notice ==
= 1.0.0 =
*	this is the first release.
