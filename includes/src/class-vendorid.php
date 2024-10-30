<?php
/**
 * RADIUS vendor ID assignments.  Thanks to FreeRADIUS for these assignments
 * which were parsed from freeradius-server/share/dictionary.*
 *
 * @package miniorange-radius-client/includes/src
 */

namespace Dapphp\Radius;

if ( ! defined( 'ABSPATH' ) ) {
	exit; // Exit if accessed directly.
}
if ( ! class_exists( 'VendorId' ) ) {

	/**
	 * RADIUS vendor ID assignments.  Thanks to FreeRADIUS for these assignments
	 * which were parsed from freeradius-server/share/dictionary.*
	 */
	class VendorId {

		const _3COM                         = 43;
		const _3GPP                         = 10415;
		const _3GPP2                        = 5535;
		const ACC                           = 5;
		const ACME                          = 9148;
		const ACTELIS                       = 5468;
		const AEROHIVE                      = 26928;
		const AIRESPACE                     = 14179;
		const ALCATEL                       = 3041;
		const ALCATEL_ESAM                  = 637;
		const ALCATEL_LUCENT_AAA            = 831;
		const ALCATEL_SR                    = 6527;
		const ALTEON                        = 1872;
		const ALTIGA                        = 3076;
		const ALVARION                      = 12394;
		const APC                           = 318;
		const APTILO                        = 13209;
		const APTIS                         = 2637;
		const ARBOR                         = 9694;
		const ARUBA                         = 14823;
		const ASCEND                        = 529;
		const ASN                           = 23782;
		const AUDIOCODES                    = 5003;
		const AVAYA                         = 2167;
		const AZAIRE                        = 7751;
		const BAY_NETWORKS                  = 1584;
		const BINTEC                        = 272;
		const BLUECOAT                      = 14501;
		const BOINGO                        = 22472;
		const BRISTOL                       = 4363;
		const BROADSOFT                     = 6431;
		const BROCADE                       = 1588;
		const BSKYB                         = 16924;
		const BT                            = 594;
		const CABLELABS                     = 4491;
		const CABLETRON                     = 52;
		const CAMIANT                       = 21274;
		const CHILLISPOT                    = 14559;
		const CISCO                         = 9;
		const CISCO_ASA                     = 3076;
		const CISCO_BBSM                    = 5263;
		const CISCO_VPN3000                 = 3076;
		const CISCO_VPN5000                 = 255;
		const CITRIX                        = 66;
		const CLAVISTER                     = 5089;
		const COLUBRIS                      = 8744;
		const COLUMBIA_UNIVERSITY           = 11862;
		const COMPATIBLE                    = 255;
		const COSINE                        = 3085;
		const DANTE                         = 27262;
		const DHCP                          = 54;
		const DIGIUM                        = 22736;
		const DLINK                         = 171;
		const DRAGONWAVE                    = 7262;
		const EFFICIENTIP                   = 2440;
		const ELTEX                         = 35265;
		const EPYGI                         = 16459;
		const EQUALLOGIC                    = 12740;
		const ERICSSON                      = 193;
		const ERICSSON_AB                   = 2352;
		const ERICSSON_PACKET_CORE_NETWORKS = 10923;
		const ERX                           = 4874;
		const EXTREME                       = 1916;
		const F5                            = 3375;
		const FDXTENDED                     = 34536;
		const FORTINET                      = 12356;
		const FOUNDRY                       = 1991;
		const FREEDHCP                      = 34673;
		const FREERADIUS                    = 11344;
		const FREESWITCH                    = 27880;
		const GANDALF                       = 64;
		const GARDEROS                      = 16108;
		const GEMTEK                        = 10529;
		const H3C                           = 25506;
		const HILLSTONE                     = 28557;
		const HP                            = 11;
		const HUAWEI                        = 2011;
		const IEA                           = 24023;
		const INFOBLOX                      = 7779;
		const INFONET                       = 4453;
		const IPUNPLUGGED                   = 5925;
		const ISSANNI                       = 5948;
		const ITK                           = 1195;
		const JUNIPER                       = 2636;
		const KARLNET                       = 762;
		const KINETO                        = 16445;
		const LANCOM                        = 2356;
		const LANTRONIX                     = 244;
		const LIVINGSTON                    = 307;
		const LOCAL_WEB                     = 19220;
		const LUCENT                        = 4846;
		const MANZARA                       = 19382;
		const MEINBERG                      = 5597;
		const MERAKI                        = 29671;
		const MERIT                         = 61;
		const MERU                          = 15983;
		const MICROSOFT                     = 311;
		const MIKROTIK                      = 14988;
		const MOTOROLA                      = 161;
		const MOTOROLA_WIMAX                = 161;
		const NAVINI                        = 6504;
		const NETSCREEN                     = 3224;
		const NETWORKPHYSICS                = 7119;
		const NEXANS                        = 266;
		const NOKIA                         = 94;
		const NOMADIX                       = 3309;
		const NORTEL                        = 562;
		const NTUA                          = 969;
		const PACKETEER                     = 2334;
		const PALOALTO                      = 25461;
		const PATTON                        = 1768;
		const PERLE                         = 1966;
		const PROPEL                        = 14895;
		const PROSOFT                       = 4735;
		const PROXIM                        = 841;
		const PUREWAVE                      = 21074;
		const QUICONNECT                    = 14436;
		const QUINTUM                       = 6618;
		const REDCREEK                      = 1958;
		const RFC4679                       = 3561;
		const ADSL_FORUM                    = 3561;
		const RIVERBED                      = 17163;
		const RIVERSTONE                    = 5567;
		const ROARINGPENGUIN                = 10055;
		const RUCKUS                        = 25053;
		const RUGGEDCOM                     = 15004;
		const SG                            = 2454;
		const SHASTA                        = 3199;
		const SHIVA                         = 166;
		const SIEMENS                       = 4329;
		const SLIPSTREAM                    = 7000;
		const SONICWALL                     = 8741;
		const SPRINGTIDE                    = 3551;
		const STARENT                       = 8164;
		const SURFNET                       = 1076;
		const SYMBOL                        = 388;
		const TELEBIT                       = 117;
		const TELEKOM                       = 1431;
		const TERENA                        = 25178;
		const TRAPEZE                       = 14525;
		const TRAVELPING                    = 18681;
		const TROPOS                        = 14529;
		const T_SYSTEMS_NOVA                = 16787;
		const UKERNA                        = 25622;
		const UNIX                          = 4;
		const USR                           = 429;
		const UTSTARCOM                     = 7064;
		const VALEMOUNT                     = 16313;
		const VERSANET                      = 2180;
		const WALABI                        = 2004;
		const WAVERIDER                     = 2979;
		const WICHORUS                      = 27030;
		const WIFIALLIANCE                  = 40808;
		const WIMAX                         = 24757;
		const WIMAX_ALVARION                = 24757;
		const WIMAX_WICHORUS                = 24757;
		const WISPR                         = 14122;
		const XEDIA                         = 838;
		const XYLAN                         = 800;
		const YUBICO                        = 41482;
		const ZEUS                          = 7146;
		const ZTE                           = 3902;
		const ZYXEL                         = 890;
	}
}
