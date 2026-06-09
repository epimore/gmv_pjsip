#pragma once

/*
 * Keep this wrapper intentionally small.
 *
 * gmv_pjsip_sys only mirrors the pjproject C symbols needed by the safe layer.
 * The safe crate should expose a GB28181-oriented API.
 *
 * Do not include pjmedia/pjnath here unless the safe layer really needs them.
 * gmv already owns RTP/PS/FLV/HLS/DASH media processing.
 */

#include <pjlib.h>
#include <pjlib-util.h>

#include <pjsip.h>
#include <pjsip_ua.h>
#include <pjsip_simple.h>

#include <pjsip/sip_msg.h>
#include <pjsip/sip_parser.h>
#include <pjsip/sip_endpoint.h>
#include <pjsip/sip_transport.h>
#include <pjsip/sip_transaction.h>
#include <pjsip/sip_dialog.h>
#include <pjsip/sip_ua_layer.h>
#include <pjsip/sip_util.h>
#include <pjsip/sip_auth.h>
#include <pjsip/sip_auth_msg.h>

/*
#include <pjnath.h>
#include <pjmedia.h>
#include <pjmedia-codec.h>*/
