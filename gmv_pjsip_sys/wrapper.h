#pragma once

/*
 * Minimal PJSIP/PJLIB surface for GB28181 SIP signaling.
 *
 * Keep this file intentionally small. Bindgen will only generate symbols that
 * are reachable from the headers included here and allowed by build.rs.
 */

#include <pjlib.h>
#include <pjlib-util.h>

#include <pjsip.h>
#include <pjsip/sip_auth.h>
#include <pjsip/sip_config.h>
#include <pjsip/sip_endpoint.h>
#include <pjsip/sip_errno.h>
#include <pjsip/sip_event.h>
#include <pjsip/sip_msg.h>
#include <pjsip/sip_parser.h>
#include <pjsip/sip_resolve.h>
#include <pjsip/sip_transaction.h>
#include <pjsip/sip_transport.h>
#include <pjsip/sip_types.h>
#include <pjsip/sip_uri.h>

/*
 * Reserved for later expansion.
 *
 * GB28181 phase1-3 only needs SIP signaling. When gmv_pjsip starts using PJSIP
 * dialog/invite/simple modules or PJNATH/PJMEDIA directly, uncomment the
 * corresponding headers and the allowlist lines in build.rs.
 */

/* PJSIP UA / SIMPLE */
// #include <pjsip_ua.h>
// #include <pjsip_simple.h>

/* PJNATH */
// #include <pjnath.h>

/* PJMEDIA */
// #include <pjmedia.h>
// #include <pjmedia-codec.h>
// #include <pjmedia/transport.h>
// #include <pjmedia/transport_udp.h>
