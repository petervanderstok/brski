/* switch-server -- implementation of OCF switch device using
 * a simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 * switch server is added by:
 * Peter van der Stok <consultancy@vanderstok.org>
 * This file relies on oscore
 */
#ifndef __SWITCH_H__
#define __SWITCH_H__

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>

#include "oscore.h"
#include "oscore-context.h"
#include "cbor.h"
#include "cose.h"
#include "coap.h"

/*
 * POST handler - /ocf/authz_info
 * receives request to set switch
 */
void
switch_hnd_post_authz(coap_context_t  *ctx,
             struct coap_resource_t *resource,
             coap_session_t *session,
             coap_pdu_t *request,
             coap_binary_t *no_token,
             coap_string_t *query,
             coap_pdu_t *response);

/*
 * POST handler - /ocf/switch
 * receives request to set switch
 */
void
ocf_hnd_post_switch(coap_context_t *ctx,
                coap_resource_t *resource,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query,
                coap_pdu_t *response
) ;


/*
 * GET handler - /ocf/switch
 * receives request to create oscore group
 */
void
ocf_hnd_get_switch(coap_context_t  *ctx,
             struct coap_resource_t *resource,
             coap_session_t *session,
             coap_pdu_t *request,
             coap_binary_t *no_token,
             coap_string_t *query,
             coap_pdu_t *response);
             



void
switch_init_resources(coap_context_t *ctx);

void
switch_usage( const char *program, const char *version) ;

#endif /* __SWITCH_H__  */

