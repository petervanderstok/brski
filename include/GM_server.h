/* GM-server -- implementation of Group Manager using
 * a simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 * Group Manager (GM) server is added by:
 * Peter van der Stok <consultancy@vanderstok.org>
 * This file relies on oscore
 *
 * Copyright (C) 2010--2018 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 *
 * A resource exists for a group
 * A new group resource is created for a new group by authz-info
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>

#include "oscore_oauth.h"
#include "coap.h"




/* GM-create_context
 * creates context from information stored in token and salt_loc
 */
void
GM_create_context(oauth_token_t *token, uint8_t *nonce);
 

/*
 * Return error and error message
 */
void
oscore_error_return(uint8_t error, coap_pdu_t *response,
                                       const char *message);


/*
 * POST handler - /GM/join/GRP
 * receives request to add a member to group
 */
void
GM_hnd_post_grp(coap_context_t *ctx,
                coap_resource_t *resource,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query,
                coap_pdu_t *response
) ;



/*
 * Group resource creation POST handler 
 * - creates group resource to be filled in with POST
 */
coap_resource_t *
GM_insert_grp_resource( coap_context_t  *ctx, 
               coap_string_t *uri_path, coap_pdu_t *response);
 

/*
 * POST handler - /GM/manage
 * receives request to create oscore group
 */
void
GM_hnd_post_manage(coap_context_t  *ctx,
             struct coap_resource_t *resource,
             coap_session_t *session,
             coap_pdu_t *request,
             coap_binary_t *no_token,
             coap_string_t *query,
             coap_pdu_t *response);
             

/*
 * POST handler - /authz-info
 * receives CWT with authorization to join oscore group
 */
void
GM_hnd_post_authz(coap_context_t  *ctx,
             struct coap_resource_t *resource,
             coap_session_t *session,
             coap_pdu_t *request,
             coap_binary_t *no_token,
             coap_string_t *query,
             coap_pdu_t *response);




void
GM_usage( const char *program, const char *version);
 

int
GM_join(coap_context_t *ctx, char *group_name);

void
GM_init_resources(coap_context_t *ctx);

