/* coap-server -- implementation of coap server using
 * a simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 * coap server is separated by:
 * Peter van der Stok <consultancy@vanderstok.org>
 * This file relies on oscore
 *
 * Copyright (C) 2010--2018 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 */
#ifndef __COAP_S_H__
#define __COAP_S_H__

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
#include "oscore-group.h"
#include "cbor.h"
#include "cose.h"
#include "coap.h"


#define INDEX "This is a test server made with libcoap (see https://libcoap.net)\n" \
              "Copyright (C) 2010--2018 Olaf Bergmann <bergmann@tzi.org>\n\n"


/* temporary storage for dynamic resource representations */
extern int quit;
         
/* changeable clock base (see handle_put_time()) */
extern time_t clock_offset;
extern time_t my_clock_base;

extern struct coap_resource_t *time_resource;
extern int resource_flags;

extern char *cert_file;        /* Combined certificate and private key in PEM */
extern char *ca_file;          /* CA for cert_file - for cert checking in PEM */
extern char *root_ca_file;     /* List of trusted Root CAs in PEM */
#define MAX_KEY   64           /* Maximum length of a key (i.e., PSK) in bytes. */
extern uint8_t key[MAX_KEY];
extern ssize_t key_length;
extern int key_defined;
extern const char *hint;
extern int support_dynamic;           

typedef struct dynamic_resource_t {
  coap_string_t *uri_path;
  coap_string_t *value;
  coap_resource_t *resource;
  int created;
  uint16_t media_type;
} dynamic_resource_t;

extern int dynamic_count;
extern dynamic_resource_t *dynamic_entry;


/* SIGINT handler: set quit to 1 for graceful termination */
void
handle_sigint(int signum);

int
MC_join(coap_context_t *ctx, char *group_name);



 /* regular server handler for blocked request
 * no block used: return 1
 * block used but not complete: return 2
 * block missing: return 3
 * all blocks received: return 0;
 * uses resource->userdata to store intermediate results
 * coap_handle_block
 */
uint8_t
coap_handle_block(
           struct coap_resource_t *resource,
           coap_pdu_t *request,
           coap_pdu_t *response);
           
 
/* assemble data
 * ok: returns data
 * nok: reurns null
 */         
uint8_t *
assemble_data(struct coap_resource_t *resource,
           coap_pdu_t *request,
           coap_pdu_t *response,
           size_t *size);

/*
 * Regular DELETE handler - used by resources created by the
 * GM authorization handler
 */

void
GM_hnd_delete(coap_context_t *ctx,
           struct coap_resource_t *resource,
           coap_session_t *session,
           coap_pdu_t *request,
           coap_binary_t *token,
           coap_string_t *query,
           coap_pdu_t *response
) ;




void
coap_init_resources(coap_context_t *ctx) ;


coap_context_t *
get_context(const char *node, const char *port) ;


void
coap_init_resources(coap_context_t *ctx) ;

#endif /* __COAP_S_H__  */

