/* switch-server -- implementation of OCF switch device using
 * a simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 * switch server is added by:
 * Peter van der Stok <consultancy@vanderstok.org>
 * This file relies on oscore
 */
#ifndef __AS_H__
#define __AS_H__

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

typedef struct AS_client_t AS_client_t;
struct AS_client_t{
  AS_client_t * next;
  size_t       client_name_len;
  uint8_t      *client_name;  /* user name  */
  size_t       client_id_len;
  uint8_t      *client_id;  /* oscore identifier */		
  size_t       iv_len;
  uint8_t      *iv;
};


typedef struct AS_server_t AS_server_t;

struct AS_server_t{
  AS_server_t *next;
  size_t      identifier_len;  /* user name */
  uint8_t     *identifier;
  uint8_t     *server_id;   /* oscore identifier  */
  size_t      server_id_len;
  AS_client_t *clients;  	
  size_t      scope_len;
  uint8_t     *scope;
  size_t      audience_len;
  uint8_t     profile;
  uint8_t     *audience; 
  size_t      AS_server_len;
  uint8_t     *AS_server;
  size_t      shared_secret_len;
  uint8_t     *shared_secret;
  oauth_cnf_t *oscore_context;
};

void
AS_init_resources(coap_context_t *ctx);

#endif /* __AS_H__  */

