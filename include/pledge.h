/* Pledge with Join_proxy -server -- implementation of 
 * the Constrained Application Protocol (CoAP) server interface
 *         as defined in RFC 7252
 * Peter van der Stok <consultancy@vanderstok.org>
 * Copyright (C) 2010--2018 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 *
 */


#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include "coap.h"
#include "client_request.h"

uint8_t
pledge_arrived(uint16_t code, coap_string_t *arrived);

int8_t
pledge_connect_pledge(client_request_t *client);
  
int8_t  
pledge_voucher_request(client_request_t *client); 

int8_t
pledge_status_voucher(client_request_t *client);
	
int8_t
pledge_get_certificate(client_request_t *client);

int8_t
pledge_get_attributes(client_request_t *client);
 
int8_t 
pledge_enroll_certificate(client_request_t *client);

uint8_t
pledge_discover_join_proxy(client_request_t *client, coap_string_t *MC_coap);

int
pledge_get_contexts(client_request_t *client, client_request_t *server, const char *node, const char *port);

int16_t
pledge_discover_brski_port(client_request_t *client, uint16_t port);
	
int8_t
pledge_registrar_session(client_request_t *client, uint16_t *port);

int
pledge(int argc, char **argv);
