/* handle_voucher -- implementation of voucher handling routines using
 * a simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 * handle voucher is added by:
 * Peter van der Stok <consultancy@vanderstok.org>
 */
#ifndef __CR_H__
#define __CR_H__

#include "coap_internal.h"
#include "coap_dtls.h"
#include "coap_session.h"
#include "resource.h"

typedef int16_t (*coap_resp_handler_t)
       (unsigned char *,     /* response payload */
       size_t size,          /* size of payload  */
       uint16_t code,        /* message code     */  
       uint16_t block_num,   /* block number     */
       uint16_t more);       /* more blocks      */

/* redefinition of coap_uri_t  */
typedef struct {
  coap_string_t host;  /**< host part of the URI */
  uint16_t port;          /**< The port in host byte order */
  coap_string_t path;  /**< Beginning of the first path segment.
                           Use coap_split_path() to create Uri-Path options */
  coap_string_t query; /**<  The query part if present */

  /** The parsed scheme specifier. */
  enum coap_uri_scheme_t scheme;
} client_uri_t;

/* parameters to be set for given client request */
typedef struct client_request_t {
   void * next;
   coap_context_t *ctx;
   /* used for DTLS connection */
   coap_dtls_cn_callback_t verify_cn_callback; 
   coap_dtls_pki_t dtls_pki;
   coap_dtls_cpsk_t dtls_psk;
   char    client_sni[256];
   char    *cert_file; /* Combined certificate and private key in PEM */
   char    *ca_file;   /* CA for cert_file - for cert checking in PEM */
   char    *root_ca_file; /* List of trusted Root CAs in PEM */
   int     use_pem_buf; /* Map these cert/key files into memory to test
                               PEM_BUF logic if set */
   uint8_t *cert_mem; /* certificate and private key in PEM_BUF */
   uint8_t *ca_mem;   /* CA for cert checking in PEM_BUF */
   size_t  cert_mem_len;
   size_t  ca_mem_len;
   /* used for client request parameters */
   int     create_uri_opts;
   uint8_t method;        /* the method we are using in our requests, ussually GET */
   unsigned char msgtype; /* usually, requests are sent confirmable */
   unsigned int block_size;
   uint8_t MC_wait_loops;
   int     flags;
   int reliable;
   coap_optlist_t *optlist;
   coap_binary_t  the_token;
   client_uri_t uri;                     /* request URI */
   coap_string_t proxy;
   coap_string_t payload;       /* optional payload to send */
   coap_session_t *session;
} client_request_t;
       

coap_string_t *get_discovered_host_port(uint16_t *port);

void 
set_discovery_wanted(void);

client_request_t *
client_request_init(void);
 
coap_session_t *
coap_start_session(client_request_t *client);
  
int8_t
coap_start_request(client_request_t *client, uint16_t ct);

void
fill_keystore(client_request_t *client);

void 
Clean_client_request(void);

int8_t 
is_ready(void);

void 
make_ready(void);

void 
reset_ready(void);

int8_t
coap_jp_send(uint8_t * data, size_t size);

void 
set_port(client_request_t *client, uint16_t port);

uint16_t 
get_port(client_request_t *client);

void 
set_scheme( client_request_t *client, uint8_t scheme);

void 
set_method(client_request_t *client, uint8_t mth);

void 
set_token(client_request_t *client, coap_binary_t *token);

void 
set_block(client_request_t *client, uint16_t size);

void 
set_host( client_request_t *client, coap_string_t *host);

void 
set_query(client_request_t *client, coap_string_t *query);

void 
set_path( client_request_t *client, coap_string_t *path);

void 
get_path( client_request_t *client, coap_string_t *path);

coap_string_t *
get_host(client_request_t *client);

void 
reset_block(client_request_t *client);

void 
set_message_type( client_request_t *client, unsigned char type);

void 
uri_options_on(client_request_t *client);

void 
uri_options_off(client_request_t *client);

void 
set_flags(client_request_t *client, uint16_t flag);

void 
remove_flags(client_request_t *client, uint16_t flag);

void 
create_uri_options(client_request_t *client, uint16_t ct);

void 
set_resp_handler(coap_resp_handler_t handler);

void 
reset_resp_handler(void);

void 
set_MC_wait_loops(client_request_t *client, uint8_t loops);

void 
set_certificates(client_request_t *client, char *cert, char *ca);

void 
set_pki_callback(client_request_t *client, coap_dtls_cn_callback_t function);

void 
set_payload(client_request_t *client, coap_string_t *pl);

coap_session_t *
client_return_session(client_request_t *client);

coap_pdu_t *
coap_new_request(client_request_t *client,
                 coap_session_t *session,
                 uint8_t m,
                 coap_optlist_t **options,
                 unsigned char *data,
                 size_t length) ;

// void set_payload_code( pl_code_t function);

#define JP_STANDARD_PORT        0
#define JP_DTLS_PORT            1
#define JP_BRSKI_PORT           2

void
init_URIs(coap_address_t *addr, uint8_t proto, uint8_t port_type);

coap_string_t *
getURI( uint8_t port_type);

#endif /* __CR_H__  */

