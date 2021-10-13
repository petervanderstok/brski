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

coap_string_t *get_discovered_host_port(uint16_t *port);

void set_discovery_wanted(void);
       
coap_session_t *
coap_start_session(coap_context_t *ctx);
  
int8_t
coap_start_request(uint16_t ct, coap_context_t *ctx);

void
fill_keystore(coap_context_t *ctx);

void 
end_coap_client(coap_context_t *ctx);

int8_t is_ready(void);

void make_ready(void);

void reset_ready(void);

int8_t
coap_jp_send(uint8_t * data, size_t size);

void set_port(uint16_t port);

uint16_t get_port(void);

void set_scheme( uint8_t scheme);

void set_method(uint8_t mth);

void set_token(coap_binary_t *token);

void set_block(uint16_t size);

void set_host( coap_string_t *host);

void set_query(coap_string_t *query);

void set_path( coap_string_t *path);

void get_path( coap_string_t *path);

coap_str_const_t *get_host(void);

void reset_block(void);

void set_message_type( unsigned char type);

void uri_options_on(void);

void uri_options_off(void);

void set_flags(uint16_t flag);

void remove_flags(uint16_t flag);

void create_uri_options(uint16_t ct);

void set_resp_handler(coap_resp_handler_t handler);

void reset_resp_handler(void);

void set_MC_wait_loops(uint8_t loops);

void clear_MC_returns( void);

void set_certificates(char *cert, char *ca);

void set_pki_callback(coap_dtls_cn_callback_t function);

void set_payload(coap_string_t *pl);

coap_session_t *client_return_session(void);

coap_pdu_t *
coap_new_request(coap_context_t *ctx,
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

