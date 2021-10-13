/* edhoc -- implementation of edhoc routines using
 * a simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 * edhoc is added by:
 * Peter van der Stok <consultancy@vanderstok.org>
 */
#ifndef __EDH_H__
#define __EDH_H__

#include "coap_internal.h"
#include "oscore-context.h"
#include "str.h"
#include <mbedtls/ecdh.h>

#define COAP_PORT             "5683"
#define ALL_COAP_LOCAL_NODES  "FF02::FD"

#define COAP_MEDIATYPE_APPLICATION_EDHOC           1003 /* application/edhoc, draft edhoc  */ 

/* define pledge states to join_proxy */
typedef enum {EDHOC_MESSAGE_1, EDHOC_MESSAGE_2, EDHOC_MESSAGE_3, EDHOC_CONNECTED, EDHOC_DONE, EDHOC_FAILED} edhoc_state_t;

/* set key file name */
void
edhoc_set_key(char *name, size_t size);

/* set certificate file name */
void
edhoc_set_certificate( char *name, size_t size);

void
edhoc_init_suite_files(char *key_ed25519, char *key_es256, char *cert_ed25519, char *cert_es256);

/* stores message2 received for edhoc after message_1 */
int16_t
message_2_receipt(unsigned char *data, size_t len, uint16_t code, uint16_t block_num, uint16_t more);

/* stores message4 received for edhoc after message_1 */
int16_t
message_4_receipt(unsigned char *data, size_t len, uint16_t code, uint16_t block_num, uint16_t more);

void
init_edhoc_resources(coap_context_t *ctx);

void
edhoc_oscore_session(coap_context_t *ctx, coap_session_t *session, edhoc_state_t *client_state, uint16_t method_corr, uint8_t suite, coap_string_t **message);

int16_t
edhoc_create_message_1(coap_string_t *message_1, coap_string_t *G_X_string, uint16_t method_corr, uint8_t suite);

int16_t
edhoc_create_message_3(coap_string_t *message_1, coap_string_t *message_2, coap_string_t *message_3);

oscore_ctx_t *
edhoc_read_message_4(coap_string_t *message_1, coap_string_t *message_2, coap_string_t *message_3, coap_string_t *message_4);


#endif /* __EDH_H__  */

