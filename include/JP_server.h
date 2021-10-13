/* JP-server -- implementation of MASA server using
 * a simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 * Join_proxy server is added by:
 * Peter van der Stok <consultancy@vanderstok.org>
 */
#ifndef __JP_H__
#define __JP_H__

#include "coap_internal.h"



#define JP_NOT_DEFINED       0
#define JP_SERVER            1
#define JP_PROXY             2


void
JP_init_resources(coap_context_t *ctx);

void
jp_registrar(void);

void
jp_proxy(void);

int
jp_transfer(coap_session_t *session, uint8_t *payload, size_t len);

int
jp_return_transfer(coap_session_t *session, const uint8_t *payload, size_t len);

void
jp_set_brskifd(uint16_t);

void
jp_set_context(coap_context_t *ctx);

coap_context_t *
jp_get_context(void);

void 
jp_set_registrar_session(coap_session_t *s);

uint8_t
jp_not_registrar(uint16_t fd);

uint8_t
jp_is_proxy(coap_session_t *session);

#endif /* __JP_H__  */

