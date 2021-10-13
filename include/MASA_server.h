/* MASA-server -- implementation of MASA server using
 * a simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 * MASA server is added by:
 * Peter van der Stok <consultancy@vanderstok.org>
 */
#ifndef __MS_H__
#define __MS_H__

#include "coap_internal.h"

void
MS_init_resources(coap_context_t *ctx);

#endif /* __MS_H__  */

