/* Registrar-server -- implementation of Registrar server using
 * a simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 * Registrar server is added by:
 * Peter van der Stok <consultancy@vanderstok.org>
 */
#ifndef __RG_H__
#define __RG_H__

#include "coap_internal.h"


void
RG_init_resources(coap_context_t *ctx);

void 
set_multiple_pledge_entries(void);

#endif /* __AS_H__  */

