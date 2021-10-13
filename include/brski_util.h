/* brski_util.h -- implementation of readi/writing between memory and file
 * and malloc utilities.
 * a simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 * brski_util is added by:
 * Peter van der Stok <consultancy@vanderstok.org>
 */
 
#include <stdint.h>
#include "str.h"


#ifndef __BU_H__
#define __BU_H__

void *COAP_MALLOC(size_t size);
	
void COAP_FREE(void *adr);

void brski_error_return(uint8_t error, coap_pdu_t *response, const char *message);

uint32_t coap_malloc_loss(void);

uint8_t *read_file_mem(const char* file, size_t *length);

uint8_t write_file_mem(const char* file, coap_string_t *contents);

#endif /* __BU_H__  */

