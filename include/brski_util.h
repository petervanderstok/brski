/* brski_util.h -- implementation of readi/writing between memory and file
 * and malloc utilities.
 * a simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 * brski_util is added by:
 * Peter van der Stok <consultancy@vanderstok.org>
 */
 
#include <stdint.h>
#include "str.h"
#include "coap_internal.h"


#ifndef __BU_H__
#define __BU_H__

typedef struct ret_data_t {
  void           *next;
  coap_string_t  *RG_ret_data;
  coap_string_t  *RG_in_data;
  coap_session_t *session;
} ret_data_t;


void brski_error_return(uint8_t error, coap_pdu_t *response, const char *message);

uint8_t *read_file_mem(const char* file, size_t *length);

uint8_t write_file_mem(const char* file, coap_string_t *contents);

uint8_t *assemble_data(coap_session_t *session,
           coap_pdu_t *request,
           coap_pdu_t *response,
           size_t *size);
           
void RG_verify_release(coap_session_t *session, coap_pdu_t *response);

ret_data_t *RG_corresponding_data(coap_session_t *session);

coap_string_t *RG_new_return_data(coap_session_t *session);        

#endif /* __BU_H__  */

