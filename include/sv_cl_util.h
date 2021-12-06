/* sv_cl_util.h -- implementation of reading/writing between memory and file
 * multi_users block reconstruction related to session.
 * a simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 * sv_cl_util is added by:
 * Peter van der Stok <consultancy@vanderstok.org>
 */
 
#include <stdint.h>
#include "str.h"
#include "coap_internal.h"


#ifndef __SCU_H__
#define __SCU_H__

/* maintains list of blocks belonging to the specified session */
typedef struct ret_data_t {
  void           *next;
  coap_string_t  *SC_ret_data;
  coap_string_t  *SC_in_data;
  coap_session_t *session;
} ret_data_t;


void server_error_return(uint8_t error, coap_pdu_t *response, const char *message);

uint8_t *read_file_mem(const char* file, size_t *length);

uint8_t write_file_mem(const char* file, coap_string_t *contents);

uint8_t *assemble_data(coap_session_t *session,
           coap_pdu_t *request,
           coap_pdu_t *response,
           size_t *size);
           
void SC_verify_release(coap_session_t *session, coap_pdu_t *response);

ret_data_t *SC_corresponding_data(coap_session_t *session);

coap_string_t *SC_new_return_data(coap_session_t *session);        

#endif /* __SCU_H__  */

