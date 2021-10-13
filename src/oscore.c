/*
 * Copyright (c) 2018, SICS, RISE AB
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/**
 * \file
 *      An implementation of the Object Security for Constrained RESTful Enviornments (Internet-Draft-12) .
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 * adapted to libcoap and major rewrite
 *     Peter van der Stok <consultancy@vanderstok.org>
 *     on request of Fairhair alliance
 *
 */

#include "oscore.h"
#include "oscore-context.h"
#include "oscore-crypto.h"
#include "cbor.h"
#include "coap.h"
#include "stdio.h"
#include "option.h"
#include "pdu.h"
#include "coap_debug.h"
#include "utlist.h"
#include <stdbool.h>
#include "net.h"
#include "ed25519.h"

#define AAD_BUF_LEN 60      /* length of aad_buffer */
#define MAX_IV_LEN  10      /* maximum length of iv buffer */

/* indicates usage of default oscore context */
static uint8_t master_secret[35] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23};

static uint8_t salt[8] = {0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40}; 

static uint8_t sender_id[6] = { 0x63, 0x6C, 0x69, 0x65, 0x6E, 0x74 };
                            /* client */
static uint8_t receiver_id[6] = { 0x73, 0x65, 0x72, 0x76, 0x65, 0x72 };
                            /* server */

/* oscore_cs_params
 * returns cbor array [[param_type], [paramtype, param]]
 */
uint8_t *
oscore_cs_params(int8_t param, int8_t param_type, size_t *len){
    uint8_t buf[50];
    uint8_t *pt = buf;
    *len = 0;
    *len += cbor_put_array(&pt, 2);
    *len += cbor_put_array(&pt, 1);
    *len += cbor_put_number(&pt, param_type);
    *len += cbor_put_array(&pt, 2);
    *len += cbor_put_number(&pt, param_type);
    *len += cbor_put_number(&pt, param);
    uint8_t *result = coap_malloc(*len);
    memcpy(result, buf, *len);
    return result;
}

/* oscore_cs_key_params
 * returns cbor array [paramtype, param]
 */
uint8_t *
oscore_cs_key_params(int8_t param, int8_t param_type, size_t *len){
	uint8_t buf[50];
	uint8_t *pt = buf;
    *len = 0;
    *len += cbor_put_array(&pt, 2);
    *len += cbor_put_number(&pt, param_type);
    *len += cbor_put_number(&pt, param);
    uint8_t *result = coap_malloc(*len);
    memcpy(result, buf, *len);
    return result;
}	

/* extract_param
 * extract algorithm paramater from [type, param]
 */
static int
extract_param(uint8_t *cbor_array){
  int64_t  mm = 0;
  uint8_t elem = cbor_get_next_element(&cbor_array);
  if (elem == CBOR_ARRAY){
    uint64_t arr_size = cbor_get_element_size(&cbor_array);
    if (arr_size != 2) return 0;
    for (uint16_t i=0; i < arr_size; i++){
      int8_t ok = cbor_get_number(&cbor_array, &mm);
      if (ok != 0)return 0;
    }     
	return (int)mm;
  }
  return 0;
}


/* extract_type
 * extract algorithm paramater from [type, param]
 */
static int
extract_type(uint8_t *cbor_array){
  int64_t  mm = 0;
  uint8_t elem = cbor_get_next_element(&cbor_array);
  if (elem == CBOR_ARRAY){
    uint64_t arr_size = cbor_get_element_size(&cbor_array);
    if (arr_size != 2) return 0;
    if(cbor_get_number(&cbor_array, &mm) == 1) return 0;         
	return (int)mm;
  }
  return 0;
}



//
// oscore_init
//
/* Initialize the default test oscore security context */
oscore_ctx_t *
oscore_init(void)
{
  oscore_ctx_t *osc_ctx = NULL;
/* prepare one sender receiver context   */
  osc_ctx = oscore_derive_ctx(master_secret, 
      16, salt, 8,
      COSE_Algorithm_AES_CCM_16_64_128, sender_id, 6, receiver_id, 6, NULL, 0, 
      OSCORE_DEFAULT_REPLAY_WINDOW);
  if(!osc_ctx ){
	coap_log(LOG_CRIT, "Could not create OSCORE Security Context!\n");
  }
  oscore_enter_context(osc_ctx); 

/* return default first context  */
  return osc_ctx;
}


//
// coap_is_request
//
uint8_t
coap_is_request(coap_pdu_t *coap_pkt)
{
  if(coap_pkt->code >= COAP_REQUEST_GET && coap_pkt->code <= COAP_REQUEST_IPATCH) {
    return 1;
  } else {
    return 0;
  }
}

//
// u64tob
//
uint8_t
u64tob(uint64_t in, uint8_t *buffer)
{
  memcpy(buffer, &in, 8);
  
  uint8_t i;
  for( i = 8; i > 0; i--){
    if( buffer[i-1] == 0 ){
 	break;
    }  
  }
  return 9 - i;
}

//
// btou64
//
uint64_t
btou64(uint8_t *bytes, size_t len)
{
  uint8_t buffer[8];
  memset(buffer, 0, 8); /* function variables are not initializated to anything */
  int offset = 8 - len;
  uint64_t num;

  memcpy((uint8_t *)(buffer + offset), bytes, len);

  num =
    (uint64_t)buffer[0] << 56 |
    (uint64_t)buffer[1] << 48 |
    (uint64_t)buffer[2] << 40 |
    (uint64_t)buffer[3] << 32 |
    (uint64_t)buffer[4] << 24 |
    (uint64_t)buffer[5] << 16 |
    (uint64_t)buffer[6] << 8 |
    (uint64_t)buffer[7];

  return num;
}

static size_t
oscore_prepare_int(uint8_t group, oscore_ctx_t *ctx, cose_encrypt0_t *cose, uint8_t *oscore_option, size_t oscore_option_len, 
       uint8_t *external_aad_ptr)
{
  size_t external_aad_len = 0;
  if ((oscore_option_len > 0) && (oscore_option != NULL)  && (group == 1)){
    external_aad_len += cbor_put_array(&external_aad_ptr, 7);
  }else if ((oscore_option_len > 0) && (oscore_option != NULL)  && (group == 0)){
      external_aad_len += cbor_put_array(&external_aad_ptr, 6);
  } else if ((oscore_option_len == 0) && (group == 0)){
      external_aad_len += cbor_put_array(&external_aad_ptr, 5);
  }else if ((oscore_option_len == 0) && (group == 1)){
      external_aad_len += cbor_put_array(&external_aad_ptr, 6);
  }
  
  external_aad_len += cbor_put_unsigned(&external_aad_ptr, 1);
  /* Version, always "1" for this version of the draft */
  if (group != 1){
  /* Algoritms array with one item*/
    external_aad_len += cbor_put_array(&external_aad_ptr, 1); 
  /* Encryption Algorithm   */
    external_aad_len += 
           cbor_put_number(&external_aad_ptr, cose->alg);
  } else { 
  /* Algoritms array with 4 items */
     external_aad_len += cbor_put_array(&external_aad_ptr, 4);
  /* Encryption Algorithm   */
     external_aad_len += cbor_put_number(&external_aad_ptr, cose->alg);     
  /* signature Algorithm */
     external_aad_len += cbor_put_number(&external_aad_ptr, 
                             ctx->counter_signature_algorithm );
     
       size_t counter_signature_key_parameters_len = 0;
       int16_t type = extract_type(
                     ctx->counter_signature_parameters);
       int16_t param = extract_param(
                     ctx->counter_signature_parameters);
       uint8_t *counter_signature_key_parameters = 
          oscore_cs_params(param,
          type, &counter_signature_key_parameters_len);
          memcpy(external_aad_ptr, 
              counter_signature_key_parameters, 
              counter_signature_key_parameters_len);
          external_aad_ptr = external_aad_ptr + 
                   counter_signature_key_parameters_len;
          external_aad_len += 
                     counter_signature_key_parameters_len;
          memcpy(external_aad_ptr, 
              ctx->counter_signature_parameters, 
              ctx->counter_signature_parameters_len);
          external_aad_ptr = external_aad_ptr + 
                   ctx->counter_signature_parameters_len;
          external_aad_len += 
                   ctx->counter_signature_parameters_len;
  }
  external_aad_len += cbor_put_bytes(&external_aad_ptr, 
              cose->key_id, cose->key_id_len);
  external_aad_len += cbor_put_bytes(&external_aad_ptr, 
               cose->partial_iv, cose->partial_iv_len);
  external_aad_len += cbor_put_bytes(&external_aad_ptr, NULL, 0); 
  if (group == 1){
    external_aad_len += cbor_put_bytes(&external_aad_ptr, 
       ctx->id_context, ctx->id_context_len);
  }
  if(oscore_option != NULL && oscore_option_len > 0){
     external_aad_len += cbor_put_bytes(&external_aad_ptr,
           oscore_option, oscore_option_len);
}
  /* Put integrity protected option, at present there are none. */
  return external_aad_len;
}



//  oscore_pdu_print
//  prints contents of pdu
void
oscore_pdu_print(coap_pdu_t *pdu, const char *s)
{
   if (coap_get_log_level() < LOG_NOTICE) return;
   fprintf(stderr, " %s", s);
   fprintf(stderr,"______________________________________ \n");
   coap_show_pdu(LOG_NOTICE, pdu);
   fprintf(stderr, "________________________________________\n");
}

// oscore_pdu_init
// copy of pdu_int but without the size limitation of 256 bytes

static coap_pdu_t *
oscore_pdu_init(uint8_t type, uint8_t code, uint16_t tid, size_t size) {
  coap_pdu_t *pdu;

  pdu = coap_malloc_type(COAP_PDU, sizeof(coap_pdu_t));
  if (!pdu) return NULL;
  pdu->max_hdr_size = COAP_PDU_MAX_TCP_HEADER_SIZE;
  uint8_t *buf;
  pdu->alloc_size = size;
  buf = coap_malloc( pdu->alloc_size + pdu->max_hdr_size);
  if (buf == NULL) {
    coap_free_type(COAP_PDU, pdu);
    return NULL;
  }
  pdu->token = buf + pdu->max_hdr_size;
  coap_pdu_clear(pdu, size);
  pdu->tid = tid;
  pdu->type = type;
  pdu->code = code;
  return pdu;
}


//
// oscore_payload_copy
//  copies the contentents of source_pdu to destination_pdu
// used size and data are adapted
// no need to test on space, beacuse token pointers are exchanged
void
oscore_payload_copy( coap_pdu_t *source, coap_pdu_t *destination)
{
/* first swap pointers such that memory can be restored later  */

  void *pt = destination->token;
  destination->token = source->token;
  source->token = pt;
  pt = destination->data;
  destination->data = source->data;
  source->data = pt;
/* copy essential pdu values   */
  destination->token_length = source->token_length;
  destination->max_delta = source->max_delta;
  destination->used_size = source->used_size;
  destination->alloc_size = source->alloc_size;
  destination->max_size = source->max_size;
  destination->code = source->code;
}

//
// oscore_shadow_pdu
// creates a new pdu with token and hdr copied from pdu
// shadowed from pdu
static coap_pdu_t *
oscore_shadow_pdu(coap_pdu_t *pdu, size_t size)
{
  coap_pdu_t *newpdu = oscore_pdu_init( pdu->type, pdu->code,
                                    pdu->tid, size);
  newpdu->hdr_size = pdu->hdr_size;
  if (newpdu->hdr_size > newpdu->max_hdr_size)
                     newpdu->hdr_size = newpdu->max_hdr_size;
  for (int i = - newpdu->hdr_size; i < 0; i++)
                       newpdu->token[i] = pdu->token[i];
  coap_add_token(newpdu, pdu->token_length, pdu->token);
  return newpdu;
}


//
// oscore_external_option_copy
// acts on external options not to be encrypted
// external options from source are copied to destination
// COAP_OPTION_OSCORE is added to destination at ordered place
// error returns 0
// OK returns 1
int
oscore_external_option_copy( cose_encrypt0_t *cose, uint8_t group,
          coap_pdu_t *source, 
          coap_pdu_t *storage, coap_pdu_t *destination)
{
  coap_opt_t *src_opt = source->token + source->token_length;
  coap_opt_t *end_opt = source->token + source->used_size;
  size_t buffer_length;
  size_t opt_size;
  coap_option_t option;
  const uint8_t *src_value;
  uint8_t src_length;
  uint16_t src_option = 0; 
  bool osc_copied = false;
  uint8_t option_value_buffer[15];
  int oscore_length = 0; 
  while ((src_opt < end_opt) && (*src_opt != COAP_PAYLOAD_START))
  { 
    src_option = src_option + 
                          (uint16_t)coap_opt_delta(src_opt);
    src_value = coap_opt_value(src_opt);
    src_length = coap_opt_length(src_opt);

    if ((src_option > COAP_OPTION_OSCORE)   && !osc_copied){
       osc_copied = true;
 /* add the oscore option to destination   */
       oscore_length = oscore_encode_option_value( 
                      option_value_buffer, cose, group);
       if (!coap_add_option(destination, COAP_OPTION_OSCORE,
                            oscore_length, option_value_buffer))
                                             return 0;
    }
    switch (src_option){
/* external options are copied to destination*/
    case COAP_OPTION_URI_HOST :
    case COAP_OPTION_URI_PORT :
      if (!coap_add_option(destination, src_option, src_length, 
                                              src_value))
                                    return 0;
      break;
/* internal options copied to storage  */
    default :
      if (!coap_add_option( storage, src_option, src_length, 
                                              src_value))
                                                   return 0;
    }
    buffer_length = end_opt - src_opt;
    opt_size = coap_opt_parse(src_opt, buffer_length, &option);
    if (opt_size == 0)return 0;
    src_opt = src_opt + opt_size;
  }

/* end of options in source, 
  insert the external options if not done already 
*/ 
  if (!osc_copied)
  {
    osc_copied = true;
/* add the oscore option to destination   */
    oscore_length = oscore_encode_option_value( 
                                  option_value_buffer, cose, group);
    if (!coap_add_option(destination, COAP_OPTION_OSCORE,
                            oscore_length, option_value_buffer))
                                             return 0;
  }
  int payload_length;
  if (source->data == NULL) payload_length = 0;
  else payload_length = source->token - source->data
                                          + source->used_size;
  if (!coap_add_data( storage, payload_length, source->data))
       return 0;
  else return 1;
}

//
// oscore_merge_options_payload
/* options from decrypted are merged (ordered) 
 *        with options from source
 * payload from decrypted data is added to destination   */
/* error returns 0   when options are wrong      
 * no error returns 1;                              */
int8_t 
oscore_merge_options_payload( uint8_t *decrypted, 
                   size_t decrypt_length, coap_pdu_t *source, 
                                   coap_pdu_t *destination)
{
  size_t buffer_length;
  size_t opt_size;
  coap_option_t option;
  coap_opt_t *src_opt = source->token + source->token_length;
  coap_opt_t *src_old = NULL;
  coap_opt_t *end_src_opt = source->data - 1;
  if (source->data == NULL) 
            end_src_opt = source->used_size + source->token;
  uint16_t dcrt_option = 0;
  uint16_t src_option = 0; 
  const uint8_t *src_value = NULL;
  uint8_t src_length = 0;
  const uint8_t *dcrt_value = NULL;
  uint8_t dcrt_length = 0;
  destination->code = *decrypted;
  decrypted++;
  coap_opt_t *dcrt_opt = (coap_opt_t *)decrypted;
  
  coap_opt_t *end_dcrt_opt = decrypted + decrypt_length - 1;
  coap_opt_t *dcrt_old = NULL;
/* code is restored and decrypted points to options, payload  */
  while ((src_option != COAP_MAX_OPT) || (dcrt_option != COAP_MAX_OPT)) 
    {
    if ((src_opt < end_src_opt) && 
                 (*src_opt != COAP_PAYLOAD_START))
    {
      if (src_opt != src_old){ 
        src_value = coap_opt_value(src_opt);
        src_length = coap_opt_length(src_opt);
        src_option = src_option + 
                          (uint16_t)coap_opt_delta(src_opt);
       }
    }
    else src_option = COAP_MAX_OPT;
    if ((dcrt_opt < end_dcrt_opt) && 
                   (*dcrt_opt != COAP_PAYLOAD_START))
    {
      if (dcrt_opt != dcrt_old){ 
        dcrt_value = coap_opt_value(dcrt_opt);
        dcrt_length = coap_opt_length(dcrt_opt);
        dcrt_option = dcrt_option +    
                           (uint16_t)coap_opt_delta(dcrt_opt);
        dcrt_old = dcrt_opt;
      }
    }
    else dcrt_option = COAP_MAX_OPT;

// copy the option with lowest option-number
    if (src_option < dcrt_option){
      switch (src_option){
/* only unprotected end to end options are copied  */
/* block inserted by proxies is not supported  */
       case COAP_OPTION_URI_HOST :
       case COAP_OPTION_URI_PORT :
         coap_add_option(destination, src_option, src_length, 
                                               src_value);
         break;
       default:
         break;
      }
      buffer_length = end_src_opt - src_opt;
      opt_size = coap_opt_parse(src_opt, buffer_length , &option);
      src_opt = src_opt + opt_size;
    }
    else if (dcrt_option != COAP_MAX_OPT){
      coap_add_option(destination, dcrt_option, dcrt_length, 
                                               dcrt_value);
      buffer_length = end_dcrt_opt - dcrt_opt;
      opt_size = coap_opt_parse(dcrt_opt, buffer_length , &option);
      if (opt_size == 0) return 0;
      dcrt_opt = dcrt_opt + opt_size;
    }
  }
// all options are copied over in the right order
// now copy payload
  if (*dcrt_opt == COAP_PAYLOAD_START){
    dcrt_opt++;
    int16_t pl_length= 
              decrypt_length - (dcrt_opt - decrypted) - 1;
    if (pl_length > 0)
        coap_add_data(destination, pl_length, dcrt_opt);
  }
  return 1;
}

//
// oscore_encode_option_value
//
int
oscore_encode_option_value(uint8_t *option_buffer, cose_encrypt0_t *cose,
uint8_t group)
{
  uint8_t offset = 1;
  if(cose->partial_iv_len > 5){
	  return 0;
  }
  if (group== OSCORE_GROUP) option_buffer[0] = 0x20;
  else option_buffer[0] = 0;
  if(cose->partial_iv_len > 0 && cose->partial_iv != NULL) {
    option_buffer[0] |= (0x05 & cose->partial_iv_len);
    memcpy(&(option_buffer[offset]), cose->partial_iv, cose->partial_iv_len);
    offset += cose->partial_iv_len;
  }
  if(cose->kid_context_len > 0 && cose->kid_context != NULL) {
    option_buffer[0] |= 0x10;
    option_buffer[offset] = cose->kid_context_len;
    offset++;
    memcpy(&(option_buffer[offset]), cose->kid_context, cose->kid_context_len);
    offset += cose->kid_context_len;
  } 

  if(cose->key_id_len > 0 && cose->key_id != NULL) {
    option_buffer[0] |= 0x08;
    memcpy(&(option_buffer[offset]), 
                    cose->key_id, cose->key_id_len);
    offset += cose->key_id_len;
  }

  if(offset == 1 && option_buffer[0] == 0) { 
/* If option_value is 0x00 it should be empty. */
	  return 0;
  }
  return offset;
}


//
// oscore_decode_option_value
// error: return 0
// OK: return 1
//
int
oscore_decode_option_value(uint8_t *option_value, int option_len, cose_encrypt0_t *cose)
{
  uint8_t *opt_value = option_value;
  if(option_len == 0) return 1; /*empty option  */
  if( option_len > 255 || option_len < 0 || (opt_value[0] & 0x06) == 6 || (opt_value[0] & 0x07) == 7 || (opt_value[0] & 0xC0) != 0) {
    return 0;
  }

  uint8_t partial_iv_len = (opt_value[0] & 0x07);
  uint8_t offset = 1;
  if(partial_iv_len != 0) {    
    if( offset + partial_iv_len > option_len) {
      return 0;
    }
    cose_encrypt0_set_partial_iv(cose, &(opt_value[offset]), partial_iv_len);
    offset += partial_iv_len;
  }
  
  if((opt_value[0] & 0x10) != 0) {
    uint8_t kid_context_len = opt_value[offset];
    offset++;
    if (offset + kid_context_len > option_len) {
      return 0;
    }
    cose_encrypt0_set_kid_context(cose, &(opt_value[offset]), kid_context_len);
    offset = offset + kid_context_len;
  }

  if((opt_value[0] & 0x08) != 0) {
    int kid_len = option_len - offset;
    if (kid_len <= 0) {
      return 0;
    }
    cose_encrypt0_set_key_id(cose, &(opt_value[offset]), kid_len);
  }
  return 1;
}

//
/* oscore_message_decrypt
 * decrypts pdu and returns decrypted message 
 * when oscore-option is not present, returns NULL */
coap_pdu_t *
oscore_message_decrypt(coap_pdu_t *pdu, coap_session_t *session)
/* pdu contains incoming message with encrypted payload *
 * function returns decrypted message                   *
 * and verifies signature, if present                   * 
 * returns NULL when decryption,verification fails      */
{
  coap_context_t *ctx = session->context;	
  oscore_pdu_print(pdu, 
        "\nENCRYPTed pdu received by oscore_message_decrypt\n");
  coap_pdu_t *decrypt_pdu = oscore_shadow_pdu(pdu, 
             coap_session_max_pdu_size(session));
  uint8_t *osc_value;   /* value of OSCORE option */
  uint8_t osc_size;     /* size of OSCORE OPTION */
  coap_string_t optstring;
  coap_str_const_t optcons;
  uint8_t group_message = 0;
  coap_opt_iterator_t opt_iter;
  coap_opt_t *opt = NULL; 
  cose_sign1_t sign[1];
  cose_sign1_init(sign);  /* clear sign memory */
  cose_encrypt0_t cose[1];
  cose_encrypt0_init(cose);  /* clear cose memory */
  oscore_ctx_t *osc_ctx = NULL;
  uint8_t aad_buffer[60];
  uint8_t nonce_buffer[13];
  int pltxt_size = 0;
  uint8_t coap_request = coap_is_request(pdu);
  
   
// find OSCORE option in pdu
  opt = coap_check_option(pdu, COAP_OPTION_OSCORE, &opt_iter);
  if (opt){
    optcons.length = coap_opt_length(opt);
    optcons.s  = coap_opt_value(opt);
  }
  else {
    coap_delete_pdu(decrypt_pdu);
    return NULL;
  } 
  memcpy(&optstring, &optcons, sizeof(optstring)); /* to avoid compilation warning  */
  osc_value = (uint8_t *)optstring.s;
  osc_size  = optstring.length;
/* pdu is oscore encrypted message                          */
/* For request message:                                     */
/*         find context with context_id or sender_id        */
/*         as specified in cose key_id                      */
  if (coap_request){
    if (oscore_decode_option_value(osc_value, osc_size, 
                                                  cose) == 0)
    {
      coap_log(LOG_WARNING,"OSCORE Option cannot be decoded.\n");
      coap_delete_pdu(decrypt_pdu);
      return NULL;
    } 
    osc_ctx = oscore_find_context(cose->key_id, cose->key_id_len, 
          NULL, 0, /* no recipient id */
          cose->kid_context, cose->kid_context_len);
/* to be used for encryption of returned response later */
    ctx->osc_ctx = (void *)osc_ctx;
  } else /* !coap_request */{
    osc_ctx = ctx->osc_ctx; /* this is response context */ 
  }
  if(osc_ctx == NULL) {
    coap_log(LOG_CRIT,"OSCORE Security Context not found.\n");
    coap_delete_pdu(decrypt_pdu);
    return NULL;
  }
/* context has been found   */

  if (osc_size > 0)
    if ((osc_value[0] & 0x20) == 0x20) group_message = 1; /* group message received */
  if ((group_message == 1) && (osc_ctx->mode != OSCORE_GROUP)){
	  /* group_message cannot be treated according to oscore context */
	  coap_log(LOG_WARNING,"untreatable OSCORE group message.\n");
      coap_delete_pdu(decrypt_pdu);
      return NULL;  
  }
  if (coap_request){
/*  Verify the sequence number using the Replay window        */
    if(!oscore_validate_sender_seq(osc_ctx->recipient_context, cose)) {
      coap_log(LOG_WARNING,"OSCORE Replayed or old message\n");
      coap_delete_pdu(decrypt_pdu);
      return NULL;
    }
  }

  uint8_t *st_encrypt =  pdu->data;
  int encrypt_len = pdu->used_size - (pdu->data - pdu->token);
  int mes_len = encrypt_len - Ed25519_SIGNATURE_LEN;
  if (mes_len < 0)mes_len = 0;
  if (group_message == 0)mes_len = 0;

/* fill cose with sender context for returned response         */
  oscore_dec_fill_cose(coap_request, cose, osc_ctx);
  size_t aad_len = 
     oscore_prepare_aad(group_message, osc_ctx, cose, 
                                    NULL, 0, aad_buffer);
  assert(aad_len < 60);
  cose_encrypt0_set_aad(cose, aad_buffer, aad_len);
  oscore_generate_nonce(cose, osc_ctx, nonce_buffer, 13);
  cose_encrypt0_set_nonce(cose, nonce_buffer, 13);
  
  uint8_t *plaintext_buffer = 
              coap_malloc(pdu->alloc_size + pdu->max_hdr_size); 

  if ((encrypt_len == 0) || (st_encrypt == NULL)) {
	  coap_log(LOG_WARNING,"encrypted data are not present\n");
	  coap_delete_pdu(decrypt_pdu);
	  return NULL;
  }

  size_t tag_len = cose_tag_len(cose->alg);
/* from here on decryption is warranted    */
  if (group_message == 1) encrypt_len = 
                          encrypt_len - Ed25519_SIGNATURE_LEN;
  cose_encrypt0_set_ciphertext(cose, st_encrypt, encrypt_len);
  pltxt_size = cose_encrypt0_decrypt(cose, plaintext_buffer,
                                     encrypt_len - tag_len);
  if(pltxt_size <= 0) {
    coap_log(LOG_WARNING,"OSCORE Decryption Failure, result code: %d \n", (int)pltxt_size);
    if(coap_request)
               oscore_roll_back_seq(osc_ctx->recipient_context);
    coap_free_type(COAP_OSCORE_BUF, plaintext_buffer);
    coap_delete_pdu(decrypt_pdu);
    return NULL;
  }

  assert(pltxt_size < pdu->alloc_size + pdu->max_hdr_size ); 
  if (group_message == 1){
/* verify signature     */
     uint8_t *st_signature = st_encrypt + encrypt_len;
     uint8_t *sig_buffer = NULL;
     size_t  sig_len =0;

     aad_len = oscore_prepare_int(group_message, osc_ctx, cose, 
                             osc_value, osc_size, aad_buffer);
     sig_buffer = coap_malloc(aad_len + encrypt_len + 30);
     oscore_populate_sign(coap_request, sign, osc_ctx);
     sig_len = oscore_prepare_sig_structure(sig_buffer, 
                  aad_buffer, aad_len, st_encrypt, encrypt_len);
     assert(aad_len + encrypt_len + 30 > sig_len);             
     cose_sign1_set_signature(sign, st_signature);
     cose_sign1_set_ciphertext(sign, sig_buffer, sig_len);
     int sign_res = cose_sign1_verify(sign);
     coap_free(sig_buffer);
     if (sign_res == 0){
       coap_log(LOG_WARNING,
           "OSCORE signature verification Failure \n");
       coap_free_type(COAP_OSCORE_BUF, plaintext_buffer);
       coap_delete_pdu(decrypt_pdu);
       return NULL;
     }
  } 
// plaintext contains decrypted code, options and payload
// merge plaintext options with pdu options to decrypt_pdu
// and finally copy contents of decrypt_pdu back to pdu
  int8_t ok = oscore_merge_options_payload( 
       plaintext_buffer, pltxt_size, pdu, decrypt_pdu);
  if (ok == 0) return NULL;
//  oscore_payload_copy(decrypt_pdu, pdu);
  coap_free_type(COAP_OSCORE_BUF, plaintext_buffer);
//  coap_delete_pdu(decrypt_pdu);
  oscore_pdu_print(decrypt_pdu, "\nDECRYPTED message in original PDU\n");
  return decrypt_pdu;
}

//
// oscore_dec_fill_cose
/* called from oscore_message_decrypt                   
 * fills cose fields from context and sender context           *
 * oscore_option_decode fills cose fields from oscore option   */
void
oscore_dec_fill_cose(uint8_t coap_request, cose_encrypt0_t *cose, oscore_ctx_t *osc_ctx)
{
   if (!coap_request)
     oscore_populate_cose(coap_request, cose, osc_ctx);
  else cose_encrypt0_set_key(cose, 
         osc_ctx->sender_context->sender_key, CONTEXT_KEY_LEN);
/* partial_iv to sender_context->seq for nonce construction */
  uint64_t incoming_seq = btou64(cose->partial_iv, cose->partial_iv_len);
  osc_ctx->sender_context->seq = incoming_seq;
  cose_encrypt0_set_alg(cose, osc_ctx->alg);
}


//
// oscore_enc_fill_cose
/* called from oscore_message_encrypt                   
 * fills cose fields from context and sender context           *
 * oscore_option_decode fills cose fields from oscore option   */
void
oscore_enc_fill_cose(uint8_t coap_request, cose_encrypt0_t *cose, oscore_ctx_t *osc_ctx)
{
   oscore_populate_cose(coap_request, cose, osc_ctx);
   if(!coap_request){ 
     cose_encrypt0_set_kid_context(cose, NULL, 0);
   }
   if (coap_request && osc_ctx->mode == OSCORE_GROUP)
      cose_encrypt0_set_kid_context(cose,
                  osc_ctx->id_context, osc_ctx->id_context_len); 
}


//
// oscore_populate_cose
/* called from oscore_enc_fill_cose and oscore_dec_fill_cose 
* fills cose fields from context and sender context             
* oscore_option_decode fills cose fields from oscore option    */
void
oscore_populate_cose(uint8_t coap_request, cose_encrypt0_t *cose, oscore_ctx_t *osc_ctx)
{
  cose_encrypt0_set_alg(cose, osc_ctx->alg);

  uint8_t partial_iv_buffer[MAX_IV_LEN];
  uint8_t partial_iv_len;
  oscore_sender_ctx_t *se_ctx = osc_ctx->sender_context;
  cose_encrypt0_set_key(cose, se_ctx->sender_key, 
                                            CONTEXT_KEY_LEN);
  cose_encrypt0_set_key_id(cose, se_ctx->sender_id, 
                                       se_ctx->sender_id_len);
  partial_iv_len = u64tob( se_ctx->seq, partial_iv_buffer);
  assert(partial_iv_len < 9);
  cose_encrypt0_set_partial_iv(cose, partial_iv_buffer,
                                              partial_iv_len);
  cose_encrypt0_set_kid_context(cose, osc_ctx->id_context, 
                                        osc_ctx->id_context_len);
  if (!coap_request){
    cose_encrypt0_set_key(cose, osc_ctx->recipient_context->
            recipient_key, CONTEXT_KEY_LEN);
  }
}

/* Sets alg and keys in COSE SIGN  */
void
oscore_populate_sign(uint8_t coap_request, cose_sign1_t *sign, oscore_ctx_t *ctx)
{
  cose_sign1_set_alg(sign, ctx->counter_signature_algorithm,
               extract_param(ctx->counter_signature_parameters),
               extract_type(ctx->counter_signature_parameters));
  if (coap_request){
    cose_sign1_set_private_key(sign, 
                      ctx->sender_context->private_key); 
    cose_sign1_set_public_key(sign, 
                      ctx->sender_context->public_key);
  } else {
    cose_sign1_set_public_key(sign, 
                      ctx->recipient_context->public_key);
    cose_sign1_set_private_key(sign, 
                      ctx->recipient_context->private_key);
  }
}

//
// new function for libcoap
// oscore_message_encrypt
//
coap_pdu_t *
oscore_message_encrypt(coap_pdu_t *pdu, coap_session_t *session)
{
/* pdu contains options and payload to encrypt  */
/* returns message containing encrypted options  
   and encrypted payload as new payload  */
  coap_context_t *ctx = session->context;
  uint8_t coap_request = coap_is_request(pdu);
  coap_pdu_t *encrypt_pdu = oscore_shadow_pdu(pdu,   
                        coap_session_max_pdu_size(session));
                 /* will contain final encrypted message */
  /* Overwrite the CoAP code. */
  if(coap_request) {
    encrypt_pdu->code = COAP_REQUEST_POST;
  } else {
    encrypt_pdu->code = COAP_RESPONSE_CODE(204);
  }                         
  encrypt_pdu->token[-encrypt_pdu->hdr_size + 1] = encrypt_pdu->code;
  
  coap_pdu_t *storage_pdu = oscore_shadow_pdu(pdu, 
                       coap_session_max_pdu_size(session)); 
                 /* contains part from pdu to be encrypted */
  uint8_t *ciphertext_buffer = NULL;
  uint8_t aad_buffer[AAD_BUF_LEN];
  uint8_t nonce_buffer[13];
  int16_t ciphertext_len = 0;
  oscore_ctx_t *osc_ctx = (oscore_ctx_t *)ctx->osc_ctx; 
  cose_encrypt0_t cose[1];
  cose_encrypt0_init(cose);  /* clears cose memory */
  cose_sign1_t sign[1];
  cose_sign1_init(sign);  /* clear sign memory */
  if(osc_ctx == NULL) {
    coap_log(LOG_CRIT,"OSCORE Security Context not found.\n");
    return NULL;
  }
  uint8_t group = 0;
  if (osc_ctx->mode == OSCORE_GROUP) group = 1;
  coap_opt_iterator_t opt_iter;
  coap_opt_t *opt = NULL; 
  opt = coap_check_option(pdu, COAP_OPTION_OSCORE, &opt_iter);
  if (opt){ /* no double encryption */
	coap_log(LOG_CRIT,"message is already encrypted.\n");
    return NULL;
  }

/* all seems to be OK, just go ahead    */
  oscore_pdu_print(pdu, "\nORIGINAL PDU in oscore_message_encrypt    \n");
  if(coap_request) oscore_increment_sender_seq(osc_ctx);
  oscore_enc_fill_cose(coap_request, cose, osc_ctx);
  uint16_t aad_len = oscore_prepare_aad(group, osc_ctx, cose,
                                         NULL, 0, aad_buffer);
  assert(aad_len < AAD_BUF_LEN);
  cose_encrypt0_set_aad(cose, aad_buffer, aad_len);
  oscore_generate_nonce(cose, osc_ctx, nonce_buffer, 13);
  cose_encrypt0_set_nonce(cose, nonce_buffer, 13);
/* cose is modified for encode option in response message */
  if(!coap_request){
    if (group != 1)
              cose_encrypt0_set_key_id(cose, NULL, 0);
    cose_encrypt0_set_partial_iv(cose, NULL, 0);
  }

/* oscore option is created in oscore_external_option_copy  */
  oscore_external_option_copy( cose, group, pdu, storage_pdu, 
                                        encrypt_pdu);
/* storage_pdu contains options and payload to be encrypted */
/* encrypt_pdu contains token and external options  */
/* now encrypt the payload with options from storage_pdu */
/* payload copy of storage_pdu to cose plaintext */
  uint8_t *start_plaintext = storage_pdu->token +
                                  storage_pdu->token_length -1;
  *start_plaintext = pdu->code;
  size_t tag_len = cose_tag_len(cose->alg);
/* pdu->code precedes token in oscore payload */
  size_t plaintext_len = storage_pdu->used_size - 
                                  storage_pdu->token_length + 1;
  cose_encrypt0_set_plaintext(cose, start_plaintext,
                                  plaintext_len);
  ciphertext_buffer = coap_malloc(
       plaintext_len + tag_len + Ed25519_SIGNATURE_LEN + 1);
  ciphertext_len = cose_encrypt0_encrypt(cose,
             ciphertext_buffer, plaintext_len + tag_len);
  if (ciphertext_len < 0){
       coap_log(LOG_WARNING,"OSCORE encryption Failure \n");
       coap_delete_pdu(encrypt_pdu);
       return NULL;
  }
  assert(ciphertext_len  < plaintext_len + tag_len + 1);
  if (osc_ctx->mode == OSCORE_GROUP ){

/* sign request message     */
     uint8_t *sig_buffer = NULL;
     uint8_t oscore_option[20];
     size_t option_len = oscore_encode_option_value( 
                           oscore_option, cose, OSCORE_GROUP);
/* cose was modified oscore-option fill  */
     oscore_enc_fill_cose(coap_request, cose, osc_ctx);
     aad_len = oscore_prepare_int(osc_ctx->mode, osc_ctx, cose,
                          oscore_option, option_len, aad_buffer);
     sig_buffer = coap_malloc(aad_len + ciphertext_len + 30);
     oscore_populate_sign(coap_request, sign, osc_ctx);
     size_t sig_len = oscore_prepare_sig_structure(sig_buffer, 
     aad_buffer, aad_len, ciphertext_buffer, ciphertext_len);
     assert(aad_len + ciphertext_len + 30 > sig_len);
     uint8_t *st_signature = ciphertext_buffer + ciphertext_len;
     cose_sign1_set_signature(sign, st_signature);
     cose_sign1_set_ciphertext(sign, sig_buffer, sig_len);
     int sign_res = cose_sign1_sign(sign);
     coap_free(sig_buffer);
     if (sign_res ==0){
       coap_log(LOG_WARNING,"OSCORE signature Failure \n");
       coap_delete_pdu(encrypt_pdu);
       return NULL;
     }
/* signature at end of encrypted text  */
     ciphertext_len = ciphertext_len + Ed25519_SIGNATURE_LEN;
   }  
// Add  encrypted payload to final message in pdu
  coap_add_data(encrypt_pdu, ciphertext_len, ciphertext_buffer);
  coap_free_type(COAP_OSCORE_BUF, ciphertext_buffer);
  coap_delete_pdu(storage_pdu);
  oscore_pdu_print(encrypt_pdu, "\nMODIFIED PDU in oscore_message_encrypt    \n");
  return encrypt_pdu;
}


//
// oscore_prepare_sig_structure
// creates and sets structure to be signed
size_t
oscore_prepare_sig_structure(uint8_t *sig_ptr,
uint8_t *aad_buffer, uint16_t aad_len,
uint8_t *text, uint16_t text_len)
{
  uint16_t sig_len = 0;
  char countersig0[] = "CounterSignature0";
  sig_len += cbor_put_array(&sig_ptr, 5);
  sig_len += cbor_put_text(&sig_ptr, countersig0, strlen(countersig0));
  sig_len += cbor_put_bytes(&sig_ptr, NULL, 0);
  sig_len += cbor_put_bytes(&sig_ptr, NULL, 0);
  sig_len += cbor_put_bytes(&sig_ptr, 
                  aad_buffer, aad_len); 
  sig_len += cbor_put_bytes(&sig_ptr, text, text_len);
  return sig_len;

}


//
// oscore_prepare_aad
/* Creates and sets External AAD for encryption */
size_t
oscore_prepare_aad(uint8_t group, oscore_ctx_t *ctx, cose_encrypt0_t *cose,     uint8_t *oscore_option, size_t oscore_option_len, uint8_t *buffer)
{
  uint8_t external_aad_buffer[40];
  uint8_t *external_aad_ptr = external_aad_buffer;
  uint8_t external_aad_len = 0;
  /* Serialize the External AAD*/
  external_aad_len = oscore_prepare_int(group, ctx, cose, oscore_option, oscore_option_len, external_aad_ptr);
  
  uint8_t ret = 0;
  char encrypt0[] = "Encrypt0";
  /* Begin creating the AAD */
  ret += cbor_put_array(&buffer, 3);
  ret += cbor_put_text(&buffer, encrypt0, strlen(encrypt0));
  ret += cbor_put_bytes(&buffer, NULL, 0);
  ret += cbor_put_bytes(&buffer, external_aad_buffer, external_aad_len);  

  return ret;
}

//
// oscore_generate_nonce
/* Creates Nonce */
void
oscore_generate_nonce(cose_encrypt0_t *ptr, oscore_ctx_t *ctx, uint8_t *buffer, uint8_t size)
{
  memset(buffer, 0, size);
  buffer[0] = (uint8_t)(ptr->key_id_len);
  memcpy(&(buffer[((size - 5) - ptr->key_id_len)]), ptr->key_id, ptr->key_id_len);
  memcpy(&(buffer[size - ptr->partial_iv_len]), ptr->partial_iv, ptr->partial_iv_len);
  for(int i = 0; i < size; i++) {
    buffer[i] = buffer[i] ^ (uint8_t)ctx->common_iv[i];
  }
}


//
// oscore_validate_sender_seq
//
/*Return 1 if OK, 0 otherwise */
uint8_t
oscore_validate_sender_seq(oscore_recipient_ctx_t *ctx, cose_encrypt0_t *cose)
{
  uint64_t incoming_seq = btou64(cose->partial_iv, cose->partial_iv_len);
 
  ctx->rollback_last_seq = ctx->last_seq;
  ctx->rollback_sliding_window = ctx->sliding_window;

  /* special case with incoming sequence rolled over to 0 */
  if (incoming_seq == 0){
    ctx->last_seq = 0;
    ctx->initial_state = 1;
  }

  /* Special case since we do not use unisgned int for seq */
  if(ctx->initial_state == 1) {
      ctx->initial_state = 0;
      int shift = incoming_seq - ctx->last_seq;
      ctx->sliding_window = ctx->sliding_window << shift;
      ctx->sliding_window = ctx->sliding_window | 1;
      ctx->last_seq = incoming_seq;
      return 1;
  }
  if(incoming_seq >= OSCORE_SEQ_MAX) {
    coap_log(LOG_WARNING,"OSCORE Replay protection, SEQ larger than SEQ_MAX.\n");
    return 0;
  }

  if(incoming_seq > ctx->last_seq) {
    /* Update the replay window */
    int shift = incoming_seq - ctx->last_seq;
    ctx->sliding_window = ctx->sliding_window << shift;
    ctx->sliding_window = ctx->sliding_window | 1;
    ctx->last_seq = incoming_seq;
  } else if(incoming_seq == ctx->last_seq) {
      coap_log(LOG_WARNING, "OSCORE Replay protextion, replayed SEQ.\n");
      return 0;
  } else { /* seq < recipient_seq */
    if(incoming_seq + ctx->replay_window_size < ctx->last_seq) {
       coap_log(LOG_WARNING, "OSCORE Replay protection, SEQ outside of replay window.\n");
      return 0;
    }
    /* seq+replay_window_size > recipient_seq */
    int shift = ctx->last_seq - incoming_seq;
    uint32_t pattern = 1 << shift;
    uint32_t verifier = ctx->sliding_window & pattern;
    verifier = verifier >> shift;
    if(verifier == 1) {
	  coap_log(LOG_WARNING,"OSCORE Replay protection, replayed SEQ.\n");
      return 0;
    }
    ctx->sliding_window = ctx->sliding_window | pattern;
  }

  return 1;
}

//
// oscore_increment_sender_seq
//
/* Return 0 if SEQ MAX, return 1 if OK */
uint8_t
oscore_increment_sender_seq(oscore_ctx_t *ctx)
{
  ctx->sender_context->seq++;

  if(ctx->sender_context->seq >= OSCORE_SEQ_MAX) {
    return 0;
  } else {
    return 1;
  }
}

//
// oscore_roll_back_seq
/* Restore the sequence number and replay-window to the previous state. This is to be used when decryption fail. */
void
oscore_roll_back_seq(oscore_recipient_ctx_t *ctx)
{
	
  if(ctx->rollback_sliding_window != 0) {
    ctx->sliding_window = ctx->rollback_sliding_window;
    ctx->rollback_sliding_window = 0;
  }
  if(ctx->rollback_last_seq != 0) {
    ctx->last_seq = ctx->rollback_last_seq;
    ctx->rollback_last_seq = 0;
  }
}


