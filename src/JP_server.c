/* Join_proxy-server -- implementation of Registrar using
 * a simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 * Join_proxy Server  is added by:
 * Peter van der Stok <consultancy@vanderstok.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 *
 * Join_proxy uses est-coaps and constrained-voucher and constrained-join-proxy drafts
 * to realize BRSKI
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <sys/stat.h>
#include <errno.h>
#include <signal.h>
#ifdef _WIN32
#define strcasecmp _stricmp
#include "getopt.c"
#if !defined(S_ISDIR)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif
#else
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>
#include <time.h>
#endif


#include "oscore_oauth.h"
#include "coap_server.h"
#include "oscore.h"
#include "oscore-context.h"
#include "cbor.h"
#include "cose.h"
#include "coap_session.h"
#include "coap_internal.h"
#include "JP_server.h"
#include "brski.h"
#include "utlist.h"
#include "client_request.h"
#include "coap_dtls.h"
#include <coap.h>

/* global coap_start variables */
#define MAX_USER 128 /* Maximum length of a user name (i.e., PSK
                      * identity) in bytes. */
#define MAX_KEY   64 /* Maximum length of a key (i.e., PSK) in bytes. */

#define FLAGS_BLOCK 0x01

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

#define BOOT_KEY    1
#define BOOT_NAME   2

#define JP_DEFAULT_PORT  5685

static coap_context_t *jp_ctx = NULL;

void
jp_set_context(coap_context_t *ctx){
	jp_ctx = ctx;
}

coap_context_t *
jp_get_context(void){
	return jp_ctx;
}


/* reference to AS; to be returned when no oscore encryption */
static uint8_t *IP_AS = NULL;
static size_t  IP_AS_len = 0;

/* shared key between AS and Registrar for boot */
static uint8_t *ASRG_KEY = NULL;
static uint8_t *ASRG_key_id = NULL;
static size_t  ASRG_key_id_len = 0; 
// static uint8_t ASRG_IV[COSE_algorithm_AES_CCM_16_64_128_IV_LEN];

/* stores data for block2 return */
static coap_string_t JP_ret_data = {
	.length = 0,
	.s = NULL
};

status_t  *STATUS = NULL;

typedef struct ih_def_t {
  char* hint_match;
  coap_bin_const_t *new_identity;
  coap_bin_const_t *new_key;
} ih_def_t;
              
     
#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */


/*
 * Return error and error message
 */
static void
oscore_error_return(uint8_t error, coap_pdu_t *response,
                                       const char *message){
  unsigned char opt_buf[5];
  coap_log(LOG_WARNING,"%s",message);
  response->code = error;
  response->data = NULL;
  response->used_size = response->token_length;
  coap_add_option(response,
                COAP_OPTION_CONTENT_FORMAT,
                coap_encode_var_safe(opt_buf, sizeof(opt_buf),
                COAP_MEDIATYPE_TEXT_PLAIN), opt_buf);
  coap_add_data(response, strlen(message), 
                                  (const uint8_t *)message);
}

static void
jp_return_bootkey(coap_string_t *response)
{
  int nr =0;
  uint8_t req_buf[30];
  uint8_t *buf = req_buf;
  coap_string_t *uri_port = getURI(JP_STANDARD_PORT);
  if (ASRG_KEY != NULL)free(ASRG_KEY);
  ASRG_KEY = coap_malloc(COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);
  prng(ASRG_KEY, COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);

  nr += cbor_put_map(&buf, 2);
  nr += cbor_put_number(&buf, BOOT_KEY);
  nr += cbor_put_bytes(&buf, ASRG_KEY, COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);
  nr += cbor_put_number(&buf, BOOT_NAME);
  nr += cbor_put_bytes(&buf, uri_port->s, uri_port->length);
  response->length = nr;
  response->s = coap_malloc(nr);
  memcpy(response->s,req_buf, nr);
  return;
}


/*
 * POST handler - /RG/boot
 * receives request to bootstrap Registrar server
 * connection via unprotected direct wifi
 * creation of oscore shared secret between Registrar and its creator
 * reception of wifi ssid and password.
 */
static void
JP_hnd_post_boot(coap_context_t *ctx UNUSED_PARAM,
                coap_resource_t *resource,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response
) {
  uint8_t* data = NULL;
  size_t size = 0; 
  uint8_t  ok = 0;
  uint8_t  tag = 0;
  
	/* check whether data need to be returend */
  if (request) {
	coap_block_t block2 = { 0, 0, 0};
	if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)){	
      coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_ACE_CBOR, -1,
                                 JP_ret_data.length, JP_ret_data.s);
     return;
     } /* coap_get_block */
  } /* request */
	
  data = assemble_data(session, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */
  if ((data == NULL) | (size == 0)){
	  oscore_error_return(COAP_RESPONSE_CODE(400), 
      response, "Did not find request data\n");
	  return;
  }
  coap_string_t *uri_port = getURI(JP_STANDARD_PORT);
  if (uri_port == NULL){
	  oscore_error_return(COAP_RESPONSE_CODE(400), 
          response, "URI information is not available\n");
  }
  if (uri_port->s == NULL){
	  oscore_error_return(COAP_RESPONSE_CODE(400), 
          response, "URI information is not initialized\n");
  }
    uint8_t  elem = cbor_get_next_element(&data);
    if (elem == CBOR_MAP){ 
      uint64_t map_size = cbor_get_element_size(&data);
      for (uint i=0 ; i < map_size; i++){
        tag = cose_get_tag(&data);
        switch (tag){
          case OAUTH_CLAIM_ACCESSTOKEN:
            if (ASRG_key_id != NULL) free(ASRG_key_id);
            cbor_get_string_array(&data, 
                           &ASRG_key_id, &ASRG_key_id_len);
            break;
          case OAUTH_CLAIM_KEYINFO:
            if (IP_AS != NULL) free(IP_AS);
            cbor_get_string_array(&data, 
                           &IP_AS, &IP_AS_len);
            break;
          default:
            ok = 1;
            break;
        } /* switch  */ 
        if(ok != 0){
          oscore_error_return(COAP_RESPONSE_CODE(400), 
          response, "Decode error in switch boot payload\n");
          return;
        } /* if ok */
      } /* for map_size  */
      if(JP_ret_data.s != NULL)coap_free(JP_ret_data.s);
      jp_return_bootkey(&JP_ret_data);
    } /* if elem */
    response->code = COAP_RESPONSE_CODE(201);  
    coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_ACE_CBOR, -1,
                                 JP_ret_data.length, JP_ret_data.s);   
    return; 
}


#define HANDLE_BLOCK1(Pdu)                                        \
  ((method == COAP_REQUEST_PUT || method == COAP_REQUEST_POST) && \
   ((flags & FLAGS_BLOCK) == 0) &&                                \
   ((Pdu)->hdr->code == COAP_RESPONSE_CODE(201) ||                \
    (Pdu)->hdr->code == COAP_RESPONSE_CODE(204)))


 
/*
 * init resources for JP
 */

void
JP_init_resources(coap_context_t *ctx) {
	
/* creates resources for join_proxy */
  
  coap_resource_t *r;
  r = coap_resource_init(NULL, 0);
  
  r = coap_resource_init(coap_make_str_const("est/boot"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_POST, JP_hnd_post_boot); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("60"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"boot Registrar\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"oic.d.registrar\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"ocf boot device\""), 0);
  coap_add_resource(ctx, r);

}

