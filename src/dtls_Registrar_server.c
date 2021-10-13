/* Registrar-server -- implementation of Registrar using
 * a simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 * Registrar Server (RS) is added by:
 * Peter van der Stok <consultancy@vanderstok.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 *
 * Registrar uses est-coaps and constrained-voucher drafts
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
#include "Registrar_server.h"
#include "brski.h"
#include "utlist.h"
#include "client_request.h"
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

/* reference to AS; to be returned when no oscore encryption */
static uint8_t *IP_AS = NULL;
static size_t  IP_AS_len = 0;

/* name and IP address of switch to be used in AS */
static coap_string_t IP_RG = {.length =0, .s = NULL};
static coap_string_t RG_identifier = {.length =0, .s = NULL};

/* shared key between AS and Registrar for boot */
static uint8_t *ASRG_KEY = NULL;
static uint8_t *ASRG_key_id = NULL;
static size_t  ASRG_key_id_len = 0; 
// static uint8_t ASRG_IV[COSE_algorithm_AES_CCM_16_64_128_IV_LEN];

/* stores data for block2 return */
static coap_string_t RG_ret_data = {
	.length = 0,
	.s = NULL
};

static status_t  *STATUS = NULL;
static uint8_t multiple_pledge_entries = 1;       /* multiple enroll of a pledge is not allowed  */

void set_multiple_pledge_entries(void){
  multiple_pledge_entries = 0;
}

typedef struct ih_def_t {
  char* hint_match;
  coap_bin_const_t *new_identity;
  coap_bin_const_t *new_key;
} ih_def_t;


static int
client_verify_cn_callback(const char *cn,
                   const uint8_t *asn1_public_cert UNUSED_PARAM,
                   size_t asn1_length UNUSED_PARAM,
                   coap_session_t *session UNUSED_PARAM,
                   unsigned depth,
                   int validated UNUSED_PARAM,
                   void *arg UNUSED_PARAM
) {
  coap_log(LOG_INFO, "CN '%s' presented by server (%s)\n",
           cn, depth ? "CA" : "Certificate");
  return 1;
}


static uint16_t masa_code = 0;
static coap_string_t masa_voucher = {
	.length = 0,
	.s = NULL
};
                   

static uint16_t audit_code = 0;
static coap_string_t audit_log = {
	.length = 0,
	.s = NULL
};


typedef struct continue_t{
	coap_context_t         *ctx;
    coap_resource_t        *resource;
    coap_session_t         *session;
    coap_pdu_t             *request;
    coap_pdu_t             *response;
    coap_binary_t          *token;
} continue_t;

/* this is non-reentrant *
 * for reentrancy,a Struct needs to be created per session  */
 
continue_t CONTINUATION;
     
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

/* cr_namenr(uint8_t *result)
 * creates identifier of 6 ciphers for unique name
 */
static void
cr_namenr(uint8_t * result){
   uint32_t numb=rand();
   for (uint8_t qq=0; qq < 6; qq++){
     uint32_t numb10 = numb/10;
     result[qq] = numb -10*numb10 +0x30;
     numb = numb10;
   }
}

static void
RG_return_bootkey(coap_string_t *response)
{
  int nr =0;
  uint8_t req_buf[30];
  uint8_t *buf = req_buf;
  if (ASRG_KEY != NULL)free(ASRG_KEY);
  ASRG_KEY = coap_malloc(COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);
  prng(ASRG_KEY, COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);

  nr += cbor_put_map(&buf, 2);
  nr += cbor_put_number(&buf, BOOT_KEY);
  nr += cbor_put_bytes(&buf, ASRG_KEY, COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);
  nr += cbor_put_number(&buf, BOOT_NAME);
  nr += cbor_put_bytes(&buf, RG_identifier.s, RG_identifier.length);
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
RG_hnd_post_boot(coap_context_t *ctx UNUSED_PARAM,
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
                                 RG_ret_data.length, RG_ret_data.s);
     return;
     } /* coap_get_block */
  } /* request */
	
  data = assemble_data(resource, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */
  if ((data == NULL) | (size == 0)){
	  oscore_error_return(COAP_RESPONSE_CODE(400), 
      response, "Did not find request data\n");
	  return;
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
      if(RG_ret_data.s != NULL)coap_free(RG_ret_data.s);
      RG_ret_data.s = NULL;
      RG_return_bootkey(&RG_ret_data);
    } /* if elem */
    response->code = COAP_RESPONSE_CODE(201);  
    coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_ACE_CBOR, -1,
                                 RG_ret_data.length, RG_ret_data.s);   
    return; 
}


#define HANDLE_BLOCK1(Pdu)                                        \
  ((method == COAP_REQUEST_PUT || method == COAP_REQUEST_POST) && \
   ((flags & FLAGS_BLOCK) == 0) &&                                \
   ((Pdu)->hdr->code == COAP_RESPONSE_CODE(201) ||                \
    (Pdu)->hdr->code == COAP_RESPONSE_CODE(204)))

/* find_status_session
 * find status of pledge for current session
 */
static  status_t *
find_status_session(coap_session_t *session){
	status_t *status = STATUS;
	while (status != NULL){
		if (status->session == session) return status;
		status = status->next;
	}
	return NULL;
}

/* stores return audit_log returned by /est/ra of MASA *
 * and returns it to client of registrar
 */
static int16_t
add_audit_log( unsigned char *data, size_t len, uint16_t code, 
                            uint16_t block_num, uint16_t more) {							
	if (block_num == 0){							
      if (audit_log.s != NULL)coap_free(audit_log.s);
      audit_log.s = NULL;
      audit_log.length = 0;
    }
    audit_code = code;
    if ((code >> 5) == 2) { 
      size_t offset = audit_log.length;
      /* Add in new block to end of current data */
      coap_string_t new_mess = {.length = audit_log.length, .s = audit_log.s};
      audit_log.length = offset + len;
      audit_log.s = coap_malloc(offset+len);
      if (offset != 0) 
        memcpy (audit_log.s, new_mess.s, offset);  /* copy old contents  */
      if (new_mess.s != NULL)coap_free(new_mess.s);
      memcpy(audit_log.s + offset, data, len);         /* add new contents  */  
        /* must change status dependent on audit log */
      if (more) return 0;   /* wait for other blocks  */
		  /* last block arrived */
      audit_t *audit = brski_parse_audit(&audit_log);
      status_t *status = find_status_session(CONTINUATION.session);
      brski_validate(status, audit);
      remove_audit(audit);
      unsigned char acceptable[] = "voucher is acceptable";
      coap_string_t payload = { .length = sizeof(acceptable), .s = acceptable};
      coap_pdu_t *pdu = NULL;
      unsigned char not_acceptable[] = "voucher is NOT acceptable";
      if (status->acceptable != VOUCHER_ACCEPTABLE){
        payload.s = not_acceptable;
        payload.length = sizeof(not_acceptable);
      } 
      reset_block();
      if (! (pdu = coap_new_request(CONTINUATION.ctx, CONTINUATION.session, COAP_RESPONSE_CODE( 205), NULL, payload.s, payload.length))) {
          return -1;;
      }
      if (status->acceptable != VOUCHER_ACCEPTABLE) pdu->code = COAP_RESPONSE_CODE(400);
      pdu->type = COAP_MESSAGE_CON;
      coap_log(LOG_DEBUG, "sending CoAP request:\n");
      if (coap_get_log_level() < LOG_DEBUG)
                           coap_show_pdu(LOG_INFO, pdu);
      coap_send(CONTINUATION.session, pdu);
      return 0;
    } else { /* error occurred  code != 2 */
      unsigned char not_acceptable[] = "voucher is NOT acceptable";
      coap_string_t payload = { .length = sizeof(not_acceptable), .s = not_acceptable};
      coap_pdu_t *pdu = NULL;
      reset_block();
      if (! (pdu = coap_new_request(CONTINUATION.ctx, CONTINUATION.session, COAP_RESPONSE_CODE( 400), NULL, payload.s, payload.length))) {
         return -1;
      }
      pdu->type = COAP_MESSAGE_CON;
      coap_log(LOG_DEBUG, "sending CoAP request:\n");
      if (coap_get_log_level() < LOG_DEBUG)
              coap_show_pdu(LOG_INFO, pdu);
      coap_send(CONTINUATION.session, pdu);
      return -1;
    }
}


/* stores masa voucher returned by /est/crts  of MASA *
 * and returns it to the client of registrar
 */
static int16_t
add_voucher( unsigned char *data, size_t len, uint16_t code, 
                       uint16_t block_num, uint16_t more) {
	if (block_num == 0){
      if (masa_voucher.s != NULL)coap_free(masa_voucher.s);
      masa_voucher.s = NULL;
      masa_voucher.length = 0;
    }
    masa_code = code;
    if ((code >> 5) == 2){
      size_t offset = masa_voucher.length;
      /* Add in new block to end of current data */
      coap_string_t new_mess = {.length = masa_voucher.length, .s = masa_voucher.s};
      masa_voucher.length = offset + len;
      masa_voucher.s = coap_malloc(offset+len);
      if (offset != 0) 
        memcpy (masa_voucher.s, new_mess.s, offset);  /* copy old contents  */
      if (new_mess.s != NULL)coap_free(new_mess.s);
      memcpy(masa_voucher.s + offset, data, len);         /* add new contents  */  
      if (more) return 0;   /* wait for other blocks  */
		  /* last block arrived */		
      coap_string_t payload = { .length = masa_voucher.length, .s = masa_voucher.s};
      coap_pdu_t *pdu = NULL;
      reset_block();
      if (! (pdu = coap_new_request(CONTINUATION.ctx, CONTINUATION.session, COAP_RESPONSE_CODE(205), NULL, payload.s, payload.length))) {
         return -1;;
      }
      pdu->type = COAP_MESSAGE_CON;
      coap_log(LOG_DEBUG, "sending CoAP request:\n");
      if (coap_get_log_level() < LOG_DEBUG)
             coap_show_pdu(LOG_INFO, pdu);
      coap_send(CONTINUATION.session, pdu);
      return 0;
    } else { /* error ocurred */
      coap_string_t payload = { .length = 0, .s = NULL};
      coap_pdu_t *pdu = NULL;
      reset_block();
      if (! (pdu = coap_new_request(CONTINUATION.ctx, CONTINUATION.session, COAP_RESPONSE_CODE(400), NULL, payload.s, payload.length))) {
         return -1;
      }
      pdu->type = COAP_MESSAGE_NON;
      coap_log(LOG_DEBUG, "sending CoAP request:\n");
      if (coap_get_log_level() < LOG_DEBUG)
             coap_show_pdu(LOG_INFO, pdu);
      coap_send(CONTINUATION.session, pdu);
      return -1;
    }
}


/* read_file_mem
 * reads file into memory 
 * returns data with length + 1
 */
static uint8_t *read_file_mem(const char* file, size_t *length) {
  FILE *f = fopen(file, "r");
  uint8_t *buf;
  struct stat statbuf;

  *length = 0;
  if (!f)
    return NULL;

  if (fstat(fileno(f), &statbuf) == -1) {
    fclose(f);
    return NULL;
  }
  buf = malloc(statbuf.st_size+1);
  if (!buf)
    return NULL;

  if (fread(buf, 1, statbuf.st_size, f) != (size_t)statbuf.st_size) {
    fclose(f);
    free(buf);
    return NULL;
  }
  buf[statbuf.st_size] = '\000';
  *length = (size_t)(statbuf.st_size + 1);
  fclose(f);
  return buf;
}

static int8_t 
insert_status(voucher_t *voucher_request, coap_string_t *request_voucher, coap_session_t *session){
	status_t *status = coap_malloc(sizeof(status_t));
	memset(status, 0, sizeof(status_t));
	status->next = STATUS;
	STATUS = status;
	if (voucher_request->cvr_nonce_len > 0){
      status->cvr_nonce= coap_malloc(voucher_request->cvr_nonce_len);
      status->cvr_nonce_len = voucher_request->cvr_nonce_len;
      memcpy(status->cvr_nonce, voucher_request->cvr_nonce, status->cvr_nonce_len);
    }
    if (voucher_request->cvr_idevid_len > 0){
      status->cvr_idevid = coap_malloc(voucher_request->cvr_idevid_len);
      status->cvr_idevid_len = voucher_request->cvr_idevid_len;
      memcpy(status->cvr_idevid, voucher_request->cvr_idevid, status->cvr_idevid_len);
    }
    if (voucher_request->serial_len > 0){
      status->serial = coap_malloc(voucher_request->serial_len);
      status->serial_len = voucher_request->serial_len;
      memcpy(status->serial, voucher_request->serial, status->serial_len);
    }
    status->session = session;
    if (request_voucher->length > 0){
      status->request_voucher = coap_malloc(request_voucher->length);
      status->rv_len = request_voucher->length;
	  memcpy(status->request_voucher, request_voucher->s, request_voucher->length);
    }
	status->acceptable = VOUCHER_ACCEPTABLE;   /* assume it is OK  */
	if (voucher_request->domainid_len > 0){
	  status->domainid = coap_malloc(voucher_request->domainid_len);
	  status->domainid_len = voucher_request->domainid_len;
	  memcpy(status->domainid, voucher_request->domainid, voucher_request->domainid_len);
    }
	return 0;
}



/* find_status_request
 * find status of pledge for given request_voucher
 */
static  status_t *
find_status_request(voucher_t *request){
	status_t *status = STATUS;
	while (status != NULL){
		if (request->domainid_len == status->domainid_len){
			if (memcmp(status->domainid, request->domainid, status->domainid_len) == 0)
			      return status;
		}
		if (request->cvr_idevid_len == status->cvr_idevid_len){
			if (memcmp(status->cvr_idevid, request->cvr_idevid, request->cvr_idevid_len) == 0)
			     return status;
		}
		status = status->next;
	}
	return NULL;
}

/*
 * call_MASA_ra
 * calls to MASA for request audit log (ra) request
 * ends original unsigned request_voucher to MASA
 * modifies contents of status when necessary
 */
int8_t
call_MASA_ra(status_t *status, coap_context_t *ctx){
  coap_string_t payload = { .length = status->rv_len, .s = status->request_voucher};
  if (payload.s == NULL) return 1;
  set_resp_handler(add_audit_log);
  set_scheme( COAP_URI_SCHEME_COAPS);
  set_method (COAP_REQUEST_POST);
  set_pki_callback(client_verify_cn_callback);
  char ra[] = "est/ra";
  coap_string_t path = {.length = strlen(ra), .s = (uint8_t *)ra}; 
  set_path( &path);
  set_payload(&payload);
  /* sends unsigned request_voucher */
  int8_t ok = coap_start_request(COAP_MEDIATYPE_APPLICATION_ACE_CBOR, ctx);
/* audit_log contains returned MASA log */
  return ok;
}

/*
 * call_MASA_rv
 * prepares call to MASA for request voucher (rv) request
 * and sends masa_request to MASA
 */
 int8_t
 call_MASA_rv(coap_string_t *masa_request, coap_string_t *return_voucher, coap_context_t * ctx){
  set_resp_handler(add_voucher);
  set_scheme( COAP_URI_SCHEME_COAPS);
  set_method (COAP_REQUEST_POST);
  set_pki_callback(client_verify_cn_callback);
  set_flags( FLAGS_BLOCK); 
  static char cert_nm[] = REGIS_SRV_COMB; 
  static char ca_nm[] = CA_REGIS_CRT;
  char *ca = ca_nm;
  char *cert = cert_nm;
  set_certificates( cert, ca);
  char rv[] = "est/rv";
  coap_string_t path = {.length = 0, .s = NULL}; 
  path.s = (uint8_t *)rv;
  path.length = strlen(rv);
  set_path( &path);
  set_method (COAP_REQUEST_POST);
  set_payload(masa_request);
  coap_start_session(ctx);
  return coap_start_request(COAP_MEDIATYPE_APPLICATION_VOUCHER_COSE_CBOR, ctx);
}

/*
 * GET handler - /est/vs
 * receives request to obtain voucher status
 * protected via DTLS
 */
void
RG_hnd_get_vs(coap_context_t *ctx,
                coap_resource_t *resource,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response)
{
  uint8_t* data = NULL;
  size_t size = 0; 
		/* check whether data need to be returend */
  if (request) {
	coap_block_t block2 = { 0, 0, 0};
	if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)){	
      coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_CSRATTRS, -1,
                                 RG_ret_data.length, RG_ret_data.s);
     return;
     } /* coap_get_block */
  } /* request */
	
  data = assemble_data(resource, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */
  if ((size < 1) | (data == NULL)){
	  oscore_error_return(COAP_RESPONSE_CODE(400), 
      response, "status did not arrive\n");
	  return;
  }
/* fill continuation for code execution after masa invocation */
  CONTINUATION.ctx = ctx;
  CONTINUATION.request = request;
  CONTINUATION.session = session;
  CONTINUATION.response = response;
  CONTINUATION.token = token;
  CONTINUATION.resource = resource;
  
  coap_string_t log = { .length = size, .s = data};
  /* log contains log data from pledge */
  status_t *status = find_status_session(session);
  if (status == NULL){
	  oscore_error_return(COAP_RESPONSE_CODE(400), 
      response, "no status for this DTLS connection\n");
	  return;
  }
  int8_t ok = brski_readstatus(&log, status);
  if (ok != 0){
  	  oscore_error_return(COAP_RESPONSE_CODE(400), 
      response, "voucher status data are not available\n");
	  return;
  }
  if (status->acceptable != VOUCHER_ACCEPTABLE){
	  oscore_error_return(COAP_RESPONSE_CODE(400), 
      response, "voucher is not acceptable\n");
	  return;
  }
  call_MASA_ra( status, ctx);
  response->used_size = response->token_length;
  response->type = COAP_MESSAGE_ACK;
  response->code = 0;  /* empty ack */
}

/*
 * GET handler - /est/es
 * receives request to obtain enroll status
 * protected via DTLS
 */
void
RG_hnd_get_es(coap_context_t *ctx UNUSED_PARAM,
                coap_resource_t *resource,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response)
{
  uint8_t* data = NULL;
  size_t size = 0; 
		/* check whether data need to be returend */
  if (request) {
	coap_block_t block2 = { 0, 0, 0};
	if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)){	
      coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_CSRATTRS, -1,
                                 RG_ret_data.length, RG_ret_data.s);
     return;
     } /* coap_get_block */
  } /* request */
	
  data = assemble_data(resource, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */
  response->code = COAP_RESPONSE_CODE(205); 
  RG_ret_data.length = 0;
  int8_t ok = brski_voucherstatus(&RG_ret_data);
  if (ok != 0){
	  oscore_error_return(COAP_RESPONSE_CODE(400), 
      response, "enroll status data not available\n");
	  return;
  }
  response->code = COAP_RESPONSE_CODE(203);  
}

/*
 * POST handler - /est/rv
 * receives request with request voucher
 * protected via DTLS
 */
void
RG_hnd_post_rv(coap_context_t *ctx,
                coap_resource_t *resource,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response)
{
  uint8_t* data = NULL;
  size_t size = 0; 
  coap_opt_iterator_t opt_iter;
  coap_opt_t *opt = NULL;
  const uint8_t *fm_value = NULL;   /* value of content-format option */
//  uint8_t fm_size;     /* size of content format OPTION */ 
		/* check whether data need to be returend */

  if (request) {
	coap_block_t block2 = { 0, 0, 0};
	if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)){	
      coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_VOUCHER_COSE_CBOR, -1,
                                 RG_ret_data.length, RG_ret_data.s);
     return;
     } /* coap_get_block */
  } /* request */
  data = assemble_data(resource, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */
  if ((data == NULL) || (size == 0)){
	  oscore_error_return(COAP_RESPONSE_CODE(400), 
      response, "Did not find request data\n");
	  return;
  }
  /* data points to request voucher with size */
  response->code = COAP_RESPONSE_CODE(205);
  opt = coap_check_option(request, COAP_OPTION_CONTENT_FORMAT, &opt_iter);
  if (opt){
    fm_value = coap_opt_value(opt);
  }
  /* fill continuation for code execution after masa invocation */
  CONTINUATION.ctx = ctx;
  CONTINUATION.request = request;
  CONTINUATION.session = session;
  CONTINUATION.response = response;
  CONTINUATION.token = token;
  CONTINUATION.resource = resource;
  
  coap_string_t *voucher_request = NULL;
  coap_string_t signed_voucher_request = {.s = NULL, .length = 0};
  signed_voucher_request.length = size;
  signed_voucher_request.s = data;
  char cpc[] = REGIS_CLIENT_DER;    /* contains pledge certificate in DER */
  char *file_name = cpc;
  voucher_t *req_contents = NULL;
  uint16_t ct = (fm_value[0]<<8) + fm_value[1];
  if (ct == COAP_MEDIATYPE_APPLICATION_VOUCHER_COSE_CBOR){
	  /* signed voucher_request  */
	  voucher_request = brski_verify_signature(&signed_voucher_request, file_name);
  }  else if (ct == COAP_MEDIATYPE_APPLICATION_ACE_CBOR){
	  voucher_request = coap_malloc(sizeof(coap_string_t));
	  voucher_request->length = size;
	  voucher_request->s = data;	
  }  else {
	  oscore_error_return(COAP_RESPONSE_CODE(400), 
              response, "illegal media format \n");
	  return;
  }
	  
  if (voucher_request != NULL){
	  req_contents = brski_parse_voucher(voucher_request);
  } 
  if (req_contents == NULL){
		  oscore_error_return(COAP_RESPONSE_CODE(400), 
              response, "voucher request cannot be parsed\n");
          if (voucher_request != NULL){
			  if ((voucher_request->s != NULL) && (voucher_request->s != data))coap_free(voucher_request->s);
			  coap_free(voucher_request);
		  }
	      return;
  }  /* if req_contents  */
  if (multiple_pledge_entries){
     if (find_status_request(req_contents) != NULL){
	   		  oscore_error_return(COAP_RESPONSE_CODE(400), 
              response, "this pledge is already enrolled\n");
          if (voucher_request != NULL){
			  if ((voucher_request->s != NULL) && (voucher_request->s != data))coap_free(voucher_request->s);
			  coap_free(voucher_request);
		  }
	      return;
	  }
   }
  /* voucher is accepted by registrar    */
  /* start a status log for this device  */
  /* identified by its serial number     */
  insert_status(req_contents, voucher_request, session);
  if ((voucher_request->s != NULL) && (voucher_request->s != data))coap_free(voucher_request->s);
  coap_free(voucher_request);
  coap_string_t masa_request= {.s = NULL, .length = 0};
  int8_t ok = brski_create_masa_request(&masa_request, req_contents, &signed_voucher_request, file_name);
  remove_voucher(req_contents);
  if (ok != 0){
	  oscore_error_return(COAP_RESPONSE_CODE(400), 
              response, "MASA voucher_request cannot be generated\n");
      if (masa_request.s != NULL) coap_free(masa_request.s);
	  return;
  }
  char crk[] = REGIS_SRV_KEY;
  char *key_file = crk;
  if (RG_ret_data.s != NULL) coap_free(RG_ret_data.s);
  RG_ret_data.s = NULL;
  RG_ret_data.length = 0;
  coap_string_t masa_request_sign= {.s = NULL, .length = 0};
  ok = brski_sign_payload(&masa_request_sign, &masa_request, key_file );
  if (ok != 0){
	 oscore_error_return(COAP_RESPONSE_CODE(400), 
              response, "cannot sign masa voucher_request\n");
     if (masa_request_sign.s != NULL) coap_free(masa_request_sign.s);
	 return; 
  }
  call_MASA_rv(&masa_request_sign, &RG_ret_data, ctx);
  response->type = COAP_MESSAGE_ACK;
  response->used_size = response->token_length;
  response->code = 0;  /* empty ack */
}

/*
 * GET handler - /est/crts
 * receives request to obtain CA certificate
 * protected via DTLS
 */
void
RG_hnd_get_crts(coap_context_t *ctx UNUSED_PARAM,
                coap_resource_t *resource,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response)
{
  uint8_t* data = NULL;
  size_t size = 0; 
		/* check whether data need to be returend */
  if (request) {
	coap_block_t block2 = { 0, 0, 0};
	if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)){	
      coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_PKCS7_CERTS, -1,
                                 RG_ret_data.length, RG_ret_data.s);
     return;
     } /* coap_get_block */
  } /* request */
	
  data = assemble_data(resource, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */
  response->code = COAP_RESPONSE_CODE(205); 
 
  int ok = brski_return_certificate(&RG_ret_data);
  if (ok != 0){
	  coap_log(LOG_ERR," certficate cannot be returned \n");
	  return;
  }
  coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_PKCS7_CERTS, -1,
                                 RG_ret_data.length, RG_ret_data.s);   
}

/*
 * POST handler - /est/sen
 * receives request to enroll
 * protected via DTLS
 */
void
RG_hnd_post_sen(coap_context_t *ctx UNUSED_PARAM,
                coap_resource_t *resource,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response)
{
  uint8_t* data = NULL;
  size_t size = 0; 
		/* check whether data need to be returned */
  if (request) {
	coap_block_t block2 = { 0, 0, 0};
	if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)){	
      coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_PKCS7_CERTS, -1,
                                 RG_ret_data.length, RG_ret_data.s);
     return;
     } /* coap_get_block */
  } /* request */
	
  data = assemble_data(resource, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */
  if ((data == NULL) | (size == 0)){
	  oscore_error_return(COAP_RESPONSE_CODE(400), 
      response, "Did not find request data\n");
	  return;
  }
  /* data points to csr with size */
  status_t *status = find_status_session(session);
  if (status->acceptable == VOUCHER_REJECTED){
	  oscore_error_return(COAP_RESPONSE_CODE(400), 
      response, "Voucher is not acceptable\n");
	  return;
  }
  response->code = COAP_RESPONSE_CODE(205); 

/* create certificate  */
  int8_t ok = brski_create_crt(&RG_ret_data, data, size);
  if (ok != 0){
	  oscore_error_return(COAP_RESPONSE_CODE(400), 
      response, "CRT cannot be created\n");
	  return;
  }

  coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_PKCS7_CERTS, -1,
                                 RG_ret_data.length, RG_ret_data.s);   
}

/*
 * POST handler - /est/sren
 * receives request to re-enroll
 * protected via DTLS
 */
void
RG_hnd_post_sren(coap_context_t *ctx UNUSED_PARAM,
                coap_resource_t *resource,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response)
{
  uint8_t* data = NULL;
  size_t size = 0; 
		/* check whether data need to be returend */
  if (request) {
	coap_block_t block2 = { 0, 0, 0};
	if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)){	
      coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_PKCS7_CERTS, -1,
                                 RG_ret_data.length, RG_ret_data.s);
     return;
     } /* coap_get_block */
  } /* request */
	
  data = assemble_data(resource, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */
  if ((data == NULL) | (size == 0)){
	  oscore_error_return(COAP_RESPONSE_CODE(400), 
      response, "Did not find request data\n");
	  return;
  }
   /* data points to csr with size */
  status_t *status = find_status_session(session);
  if (status->acceptable == VOUCHER_REJECTED){
	  oscore_error_return(COAP_RESPONSE_CODE(400), 
      response, "Voucher is not acceptable\n");
	  return;
  }
  response->code = COAP_RESPONSE_CODE(205); 
  int8_t ok = brski_create_crt(&RG_ret_data, data, size);
  if (ok != 0){
	  oscore_error_return(COAP_RESPONSE_CODE(400), 
      response, "CRT cannot be created\n");
	  return;
  }
  if (RG_ret_data.s == NULL) response->code = COAP_RESPONSE_CODE(400);
  coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_PKCS7_CERTS, -1,
                                 RG_ret_data.length, RG_ret_data.s);   
}

/*
 * POST handler - /est/skg
 * receives request to generate key
 * protected via DTLS
 */
void
RG_hnd_post_skg(coap_context_t *ctx UNUSED_PARAM,
                coap_resource_t *resource,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response)
{
  uint8_t *data = NULL;
  size_t size = 0; 
  uint8_t *response1 = NULL;
  size_t resp1_len= 0;
  uint8_t *response2 = NULL;
  size_t resp2_len= 0;
		/* check whether data need to be returend */
  if (request) {
	coap_block_t block2 = { 0, 0, 0};
	if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)){	
      coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_MULTIPART_CORE, -1,
                                 RG_ret_data.length, RG_ret_data.s);
     return;
     } /* coap_get_block */
  } /* request */
	
  data = assemble_data(resource, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */
  if ((data == NULL) | (size == 0)){
	  oscore_error_return(COAP_RESPONSE_CODE(400), 
      response, "Did not find request data\n");
	  return;
  }
  char file1[] = "/home/pi/certificates/8021ar/work/Wt1234.key.der";
  response1 = read_file_mem(file1, &resp1_len); 
  if (resp1_len > 0)resp1_len--;
  char file2[] = "/home/pi/certificates/8021ar/work/empty.cert.der";
  response2 = read_file_mem(file2, &resp2_len); 
  if (resp2_len > 0)resp2_len--;
  if (resp1_len != 0 && resp2_len != 0){
    response->code = COAP_RESPONSE_CODE(204); 
    RG_ret_data.length = resp1_len + resp2_len + 20;
    if (RG_ret_data.s != NULL) coap_free(RG_ret_data.s);
    RG_ret_data.s = coap_malloc(RG_ret_data.length);
    uint8_t *buf = RG_ret_data.s;
    size_t  nr = 0;
    nr += cbor_put_array(&buf, 4);
    nr += cbor_put_number(&buf, COAP_MEDIATYPE_APPLICATION_PKCS8);
    nr += cbor_put_bytes(&buf, response1, resp1_len);
    coap_free(response1);
    nr += cbor_put_number(&buf, COAP_MEDIATYPE_APPLICATION_PKCS7_CERTS);
    nr += cbor_put_bytes(&buf, response2, resp2_len);
    coap_free(response2);
    RG_ret_data.length = nr;
  }
  else {
	if (resp1_len > 0)coap_free(response1);
	if (resp2_len > 0)coap_free(response2);
	response->code = COAP_RESPONSE_CODE(400);
	RG_ret_data.length =  0;
	if (RG_ret_data.s != NULL) coap_free(RG_ret_data.s);
	RG_ret_data.s = NULL;
  }
  coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_MULTIPART_CORE, -1,
                                 RG_ret_data.length, RG_ret_data.s);   
}

/*
 * GET handler - /est/att
 * receives request to return certificate attributes
 * protected via DTLS
 */
void
RG_hnd_get_att(coap_context_t *ctx UNUSED_PARAM,
                coap_resource_t *resource,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response)
{
  uint8_t* data = NULL;
  size_t size = 0; 
		/* check whether data need to be returend */
  if (request) {
	coap_block_t block2 = { 0, 0, 0};
	if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)){	
      coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_CSRATTRS, -1,
                                 RG_ret_data.length, RG_ret_data.s);
     return;
     } /* coap_get_block */
  } /* request */
  
  data = assemble_data(resource, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */
  response->code = COAP_RESPONSE_CODE(205); 
  char file[] = CSR_ATTRIBUTES;
  RG_ret_data.s = read_file_mem(file, &RG_ret_data.length); 
  if (RG_ret_data.length > 0)RG_ret_data.length--;
  response->code = COAP_RESPONSE_CODE(201);  
  coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_CSRATTRS, -1,
                                 RG_ret_data.length, RG_ret_data.s);   
}


/*
 * GET handler - IP_brski_Port.s
 * receives requests and sends them on
 * receives responses and returns them on
 * encapsulates DTLS
 */
void
RG_hnd_proxy(coap_context_t *ctx UNUSED_PARAM,
                coap_resource_t *resource,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response)
{
  char  resp[] = "I am a brski join_proxy ";
  uint8_t *data = NULL;
  uint8_t *resp_data = (uint8_t *)resp;
  size_t data_len = strlen(resp); 
  size_t size = 0;
		/* check whether data need to be returend */
  if (request) {
	coap_block_t block2 = { 0, 0, 0};
	if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)){	
      coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_CSRATTRS, -1,
                                 RG_ret_data.length, RG_ret_data.s);
     return;
     } /* coap_get_block */
  } /* request */
  
  data = assemble_data(resource, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */

  response->code = COAP_RESPONSE_CODE(201);  
  coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_CSRATTRS, -1,
                                 data_len, resp_data);   
}

 
/*
 * init resources for RG
 */

void
RG_init_resources(coap_context_t *ctx) {
	
/* initialize of Authorization server issuer address*/
  struct ifaddrs *ifaddr, *ifa;
  int family, s;
  if (getifaddrs(&ifaddr) != -1) {
	 char host[NI_MAXHOST];
     ifa = ifaddr;
     while (ifa){
		 if (ifa->ifa_addr){
			family = ifa->ifa_addr->sa_family;
			s = getnameinfo(ifa->ifa_addr,
                 (family == AF_INET) ? sizeof(struct sockaddr_in) :
                                      sizeof(struct sockaddr_in6),
                     host, NI_MAXHOST,
                     NULL, 0, NI_NUMERICHOST);
            if (s == 0 && strlen(host) > 3){
			  uint8_t lan_att = 0;
			  for (uint8_t k = 0; k < strlen(host); k++) {
				  char ch = host[k];
				  if (ch == '%') lan_att = 1;
			  }
			  if (lan_att == 0){
				char prefix[] = "coap://[";
				uint8_t pre_len = strlen(prefix);
				uint8_t ep_len = strlen(prefix) + strlen(host) +1;
				char wlan0[] = "wlan0";
				if (strcmp(wlan0, ifa->ifa_name)  == 0){
			      IP_RG.s = malloc(ep_len+1);
			      IP_RG.length = ep_len;
			      memcpy(IP_RG.s, prefix, pre_len);
			      memcpy(IP_RG.s + pre_len, host, strlen(host));
			      IP_RG.s[ep_len-1] = ']';
			      IP_RG.s[ep_len] = 0;
			    }
		      }  /* lan_att */
	        }  /* s==0 */
		  } /* ifa->if_addr */
          ifa = ifa->ifa_next;
	 } /* while */        
  } /* getifaddrs  */
  freeifaddrs( ifaddr);	
  
  char uu_pre[] = "uu_RG";
  RG_identifier.length = 11;
  RG_identifier.s = coap_malloc(RG_identifier.length);
  memcpy(RG_identifier.s, uu_pre, 5);
  cr_namenr(RG_identifier.s + 5);
	
	/* creates resources
	 */
  
  
  coap_resource_t *r;

  r = coap_resource_init(NULL, 0);
  
    
r = coap_resource_init(coap_make_str_const("est/boot"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_POST, RG_hnd_post_boot); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("60"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"boot Registrar\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"oic.d.registrar\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"ocf boot device\""), 0);

  coap_add_resource(ctx, r);
  
  
r = coap_resource_init(coap_make_str_const("est/crts"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_GET, RG_hnd_get_crts);
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("60"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"Obtain CA certificate\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.est.crts\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"est-coaps\""), 0);

  coap_add_resource(ctx, r);

r = coap_resource_init(coap_make_str_const("est/sen"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_POST, RG_hnd_post_sen); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("286"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"Initial enrollment\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.est.sen\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"est-coaps\""), 0);

  coap_add_resource(ctx, r);
  
r = coap_resource_init(coap_make_str_const("est/sren"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_POST, RG_hnd_post_sren); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("286"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"Certificate reissuance\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.est.sren\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"est-coaps\""), 0);
  coap_add_resource(ctx, r);
  
r = coap_resource_init(coap_make_str_const("est/skg"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_POST, RG_hnd_post_skg); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("286"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"Server key generation\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.est.skg\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"est-coaps \""), 0);
  coap_add_resource(ctx, r);

r = coap_resource_init(coap_make_str_const("est/att"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_GET, RG_hnd_get_att); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("285"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"csr attributes\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.est.att\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"est-coaps \""), 0);
  coap_add_resource(ctx, r);
  
  r = coap_resource_init(coap_make_str_const("est/rv"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_POST, RG_hnd_post_rv); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("500"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"request voucher\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.est.rv\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"est-constrained-voucher \""), 0);
  coap_add_resource(ctx, r);
  
  r = coap_resource_init(coap_make_str_const("est/vs"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_GET, RG_hnd_get_vs); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("60"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"voucher status\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.est.vs\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"est-constrained-voucher\""), 0);
  coap_add_resource(ctx, r);
  
  r = coap_resource_init(coap_make_str_const("est/es"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_GET, RG_hnd_get_es); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("60"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"enroll status\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.est.es\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"est-constrained-voucher\""), 0);
  coap_add_resource(ctx, r);
  
  coap_string_t *uri_port = getURI(JP_BRSKI_PORT);
  if (uri_port != NULL){
	  if (uri_port->s != NULL){
         r = coap_resource_init(coap_make_str_const((const char *)uri_port->s), resource_flags);
         coap_register_handler(r, COAP_REQUEST_GET, RG_hnd_proxy); 
         coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("62"), 0);
         coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"brski-proxy\""), 0);
         coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"brski-port\""), 0);
         coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"join-proxy\""), 0);
         coap_add_resource(ctx, r);
      } else coap_log(LOG_WARNING,"brski URI does not exist  \n");
  } else coap_log(LOG_WARNING,"brski URI does not exist  \n");
}

