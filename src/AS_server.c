/* AS-server -- implementation of Authorization Server using
 * a simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 * Authorization Server (AS) is added by:
 * Peter van der Stok <consultancy@vanderstok.org>
 * This file relies on oscore
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 *
 * authorization for access are created by authz-info
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
#include "coap.h"
#include "AS_server.h"

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

#define COSE_algorithm_AES_CCM_16_64_128_SALT_LEN  8 /* for local use  */
#define BOOT_KEY     1
#define BOOT_NAME    2
#define KEY_REQUEST  1


/* shared keys between AS and Cx, SW */
static uint8_t *ASCx_KEY = NULL;
static uint8_t ASCx_KEY_LEN = 0;
static uint8_t *ASCx_key_id = NULL;
static size_t  ASCx_key_id_len = 0;
static char    ASSW_key_id[] = "ASSW_KEY";
static size_t  ASSW_key_id_len = 8;
static uint8_t *ASSW_KEY = NULL;
static uint8_t ASSW_KEY_LEN = 0;

/* IP address of AS
 * and unique identifier of AS
 */
static coap_string_t IP_AS = {.length =0, .s = NULL};
static coap_string_t AS_identifier = {.length =0, .s = NULL};

AS_server_t *server_chain = NULL;

/* stores data for block2 return */
coap_string_t return_data = {
	.length = 0,
	.s = NULL
};


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

/* cr_ident(void)
 * creates identifier of 6 characters for oscore context
 */
static char *
cr_ident(void){
   char *result=coap_malloc(6);
   uint32_t numb=rand();
   for (uint8_t qq=0; qq < 6; qq++){
     uint32_t numb10 = numb/10;
     result[qq] = numb -10*numb10 +0x30;
     numb = numb10;
   }
   return result;
}

/* AS _find_client
 * returns specified client entry
 */
static AS_client_t *
AS_find_client(uint8_t *client_name, size_t client_name_len, AS_client_t * current){
  while (current != NULL){
	  if (current->client_name_len == client_name_len){
	     if (strncmp((char *)current->client_name, (char *)client_name, client_name_len) == 0)
	           return current;
	  }
	  current = current->next;
  }
  return current;
}


/* AS_add_client
 * adds client to server
 */
static uint8_t
AS_add_client(AS_server_t *server_entry, AS_client_t *client_entry){
  AS_client_t *current = server_entry->clients;
  current = AS_find_client(client_entry->client_name, client_entry->client_name_len, current);
  /* client does not exist add client to server */
  client_entry->next = server_entry->clients;
  server_entry->clients = client_entry;
  return 0;
}


/* AS _find_server
 * returns specified server entry
 */
static AS_server_t *
AS_find_server(uint8_t *identifier, size_t identifier_len){
  AS_server_t *current = server_chain;
  while (current != NULL){
	  if (current->identifier_len == identifier_len){
	     if (strncmp((char *)current->identifier, (char *)identifier, identifier_len) == 0)
	           return current;
	  }
	  current = current->next;
  }
  return current;
}

/* AS _enter_server
 * inserts a new server entry into chain of servers
 */
static uint8_t 
AS_enter_server(AS_server_t *entry){
    AS_server_t *current = AS_find_server(
      entry->identifier, entry->identifier_len);
      /* enter server only once   */
    if (current == NULL){	
      entry->next = server_chain;
      server_chain = entry;
      return 0;
    }
    return 1;
}


/* fill_server_conf
 * fill configuration with server - client configuration
 */
static oauth_cnf_t *
fill_switch_conf(uint8_t *client_id, size_t client_id_len,
                 uint8_t *server_id, size_t server_id_len){
  oauth_cnf_t *cnf = coap_malloc(sizeof(oauth_cnf_t));
  memset(cnf, 0, sizeof(oauth_cnf_t));
  cnf->alg = COSE_Algorithm_AES_CCM_16_64_128;
  cnf->hkdf = COSE_Algorithm_HKDF_SHA_256;
  cnf->context_id = NULL;
  cnf->context_id_len = 0;
  cnf->server_id = coap_malloc(server_id_len);
  cnf->server_id_len = server_id_len;
  strncpy((char *)cnf->server_id, (char *)server_id, server_id_len);
  cnf->client_id = coap_malloc(client_id_len);
  cnf->client_id_len = client_id_len;
  strncpy((char *)cnf->client_id, (char *)client_id, client_id_len);
  cnf->rpl = OSCORE_DEFAULT_REPLAY_WINDOW;
  cnf->profile = OAUTH_PROF_COAP_OSCORE;
  cnf->exp = 1444064944;
  cnf->kty = COSE_KTY_OKP;
  cnf->ms = coap_malloc(COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);
  prng(cnf->ms, COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);
  cnf->ms_len = COSE_algorithm_AES_CCM_16_64_128_KEY_LEN;
  cnf->salt = coap_malloc(COSE_algorithm_AES_CCM_16_64_128_SALT_LEN);
  prng(cnf->salt, COSE_algorithm_AES_CCM_16_64_128_SALT_LEN);
  cnf->salt_len = COSE_algorithm_AES_CCM_16_64_128_SALT_LEN;
  return cnf;
}

	    
	    
	    
/* AS_create_context
 * creates context from information stored in token and salt_loc
 */
static void
AS_create_context(oauth_token_t *token, uint8_t *nonce){
  
  oauth_cnf_t *pt = token->osc_sec_config;
  uint8_t *rid  = coap_malloc(pt->server_id_len);
  uint8_t *cid  = coap_malloc(pt->client_id_len);
  uint8_t *ctid = coap_malloc(pt->context_id_len);
  uint8_t *ms   = coap_malloc(pt->ms_len);
  
  for (uint8_t qq =0; qq < pt->ms_len; qq++) 
                     ms[qq] = pt->ms[qq];
  for (uint8_t qq =0; qq < pt->client_id_len; qq++) 
                     cid[qq] = pt->client_id[qq];
  for (uint8_t qq =0; qq < pt->server_id_len; qq++) 
                     rid[qq] = pt->server_id[qq];
  for (uint8_t qq =0; qq < pt->context_id_len; qq++) 
                     ctid[qq] = pt->context_id[qq];
  oscore_ctx_t *osc_ctx = oscore_derive_ctx(
    ms, pt->ms_len, nonce, 24, 
    pt->alg,
    cid, pt->client_id_len, 
    rid, pt->server_id_len, 
    ctid, pt->context_id_len,
    OSCORE_DEFAULT_REPLAY_WINDOW);
    pt->ms = NULL;
    pt->ms_len = 0;
  oscore_enter_context(osc_ctx);
}

/* AS_prepare_aad
 * prepares aad for switch client and server 
 * to encrypt and decrypt
 */
static size_t
AS_prepare_aad(int8_t alg, uint8_t *aad_buffer){
  size_t ret = 0;
  uint8_t buffer[10];
  uint8_t *buf = buffer;
  size_t buf_len = 0;
  buf_len += cbor_put_map(&buf, 1);
  buf_len += cbor_put_number(&buf, COSE_HP_ALG);
  buf_len += cbor_put_number(&buf, alg);
  char encrypt0[] = "Encrypt0";
  /* Begin creating the AAD */
  ret += cbor_put_array(&aad_buffer, 3);
  ret += cbor_put_text(&aad_buffer, encrypt0, strlen(encrypt0));
  ret += cbor_put_bytes(&aad_buffer, buffer, buf_len);
  ret += cbor_put_bytes(&aad_buffer, NULL, 0); 
  return ret;
}

/* AS_return_bootkey
 * returns ASCx_KEY  
 */
static void
AS_return_bootkey(coap_string_t *result)
{
	/*return coap string with data*/

  int nr =0;
  uint8_t req_buf[30];
  uint8_t *buf = req_buf;
  ASCx_KEY_LEN = COSE_algorithm_AES_CCM_16_64_128_KEY_LEN;
  if (ASCx_KEY != NULL)free( ASCx_KEY);
  ASCx_KEY = coap_malloc(ASCx_KEY_LEN);
  prng(ASCx_KEY, ASCx_KEY_LEN);
  nr += cbor_put_map(&buf, 2);
  nr += cbor_put_number(&buf, BOOT_KEY);
  nr += cbor_put_bytes(&buf, ASCx_KEY, ASCx_KEY_LEN);
  nr += cbor_put_number(&buf, BOOT_NAME);
  nr += cbor_put_bytes(&buf, AS_identifier.s, AS_identifier.length);
  result->s = coap_malloc(nr);
  memcpy(result->s, req_buf, nr);
  result->length = nr;
}


/* AS_return_nonce
 * returns nonce  
 */
static void
AS_return_nonce(coap_string_t *result, uint8_t *cnonce)
{
  int nr =0;
  uint8_t req_buf[30];
  uint8_t *buf = req_buf;
 
  if (cnonce != NULL){ 
    nr += cbor_put_map(&buf, 1);
    nr += cbor_put_number(&buf, OAUTH_OSC_PROF_NONCE2);
    nr += cbor_put_bytes(&buf, cnonce, 8);
  }
  result->s = coap_malloc(nr);
  memcpy(result->s, req_buf, nr);
  result->length = nr;
}


/* AS_generate_token
 * generates token for access to server
 * to be returned by requesting client
 */
static size_t
AS_generate_token(AS_server_t *entry, uint8_t **token){
  uint16_t cti_cont = (uint16_t)rand();
  uint8_t *cti_pt  = (uint8_t *)&cti_cont;
  size_t len = 0;
  len += cbor_put_map(token, 7);
  len += cbor_put_number(token, CWT_CLAIM_ISS);
  len += cbor_put_bytes(token, IP_AS.s, IP_AS.length);
  len += cbor_put_number(token, CWT_CLAIM_AUD);
  len += cbor_put_bytes(token, entry->identifier, entry->identifier_len);
  len += cbor_put_number(token, CWT_CLAIM_EXP);
  len += cbor_put_number(token, 1444060944);
  len += cbor_put_number(token, CWT_CLAIM_CTI);
  len += cbor_put_bytes(token, cti_pt, 2);
  len += cbor_put_number(token, CWT_CLAIM_SCOPE);
  len += cbor_put_bytes(token, entry->scope,
                                     entry->scope_len);
  len += cbor_put_number(token, CWT_CLAIM_PROFILE);
  len += cbor_put_number(token,entry->profile);
  len += cbor_put_number(token, CWT_CLAIM_CNF);
/* establishes oscore security context between Client and server */
  len += cbor_put_map(token, 1);
  len += cbor_put_number(token, CWT_OSCORE_SECURITY_CONTEXT);
  len += oauth_create_OSCORE_Security_context(token, entry->oscore_context);
  return len;
}


/* AS_token_response
 * returns encrypted token in response
 * size = 0 when error occurred
 */
static  size_t 
AS_token_response(AS_server_t *entry, uint8_t **cwt, 
            uint8_t *iv, size_t iv_len, uint8_t * kid, size_t kid_len){
  uint8_t  *token_buf = coap_malloc(450);
  uint8_t  *token = token_buf;
  size_t len = oauth_create_encrypt_header(cwt, 
                               iv, iv_len, kid, kid_len);
  size_t token_len = AS_generate_token(entry, &token);       
  uint8_t aad_buffer[35];
  uint8_t *ciphertext = coap_malloc(450);
  int32_t ciphertext_len = 0;
  cose_encrypt0_t cose[1];
  cose_encrypt0_init(cose);  /* clears cose memory */
  cose_encrypt0_set_alg(cose, COSE_Algorithm_AES_CCM_16_64_128);
  cose_encrypt0_set_key(cose, entry->shared_secret, 
                      COSE_algorithm_AES_CCM_16_64_128_KEY_LEN );
  uint8_t aad_len = AS_prepare_aad(
                   COSE_Algorithm_AES_CCM_16_64_128, aad_buffer);
  cose_encrypt0_set_aad(cose, aad_buffer, aad_len);
  cose_encrypt0_set_nonce(cose, iv, 
                        COSE_algorithm_AES_CCM_16_64_128_IV_LEN);
  cose_encrypt0_set_plaintext(cose, token_buf, token_len);
  ciphertext_len = cose_encrypt0_encrypt(cose,
         ciphertext, 
         len + COSE_algorithm_AES_CCM_16_64_128_TAG_LEN);
  free(token_buf);
  if (ciphertext_len < 0) return 0;
  len += cbor_put_bytes(cwt, ciphertext, ciphertext_len);
  free(ciphertext);

  return len;                                 
}
								
/* AS_get_scope
 * fills the scope array of token
 * from the received CBOR map stored in the token->scope
 */
static uint8_t
AS_get_scope(uint8_t *data, uint8_t **scope, size_t *len){
  return cbor_get_string_array(&data, scope, len);
}


/* AS_client_print
 * prints client entry attributes
 */
static void
AS_client_print(AS_client_t *client_entry){
  if (coap_get_log_level() < LOG_DEBUG) return;
  if (client_entry != NULL){
	if(client_entry->client_name != NULL){
	  fprintf(stderr,"           client : ");
	  for (uint qq = 0; 
              qq < client_entry->client_name_len; qq++)
             fprintf(stderr,"%c",client_entry->client_name[qq]);
        fprintf(stderr,"\n");
	} 
	if(client_entry->client_id != NULL){
	  fprintf(stderr,"        client_id : ");
	  for (uint qq = 0; 
              qq < client_entry->client_id_len; qq++)
             fprintf(stderr,"%c",client_entry->client_id[qq]);
        fprintf(stderr,"\n");
	} 
    if(client_entry->iv != NULL){
	  fprintf(stderr,"               iv : ");
	  for (uint qq = 0; qq < client_entry->iv_len; qq++)
                  fprintf(stderr," %02x",client_entry->iv[qq]);
      fprintf(stderr,"\n");
	} 
  }  /* if client_entry  */
}

/* AS_server_print
 * prints all server entry attributes and itself
 */
static void
AS_server_print(AS_server_t *server_entry){
  if (coap_get_log_level() < LOG_DEBUG) return;
  if (server_entry != NULL){
	fprintf(stderr,"------server_entry----------------------\n");
	if(server_entry->identifier != NULL){
	  fprintf(stderr,"  identifier  :  ");
	  for (uint qq = 0; qq < server_entry->identifier_len; qq++)
              fprintf(stderr,"%c",server_entry->identifier[qq]);
        fprintf(stderr,"\n");
	}

	AS_client_t *pt = server_entry->clients;
    if (pt != NULL) fprintf(stderr,"     clients  :  \n");
	while( pt!= NULL){
      AS_client_print(pt);
      pt = pt->next;
	}
	if(server_entry->scope != NULL){
	  fprintf(stderr,"       scope  :  ");
	  for (uint qq = 0; qq < server_entry->scope_len; qq++)
                          fprintf(stderr,"%c",server_entry->scope[qq]);
      fprintf(stderr,"\n");
	}	
    if(server_entry->audience != NULL){
	  fprintf(stderr,"    audience  :  ");
	  for (uint qq = 0; qq < server_entry->audience_len; qq++)
                       fprintf(stderr,"%c",server_entry->audience[qq]);
      fprintf(stderr,"\n");
	}
    if(server_entry->shared_secret != NULL){
	  fprintf(stderr,"shared_secret :  ");
	  for (uint qq = 0; qq < server_entry->shared_secret_len; qq++)
                       fprintf(stderr," %02x",server_entry->shared_secret[qq]);
      fprintf(stderr,"\n");
	}
	fprintf(stderr,"     profile  :  ");
    fprintf(stderr,"%d \n", server_entry->profile);
	if(server_entry->AS_server != NULL){
	  fprintf(stderr,"   AS_server  :  ");
	  for (uint qq = 0; qq < server_entry->AS_server_len; qq++)
                       fprintf(stderr,"%c",server_entry->AS_server[qq]);
      fprintf(stderr,"\n");
	}
    if(server_entry->server_id != NULL){
	  fprintf(stderr,"   server_id  :  ");
	  for (uint qq = 0; qq < server_entry->server_id_len; qq++)
                       fprintf(stderr,"%c",server_entry->server_id[qq]);
      fprintf(stderr,"\n");
	}
	if(server_entry->oscore_context != NULL)
	                    oauth_print_conf(server_entry->oscore_context);
  }
}

/* AS_print_server_chain
 * print identifiers of chain of entered servers
 */
static void
AS_print_server_chain(void){
  if (coap_get_log_level() < LOG_DEBUG) return;
  AS_server_t *current = server_chain;
  fprintf(stderr, "----- chain of servers ------------\n");
  if (current == NULL){
	  fprintf(stderr,"   chain is empty  \n");
	  return;
  }
  while (current != NULL){
	  fprintf(stderr," entry identfier is :");
	  for (uint qq = 0; qq < current->identifier_len; qq++)
                     fprintf(stderr,"%c", current->identifier[qq]);
	  fprintf(stderr,"\n");
	  current = current->next;
  }  /* while  */
}
 
      
/* AS_client_delete
 * frees all client entry attributes and itself
 */
static void
AS_client_delete(AS_client_t *client_entry){
  if (client_entry != NULL){
    if(client_entry->client_id != NULL)
                       free(client_entry->client_id);
    if(client_entry->client_name != NULL)
                       free(client_entry->client_name);
    if(client_entry->iv != NULL)free(client_entry->iv);
    free(client_entry);
  }
}
 
/* AS_server_delete
 * frees all server entry attributes and itself
 */
static void
AS_server_delete(AS_server_t *server_entry){
  if (server_entry != NULL){
	if(server_entry->identifier != NULL)free(server_entry->identifier);
	while (server_entry->clients != NULL){
      AS_client_t *pt = server_entry->clients;
      server_entry->clients = pt->next;
      AS_client_delete(pt);
	}
	if(server_entry->scope != NULL)free(server_entry->scope);	
    if(server_entry->audience != NULL)free(server_entry->audience);
    if(server_entry->oscore_context != NULL)
                        oauth_delete_conf(server_entry->oscore_context);
    free(server_entry);
  }
}


/*
 * Return error and error message
 */
static void
oscore_error_return(uint8_t error, coap_pdu_t *response,
                                       const char *message){
  unsigned char opt_buf[5];
  coap_log(LOG_WARNING," %s",message);
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



#define AS_KEY_REQUEST  1

/*
 * POST handler - /AS/init
 * receives token encrypted with shared secret
 * to set up oscore connection between authorizer and AS
 */
static void
AS_hnd_post_init(coap_context_t *ctx UNUSED_PARAM,
                coap_resource_t *resource,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response
) {
	/* check whether data need to be returend */
  if (request) {
	coap_block_t block2 = { 0, 0, 0};
	if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)){	
      coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_ACE_CBOR, -1,
                                 return_data.length, return_data.s);
     return;
     } /* coap_get_block */
  } /* request */
				
  oauth_cwtkey_t *key_enc = NULL;
  size_t size;
  uint8_t *data;
  oauth_token_t *AS_token = NULL;
  uint8_t *cnonce = NULL;
  coap_log(LOG_DEBUG, "hnd_post_init start \n");
  coap_show_pdu(LOG_DEBUG, response);
  data = assemble_data(resource, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */
  if ((data == NULL) | (size == 0)){
	  oscore_error_return(COAP_RESPONSE_CODE(400), 
      response, "Did not find request data");
	  return;
  }
/* 
 * authorization client has sent oscore context data
 */
  coap_log(LOG_DEBUG, "hnd_post_init after assemble \n");
  coap_show_pdu(LOG_DEBUG, response);
  if (oauth_strip(&data, &cnonce, &key_enc) == 1){
    oscore_error_return(COAP_RESPONSE_CODE(400), 
                      response, "Cannot extract CWT\n");
    return;
  } /* if oauth_strip  */
 
/*  keyenc points to algorithm information 
    data points to encrypted CWT contained in CBOR_BYTE_STRING
    decryption is possible  */
  uint8_t aad_buffer[35];
  char ocf_switch[] = "oic_onoff";
  uint8_t *enc_token = key_enc->data;
  uint8_t elem = cbor_get_next_element(&enc_token);
  if (elem != CBOR_TAG){
    oscore_error_return(COAP_RESPONSE_CODE(400), 
            response, "No CWT tag found");
    return;
  }
  size_t aad_len = AS_prepare_aad(
                   COSE_Algorithm_AES_CCM_16_64_128, aad_buffer);
  AS_token = oauth_decrypt_token(&enc_token, ASCx_KEY, aad_buffer, aad_len);
  if (AS_token == NULL){
	oscore_error_return(COAP_RESPONSE_CODE(400), 
            response, "impossible to decrypt token");
    return;
  }
  size_t scope_len;
  uint8_t *scope = NULL;
  AS_get_scope(AS_token->scope, &scope, &scope_len);
  if ((strncmp((char *)scope, ocf_switch, scope_len) == 0)
             && (scope_len == strlen(ocf_switch))){
/* check authorization for switch manipulation */

  } /* if ocf_switch */
  else{
    oscore_error_return(COAP_RESPONSE_CODE(400), 
                               response, "Illegal scope value");
    return;
  }
  
/* cnonce contains received 8-byte nonce      */
  oauth_cnf_t *pt= AS_token->osc_sec_config;
  if (pt == NULL){
    oscore_error_return(COAP_RESPONSE_CODE(400), 
                               response, "configuration is missing");
    return;
  }
  uint8_t  *nonce = coap_malloc(24);
  uint32_t nonce1 = (uint32_t)rand();
  uint32_t nonce2 = (uint32_t)rand();
  for (int qq =0 ; qq < 4; qq ++){
     nonce[qq + 16] = ((nonce1 >> (qq*8)) & 0xFF);
     nonce[qq + 20] = ((nonce2 >> (qq*8)) & 0xFF);
     nonce[qq+8] = cnonce[qq];
     nonce[qq+12] = cnonce[qq+4];
     nonce[qq] = pt->salt[qq];
     nonce[qq+4] = pt->salt[qq+4];
  }
  /* nonce not be freeed because used in context */
  free(cnonce);
  if (return_data.s != NULL) coap_free(return_data.s);
  AS_create_context(AS_token, nonce);
  oauth_delete_token(AS_token);
  AS_return_nonce(&return_data, nonce+16);
  response->code = COAP_RESPONSE_CODE(204);
  coap_show_pdu(LOG_DEBUG, response);
  coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_ACE_CBOR, -1,
                                 return_data.length, return_data.s);
  return;
}


/*
 * POST handler - /AS/boot
 * receives request to bootstrap AS server
 * connection via unprotected direct wifi
 * creation of oscore shared secret between AS and its creator
 * reception of wifi ssid and password.
 */
static void
AS_hnd_post_boot(coap_context_t *ctx UNUSED_PARAM,
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
                                 return_data.length, return_data.s);
     return;
     } /* coap_get_block */
  } /* request */
  
  data = assemble_data(resource, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */
  fprintf(stderr, "in BOOT data = %p       size = %d \n", (void *)data, (int)size);
  if ((data == NULL) | (size == 0)){
     oscore_error_return(COAP_RESPONSE_CODE(400), 
      response, "Did not find request data");
     return;
  } 
    uint8_t  elem = cbor_get_next_element(&data);
    if (elem == CBOR_MAP){ 
      uint64_t map_size = cbor_get_element_size(&data);
      for (uint i=0 ; i < map_size; i++){
        tag = cose_get_tag(&data);
       switch (tag){
          case AS_KEY_REQUEST:
            if (ASCx_key_id != NULL) free(ASCx_key_id);
            cbor_get_string_array(&data, 
                           &ASCx_key_id, &ASCx_key_id_len);
            break;
          default:
            ok = 1;
            break;
        } /* switch  */ 
        if(ok != 0){
          oscore_error_return(COAP_RESPONSE_CODE(400), 
          response, "Decode error in AS boot payload");
          return;
        } /* if ok */
      } /* for map_size  */
      if (return_data.s != NULL)coap_free(return_data.s);
      AS_return_bootkey(&return_data);
    } /* if elem */
    response->code = COAP_RESPONSE_CODE(201);
    coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_ACE_CBOR, -1,
                                 return_data.length, return_data.s);
    return; 
}


/*
 * POST handler - /AS/server
 * receives request to add a server
 */
static void
AS_hnd_post_server(coap_context_t *ctx UNUSED_PARAM,
                coap_resource_t *resource,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response
) {
  uint8_t* data = NULL;
  size_t size = 0; 
  uint8_t  ok = 1;
  uint8_t  tag = 0;
  int64_t mm = 0;
  uint8_t *client_id = NULL;
  size_t  client_id_len = 0;
  
  if (!session->oscore_encryption){
     oscore_error_return(COAP_RESPONSE_CODE(401), 
     response, "No oscore protection");
     return;
  }
  
  data = assemble_data(resource, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */
  if ((data == NULL) | (size == 0)){
	  oscore_error_return(COAP_RESPONSE_CODE(400), 
      response, "Did not find request data");
	  return;
   }
/* data found */
	uint8_t  elem = cbor_get_next_element(&data);
    if (elem == CBOR_MAP){ 
      uint64_t map_size = cbor_get_element_size(&data);
      AS_server_t *server_entry = coap_malloc(sizeof(AS_server_t));
      memset (server_entry, 0, sizeof(AS_server_t));
      uint8_t *pt = NULL;
      for (uint i=0 ; i < map_size; i++){
        tag = cose_get_tag(&data);
        switch (tag){
          case CWT_CLAIM_SCOPE:
            ok = cbor_get_string_array(&data, &pt, 
                                            &server_entry->scope_len);
            server_entry->scope = pt;
            break;
          case CWT_CLAIM_ISS:
            ok = cbor_get_string_array(&data, &pt, 
                                         &server_entry->AS_server_len);
            server_entry->AS_server = pt;
            break;  
          case CWT_CLAIM_PROFILE:
            ok = cbor_get_number(&data, &mm);
            if (ok == 0)server_entry->profile = (uint8_t)mm;
            break;            
          case CWT_CLAIM_SUB:
            ok = cbor_get_string_array(&data, &pt, 
                                         &server_entry->identifier_len);
            server_entry->identifier = pt;
            break;
          case CWT_CLAIM_AUD:
            ok = cbor_get_string_array(&data, &pt, 
                                         &server_entry->audience_len);
            server_entry->audience = pt;
            break;
          case OAUTH_REQ_CLIENTSECRET:
            ok = cbor_get_string_array(&data, &pt, 
                                         &server_entry->shared_secret_len);
            server_entry->shared_secret = pt;
            break;
          case OAUTH_REQ_CLIENTID:
            ok = cbor_get_string_array(&data, &client_id, 
                                         &client_id_len);
            break;
          default:
            ok = 1;
            break;
        } /* switch  */ 
        if(ok != 0){
          oscore_error_return(COAP_RESPONSE_CODE(400), 
          response, "Decode error in AS server payload");
          if (client_id != NULL) free(client_id);
          AS_server_delete(server_entry);
          return;
        } /* if ok */
      } /* for map_size  */

      if (client_id != NULL) free(client_id);
      server_entry->server_id = (uint8_t *)cr_ident();
      server_entry->server_id_len = 6;
      server_entry->server_id[0] = 0x53;  /* S */
      server_entry->server_id[1] = 0x5f;  /* _ */
      if (ASSW_KEY != NULL) free(ASSW_KEY);
      ASSW_KEY = coap_malloc(server_entry->shared_secret_len);
      ASSW_KEY_LEN = server_entry->shared_secret_len;
      memcpy( ASSW_KEY, server_entry->shared_secret,
                             server_entry->shared_secret_len);
 
/* enter server  */
      ok = AS_enter_server(server_entry);
      if(ok != 0){
          oscore_error_return(COAP_RESPONSE_CODE(400), 
          response, "Server already exists");
          return;
      } /* if ok */
      AS_server_print(server_entry);
      AS_print_server_chain();
      response->code = COAP_RESPONSE_CODE(201);
    } /* if elem */
char empty[]="";
    coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_ACE_CBOR, -1,
                                 0, (uint8_t *)empty);
  return; 
}


/*
 * POST handler - /AS/client
 * receives request to add a client to a server
 */
static void
AS_hnd_post_client(coap_context_t *ctx UNUSED_PARAM,
                coap_resource_t *resource,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response
) {
  uint8_t* data = NULL;
  size_t size = 0; 
  uint8_t  ok = 1;
  uint8_t  tag = 0;
  
  
  if (!session->oscore_encryption){
     oscore_error_return(COAP_RESPONSE_CODE(401), 
     response, "No oscore protection");
     return;
  }
 
  data = assemble_data(resource, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */
  if ((data == NULL) | (size == 0)){
	  oscore_error_return(COAP_RESPONSE_CODE(400), 
      response, "Did not find request data");
	  return;
  }

/* data found */
	uint8_t  elem = cbor_get_next_element(&data);
    if (elem == CBOR_MAP){ 
      uint64_t map_size = cbor_get_element_size(&data);
      AS_client_t *client_entry = coap_malloc(sizeof(AS_client_t));
      memset (client_entry, 0, sizeof(AS_client_t));
      uint8_t *pt = NULL;
      uint8_t *identifier = NULL;
      size_t  identifier_len = 0;
      uint8_t *scope = NULL;
      size_t  scope_len = 0;
      uint8_t *AS_server = NULL;
      size_t  AS_server_len = 0;
      for (uint i=0 ; i < map_size; i++){
        tag = cose_get_tag(&data);
        switch (tag){
          case CWT_CLAIM_SCOPE:
            ok = cbor_get_string_array(&data, &scope, 
                                            &scope_len);
            break;
          case CWT_CLAIM_ISS:
            ok = cbor_get_string_array(&data, &AS_server, 
                                         &AS_server_len);
            break;  
          case CWT_CLAIM_AUD:
            ok = cbor_get_string_array(&data, &identifier, 
                                         &identifier_len);
            break;
          case OAUTH_REQ_CLIENTID:
            ok = cbor_get_string_array(&data, &pt, 
                                         &client_entry->client_name_len);
            client_entry->client_name = pt;
            break;
          default:
            ok = 1;
            break;
        } /* switch  */ 
 
      } /* for map_size  */
      if( ok != 0){
        oscore_error_return(COAP_RESPONSE_CODE(400), 
          response, "Decode error in AS server payload");
        if (scope != NULL) free(scope);
        if (AS_server != NULL) free(AS_server);
        AS_client_delete(client_entry);
        return;
	}
      client_entry->client_id = (uint8_t *)cr_ident();
      client_entry->client_id_len = 6;
      client_entry->client_id[0] = 0x43;  /* C */
      client_entry->client_id[1] = 0x5f;  /* _ */
      AS_server_t *server_entry = NULL;
      if (identifier != NULL){
         server_entry = AS_find_server(identifier, identifier_len);
         free( identifier);
      }
      if(server_entry == NULL){
          oscore_error_return(COAP_RESPONSE_CODE(400), 
          response, "Server does not exist");
          if (scope != NULL) free(scope);
          if (AS_server != NULL) free(AS_server);
          AS_client_delete(client_entry);
          return;
      } /* if server_entry */
      if (scope != NULL){
        ok = strncmp((char *)scope, (char *)server_entry->scope, scope_len);
        free(scope);
      } else ok = 1;
      if (AS_server != NULL) free(AS_server);
      if (ok != 0){
		 oscore_error_return(COAP_RESPONSE_CODE(400), 
                      response, "wrong parameter values");
         AS_client_delete( client_entry);
         return;
	  }
      ok = AS_add_client(server_entry, client_entry);
      if (ok != 0){
		 oscore_error_return(COAP_RESPONSE_CODE(400), 
                      response, "Client already exists for server");
         AS_client_delete( client_entry);
         return;
	  }
      AS_server_print(server_entry);
      response->code = COAP_RESPONSE_CODE(201);
    } /* if elem */
    coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_ACE_CBOR, -1,
                                 0, NULL);
  return; 
}



/*
 * POST handler - /AS/introspect
 * receives request to set the switch value
 */
static void
AS_hnd_post_introspect(coap_context_t *ctx UNUSED_PARAM,
                coap_resource_t *resource,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response
) {
  uint8_t* data = NULL;
  size_t size = 0; 
  uint8_t  ok = 1;
  uint8_t  tag = 0;
  uint8_t *scope = NULL;
  
  if (!session->oscore_encryption){
     oscore_error_return(COAP_RESPONSE_CODE(401), 
     response, "No oscore protection");
     return;
  }
  data = assemble_data(resource, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */
  if ((data == NULL) | (size == 0)){
	  oscore_error_return(COAP_RESPONSE_CODE(400), 
      response, "Did not find request data");
      return;
  };
  
	uint8_t  elem = cbor_get_next_element(&data);
    if (elem == CBOR_MAP){ 
      uint64_t map_size = cbor_get_element_size(&data);
      for (uint i=0 ; i < map_size; i++){
        tag = cose_get_tag(&data);
        switch (tag){
          case CWT_CLAIM_SCOPE:
            ok = AS_get_scope(data, &scope, &size);
            break;
          default:
            ok = 1;
            break;
        } /* switch  */ 
        if(ok != 0){
          oscore_error_return(COAP_RESPONSE_CODE(400), 
          response, "Decode error in AS introspect payload");
          return;
        } /* if ok */
      } /* for map_size  */
      response->code = COAP_RESPONSE_CODE(201);
    } /* if elem */
    coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_ACE_CBOR, -1,
                                 0, NULL);
  return; 
}



/*
 * POST handler - /AS/token
 * receives CWT with authorization to manipulate switch
 * sets up the oscore context
 */
static void
AS_hnd_post_token(coap_context_t  *ctx UNUSED_PARAM,
             struct coap_resource_t *resource,
             coap_session_t *session,
             coap_pdu_t *request,
             coap_binary_t *token,
             coap_string_t *query UNUSED_PARAM,
             coap_pdu_t *response)
{    
  uint8_t* data = NULL;
  size_t size = 0; 
  uint8_t  ok = 1;
  uint8_t  tag = 0;
  uint8_t *client_id = NULL;
  size_t  client_id_len = 0;
  uint8_t *identifier;
  size_t  identifier_len;
 
  if (!session->oscore_encryption){
     oscore_error_return(COAP_RESPONSE_CODE(401), 
     response, "No oscore protection");
     return;
  }
  	/* check whether data need to be returend */
  if (request) {
	coap_block_t block2 = { 0, 0, 0};
	if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)){	
      coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_ACE_CBOR, -1,
                                 return_data.length, return_data.s);
     return;
     } /* coap_get_block */
  } /* request */
  
  data = assemble_data(resource, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */
  if ((data == NULL) | (size == 0)){
	  oscore_error_return(COAP_RESPONSE_CODE(400), 
                 response, "invalid client");
      return;
  }
	uint8_t  elem = cbor_get_next_element(&data);
    if (elem == CBOR_MAP){
      uint64_t map_size = cbor_get_element_size(&data);
      for (uint i=0 ; i < map_size; i++){
        tag = cose_get_tag(&data);
        switch (tag){
		  case CWT_CLAIM_AUD:
            ok = cbor_get_string_array(&data, &identifier, 
                                         &identifier_len);
            break;	
          case OAUTH_REQ_CLIENTID:
            ok = cbor_get_string_array(&data, &client_id, 
                                         &client_id_len);
            break;	                                    	  
          default:
            ok = 1;
            break;
        } /* switch  */ 
        if(ok != 0){
          oscore_error_return(COAP_RESPONSE_CODE(400), 
          response, "Decode error in AS token payload");
          return;
        } /* if ok */
      } /* for map_size  */
      AS_server_t *server_entry =  AS_find_server(identifier, identifier_len);
      if (server_entry == NULL){
		 if(client_id != NULL) free(client_id);
		 if (identifier != NULL) free(identifier);
		 oscore_error_return(COAP_RESPONSE_CODE(400), 
         response, "Server not found");
         return;
	  }
	  free(identifier);
	  identifier = NULL;
	  AS_client_t *current = server_entry->clients;
      current = AS_find_client(
                client_id, client_id_len, current);
      if( client_id != NULL) free( client_id);
      if (current != NULL){
	    oauth_cnf_t *conf = fill_switch_conf(
	              current->client_id, current->client_id_len,
	      server_entry->server_id, server_entry->server_id_len); 
	    if (conf == NULL){
		   oscore_error_return(COAP_RESPONSE_CODE(400), 
                   response, "cannot create C0<=>SW configuration");
           return;
		}		
		server_entry->oscore_context = conf;
		current->iv = coap_malloc(COSE_algorithm_AES_CCM_16_64_128_IV_LEN);
        current->iv_len = COSE_algorithm_AES_CCM_16_64_128_IV_LEN;
        prng(current->iv, COSE_algorithm_AES_CCM_16_64_128_IV_LEN);		
		AS_server_print(server_entry);
		uint8_t *cwt_buf = coap_malloc(500);
		uint8_t *cwt = cwt_buf;
	    uint8_t *resp_buf = coap_malloc(500);
        uint8_t *resp = resp_buf;
        size_t  len = cbor_put_map(&resp, 3);
        len += cbor_put_number(&resp, OAUTH_REQ_ACCESSTOKEN);
        size_t cwt_len = AS_token_response(server_entry, &cwt, 
                        current->iv, current->iv_len, 
                        (uint8_t *)ASSW_key_id, ASSW_key_id_len);
        len += cbor_put_bytes(&resp, cwt_buf, cwt_len);
        free(cwt_buf);
        cwt_buf = NULL;
        /* oscore security context between client and server  */
        len += cbor_put_number(&resp, CWT_CLAIM_PROFILE);
        len += cbor_put_number(&resp, conf->profile);
        len += cbor_put_number(&resp, CWT_CLAIM_CNF);
        len += cbor_put_map(&resp, 1);
        len += cbor_put_number(&resp, CWT_OSCORE_SECURITY_CONTEXT);
        len += oauth_create_OSCORE_Security_context(&resp, server_entry->oscore_context);
        if (return_data.s != NULL){
			coap_free(return_data.s);
			return_data.s = NULL;
		}
        if (len > 0){
		  return_data.s = resp_buf;
		  return_data.length = len;
          response->code = COAP_RESPONSE_CODE(201);
          coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_ACE_CBOR, -1,
                                 return_data.length, return_data.s);
        } 
        else{
		  free(resp_buf);
	      oscore_error_return(COAP_RESPONSE_CODE(400), 
          response, "error in token creation");	
	    } /* if len */
      }
      else{
		oscore_error_return(COAP_RESPONSE_CODE(400), 
                 response, "invalid client");
	  } /* if current */
    } /* if elem */

  return; 
}

 
/*
 * init resources for AS
 */

void
AS_init_resources(coap_context_t *ctx) {
	
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
			      IP_AS.s = malloc(ep_len+1);
			      IP_AS.length = ep_len;
			      memcpy(IP_AS.s, prefix, pre_len);
			      memcpy(IP_AS.s + pre_len, host, strlen(host));
			      IP_AS.s[ep_len-1] = ']';
			      IP_AS.s[ep_len] = 0;
			    }
		      }  /* lan_att */
	        }  /* s==0 */
		  } /* ifa->if_addr */
          ifa = ifa->ifa_next;
	 } /* while */        
  } /* getifaddrs  */
  freeifaddrs( ifaddr);	
  
  char uu_pre[] = "uu_AS";
  AS_identifier.length = 11;
  AS_identifier.s = coap_malloc(AS_identifier.length);
  memcpy(AS_identifier.s, uu_pre, 5);
  cr_namenr(AS_identifier.s + 5);
	
	/* creates resources
	 */
  
  
  coap_resource_t *r;

  r = coap_resource_init(NULL, 0);
  
r = coap_resource_init(coap_make_str_const("AS/token"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_POST, AS_hnd_post_token);
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("60"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"Request token\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"core.token\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"authz token\""), 0);

  coap_add_resource(ctx, r);

r = coap_resource_init(coap_make_str_const("AS/boot"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_POST, AS_hnd_post_boot); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("60"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"AS bootstrap\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"core.boot\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"authz bootstrap\""), 0);

  coap_add_resource(ctx, r);
  
r = coap_resource_init(coap_make_str_const("AS/init"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_POST, AS_hnd_post_init); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("60"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"AS oscore context\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"core.init\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"authz initialization \""), 0);

  coap_add_resource(ctx, r);
  
r = coap_resource_init(coap_make_str_const("AS/server"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_POST, AS_hnd_post_server); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("60"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"AS add authorization server\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"core.server\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"server addition \""), 0);

  coap_add_resource(ctx, r);
  
r = coap_resource_init(coap_make_str_const("AS/client"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_POST, AS_hnd_post_client); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("60"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"AS add authorization client\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"core.client\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"client addition \""), 0);
  coap_add_resource(ctx, r);
    
r = coap_resource_init(coap_make_str_const("AS/introspect"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_POST, AS_hnd_post_introspect); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("60"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"AS introspection\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"core.introspection\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"authz introspection\""), 0);

  coap_add_resource(ctx, r);
  
}

