/* oscore_oauth -- implementation of authorization using
 * a simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 * this file is added by:
 * Peter van der Stok <consultancy@vanderstok.org>
 * This file relies on oscore
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 *
 */
#ifndef __OAUTH_H__
#define __OAUTH_H__

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>

#include "oscore.h"
#include "oscore-context.h"
#include "cbor.h"
#include "cose.h"
#include "coap.h"

/* authz token request/response parameters */

#define OAUTH_REQ_ACCESSTOKEN       1
#define OAUTH_REQ_EXPIRESIN         2
#define OAUTH_REQ_AUDIENCE          5
#define OAUTH_REQ_SCOPE             9
#define OAUTH_REQ_CLIENTID          24
#define OAUTH_REQ_CLIENTSECRET      25
#define OAUTH_REQ_RESPONSETYPE      26
#define OAUTH_REQ_GRANTTYPE         33
#define OAUTH_REQ_TOKENTYPE         34
#define OAUTH_REQ_ACEPROFILE        38
#define OAUTH_REQ_CNONCE            39

#define OAUTH_CRH_AS                1
#define OAUTH_CRH_KID               2
#define OAUTH_CRH_AUDIENCE          5
#define OAUTH_CRH_SCOPE             9
#define OAUTH_CRH_CNONCE            39

#define OAUTH_CLAIM_KDCCHALLENGE      205
#define OAUTH_CLAIM_SIGN_INFO         203 

#define OAUTH_OSC_PROF_NONCE1        65
#define OAUTH_OSC_PROF_NONCE2        66

/* oauth profiles */

#define OAUTH_PROF_COAP_OSCORE       2
#define OAUTH_PROF_COAP_DTLS         4
#define OAUTH_PROF_COAP_MQTT         6

typedef struct oauth_cnf_t{
  int8_t    alg;
  int8_t    hkdf;
  int8_t    cs_alg;
  uint8_t   *cs_params;
  size_t    cs_params_len;
  uint8_t   *cs_key_params;
  size_t    cs_key_params_len;
  int8_t    cs_key_enc;
  int8_t    kty;
  int8_t    crv;
  uint8_t   rpl;
  uint8_t   *client_id; /* Sender ID: allocated by GM */
  size_t    client_id_len;
  uint8_t   *server_id; /* Recipient ID: allocated by GM */
  size_t    server_id_len;
  uint8_t   *group_id;  /* name of group  */
  size_t    group_id_len;
  uint8_t   *ms;
  size_t    ms_len;
  uint8_t   *salt;
  size_t    salt_len;
  uint8_t   *context_id;
  size_t    context_id_len;
  size_t    num;
  uint16_t   profile;
  uint8_t   *pub_key;
  size_t    pub_key_len;
  uint64_t  exp;   
}oauth_cnf_t;

typedef struct oauth_token_t{
  uint8_t  *iss;
  size_t   iss_len;
  uint8_t  *sub;
  size_t   sub_len;
  uint8_t  *aud;
  size_t   aud_len;
  uint64_t exp;
  uint64_t iat;
  uint8_t  *cti;
  size_t   cti_len;
  uint8_t  *scope;
  size_t   scope_len;
  uint8_t  *client_cred;
  size_t   client_cred_len;
  size_t   key_info_len;
  int8_t   *key_info;
  uint16_t profile;
  oauth_cnf_t    *osc_sec_config;
}oauth_token_t;
  
typedef struct oauth_cwtkey_t{
  int8_t    alg;
  uint8_t  *kid;
  size_t   kid_len;
  uint8_t  *iv;
  size_t   iv_len;
  int8_t   kty;
  int8_t   crv;
  uint8_t  *signature;
  size_t   signature_len;
  uint8_t  *data;
  size_t   data_len;
  oauth_token_t  *token;
}oauth_cwtkey_t;


/* oauth_delete_conf
 * frees memory of oscore_configuration
 */
void
oauth_delete_conf(oauth_cnf_t *cf);


/* oauth_delete_cwt_key
 * frees memory of cwt_key
 */
void
oauth_delete_cwt_key(oauth_cwtkey_t *ck);

/* oauth_delete_token
 * frees memory of token
 */
void
oauth_delete_token(oauth_token_t *token);


/* oauth_print_conf
 * prints contents of configuration
 */
void
oauth_print_conf(oauth_cnf_t *conf);


/* oauth_print_token
 * prints contents of token (followed by configuration)
 */
void
oauth_print_token(oauth_token_t *token);


/* oauth_print_cwt_key
 * prints contents of cwt_key
 */
void
oauth_print_cwt_key(oauth_cwtkey_t *ck);

/* oauth_read_nonce(databuf, len)
 * reads 8-byte nonce and rsnonce from databuf
 */
uint8_t 
oauth_read_nonce(unsigned char *databuf, 
                       uint8_t **cnonce, uint8_t **rsnonce);
                       
/* Read configuration information from CWT_CNF map
 * data points to map
 */
oauth_cnf_t *
oauth_cwt_configuration(uint8_t **data);
                      
                       
/* oauth_read_token
 * read the CWT token from input data
 */
struct oauth_token_t *
oauth_read_token(uint8_t **data);
  

/* oauth_read_CWT_key
 * returns cwtkey information
 * if error: returns NULL
 */
oauth_cwtkey_t *
oauth_read_CWT_key(uint8_t **data);


/* oauth_create_OSCORE_Security_context
 * fills OSCORE security context into CBOR map
 ** filled in by AS for PoP  ****
*/
size_t
oauth_create_OSCORE_Security_context(uint8_t **buf, oauth_cnf_t *param);


/* oauth_read_OSCORE_security_context
 * Decodes the map following the key info
 * expects map with Group Security Context
 * returns configuration
 */
oauth_cnf_t *
oauth_read_OSCORE_security_context(unsigned char **databuf);


/* oauth_encrypt_token
 * encrypts token using encrypt_key
 * cipher_text = oauth_encrypt_token(token, ASGM_KEY,
        aad_buffer, aad_len, &ciphertext_len){ 
*/
uint8_t *
oauth_encrypt_token(uint8_t *token, size_t token_len, uint8_t *encrypt_key,
        uint8_t *aad_buffer, size_t aad_len, 
        uint8_t *iv, size_t *ciphertext_len); 
        

/* oauth_decrypt_token
 * decrypts token using decrypt_key
 */
oauth_token_t *
oauth_decrypt_token(uint8_t **enc_token, uint8_t *decrypt_key,
        uint8_t *aad_buffer, size_t aad_len);
        
        
/* oauth_strip
 * separates access_token and nonce text
 * returns accesstoken in data, and nonce is cnonce
 * return 0 is OK; 1 is Nok
 */
uint8_t
oauth_strip(uint8_t **data, uint8_t **nonce, oauth_cwtkey_t **key_enc);

  
/* oauth_create_signature_header
 * fills description of signature algorithm
 */
size_t 
oauth_create_signature_header(uint8_t **token);

  
/* oauth_create_encrypt_header
 * fills description of encryption algorithm
 */
size_t 
oauth_create_encrypt_header(uint8_t **token, 
        uint8_t *iv, size_t iv_len, uint8_t *kid, size_t kid_len);
                  
#endif /* __OAUTH_H__  */
