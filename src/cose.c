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
 *      An implementation of the CBOR Object Signing and Encryption (RFC).
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 * added sign1 addition for coaplib
 *      Peter van der Stok <consultancy@vanderstok.org >
 *
 */


#include "stdio.h"
#include "cose.h"
#include "mem.h"
#include "cbor.h"
#include "oscore-crypto.h"
#include "oscore-context.h"
#include "string.h"

/* return tag length belonging to cose algorithm */
int
cose_tag_len(int cose_alg){
	 switch (cose_alg){
       case COSE_Algorithm_AES_CCM_16_64_128:
         return COSE_algorithm_AES_CCM_16_64_128_TAG_LEN;
         break;
       case COSE_Algorithm_AES_CCM_64_64_128:
         return COSE_algorithm_AES_CCM_64_64_128_TAG_LEN;
         break;
       case COSE_Algorithm_AES_CCM_16_128_128:
         return COSE_algorithm_AES_CCM_16_128_128_TAG_LEN;
         break;
       case COSE_Algorithm_AES_CCM_64_128_128:
         return COSE_algorithm_AES_CCM_64_128_128_TAG_LEN;
         break;         
       default:
         return 0;
         break;
	 }
}


/* return hash length belonging to cose algorithm */
int
cose_hash_len(int cose_alg){
    switch (cose_alg){
      case COSE_ALGORITHM_ES256:
         return   COSE_Algorithm_HMAC256_256_HASH_LEN;
         break;
       case COSE_ALGORITHM_ES512:
         return   COSE_ALGORITHM_ES512_HASH_LEN;
         break;
       case COSE_ALGORITHM_ES384:
         return   COSE_ALGORITHM_ES384_HASH_LEN;
         break;
       case COSE_Algorithm_HMAC256_64:
         return   COSE_Algorithm_HMAC256_64_HASH_LEN;
         break;
       case COSE_Algorithm_HMAC256_256:
         return   COSE_Algorithm_HMAC256_256_HASH_LEN;
         break;       
       case COSE_Algorithm_HMAC384_384:
         return   COSE_Algorithm_HMAC384_384_HASH_LEN;
         break;
       case COSE_Algorithm_HMAC512_512:
         return   COSE_Algorithm_HMAC512_512_HASH_LEN;
         break;
        case COSE_ALGORITHM_SHA_256_64:
         return   COSE_ALGORITHM_SHA_256_64_LEN;
         break;
       case COSE_ALGORITHM_SHA_256_256:
         return   COSE_ALGORITHM_SHA_256_256_LEN;
         break;       
       case COSE_ALGORITHM_SHA_512_256:
         return   COSE_ALGORITHM_SHA_512_256_LEN;
         break;        
       default:
         return 0;
         break;
     }
}

/* return nonce length belonging to cose algorithm */
int
cose_nonce_len(int cose_alg){
     switch (cose_alg){
       case COSE_Algorithm_AES_CCM_16_64_128:
         return COSE_algorithm_AES_CCM_16_64_128_IV_LEN;
         break;
       case COSE_Algorithm_AES_CCM_64_64_128:
         return COSE_algorithm_AES_CCM_64_64_128_IV_LEN;
         break;
       case COSE_Algorithm_AES_CCM_16_128_128:
         return COSE_algorithm_AES_CCM_16_128_128_IV_LEN;
         break;
       case COSE_Algorithm_AES_CCM_64_128_128:
         return COSE_algorithm_AES_CCM_64_128_128_IV_LEN;
         break;         
       default:
         return 0;
         break;
	 }
}
 
/* return key length belonging to cose algorithm */
int
cose_key_len(int cose_alg){
	switch (cose_alg){
       case COSE_Algorithm_AES_CCM_16_64_128:
         return COSE_algorithm_AES_CCM_16_64_128_KEY_LEN;
         break;
       case COSE_Algorithm_AES_CCM_64_64_128:
         return COSE_algorithm_AES_CCM_64_64_128_KEY_LEN;
         break;
       case COSE_Algorithm_AES_CCM_16_128_128:
         return COSE_algorithm_AES_CCM_16_128_128_KEY_LEN;
         break;
       case COSE_Algorithm_AES_CCM_64_128_128:
         return COSE_algorithm_AES_CCM_64_128_128_KEY_LEN;
         break;
       default:
         return 0;
         break;
	}
}

struct CWT_tag_t{
  int16_t     tag_value;
  const char *tag_name;
};

#define NR_OF_TAGS 36
static struct CWT_tag_t cwt_tags[NR_OF_TAGS] = 
/* oscore_context tags */
{
{OSCORE_CONTEXT_MS,"ms"},
{OSCORE_CONTEXT_CLIENTID,"clientId"},
{OSCORE_CONTEXT_SERVERID,"serverId"},
{OSCORE_CONTEXT_HKDF,"hkdf"},
{OSCORE_CONTEXT_ALG,"alg"},
{OSCORE_CONTEXT_SALT,"salt"},
{OSCORE_CONTEXT_CONTEXTID,"contextId"},
{OSCORE_CONTEXT_RPL,"rpl"},
{OSCORE_CONTEXT_CSALG, "cs_alg"},
{OSCORE_CONTEXT_CSPARAMS, "cs_params"},
{OSCORE_CONTEXT_CSKEYPARAMS, "cs_key_params"},

/*  CWT - cnf tag  */
{CWT_OSCORE_SECURITY_CONTEXT,"OSCORE_Security_Context"},
{CWT_KEY_COSE_KEY,"COSE_Key"},
{CWT_KEY_ENCRYPTED_COSE_KEY,"Encrypted_COSE_Key"},
{CWT_KEY_KID,"CWT_kid"},  

/* CWT tags */
{CWT_CLAIM_ISS,"iss"},
{CWT_CLAIM_SUB,"sub"},
{CWT_CLAIM_AUD,"aud"},
{CWT_CLAIM_EXP,"exp"},
{CWT_CLAIM_NBF,"nbf"},
{CWT_CLAIM_IAT,"iat"},
{CWT_CLAIM_CTI,"cti"},
{CWT_CLAIM_CNF,"cnf"},
{CWT_KEY_KID,"kid"},
/* OAUTH-AUTHZ claims   */
{CWT_CLAIM_SCOPE,"scope"},
{CWT_CLAIM_PROFILE,"profile"},
{CWT_CLAIM_CNONCE,"cnonce"},
{OAUTH_CLAIM_GRANTTYPE, "grant_type"},
{OAUTH_CLAIM_REQCNF, "req_cnf"},
{OAUTH_CLAIM_ACCESSTOKEN, "access_token"},
{OAUTH_CLAIM_RSCNF, "rs_cnf"},
{OAUTH_CLAIM_KEYINFO, "key_info"},
/* group-comm tags*/
{COSE_KCP_KTY, "kty"},
{COSE_KTP_CRV,"crv"},
{COSE_KCP_KEYOPS, "key_ops"},
{COSE_KCP_BASE_IV, "iv"},
};

//  cose_get_tag
//  returns tag value from ACE defined CBOR array of maps
int16_t
cose_get_tag(uint8_t **data)
{
  uint8_t elem = cbor_get_next_element(data);
  if (elem == CBOR_UNSIGNED_INTEGER)
    return (int16_t)cbor_get_unsigned_integer(data);
  if (elem == CBOR_NEGATIVE_INTEGER)
    return (int16_t)cbor_get_negative_integer(data);
  if ((elem == CBOR_BYTE_STRING) | (elem == CBOR_TEXT_STRING)){
    size_t len = cbor_get_element_size(data);
    uint8_t *ident = NULL;
    ident = realloc(ident, len);
    cbor_get_array(data, ident,(uint64_t)len);

/* verify that string a valid string and find tag value */
    for (int k=0; k < NR_OF_TAGS; k++){
      if (
        (strncmp((char *)ident, cwt_tags[k].tag_name, len) == 0)
        && (len == strlen(cwt_tags[k].tag_name)))
      {
        free(ident);
        return cwt_tags[k].tag_value;
      }  /* if  */
    }  /* for NR_OF_TAGS  */
    free(ident);
    return UNDEFINED_TAG;
  }  /* if BYTE_STRING  */
  return UNDEFINED_TAG;
}



/* Return length */
int
cose_encrypt0_encode(cose_encrypt0_t *ptr, uint8_t *buffer)
{
  int ret = 0;
  ret += cbor_put_array(&buffer, 3);
  ret += cbor_put_bytes(&buffer, NULL, 0);
  /* ret += cose encode attributyes */
  ret += cbor_put_bytes(&buffer, ptr->ciphertext, ptr->ciphertext_len);
  return ret;
}

/*Return status */
int cose_encrypt0_decode(cose_encrypt0_t *ptr, uint8_t *buffer, int size);

/* Initiate a new COSE Encrypt0 object. */
void
cose_encrypt0_init(cose_encrypt0_t *ptr)
{
  memset( ptr, 0, sizeof(cose_encrypt0_t));
}

void
cose_encrypt0_set_alg(cose_encrypt0_t *ptr, uint8_t alg)
{
  ptr->alg = alg;
}

void
cose_encrypt0_set_ciphertext(cose_encrypt0_t *ptr, uint8_t *buffer, int size)
{
  ptr->ciphertext = buffer;
  ptr->ciphertext_len = size;
}

void
cose_encrypt0_set_plaintext(cose_encrypt0_t *ptr, uint8_t *buffer, int size)
{
  ptr->plaintext = buffer;
  ptr->plaintext_len = size;
}
/* Return length */
int cose_encrypt0_get_plaintext(cose_encrypt0_t *ptr, uint8_t **buffer);

void
cose_encrypt0_set_partial_iv(cose_encrypt0_t *ptr, uint8_t *buffer, int size)
{
  memcpy(ptr->partial_iv, buffer, size);
  ptr->partial_iv_len = size;
}

/* Return length */
int
cose_encrypt0_get_partial_iv(cose_encrypt0_t *ptr, uint8_t **buffer)
{
  *buffer = ptr->partial_iv;
  return ptr->partial_iv_len;
}

void
cose_encrypt0_set_key_id(cose_encrypt0_t *ptr, uint8_t *buffer, int size)
{
  ptr->key_id = buffer;
  ptr->key_id_len = size;
}
/* Return length */
int
cose_encrypt0_get_key_id(cose_encrypt0_t *ptr, uint8_t **buffer)
{
  *buffer = ptr->key_id;
  return ptr->key_id_len;
}

int cose_encrypt0_get_kid_context(cose_encrypt0_t *ptr, uint8_t **buffer){
  *buffer = ptr->kid_context;
  return ptr->kid_context_len;
}

void cose_encrypt0_set_kid_context(cose_encrypt0_t *ptr, uint8_t *buffer, int size){
  ptr->kid_context = buffer;
  ptr->kid_context_len = size;
} 


void
cose_encrypt0_set_aad(cose_encrypt0_t *ptr, uint8_t *buffer, int size)
{
  ptr->aad = buffer;
  ptr->aad_len = size;
}
/* Returns 1 if successfull, 0 if key is of incorrect length. */
int
cose_encrypt0_set_key(cose_encrypt0_t *ptr, uint8_t *key, int key_size)
{
  if(key_size != 16) {
    return 0;
  }

  ptr->key = key;
  ptr->key_len = key_size;

  return 1;
}

void
cose_encrypt0_set_nonce(cose_encrypt0_t *ptr, uint8_t *buffer, int size)
{
  ptr->nonce = buffer;
  ptr->nonce_len = size;
}

int
cose_encrypt0_encrypt(cose_encrypt0_t *ptr, uint8_t *ciphertext_buffer, int ciphertext_len)
{
  if(ptr->key == NULL || ptr->key_len != cose_key_len(ptr->alg)) {
    return -1;
  }
  if(ptr->nonce == NULL || ptr->nonce_len != cose_nonce_len(ptr->alg)) {
    return -2;
  }
  if(ptr->aad == NULL || ptr->aad_len == 0) {
    return -3;
  }
  if(ptr->plaintext == NULL || ptr->plaintext_len < (ciphertext_len - cose_tag_len(ptr->alg))) {
    return -4;
  }
  return oscore_AES_CCM_encrypt(ptr->alg, ptr->key, ptr->key_len, ptr->nonce, ptr->nonce_len, ptr->aad, ptr->aad_len, ptr->plaintext, ptr->plaintext_len, ciphertext_buffer);
}

int
cose_encrypt0_decrypt(cose_encrypt0_t *ptr, uint8_t *plaintext_buffer, int plaintext_len)
{
  int ret_len =0;
  if(ptr->key == NULL || ptr->key_len != cose_key_len(ptr->alg)) {
    return -1;
  }
  if(ptr->nonce == NULL || ptr->nonce_len != cose_nonce_len(ptr->alg)) {
    return -2;
  }
  if(ptr->aad == NULL || ptr->aad_len == 0) {
    return -3;
  }
  if(ptr->ciphertext == NULL || ptr->ciphertext_len < (plaintext_len + cose_tag_len(ptr->alg))) {
    return -4;
  }

  ret_len = oscore_AES_CCM_decrypt(ptr->alg, ptr->key, ptr->key_len, ptr->nonce, ptr->nonce_len, ptr->aad, ptr->aad_len, ptr->ciphertext, ptr->ciphertext_len, plaintext_buffer);
  return ret_len;
}

/* ed25519 signature functions    */

void cose_sign1_init(cose_sign1_t *ptr){
  memset( ptr, 0, sizeof(cose_sign1_t));
}

void cose_sign1_set_alg(cose_sign1_t *ptr, int alg, 
          int alg_param, int alg_kty){
  ptr->alg = alg;
  ptr->alg_param = alg_param;
  ptr->alg_kty = alg_kty;
}

void cose_sign1_set_ciphertext(cose_sign1_t *ptr, uint8_t *buffer, int size){
  ptr->ciphertext = buffer;
  ptr->ciphertext_len = size;
}

/* Return length */
int cose_sign1_get_signature(cose_sign1_t *ptr, uint8_t **buffer){
  *buffer = ptr->signature;
  return ptr->signature_len;
}

void cose_sign1_set_signature(cose_sign1_t *ptr, uint8_t *buffer){
  ptr->signature = buffer;
  ptr->signature_len = Ed25519_SIGNATURE_LEN;
}

void cose_sign1_set_sigstructure(cose_sign1_t *ptr, uint8_t *buffer, int size){
  ptr->sigstructure = buffer;
  ptr->sigstructure_len = size;
}

void cose_sign1_set_public_key(cose_sign1_t *ptr, uint8_t *buffer){
  ptr->public_key = buffer;
  ptr->public_key_len = Ed25519_PUBLIC_KEY_LEN;
}

void cose_sign1_set_private_key(cose_sign1_t *ptr, uint8_t *buffer){
  ptr->private_key = buffer;
  ptr->private_key_len = Ed25519_PRIVATE_KEY_LEN;
}

int cose_sign1_sign(cose_sign1_t *ptr){
   return oscore_edDSA_sign(ptr->alg, ptr->alg_param, ptr->signature, ptr->ciphertext, ptr->ciphertext_len, ptr->private_key, ptr->public_key);
}

int cose_sign1_verify(cose_sign1_t *ptr){
   return oscore_edDSA_verify(ptr->alg, ptr->alg_param, ptr->signature, ptr->ciphertext, ptr->ciphertext_len, ptr->public_key);
}


