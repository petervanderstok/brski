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
 *      An implementation of the Hash Based Key Derivation Function (RFC) and wrappers for AES-CCM*.
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 * \extended for libcoap
 *      Peter van der Stok <consultancy@vanderstok.org>
 *      on request of Fairhair alliance
 */


#include "oscore-crypto.h"
#include "ccm-star.h"
#include <string.h>
#include "oscore.h"
#include "cose.h"
#include "pdu.h"
#include "coap_debug.h"

#include <stdio.h>
#include "dtls-hmac.h"
#include "ed25519.h"
#include "oscore-context.h"



/* Returns 0 if failure to encrypt. Ciphertext length, otherwise.
   Tag-length and ciphertext length is derived from algorithm. No check is done to ensure
   that ciphertext buffer is of the correct length. */
int
oscore_AES_CCM_encrypt(uint8_t alg, uint8_t *key, uint8_t key_len, uint8_t *nonce, uint8_t nonce_len,
        uint8_t *aad, uint8_t aad_len, uint8_t *plaintext_buffer, uint16_t plaintext_len, uint8_t *ciphertext_buffer)
{
  if(alg != COSE_Algorithm_AES_CCM_16_64_128 || key_len != 16 || nonce_len != 13) {
    return -5;
  }
  uint8_t tag_len = AES_CCM_TAG;
  uint8_t *encryption_buffer = 
              coap_malloc(plaintext_len + AES_CCM_TAG);
  memcpy(encryption_buffer, plaintext_buffer, plaintext_len);
  CCM_STAR.set_key(key);
  CCM_STAR.aead(nonce, encryption_buffer, plaintext_len, aad, aad_len, encryption_buffer + plaintext_len, tag_len, 1);

 if (coap_get_log_level() >= LOG_INFO){

    fprintf(stderr,"Encrypt:\n");
    fprintf(stderr,"\nKey:\n");
    for (uint16_t u = 0 ; u < key_len; u++)
                             fprintf(stderr," %02x",key[u]);
    fprintf(stderr,"\nIV:\n");
    for (uint16_t u = 0 ; u < nonce_len; u++)
                           fprintf(stderr," %02x",nonce[u]);
    fprintf(stderr,"\nAAD:\n");
    for (uint16_t u = 0 ; u < aad_len; u++)
                             fprintf(stderr," %02x",aad[u]);
    fprintf(stderr,"\nPlaintext_len %d  \n", plaintext_len);
    for (uint16_t u = 0 ; u < plaintext_len; u++)
                fprintf(stderr," %02x",plaintext_buffer[u]);
    fprintf(stderr,"\nCiphertext&Tag:\n");
    for (uint16_t u = 0 ; u < plaintext_len+tag_len; u++) 
                fprintf(stderr," %02x",encryption_buffer[u]);
    fprintf(stderr,"\n");
  }
 
  memcpy(ciphertext_buffer, encryption_buffer, plaintext_len + tag_len);
  coap_free(encryption_buffer);
  return plaintext_len + tag_len;
}

/* Return 0 if if decryption failure. Plaintext length otherwise.
   Tag-length and plaintext length is derived from algorithm. No check is done to ensure
   that plaintext buffer is of the correct length. */
int
oscore_AES_CCM_decrypt(uint8_t alg, uint8_t *key, uint8_t key_len, uint8_t *nonce, uint8_t nonce_len,
        uint8_t *aad, uint8_t aad_len, uint8_t *ciphertext_buffer, uint16_t ciphertext_len, uint8_t *plaintext_buffer)
{
  if(alg != COSE_Algorithm_AES_CCM_16_64_128 || key_len != 16 || nonce_len != 13) {
    return -5;
  }
  uint8_t tag_len = AES_CCM_TAG;
  int plaintext_len = ciphertext_len - tag_len;
  uint8_t *tag_buffer = coap_malloc(AES_CCM_TAG);
  memset( tag_buffer, 0, AES_CCM_TAG);
  uint8_t *decryption_buffer = coap_malloc(plaintext_len + 
                                           AES_CCM_TAG);
  memcpy(decryption_buffer, ciphertext_buffer, plaintext_len + AES_CCM_TAG);
  memset(plaintext_buffer, 0, plaintext_len);
  CCM_STAR.set_key(key);
  CCM_STAR.aead(nonce, decryption_buffer, plaintext_len, aad, aad_len, tag_buffer, tag_len, 0);

  if (coap_get_log_level() >= LOG_INFO){

     fprintf(stderr,"Decrypt:\n");
     fprintf(stderr,"Key:\n");
     for (uint16_t u = 0 ; u < key_len; u++)
                             fprintf(stderr," %02x",key[u]);
     fprintf(stderr,"\nIV:\n");
     for (uint16_t u = 0 ; u < nonce_len; u++)
                           fprintf(stderr," %02x",nonce[u]);
     fprintf(stderr,"\nAAD:\n");
     for (uint16_t u = 0 ; u < aad_len; u++)
                             fprintf(stderr," %02x",aad[u]);
     fprintf(stderr,"\nciphertext_len  %d \n", ciphertext_len);
     fprintf(stderr,"incoming ciphertext + AES_CCM_TAG \n");
     for (uint16_t u = 0 ; u < ciphertext_len; u++)
                fprintf(stderr," %02x",ciphertext_buffer[u]);
     fprintf(stderr,"\nDecryption &Tag:\n");
     for (uint16_t u = 0 ; u < ciphertext_len; u++)
                fprintf(stderr," %02x",decryption_buffer[u]);
     fprintf(stderr, "\nTag buffer ");
     for (uint16_t u = 0 ; u < AES_CCM_TAG; u++)
                fprintf(stderr," %02x",tag_buffer[u]);
     fprintf(stderr, "\n");
   }

  if(memcmp(tag_buffer, 
    decryption_buffer + plaintext_len, AES_CCM_TAG) != 0) {
    coap_free(decryption_buffer);
    coap_free( tag_buffer );
    return -2; 
          /* Decryption failure */
  }
  memcpy(plaintext_buffer, decryption_buffer, plaintext_len);
  
  coap_free(decryption_buffer);
  coap_free( tag_buffer );
  return plaintext_len;
}


/* only works with key_len <= 64 bytes */
void
hmac_sha256(uint8_t *key, uint8_t key_len, uint8_t *data, uint8_t data_len, uint8_t *hmac)
{
  dtls_hmac_context_t ctx;
  dtls_hmac_init(&ctx, key, key_len);
  dtls_hmac_update(&ctx, data, data_len);
  dtls_hmac_finalize(&ctx, hmac);

}


int
hkdf_extract( uint8_t *salt, uint8_t salt_len, uint8_t *ikm, size_t ikm_len, uint8_t *prk_buffer)
{
  uint8_t zeroes[32];
  memset(zeroes, 0, 32);
  
  if(salt == NULL || salt_len == 0){
    hmac_sha256(zeroes, 32, ikm, ikm_len, prk_buffer);
  } else { 
    hmac_sha256(salt, salt_len, ikm, ikm_len, prk_buffer);
  }
  return 0;
}

int
hkdf_expand( uint8_t *prk, uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len)
{
  int N = (okm_len + 32 - 1) / 32; /* ceil(okm_len/32) */
  uint8_t *aggregate_buffer = coap_malloc(32 + info_len +1);
  uint8_t *out_buffer = coap_malloc((N+1)*32); /* 32 extra bytes to fit the last block */
  int i;
  /* Compose T(1) */
  memcpy(aggregate_buffer, info, info_len);
  aggregate_buffer[info_len] = 0x01;
  hmac_sha256(prk, 32, aggregate_buffer, info_len + 1, &(out_buffer[0]));
  /* Compose T(2) -> T(N) */
  memcpy(aggregate_buffer, &(out_buffer[0]), 32);
  for(i = 1; i < N; i++) {
    memcpy(&(aggregate_buffer[32]), info, info_len);
    aggregate_buffer[32 + info_len] = i + 1;
    hmac_sha256(prk, 32, aggregate_buffer, 32 + info_len + 1, &(out_buffer[i * 32]));
    memcpy(aggregate_buffer, &(out_buffer[i * 32]), 32);
  }
  memcpy(okm, out_buffer, okm_len);
  coap_free(out_buffer);
  coap_free(aggregate_buffer);
  return 0;
}

int
hkdf(uint8_t *salt, uint8_t salt_len, uint8_t *ikm, uint8_t ikm_len, uint8_t *info, uint8_t info_len, uint8_t *okm, uint8_t okm_len)
{

  uint8_t prk_buffer[32];
  hkdf_extract(salt, salt_len, ikm, ikm_len, prk_buffer);
  hkdf_expand(prk_buffer, info, info_len, okm, okm_len);
  return 0;
}

/* Return 0 if key pair generation failure. Key lengths are derived fron ed25519 values. No check is done to ensure that buffers are of the correct length. */

int
oscore_edDSA_keypair(int8_t alg, int8_t alg_param, uint8_t *private_key, uint8_t *public_key, uint8_t *ed25519_seed)
{
    if(alg != COSE_Algorithm_EdDSA || alg_param != COSE_Elliptic_Curve_Ed25519)  {
       return 0;
    }
    ed25519_create_keypair(public_key, private_key, ed25519_seed);

  if (coap_get_log_level() >= LOG_INFO){

    fprintf(stderr,"\nKeyPair:\n");
    fprintf(stderr,"Public Key:\n");
    for (uint16_t u = 0 ; u < Ed25519_PUBLIC_KEY_LEN; u++)
                fprintf(stderr," %02x",public_key[u]);
    fprintf(stderr,"\nPrivate Key:\n");
    for (uint16_t u = 0 ; u < Ed25519_PRIVATE_KEY_LEN; u++)
                fprintf(stderr," %02x",private_key[u]);
    fprintf(stderr,"\nseed \n");
    for (uint16_t u = 0 ; u < Ed25519_SEED_LEN; u++)
                fprintf(stderr," %02x",ed25519_seed[u]);
    fprintf(stderr, "\n");
  }

  return 1;
}

/* Return 0 if signing failure. Signatue length otherwise, signature length and key length are derived fron ed25519 values. No check is done to ensure that buffers are of the correct length. */

int
oscore_edDSA_sign(int8_t alg, int8_t alg_param, uint8_t *signature, uint8_t *ciphertext, uint16_t ciphertext_len, uint8_t *private_key, uint8_t *public_key){
   if(alg != COSE_Algorithm_EdDSA || alg_param != COSE_Elliptic_Curve_Ed25519)  {
    return 0;
  }

  ed25519_sign(signature, ciphertext, ciphertext_len, public_key, private_key);

  if (coap_get_log_level() >= LOG_INFO){

    fprintf(stderr,"Sign:\n");
    fprintf(stderr,"Public Key:\n");
    for (uint16_t u = 0 ; u < Ed25519_PUBLIC_KEY_LEN; u++)
                fprintf(stderr," %02x",public_key[u]);
    fprintf(stderr,"\n");
    fprintf(stderr,"Private Key:\n");
    for (uint16_t u = 0 ; u < Ed25519_PRIVATE_KEY_LEN; u++)
                fprintf(stderr," %02x",private_key[u]);
    fprintf(stderr,"\n");
    fprintf(stderr,"incoming ciphertext \n");
    for (uint16_t u = 0 ; u < ciphertext_len; u++)
                fprintf(stderr," %02x",ciphertext[u]);
    fprintf(stderr,"\n");
    fprintf(stderr,"Signature:\n");
    for (uint16_t u = 0 ; u < Ed25519_SIGNATURE_LEN; u++)
                fprintf(stderr," %02x",signature[u]);
    fprintf(stderr,"\n");
  }
    
    return 1;
}

/* Return 0 if signing failure. Signatue length otherwise, signature length and key length are derived fron ed25519 values. No check is done to ensure that buffers are of the correct length. */

int
oscore_edDSA_verify(int8_t alg, int8_t alg_param, uint8_t *signature, uint8_t *plaintext, uint16_t plaintext_len, uint8_t *public_key){
  if(alg != COSE_Algorithm_EdDSA || alg_param != COSE_Elliptic_Curve_Ed25519)  {
    return 0;
  }

  if (coap_get_log_level() >= LOG_INFO){
     fprintf(stderr,"Verify:\n");
     fprintf(stderr,"Public Key:\n");
     for (uint16_t u = 0 ; u < Ed25519_PUBLIC_KEY_LEN; u++)
                fprintf(stderr," %02x",public_key[u]);
     fprintf(stderr,"\n");
     fprintf(stderr,"incoming ciphertext \n");
     for (uint16_t u = 0 ; u < plaintext_len; u++)
                fprintf(stderr," %02x",plaintext[u]);
     fprintf(stderr,"\n");
     fprintf(stderr,"Signature:\n");
     for (uint16_t u = 0 ; u < Ed25519_SIGNATURE_LEN; u++)
                fprintf(stderr," %02x",signature[u]);
     fprintf(stderr,"\n");
  }

  int res = ed25519_verify(signature, plaintext, plaintext_len, public_key);

  return res;
}



   
