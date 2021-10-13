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
 * 
 * \adapted to libcoap 
 *      Peter van der Stok <consultancy@vanderstok.org>
 *      on request of Fairhair alliance
 */

#ifndef _CRYPTO_H
#define _CRYPTO_H

#include "coap.h"
#include "pdu.h"
#include <mbedtls/pk.h>

#define HKDF_INFO_MAXLEN 25
#define HKDF_OUTPUT_MAXLEN 25
#define AES_CCM_TAG 8

/* Plaintext Maxlen and Tag Maxlen is quite generous. */
#define AEAD_PLAINTEXT_MAXLEN COAP_MAX_CHUNK_SIZE
#define AEAD_TAG_MAXLEN COAP_MAX_CHUNK_SIZE 



/* Returns =< 0 if failure to encrypt. Ciphertext length + tag length, otherwise.
   Tag length and ciphertext length is derived from algorithm. No check is done to ensure
   that ciphertext buffer is of the correct length. */
int
oscore_mbedtls_encrypt_aes_ccm(int8_t alg, uint8_t *key, size_t key_len, uint8_t *nonce, size_t nonce_len,
        uint8_t *aad, size_t aad_len, uint8_t *plaintext_buffer, size_t plaintext_len, uint8_t *ciphertext_buffer);
        
 /* Return <= 0 if if decryption failure. Plaintext length otherwise.
   Tag-length and plaintext length is derived from algorithm. No check is done to ensure
   that ciphertext buffer or plaintext_buffer is of the correct length. */
int
oscore_mbedtls_decrypt_aes_ccm(uint8_t alg, uint8_t *key, size_t key_len, uint8_t *nonce, size_t nonce_len,
        uint8_t *aad, size_t aad_len, uint8_t *ciphertext_buffer, size_t ciphertext_len, uint8_t *plaintext_buffer);
        
/* ECP support for secp256r1 */
/* oscore_mbedtls_ecp_sign
 * signs the 256 bith has over the payload
 * algorithm is COSE_Algorithm_ES256 and params is COSE_curve_P_256
 * returns 0 when OK,
 * returns != 0 when error occurred
 */

int
oscore_mbedtls_ecp_verify(int8_t cose_alg, int8_t alg_param, uint8_t *signature, 
size_t signature_len, uint8_t *payload, size_t payload_len, mbedtls_pk_context *mbed_ctx);      

   /* oscore_mbedtls_ecp_verify
 * verifies the 256 bit hash over the payload
 * algorithm is COSE_Algorithm_ES256 and params is COSE_curve_P_256
 * returns 0 when OK,
 * returns != 0 when error occurred
 */

int
oscore_mbedtls_ecp_sign(int8_t cose_alg, int8_t alg_param, uint8_t *signature, 
size_t *signature_len, uint8_t *payload, size_t payload_len, mbedtls_pk_context *mbed_ctx);        

void
hmac_sha256(uint8_t *key, uint8_t key_len, uint8_t *data, uint8_t data_len, uint8_t *hmac);

int
hkdf_extract( uint8_t *salt, uint8_t salt_len, uint8_t *ikm, size_t ikm_len, uint8_t *prk_buffer);

int
hkdf_expand( uint8_t *prk, uint8_t *info, size_t info_len, uint8_t *okm, size_t okm_len);

/* Returns 0 if failure to encrypt. Ciphertext length, otherwise. Tag-length and ciphertext length is derived from algorithm. No check is done to ensure that ciphertext buffer is of the correct length. */

int oscore_AES_CCM_encrypt(uint8_t alg, uint8_t *key, uint8_t key_len, uint8_t *nonce, uint8_t nonce_len, uint8_t *aad, uint8_t aad_len, uint8_t *plaintext_buffer, uint16_t plaintext_len, uint8_t *ciphertext_buffer);

/* Return 0 if if decryption failure. Plaintext length otherwise. Tag-length and plaintext length is derived from algorithm. No check is done to ensure that plaintext buffer is of the correct length. */

int oscore_AES_CCM_decrypt(uint8_t alg, uint8_t *key, uint8_t key_len, uint8_t *nonce, uint8_t nonce_len, uint8_t *aad, uint8_t aad_len, uint8_t *ciphertext_buffer, uint16_t ciphertext_len, uint8_t *plaintext_buffer);

/* Return 0 if signing failure. Signatue length otherwise, signature length and key length are derived fron ed25519 values. No check is done to ensure that buffers are of the correct length. */

int
oscore_edDSA_sign(int8_t alg, int8_t alg_param, uint8_t *signature, uint8_t *ciphertext, uint16_t ciphertext_len, uint8_t *seed, uint8_t *public_key);

/* Return 0 if signing failure. Signatue length otherwise, signature length and key length are derived fron ed25519 values. No check is done to ensure that buffers are of the correct length. */

int
oscore_edDSA_verify(int8_t alg, int8_t alg_param, uint8_t *signature, uint8_t *plaintext, uint16_t plaintext_len, uint8_t *public_key);

/* int hkdf(uint8_t whichSha, const uint8_t *salt, uint8_t salt_len, const uint8_t *ikm,  uint8_t ikm_len, const uint8_t *info, uint8_t info_len, uint8_t *okm, uint8_t   okm_len); */
int hkdf(uint8_t *salt, uint8_t salt_len, uint8_t *ikm, uint8_t ikm_len, uint8_t *info, uint8_t info_len, uint8_t *okm, uint8_t okm_len);

#endif /* _CRYPTO_H */
