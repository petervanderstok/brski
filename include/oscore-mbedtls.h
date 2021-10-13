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

#ifndef _M_CRYPTO_H
#define _M_CRYPTO_H

#include "coap.h"
#include "pdu.h"
#include "bn.h"
#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <mbedtls/cipher.h>

mbedtls_ecp_group_id
cose_group_id(int cose_curve);

mbedtls_md_type_t
cose_to_mbedtls_md(int cose_alg);

mbedtls_cipher_id_t
cose_to_mbedtls_id(int cose_alg);


/* extract signature
 * p points to asn structure
 * end points to en structure
 * on conclusion: signature contains the 64 byte signature 
 */
void
extract_asn_signature(uint8_t *p, uint8_t *end, uint8_t *signature);

/*create asn signature
 * on entry p points to the 64 byte signature
 * en exit asn-signature contains the asn1 enveloped signature
 * minimum size of asn_signature = 6
 */
void
create_asn_signature(uint8_t *p, uint8_t *asn_signature, size_t *tot_len);

/* uncompresses secp256r1 compressed public key X
 * to uncompressed parts X,Y1 or X,Y2*/
void uncompress(struct bn *X, struct bn *Y1, struct bn *Y2);

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



#endif /* _M_CRYPTO_H */
