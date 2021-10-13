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
 * \adapted with sign1 function for libcoap 
 *      Peter van der Stok <consultancy@vanderstok.org>
 *      on request of Fairhair alliance
 */


#ifndef _COSE_H
#define _COSE_H
#include "coap.h"

/* cose curves */

#define COSE_Elliptic_Curve_Ed25519          6   /* used with EdDSA only     */
#define COSE_curve_P_256                     1   /* with ECDSA known as secp256r1  */
#define COSE_curve_X25519                    4   /* used with ECDH only      */

#define COSE_KEY_EC2                         2

/* key, tag, and signature lengths  */
#define COSE_ALGORITHM_Ed25519_SIG_LEN       64
#define COSE_ALGORITHM_Ed25519_PRIV_KEY_LEN  64
#define COSE_ALGORITHM_Ed25519_PUB_KEY_LEN   32

#define COSE_algorithm_AES_CCM_64_64_128_KEY_LEN  16
#define COSE_algorithm_AES_CCM_64_64_128_IV_LEN   7
#define COSE_algorithm_AES_CCM_64_64_128_TAG_LEN  8

#define COSE_algorithm_AES_CCM_16_64_128_KEY_LEN  16
#define COSE_algorithm_AES_CCM_16_64_128_IV_LEN   13
#define COSE_algorithm_AES_CCM_16_64_128_TAG_LEN   8

#define COSE_algorithm_AES_CCM_64_128_128_KEY_LEN  16
#define COSE_algorithm_AES_CCM_64_128_128_IV_LEN   7
#define COSE_algorithm_AES_CCM_64_128_128_TAG_LEN  16

#define COSE_algorithm_AES_CCM_16_128_128_KEY_LEN  16
#define COSE_algorithm_AES_CCM_16_128_128_IV_LEN   13
#define COSE_algorithm_AES_CCM_16_128_128_TAG_LEN  16

#define COSE_ALGORITHM_ES256_PRIV_KEY_LEN    24
#define COSE_ALGORITHM_ES256_PUB_KEY_LEN     32
#define COSE_ALGORITHM_ES256_SIGNATURE_LEN   64
#define COSE_ALGORITHM_ES256_HASH_LEN        32

#define COSE_ALGORITHM_ES384_PRIV_KEY_LEN    24
#define COSE_ALGORITHM_ES384_PUB_KEY_LEN     32
#define COSE_ALGORITHM_ES384_SIGNATURE_LEN   64
#define COSE_ALGORITHM_ES384_HASH_LEN        48

#define COSE_ALGORITHM_ES512_PRIV_KEY_LEN    24
#define COSE_ALGORITHM_ES512_PUB_KEY_LEN     32
#define COSE_ALGORITHM_ES512_SIGNATURE_LEN   64
#define COSE_ALGORITHM_ES512_HASH_LEN        64

#define COSE_ALGORITHM_ECDH_PRIV_KEY_LEN     32
#define COSE_ALGORITHM_ECDH_PUB_KEY_LEN      32

#define COSE_ALGORITHM_SHA_512_256_LEN       32
#define COSE_ALGORITHM_SHA_256_256_LEN       32
#define COSE_ALGORITHM_SHA_256_64_LEN        8

#define COSE_Algorithm_HMAC256_64_HASH_LEN   16
#define COSE_Algorithm_HMAC256_256_HASH_LEN  32 
#define COSE_Algorithm_HMAC384_384_HASH_LEN  48
#define COSE_Algorithm_HMAC512_512_HASH_LEN  64

/* cose algorithms */
#define COSE_Algorithm_EdDSA                 -8
#define COSE_Algorithm_HKDF_SHA_256          -10
#define COSE_ALGORITHM_ES256                 -7      /* with ECC known as secp256r1 */
#define COSE_ALGORITHM_ES512                 -36     /* with ECDSA  */
#define COSE_ALGORITHM_ES384                 -35     /* with ECDSA */
#define COSE_ALGORITHM_ES256K                -47     /* with ECC known as secp256k1 */
#define COSE_ALGORITHM_SHA_512_256           -17
#define COSE_ALGORITHM_SHA_256_256           -16
#define COSE_ALGORITHM_SHA_256_64            -15
#define COSE_ALGORITHM_SHA_1                 -14
#define COSE_Algorithm_AES_CCM_16_64_128     10
#define COSE_Algorithm_AES_CCM_16_64_256     11
#define COSE_Algorithm_AES_CCM_64_64_128     12
#define COSE_Algorithm_AES_CCM_64_64_256     13
#define COSE_Algorithm_AES_CCM_16_128_128    30
#define COSE_Algorithm_AES_CCM_16_128_256    31
#define COSE_Algorithm_AES_CCM_64_128_128    32
#define COSE_Algorithm_AES_CCM_64_128_256    33
#define COSE_Algorithm_HMAC256_64            4       /* truncated to 64 bits */
#define COSE_Algorithm_HMAC256_256           5 
#define COSE_Algorithm_HMAC384_384           6 
#define COSE_Algorithm_HMAC512_512           7

#define UNDEFINED_TAG             0xff

/* COSE OSCORE Security tags  */
#define OSCORE_CONTEXT_MS          1
#define OSCORE_CONTEXT_CLIENTID    2
#define OSCORE_CONTEXT_SERVERID    3
#define OSCORE_CONTEXT_HKDF        4
#define OSCORE_CONTEXT_ALG         5
#define OSCORE_CONTEXT_SALT        6
#define OSCORE_CONTEXT_CONTEXTID   7
#define OSCORE_CONTEXT_RPL         8
#define OSCORE_CONTEXT_CSALG       9
#define OSCORE_CONTEXT_CSPARAMS    10
#define OSCORE_CONTEXT_CSKEYPARAMS 11
#define OSCORE_CONTEXT_CSKEYENC    12

/* COSE Web Token claims    */
#define CWT_CLAIM_ISS                1
#define CWT_CLAIM_SUB                2
#define CWT_CLAIM_AUD                3
#define CWT_CLAIM_EXP                4
#define CWT_CLAIM_NBF                5
#define CWT_CLAIM_IAT                6
#define CWT_CLAIM_CTI                7
#define CWT_CLAIM_CNF                8
#define CWT_CLAIM_SCOPE              9
#define CWT_CLAIM_PROFILE            38
#define CWT_CLAIM_CNONCE             39
#define CWT_CLAIM_EXI                40

#define CWT_OSCORE_SECURITY_CONTEXT  4

/* COSE CWT COSE keys    */
#define CWT_KEY_COSE_KEY             1
#define CWT_KEY_ENCRYPTED_COSE_KEY   2
#define CWT_KEY_KID                  3  
#define CWT_LABEL_k                  -1

/* OAUTH Claims  */
#define OAUTH_CLAIM_ACCESSTOKEN   1
#define OAUTH_CLAIM_REQCNF        4
#define OAUTH_CLAIM_GRANTTYPE     33
#define OAUTH_CLAIM_RSCNF         41
#define OAUTH_CLAIM_KEYINFO       105
#define OAUTH_CLAIM_RSNONCE       126

/* COSE header parameters  */
#define COSE_HP_ALG               1
#define COSE_HP_CRIT              2
#define COSE_HP_CT                3
#define COSE_HP_KID               4
#define COSE_HP_IV                5
#define COSE_HP_CS                7
#define COSE_HP_CS0               9
#define COSE_HP_X5BAG             32
#define COSE_HP_X5CHAIN           33
#define COSE_HP_X5T               33
#define COSE_HP_X5U               34

/* COSE Key Types   */
#define COSE_KTY_OKP              1
#define COSE_KTY_EC2              2
#define COSE_KTY_RSA              3
#define COSE_KTY_SYMMETRIC        4

/* COSE Key Operations  */
#define COSE_KOP_SIGN             1
#define COSE_KOP_VERIFY           2
#define COSE_KOP_ENCRYPT          3
#define COSE_KOP_DECRYPT          4

/* COSE Key Common Parameters  */
#define COSE_KCP_KTY              1
#define COSE_KCP_KID              2
#define COSE_KCP_ALG              3
#define COSE_KCP_KEYOPS           4
#define COSE_KCP_BASE_IV          113 /* temporary  */

/* COSE Key Type Parameters   KEY Type OKP */
#define COSE_KTP_CRV              -1
#define COSE_KTP_X                -2
#define COSE_KTP_Y                -3

/* COSE CBOR Tag values   */
#define CBOR_TAG_COSE_SIGN        98
#define CBOR_TAG_COSE_SIGN1       18
#define CBOR_TAG_COSE_ENCRYPT     96
#define CBOR_TAG_COSE_ENCRYPT0    16
#define CBOR_TAG_COSE_MAC         97
#define CBOR_TAG_COSE_MAC0        17


//  cose_get_tag
//  returns tag value from ACE defined tags in CBOR maps
int16_t
cose_get_tag(uint8_t **data);

/* parameter value functions */

/* return tag length belonging to cose algorithm */
int
cose_tag_len(int cose_alg);

/* return hash length belonging to cose algorithm */
int
cose_hash_len(int cose_alg);

/* return nonce length belonging to cose algorithm */
int
cose_nonce_len(int cose_alg);

/* return key length belonging to cose algorithm */
int
cose_key_len(int cose_alg);

/* COSE Encrypt0 Struct */
typedef struct cose_encrypt0_t {

  uint8_t alg;

  uint8_t *key;
  int key_len;

  uint8_t partial_iv[8];
  int partial_iv_len;

  uint8_t *key_id;
  int key_id_len;

  uint8_t *kid_context;
  int kid_context_len;

  uint8_t *nonce;
  int nonce_len;

  uint8_t *aad;
  int aad_len;

//  uint8_t *external_aad;
//  int external_aad_len;

  uint8_t *plaintext;
  int plaintext_len;

  uint8_t *ciphertext;
  int ciphertext_len;
} cose_encrypt0_t;

/* COSE Sign1 Struct */
typedef struct cose_sign1_t {

  int     alg;
  int     alg_param;
  int     alg_kty;

  uint8_t *private_key;
  int private_key_len;

  uint8_t *public_key;
  int public_key_len;

  uint8_t *ciphertext;
  int ciphertext_len;

  uint8_t *sigstructure;
  int sigstructure_len;

  uint8_t *signature;
  int signature_len;
} cose_sign1_t;



/* Return length */
int cose_encrypt0_encode(cose_encrypt0_t *ptr, uint8_t *buffer);

/*Return status */
int cose_encrypt0_decode(cose_encrypt0_t *ptr, uint8_t *buffer, int size);

/* Initiate a new COSE Encrypt0 object. */
void cose_encrypt0_init(cose_encrypt0_t *ptr);

void cose_encrypt0_set_alg(cose_encrypt0_t *ptr, uint8_t alg);

void cose_encrypt0_set_plaintext(cose_encrypt0_t *ptr, uint8_t *buffer, int size);

void cose_encrypt0_set_ciphertext(cose_encrypt0_t *ptr, uint8_t *buffer, int size);

/* Return length */
int cose_encrypt0_get_plaintext(cose_encrypt0_t *ptr, uint8_t **buffer);

void cose_encrypt0_set_partial_iv(cose_encrypt0_t *ptr, uint8_t *buffer, int size);

/* Return length */
int cose_encrypt0_get_partial_iv(cose_encrypt0_t *ptr, uint8_t **buffer);

void cose_encrypt0_set_key_id(cose_encrypt0_t *ptr,
                                uint8_t *buffer, int size);

/* Return length */
int cose_encrypt0_get_key_id(cose_encrypt0_t *ptr,
                                          uint8_t **buffer);

void cose_encrypt0_set_aad(cose_encrypt0_t *ptr, 
                                   uint8_t *buffer, int size);

/* Return length */
int cose_encrypt0_get_kid_context(cose_encrypt0_t *ptr,
                                            uint8_t **buffer);

void cose_encrypt0_set_kid_context(cose_encrypt0_t *ptr, 
                                uint8_t *buffer, int size);

/* Returns 1 if successfull, 0 if key is of incorrect length. */
int cose_encrypt0_set_key(cose_encrypt0_t *ptr, 
                               uint8_t *key, int key_size);

void cose_encrypt0_set_nonce(cose_encrypt0_t *ptr, 
                              uint8_t *buffer, int size);

int cose_encrypt0_encrypt(cose_encrypt0_t *ptr, 
             uint8_t *ciphertext_buffer, int ciphertext_len);

int cose_encrypt0_decrypt(cose_encrypt0_t *ptr, 
             uint8_t *plaintext_buffer, int plaintext_len);

/* ed25519 signature functions    */

void cose_sign1_init(cose_sign1_t *ptr);

void cose_sign1_set_alg(cose_sign1_t *ptr, int alg,
                                int alg_param, int alg_kty);

void cose_sign1_set_ciphertext(cose_sign1_t *ptr, 
                               uint8_t *buffer, int size);

void cose_sign1_set_public_key(cose_sign1_t *ptr, 
                                          uint8_t *buffer);

void cose_sign1_set_private_key(cose_sign1_t *ptr, 
                                           uint8_t *buffer);

/* Return length */
int cose_sign1_get_signature(cose_sign1_t *ptr, 
                                          uint8_t **buffer);

void cose_sign1_set_signature(cose_sign1_t *ptr,
                                            uint8_t *buffer);

int cose_sign1_sign(cose_sign1_t *ptr);

void cose_sign1_set_sigstructure(cose_sign1_t *ptr,
                                 uint8_t *buffer, int size);

int cose_sign1_verify(cose_sign1_t *ptr);

#endif /* _COSE_H */
