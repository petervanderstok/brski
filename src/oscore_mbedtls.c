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
 *      An interface between oscore and mbedtls encryption and signature library
 * successor to oscore-crypto.c
 * backward compatible with oscore-crypto.c
 * \author
 *      Peter van der Stok <consultancy@vanderstok.org>
 */

#include <stdio.h>
#include <string.h>

#include "oscore-crypto.h"
#include "oscore-mbedtls.h"
#include "oscore.h"
#include "cose.h"
#include "pdu.h"
#include "coap_debug.h"
#include "bn.h"
#include "oscore-context.h"

#include <mbedtls/x509_crt.h>
#include <mbedtls/ccm.h>
#include <mbedtls/asn1.h>
#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/config.h>   

/* waiting for inclusion in mebdtls  */
#include "ed25519.h"

#define ERR_LEN        1024
#define CRT_BUF_SIZE   1024
#define TAG_LEN        16

/* map COSE parameter values to mebdtls parameter values  */


/* cose_to_mbedtls_alg( cose_alg)
 * returns mbedtls algorithm number from cose algorith number
 */
mbedtls_cipher_id_t
cose_to_mbedtls_id(int cose_alg){
	switch (cose_alg){
	   case COSE_Algorithm_EdDSA:
         return   MBEDTLS_CIPHER_ID_NONE ;
         break;	   
       case COSE_Elliptic_Curve_Ed25519:
         return   MBEDTLS_CIPHER_ID_NONE ;
         break;
       case COSE_Algorithm_HKDF_SHA_256:
         return   MBEDTLS_CIPHER_ID_NONE ;
         break;
       case COSE_ALGORITHM_ES256:
         return   MBEDTLS_CIPHER_ID_NONE ;
         break;
       case COSE_ALGORITHM_ES512:
         return   MBEDTLS_CIPHER_ID_NONE ;
         break;
       case COSE_ALGORITHM_ES384:
         return   MBEDTLS_CIPHER_ID_NONE ;
         break;
       case COSE_Algorithm_AES_CCM_16_64_128:
       case COSE_Algorithm_AES_CCM_64_64_128:       
       case COSE_Algorithm_AES_CCM_16_128_128:
       case COSE_Algorithm_AES_CCM_64_128_128:             
         return MBEDTLS_CIPHER_ID_AES;
         break; 
       default:
         return MBEDTLS_CIPHER_ID_NONE;
         break;

	}
}

/* cose_to_mbedtls_alg( cose_alg)
 * returns mbedtls algorithm number from cose algorith number
 */
mbedtls_md_type_t
cose_to_mbedtls_md(int cose_alg){
	switch (cose_alg){
	   case COSE_Algorithm_HMAC256_64:
         return   MBEDTLS_MD_SHA256;
         break;	   
	   case COSE_Algorithm_HMAC256_256:
         return   MBEDTLS_MD_SHA256;
         break;
	   case COSE_Algorithm_HMAC384_384:
         return   MBEDTLS_MD_SHA384 ;
         break;
	   case COSE_Algorithm_HMAC512_512:
         return   MBEDTLS_MD_SHA512 ;
         break;
	   case COSE_ALGORITHM_ES256:
         return   MBEDTLS_MD_SHA256;
         break;         
	   case COSE_ALGORITHM_ES512:
         return   MBEDTLS_MD_SHA512;
         break;   
	   case COSE_ALGORITHM_ES384:
         return   MBEDTLS_MD_SHA384;
         break;                     
       default:
         return MBEDTLS_MD_NONE;
         break;

	}
}


mbedtls_ecp_group_id
cose_group_id(int cose_curve){
	switch(cose_curve){
	  case COSE_curve_P_256:
         return   MBEDTLS_ECP_DP_SECP256R1;
         break;
       case COSE_ALGORITHM_ES256K:
         return   MBEDTLS_ECP_DP_SECP256K1;
         break;
       case COSE_curve_X25519:
         return   MBEDTLS_ECP_DP_CURVE25519;
       default:
         return MBEDTLS_ECP_DP_NONE;
         break;
	}
}

/* extract signature
 * p points to asn structure
 * end points to en structure
 * on conclusion: signature contains the 64 byte signature 
 */
void
extract_asn_signature(uint8_t *p, uint8_t *end, uint8_t *signature){
/* sequence of sequences expected */
    char err_buf[CRT_BUF_SIZE]; 
    size_t len =0;
    memset(signature, 0, 64);
    int ret = mbedtls_asn1_get_tag(&p, end, &len ,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0){
	mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
	coap_log( LOG_ERR, " failed\n  !  mbedtls_asn1_get_tag finding sequence of sequences"
                            "returned -0x%04x - %s\n\n", (unsigned int) -ret, err_buf );
			    return;
    }
    unsigned char *q = p;
    unsigned char *qend = q + len;
    int tag = 0;
    int nr = 1; /* denotes first or second part */
	        while (q < qend){
		       size_t plen;
		       q++;
	           ret = mbedtls_asn1_get_len(&q, end, &plen);
	           if (ret != 0){
                   mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
                   coap_log(LOG_ERR, " failed\n  !  mbedtls_asn1_get_len "
                            "returned -0x%04x - %s\n\n", (unsigned int) -ret, err_buf );
	           }
		   tag = *(q-2);
		   if (tag != MBEDTLS_ASN1_INTEGER)coap_log(LOG_ERR,"unexpected asn1 tag in signature\n");
		   uint8_t *s = q;
		   size_t s_len = plen;   
		   if (s[0] == 0) {
		       s++;
		       s_len--;
		   }
		   size_t sig_ind = 32*nr - s_len; /* add preceding zeroes */
		   if (s_len > 32)coap_log(LOG_ERR,"Incorrect asn sequence for 64 byte signature \n");
		   for (uint qq = 0; qq < s_len; qq++){
		       signature[sig_ind] = s[qq];
		       sig_ind++;
		   }
		   q = q + plen;
		   nr++;
	       }
}

/*create asn signature
 * on entry p points to the 64 byte signature
 * en exit asn-signature contains the asn1 enveloped signature
 * minimum size of asn_signature = 6
 */
void
create_asn_signature(uint8_t *p, uint8_t *asn_signature, size_t *tot_len){
    uint8_t *q = asn_signature + 2; /* start of first 32 bytes */
    uint8_t asn_len = 32 + 32 + 2 + 2;
    memset(asn_signature, 0, *tot_len);
    asn_signature[0] = 0x30;
    for (uint i = 0; i <2; i++){
      uint8_t dummy = 0;	
      uint8_t len = 32;
      while (p[0] == 0){ /* skip leading zeroes */
	      len--;
	      asn_len--;
	      p++;
      }
      if (((p[0] >> 7) & 1) == 1){
	    len++;
	    asn_len++;
	    dummy = 1;
      }
      q[0] = MBEDTLS_ASN1_INTEGER;
      q[1] = len;
      q = q + 2 + len;
      p = p + len - dummy;
      for (int qq = -len + dummy; qq < 0; qq++) q[qq] = p[qq];
   }
   /* fill in total length */
   asn_signature[1] = asn_len;
   *tot_len = asn_len + 2;
}

/* uncompresses secp256r1 compressed public key X
 * to uncompressed parts X,Y1 or X,Y2*/
void uncompress(struct bn *X, struct bn *Y1, struct bn *Y2)
{
  struct bn x, prime, A, B, three, two, zero, one, tmp, res;
  struct bn xPow3, ax, partial, combined, modulo, root1, root2;
  struct bn x2, x3;
    bignum_init(&x);
    bignum_init(&x2);
    bignum_init(&x3);
    bignum_init(&prime); 
    bignum_init(&A); 
    bignum_init(&B); 
    bignum_init(&three); 
    bignum_init(&two); 
    bignum_init(&zero); 
    bignum_init(&one);
    bignum_init(&xPow3);
    bignum_init(&ax);
    bignum_init(&partial); 
    bignum_init(&combined); 
    bignum_init(&modulo);
    bignum_init(& root1); 
    bignum_init(&root2);
    bignum_init(&tmp);
    bignum_init(&res);
    bignum_assign(&x, X);
		// secp256r1
		// y^2 = x^3 + ax + b -> y = +- sqrt(a x + b + x^3)
        char prime_char[] = "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff";
        char A_char[] = "ffffffff00000001000000000000000000000000fffffffffffffffffffffffc";
        char B_char[] = "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b";
		bignum_from_string(&prime, prime_char, 64);
        bignum_from_string(&A, A_char, 64);
		bignum_from_string(&B, B_char, 64);
		bignum_from_int(&three, (DTYPE_TMP)3);
		bignum_from_int(&two, (DTYPE_TMP)2);
		bignum_from_int(&zero, (DTYPE_TMP)0);
		bignum_from_int(&one, (DTYPE_TMP)1);	
	
		bignum_mul(&x, &A, &tmp);                     /* ax = a * x */
		bignum_mod(&tmp, &prime, &ax);		
		bignum_add(&ax, &B, &tmp);                    /* partial= ax + b */	
		bignum_mod(&tmp, &prime, &partial);			
		bignum_mul(&x, &x, &tmp);
		bignum_mod(&tmp, &prime, &x2);                /* x2 = x * x % prime  */
		bignum_mul(&x, &x2, &tmp);
		bignum_mod(&tmp, &prime, &x3);	              /* x3 = x2 * x % prime  */
		bignum_add(&x3, &partial, &combined);         /* combined = partial + x3) */
        bignum_mod(&combined, &prime, &modulo);       /* modulo = combined % prime */			
		
        bignum_squaremod(&modulo, &prime, &root1);       /*  root1 = sqrtmod(modulo) */		
		bignum_assign(Y1, &root1);
		    /* x = p - x; */
    bignum_sub(&prime, &root1, Y2);     /* Y2 = p - x */
    bignum_mul( Y2, Y2, &tmp);
    bignum_mod( &tmp, &prime, &res);   /* res = (p-x)*(p-x) mod p  */
    if (bignum_cmp(&res, &modulo) != EQUAL)bignum_assign(Y2, &zero);
}

void 
oscore_mbedtls_hmac(int8_t alg, uint8_t *key, uint8_t key_len, uint8_t *plaintext, uint16_t plaintext_len, uint8_t * ciphertext){
	mbedtls_md_context_t ctx;
	mbedtls_md_type_t md_type = cose_to_mbedtls_md( alg);
	
	mbedtls_md_init( &ctx);
	mbedtls_md_setup( &ctx, mbedtls_md_info_from_type( md_type), 1);
	mbedtls_md_hmac_starts( &ctx, (const unsigned char *) key, key_len);
	mbedtls_md_hmac_update( &ctx, (const unsigned char *) plaintext, plaintext_len);
	mbedtls_md_hmac_finish( &ctx, ciphertext);
	mbedtls_md_free( &ctx);
	
}


/* Returns =< 0 if failure to encrypt. Ciphertext length + tag length, otherwise.
   Tag length and ciphertext length is derived from algorithm. No check is done to ensure
   that ciphertext buffer is of the correct length.
   ciphertext should be prepared with plaintext_len + tag length space */
int
oscore_mbedtls_encrypt_aes_ccm(int8_t alg, uint8_t *key, size_t key_len, uint8_t *nonce, size_t nonce_len,
        uint8_t *aad, size_t aad_len, uint8_t *plaintext_buffer, size_t plaintext_len, uint8_t *ciphertext_buffer)
{
    int ret = 0;
    mbedtls_cipher_id_t cipher_id = cose_to_mbedtls_id(alg);
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ccm_context   ctx;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    char buf[ERR_LEN];
    /*
     * Go for a conservative 16-byte (128-bit) tag and append it to the
     * ciphertext
     */  
    uint8_t  tag_len = cose_tag_len( alg);
    uint8_t  tag[TAG_LEN];
    
    if (cipher_id ==  MBEDTLS_CIPHER_ID_NONE) return -5; 
    if (cose_key_len( alg) != key_len) return -5;
    if (cose_nonce_len( alg) != nonce_len) return -5;
    
    /* Setup AES-CCM contex */
    mbedtls_ccm_init(&ctx);

    ret = mbedtls_ccm_setkey(&ctx, cipher_id , key, 
                                8 * key_len);
    if (ret != 0) {
        mbedtls_strerror( ret, buf, ERR_LEN);
        coap_log(LOG_ERR,"failed\n ! mbedtls_ccm_setkey() returned -0x%04X\n -%s", (unsigned int)-ret, buf);
        return ret;
    }
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
        fprintf(stderr,"\nPlaintext_len %d  \n", (int)plaintext_len);
        for (uint16_t u = 0 ; u < plaintext_len; u++)
                fprintf(stderr," %02x",plaintext_buffer[u]);
    }
    ret = mbedtls_ccm_encrypt_and_tag( &ctx, plaintext_len,
                       nonce, nonce_len,
                       aad, aad_len,
                       plaintext_buffer, ciphertext_buffer,
                       tag, tag_len);  
    if (ret != 0) {
        mbedtls_strerror( ret, buf, ERR_LEN);
        coap_log(LOG_ERR,"failed ! \n mbedtls_ccm_encrypt_and_tag() returned -0x%04X  -%s\n",
                  (unsigned int) -ret, buf);
        return ret;
    }
    
     /* copy tag at end of encrypted buffer */
  memcpy(ciphertext_buffer + plaintext_len, tag, tag_len);

 if (coap_get_log_level() >= LOG_INFO){

    fprintf(stderr,"\nCiphertext&Tag:\n");
    for (uint16_t u = 0 ; u < plaintext_len+tag_len; u++) 
                fprintf(stderr," %02x", ciphertext_buffer[u]);
    fprintf(stderr,"\nTag:\n");
    for (uint16_t u = 0 ; u < tag_len; u++) 
                fprintf(stderr," %02x", tag[u]);
    fprintf(stderr,"\n");
  }

  return plaintext_len + tag_len;
}

/* Return <= 0 if if decryption failure. Plaintext length otherwise.
   Tag-length and plaintext length is derived from algorithm. No check is done to ensure
   that ciphertext buffer or plaintext_buffer is of the correct length. 
   returned plaintext_len  is equal to ciphertext_len - tag_len
   tag must be attached at end of ciphertext_buffer */
int
oscore_mbedtls_decrypt_aes_ccm(uint8_t alg, uint8_t *key, size_t key_len, uint8_t *nonce, size_t nonce_len,
        uint8_t *aad, size_t aad_len, uint8_t *ciphertext_buffer, size_t ciphertext_len, uint8_t *plaintext_buffer)
{
    int ret = 0;
    mbedtls_cipher_id_t cipher_id = cose_to_mbedtls_id(alg);
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ccm_context   ctx;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    char buf[ERR_LEN];
    /*
     * Go for a conservative 16-byte (128-bit) tag and append it to the
     * ciphertext
     */    
    uint8_t  tag_len = cose_tag_len( alg);
    uint8_t  tag[TAG_LEN];
    
    if (cipher_id ==  MBEDTLS_CIPHER_ID_NONE) return -5;
    if (cose_key_len( alg) != key_len) return -5;
    if (cose_nonce_len( alg) != nonce_len) return -5;
    
    /* tag is placed at end of ciphertext */
    ciphertext_len = ciphertext_len - tag_len;
    memset(tag, 0, tag_len);
    for (uint8_t qq = 0 ; qq < tag_len; qq++) tag[qq] = ciphertext_buffer[ciphertext_len + qq];
    
             
    /* Setup AES-CCM contex */
    mbedtls_ccm_init(&ctx);

    ret = mbedtls_ccm_setkey(&ctx, cipher_id , key, 8 * key_len);
    if (ret != 0) {
        mbedtls_strerror( ret, buf, ERR_LEN);
        coap_log(LOG_ERR,"failed\n ! mbedtls_ccm_setkey() returned -0x%04X\n -%s", (unsigned int)-ret, buf);
        return ret;
    }
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
       fprintf(stderr,"\nciphertext_len  %d \n", (int)ciphertext_len);
       fprintf(stderr,"incoming ciphertext + AES_CCM_TAG \n");
       for (uint16_t u = 0 ; u < ciphertext_len; u++)
                fprintf(stderr," %02x",ciphertext_buffer[u]);
       fprintf(stderr, "\nTag buffer ");
       for (uint16_t u = 0 ; u < AES_CCM_TAG; u++)
                fprintf(stderr," %02x",tag[u]);
       fprintf(stderr, "\n");
    }
   
    ret = mbedtls_ccm_auth_decrypt(&ctx, ciphertext_len,
                       nonce, nonce_len,
                       aad, aad_len,
                       ciphertext_buffer, plaintext_buffer,
                       tag, tag_len);
    if (ret != 0) {
        mbedtls_strerror( ret, buf, ERR_LEN);
        coap_log(LOG_ERR,"failed ! \n mbedtls_ccm_auth_decrypt() returned -0x%04X  -%s\n",
                  (unsigned int) -ret, buf);
        return ret;
    }
    
    if (coap_get_log_level() >= LOG_INFO){  
       fprintf(stderr,"Decryption &Tag:\n");
       for (uint16_t u = 0 ; u < ciphertext_len; u++)
                fprintf(stderr," %02x",plaintext_buffer[u]);
       fprintf(stderr,"\n");
    }

  if(memcmp(tag, 
    ciphertext_buffer + ciphertext_len, tag_len) != 0) {
       return -2; 
          /* Decryption failure */
  }
  return ciphertext_len;
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
hkdf( uint8_t *salt, uint8_t salt_len, uint8_t *ikm, uint8_t ikm_len, uint8_t *info, uint8_t info_len, uint8_t *okm, uint8_t okm_len)
{

  uint8_t prk_buffer[32];
  hkdf_extract(salt, salt_len, ikm, ikm_len, prk_buffer);
  hkdf_expand(prk_buffer, info, info_len, okm, okm_len);
  return 0;
}

/* ECP support for secp256r1 */

/* oscore_mbedtls_ecp_sign
 * signs the 256 bit hash over the payload
 * algorithm is COSE_Algorithm_ES256 and params is COSE_curve_P_256
 * returns 0 when OK,
 * returns != 0 when error occurred
 */

int
oscore_mbedtls_ecp_sign(int8_t cose_alg, int8_t alg_param, uint8_t *signature, 
size_t *signature_len, uint8_t *payload, size_t payload_len, mbedtls_pk_context *mbed_ctx){
    mbedtls_ecp_group_id group = cose_group_id(alg_param);
    mbedtls_md_type_t md_type = cose_to_mbedtls_md(cose_alg);
    if(group == (mbedtls_ecp_group_id)MBEDTLS_PK_NONE || md_type == MBEDTLS_MD_NONE)  {
        return -5;
    }
    size_t hash_len = cose_hash_len(cose_alg);
    if (hash_len == 0) return -5;
    int     ret = 1;       /* mbedtls error return */
    unsigned char hash[COSE_Algorithm_HMAC512_512_HASH_LEN];  /* maximum length hash */
	mbedtls_ecdsa_context      sign_key;
	mbedtls_ecdsa_context      *key = &sign_key;
    mbedtls_ctr_drbg_context ctr_drbg;	
    mbedtls_ecdsa_init( key );	
    mbedtls_ctr_drbg_init( &ctr_drbg );
    memset( signature, 0, *signature_len);
    mbedtls_ecp_keypair_init(key);
	const char *pers = "mbedtls_pk_sign";    
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init( &entropy );
    uint8_t private_key[100];
    memset(private_key, 0, 100);
    size_t private_key_len = 100;
    char err_buf[CRT_BUF_SIZE];    
    memset( err_buf, 0, sizeof( err_buf ) );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
		mbedtls_strerror( ret, err_buf, sizeof(err_buf));		
        coap_log( LOG_ERR," failed\n  ! mbedtls_ctr_drbg_seed returned %d - %s\n", -ret, err_buf );
        goto exit;
    }

    mbedtls_ecdsa_context *key_pair = mbed_ctx->pk_ctx;
    private_key_len = mbedtls_mpi_size(&key_pair->d);
    ret = mbedtls_mpi_write_binary( &key_pair->d, private_key, private_key_len);
    if (ret != 0 ){
		mbedtls_strerror( ret, err_buf, sizeof(err_buf));
        coap_log(LOG_ERR, " failed\n  ! mbedtls_mpi_write_binary %d - %s\n", -ret, err_buf);
		goto exit;
	}
  
    /* calculate hash over payload  */
    
    if( ( ret = mbedtls_sha256_ret( payload, payload_len, hash, 0 ) ) != 0 )
    {
		mbedtls_strerror( ret, err_buf, sizeof(err_buf));
        coap_log( LOG_ERR, " failed\n  ! mbedtls_sha256_ret returned %d - %s\n", -ret, err_buf );
        goto exit;
    }

    /* Sign message hash  */
    uint8_t mbed_sig[100];
    if( ( ret = mbedtls_pk_sign( mbed_ctx, md_type,
                                       hash, 0,
                                       mbed_sig, signature_len,
                                       mbedtls_ctr_drbg_random, &ctr_drbg ) ) != 0 )
    {
		mbedtls_strerror( ret, err_buf, sizeof(err_buf));		
        coap_log( LOG_ERR," failed\n  ! mbedtls_pk_sign returned %d - %s\n", -ret, err_buf );
        goto exit;
    }
//    fprintf(stderr,"asn signature with length %d \n", *signature_len);
//        for (uint16_t u = 0 ; u < *signature_len; u++)
//                fprintf(stderr," %02x", mbed_sig[u]);
//        fprintf(stderr,"\n");        
    extract_asn_signature(mbed_sig, mbed_sig + *signature_len, signature);
    *signature_len = COSE_ALGORITHM_ES256_SIGNATURE_LEN;

  if (coap_get_log_level() >= LOG_INFO){

    fprintf(stderr,"Sign:\n");
    fprintf(stderr,"Private Key:\n");
    for (uint16_t u = 0 ; u < private_key_len; u++)
                fprintf(stderr," %02x",private_key[u]);
    fprintf(stderr,"\n");
    fprintf(stderr,"incoming payload \n");
    for (uint16_t u = 0 ; u < payload_len; u++)
                fprintf(stderr," %02x",payload[u]);
    fprintf(stderr,"\n");
    fprintf(stderr,"sha 256 hash: \n");
    for (uint qq =0; qq < hash_len; qq++)
                  fprintf(stderr," %02x", hash[qq]);
    fprintf(stderr,"\n");
    fprintf(stderr,"Signature:\n");
    for (uint16_t u = 0 ; u < *signature_len; u++)
                fprintf(stderr," %02x",signature[u]);
    fprintf(stderr,"\n");
  }
exit:
    mbedtls_ecdsa_free( key );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    return ret;
}

/* oscore_mbedtls_ecp_verify
 * verifies the 256 bit hash over the payload
 * algorithm is COSE_Algorithm_ES256 and params is COSE_curve_P_256
 * returns 0 when OK,
 * returns != 0 when error occurred
 */
int
oscore_mbedtls_ecp_verify(int8_t cose_alg, int8_t alg_param, uint8_t *signature, 
    size_t signature_len, uint8_t *payload, size_t payload_len, mbedtls_pk_context *mbed_ctx){
    mbedtls_ecp_group_id group = cose_group_id(alg_param);
    mbedtls_md_type_t md_type = cose_to_mbedtls_md(cose_alg);
    if(group == (mbedtls_ecp_group_id)MBEDTLS_PK_NONE || md_type == MBEDTLS_MD_NONE)  {
        return -5;
    }
    size_t hash_len = cose_hash_len(cose_alg);
    if (hash_len == 0) return -5;
    int     ret = 1;       /* mbedtls error return */
    unsigned char hash[COSE_Algorithm_HMAC512_512_HASH_LEN];  /* maximum length hash */
    mbedtls_ctr_drbg_context ctr_drbg;	
    mbedtls_ctr_drbg_init( &ctr_drbg );
    uint8_t public_key[100];
    memset  (public_key, 0, 100);
    size_t public_key_len = 100;
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init( &entropy );
    char err_buf[CRT_BUF_SIZE];    
    memset( err_buf, 0, sizeof( err_buf ) ); 
    
    mbedtls_ecdsa_context *key_pair = mbed_ctx->pk_ctx;
    ret = mbedtls_ecp_point_write_binary( &key_pair->grp, &key_pair->Q,
            MBEDTLS_ECP_PF_UNCOMPRESSED, &public_key_len, public_key, public_key_len);
    if (ret != 0)
    {
		mbedtls_strerror( ret, err_buf, sizeof(err_buf));
        coap_log(LOG_ERR, " failed\n  !mbedtls_ecp_point_write_binary returned %d - %s\n", -ret, err_buf );
        goto exit;
    }
    
    if (coap_get_log_level() >= LOG_INFO){
      fprintf(stderr,"Verify:\n");
      fprintf(stderr,"Public Key:\n");
      for (uint16_t u = 0 ; u < public_key_len; u++)
                fprintf(stderr," %02x",public_key[u]);
      fprintf(stderr,"\n");
      fprintf(stderr,"incoming payload \n");
      for (uint16_t u = 0 ; u < payload_len; u++)
                fprintf(stderr," %02x",payload[u]);
      fprintf(stderr,"\n");

      fprintf(stderr,"Signature:\n");
      for (uint16_t u = 0 ; u < signature_len; u++)
                fprintf(stderr," %02x",signature[u]);
      fprintf(stderr,"\n");
    }
    /* calculate hash over payload  */
    
    if( ( ret = mbedtls_sha256_ret( payload, payload_len, hash, 0 ) ) != 0 )
    {
		mbedtls_strerror( ret, err_buf, sizeof(err_buf));
        coap_log( LOG_ERR, " failed\n  ! mbedtls_sha256_ret returned %d - %s\n", -ret, err_buf );
      
    }
    
    if (coap_get_log_level() >= LOG_INFO){
        fprintf(stderr,"sha 256 hash: \n");
        for (uint qq =0; qq < hash_len; qq++)
                  fprintf(stderr," %02x", hash[qq]);
        fprintf(stderr,"\n");
    }
    uint8_t mbed_sig[100];
    size_t sig_len = 100;
    create_asn_signature(signature, mbed_sig, &sig_len);
//    fprintf(stderr,"asn signature with length %d \n", (int)sig_len);
//    for (uint16_t u = 0 ; u < sig_len; u++)
//                fprintf(stderr," %02x",mbed_sig[u]);
//      fprintf(stderr,"\n");
    if( ( ret = mbedtls_pk_verify( mbed_ctx, MBEDTLS_MD_SHA256, hash, 0,
                                       mbed_sig, sig_len ) ) != 0 )
    {
		mbedtls_strerror( ret, err_buf, sizeof(err_buf));		
        coap_log( LOG_ERR," failed\n  ! mbedtls_pk_verify returned %d - %s\n", -ret, err_buf );
    }

exit:
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    return ret;
} 

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

/* backward compatibility with old aes_ccm only version   */
int oscore_AES_CCM_encrypt(uint8_t alg, uint8_t *key, uint8_t key_len, uint8_t *nonce, uint8_t nonce_len,
 uint8_t *aad, uint8_t aad_len, uint8_t *plaintext_buffer, uint16_t plaintext_len, uint8_t *ciphertext_buffer){
	 
   return oscore_mbedtls_encrypt_aes_ccm(alg, key, key_len, nonce, nonce_len,
        aad, aad_len, plaintext_buffer, plaintext_len, ciphertext_buffer);
 }
 
 int oscore_AES_CCM_decrypt(uint8_t alg, uint8_t *key, uint8_t key_len, uint8_t *nonce, uint8_t nonce_len,
        uint8_t *aad, uint8_t aad_len, uint8_t *ciphertext_buffer, uint16_t ciphertext_len, uint8_t *plaintext_buffer)
{
	return oscore_mbedtls_decrypt_aes_ccm(alg, key, key_len, nonce, nonce_len,
        aad, aad_len, ciphertext_buffer, ciphertext_len, plaintext_buffer);
}


/* only works with key_len <= 64 bytes */
void
hmac_sha256(uint8_t *key, uint8_t key_len, uint8_t *data, uint8_t data_len, uint8_t *hmac)
{
	oscore_mbedtls_hmac(COSE_Algorithm_HMAC256_256, key, key_len, data, data_len, hmac);
}


/* Return 0 if signing failure. Signatue length otherwise, signature length and key length are derived fron ed25519 values. No check is done to ensure that buffers are of the correct length. */
/* when public key is NULL, seed is used to generate public key and private key */
/* when, public key is present, then seed is private key   */
/* waiting for implementation in mbedtls; for the moment local routines are used  */

int
oscore_edDSA_sign(int8_t alg, int8_t alg_param, uint8_t *signature, uint8_t *ciphertext, uint16_t ciphertext_len, uint8_t *seed, uint8_t *public_key){
   if(alg != COSE_Algorithm_EdDSA || alg_param != COSE_Elliptic_Curve_Ed25519)  {
    return 0;
  }
  unsigned char new_private_key[Ed25519_PRIVATE_KEY_LEN];
  unsigned char new_public_key [Ed25519_PUBLIC_KEY_LEN];
  /* seed (32 bytes) on input comes from private key file generated by e.g. openssl  */
  /* from seed generate private and public key */
  if (public_key == NULL){
     ed25519_create_keypair(new_public_key, new_private_key, seed);
  } else {
      memcpy(new_private_key, seed, Ed25519_PRIVATE_KEY_LEN);
      memcpy(new_public_key, public_key, Ed25519_PUBLIC_KEY_LEN);
  }

  ed25519_sign(signature, ciphertext, ciphertext_len, new_public_key, new_private_key);

  if (coap_get_log_level() >= LOG_INFO){

    fprintf(stderr,"Sign:\n");
    fprintf(stderr,"Public Key:\n");
    for (uint16_t u = 0 ; u < Ed25519_PUBLIC_KEY_LEN; u++)
                fprintf(stderr," %02x",new_public_key[u]);
    fprintf(stderr,"\n");
    fprintf(stderr,"Private Key:\n");
    for (uint16_t u = 0 ; u < Ed25519_PRIVATE_KEY_LEN; u++)
                fprintf(stderr," %02x",new_private_key[u]);
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


