/*
 *  Public key-based signature creation program
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */
 
#include "ecc.h"
#include "ed25519.h"
#include "edDSA_ge.h"
#include "edDSA_sc.h"
#include "edDSA_ge.h"
#include "sha512.h"

#include "mbedtls/config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include "mbedtls/error.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"
#include "mbedtls/asn1.h"
#include "mbedtls/sha256.h"
#include "mbedtls/x509_crt.h"
#include <string.h>

#define KEY         "../../certificates/8021ar/try/private/ca-key.pem"
#define CERT        "../../certificates/8021ar/try/certs/ca-cert.pem"
#define X509_R      "../../coap_cc_code/certificates/brski/certs/ca-regis.crt"
#define KEY_R       "../../coap_cc_code/certificates/brski/private/ca-regis.key"

#define X509_E      "../../coap_cc_code/certificates/brski/intermediate/certs/pledge_ed25519_crt.der"
#define KEY_E       "../../coap_cc_code/certificates/brski/intermediate/private/pledge_ed25519_key.der"

#define PLEDGE_PWD     "watnietweet"

#define CRT_BUF_SIZE  1024


static uint8_t *
parse_array(uint8_t **p, uint8_t *end, uint8_t *oid, size_t oid_len, int8_t *present, size_t *size){
    char err_buf[CRT_BUF_SIZE];
    size_t len = 0;
    int     tag = 0;
    int8_t present_below = 0;
    
    while (*p < end){
		tag = (int)(*p)[0];
        (*p)++;
	    int ret = mbedtls_asn1_get_len(p, end, &len);
	    if (ret != 0){
	        mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
            printf( " failed\n  !  mbedtls_asn1_get_len"
                            "returned -0x%04x - %s\n\n", (unsigned int) -ret, err_buf );
            return NULL;
        }
	    uint8_t *ct = *p;
		if (tag == (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)){
			uint8_t * pt = parse_array(&ct, ct+len, oid, oid_len, &present_below, size );
			if (pt != NULL)return pt;
		}
		if (tag == MBEDTLS_ASN1_OID){
			printf("object ");
			for (int qq = 0; qq < len; qq++)printf("%02x",(*p)[qq]);
			printf("\n");
			if (memcmp(*p, oid, oid_len) == 0) *present = 1;
		}
		if (tag == MBEDTLS_ASN1_OCTET_STRING){
			printf("octet string  ");
		    for (int qq = 0; qq < len; qq++)printf("%02x",(*p)[qq]);
		    printf("\n");
		    if (present_below == 1){
				printf("return oid *p\n");
				*size = len;
				return *p;
			}
		}
		if (tag == MBEDTLS_ASN1_BIT_STRING){
			printf("bit string  ");
		    for (int qq = 1; qq < len; qq++)printf("%02x",(*p)[qq]);
		    printf("\n");
		    if (present_below == 1){
				printf("return oid \n");
				*size = len -1;
				return *p+1;
			}
		}
	    *p = *p + len;   
	} /* while */
	return NULL;
}

/* parse_oid
 * p points to start of DER of certificate or key file
 * searches for object with oid specified in oid
 * return pointer to specified object with length returned in size
 * null pointer means not found
 */
static uint8_t *
parse_oid(uint8_t **p, uint8_t *end, uint8_t *oid, size_t oid_len, size_t *size){
	int8_t present = 0;
	return parse_array(p, end, oid, oid_len, &present, size);
}

int main( void )
{
    int ret = 0;
    char c_file[] = X509_E;
    char *cert_file = c_file;
    char k_file[] = KEY_E;
    char *key_file = k_file;
 
    unsigned char public_key[32];
    unsigned char new_public_key[32];
    unsigned char seed[32];
	unsigned char private_key[64];
	unsigned char signature[ 64];
	
    unsigned char input_array[ 256];
    memset(input_array, 25, 256);
    uint8_t *result = NULL;
    
    struct stat buffer;
    int         status;
    
/* read private key from key file  */

    FILE *f = fopen(k_file, "r");
    
   status = stat(k_file, &buffer);
   if(status == 0) {
        printf("file size is %d \n", (int)buffer.st_size);
   }
   result = malloc((int)buffer.st_size + 2);
    if (f == NULL){
		printf("key file could not be opened \n");
		exit(0);
	}
    size_t size = (int)buffer.st_size;
    size_t res = fread(result, size, 1, f);
	
    uint8_t *p = result; 
    uint8_t *end = p + size;
    size_t key_size = 0;
    uint8_t  ED25519[3] = {0x2b, 0x65, 0x70};
    uint8_t *found = parse_oid(&p, end, ED25519, 3, &key_size);
    if (found != NULL){
		printf("found ED25519 private key with size %d\n", (int)key_size - 2);
		for (int qq =2; qq< key_size; qq++)seed[qq-2] = found [qq];
		printf("\n ED25519 seed: \n");
		for (int i = 0; i < 32 ; i++){
             printf(" %02x", seed[i]);
        }
    printf("\n");
	} else {printf("Nothing found \n");}


    free(result);
    
  /* read public key from certificate  */
    
   f = fopen(c_file, "r");
    
   status = stat(c_file, &buffer);
   if(status == 0) {
        printf("file size is %d \n", (int)buffer.st_size);
   }
   result = malloc((int)buffer.st_size + 2);
    if (f == NULL){
		printf("certificate file could not be opened \n");
		exit(0);
	}
    size = (int)buffer.st_size;
    res = fread(result, size, 1, f);
	
    p = result; 
    end = p + size;
    key_size = 0;
    found = parse_oid(&p, end, ED25519, 3, &key_size);
    if (found != NULL){
		printf("found ED25519 public key with size %d\n", (int)key_size);
		for (int qq =0; qq< key_size; qq++)public_key[qq] = found [qq];
		printf("\n");
		for (int i = 0; i < 32 ; i++){
            printf(" %02x", public_key[i]);
         }
    printf("\n");
	} else {printf("Nothing found \n");}

/* manipulate private and public key  */
 
    ed25519_create_keypair(new_public_key, private_key, seed);
    
    printf(" ed25519 new public key \n");
    for (int i = 0; i < 32 ; i++){
      printf(" %02x", new_public_key[i]);
    }
    printf("\n");    

/* sign input_array with key pair */
    printf("sign with new_public_key and private key \n");
    ed25519_sign(signature, input_array, sizeof(input_array), new_public_key, private_key);
    printf(" ed25519 public key \n");
    for (int i = 0; i < 32 ; i++){
      printf(" %02x", new_public_key[i]);
    }
    printf("\n");

    printf(" ed25519 private key \n");
    for (int i = 0; i < 32 ; i++){
      printf(" %02x", private_key[i]);
    }
    printf("\n");
    
    printf(" ed25519 signature \n");
    for (int i = 0; i < 64 ; i++){
      printf(" %02x", signature[i]);
    }
    printf("\n");
    
    /* verify the signature with new_public_key */
    printf("verify with new public key \n");
    if (ed25519_verify(signature, input_array, sizeof(input_array), new_public_key)) {
        printf("valid signature\n");
        for (int i = 0; i <64 ; i++){
          printf(" %02x", signature[i]);
        }
        printf("\n");
    } else {
        printf("invalid signature\n");
    }
    /* verify the signature with certificate public_key */
    printf("verify with certificate public key \n");    
    if (ed25519_verify(signature, input_array, sizeof(input_array), public_key)) {
        printf("valid signature\n");
        for (int i = 0; i <64 ; i++){
          printf(" %02x", signature[i]);
        }
        printf("\n");
    } else {
        printf("invalid signature\n");
    }

}
