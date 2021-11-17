/* edhoc -- implementation of edhoc routines using
 * a simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 * edhoc is added by:
 * Peter van der Stok <consultancy@vanderstok.org>
 */

#include "coap_internal.h"
#include "coap.h"
#include "cbor.h"
#include "cose.h"
#include "edhoc.h"
#include "bn.h"
#include "oscore-crypto.h"
#include "oscore-mbedtls.h"
#include "oscore-context.h"
#include "client_request.h"
#include "coap_server.h"
#include "brski.h"

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <mbedtls/x509_crt.h>
#include <mbedtls/asn1.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/config.h>

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

#define COSE_UNDEFINED         6666
#define COSE_x5t               34
#define COSE_x5chain           33

/* transported certificates with public key */
/* Initiator certificate stored at Receiver */
#define X509_initiator       "./certificates/transport/registrar/client.der"
/* Receiver certificate stored at Initiator */
#define X509_receiver        "./certificates/transport/pledge/server.der"

/* max length of keys and nonces for storage*/
#define MAX_NONCE_LEN               16
#define MAX_HASH_LEN                64
#define MAX_TAG_LEN                 16
#define MAX_SIGNATURE_LEN           100
#define MAX_KEY_LEN                 64
#define SALT_LEN                    8

#define C_X_offset              24  /* substraction factor of single byte identifier */

#define CRT_BUF_SIZE            1024 /* for mbedtls error string */

/* variables used for edhoc communication  */

/* structures used for ephemeral diffie hellman mbedtls contexts */
typedef struct edhoc_context_t {
mbedtls_ctr_drbg_context  *ctr_drbg;	
mbedtls_ecp_group         *grp;
mbedtls_ecp_point         *pub;
mbedtls_mpi               *priv;
mbedtls_mpi               *shar;
mbedtls_entropy_context   *entropy;
} edhoc_context_t;

static mbedtls_ctr_drbg_context    ecdh_cli_drbg;
static mbedtls_ecp_group           ecdh_cli_grp;
static mbedtls_ecp_point           ecdh_cli_pub;
static mbedtls_mpi                 ecdh_cli_priv;
static mbedtls_mpi                 ecdh_cli_shar;
static mbedtls_entropy_context     ecdh_cli_entr;
static mbedtls_ctr_drbg_context    ecdh_srv_drbg;
static mbedtls_ecp_group           ecdh_srv_grp;
static mbedtls_ecp_point           ecdh_srv_pub;
static mbedtls_mpi                 ecdh_srv_priv;
static mbedtls_mpi                 ecdh_srv_shar;
static mbedtls_entropy_context     ecdh_srv_entr;
static edhoc_context_t edhoc_cli_ctx = 
    {.ctr_drbg = &ecdh_cli_drbg, .grp = &ecdh_cli_grp, .pub = &ecdh_cli_pub, .priv = &ecdh_cli_priv, .shar = &ecdh_cli_shar, .entropy = &ecdh_cli_entr};
static edhoc_context_t edhoc_srv_ctx = 
    {.ctr_drbg = &ecdh_srv_drbg, .grp = &ecdh_srv_grp, .pub = &ecdh_srv_pub, .priv = &ecdh_srv_priv, .shar = &ecdh_srv_shar, .entropy = &ecdh_srv_entr}; 

/* structure for edhoc suites */  
#define EDHOC_MAX_SUITE       4

typedef struct edhoc_suite_t {
   int16_t aead;
   int16_t hash;
   int16_t ecdh_curve;
   int16_t sign_alg;
   int16_t sign_curve;
   int16_t app_aead;
   int16_t app_hash;
   coap_string_t key;
   coap_string_t cert;
} edhoc_suite_t;  

static edhoc_suite_t supported_cipher_suites[EDHOC_MAX_SUITE] = { 
  /* suite 0 */
  {COSE_Algorithm_AES_CCM_16_64_128, COSE_ALGORITHM_SHA_256_256, COSE_curve_X25519,
  COSE_Algorithm_EdDSA, COSE_Elliptic_Curve_Ed25519,
  COSE_Algorithm_AES_CCM_16_64_128, COSE_ALGORITHM_SHA_256_256,
  {.length = 0, .s = NULL}, {.length = 0, .s = NULL}},  
  /* suite 1 */
  {COSE_Algorithm_AES_CCM_16_128_128, COSE_ALGORITHM_SHA_256_256, COSE_curve_X25519,
  COSE_Algorithm_EdDSA, COSE_Elliptic_Curve_Ed25519,
  COSE_Algorithm_AES_CCM_16_64_128, COSE_ALGORITHM_SHA_256_256,
  {.length = 0, .s = NULL}, {.length = 0, .s = NULL}}, 
  /* suite 2 */
  {COSE_Algorithm_AES_CCM_16_64_128, COSE_ALGORITHM_SHA_256_256, COSE_curve_P_256,
  COSE_ALGORITHM_ES256, COSE_curve_P_256,
  COSE_Algorithm_AES_CCM_16_64_128, COSE_ALGORITHM_SHA_256_256,
  {.length = 0, .s = NULL}, {.length = 0, .s = NULL}},
  /* suite 3 */
  {COSE_Algorithm_AES_CCM_16_128_128, COSE_ALGORITHM_SHA_256_256, COSE_curve_P_256,
  COSE_ALGORITHM_ES256, COSE_curve_P_256,
  COSE_Algorithm_AES_CCM_16_64_128, COSE_ALGORITHM_SHA_256_256,
  {.length = 0, .s = NULL}, {.length = 0, .s = NULL}}
  };
   
static uint8_t       edhoc_corr   = 0;
static uint8_t       edhoc_method = 0; /* 0: initiator Signature key; 1: Responder signature key  */
static edhoc_suite_t *current_cipher_suite = NULL;
static char          edhoc_function = '0';    /* set to 'I in initiator and to 'R in Responder */

static uint8_t edhoc_state = EDHOC_MESSAGE_1; 

void
edhoc_init_suite_files(char *key_ed25519, char *key_es256, char *cert_ed25519, char *cert_es256){
  /* suite 0 ED25519 */
  if (key_ed25519 != NULL){
    supported_cipher_suites[0].key.length = strlen(key_ed25519);
    supported_cipher_suites[0].key.s =      coap_malloc(strlen(key_ed25519)+1);
    memcpy(supported_cipher_suites[0].key.s, key_ed25519, strlen(key_ed25519));
    supported_cipher_suites[0].key.s[strlen(key_ed25519)] = 0;
  }
  if (cert_ed25519 != NULL){
    supported_cipher_suites[0].cert.length = strlen(cert_ed25519);
    supported_cipher_suites[0].cert.s =      coap_malloc(strlen(cert_ed25519)+1);
    memcpy(supported_cipher_suites[0].cert.s, cert_ed25519, strlen(cert_ed25519));
    supported_cipher_suites[0].cert.s[strlen(cert_ed25519)] = 0;
  }
  /* suite 1 ED25519 */
  if (key_ed25519 != NULL){
    supported_cipher_suites[1].key.length = strlen(key_ed25519);
    supported_cipher_suites[1].key.s =      coap_malloc(strlen(key_ed25519)+1);
    memcpy(supported_cipher_suites[1].key.s, key_ed25519, strlen(key_ed25519));
    supported_cipher_suites[1].key.s[strlen(key_ed25519)] = 0;
  }
  if (cert_ed25519 != NULL){
    supported_cipher_suites[1].cert.length = strlen(cert_ed25519);
    supported_cipher_suites[1].cert.s =      coap_malloc(strlen(cert_ed25519)+1);
    memcpy(supported_cipher_suites[1].cert.s, cert_ed25519, strlen(cert_ed25519));
    supported_cipher_suites[1].cert.s[strlen(cert_ed25519)] = 0;  
  }
  /* suite 2 ES256 */
  if (key_es256 != NULL){
    supported_cipher_suites[2].key.length = strlen(key_es256);
    supported_cipher_suites[2].key.s =      coap_malloc(strlen(key_es256)+1);
    memcpy(supported_cipher_suites[2].key.s, key_es256, strlen(key_es256));
    supported_cipher_suites[2].key.s[strlen(key_es256)] = 0;
  }
  if (cert_es256 != NULL){
    supported_cipher_suites[2].cert.length = strlen(cert_es256);
    supported_cipher_suites[2].cert.s =      coap_malloc(strlen(cert_es256)+1);
    memcpy(supported_cipher_suites[2].cert.s, cert_es256, strlen(cert_es256));
    supported_cipher_suites[2].cert.s[strlen(cert_es256)] = 0;
  }
  /* suite 3 ES256 */
  if (key_es256 != NULL){
    supported_cipher_suites[3].key.length = strlen(key_es256);
    supported_cipher_suites[3].key.s =      coap_malloc(strlen(key_es256)+1);
    memcpy(supported_cipher_suites[3].key.s, key_es256, strlen(key_es256));
    supported_cipher_suites[3].key.s[strlen(key_es256)] = 0;
  }
  if (cert_es256 != NULL){
    supported_cipher_suites[3].cert.length = strlen(cert_es256);
    supported_cipher_suites[3].cert.s =      coap_malloc(strlen(cert_es256)+1);
    memcpy(supported_cipher_suites[3].cert.s, cert_es256, strlen(cert_es256));
    supported_cipher_suites[3].cert.s[strlen(cert_es256)] = 0;  
  }
}

/* stores data of last identifier */
static coap_string_t edhoc_C_I = {
	.length = 0,
	.s = NULL
};
static coap_string_t edhoc_C_R = {	
  .length = 0,
	.s = NULL
};

  /* G_X_string contains the G_X sent by the initiator in message_1 */
static coap_string_t G_X_string = {
	.length = 0,
	.s = NULL
};

static uint16_t edhoc_code = 0;
static coap_string_t edhoc_message_2 = {
	.length = 0,
	.s = NULL
};

static coap_string_t edhoc_message_4 = {
	.length = 0,
	.s = NULL
};

/* stores message2 received for edhoc after message_1 */
int16_t
message_2_receipt(unsigned char *data, size_t len, uint16_t code, 
                   uint16_t block_num, uint16_t more) {  
  if (code >> 5 != 2){
    if (edhoc_message_2.s != NULL)coap_free(edhoc_message_2.s);
    edhoc_message_2.length = 0;
    edhoc_message_2.s = NULL;
    edhoc_code = code;
    return 0;
  }
  if (block_num == 0){   /* newly arrived message */
	if (edhoc_message_2.s != NULL)coap_free(edhoc_message_2.s);
    edhoc_message_2.length = 0;
    edhoc_message_2.s = NULL;
  }
  size_t offset = edhoc_message_2.length;
      /* Add in new block to end of current data */
  coap_string_t new_mess = {.length = edhoc_message_2.length, .s = edhoc_message_2.s};
  edhoc_message_2.length = offset + len;
  edhoc_message_2.s = coap_malloc(offset+len);
  if (offset != 0) 
     memcpy (edhoc_message_2.s, new_mess.s, offset);  /* copy old contents  */
  if (new_mess.s != NULL)coap_free(new_mess.s);
  memcpy(edhoc_message_2.s + offset, data, len);         /* add new contents  */
  edhoc_code = code;
  return 0;
}

/* stores message4 received for edhoc after message_1 */
int16_t
message_4_receipt(unsigned char *data, size_t len, uint16_t code, 
                         uint16_t block_num, uint16_t more) {
  if (code >> 5 != 2){
    if (edhoc_message_4.s != NULL)coap_free(edhoc_message_4.s);
    edhoc_message_4.length = 0;
    edhoc_message_4.s = NULL;
    edhoc_code = code;
    return 0;
  }
  if (block_num == 0){   /* newly arrived message */
	if (edhoc_message_4.s != NULL)coap_free(edhoc_message_4.s);
    edhoc_message_4.length = 0;
    edhoc_message_4.s = NULL;
  }
  size_t offset = edhoc_message_4.length;
      /* Add in new block to end of current data */
  coap_string_t new_mess = {.length = edhoc_message_4.length, .s = edhoc_message_4.s};
  edhoc_message_4.length = offset + len;
  edhoc_message_4.s = coap_malloc(offset+len);
  if (offset != 0) 
     memcpy (edhoc_message_4.s, new_mess.s, offset);  /* copy old contents  */
  if (new_mess.s != NULL)coap_free(new_mess.s);
  memcpy(&edhoc_message_4.s[offset],data, len);         /* add new contents  */
  edhoc_code = code;
  return 0;
}

/* and the messages belonging to this identifier  */
static coap_string_t edhoc_message_1 = {
	.length = 0,
	.s = NULL
};

static coap_string_t edhoc_message_3 = {
	.length = 0,
	.s = NULL
};

static coap_string_t edhoc_G_XY = {
	.length = 0,
	.s = NULL
};

/* variables used for libcoap  */

int resource_flags;

/* read_file_mem
 * read from file to memory 
 * returns pointer with contents with length
 * returns ok = 0; nok = 1;
 */
static uint8_t *
read_file_mem(const char* file, size_t *length) {
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

/* write_file_mem
 * write from memory contained in contents to file
 * returns ok = 0; nok = 1;
 */
 static uint8_t 
 write_file_mem(const char* file, coap_string_t *contents) {
  FILE *f = fopen(file, "w");
  if (f == NULL){
      coap_log(LOG_DEBUG, "file %s cannot be opened\n", file);
	  return 1;
  }
  size_t size = fwrite( contents->s, contents->length, 1, f);
  fclose( f);
  if (size == 1)return 0;
  return 1;
}

static void
edhoc_free(edhoc_context_t *edhoc_ctx){
    mbedtls_ctr_drbg_free ( edhoc_ctx->ctr_drbg);
    mbedtls_ecp_group_free( edhoc_ctx->grp);
    mbedtls_ecp_point_free( edhoc_ctx->pub);
    mbedtls_mpi_free      ( edhoc_ctx->priv);
    mbedtls_mpi_free      ( edhoc_ctx->shar);      
    mbedtls_entropy_free  ( edhoc_ctx->entropy);  
}

static void
edhoc_init(edhoc_context_t *edhoc_ctx){
    mbedtls_ctr_drbg_init ( edhoc_ctx->ctr_drbg);
    mbedtls_ecp_group_init( edhoc_ctx->grp);
    mbedtls_ecp_point_init( edhoc_ctx->pub);
    mbedtls_mpi_init      ( edhoc_ctx->priv);
    mbedtls_mpi_init      ( edhoc_ctx->shar);      
    mbedtls_entropy_init  ( edhoc_ctx->entropy);  
}

/* edhoc_check_C_X
 * check of current C_X is identical to last stored C_X
 * no agreement: returns -1
 * agreement returns 0
 */
static int8_t
edhoc_check_C_X( char IR, uint8_t *C_X, size_t C_X_len){
  if (IR == 'I'){
    if (C_X_len != edhoc_C_I.length)return -1;
    for (uint qq = 0; qq < C_X_len; qq++) if (C_X[qq] != edhoc_C_I.s[qq]) return -1;
  } else if (IR == 'R'){
    if (C_X_len != edhoc_C_R.length)return -1;
    for (uint qq = 0; qq < C_X_len; qq++) if (C_X[qq] != edhoc_C_R.s[qq]) return -1;
  }
  else return -1;
  return 0;
}


/* edhoc_return_C_X  (X = I,R)
 * return specified stored C_X
 * nothing stored : returns -1
 * agreement returns 0
 */
static int8_t
edhoc_return_C_X(char IR, uint8_t **C_X, size_t *C_X_len){
  if ( IR == 'I'){
    if  (edhoc_C_I.s == NULL) return -1;
    *C_X_len = edhoc_C_I.length;
    *C_X = coap_malloc(*C_X_len);    
    memcpy(*C_X, edhoc_C_I.s, *C_X_len);
  } else if (IR == 'R'){
    if  (edhoc_C_R.s == NULL) return -1;
    *C_X_len = edhoc_C_R.length;
    *C_X = coap_malloc(*C_X_len);    
    memcpy(*C_X, edhoc_C_R.s, *C_X_len);
  }
  else return -1;
  return 0;
}


/* edhoc_enter_C_X
 * stores specified C_X
 * no agreement: returns -1
 * agreement returns 0
 */
static int8_t
edhoc_enter_C_X(char IR, uint8_t *C_X, size_t C_X_len){
  if ( IR == 'I'){
    if (edhoc_C_I.s != NULL)coap_free(edhoc_C_I.s);
    edhoc_C_I.s = NULL;  
    if ((C_X == NULL) || (C_X_len == 0)){
      edhoc_C_I.length = 0;
    } else {
      edhoc_C_I.s = coap_malloc(C_X_len);
      edhoc_C_I.length = C_X_len;
      memcpy(edhoc_C_I.s, C_X, C_X_len);
    }
  } else if (IR == 'R'){
    if (edhoc_C_R.s != NULL)coap_free(edhoc_C_R.s);
    edhoc_C_R.s = NULL;  
    if ((C_X == NULL) || (C_X_len == 0)){
      edhoc_C_R.length = 0;
    } else {
      edhoc_C_R.s = coap_malloc(C_X_len);
      edhoc_C_R.length = C_X_len;
      memcpy(edhoc_C_R.s, C_X, C_X_len);
    }
  }
  else return -1;
  return 0;
}

/* edhoc_cbor_put_C_X
 * data points to first location to store
 * C_X and C_X_len specify the identifier to store
 * stores a cbor array when C_X_len > 0
 * stores a cbor unsigned/negative integer - 24 when C_X_len = 1 and  identifier < 48
 * returns number of bytes stored
 * data points to location after the last store
 */
static size_t
edhoc_cbor_put_C_X(uint8_t **data, uint8_t *C_X, size_t C_X_len){
  if (C_X_len != 1){
    return cbor_put_bytes(data, C_X, C_X_len);
  } else if (C_X_len == 1) {
    if (C_X[0] < 48){
      int8_t nb = C_X[0] - C_X_offset;
      return cbor_put_number(data, nb);
    } else {
      return cbor_put_bytes(data, C_X, C_X_len);
    }
  }
  else return 0;
}

/* edhoc_cbor_get_C_X
 * data points to first location to retrieve cbor representation of C_X
 * returns C_X and C_X_len 
 * data points to location after the last store
 * ok , returns 0.
 */
static int8_t
edhoc_cbor_get_C_X(uint8_t **data, uint8_t **C_X, size_t *C_X_len){
  int64_t  mm = 0;
  uint8_t  elem = cbor_get_next_element(data);
  if (elem == CBOR_BYTE_STRING){
	  return cbor_get_string_array( data, C_X, C_X_len);
  } else if (elem == CBOR_UNSIGNED_INTEGER || elem == CBOR_NEGATIVE_INTEGER){
    int8_t ok = cbor_get_number( data, &mm);
    if (ok != 0)return ok;
    int16_t val = (int8_t)(mm);
    *C_X = coap_malloc(2);
    memset(*C_X, 0, 2);
    (*C_X)[0] = val + C_X_offset;
    *C_X_len = 1;
  }
  return 0;
}


/*
 * Return error and error message
 */
static void
edhoc_error_return(char IR, uint8_t error, coap_pdu_t *response,
                                       const char *message){
  unsigned char opt_buf[5];
  uint8_t  *C_X = NULL;
  size_t   C_X_len = 0;
  if ((IR = 'I')&& ((edhoc_corr == 1) || (edhoc_corr == 0))){
    edhoc_return_C_X('R', &C_X, &C_X_len);
  } else if ((IR = 'R')&& ((edhoc_corr == 2) || (edhoc_corr == 0))){
    edhoc_return_C_X('I', &C_X, &C_X_len);
  }
  coap_log(LOG_WARNING,"%s",message);
  size_t  ms_size = strlen(message) + C_X_len + 4;
  uint8_t *edhoc_message = coap_malloc(ms_size);
  size_t  nr = 0;
  char    *pt = NULL;
  memcpy(&pt, &message, sizeof(void *));
  uint8_t *buf = edhoc_message;
  nr += cbor_put_bytes(&buf, C_X, C_X_len);
  nr += cbor_put_text(&buf, pt, strlen(message));
  assert (nr < ms_size);
  response->code = error;
  response->data = NULL;
  response->used_size = response->token_length;
  coap_add_option(response,
                COAP_OPTION_CONTENT_FORMAT,
                coap_encode_var_safe(opt_buf, sizeof(opt_buf),
                COAP_MEDIATYPE_TEXT_PLAIN), opt_buf);
  coap_add_data(response, nr, (const uint8_t *)edhoc_message);
}


/* edhoc_parse_der
 * p points to start of certificate or key file using DER format
 * end points to end
 * searches for oid object specified in oid
 * return pointer to specified object with length returned in size
 * null pointer means not found
 */
static uint8_t *
edhoc_parse_der(uint8_t **p, uint8_t *end, uint8_t *oid, size_t oid_len, int8_t *present, size_t *size){
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
            coap_log(LOG_ERR, " failed\n  !  mbedtls_asn1_get_len"
                            "returned -0x%04x - %s\n\n", (unsigned int) -ret, err_buf );
            return NULL;
      }
	    uint8_t *ct = *p;
		if (tag == (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)){
			uint8_t * pt = edhoc_parse_der(&ct, ct+len, oid, oid_len, &present_below, size );
			if (pt != NULL)return pt;
		}
		if (tag == MBEDTLS_ASN1_OID){
			if (memcmp(*p, oid, oid_len) == 0) *present = 1;
		}
		if (tag == MBEDTLS_ASN1_OCTET_STRING){
		    if (present_below == 1){
				  *size = len;
				  return *p;
			  }
		}
		if (tag == MBEDTLS_ASN1_BIT_STRING){
		    if (present_below == 1){
				  *size = len -1;
				  return (*p) + 1;
			  }
		}
    *p = *p + len;   
	} /* while */
	return NULL;
}

/* edhoc_parse_oid
 * p points to start of certificate or key file using DER format
 * end points to end
 * searches for ED25519 key
 * return pointer to specified object with length returned in size
 * null pointer means not found
 */
static uint8_t *
edhoc_parse_oid(uint8_t **p, uint8_t *end, size_t *size){
  uint8_t  ED25519[3] = {0x2b, 0x65, 0x70};
	int8_t present = 0;
	return edhoc_parse_der(p, end, ED25519, 3, &present, size);
}

/* edhoc_compose_info
 * composes CBOR array for key or nonce generation
 * return size of cbor array
 */
static size_t
edhoc_compose_info(uint8_t *buf, int16_t alg, uint8_t *enc, size_t enc_len, char *ident, size_t ident_len ,size_t length){
  uint8_t *pt = buf;
  size_t nr = 0;
  nr += cbor_put_array( &pt, 4);
  nr += cbor_put_number( &pt, alg);
  nr += cbor_put_bytes( &pt, enc, enc_len);
  nr += cbor_put_text( &pt, ident, ident_len);
  nr += cbor_put_number( &pt, length);

  return nr;
}

/* edhoc_create_key
 * creates_key with compose_info
 */
static void
edhoc_create_key( uint8_t **key, size_t key_len, char *k_xx, size_t k_xx_len,
                      uint8_t *TH_x, uint8_t *prk){  
    *key = coap_malloc(key_len);
    int16_t alg = current_cipher_suite->aead;
    int16_t hash_alg = current_cipher_suite->hash;
    size_t  hash_len = cose_hash_len (hash_alg);
    size_t  len = hash_len + k_xx_len + 20;    /* estimated ample space */
    uint8_t *info = coap_malloc( len);
    size_t  info_len = edhoc_compose_info(info, alg, 
              TH_x, hash_len, k_xx, k_xx_len, key_len);
    assert( info_len < len);
    hkdf_expand( prk, info, info_len, *key, key_len);
    coap_free( info);
}

/* edhoc_create_oscore_context
 * on input TH_4 and prk_4x3m
 * generates master-salt and master-secret for oscore context with identifier C_R
 * returns osc_ctx when context is generated
 * else returns NULL
 */
static oscore_ctx_t *
edhoc_create_oscore_context(uint8_t *PRK_4x3m, uint8_t *TH_4){ 
  int16_t alg      = current_cipher_suite->app_aead;
  size_t  key_len  = cose_key_len(alg);
  uint8_t *Master_key  = NULL;
  uint8_t *Master_salt = NULL;
  char    secret[]     = "OSCORE Master Secret";
  char    salt[]       = "OSCORE Master Salt";
  int8_t ok = 0;
  edhoc_create_key( &Master_key, key_len, secret, sizeof(secret) - 1,
                      TH_4, PRK_4x3m);  
  edhoc_create_key( &Master_salt, SALT_LEN, salt, sizeof(salt) - 1,
                      TH_4, PRK_4x3m);
  uint8_t *C_I = NULL;
  size_t  C_I_len = 0;
  uint8_t *C_R = NULL;
  size_t  C_R_len = 0;  
  ok = edhoc_return_C_X('I', &C_I, &C_I_len);
  if (ok != 0) return NULL;     
  ok = edhoc_return_C_X('R', &C_R, &C_R_len);
  if (ok != 0) return NULL;                
  oscore_ctx_t *osc_ctx = NULL;
/* prepare one sender receiver context   */
  osc_ctx = oscore_derive_ctx(Master_key, 
      key_len, Master_salt, SALT_LEN,
      alg, C_R, C_R_len, C_I, C_I_len, NULL, 0, 
      OSCORE_DEFAULT_REPLAY_WINDOW);
  if(!osc_ctx ){
	  coap_log(LOG_CRIT, "Could not create OSCORE Security Context!\n");
  }
  oscore_enter_context(osc_ctx); 
  return osc_ctx;                                          
}

/*  
 * IR specifies if this is an "I" Initiator or "R" Responder
 * returns KEY_F and allocates space
 * KEY_F contans key file in DER
 * returns error -1 when parameter values are not supported
 * returns 0 when OK
 */
static int16_t
edhoc_edDSA_KEY( uint8_t **KEY_F, size_t *KEY_F_len){
    int16_t alg = current_cipher_suite->sign_alg; 
    if  (alg == COSE_ALGORITHM_ES256){
      coap_log(LOG_ERR,"use edhoc_ES256_KEY for ES256 algorithm \n");
      return -1;
    } else if (alg != COSE_Algorithm_EdDSA){
      coap_log(LOG_ERR,"unsupported algorithm \n");
      return -1;
    }
    if (current_cipher_suite->key.s == NULL){
      coap_log(LOG_ERR,"edDSA key file is not defined in edhoc suite \n");
      return -1;
    }
    struct stat buffer;
    int        status;
    FILE *f = fopen((char *)current_cipher_suite->key.s, "r");
    status = stat((char *)current_cipher_suite->key.s, &buffer);
    if ((status != 0) || (f == NULL)){
      coap_log(LOG_ERR, "key file %s could not be opened \n", (char *)current_cipher_suite->key.s);
      return -1;
    }
    size_t size = (int)buffer.st_size;
    *KEY_F = coap_malloc(size + 2);
    size_t res = fread(*KEY_F, size, 1, f);
    if (res == 0){
      coap_log(LOG_ERR,"problems with reading key file %s \n", (char *)current_cipher_suite->key.s);
      return -1;
    }
    *KEY_F_len = size;
    return 0;
}

/* edhoc_ID_CRED
 * IR specifies if this is an "I" Initiator or "R" Responder
 * generates ID_CRED_x and CRED_x from certificate file and allocates space
 * CRED_x contains certificate in DER
 * ID_CRED_x contans {x5chain, certificate in DER);
 * returns error -1 when parameter values are not supported
 * returns 0 when OK
 */
static int16_t
edhoc_ID_CRED(  char IR,
                uint8_t **ID_CRED_x, size_t *ID_CRED_x_len,
                uint8_t **CRED_x, size_t *CRED_x_len){ 
    char c_trans_R[]   = X509_initiator;
    char c_trans_I[]   = X509_receiver;
    char *cert_file    = NULL; 
    uint8_t *CERT_F = NULL;       /* ED25519 certificate storage */           
    mbedtls_x509_crt        crt;
    mbedtls_x509_crt_init(&crt);
    uint8_t *start_raw = NULL;
    size_t  size_raw = 0;
    int16_t alg = current_cipher_suite->sign_alg; 
    int    ret = 0;  /* mbedtls error return  */          
    if (IR == edhoc_function){  /* use local original certificate files */
      cert_file = (char *)current_cipher_suite->cert.s;
      if (cert_file == NULL){
        coap_log(LOG_ERR, " certificate file is not define in edhoc suite \n");
        ret = -1;
        goto exit;
      }
    } else {  /* use transported certificate files */
      /* no separation for algorithm, correct ones shlould have been transported  */
      if (IR == 'I')cert_file = c_trans_R;
      if (IR == 'R')cert_file = c_trans_I;
    }
    uint8_t hash[MAX_HASH_LEN];
    uint8_t *data = NULL;
    char err_buf[CRT_BUF_SIZE];    
    memset( err_buf, 0, sizeof( err_buf ) );	
 
    /* find raw certificate  */  
    if (alg == COSE_ALGORITHM_ES256){ 
      ret = mbedtls_x509_crt_parse_file( &crt, cert_file);
      if( ret != 0 )
      {
        mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
        coap_log(LOG_ERR,  " failed\n  !  mbedtls_x509_crt_parse_file %s "
                        "returned -x%02x - %s\n\n", cert_file, (unsigned int) -ret, err_buf );
       goto exit;
      }
      mbedtls_x509_buf *der = &crt.raw;
      start_raw = der->p;
      size_raw  = der->len;
    } else if (alg == COSE_Algorithm_EdDSA){
      struct stat buffer;
      int         status;
      FILE *f = fopen(cert_file, "r");
      status = stat(cert_file, &buffer);
      if ((status != 0) || (f == NULL)){
        coap_log(LOG_ERR, " certificate file %s could not be opened \n", cert_file);
        return -1;
      }
      size_t size = (int)buffer.st_size;
      CERT_F = coap_malloc(size + 2);
      size_t res = fread(CERT_F, size, 1, f);
      if (res == 0){
        coap_log(LOG_ERR,"problems with reading certificate file %s \n", cert_file);
        return -1;
      }
      start_raw = CERT_F;
      size_raw = size;
    }
    ret = mbedtls_sha256_ret(start_raw, size_raw, hash, 0);
    if( ret != 0 )
    {
        mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
        coap_log(LOG_ERR,  " failed\n  !  mbedtls_sha256_ret "
                        "returned -x%02x - %s\n\n", (unsigned int) -ret, err_buf );
        goto exit;
    }
    size_t nr = 0;
    
/* create test vector hash  */
/*
    data = coap_malloc(40);
    uint8_t *pt = data;
    nr += cbor_put_map(&pt, 1);  
    nr += cbor_put_number( &pt, COSE_x5t);
    nr += cbor_put_array( &pt, 2);
    nr += cbor_put_number( &pt, COSE_ALGORITHM_SHA_256_64);
    nr += cbor_put_bytes( &pt, hash, COSE_ALGORITHM_SHA_256_64_LEN);
    assert( nr < 40);
    * */

/* create certificate to be restored */

    data = coap_malloc( size_raw + 10);
    uint8_t *pt = data;
    nr += cbor_put_map(&pt, 1);  
    nr += cbor_put_number( &pt, COSE_x5chain);
    nr += cbor_put_bytes ( &pt, start_raw, size_raw);
    assert( nr < size_raw + 10);

    *ID_CRED_x = coap_malloc(nr);
    *ID_CRED_x_len = nr;
    memcpy(*ID_CRED_x, data, nr);
    coap_free(data);
 
    pt = coap_malloc(size_raw + 5);
    *CRED_x = pt;
    nr = 0;
    nr += cbor_put_bytes( &pt, start_raw, size_raw);
    assert (nr < size_raw + 5);
    *CRED_x_len = nr;
    if (CERT_F != NULL)coap_free(CERT_F);   /* release space where ED25519 certificate is stored */
  
exit:
    mbedtls_x509_crt_free(&crt); 
    return ret;
}


/* edhoc_P_x (with x = 2e , 3ae)
 * IR specifies Initiator or Responder
 * calculates P_2e, P_3ae from Id_cred_R and the cbor byte string of signature
 * return size of P_X
 */
static size_t 
edhoc_P_x( uint8_t **P_x, char IR, uint8_t *signature, size_t signature_len){
  uint8_t *ID_CRED = NULL;
  size_t   ID_CRED_len = 0;
  uint8_t *CRED = NULL;
  size_t   CRED_len = 0;
  int16_t ret = edhoc_ID_CRED( IR, &ID_CRED, &ID_CRED_len, &CRED, &CRED_len);
  if (ret != 0) return 0;
  uint8_t *buf = coap_malloc(ID_CRED_len + signature_len + 10);
  *P_x = buf;
  memcpy(buf, ID_CRED, ID_CRED_len);
  size_t nr = ID_CRED_len;
  buf = buf + ID_CRED_len;
  nr += cbor_put_bytes( &buf, signature, signature_len);
  assert (nr < ID_CRED_len + signature_len + 10);
  coap_free(CRED);
  coap_free(ID_CRED);
  return nr;
}

/* edhoc_M_x (x = 2,3)   (X = I, R)
 * IR specifies X
 * generates the cbor array of Signature1, ID_CRED_X, TH_x , CRED_X, MAC_x
 * return size of CBOR array stored in M_x
 */
static size_t
edhoc_M_x(uint8_t **M_x, char IR, uint8_t *TH_x, size_t TH_x_len,
                                        uint8_t *MAC_x, size_t MAC_x_len){
  
   char Signature1[] = "Signature1";
   uint8_t  *CRED_X = NULL;
   uint8_t  *ID_CRED_X = NULL;
   size_t    CRED_X_len = 0;
   size_t    ID_CRED_X_len = 0;
   int16_t   ret = edhoc_ID_CRED( IR, &ID_CRED_X, &ID_CRED_X_len, &CRED_X, &CRED_X_len);
   if (ret != 0) return 0;
   size_t  buf_len = TH_x_len + CRED_X_len + 4;
   uint8_t *buf = coap_malloc(buf_len);
   uint8_t *pt = buf;
   size_t  nr = cbor_put_bytes(&pt, TH_x, TH_x_len);
   assert(nr < TH_x_len + 4);
   memcpy( pt, CRED_X, CRED_X_len);
   buf_len = nr + CRED_X_len;
   size_t M_x_len = buf_len + sizeof(Signature1) + ID_CRED_X_len + MAC_x_len + 20;
   pt = coap_malloc(M_x_len);
   *M_x = pt;
   nr  = cbor_put_array( &pt, 4);
   nr += cbor_put_text( &pt, Signature1, sizeof(Signature1) - 1);
   nr += cbor_put_bytes( &pt, ID_CRED_X, ID_CRED_X_len);
   nr += cbor_put_bytes( &pt, buf, buf_len);
   nr += cbor_put_bytes( &pt, MAC_x, MAC_x_len);
   coap_free(buf);
   coap_free(ID_CRED_X);
   coap_free(CRED_X);
   assert( nr < M_x_len);  
   return nr;
}

/* edhoc_A_3ae 
 * generates the cbor sequence of "Encrypt0", h'', h'TH_3'
 * return size of CBOR array stored in A_3ae
 */
static size_t
edhoc_A_3ae(uint8_t **A_3ae, uint8_t *TH_3){
   char Encrypt0[] = "Encrypt0";
    int16_t hash_alg = current_cipher_suite->hash;
    size_t  hash_len = cose_hash_len (hash_alg);
   size_t A_3ae_len = sizeof(Encrypt0) + hash_len + 5;
   uint8_t *pt = coap_malloc(A_3ae_len);
   *A_3ae = pt;   
   size_t  nr = 0;
   nr += cbor_put_array( &pt, 3);  
   nr += cbor_put_text( &pt, Encrypt0, sizeof(Encrypt0) - 1);
   nr += cbor_put_bytes( &pt, NULL, 0);
   nr += cbor_put_bytes( &pt, TH_3, hash_len);
   assert( nr < A_3ae_len);
   return nr;
}

/* edhoc_A_xm (with x = 2, 3)
 * generates the cbor array of Encrypt0, ID_CRED_X, TH_x ++ CRED_X
 * return size of CBOR array stored in A_xm
 */
static size_t
edhoc_A_xm(uint8_t **A_xm, uint8_t *ID_CRED, size_t ID_CRED_len, uint8_t *TH_x, size_t TH_x_len,
                                                               uint8_t *CRED, size_t CRED_len){
   char Encrypt0[] = "Encrypt0";
   size_t  buf_len = TH_x_len + CRED_len + 4;
   uint8_t *buf = coap_malloc(buf_len);
   size_t  nr = 0;
   uint8_t *pt = buf;
   nr = cbor_put_bytes( &pt, TH_x, TH_x_len);
   assert( nr < TH_x_len + 4);
   if (CRED_len > 0)memcpy(pt, CRED, CRED_len);
   buf_len = nr + CRED_len;
   size_t A_xm_len = buf_len + sizeof(Encrypt0) + ID_CRED_len + 20;
   pt = coap_malloc(A_xm_len);
   *A_xm = pt;   
   nr = 0;
   nr += cbor_put_array( &pt, 3);
   nr += cbor_put_text( &pt, Encrypt0, sizeof(Encrypt0) - 1);
   nr += cbor_put_bytes( &pt, ID_CRED, ID_CRED_len);
   nr += cbor_put_bytes( &pt, buf, buf_len);
   coap_free(buf);
   assert( nr < A_xm_len);
   return nr;
}

/* edhoc_data_2
 * creates data2: ? h'C_I' h'G_Y' h'C_R'
 */
void 
edhoc_data_2(uint8_t **data_2, size_t *data_2_len, uint8_t *G){
  size_t nr =0;
  uint8_t *C_I = NULL;
  uint8_t *C_R = NULL;
  size_t  C_I_len = 0;
  size_t  C_R_len = 0;
  edhoc_return_C_X('I', &C_I, &C_I_len);
  edhoc_return_C_X('R', &C_R, &C_R_len);
  *data_2 = coap_malloc(C_I_len + C_R_len + COSE_ALGORITHM_ECDH_PUB_KEY_LEN + 4);
  uint8_t *buf = *data_2;  
  if ((edhoc_corr == 0) || (edhoc_corr == 2))
                               nr += edhoc_cbor_put_C_X( &buf, C_I, C_I_len);
  nr += cbor_put_bytes( &buf, G, COSE_ALGORITHM_ECDH_PUB_KEY_LEN);
  nr += edhoc_cbor_put_C_X( &buf, C_R, C_R_len);                            
  assert( nr < C_I_len + C_R_len + COSE_ALGORITHM_ECDH_PUB_KEY_LEN + 4);
  *data_2_len = nr;
}

/* edhoc_TH_4_gen 
 * returns sha256( TH_3, CIPHERTEXT_3) into TH_4
 * returns error -1 when parameter values are not supported
 * returns 0 when OK
 */
static int
edhoc_TH4_gen(uint8_t *TH_4, uint8_t *TH_3, uint8_t *CIPHER3, size_t CIPHER3_len){
  int16_t hash_alg = current_cipher_suite->hash;
  size_t  hash_len = cose_hash_len (hash_alg);
  char err_buf[CRT_BUF_SIZE];    
  memset( err_buf, 0, sizeof( err_buf ) );	
  uint8_t *start = coap_malloc(hash_len + CIPHER3_len + 8);
  uint8_t *pt = start;
  size_t nr = cbor_put_bytes( &pt, TH_3, hash_len);
  nr += cbor_put_bytes(&pt,CIPHER3, CIPHER3_len);
  int ret = mbedtls_sha256_ret(start, nr , TH_4, 0);
  if( ret != 0 )
    {
        mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
        coap_log(LOG_ERR,  " failed\n  !  mbedtls_sha256_ret "
                        "returned -x%02x - %s\n\n", (unsigned int) -ret, err_buf );
        coap_free(start);
        return -1;
    } 
  coap_free(start);  
  return 0;
}

/* edhoc_TH_3_gen 
 * returns sha256( TH_2, CIPHERTEXT_2, data_3) into TH_3
 * returns error -1 when parameter values are not supported
 * returns 0 when OK
 */
static int
edhoc_TH_3_gen(uint8_t *TH_3, uint8_t *TH_2, uint8_t *CIPHERTEXT_2, size_t CIPHER_LEN, uint8_t *data_3, size_t data_3_len){
  int16_t hash_alg = current_cipher_suite->hash;
  size_t  hash_len = cose_hash_len (hash_alg);
  char err_buf[CRT_BUF_SIZE];    
  memset( err_buf, 0, sizeof( err_buf ) );	
  uint8_t *start = coap_malloc(hash_len + CIPHER_LEN + data_3_len + 10);
  uint8_t *pt = start;
  size_t nr = cbor_put_bytes( &pt, TH_2, hash_len);
  memcpy(pt, CIPHERTEXT_2, CIPHER_LEN);
  nr = nr + CIPHER_LEN;
  pt = pt + CIPHER_LEN;
  memcpy(pt, data_3, data_3_len);
  nr = nr + data_3_len;
  assert(nr < hash_len + CIPHER_LEN + data_3_len + 10);

  int ret = mbedtls_sha256_ret(start, nr , TH_3, 0);
  if( ret != 0 )
    {
        mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
        coap_log(LOG_ERR,  " failed\n  !  mbedtls_sha256_ret "
                        "returned -x%02x - %s\n\n", (unsigned int) -ret, err_buf );
        coap_free(start);
        return -1;
    }  
  coap_free(start);  
  return 0;
}  


/* edhoc_TH_2_gen 
 * returns sha256( message, data_2) into TH_2
 * returns error -1 when parameter values are not supported
 * returns 0 when OK
 */
int
edhoc_TH_2_gen(uint8_t *TH_2, coap_string_t *message, uint8_t *data_2, size_t data_2_len){
  char err_buf[CRT_BUF_SIZE];    
  memset( err_buf, 0, sizeof( err_buf ) );	
  uint8_t *start = coap_malloc(data_2_len + message->length);
  memcpy(start, message->s, message->length);
  memcpy(start + message->length, data_2, data_2_len);
  /* still needs parametrezition from cipher_suite */
  int ret = mbedtls_sha256_ret(start, message->length + data_2_len, TH_2, 0);
  if( ret != 0 )
    {
        mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
        coap_log(LOG_ERR,  " failed\n  !  mbedtls_sha256_ret "
                        "returned -x%02x - %s\n\n", (unsigned int) -ret, err_buf );
        coap_free(start);
        return -1;
    } 
  coap_free(start);  
  return 0;
}  

/* edhoc_decompose_CIPHER_Y (x = 2, 3)
 * on input CIPHERTEXT_Y
 * generates ID_CRED_X and signature  (X is R, I);
 * OK: return 0;
 * NOT Ok: returns -1
 */
static int16_t
edhoc_decompose_CIPHER_Y(uint8_t *CIPHERTEXT_Y, uint8_t **ID_CRED_X, size_t *ID_CRED_X_len, 
                                                uint8_t **signature, size_t *signature_len){
                                             
    int64_t mm = 0;
    uint8_t *data = CIPHERTEXT_Y;
    int8_t  elem = cbor_get_next_element(&data);
    if (elem != CBOR_MAP) return -1;
    size_t map_size = cbor_get_element_size(&data);
    if (map_size != 1) return -1;
    int8_t ok = cbor_get_number(&data, &mm);
    if (ok != 0)return -1;
    /* possible values, COSE_x5t and COSE_x5chain */
    if (mm == COSE_x5t){  /* ID_CRED_X contains Certificate hash */
        elem = cbor_get_next_element(&data);
        if (elem != CBOR_ARRAY) return -1;
        size_t arr_size = cbor_get_element_size(&data);
        if (arr_size != 2) return -1;
        ok += cbor_get_number(&data, &mm);
        if (ok != 0) return -1;
        if (mm != COSE_ALGORITHM_SHA_256_64) return -1;
        elem = cbor_get_next_element(&data);
        if (elem != CBOR_BYTE_STRING) return -1;
        size_t hash_len = cbor_get_element_size(&data);
        if (COSE_ALGORITHM_SHA_256_64_LEN != hash_len) return -1;
        data = data + hash_len;  /*skip cbor byte string */
    } else if (mm == COSE_x5chain){ /* ID_CRED_x contains certificate */
        elem = cbor_get_next_element(&data);
        if (elem != CBOR_BYTE_STRING) return -1;
        size_t cert_size = cbor_get_element_size(&data);
        data = data + cert_size;
    } else {
      coap_log(LOG_ERR,"ID_CRED has unsupported tag %d \n", (int)mm);
      return -1;
    }
    *ID_CRED_X_len = data - CIPHERTEXT_Y;
    *ID_CRED_X = coap_malloc(*ID_CRED_X_len);
    memcpy(*ID_CRED_X, CIPHERTEXT_Y, *ID_CRED_X_len);
    ok += cbor_get_string_array(&data, signature, signature_len);
    if (ok != 0)return -1;
    return 0;
}

/* edhoc_check_CIPHER3
 * decrypts CIPHER3 text from input TH_3 and prk_x into P_3ae
 * invokes decrypt algorithm specified in ciphersuit
 * OK: returns 0
 * NOK: returns 1
 */
static int16_t
edhoc_check_CIPHER3(uint8_t *P_3ae, uint8_t *CIPHER3, size_t CIPHER3_LEN, uint8_t *TH_3, uint8_t *prk_x){
  uint8_t *A_3ae  = NULL;
  uint8_t *K_3ae  = NULL;
  uint8_t *IV_3ae = NULL;
  char     iv_3ae[] = "IV_3ae";
  char     k_3ae[]  = "K_3ae";
  int16_t alg = current_cipher_suite->aead;
  size_t nonce_len = cose_nonce_len(alg);
  size_t key_len   = cose_key_len(alg);
  size_t A_3ae_len = edhoc_A_3ae(&A_3ae, TH_3);
    edhoc_create_key( &K_3ae, key_len, k_3ae, sizeof(k_3ae) - 1,
                      TH_3, prk_x); 
    edhoc_create_key( &IV_3ae, nonce_len, iv_3ae, sizeof(iv_3ae) -1,
                      TH_3, prk_x);                    
    int16_t ret = oscore_mbedtls_decrypt_aes_ccm(alg, K_3ae, key_len, IV_3ae, nonce_len,
        A_3ae, A_3ae_len, CIPHER3, CIPHER3_LEN, P_3ae); 
  if (ret == -5)coap_log(LOG_ERR,"unsupported parameter types for decryption \n");
  coap_free(A_3ae);
  coap_free(K_3ae);
  coap_free(IV_3ae);
  if (ret < 0) return 1;
  return 0;
}
    
    
/* edhoc_gen_CIPHER3
 * generates CIPHER3 text from input "in" and prk_x
 * invokes encrypt algorithm specified in ciphersuit
 * OK: returns 0
 * NOK: returns 1
 */
static int16_t
edhoc_gen_CIPHER3(uint8_t *TH_3, uint8_t *prk_x, uint8_t *CIPHER_3, uint8_t *in, size_t in_len){
    uint8_t *K_3ae = NULL;
    uint8_t *A_3ae = NULL;
    uint8_t *IV_3ae = NULL;
    char     k_3ae[] = "K_3ae";
    char     iv_3ae[] = "IV_3ae";
    int16_t alg = current_cipher_suite->aead;
    size_t  key_len   = cose_key_len( alg);
    size_t  nonce_len = cose_nonce_len (alg);
    size_t   A_3ae_len = edhoc_A_3ae(&A_3ae, TH_3); 
    edhoc_create_key( &K_3ae, key_len, k_3ae, sizeof(k_3ae) - 1,
                      TH_3, prk_x);  
    edhoc_create_key( &IV_3ae, nonce_len, iv_3ae, sizeof(iv_3ae) -1,
                      TH_3, prk_x);  
    /* aes calculates ciphertext, stored into CIPHER_3, from in */
    size_t ret = oscore_mbedtls_encrypt_aes_ccm(alg, K_3ae, key_len, IV_3ae, nonce_len,
               A_3ae, A_3ae_len, in, in_len, CIPHER_3);
    if (ret == -5)coap_log(LOG_ERR,"unsupported parameter types for encryption \n");           
    coap_free(A_3ae);
    coap_free(K_3ae);
    coap_free(IV_3ae);
    if (ret < 0) return 1;
    return 0;
}

/* edhoc_gen_MAC_3
 * IR specifies "I" Initiator or "R" Responder
 * generates MAC_3 from TH_3 and prk_x
 * creates internally CRED_I and ID_CRED_I
 * invokes encrypt algorithm specified in ciphersuite
 * OK : returns 0
 * NOK : returns 1
 */
static int
edhoc_gen_MAC_3(char IR, uint8_t *TH_3, uint8_t *prk_x, uint8_t *MAC_3){
    uint8_t *ID_CRED_I = NULL;
    size_t  ID_CRED_I_len = 0;
    uint8_t *CRED_I = NULL;
    size_t  CRED_I_len = 0;
    uint8_t *A_3m = NULL;
    uint8_t *K_3m = NULL;
    uint8_t *IV_3m = NULL;
    char    k_3m[] = "K_3m";
    char    iv_3m[] = "IV_3m";
    int16_t alg = current_cipher_suite->aead;
    size_t  nonce_len = cose_nonce_len(alg);
    size_t  key_len   = cose_key_len(alg);
    int16_t hash_alg = current_cipher_suite->hash;
    size_t  hash_len = cose_hash_len (hash_alg);   
    int16_t ret = edhoc_ID_CRED(IR,
                  &ID_CRED_I, &ID_CRED_I_len, &CRED_I, &CRED_I_len);
    if (ret != 0) return 1;
    size_t A_3m_len = edhoc_A_xm(&A_3m, ID_CRED_I, ID_CRED_I_len, TH_3, hash_len,
                                                        CRED_I, CRED_I_len); 
    edhoc_create_key( &IV_3m, nonce_len, iv_3m, sizeof(iv_3m) - 1,
                      TH_3, prk_x);  
    edhoc_create_key( &K_3m, key_len, k_3m, sizeof(k_3m) - 1,
                      TH_3, prk_x);                                                                        
      /* COSE_Algorithm_AES_CCM calculates the tag, stored into MAC_3, returned with an empty plaintext */
    ret = oscore_mbedtls_encrypt_aes_ccm(alg, K_3m, key_len, IV_3m, nonce_len,
          A_3m, A_3m_len, NULL, 0, MAC_3);
    if (ret == -5)coap_log(LOG_ERR,"illegal parameter values for oscore_mbedtls_encrypt_aes_ccm\n");
    coap_free(CRED_I);
    coap_free(ID_CRED_I);
    coap_free(A_3m);
    coap_free(IV_3m);
    coap_free(K_3m); 
    if (ret < 0)return 1; 
    return 0;  
}

/* edhoc_gen_MAC_4
 * IR specifies "I" Initiator "R" Responder
 * generates MAC_4 from TH_4 and prk_x
 * creates empty additional data
 * invokes encrypt algorithm specified in ciphersuite
 * OK returns 0
 * NOK returns 1
 */
static int
edhoc_gen_MAC_4( uint8_t *TH_4, uint8_t *prk_x, uint8_t *MAC_4){
    int16_t alg = current_cipher_suite->aead;
    size_t  nonce_len = cose_nonce_len(alg);
    size_t  key_len   = cose_key_len(alg);
    int16_t hash_alg = current_cipher_suite->hash;
    size_t  hash_len = cose_hash_len (hash_alg); 
    char    k_m4[]   = "EDHOC_message_4_Key";
    char    iv_m4[]  = "EDHOC_message_4_Nonce";
    uint8_t *IV_m4   = NULL;
    uint8_t *K_m4    = NULL;
    uint8_t *A_4m    = NULL;
    int     ok = 0;
    uint8_t empty[4];   /* to store empty cbor string h'' */
    uint8_t *pt = empty;
    size_t  empty_len = cbor_put_bytes(&pt, NULL, 0);
    size_t  A_4m_len = edhoc_A_xm(&A_4m, empty, empty_len, TH_4, hash_len,
                                                        NULL, 0);   
    edhoc_create_key( &IV_m4, nonce_len, iv_m4, sizeof(iv_m4) - 1,
                      TH_4, prk_x);                                                         
    edhoc_create_key( &K_m4, key_len, k_m4, sizeof(k_m4) -1,
                      TH_4, prk_x);          
  /* COSE_Algorithm_AES_CCM calculates, with an empty plaintext, the tag, stored into MAC_2, */
    int ret = oscore_mbedtls_encrypt_aes_ccm(alg, K_m4, key_len, IV_m4, nonce_len,
        A_4m, A_4m_len, NULL, 0, MAC_4);
    if (ret == -5)coap_log(LOG_ERR,"illegal parameter values for oscore_mbedtls_encrypt_aes_ccm\n"); 
    else if (ret < 0) coap_log(LOG_ERR,"MAC_4 cannot be calculated\n");
    coap_free(IV_m4);
    coap_free(K_m4);
    coap_free(A_4m);
    if (ret < 0)ok = 1;
    return ok;
}

/* edhoc_gen_MAC_2
 * IR specifies "I" Initiator "R" Responder
 * generates MAC_2 from TH_2 and prk_x
 * creates internally CRED_R and ID_CRED_R
 * invokes encrypt algorithm specified in ciphersuite
 * OK returns 0
 * NOK returns 1
 */
static int 
edhoc_gen_MAC_2(char IR, uint8_t *TH_2, uint8_t *prk_x, uint8_t *MAC_2){
    uint8_t *ID_CRED_R = NULL;
    size_t  ID_CRED_R_len = 0;
    uint8_t *CRED_R = NULL;
    size_t  CRED_R_len = 0;
    uint8_t *A_2m = NULL;
    uint8_t *K_2m = NULL;
    uint8_t *IV_2m = NULL;
    char    k_2m[] = "K_2m";
    char    iv_2m[] = "IV_2m";
    int16_t alg = current_cipher_suite->aead;
    size_t  nonce_len = cose_nonce_len(alg);
    size_t  key_len   = cose_key_len(alg);
    int16_t hash_alg = current_cipher_suite->hash;
    size_t  hash_len = cose_hash_len (hash_alg);  
    int16_t ret = edhoc_ID_CRED(IR,
                  &ID_CRED_R, &ID_CRED_R_len, &CRED_R, &CRED_R_len);
    if (ret != 0) return ret;
    size_t A_2m_len = edhoc_A_xm(&A_2m, ID_CRED_R, ID_CRED_R_len, TH_2, hash_len,
                                                        CRED_R, CRED_R_len);
    edhoc_create_key( &IV_2m, nonce_len, iv_2m, sizeof(iv_2m) - 1,
                      TH_2, prk_x);                                                         
    edhoc_create_key( &K_2m, key_len, k_2m, sizeof(k_2m) -1,
                      TH_2, prk_x);          
  /* COSE_Algorithm_AES_CCM calculates, with an empty plaintext, the tag, stored into MAC_2, */
    ret = oscore_mbedtls_encrypt_aes_ccm(alg, K_2m, key_len, IV_2m, nonce_len,
        A_2m, A_2m_len, NULL, 0, MAC_2);
    if (ret == -5)coap_log(LOG_ERR,"illegal parameter values for oscore_mbedtls_encrypt_aes_ccm\n");
    coap_free(CRED_R);
    coap_free(ID_CRED_R);
    coap_free(A_2m);
    coap_free(IV_2m);
    coap_free(K_2m);
    if (ret < 0)return 1;
    return 0;
}


/* edhoc-fill
 * sereve space all attributes of edhoc_ctx
 */
static void
edhoc_fill(edhoc_context_t  *edhoc_ctx){
   edhoc_ctx->ctr_drbg = coap_malloc(sizeof(mbedtls_ctr_drbg_context));
   edhoc_ctx->grp      = coap_malloc(sizeof(mbedtls_ecp_group));
   edhoc_ctx->pub      = coap_malloc(sizeof(mbedtls_ecp_point));
   edhoc_ctx->priv     = coap_malloc(sizeof(mbedtls_mpi));
   edhoc_ctx->shar     = coap_malloc(sizeof(mbedtls_mpi));
   edhoc_ctx->entropy  = coap_malloc(sizeof(mbedtls_entropy_context));  
   memset(edhoc_ctx->ctr_drbg, 0, sizeof(mbedtls_ctr_drbg_context));
   memset(edhoc_ctx->grp, 0, sizeof(mbedtls_ecp_group));
   memset(edhoc_ctx->pub, 0, sizeof(mbedtls_ecp_point));
   memset(edhoc_ctx->priv, 0, sizeof(mbedtls_mpi));
   memset(edhoc_ctx->shar, 0, sizeof(mbedtls_mpi));
   memset(edhoc_ctx->entropy, 0, sizeof(mbedtls_entropy_context));
 }
 
/* edhoc_empty
 * frees all attributes of edhoc_ctx
 */
static void
edhoc_empty(edhoc_context_t  *edhoc_ctx){
   coap_free(edhoc_ctx->ctr_drbg);
   coap_free(edhoc_ctx->grp);
   coap_free(edhoc_ctx->pub);
   coap_free(edhoc_ctx->priv);
   coap_free(edhoc_ctx->shar);
   coap_free(edhoc_ctx->entropy);  
   coap_free(edhoc_ctx);
 } 

/* edhoc_ecdh_prk
 * returns ecdh_ctx initialized private and public keys
 * on error returns NULL;
 */
static edhoc_context_t  *
edhoc_ecdh_prk(uint8_t *priv, uint8_t *pub){
  edhoc_context_t  *edhoc_ctx = coap_malloc(sizeof(edhoc_context_t));
  edhoc_fill(edhoc_ctx);
  edhoc_init(edhoc_ctx);
  const unsigned char pers [] ="ecdh";
  char err_buf[CRT_BUF_SIZE];    
  memset( err_buf, 0, sizeof( err_buf ) );	
  int    ret = 0;  /* mbedtls error return  */  
  ret = mbedtls_ctr_drbg_seed(edhoc_ctx->ctr_drbg, mbedtls_entropy_func, edhoc_ctx->entropy,
                                            pers, sizeof(pers));
  if( ret != 0 )
    {
        mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
        coap_log(LOG_ERR,  " failed\n  !  mbedtls_ctr_debug_seed "
                        "returned -x%02x - %s\n\n", (unsigned int) -ret, err_buf );
        goto exit;
    }
  mbedtls_ecp_group_id  mbedtls_groupid = cose_group_id(current_cipher_suite->ecdh_curve);
  if (mbedtls_groupid == MBEDTLS_ECP_DP_NONE){
    coap_log(LOG_ERR,"unsupported ecdh curve \n");
    ret = -2;
    goto exit;
  }
  ret = mbedtls_ecp_group_load(edhoc_ctx->grp, mbedtls_groupid);
  if( ret != 0 )
    {
        mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
        coap_log(LOG_ERR,  " failed\n  !  mbedtls_ecp_group_load "
                        "returned -x%02x - %s\n\n", (unsigned int) -ret, err_buf );
        goto exit;
    }
    ret = mbedtls_mpi_read_binary(edhoc_ctx->priv, priv, COSE_ALGORITHM_ECDH_PUB_KEY_LEN);
    if( ret != 0 )
    {
        mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
        coap_log(LOG_ERR,  " failed\n  !  mbedtls__mpi_read_binary "
                        "returned -x%02x - %s\n\n", (unsigned int) -ret, err_buf );
        goto exit;
    } 
    ret = mbedtls_mpi_read_binary(&edhoc_ctx->pub->X, pub, COSE_ALGORITHM_ECDH_PUB_KEY_LEN);
    if( ret != 0 )
    {
        mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
        coap_log(LOG_ERR,  " failed\n  !  mbedtls__mpi_write_binary "
                        "returned -x%02x - %s\n\n", (unsigned int) -ret, err_buf );
        goto exit;
    }   
exit:
   if (ret == 0)  return edhoc_ctx;
   edhoc_free(edhoc_ctx);
   edhoc_empty(edhoc_ctx);
   return  NULL;
}


/* edhoc_ecdh_gen
 * returns ecdh_ctx initialized with generated public/private keys 
 * on error returns NULL;
 */
static edhoc_context_t  *
edhoc_ecdh_gen(edhoc_context_t  *edhoc_ctx){
  edhoc_init(edhoc_ctx);
  mbedtls_ctr_drbg_context *ctr_drbg = edhoc_ctx->ctr_drbg;	
  mbedtls_entropy_context  *entropy = edhoc_ctx->entropy;
  char err_buf[CRT_BUF_SIZE];    
  memset( err_buf, 0, sizeof( err_buf ) );	
  const unsigned char pers [] ="ecdh";
  int    ret = 0;  /* mbedtls error return  */  
  mbedtls_ecp_group_id  mbedtls_groupid = cose_group_id(current_cipher_suite->ecdh_curve);
  if (mbedtls_groupid == MBEDTLS_ECP_DP_NONE){
    coap_log(LOG_ERR,"unsupported ecdh curve \n");
    ret = -2;
    goto exit;
  }
  ret = mbedtls_ctr_drbg_seed(ctr_drbg, mbedtls_entropy_func, entropy,
                                            pers, sizeof(pers));
  if( ret != 0 )
    {
        mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
        coap_log(LOG_ERR,  " failed\n  !  mbedtls_ctr_debug_seed "
                        "returned -x%02x - %s\n\n", (unsigned int) -ret, err_buf );
        goto exit;
    }                                           
  ret = mbedtls_ecp_group_load(edhoc_ctx->grp, mbedtls_groupid);
  if( ret != 0 )
    {
        mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
        coap_log(LOG_ERR,  " failed\n  !  mbedtls_ecp_group_load "
                        "returned -x%02x - %s\n\n", (unsigned int) -ret, err_buf );
        goto exit;
    }
    
  ret = mbedtls_ecdh_gen_public(edhoc_ctx->grp, edhoc_ctx->priv, edhoc_ctx->pub,
                                   mbedtls_ctr_drbg_random, ctr_drbg);
  if( ret != 0 )
    {
        mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
        coap_log(LOG_ERR,  " failed\n  !  mbedtls_ecdh_gen_public "
                        "returned -x%02x - %s\n\n", (unsigned int) -ret, err_buf );
        goto exit;
    } 
exit:
   if (ret == 0)  return edhoc_ctx;
   edhoc_free(edhoc_ctx);
   return  NULL;
}

/* edhoc_cli_pub_key
 * initiates ecdh_cli_ctx
 * returns ecdh_cli_ctx 
 * on error: returns NULL
 */
static edhoc_context_t * 
edhoc_cli_pub_key(void){
  return edhoc_ecdh_gen(&edhoc_cli_ctx);
}
 
 /* edhoc_srv_pub_key
 * initiates ecdh_cli_ctx
 * returns ecdh_srv_ctx 
 * on error returns NULL
 */
static edhoc_context_t * 
edhoc_srv_pub_key(void){
  return edhoc_ecdh_gen(&edhoc_srv_ctx);
}

/* edhoc_public_key
 * returns public key stored in mbed_ctx
 * Pub is assumed to point to COSE_ALGORITHM_ECDH_PUB_KEY_LEN (32) bytes
 * 0: OK return
 * else: NOK
 */
int
edhoc_public_key(mbedtls_pk_context *mbed_ctx, uint8_t *Pub){
  char err_buf[CRT_BUF_SIZE];    
  memset( err_buf, 0, sizeof( err_buf ) );	
  int ret = 0; /* error return */   
  mbedtls_ecdsa_context *key_pair = mbed_ctx->pk_ctx;
  ret = mbedtls_mpi_write_binary(&key_pair->Q.X, Pub, COSE_ALGORITHM_ECDH_PUB_KEY_LEN);
  if( ret != 0 )
    {
        mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
        coap_log(LOG_ERR,  " failed\n  !  mbedtls__mpi_write_binary "
                        "returned -x%02x - %s\n\n", (unsigned int) -ret, err_buf );
        goto exit;
    } 
exit:
    return ret;
}

/* edhoc_private_key
 * returns private key stored in mbed_ctx
 * Pub is assumed to point to COSE_ALGORITHM_ECDH_PUB_KEY_LEN (32) bytes
 * 0: OK return
 * else: NOK
 */
int
edhoc_private_key(mbedtls_pk_context *mbed_ctx, uint8_t *Priv){
  char err_buf[CRT_BUF_SIZE];    
  memset( err_buf, 0, sizeof( err_buf ) );	
  int ret = 0; /* error return */   
  mbedtls_ecdsa_context *key_pair = mbed_ctx->pk_ctx; 
  ret = mbedtls_mpi_write_binary(&key_pair->d, Priv, COSE_ALGORITHM_ECDH_PUB_KEY_LEN);
  if( ret != 0 )
    {
        mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
        coap_log(LOG_ERR,  " failed\n  !  mbedtls__mpi_write_binary "
                        "returned -x%02x - %s\n\n", (unsigned int) -ret, err_buf );
        goto exit;
    } 
exit:
    return ret;
}
 
/* edhoc_ecdh_priv_key
 * returns private ephemeral key stored in ecdh_ctx
 * P is assumed to point to COSE_ALGORITHM_ECDH_PUB_KEY_LEN (32) bytes
 * 0: OK return
 * else: NOK
 */
int
edhoc_ecdh_priv_key(edhoc_context_t *edhoc_ctx, uint8_t *P){
  char err_buf[CRT_BUF_SIZE];    
  memset( err_buf, 0, sizeof( err_buf ) );	
  int ret = 0; /* error return */   
    
  ret = mbedtls_mpi_write_binary(edhoc_ctx->priv, P, COSE_ALGORITHM_ECDH_PUB_KEY_LEN);
  if( ret != 0 )
    {
        mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
        coap_log(LOG_ERR,  " failed\n  !  mbedtls__mpi_write_binary "
                        "returned -x%02x - %s\n\n", (unsigned int) -ret, err_buf );
        goto exit;
    } 
exit:
    return ret;
}

/* edhoc_ecdh_pub_key
 * returns public ephemeral key stored in ecdh_ctx
 * G is assumed to point to COSE_ALGORITHM_ECDH_PUB_KEY_LEN (32) bytes
 * 0: OK return
 * else: NOK
 */
int
edhoc_ecdh_pub_key(edhoc_context_t *edhoc_ctx, uint8_t *G){

  char err_buf[CRT_BUF_SIZE];    
  memset( err_buf, 0, sizeof( err_buf ) );	
  int ret = 0; /* error return */   
    
  ret = mbedtls_mpi_write_binary(&edhoc_ctx->pub->X, G, COSE_ALGORITHM_ECDH_PUB_KEY_LEN);
  if( ret != 0 )
    {
        mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
        coap_log(LOG_ERR,  " failed\n  !  mbedtls__mpi_write_binary "
                        "returned -x%02x - %s\n\n", (unsigned int) -ret, err_buf );
        goto exit;
    } 
exit:
    return ret;
}

/* edhoc_create_shared_secret
 * on entry G_cs contains ephemeral key of client/server
 * ehoc_ctx contains accompanying mbedtls contexts
 * on exit G_S contains shared secret
 * mbedtls contexts are liberated
 * 0: OK return
 * else: NOK
 */
int
edhoc_create_shared_secret(edhoc_context_t *edhoc_ctx, uint8_t *G_cs, uint8_t *G_S){
  size_t G_S_len = 0;
  mbedtls_ctr_drbg_context *ctr_drbg = edhoc_ctx->ctr_drbg;	
  char err_buf[CRT_BUF_SIZE];    
  memset( err_buf, 0, sizeof( err_buf ) );	
  int    ret = 0;  /* mbedtls error return  */  
  /* read G_cs  */
    ret = mbedtls_mpi_read_binary(&edhoc_ctx->pub->X, G_cs, COSE_ALGORITHM_ECDH_PUB_KEY_LEN);
    if( ret != 0 )
    {
        mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
        coap_log(LOG_ERR,  " failed\n  !  mbedtls__mpi_read_binary "
                        "returned -x%02x - %s\n\n", (unsigned int) -ret, err_buf );
        goto exit;
    } 
    mbedtls_ecp_group_id  mbedtls_groupid = cose_group_id(current_cipher_suite->ecdh_curve);
    if (mbedtls_groupid == MBEDTLS_ECP_DP_SECP256R1){
      uint8_t G_y[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];
      struct bn X, Y1, Y2;
      bignum_init(&Y1);
      bignum_init(&Y2);
      bignum_init(&X);
      bignum_from_array(&X, G_cs, COSE_ALGORITHM_ECDH_PUB_KEY_LEN);
      /* calculate Y component from X component*/
      uncompress(&X, &Y1, &Y2);
      bignum_to_array(&Y1, G_y, COSE_ALGORITHM_ECDH_PUB_KEY_LEN);
      ret = mbedtls_mpi_read_binary(&edhoc_ctx->pub->Y, G_y, COSE_ALGORITHM_ECDH_PUB_KEY_LEN);
      if( ret != 0 )
      {
          mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
          coap_log(LOG_ERR,  " failed\n  !  mbedtls__mpi_read_binary "
                        "returned -x%02x - %s\n\n", (unsigned int) -ret, err_buf );
          goto exit;
      } 
    }
    ret = mbedtls_mpi_lset(&edhoc_ctx->pub->Z, 1);
    if( ret != 0 )
      {
        mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
        coap_log(LOG_ERR,  " failed\n  !  mbedtls_mpi_lset "
                        "returned -x%02x - %s\n\n", (unsigned int) -ret, err_buf );
        goto exit;
      } 
/* compute shared secret  */
    ret = mbedtls_ecdh_compute_shared( edhoc_ctx->grp, edhoc_ctx->shar, edhoc_ctx->pub, 
                                        edhoc_ctx->priv, mbedtls_ctr_drbg_random, ctr_drbg);
    if( ret != 0 )
    {
        mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
        coap_log(LOG_ERR,  " failed\n  !  mbedtls_ecdh_compute_shared "
                        "returned -x%02x - %s\n\n", (unsigned int) -ret, err_buf );
        goto exit;
    } 
/* edhoc_ctx->shar contains shared key  goes to G_XY */
    G_S_len = mbedtls_mpi_size(edhoc_ctx->shar);
    if (G_S_len > COSE_ALGORITHM_ECDH_PUB_KEY_LEN){
      coap_log(LOG_ERR,"shared key larger than COSE_ALGORITHM_ECDH_PUB_KEY_LEN bytes \n");
      ret = -1;
      goto exit;
    }
    ret = mbedtls_mpi_write_binary(edhoc_ctx->shar, G_S, G_S_len);
    if( ret != 0 )
    {
        mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
        coap_log(LOG_ERR,  " failed\n  !  mbedtls_mpi_write_binary"
                        "returned -x%02x - %s\n\n", (unsigned int) -ret, err_buf );
        goto exit;
    } 
exit:
    return ret;   
}

/* edhoc_prk_shared_secret
 * creates shared secret form private key X and public key G_X
 * shared contains shared secret
 * 0 means Ok
 * !=0 means error
 */
static int16_t
edhoc_prk_shared_secret(uint8_t *G_R, uint8_t *X, uint8_t *shared){
  edhoc_context_t *edhoc_ctx = edhoc_ecdh_prk(X, G_R);
  int ret = edhoc_create_shared_secret(edhoc_ctx, G_R, shared);
  return ret;
}

/* edhoc_credentials
 * returns 0 when ID_CRED is a reference to a certificate or the certificate itself
 * the certificate is the certificate of the communication partner specified in IR (I, R)
 * certificate is written to file
 */
static int16_t
edhoc_credentials(char IR, uint8_t *ID_CRED, size_t ID_CRED_len){
    char *file_name = NULL;
    char name_R[] = X509_receiver;
    char name_I[] = X509_initiator;    
    int8_t ok = 0;
    uint8_t  *data = ID_CRED;
    int64_t mm = 0;
    int8_t  elem = cbor_get_next_element(&data);
    if (elem != CBOR_MAP) return -1;
    size_t map_size = cbor_get_element_size(&data);
    if (map_size != 1) return -1;
    ok = cbor_get_number(&data, &mm);
    if (ok != 0)return -1;
    /* possible values, COSE_x5t and COSE_x5chain */
    if (mm == COSE_x5t){  /* ID_CRED_X contains Certificate hash */
      coap_log(LOG_ERR, "ID_CRED: corresponding certificate or key could not be identified\n");
      return -1;
    }
    else if (mm == COSE_x5chain){
       elem = cbor_get_next_element(&data);
       if (elem != CBOR_BYTE_STRING) return -1;
       size_t cert_size = cbor_get_element_size(&data);
       coap_string_t der = { .length = cert_size, .s = data};
       /* data points to der of received certificate  */
       if (edhoc_function == 'I'){
         file_name = name_R;
       }else if (edhoc_function == 'R'){
         file_name = name_I;
       } else return -1;
       ok =  write_file_mem(file_name, &der);
       if (ok != 0) return -1;
    }
    else return -1;
    return 0;
}

/* edhoc_edDSA_CERT 
 * on exit DER contains the DER certificate with public key 
 * certificate is transported certificate
 * returns error -1 when parameter values are not supported
 * returns 0 when OK
 */
static int16_t
edhoc_edDSA_CERT( char IR, uint8_t **DER, size_t *DER_len){
    int16_t alg = current_cipher_suite->sign_alg;
    if (alg == COSE_ALGORITHM_ES256){
      coap_log(LOG_ERR,"ES256 certificates should use edhoc_ES256_CERT\n");
      return -1;
    } else if (alg != COSE_Algorithm_EdDSA){
      coap_log(LOG_ERR,"Not supported algorithm\n");
      return -1;
    }
    if (current_cipher_suite->cert.s == NULL){
      coap_log(LOG_ERR, "edDSA certificate is not defined in edhoc suite \n");
      return -1;
    }
    *DER = read_file_mem((char *)current_cipher_suite->cert.s, DER_len);
    if ((DER == NULL) || (DER_len == 0)) return -1;
    return 0;
}

/* edhoc_ES256_CERT 
 * on exit mbed_ctx contains the certificate with public key 
 * certificate is transported certificate
 * returns error -1 when parameter values are not supported
 * returns 0 when OK
 */

static int16_t
edhoc_ES256_CERT(char IR, mbedtls_x509_crt *crt){

    char c_file_R_ES[] = X509_receiver;   
    char c_file_I_ES[] = X509_initiator;  
    char *cert_file    = NULL;              
    int16_t alg = current_cipher_suite->sign_alg; 
    if (alg == COSE_Algorithm_EdDSA){
      coap_log(LOG_ERR,"ED25519 certificates cannot be parsed with mbedtls \n");
      return -1;
    } else if (alg == COSE_ALGORITHM_ES256){
      if (edhoc_function == 'I')cert_file = c_file_R_ES;
      if (edhoc_function == 'R')cert_file = c_file_I_ES;     
    }
    char err_buf[CRT_BUF_SIZE];    
    memset( err_buf, 0, sizeof( err_buf ) );	
    int    ret = 0;  /* mbedtls error return  */       
     /* find public key by parsing certificate  */  
    ret = mbedtls_x509_crt_parse_file( crt, cert_file );
    if( ret != 0 )
    {
        mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
        coap_log(LOG_ERR,  " failed\n  !  mbedtls_x509_crt_parse_file %s"
                        "returned -x%02x - %s\n\n", cert_file, (unsigned int) -ret, err_buf );
    }
    return ret; 
}

/* edhoc_ES256_KEY 
 * on exit mbed_ctx contains the public key and private key 
 * returns error -1 when parameter values are not supported
 * returns 0 when OK
 */
static int16_t
edhoc_ES256_KEY( mbedtls_pk_context *mbed_ctx){ 
    int16_t alg = current_cipher_suite->sign_alg;
    if (alg == COSE_Algorithm_EdDSA){
      coap_log(LOG_ERR, "mbedtls cannot parse ED25519 key file \n");
      return -1;
    } else if (alg != COSE_ALGORITHM_ES256){
      coap_log(LOG_ERR, "unsupported algorithm\n");
      return -1;
    }
    char err_buf[CRT_BUF_SIZE];    
    memset( err_buf, 0, sizeof( err_buf ) );	
    int    ret = 0;  /* mbedtls error return  */       
    char  pledge_pwd[]      = PLEDGE_PWD;    
     /* find public key and private key from key file */  
    if(current_cipher_suite->key.s == NULL){
      coap_log(LOG_ERR, "key-file is not defined in edhoc suite \n");
      return 2;
    }
    ret = mbedtls_pk_parse_keyfile( mbed_ctx, (char *)current_cipher_suite->key.s, pledge_pwd );
    if( ret != 0 )
    {
        mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
        coap_log(LOG_ERR,  " failed\n  !  mbedtls_pk_parse_keyfile %s  "
                        "returned -x%02x - %s\n\n", (char *)current_cipher_suite->key.s, (unsigned int) -ret, err_buf );
    }
    return ret; 
}

/* edhoc_EdDSA_privkey
 * returns EdDSA (ED25519) private key in priv_key
 * returns 0 when OK
 * not 0 when error
 */
static int16_t
edhoc_EdDSA_privkey( uint8_t **priv_key){

   uint8_t  *KEY_F    = NULL;
   size_t   KEY_F_len    = 0;
   mbedtls_pk_context  mbed_ctx;
   mbedtls_pk_init(&mbed_ctx); 
   /* preparation of edDSA priv_key */
     edhoc_edDSA_KEY( &KEY_F, &KEY_F_len);
     uint8_t  *p = KEY_F; 
     size_t seed_size = 0;
     *priv_key = edhoc_parse_oid(&p, KEY_F + KEY_F_len, &seed_size); 
     seed_size = seed_size -2;
     *priv_key = *priv_key + 2;
   return 0;
}

/* edhoc_ES256_privkey
 * returns ES256 private key in mbed-ctx
 * returns 0 when OK
 * not 0 when error
 */
static int16_t
edhoc_ES256_privkey(mbedtls_pk_context *mbed_ctx){
   int16_t ret = 0;     
   /* preparation of ecp private key */  
       ret = edhoc_ES256_KEY( mbed_ctx);  
       if (ret != 0) {
           return -2;
       }  
   return 0;
}

/* edhoc_EdDSA_pubkey
 * returns EdDSA (ED25519) public key in pub_key
 * returns 0 when OK
 * not 0 when error
 */
static int16_t
edhoc_EdDSA_pubkey(char IR, uint8_t **pub_key){
  int16_t ret = 0;
  uint8_t  *DER    = NULL;
  size_t   DER_len = 0;
  size_t   key_size = 0;
  /* preparation of edDSA pub_key */
    ret = edhoc_edDSA_CERT( IR, &DER, &DER_len);
    if ((DER == NULL) || (ret != 0)){
      coap_log(LOG_ERR, "public key certificate is not present \n");
      return -2;
    }
    uint8_t  *buf = DER; /*used for pointer progress */
    *pub_key = edhoc_parse_oid(&buf, buf + DER_len, &key_size);
    if ((key_size == 0) || (pub_key == NULL)){
      coap_log(LOG_ERR," could not find edDSA public key \n");
      return -2;
    }
  return 0;
}

/* edhoc_ES256_pubkey
 * returns ES256 public key in mbed-ctx
 * returns 0 when OK
 * not 0 when error
 */
static int16_t
edhoc_ES256_pubkey(char IR, mbedtls_pk_context *mbed_ctx){
  int16_t ok = 0;
  int16_t ret = 0;
  mbedtls_x509_crt   crt;
  mbedtls_x509_crt_init(&crt);
  mbedtls_ecdsa_context *key_pair = coap_malloc(sizeof(mbedtls_ecdsa_context));
  mbedtls_pk_setup(mbed_ctx, mbedtls_pk_info_from_type(MBEDTLS_PK_ECDSA));
  mbedtls_ecdsa_init(key_pair);
  /* preparation of ecp pub key */
    ret = edhoc_ES256_CERT( IR, &crt);
    if (ret != 0){
      ok = -4;
      goto exit;
    }
    mbedtls_ecdsa_from_keypair( key_pair, crt.pk.pk_ctx);
    mbed_ctx->pk_ctx = key_pair; 
exit:
   mbedtls_x509_crt_free(&crt);
   return ok;
}

/* edhoc_create_prk_3x3m
 *  returns prk_4x3m based on prk_3e2m
 */
static int
edhoc_create_prk_4x3m(uint8_t *prk_4x3m, uint8_t *prk_3e2m){
   uint8_t XY[COSE_ALGORITHM_ECDH_PRIV_KEY_LEN];
   uint8_t RI[COSE_ALGORITHM_ECDH_PRIV_KEY_LEN];
   uint8_t G_RI[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];
   uint8_t G_XY[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];
   uint8_t *pub = NULL;
   uint8_t *priv = NULL;
   uint8_t shared[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];
   int16_t alg = current_cipher_suite->sign_alg;
   mbedtls_pk_context  mbed_ctx;
   mbedtls_pk_init(&mbed_ctx); 

  if ((edhoc_method == 2) || (edhoc_method == 3)){
    if (edhoc_function == 'R'){   /* responder : G_I -> G_RI; Y -> XY */
      edhoc_context_t *ctx = &edhoc_srv_ctx;
      int ret = edhoc_ecdh_priv_key(ctx, XY);             /* Y -> XY */
      if (ret != 0) return ret;
      switch (alg){ 
      case COSE_Algorithm_EdDSA:  
        ret = edhoc_EdDSA_pubkey( 'I', &pub);            /* G_I -> G_RI */
        if (ret != 0) return ret;
        break;
      case COSE_ALGORITHM_ES256:  
        ret = edhoc_ES256_pubkey( 'I', &mbed_ctx);
        if (ret != 0) return ret; 
        ret = edhoc_public_key(&mbed_ctx, G_RI);         /* G_I -> G_RI */
        if (ret != 0) return ret;
        pub = G_RI;
        break;
      default:
        coap_log(LOG_ERR,"Unkown Cose algorithm %d \n", alg);
        return 2;
      }
      ret = edhoc_prk_shared_secret(pub, XY, shared);
      if (ret != 0) return ret;
    } else {                      /* initiator : G_Y -> G_XY; I -> RI */
      edhoc_context_t *ctx = &edhoc_cli_ctx;     
      int ret = edhoc_ecdh_pub_key(ctx, G_XY);          /* G_Y -> G_XY */
      if (ret != 0) return ret;
      switch (alg){ 
      case COSE_Algorithm_EdDSA:  
        ret = edhoc_EdDSA_privkey( &priv);                /* I -> RI */
        if (ret != 0) return ret;
        break;
      case COSE_ALGORITHM_ES256:  
        ret = edhoc_ES256_privkey( &mbed_ctx);
        if (ret != 0) return ret;
        ret = edhoc_private_key(&mbed_ctx, RI);           /* I -> RI */
        if (ret != 0) return ret;  
        priv = RI;     
        break;
      default:
        coap_log(LOG_ERR,"Unkown Cose algorithm %d \n", alg);
        return 2;
      }
      ret = edhoc_prk_shared_secret(G_XY, priv, shared);
      if (ret != 0) return ret;      
    }
    hkdf_extract(prk_3e2m, COSE_ALGORITHM_ECDH_PUB_KEY_LEN, shared, COSE_ALGORITHM_ECDH_PUB_KEY_LEN, prk_4x3m); 
  } else {
    memcpy(prk_4x3m, prk_3e2m, COSE_ALGORITHM_ECDH_PUB_KEY_LEN);
  }
  return 0;
}

/* edhoc_create_prk_3e2m
 *  returns prk_3e2m pased on prk_2e
 */
static int
edhoc_create_prk_3e2m(uint8_t *prk_3e2m, uint8_t *prk_2e){
   uint8_t XY[COSE_ALGORITHM_ECDH_PRIV_KEY_LEN];
   uint8_t RI[COSE_ALGORITHM_ECDH_PRIV_KEY_LEN];
   uint8_t G_RI[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];
   uint8_t G_XY[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];
   uint8_t shared[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];
   int16_t alg = current_cipher_suite->sign_alg;
   mbedtls_pk_context  mbed_ctx;
   mbedtls_pk_init(&mbed_ctx); 
   uint8_t *priv = NULL;
   uint8_t *pub  = NULL;

  if ((edhoc_method == 1) || (edhoc_method == 3)){
    if (edhoc_function == 'R'){   /* responder : G_X -> G_XY; R -> RI */
      edhoc_context_t *ctx = &edhoc_srv_ctx;
      int ret = edhoc_ecdh_pub_key(ctx, G_XY);        /* G_X -> G_XY */
      if (ret != 0) return ret;
      switch (alg){ 
      case COSE_Algorithm_EdDSA:  
        ret = edhoc_EdDSA_privkey( &priv);              /* R -> RI */
        if (ret != 0) return ret;
        break;
      case COSE_ALGORITHM_ES256:  
        ret = edhoc_ES256_privkey( &mbed_ctx);
        if (ret != 0) return ret; 
        ret = edhoc_private_key(&mbed_ctx, RI);         /* R -> RI */
        if (ret != 0) return ret;
        priv = RI;
        break;
      default:
        coap_log(LOG_ERR,"Unkown Cose algorithm %d \n", alg);
        return 2;
      }
      ret = edhoc_prk_shared_secret(G_XY, priv, shared);
      if (ret != 0) return ret;
    } else {                      /* initiator : G_R -> G_RI; X -> XY */
      edhoc_context_t *ctx = &edhoc_cli_ctx;     
      int ret = edhoc_ecdh_priv_key(ctx, XY);          /* X -> XY */
      if (ret != 0) return ret;
      switch (alg){ 
      case COSE_Algorithm_EdDSA:  
        ret = edhoc_EdDSA_pubkey('R', &pub);           /* G_R -> G_RI */
        if (ret != 0) return ret;
        break;
      case COSE_ALGORITHM_ES256:  
        ret = edhoc_ES256_pubkey('R', &mbed_ctx);
        if (ret != 0) return ret;
        ret = edhoc_public_key(&mbed_ctx, G_RI);       /* G_R -> G_RI */
        if (ret != 0) return ret;  
        pub = G_RI;     
        break;
      default:
        coap_log(LOG_ERR,"Unkown Cose algorithm %d \n", alg);
        return 2;
      }
      ret = edhoc_prk_shared_secret(pub, XY, shared);
      if (ret != 0) return ret;      
    }
    hkdf_extract(prk_2e, COSE_ALGORITHM_ECDH_PUB_KEY_LEN, shared, COSE_ALGORITHM_ECDH_PUB_KEY_LEN, prk_3e2m); 
  } else {
    memcpy(prk_3e2m, prk_2e, COSE_ALGORITHM_ECDH_PUB_KEY_LEN);
  }
  return 0;
}

/* edhoc_verify 
 * IR specifies "I" Initiator "R" Responder
 * verifies signature over payload
 * for ES256 uses mbedtls_context
 * for edDSA uses public key directly.
 * obtains parameter values from current suite
 * Returns ecp error value
 */
static int16_t
edhoc_verify(char IR, uint8_t *signature, size_t signature_len, uint8_t *payload, size_t payload_len){
  int16_t ok = 0;
  int16_t ret = 0;
  uint8_t  *DER    = NULL;
  uint8_t  *pub_key = NULL;   
  mbedtls_x509_crt   crt;
  mbedtls_x509_crt_init(&crt);
  int16_t alg = current_cipher_suite->sign_alg;
  int16_t crv = current_cipher_suite->sign_curve;
  mbedtls_pk_context mbed_ctx;
  mbedtls_pk_init(&mbed_ctx);
   switch (alg){ 
     case COSE_ALGORITHM_ES256:  
       ok = edhoc_ES256_pubkey(IR, &mbed_ctx);
       if (ok != 0){
         coap_log(LOG_ERR,"ES256 public key could not be found \n");
         break;
       }
       ok = oscore_mbedtls_ecp_verify(alg, crv, signature, signature_len, payload, payload_len, &mbed_ctx);
       if (ok == -5){
         coap_log(LOG_ERR,"illegal parameter values for oscore_mbedtls_ecp_verify \n");
         ok = -1; 
       } else if (ok < 0) {
         coap_log(LOG_ERR,"verification failed for oscore_mbedtls_ecp_verify \n");
         ok  = -1;
       }
       break;
     case COSE_Algorithm_EdDSA:
       ok = edhoc_EdDSA_pubkey(IR, &pub_key);
       if (ok != 0){
         coap_log(LOG_ERR,"EdDSA public key could not be found \n");
         break;
       }
       ret = oscore_edDSA_verify(alg, crv, signature, payload, payload_len, pub_key);
       if (ret == -5){
         coap_log(LOG_ERR,"illegal parameter values for oscore_edDSA_verify \n");
         ok = -1; 
       } else if (ret < 0) {
         coap_log(LOG_ERR,"verification failed for oscore_edDSA_verify \n");
         ok = -1; 
       }
       break;
     default:
       coap_log(LOG_ERR," verify algorithm is not supported \n");
       ok = -2;
   }  /* switch */       

  if (DER != NULL)coap_free(DER);
  mbedtls_pk_free(&mbed_ctx);
  mbedtls_x509_crt_free(&crt);
  return ok;
}


/* edhoc_sign 
 * IR specifies "I Initiator "R" responder
 * creates signature over payload
 * for ES256 use mbedtls context
 * for edDSA uses public and private key directly
 * obtains parameter values from current suite
 * signature size is assumed to be large enough
 * Returns ecp error value
 */
static int16_t
edhoc_sign(char IR, uint8_t *signature, size_t *signature_len, uint8_t *payload, size_t payload_len){
   int16_t ok = 0; 
   int16_t ret = 0;     
   int16_t alg = current_cipher_suite->sign_alg;
   int16_t crv = current_cipher_suite->sign_curve;  
   uint8_t *seed = NULL;
   mbedtls_pk_context  mbed_ctx;
   mbedtls_pk_init(&mbed_ctx); 

   switch (alg){ 
     case COSE_ALGORITHM_ES256:
       ok = edhoc_ES256_privkey( &mbed_ctx);
       if (ok != 0){
         coap_log(LOG_ERR,"ES256 private key could not be found \n");
         break;
       }       
       ret = oscore_mbedtls_ecp_sign(alg, crv, signature, signature_len, payload, payload_len, &mbed_ctx);
       if (ret == -5)coap_log(LOG_ERR,"illegal parameter values for oscore_mbedtls_ecp_sign \n");
       if (ret < 0){
             ok = -2;
       }
       break;
     case COSE_Algorithm_EdDSA:
        /* public key is NULL because generated from seed  */
       ok = edhoc_EdDSA_privkey( &seed);
       if (ok != 0){
         coap_log(LOG_ERR,"EdDSA (ED25519) private key could not be found \n");
         break;
       }  
       ret = oscore_edDSA_sign(alg, crv, signature, payload, payload_len, seed, NULL);
       if (ret == -5)coap_log(LOG_ERR,"illegal parameter values for oscore_edDSA_sign\n");
       if (ret < 0){
             ok = -2;
       } 
       *signature_len = Ed25519_SIGNATURE_LEN;
       break;     
     default:
       coap_log(LOG_ERR," sign algorithm is not supported \n");
       ok = -2;
   }  /* switch */

   mbedtls_pk_free(&mbed_ctx);
   return ok;
}


/* edhoc_get_suite
 * gets the prefered suite from buf
 * buf can contain single number or array of numbers
 * returns selected suite
 * OK: returns 0 
 * NOK returns 1
 */
static int8_t
edhoc_get_suite(uint8_t **buf, int8_t *selected_suite){
  int8_t ok = 0;
  int64_t  mm;
  uint8_t  elem = cbor_get_next_element(buf);
  if (elem == CBOR_ARRAY){ 
    uint64_t arr_size = cbor_get_element_size(buf);
    for (uint i=0 ; i < arr_size; i++){
      ok = cbor_get_number(buf, &mm);
      if(ok != 0) return -2;
      if (i == 0) *selected_suite = (int8_t)mm;
    }
  } else if ((elem == CBOR_UNSIGNED_INTEGER) ||
            (elem == CBOR_NEGATIVE_INTEGER)){
     ok = cbor_get_number(buf, &mm); 
     *selected_suite = (int8_t)mm;       
  }
  else return -1;
  return 0;
}

/* edhoc_receive_message_1 
 * on entry data points to message_1 with length size
 * message contents : method_corr, suite, G_x, C_I, [AD_1]
 * returns error -2 when message cannot be parsed
 * returns error -1 when parameter values are not supported
 * returns 0 when OK
 */
static int16_t
edhoc_receive_message_1(coap_string_t *message,
                        uint8_t  **key, size_t *key_len,
                        uint8_t  **C_I, size_t *C_I_len,
                        uint8_t  **add, size_t *add_len){
  uint8_t *buf = message->s;
  /* disassemble message 1 */
  int8_t   ok = 0;
  int64_t  mm;
  int8_t   selected_suite = 0;
  ok = cbor_get_number(&buf, &mm);
  if(ok != 0){
    coap_log(LOG_ERR, "EDHOC message_1 is corrupted\n");
    return -2;
  } /* if ok */
  edhoc_method = (int8_t)mm/4;
  edhoc_corr = (int8_t)mm - edhoc_method *4;
  /* to be replaced with array detector */
  ok = edhoc_get_suite( &buf, &selected_suite);
  if(ok != 0){
    coap_log(LOG_ERR,  "EDHOC message_1 is corrupted\n");
    return -2;
  } /* if ok */
  if ((selected_suite > EDHOC_MAX_SUITE - 1) || (selected_suite < 0)){
    coap_log(LOG_ERR,  "selected suite is not supported\n");
    return -1;
  }
  current_cipher_suite = &supported_cipher_suites[selected_suite];
  if ((current_cipher_suite->cert.s == NULL) || (current_cipher_suite->key.s == NULL)){
    coap_log(LOG_ERR, "certificate or key files are not defined \n");
	  return -1;    
  }
  ok = cbor_get_string_array(&buf, key, key_len);
  if(ok != 0){
    coap_log(LOG_ERR,  "EDHOC message_1 is corrupted\n");
    return -2;
  } /* if ok */ 
  ok = edhoc_cbor_get_C_X(&buf, C_I, C_I_len);
  if(ok != 0){
    coap_log(LOG_ERR,  "EDHOC message_1 is corrupted\n");
    return -2;
  } /* if ok */  
  if (buf - message->s > message->length ){  /* additional data present in message_1  */
    ok = cbor_get_string_array(&buf, add, add_len);
    if(ok != 0){
       coap_log(LOG_ERR,  "EDHOC message_1 is corrupted\n");
       return -2;
    } /* if ok */  
  } /* if buf - data */
  return 0;
}


/* edhoc_cipher2_check
 * on entry buf points to CIPHERTEXT_2
 * CIPHERTEXT is checked 
 * returns error -2 when message cannot be parsed
 * returns error -1 when parameter values are not supported
 * returns 0 when OK
 */
static int16_t
edhoc_cipher2_check(uint8_t *CIPHER, uint8_t *G_Y, uint8_t *G_XY,
      uint8_t *C_X, size_t C_X_len, coap_string_t *message_1){
  char IR = 'R';  /* Responder certificate wanted */
  uint8_t *salt = NULL;
  size_t  salt_len = 0; 
  uint8_t prk_2e[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];
  uint8_t prk_3e2m[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];
  uint8_t TH_2[MAX_HASH_LEN]; 
  uint8_t *CIPHERTEXT_2 = NULL;
  size_t  CIPHERTEXT_LEN = 0;
  uint8_t *data_2 = NULL;
  size_t  data_2_len = 0;
  uint8_t *ID_CRED_R = NULL;
  size_t  ID_CRED_R_len = 0;
  uint8_t MAC_2[MAX_TAG_LEN];  
  uint8_t *M_2 = NULL;
  size_t  M_2_len = 0;
  uint8_t *signature = NULL;
  size_t  signature_len;
  char    keystream[] = "KEYSTREAM_2";  
  char err_buf[CRT_BUF_SIZE];    
  memset( err_buf, 0, sizeof( err_buf ) );	
  int    ret = 0;  /* mbedtls error return  */  
  int    ok = 0; 
  int16_t alg = current_cipher_suite->aead; 
  int16_t hash_alg = current_cipher_suite->hash;
  size_t  hash_len = cose_hash_len (hash_alg);
  hkdf_extract(salt, salt_len, G_XY, COSE_ALGORITHM_ECDH_PUB_KEY_LEN, prk_2e); 
  edhoc_create_prk_3e2m(prk_3e2m,prk_2e); 
  edhoc_data_2(&data_2, &data_2_len, G_Y);
  ok = edhoc_TH_2_gen(TH_2, message_1, data_2, data_2_len);
  if (ok < 0){
     ok = -2;
     goto exit3;
  }
  uint8_t *pt = CIPHER;
  ok = cbor_get_string_array(&pt, &CIPHERTEXT_2, &CIPHERTEXT_LEN); 
  if (ok < 0){
    ok = -2;
    goto exit3;
  }
  if (CIPHERTEXT_2 == NULL)goto exit3;
    uint8_t *K_2e = NULL;
    edhoc_create_key( &K_2e, CIPHERTEXT_LEN, keystream, sizeof(keystream) - 1,
                      TH_2, prk_2e);                                         
    /* construct CIPHERTEXT from CIPHERTEXT xor K_2e */
    for (uint qq = 0; qq < CIPHERTEXT_LEN; qq++) CIPHERTEXT_2[qq] = CIPHERTEXT_2[qq] ^ K_2e[qq];
    coap_free(K_2e);
    ok = edhoc_decompose_CIPHER_Y(CIPHERTEXT_2, &ID_CRED_R, &ID_CRED_R_len, &signature, &signature_len);
    if (ok < 0){
      coap_log(LOG_ERR," CIPHER_TEXT cannot be decoded \n");
      goto exit2;
    }
    ok = edhoc_credentials(IR, ID_CRED_R, ID_CRED_R_len); 
    coap_free(ID_CRED_R);  /* nothing done; should be checked  */ 
    if (ok != 0) goto exit2; 
    ret = edhoc_gen_MAC_2( IR, TH_2, prk_3e2m, MAC_2);
    if (ret != 0){
       ok = -2;
       goto exit2;
     } 
    size_t tag_len = cose_tag_len(alg);
    M_2_len = edhoc_M_x(&M_2, IR, TH_2, hash_len,
                             MAC_2, tag_len);  
    if (M_2_len < 0) {
      ok = -2;
      goto exit2;
    } 
    if ((edhoc_method == 1) || (edhoc_method == 3)){ /* signature_or_MAC_2 is MAC_2 */
      if (tag_len != signature_len){
        /* remember to do DH signature */
        ok = -2;
        goto exit1;
      }
      if (memcmp(MAC_2, signature, tag_len) != 0){
        ok = -2;
        goto exit1;
      }
    }     
    /* check signature over M_2 when signature_or_MAC_2 is signature */
    else ok = edhoc_verify( IR, signature, signature_len, M_2, M_2_len);
    if (ok < 0) ok = -2;
exit1:
    coap_free(M_2);
exit2:
    if(CIPHERTEXT_2 != NULL)coap_free(CIPHERTEXT_2);
    if(signature != NULL)coap_free(signature);
exit3:
    coap_free(data_2);
    return ok;
}

/* edhoc_receive_message_2 
 * on entry message contains message_2 with length size
 * message contents : data_2, CIPHERTEXT
 * data_2_len is calculated
 * returns G_Y and C_X.
 * CIPHERTEXT is checked 
 * address of CIPHERTEXT and data_2 are returned in CIPHER, data-2
 * returns error -2 when message cannot be parsed
 * returns error -1 when parameter values are not supported
 * returns 0 when OK
 */
static int16_t
edhoc_receive_message_2(coap_string_t *message_2, uint8_t **CIPHER,
                      uint8_t *G_Y, uint8_t **C_R, size_t *C_R_len  ){
  uint8_t *buf = message_2->s;
  /* disassemble message 2 */
  int8_t ok = 0;
  size_t   key_len = 0;
  uint8_t  *C_I = NULL;
  size_t   C_I_len = 0;
  *C_R_len = 0;
  if ((edhoc_corr == 0) || (edhoc_corr == 2)){
      ok = edhoc_cbor_get_C_X(&buf, &C_I, &C_I_len);
      if (ok != 0) return -2;
      ok = edhoc_check_C_X('I',C_I, C_I_len);
      if (ok != 0) {
          coap_log(LOG_ERR,"C_I in message_2 does not correspond with stored C_I \n");
          return -2;
      }      
  }

  uint8_t *key = NULL; /* provisional storage of G_Y */
  ok = cbor_get_string_array(&buf, &key, &key_len);
  if(ok != 0){
    coap_log(LOG_ERR,  "EDHOC message_2 is corrupted\n");
    return -2;
  } /* if ok */
  if (key_len != COSE_ALGORITHM_ECDH_PUB_KEY_LEN){
    coap_log(LOG_ERR,  "length of G_Y is incorrect\n");
    if(key != NULL)coap_free(key);
    return -2;    
  }   
  memcpy(G_Y, key, key_len);
  coap_free(key);
  ok = edhoc_cbor_get_C_X(&buf, C_R, C_R_len);
  if (ok != 0)return -2;
  ok = edhoc_enter_C_X('R',*C_R, *C_R_len);
  if (ok != 0)return -1;
  *CIPHER = buf;
  return 0;
}

/* edhoc_find_TH_4
 * on entry message_1, message_2 and CIPHER3;
 * edhoc_G_XY contains public ephemeral ecdh key
 * on return: TH_4, prk_4x3m
 * returns error < 0 when error
 * returns 0 when OK
 */
int16_t
edhoc_find_TH_4(uint8_t *CIPHER3, size_t CIPHER3_len, 
      coap_string_t *message_1, coap_string_t *message_2, uint8_t *TH_4){
  uint8_t TH_3[MAX_HASH_LEN];
  uint8_t TH_2[MAX_HASH_LEN];  
  uint8_t *CIPHER2 = NULL;
  uint8_t G_Y[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];   
  uint8_t *C_R = NULL;
  size_t  C_R_len = 0;  
  int     ok = 0; 
  int     ret = 0; 

    /* recuperate data_2, CIPHER2 and C_X from message 2 */
  uint8_t *data_2 = message_2->s;
  ret = edhoc_receive_message_2(message_2, &CIPHER2, G_Y, &C_R, &C_R_len);
  size_t  data_2_len = (size_t)(CIPHER2 - data_2);
  size_t  CIPHER2_LEN = message_2->length - data_2_len;
  ret = edhoc_TH_2_gen(TH_2, message_1, data_2, data_2_len);
  if (ret != 0){
    ok = -2;
    goto exit;
  }
  uint8_t *data_3 = coap_malloc(C_R_len + 3);
  size_t  data_3_len = 0;
  if ((edhoc_corr == 0) || (edhoc_corr == 1)){
    uint8_t *pt = data_3;
    data_3_len = edhoc_cbor_put_C_X(&pt, C_R, C_R_len);
    assert (data_3_len < C_R_len + 3);
  }
  ret = edhoc_TH_3_gen(TH_3, TH_2, CIPHER2, CIPHER2_LEN, data_3, data_3_len);
  coap_free(data_3);
  if (ret != 0){
    ok = -2;
    goto exit;
  }
  ret = edhoc_TH4_gen( TH_4, TH_3, CIPHER3, CIPHER3_len);
  if (ret != 0) ok = -2;
exit:
  if (C_R != NULL)coap_free(C_R);
  return ok;
}  

/* edhoc_read_message_4
 * on entry message contains message_4 with length size
 * message contents : data_4, MAC_4
 * returns error -2 when message cannot be parsed
 * returns error -1 when parameter values are not supported
 * returns 0 when OK
 */
oscore_ctx_t *
edhoc_read_message_4(coap_string_t *message_1, coap_string_t *message_2, coap_string_t *message_3, coap_string_t *message_4){
  int8_t  ok = 0;
  uint8_t *C_I = NULL;
  size_t  C_I_len = 0;
  uint8_t *salt = NULL;
  size_t  salt_len = 0; 
  uint8_t MAC_4[MAX_TAG_LEN];
  uint8_t MAC_4_mes[MAX_TAG_LEN];
  uint8_t TH_4[MAX_HASH_LEN];
  uint8_t prk_4x3m[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];  
  uint8_t prk_3e2m[COSE_ALGORITHM_ECDH_PUB_KEY_LEN]; 
  uint8_t prk_2e[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];   
  size_t  MAC_4_len = 0;
  int16_t alg      = current_cipher_suite->aead;  
  size_t  tag_len  = cose_tag_len(alg);
  uint8_t *C_R = NULL;
  size_t  C_R_len = 0;
  uint8_t *CIPHER3 = NULL;
  size_t  CIPHER3_len = 0;
  uint8_t *buf = message_3->s;
  
  if ((edhoc_corr == 1) || (edhoc_corr == 0)){
    ok = edhoc_cbor_get_C_X(&buf, &C_R, &C_R_len);
    if (ok != 0)return NULL;
  }
  hkdf_extract(salt, salt_len, edhoc_G_XY.s, COSE_ALGORITHM_ECDH_PUB_KEY_LEN, prk_2e); 
  edhoc_create_prk_3e2m(prk_3e2m,prk_2e); 
  edhoc_create_prk_4x3m(prk_4x3m,prk_3e2m);      
  CIPHER3_len = message_3->length - (buf - message_3->s);
  ok = cbor_get_string_array(&buf, &CIPHER3, &CIPHER3_len);
  if (ok != 0)return NULL; 
  ok = edhoc_find_TH_4(CIPHER3, CIPHER3_len, message_1, message_2, TH_4);
  if (ok != 0) return NULL;
  ok = edhoc_gen_MAC_4( TH_4, prk_4x3m, MAC_4);
  if (ok != 0) return NULL;
  buf = message_4->s;
  if (buf != NULL){ /* optional message_4 did not arrive  */
    if ((edhoc_corr == 2) || (edhoc_corr == 0)){
      ok = edhoc_cbor_get_C_X(&buf, &C_I, &C_I_len);
      if (ok != 0)return NULL;
      ok = edhoc_check_C_X('I',C_I, C_I_len);
      if (ok != 0) {
        coap_log(LOG_ERR,"C_R in message_3 does not correspond with stored C_R\n");
        return NULL;
      }
    } /* if edhoc-corr */
    uint8_t  elem = cbor_get_next_element(&buf);
    if (elem != CBOR_BYTE_STRING)return NULL;
    MAC_4_len = cbor_get_element_size( &buf);
    if (MAC_4_len > MAX_TAG_LEN){
      coap_log(LOG_ERR," MAC in message_4 is too large \n");
      return NULL;
    }
    cbor_get_array( &buf, MAC_4_mes, MAC_4_len);
    if (tag_len != MAC_4_len){
      coap_log(LOG_ERR,"Size of MAC_4 different from expected \n");
      return NULL;
    } else {
      if (memcmp( MAC_4_mes, MAC_4, tag_len) != 0){
        coap_log(LOG_ERR,"Received MAC_4 does not correspond with calculated MAC_4\n");
        return NULL;
      }
    } /* if tag_len */
  }   /* if buf != NULL */
  return edhoc_create_oscore_context(prk_4x3m, TH_4);
}

/* edhoc_create_message_4
 * on entry message_2 and CIPHER3, message_4 is empty coap_string;
 * G_X contains public ephemeral ecdh key
 * on return: message_3 contents : C_X , h'CIPHERTEXT_3'
 * returns #0 when error
 * returns 0 when OK
 */
int16_t
edhoc_create_message_4(uint8_t *CIPHER3, size_t CIPHER3_len, 
      coap_string_t *message_1, coap_string_t *message_2, coap_string_t *message_4){
  uint8_t *salt = NULL;
  size_t  salt_len = 0;
  uint8_t MAC_4[MAX_TAG_LEN];
  uint8_t TH_4[MAX_HASH_LEN];
  uint8_t prk_4x3m[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];  
  uint8_t prk_3e2m[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];  
  uint8_t prk_2e[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];      
  uint8_t *data_4 = NULL;
  uint8_t *C_I = NULL;
  size_t  C_I_len = 0;    
  int     ok = 0; 
  int16_t alg      = current_cipher_suite->aead;  
  size_t  tag_len  = cose_tag_len(alg);
  hkdf_extract(salt, salt_len, edhoc_G_XY.s, COSE_ALGORITHM_ECDH_PUB_KEY_LEN, prk_2e); 
  edhoc_create_prk_3e2m(prk_3e2m,prk_2e);
  edhoc_create_prk_4x3m(prk_4x3m,prk_3e2m);    
  ok = edhoc_find_TH_4(CIPHER3, CIPHER3_len, message_1, message_2, TH_4);
  if (ok != 0) return -2;
  ok = edhoc_gen_MAC_4( TH_4, prk_4x3m, MAC_4);
  if (ok != 0) return -2;
  edhoc_return_C_X('I', &C_I, &C_I_len);   /* C_I may be empty  */
  data_4 = coap_malloc(C_I_len + 3);
  size_t  data_4_len = 0;
  if ((edhoc_corr == 2) || (edhoc_corr == 0)){
    uint8_t *pt = data_4;
    data_4_len = edhoc_cbor_put_C_X(&pt, C_I, C_I_len);
    assert (data_4_len < C_I_len + 3);
    coap_free(C_I);
  }
  message_4->s = coap_malloc( data_4_len + tag_len + 3);
  uint8_t *pt = message_4->s;
  if ((edhoc_corr == 2) || (edhoc_corr == 0)){ 
    memcpy(pt, data_4, data_4_len);
    pt = pt + data_4_len;
  }
  size_t nr = data_4_len;
  nr += cbor_put_bytes(&pt, MAC_4, tag_len);
  assert( nr < data_4_len + tag_len + 3);
  message_4->length = nr;
  coap_free(data_4);
  oscore_ctx_t *osc_ctx = edhoc_create_oscore_context(prk_4x3m, TH_4);
  if (osc_ctx == NULL) return -2;
  return 0;
}

/* edhoc_cipher3_check
 * on entry buf points to CIPHERTEXT_3
 * CIPHERTEXT is checked 
 * returns error -2 when message cannot be parsed
 * returns error -1 when parameter values are not supported
 * returns 0 when OK
 */
static int16_t
edhoc_cipher3_check(uint8_t *CIPHER3, size_t CIPHER3_LEN, coap_string_t *message_2, 
             coap_string_t *message_1){
  char IR = 'I';            /* initiator certificate is wanted */
  uint8_t *ID_CRED_I = NULL;
  size_t  ID_CRED_I_len = 0;
  uint8_t *C_R = NULL;
  size_t  C_R_len = 0;
  uint8_t *M_3 = NULL;
  size_t  M_3_len = 0;    
  uint8_t MAC_3[MAX_TAG_LEN];
  uint8_t *CIPHER2 = NULL;
  uint8_t G_Y[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];
  uint8_t TH_3[MAX_HASH_LEN];
  uint8_t TH_2[MAX_HASH_LEN];  
  uint8_t prk_2e[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];
  uint8_t prk_3e2m[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];
  uint8_t prk_4x3m[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];
  uint8_t *data_3 = NULL;
  size_t  data_3_len = 0;
  int     ok = 0; 
  int     ret = 0; 
  uint8_t *salt = NULL;
  size_t  salt_len = 0; 
  int16_t hash_alg = current_cipher_suite->hash;
  size_t  hash_len = cose_hash_len (hash_alg); 
  int16_t alg      = current_cipher_suite->aead;  
  size_t  tag_len  = cose_tag_len(alg);
  hkdf_extract(salt, salt_len, edhoc_G_XY.s, COSE_ALGORITHM_ECDH_PUB_KEY_LEN, prk_2e);
  edhoc_create_prk_3e2m(prk_3e2m, prk_2e);
  edhoc_create_prk_4x3m(prk_4x3m,prk_3e2m); 
    /* recuperate data_2, CIPHER2 and C_X from message 2 */
  uint8_t *data_2 = message_2->s;
  ret = edhoc_receive_message_2(message_2, &CIPHER2, G_Y, &C_R, &C_R_len);
  size_t  data_2_len = (size_t)(CIPHER2 - data_2); 
  size_t  CIPHER2_LEN = message_2->length - data_2_len;
  ret = edhoc_TH_2_gen(TH_2, message_1, data_2, data_2_len);
  if (ret != 0){
    ok = -2;
    goto exit;
  }
  data_3 = coap_malloc(C_R_len + 3);
  if ((edhoc_corr == 0) || (edhoc_corr == 1)){
    uint8_t *pt = data_3;
    data_3_len = edhoc_cbor_put_C_X(&pt, C_R, C_R_len);
    assert (data_3_len < C_R_len + 3);
  }
  ret = edhoc_TH_3_gen(TH_3, TH_2, CIPHER2, CIPHER2_LEN, data_3, data_3_len);
  coap_free(data_3);
  if (ret != 0) return -1;
  uint8_t *P_3ae = coap_malloc(CIPHER3_LEN); /* tag_len could be substracted */
  ret = edhoc_check_CIPHER3(P_3ae, CIPHER3, CIPHER3_LEN, TH_3, prk_3e2m);
  if (ret != 0) goto exit1; 
   uint8_t *signature = NULL;
   size_t signature_len = 0;
   ok = edhoc_decompose_CIPHER_Y(P_3ae, &ID_CRED_I, &ID_CRED_I_len, &signature, &signature_len);
   if ( ok != 0) goto exit1;
   ok = edhoc_credentials(IR, ID_CRED_I, ID_CRED_I_len);
   if (ID_CRED_I != NULL)coap_free(ID_CRED_I);   
   if (ok != 0) goto exit1;
   ok = edhoc_gen_MAC_3( IR, TH_3, prk_4x3m, MAC_3);
   if (ok != 0){
      ok = -2;
      goto exit1;
    }
    M_3_len = edhoc_M_x(&M_3, IR, TH_3, hash_len,
                            MAC_3, tag_len);  
    if (M_3_len < 0){
      ok = -2;
      goto exit1;
    }


   if ((edhoc_method == 2) || (edhoc_method == 3)){ /* signature_or_MAC is MAC_3 */
     if (signature_len != tag_len){
       ret = -2;
       goto exit2;
     }
     /* remember to do DH signature */
     if (memcmp(signature, MAC_3, tag_len) != 0){
       ret = -2;
       goto exit2;
     }
   } else ret = edhoc_verify( IR, signature, signature_len, M_3, M_3_len); /*signature or MAC is signature  */
exit2:
  coap_free(M_3);                                           
exit1:
  coap_free(P_3ae);
exit:
  if (ret != 0) return -2;
  return 0;
}


/* edhoc_receive_message_3 
 * on entry data points to message_3 with length size
 * message_3 contents : C_X , h'CIPHERTEXT_3'
 * returns message_4
 * returns error -2 when message cannot be parsed
 * returns error -1 when parameter values are not supported
 * returns 0 when OK
 */
static int16_t
edhoc_receive_message_3(coap_string_t *message_4, coap_string_t *message_3, 
                        coap_string_t *message_2, coap_string_t *message_1){
  int8_t ok = 0;
  uint8_t *C_R = NULL;
  size_t  C_R_len = 0;
  uint8_t *CIPHER3 = NULL;
  size_t  CIPHER3_len = 0;
  uint8_t *buf = message_3->s;
  if ((edhoc_corr == 1) || (edhoc_corr == 0)){
    ok = edhoc_cbor_get_C_X(&buf, &C_R, &C_R_len);
    if (ok != 0)return -1;
    ok = edhoc_check_C_X('R',C_R, C_R_len);
    if (ok != 0) {
      coap_log(LOG_ERR,"C_R in message_3 does not correspond with stored C_R\n");
      return -2;
    }
  }
  CIPHER3_len = message_3->length - (buf - message_3->s);
  if (ok != 0)return -2;
  ok = cbor_get_string_array(&buf, &CIPHER3, &CIPHER3_len);
  if (ok != 0)return -2;
  ok = edhoc_cipher3_check(CIPHER3, CIPHER3_len, message_2, message_1);
  if (ok == 0)
       ok = edhoc_create_message_4(CIPHER3, CIPHER3_len, message_1, message_2, message_4);
  coap_free(CIPHER3);
  if (ok != 0)return -1;
  
  return 0;
}

/* edhoc_create_message_3
 * on entry message_1 and message_2 contains messages, message_3 is empty coap_string;
 * G_X contains public ephemeral ecdh key
 * on return: message_3 contents : C_X , h'CIPHERTEXT_3'
 * returns error < 0 when error
 * returns 0 when OK
 */
int16_t
edhoc_create_message_3(coap_string_t *message_1, coap_string_t *message_2, coap_string_t *message_3){
  char IR = 'I';      /*initiator certificate and key wanted  */
  edhoc_context_t *edhoc_ctx = &edhoc_cli_ctx;
  uint8_t G_X[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];
  uint8_t G_Y[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];  
  uint8_t G_XY[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];
  uint8_t TH_2[MAX_HASH_LEN];
  uint8_t TH_3[MAX_HASH_LEN];
  uint8_t prk_2e[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];
  uint8_t prk_3e2m[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];
  uint8_t prk_4x3m[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];
  uint8_t *data_2 = message_2->s;
  size_t  data_2_len = 0;
  uint8_t *data_3 = NULL;
  size_t  data_3_len = 0;
  uint8_t *CIPHERTEXT = NULL;
  size_t  CIPHERTEXT_LEN = 0;
  uint8_t *salt = NULL;
  size_t  salt_len = 0;  
  uint8_t *C_R = NULL;
  size_t  C_R_len = 0;
  uint8_t *M_3 = NULL;
  size_t  M_3_len = 0;    
  uint8_t MAC_3[MAX_TAG_LEN];
  int16_t hash_alg = current_cipher_suite->hash;
  size_t  hash_len = cose_hash_len (hash_alg);  
  int16_t alg      = current_cipher_suite->aead;
  size_t  tag_len = cose_tag_len(alg);
    
  int ret = 0; /* mbedtls error return */
  int  ok = 0; /* returned error */
  ret = edhoc_ecdh_pub_key(edhoc_ctx, G_X);
  if (ret != 0) {
    ok = -1;
    goto exit;}
  /* recuperate G_Y and C_X from message 2 */
  ret = edhoc_receive_message_2(message_2, &CIPHERTEXT, G_Y, &C_R, &C_R_len);
  if (ret != 0){
    ok = -1;
    goto exit;
  }
  ok = edhoc_create_shared_secret(edhoc_ctx, G_Y, G_XY);
  if (ok < 0) {
    ok = -1;
    goto exit1;
  }
  
  data_2_len = (size_t)(CIPHERTEXT - data_2);
  CIPHERTEXT_LEN = message_2->length - data_2_len;
  ok = edhoc_cipher2_check(CIPHERTEXT, G_Y, G_XY, C_R, C_R_len, message_1);
  if (ok < 0) goto exit1;
  if (edhoc_G_XY.s != NULL)coap_free(edhoc_G_XY.s);
  edhoc_G_XY.s = coap_malloc(COSE_ALGORITHM_ECDH_PUB_KEY_LEN);
  memcpy(edhoc_G_XY.s, G_XY, COSE_ALGORITHM_ECDH_PUB_KEY_LEN);
  edhoc_G_XY.length = COSE_ALGORITHM_ECDH_PUB_KEY_LEN;
  hkdf_extract(salt, salt_len, G_XY, COSE_ALGORITHM_ECDH_PUB_KEY_LEN, prk_2e); 
  edhoc_create_prk_3e2m(prk_3e2m, prk_2e);
  edhoc_create_prk_4x3m(prk_4x3m, prk_3e2m);
  ret = edhoc_TH_2_gen(TH_2, message_1, data_2, data_2_len);
  if (ret != 0){
    ok = -2;
    goto exit1;
  }
  data_3 = coap_malloc(C_R_len + 3);
  uint8_t *pt = data_3;
  if ((edhoc_corr == 1) || (edhoc_corr == 0)){
    data_3_len = edhoc_cbor_put_C_X(&pt, C_R, C_R_len);
    assert (data_3_len < C_R_len + 3);
  }
  ret = edhoc_TH_3_gen(TH_3, TH_2, CIPHERTEXT, CIPHERTEXT_LEN, data_3, data_3_len);
  if (ret != 0) {
     ok = -2;
     goto exit1;
  }
  ret = edhoc_gen_MAC_3( IR, TH_3, prk_4x3m, MAC_3);
  if (ret != 0) {
    ok = -2;
    goto exit1;
  }
    M_3_len = edhoc_M_x(&M_3, IR, TH_3, hash_len,
                             MAC_3, tag_len);  
   if (M_3_len < 0){
     ok = -2;
     goto exit1;
   }
   uint8_t signature[MAX_SIGNATURE_LEN];
   size_t signature_len = 0;
   if ((edhoc_method == 2) || (edhoc_method == 3)){ /* signature_or_MAC_3 is MAC_3 */
     signature_len = tag_len;
     memcpy(signature, MAC_3, tag_len);
     /* remember to do the DH signature  */
   } else ok = edhoc_sign(IR, signature, &signature_len, M_3, M_3_len); /*signature_or_MAC_3 is signature */
  coap_free(M_3);
  uint8_t *P_3ae = NULL;
  size_t P_3ae_len = edhoc_P_x( &P_3ae, IR, signature, signature_len);
  size_t CIPHERTEXT_3_len =  P_3ae_len + tag_len; 
  uint8_t *CIPHERTEXT_3 = coap_malloc( CIPHERTEXT_3_len);   
  ret = edhoc_gen_CIPHER3(TH_3, prk_3e2m, CIPHERTEXT_3, P_3ae, P_3ae_len);
  coap_free(P_3ae); 
  if (ret != 0){
    ok = -2;
    goto exit4;
  }
    size_t len = C_R_len + 4 + CIPHERTEXT_3_len;
    message_3->s = coap_malloc(len);
    size_t nr = 0;
    pt = message_3->s;
    if ((edhoc_corr == 0) || (edhoc_corr == 1)){
        memcpy(pt, data_3, data_3_len);
        nr = data_3_len;
        pt = pt + data_3_len;
    }
    nr += cbor_put_bytes( &pt, CIPHERTEXT_3, CIPHERTEXT_3_len);
    assert(nr < len);
    message_3->length = nr;
exit4:
    coap_free(CIPHERTEXT_3); 
exit1:
    coap_free(C_R);
    coap_free(data_3);
exit:
    return ok;
}

/* edhoc_create_message_2
 * on entry message_1 contains message_1, message_2 is empty coap_string;
 * G_X contains public ephemeral ecdh key
 * on return: message2 contents : data_2  ciphertext_2
 * returns error < 0 when error
 * returns 0 when OK
 */
static int16_t
edhoc_create_message_2(coap_string_t *message_1, uint8_t *G_X, size_t G_X_len, 
                                  uint8_t *C_I, size_t C_I_len, coap_string_t *message_2){
  char IR = 'R';    /* Responder certificate and key file wanted */
  uint8_t G_Y[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];
  uint8_t G_XY[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];
  uint8_t *salt = NULL;
  size_t  salt_len = 0;
  uint8_t prk_2e[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];
  uint8_t prk_3e2m[COSE_ALGORITHM_ECDH_PUB_KEY_LEN];
  uint8_t C_R[2];
  size_t  C_R_len = 1;
  uint8_t TH_2[MAX_HASH_LEN];
  uint8_t *data_2 = NULL;
  size_t  data_2_len = 0;
  uint8_t *M_2 = NULL;
  size_t  M_2_len = 0;    
  uint8_t MAC_2[MAX_TAG_LEN];
  char    keystream[] = "KEYSTREAM_2";
  uint8_t *CIPHERTEXT_2 = NULL;
  int16_t hash_alg = current_cipher_suite->hash;
  size_t  hash_len = cose_hash_len (hash_alg);
  int16_t alg      = current_cipher_suite->aead;  

  char err_buf[CRT_BUF_SIZE];    
  memset( err_buf, 0, sizeof( err_buf ) );	
  int ret =0; /* mbedtls error return */
  /* Responder connection identifier  */ 
  C_R[0] = 0x2b;
  C_R[1] = 0;
  message_2->s = NULL;
  message_2->length = 0;

  edhoc_context_t *edhoc_ctx = edhoc_srv_pub_key();
  if (edhoc_ctx == NULL) return -1;
 /* retrieve ephemeral ecdh 25519 public key  */
  ret = edhoc_ecdh_pub_key(edhoc_ctx, G_Y);
  if (ret != 0) return -1;
  int ok = edhoc_create_shared_secret(edhoc_ctx, G_X, G_XY);
  if (ok < 0) return ok;
  ok = edhoc_enter_C_X('I', C_I, C_I_len);
  if (ok != 0)return -1;
  ok = edhoc_enter_C_X('R',C_R, C_R_len);
  if (ok != 0)return -1;
  /* store G_XY for later use  */
  if (edhoc_G_XY.s != NULL)coap_free(edhoc_G_XY.s);
  edhoc_G_XY.s = coap_malloc(COSE_ALGORITHM_ECDH_PUB_KEY_LEN);
  memcpy(edhoc_G_XY.s, G_XY, COSE_ALGORITHM_ECDH_PUB_KEY_LEN);
  edhoc_G_XY.length = COSE_ALGORITHM_ECDH_PUB_KEY_LEN;
  hkdf_extract(salt, salt_len, G_XY, COSE_ALGORITHM_ECDH_PUB_KEY_LEN, prk_2e);
  edhoc_create_prk_3e2m(prk_3e2m,prk_2e); 
  edhoc_data_2(&data_2, &data_2_len, G_Y); 
  ret = edhoc_TH_2_gen(TH_2, message_1, data_2, data_2_len);
  if (ret != 0) {
    ok = -2;
    goto exit1;
  }
    size_t tag_len = cose_tag_len( alg);
    ret = edhoc_gen_MAC_2( IR, TH_2, prk_3e2m, MAC_2);
    if (ret != 0) {
      ok = -2;
      goto exit1;  
    }
    M_2_len = edhoc_M_x(&M_2, IR, TH_2, hash_len,
                            MAC_2, tag_len); 
   if (M_2_len < 0) {
     ok = -2;
     goto exit1;
   }
   uint8_t signature[MAX_SIGNATURE_LEN];
   size_t signature_len = 0;
   if ((edhoc_method == 1) || (edhoc_method == 3)){ /* signature_or_MAC_2 is MAC_2 */
     signature_len = tag_len;
     memcpy(signature, MAC_2, tag_len);
   } else {
     ok = edhoc_sign( IR, signature, &signature_len, M_2, M_2_len); /*signature_or_MAC_2 is signature */
     if (ok != 0)goto exit1;
   }
  uint8_t *P_2e = NULL;
  size_t P_2e_len = edhoc_P_x( &P_2e, IR, signature, signature_len);
  uint8_t *K_2e = NULL;
  edhoc_create_key( &K_2e, P_2e_len, keystream, sizeof(keystream) -1,
                      TH_2, prk_2e);    
  /* do xor on K_2e and P_2e */
  CIPHERTEXT_2 = coap_malloc(P_2e_len);
  for (uint qq= 0 ; qq < P_2e_len; qq++) CIPHERTEXT_2[qq] = K_2e[qq]^P_2e[qq];
  coap_free(K_2e);
  message_2->s = coap_malloc(data_2_len + P_2e_len + 4);
  memcpy(message_2->s, data_2, data_2_len);
  uint8_t *pt = message_2->s + data_2_len;
  size_t nr = data_2_len;
  nr += cbor_put_bytes( &pt, CIPHERTEXT_2, P_2e_len);
  assert( nr < data_2_len + P_2e_len + 4);
  message_2->length = nr;  

  if (P_2e != NULL)coap_free(P_2e);
  if(CIPHERTEXT_2 != NULL)coap_free(CIPHERTEXT_2); 
  if( M_2 != NULL)coap_free(M_2);
exit1:
  if (data_2 != NULL)coap_free(data_2);
  return ok;  
}

/* edhoc_create_message_1 
 * on entry message points to buffer to be filled;  no test on length is done
 * message contents : method_corr, suite, G_x, C_I, [AD_1]
 * returns error < 0 when error
 * returns 0 when OK
 */
int16_t
edhoc_create_message_1(coap_string_t *message_1, coap_string_t *G_X_string, uint16_t method_corr, uint8_t suite){
  /* prepare message  */
  uint8_t C_I_len = 1;
  uint8_t C_I[2];
  size_t  nr = 0;
  C_I[0] = 0x16;
  C_I[1] = 0;
  edhoc_function = 'I';   /* this is an Initiator */
  edhoc_method = method_corr >> 2;
  edhoc_corr   = method_corr & 3;
  if (suite > EDHOC_MAX_SUITE) return -1;
  current_cipher_suite = &supported_cipher_suites[suite];
  edhoc_context_t *edhoc_ctx = edhoc_cli_pub_key();
  if (edhoc_ctx == NULL) return -1;
 /* create ephemeral ecdh 25519 public key  */
  G_X_string->length = COSE_ALGORITHM_ECDH_PUB_KEY_LEN;
  G_X_string->s = coap_malloc(G_X_string->length);
  int ret = edhoc_ecdh_pub_key(edhoc_ctx, G_X_string->s);
  if (ret != 0) return -1;
   edhoc_enter_C_X('I', C_I, C_I_len);
   message_1->s =coap_malloc(8 + G_X_string->length + C_I_len);
   uint8_t *data = message_1->s;
  /* create message */
  nr += cbor_put_number(&data, method_corr);
  nr += cbor_put_number(&data, suite);
  nr += cbor_put_bytes(&data, G_X_string->s, G_X_string->length);
  nr += edhoc_cbor_put_C_X(&data, C_I, C_I_len);
  assert(nr < 8 + G_X_string->length + C_I_len);
  message_1->length = nr;
  return 0;

}

static void
hnd_post_edhoc(coap_context_t  *ctx UNUSED_PARAM,
             struct coap_resource_t *resource,
             coap_session_t *session,
             coap_pdu_t *request,
             coap_binary_t *token,
             coap_string_t *query,
             coap_pdu_t *response) {
  uint8_t* data = NULL;
  size_t   size = 0; 
  edhoc_function = 'R'; /* this is a responder */
	/* check whether data need to be returned */
  if (request) {
	coap_block_t block2 = { 0, 0, 0};
	if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)){	
      coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_EDHOC, -1,
                                 edhoc_message_2.length, edhoc_message_2.s);
     return;
     } /* coap_get_block */
  } /* request */
	
  data = assemble_data(session, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */
  if ((data == NULL) | (size == 0)){
	  edhoc_error_return('R',COAP_RESPONSE_CODE(400), 
    response, "Did not find request data\n");
	  return;
  }
  int8_t   ok =0;
  uint8_t  *G_X = NULL;
  size_t   G_X_len = 0;
  uint8_t  *C_I = NULL;
  size_t   C_I_len = 0;
  uint8_t  *add = NULL;
  size_t   add_len = 0;


  if (edhoc_state == EDHOC_MESSAGE_1){  /* reception of message_1 */
    /* clear all formerly received messages  */
    if (edhoc_message_1.s != NULL)coap_free(edhoc_message_1.s);
    edhoc_message_1.length = size;
    edhoc_message_1.s = coap_malloc(size);
    memcpy(edhoc_message_1.s, data, size);
    if (edhoc_message_2.s != NULL)coap_free(edhoc_message_2.s);
    edhoc_message_2.length = 0;
    edhoc_message_2.s = NULL;   
    if (edhoc_message_3.s != NULL)coap_free(edhoc_message_3.s);
    edhoc_message_3.length = 0;
    edhoc_message_3.s = NULL; 
    if (edhoc_message_4.s != NULL)coap_free(edhoc_message_4.s);
    edhoc_message_4.length = 0;
    edhoc_message_4.s = NULL;            
    ok = edhoc_receive_message_1(&edhoc_message_1,
                          &G_X, &G_X_len, &C_I, &C_I_len,
                          &add, &add_len);                     
    if (ok == 0){
      ok =  edhoc_create_message_2( &edhoc_message_1, G_X, G_X_len, C_I, C_I_len, &edhoc_message_2);
      if ( ok != 0){
            edhoc_error_return('R',COAP_RESPONSE_CODE(400), 
            response, "Message 2 cannot be generated \n");
            edhoc_state = 0; /* wait for message_1 */
	          return;    
      }
      edhoc_state++;                     
    /* message_1 received, send message_2 */
      response->code = COAP_RESPONSE_CODE(204);  
      coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_EDHOC, -1,
                                 edhoc_message_2.length, edhoc_message_2.s);  
    }
    return;
  } else {  /* reception of message_3  */
    edhoc_message_3.s = coap_malloc(size);
    edhoc_message_3.length = size;
    memcpy(edhoc_message_3.s, data, size);                
    ok = edhoc_receive_message_3(&edhoc_message_4, &edhoc_message_3, &edhoc_message_2, &edhoc_message_1);
    edhoc_state = 0;
    if (ok == 0){                 
      response->code = COAP_RESPONSE_CODE(204);
      coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_EDHOC, -1,
                                 edhoc_message_4.length, edhoc_message_4.s);   
      return; 
    }
    if (G_X != NULL)coap_free(G_X);
    G_X = NULL;
  }
  /* do error return */
  if (ok == -2){	  
    edhoc_error_return('R',COAP_RESPONSE_CODE(400), 
    response, "EDHOC Message_1 cannot be parsed\n");
	  return;
  } else if (ok == -1) {
    edhoc_error_return('R',COAP_RESPONSE_CODE(400), 
    response, "Server cannot handle method or cipher suite\n");
	  return;    
  } else if (ok != 0){
    edhoc_error_return('R',COAP_RESPONSE_CODE(400), 
    response, "unexpected error return\n");
	  return;    
  }
  edhoc_state = 0; /* after error ready for message_1 */
  return; 
}

/* receive message_2 for edhoc 
 * and send message_3 */
static int8_t
read_message_2(coap_context_t *ctx, coap_string_t *message_1, coap_string_t *message_3){
/*  edhoc_message_2 contains returned message_2 */
  if ((edhoc_code >> 5) != 2){
    /* received message_2 has error code */
    return -2;
  }                  
  int8_t ok = edhoc_create_message_3(message_1, &edhoc_message_2, message_3);
  return ok;
}


void
edhoc_oscore_session(coap_context_t *ctx, coap_session_t *session, 
                         edhoc_state_t *client_state, uint16_t method_corr, uint8_t suite, coap_string_t **message){
     int8_t ok = 0;
     (*message) = NULL;
     switch (*client_state) {
       case EDHOC_MESSAGE_1:
         if (suite < 2)coap_log(LOG_WARNING,"mebdtls supports suites 0 and 1 only partially \n");
         ok = edhoc_create_message_1(&edhoc_message_1, &G_X_string, method_corr, suite);
         if (ok == 0) {
			 (*message) = &edhoc_message_1;
		 }
         break;
		   case EDHOC_MESSAGE_2:
            ok = read_message_2(ctx, &edhoc_message_1, &edhoc_message_3);
		    if (ok != 0){     /* message_2 is returned */
              coap_log(LOG_ERR,"EDHOC connection could not be established \n");
              *client_state = EDHOC_FAILED;
              return;
            }
            (*message) = &edhoc_message_3;
		     break;
		   case EDHOC_MESSAGE_3:
         if ((edhoc_code >> 5) != 2){
          /* message_3 acknowledgement has error code */
            coap_log(LOG_ERR,"Returned message_4 is error message \n");
            *client_state = EDHOC_FAILED;
            return;
         } else {
           oscore_ctx_t *osc_ctx = edhoc_read_message_4(&edhoc_message_1, &edhoc_message_2, &edhoc_message_3, &edhoc_message_4);
           if (osc_ctx == NULL){
             coap_log(LOG_ERR,"oscore context could not be created \n");
             *client_state = EDHOC_FAILED;
             return;
           } else {
             /* osc_ctx  points to default oscore context  */
              ctx->osc_ctx = osc_ctx;
              session->oscore_encryption = 1;
           }
         }
		     break;
		   case EDHOC_CONNECTED:
       case EDHOC_FAILED:
       case EDHOC_DONE:
         return;
		     break;
		   default:
          *client_state = EDHOC_FAILED;
          return;
		     break;
     }  /* switch */
  (*client_state)++;
}

void
init_edhoc_resources(coap_context_t *ctx) {
  coap_resource_t *r;

  r = coap_resource_init(coap_make_str_const(".well-known/edhoc"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_POST, hnd_post_edhoc);

  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"edhoc connection\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.edhoc\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"edhoc\""), 0);

  coap_add_resource(ctx, r);
  
}

