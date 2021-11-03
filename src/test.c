/* TEST of BRSKI -- implementation of 
 * This file relies on mbedtls DTLS
 *
 * Copyright (C) 2010--2018 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 *
 */


#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
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
#include <malloc.h>
#endif
#include "oscore.h"
#include "oscore-context.h"
#include "oscore-group.h"
#include "cbor.h"
#include "cose.h"
#include "edhoc.h"

#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

#include "coap.h"
#include "coap_server.h"
#include "JP_server.h"
#include "brski.h"
#include "client_request.h"
#include "brski_util.h"
#include "pledge.h"

/* TEST prints test results */
#define TEST_LN  92   /*length of text string */
#define PROC_NM_MAX  80

/* variable silent is used to decide on print */
/* test if unequal 1 (error) is returned */
#define TEST_NOK( x )                                            \
    do {                                                         \
		char points[] = "......................................................................";   \
		char TEST__str_[TEST_LN + 1];                                \
		memset(TEST__str_, 0, sizeof(TEST__str_));                   \
		int TEST__ok_ = ( x );                                       \
		sprintf(TEST__str_, "%s returns %d     ", #x, TEST__ok_ );   \
		int LEN__str_ = strlen(TEST__str_);                          \
		if (LEN__str_ > TEST_LN) LEN__str_ = TEST_LN - 1;            \
		strncpy(TEST__str_ + LEN__str_, points, TEST_LN - LEN__str_);\
        if(TEST__ok_ != 0){if(silent) fprintf(stderr,"%s    OK return\n", TEST__str_);}      \
        else fprintf(stderr,"%s    ERROR return\n", TEST__str_);  \
    } while( 0 )  
 
 /* test if equal 0 (OK) is returned */   
#define TEST_OK( x )                                             \
    do {                                                         \
		char points[] = "..........................................................................";   \
		char TEST__str_[TEST_LN+1];                                  \
		memset(TEST__str_, 0, sizeof(TEST__str_));                   \
		int TEST__ok_ = ( x );                                       \
		sprintf(TEST__str_, "%s returns %d     ", #x, TEST__ok_ );   \
		int LEN__str_ = strlen(TEST__str_);                          \
		if (LEN__str_ > TEST_LN) LEN__str_ = TEST_LN;                \
		strncpy(TEST__str_ + LEN__str_, points, TEST_LN - LEN__str_);\
        if (TEST__ok_ == 0) {if( silent ) fprintf(stderr,"%s    OK return\n", TEST__str_);} \
        else fprintf(stderr,"%s    ERROR return\n", TEST__str_); \
    } while( 0 ) 
 
/* test if procedure executes  */    
#define TEST_VOID( x )                                                \
    do {                                                             \
		char points[] = "................................................................................";   \
		char TEST__str_[TEST_LN + 1];                                \
		memset(TEST__str_, 0, sizeof(TEST__str_));                   \
	    ( x );                                                       \
		sprintf(TEST__str_, "%s      ", #x);                               \
		int LEN__str_ = strlen(TEST__str_);                          \
		if (LEN__str_ > TEST_LN) LEN__str_ = TEST_LN;                \
		strncpy(TEST__str_ + LEN__str_, points, TEST_LN - LEN__str_);\
        if (silent)fprintf(stderr,"%s    ", TEST__str_);                        \
    } while( 0 ) 

/* test if a pointer value is returned into variable pt */      
#define TEST_PT( x )                                                 \
    do {                                                             \
		char points[] = ".......................................................";   \
		char TEST__str_[TEST_LN + 1];                                \
		memset(TEST__str_, 0, sizeof(TEST__str_));                   \
		void * TEST__pt_ = ( x );                                    \
		pt = TEST__pt_;                                              \
		sprintf(TEST__str_, "%s returns pointer     ", #x );         \
		int LEN__str_ = strlen(TEST__str_);                          \
		if (LEN__str_ > TEST_LN) LEN__str_ = TEST_LN;                \
		strncpy(TEST__str_ + LEN__str_, points, TEST_LN - LEN__str_);\
        if(TEST__pt_ != NULL){if(silent)fprintf(stderr,"%s    OK return\n", TEST__str_);}     \
        else fprintf(stderr,"%s    ERROR return\n", TEST__str_);     \
    } while( 0 ) 

/* test if a NULL pointer (error) is returned */      
#define TEST_NULL( x )                                               \
    do {                                                             \
		char points[] = ".........................................................";   \
		char TEST__str_[TEST_LN + 1];                                \
		memset(TEST__str_, 0, sizeof(TEST__str_));                   \
		void * TEST__pt_ = ( x );                                    \
		pt = TEST__pt_;                                              \
		sprintf(TEST__str_, "%s returns NULL     ", #x );            \
		int LEN__str_ = strlen(TEST__str_);                          \
		if (LEN__str_ > TEST_LN) LEN__str_ = TEST_LN;                \
		strncpy(TEST__str_ + LEN__str_, points, TEST_LN - LEN__str_);\
        if(TEST__pt_ == NULL){if(silent) fprintf(stderr,"%s    OK return\n", TEST__str_);}      \
        else fprintf(stderr,"%s    ERROR return\n", TEST__str_);     \
    } while( 0 )     
 

    
#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

#define FLAGS_BLOCK            0x01
#define CREATE_URI_OPTS        1
#define RELIABLE               0

/* certificates and key files for sever DTLS */
static char int_cert_file[] = PLEDGE_COMB;         /* Combined certificate and private key in PEM */
static char int_ca_file[] = PLEDGE_CA  ;           /* CA for cert_file - for cert checking in PEM */



static uint16_t registrar_code = 0;
static coap_string_t registrar_response = {
	.length = 0,
	.s = NULL
};

static  coap_string_t request_voucher = {.length = 0, .s = NULL};
  
/* stores data returned by Registrar */
static int16_t
add_response(unsigned char *data, size_t len, uint16_t code, 
                            uint16_t block_num, uint16_t more) {
    if (code >> 5 != 2){
    if (registrar_response.s != NULL)coap_free(registrar_response.s);
    registrar_response.length = 0;
    registrar_response.s = NULL;
    registrar_code = code;
    return 0;
  }
  if (block_num == 0){   /* newly arrived message */
	if (registrar_response.s != NULL)coap_free(registrar_response.s);
    registrar_response.length = 0;
    registrar_response.s = NULL;
  }
  size_t offset = registrar_response.length;
      /* Add in new block to end of current data */
  coap_string_t old_mess = {.length = registrar_response.length, .s = registrar_response.s};
  registrar_response.length = offset + len;
  registrar_response.s = coap_malloc(offset+len);
  if (offset != 0) 
     memcpy (registrar_response.s, old_mess.s, offset);  /* copy old contents  */
  if (old_mess.s != NULL)coap_free(old_mess.s);
  memcpy(registrar_response.s + offset, data, len);         /* add new contents  */ 
  registrar_code = code;
  return 0;
}

/* test_connect_pledge
 * starts DTLS connection with Registrar
 * returns 0; when enrolled
 * returns 1: when failure
 */
static int8_t
test_connect_pledge(client_request_t *client){
	if (client == NULL) return 1;
/* start new session to registrar with discovered host*/
  set_message_type(client, COAP_MESSAGE_CON);
/* DTLS preparations */
  set_scheme( client, COAP_URI_SCHEME_COAPS); 
  /* Start DTLS connection with ping  */ 
  coap_session_t *session = coap_start_session(client);
  if (session == NULL){
	  coap_log(LOG_WARNING,"start_session DTLS to Registrar failed  \n");
	  return 1;
  } 
    uint16_t tid = coap_new_message_id (session);
    coap_pdu_t *ping = NULL;
    ping = coap_pdu_init(COAP_MESSAGE_CON, 0, tid, 0);  
    if (ping != NULL){ 
      coap_tid_t tid = coap_send(session, ping);
      if (tid ==  COAP_INVALID_TID) return 1;
      return 0;
  }
  return 1;
}

static int8_t
test_status_voucher(client_request_t *client, int divisor){
  coap_string_t path = { .length =0 , .s = NULL};
  int8_t result = 1;
  /* est/vs  */
  int16_t ct = COAP_MEDIATYPE_APPLICATION_CBOR;
  if (registrar_response.s != NULL) coap_free(registrar_response.s);
  registrar_response.s = NULL;
  registrar_code = 0;
  char vs[] = ".well-known/brski/vs";
  path.s = (uint8_t *)vs;
  path.length = strlen(vs);
  set_path(client, &path);  
  remove_flags( client, FLAGS_BLOCK);
  set_method (client, COAP_REQUEST_POST);
  coap_string_t status = { .length = 0, .s = NULL};
  if (JSON_set() == JSON_OFF){
      brski_cbor_voucherstatus(&status);
      ct = COAP_MEDIATYPE_APPLICATION_CBOR;
  } else {
	  brski_json_voucherstatus(&status);
	  ct = COAP_MEDIATYPE_APPLICATION_JSON;
  }  
  if (status.length > 0){
	  status.length = (status.length*divisor)/10;  
	  set_payload(client, &status);   	  
	  result = coap_start_request(client, ct);    	  
      coap_free(status.s);
  }  /* if status.length  */     
  return result;
}

static int8_t
test_status_response(client_request_t *client, char *ca_name, char *masa_serv_name ){
  int8_t ok; 
  /* local MASA test */  
  if (registrar_response.s == NULL){
	 coap_log(LOG_ERR," No MASA voucher returned \n");
	 return 1;
  }
  coap_string_t *voucher = NULL;
  if (JSON_set() == JSON_OFF)
      voucher = brski_verify_cose_signature(&registrar_response, masa_serv_name, ca_name);
  else
      voucher = brski_verify_cms_signature(&registrar_response, ca_name, masa_serv_name);
  if (voucher == NULL){
	  coap_log(LOG_ERR," signature of returned masa voucher is wrong \n");
	  if (request_voucher.s != NULL)coap_free(request_voucher.s); 
	  request_voucher.s = NULL;  
	  return 1;
  }
  ok = brski_check_voucher(voucher, &request_voucher);
  if (voucher->s != NULL)coap_free(voucher->s);
  coap_free(voucher);
  if (request_voucher.s != NULL)coap_free(request_voucher.s);
  request_voucher.s = NULL;      
  if (ok != 0){
	  coap_log(LOG_ERR, "voucher request and masa returned voucher do not correspond \n");
	  return 1;
  }
  return 0;
}

static int8_t  
test_voucher_request(client_request_t *client, char *register_cert, char *pledge_comb, int divisor){ 
  coap_string_t  signed_request_voucher = { .length = 0 , .s = NULL};	
  if (client == NULL)return 1;
	/* continue session to registrar with returned registrar certificate*/
  set_message_type( client, COAP_MESSAGE_CON);
  coap_string_t path = { .length =0 , .s = NULL};
  /* est/rv  with signed requestvoucher to registrar */ 
  set_resp_handler(add_response);
  uri_options_on(client);
  set_flags( client, FLAGS_BLOCK); 
  char rv[] = ".well-known/brski/rv";
  set_method( client, COAP_REQUEST_POST);
  path.s = (uint8_t *)rv;
  path.length = strlen(rv);
  set_path(client, &path);   
  if (request_voucher.s != NULL) coap_free(request_voucher.s);
  request_voucher.s = NULL;
  if (registrar_response.s != NULL) coap_free(registrar_response.s);
  registrar_response.s = NULL;
  registrar_code = 0;  
  int8_t ok = brksi_make_signed_rv(&signed_request_voucher, &request_voucher, register_cert, pledge_comb);   
  signed_request_voucher.length = (signed_request_voucher.length*divisor)/10;
  set_payload(client, &signed_request_voucher);
  coap_free(signed_request_voucher.s);   
  if (ok != 0) return 1;
  if (JSON_set() == 1)
     return coap_start_request( client, COAP_MEDIATYPE_APPLICATION_VOUCHER_CMS_JSON);
  else
     return coap_start_request( client, COAP_MEDIATYPE_APPLICATION_VOUCHER_COSE_CBOR);    
}
  
static int8_t
test_get_certificate(client_request_t *client){
  coap_string_t payload = { .length =0 , .s = NULL};
  coap_string_t path    = { .length =0 , .s = NULL};
 /* est/crts    */
 /* get certificate from registrar  */
  if (registrar_response.s != NULL) coap_free(registrar_response.s);
  registrar_response.s = NULL;
  registrar_code = 0;  
  char crts[] = ".well-known/est/crts";
  path.s = (uint8_t *)crts;
  path.length = strlen(crts);
  if (client == NULL) return 1;
  set_path( client, &path);
  set_payload(client, &payload);
  set_method (client, COAP_REQUEST_GET);
  return coap_start_request(client, 0);
}
    
static int8_t 
test_enroll_certificate(client_request_t *client, int ct, int divisor){
  coap_string_t path    = { .length =0 , .s = NULL};
  coap_string_t payload = { .length =0 , .s = NULL};  
  int8_t result = 0;
 /* est/sen   enroll certificate  */
  if (registrar_response.s != NULL) coap_free(registrar_response.s);
  registrar_response.s = NULL;
  registrar_code = 0;  
  char sen[] = ".well-known/est/sen";
  path.s = (uint8_t *)sen;
  path.length = strlen(sen);
  if (client == NULL) return 1;
  set_path( client, &path);
  set_method( client, COAP_REQUEST_POST);
  result = brski_create_csr(&payload);
  payload.length = (payload.length*divisor)/10;
  if (result == 0){
    if (payload.length > 0){
	    set_payload( client, &payload);
	    result = coap_start_request(client, ct); 
        coap_free(payload.s);
        payload.s = NULL;
    }  /* if payload.length  */
  }  /* if result  */
  return result;
}   

static void
usage( const char *program, const char *version) {
  const char *p;
  char buffer[64];

  p = strrchr( program, '/' );
  if ( p )
    program = ++p;

  fprintf( stderr, "%s v%s -- BRSKI Test implementation\n"
     "(c) 2021 Peter van der Stok\n\n"
     "%s\n\n"
     "Usage: %s [-v num] [-h] coaps://registrar\n"
     "\t       \t\tRemote DTLS tests are done with Registrar to be specified \n"
     "General Options\n"
     "\t-v num \t\tVerbosity level (default 0, maximum is 9). Above 7,\n"
     "\t       \t\tthere is increased verbosity in GnuTLS and OpenSSL logging\n"
     "\t       \t\t-v 0 suppresses all Warning and error messages \n"
     "\t-h     \t\tHelp displays this message \n"     
     "\texamples:\t  %s coaps://localhost:5664\n"
     "\t       \t\t  %s -v 0 coaps://[registrar_ipv6]\n"
     "\t       \t\t  %s -h \n"
    , program, version, coap_string_tls_version(buffer, sizeof(buffer)),
    program, program, program, program);
}


void do_local_tests(void){
  char file_name[]  = "file_name";   /* non-existing file name */
  char pledge_crt[] = PLEDGE_CRT;    /* PLEDGE EE certificate  */
  char pledge_ca[]  = PLEDGE_CA;     /* PLEDGE CA certificate  */
  char comb_file[]  = PLEDGE_COMB;   /* PLEDGE KEY and CA certificate combined */
  char empty[]      = "";             /* 0 byte string */
  char anything[]   = "anything";     /* anything string  */
  uint16_t regis_join_port  = 0;
  coap_string_t any               = {.s = (uint8_t *)anything, .length = sizeof(anything)}; 
  coap_string_t ret_data          = {.s = NULL, .length = 0};  /* to return tenporary data in argument */
  coap_string_t cbor_PVR          = {.s = NULL, .length = 0};  /* cbor Pledge Voucher Request (PVR) */
  coap_string_t json_PVR          = {.s = NULL, .length = 0};  /* json Pledge Voucer Request (PVR) */ 
  coap_string_t cbor_RVR          = {.s = NULL, .length = 0};  /* cbor Regitrar Voucher Request (PVR) */
  coap_string_t json_RVR          = {.s = NULL, .length = 0};  /* json Registrar Voucher Request (PVR) */   
  coap_string_t cose_sign_PVR     = {.s = NULL, .length = 0};  /* cose signed cbor PVR */
  coap_string_t cms_sign_PVR      = {.s = NULL, .length = 0};  /* cms signed json PVR  */   
  coap_string_t nothing           = {.s = NULL, .length = 0};  /* empty coap string argument  */
  coap_string_t cbor_voucher      = {.s = NULL, .length = 0};  /* cbor voucher  */
  coap_string_t json_voucher      = {.s = NULL, .length = 0};  /* json voucher  */
  coap_string_t certificate       = {.s = NULL, .length = 0};  /* generated cerificate     */
  coap_string_t csr               = {.s = NULL, .length = 0};  /* certificate sign request */
  coap_string_t cbor_status       = {.s = NULL, .length = 0};  /* created cbor status  */
  coap_string_t json_status       = {.s = NULL, .length = 0};  /* created json status  */

  uint8_t   aki[3] = {0x55, 0x1d, 0x23};
  coap_string_t oid_name = {.length = sizeof(aki), .s = aki};  /* OID Authority Key Identifier      */
  audit_t *audit                  = NULL;                      /* audit returned based on voucher */
  voucher_t     *parsed_empty     = coap_malloc(sizeof(voucher_t));
  memset(parsed_empty, 0, sizeof(voucher_t));   /* empty parsed voucher */
  voucher_t     *P_PVR            = NULL;       /* parsed PVR */
  voucher_t     *P_RVR            = NULL;       /* parsed RVR */ 
  coap_string_t *log              = NULL;       /* returned audit log */
  void          *pt      = NULL;                /* pointer returned by a TEST_PT */
  uint8_t       silent   = 1;                   /* disbale test output    */

/* test procedures in file pledge.c with NULL argument */                                	   
             fprintf(stderr,"\n     START pledge procedures test \n");
             TEST_NOK(pledge_connect_pledge( NULL));                     
		     TEST_NOK(pledge_voucher_request( NULL));     
		     TEST_NOK(pledge_arrived(registrar_code, NULL));               	     	     
		   	 TEST_NOK(pledge_get_certificate( NULL));                	   	 
             TEST_NOK(pledge_get_attributes( NULL));   
             TEST_NOK(pledge_enroll_certificate( NULL));                 
             TEST_NOK(pledge_status_voucher( NULL));                                                  
		     TEST_NOK(pledge_registrar_session( NULL, &regis_join_port));
             fprintf(stderr,"     END of local procedure test \n");
                                                 
/* test all procedures in brski.c which are exported in brski.h */             
             fprintf(stderr,"\n     START brski procedures test \n");
//json_set
             set_JSON(JSON_ON);
             TEST_OK(JSON_ON - JSON_set());  
             TEST_NOK(JSON_OFF - JSON_set());
             TEST_NOK(3 - JSON_set());
             set_JSON(JSON_OFF);
             TEST_NOK(JSON_ON - JSON_set());  
             TEST_OK(JSON_OFF - JSON_set());
             TEST_NOK(3 - JSON_set()); 
             set_JSON(3);
             TEST_NOK(3 - JSON_set());  
             TEST_OK(JSON_OFF - JSON_set());                                                                         
//brski_create_csr: creates csr
             TEST_NOK(brski_create_csr(NULL));                              
             TEST_OK(brski_create_csr(&csr));          
             if (csr.s == NULL)fprintf(stderr, "    brski_create_csr did not return csr \n");   
//brski_create_crt: creates certificate                          
             TEST_NOK(brski_create_crt( NULL, NULL, 0));    
             TEST_NOK(brski_create_crt(&ret_data, NULL, 0));                                    
             TEST_NOK(brski_create_crt(&ret_data, any.s, any.length)); 
             if (ret_data.s != NULL){
				 fprintf(stderr,"      ERROR: ret_data.s points to data and should be empty\n");
				 coap_free(ret_data.s);
				 ret_data.s = NULL;
				 ret_data.length = 0;				  
			 }                        			 
             TEST_NOK(brski_create_crt( NULL, csr.s, csr.length));                        
             TEST_OK(brski_create_crt(&certificate, csr.s, csr.length));                                     
             if (certificate.s == NULL) fprintf(stderr, "     brski_create_crt did not return certificate data  \n"); 
//brski_return_oid
	         mbedtls_x509_crt  cert;
	         mbedtls_x509_crt_init( &cert );
	         TEST_OK(mbedtls_x509_crt_parse_file( &cert, pledge_crt ));
             TEST_NOK(brski_return_oid( NULL, NULL, NULL));	         
             TEST_NOK(brski_return_oid( NULL, NULL, &ret_data));	         
             TEST_NOK(brski_return_oid( &cert.v3_ext, NULL, &ret_data));	
             TEST_NOK(brski_return_oid( &cert.v3_ext, &nothing, &ret_data));
             TEST_NOK(brski_return_oid( &cert.v3_ext, &any, &ret_data));	                                           	                              
             TEST_NOK(brski_return_oid( NULL, &oid_name, &ret_data));	         
             TEST_OK(brski_return_oid( &cert.v3_ext, &oid_name, &ret_data));
             if (ret_data.s == NULL) fprintf(stderr,"        brski_return_oid does not return expected data \n"); 
             else {
				 coap_free(ret_data.s);
				 ret_data.s = NULL;
				 ret_data.length = 0;				  				 
			 } 
			 mbedtls_x509_crt_free(&cert);                           		    			  
//brski_return_certificate
             TEST_NOK(brski_return_certificate(NULL));
             TEST_OK(brski_return_certificate(&ret_data));
             if (ret_data.s != NULL){
				 coap_free(ret_data.s);
				 ret_data.s = NULL;
				 ret_data.length = 0;
		     }
		     else fprintf(stderr, "     brski_return_certificate did not return expected data  \n");  
     		     			 		 
/*          CBOR ROUTINES   */ 	

   set_JSON(JSON_OFF);
//brski_cbor_voucherrequest: creates cbor_PVR 
             TEST_NOK(brski_cbor_voucherrequest(NULL, NULL, pledge_crt));
             TEST_NOK(brski_cbor_voucherrequest(&ret_data, NULL, pledge_crt));
             if (ret_data.s != NULL){
				 fprintf(stderr,"      ERROR: ret_data.s points to data and should be empty\n");
				 coap_free(ret_data.s);
				 ret_data.s = NULL;
				 ret_data.length = 0;				  
			 }
             TEST_NOK(brski_cbor_voucherrequest(NULL, &certificate, pledge_crt));
             TEST_NOK(brski_cbor_voucherrequest(&ret_data, &any, pledge_crt)); 
             if (ret_data.s != NULL){
				 fprintf(stderr,"      ERROR: ret_data.s points to data and should be empty\n");
				 coap_free(ret_data.s);
				 ret_data.s = NULL;
				 ret_data.length = 0;				  
			 } 
             TEST_OK(brski_cbor_voucherrequest(&cbor_PVR, &certificate, pledge_crt));
             if (cbor_PVR.s == NULL)
				 fprintf(stderr,"      ERROR: cbor_PVR.s is empty, should contain cbor voucher_request\n");		 
//brski_make_signed_rv	creates cose_sign_PVR and cbor_PVR
			 coap_free(cbor_PVR.s);		
             TEST_NOK(brksi_make_signed_rv(&nothing, &ret_data, file_name, comb_file)); 
             if (ret_data.s != NULL){
				 fprintf(stderr,"     brksi_make_signed_rv returns unexpected data \n"); 
				 coap_free(ret_data.s);
				 ret_data.s = NULL;
				 ret_data.length = 0;				  
			 }
             TEST_NOK(brksi_make_signed_rv(NULL, NULL, empty, comb_file)); 
             TEST_NOK(brksi_make_signed_rv(NULL, NULL, pledge_crt, comb_file)); 
             TEST_NOK(brksi_make_signed_rv(&any, NULL, pledge_crt, comb_file));             
             TEST_NOK(brksi_make_signed_rv(NULL, &ret_data, pledge_crt, comb_file)); 
            if (ret_data.s != NULL){
				 fprintf(stderr,"     brksi_make_signed_rv returns unexpected data \n");
				 coap_free(ret_data.s); 
				 ret_data.s = NULL;
				 ret_data.length = 0;				  
			 } 	                         			     			 
             TEST_OK(brksi_make_signed_rv(&cose_sign_PVR, &cbor_PVR, pledge_crt, comb_file)); 
             if ((cose_sign_PVR.s == NULL) || (cbor_PVR.s == NULL)) 
                                  fprintf(stderr, "     brksi_make_signed_rv did not return expected data  \n");                          
//brski_parse_cbor_voucher creates P_PVR
             TEST_NULL(brski_parse_cbor_voucher(NULL));                     		     
             TEST_PT(brski_parse_cbor_voucher(&cbor_PVR));
             P_PVR = (voucher_t *)pt;
             if (pt == NULL)fprintf(stderr, "        brski_parse_cbor_voucher does not return parsed voucher \n");
//brksi_create_cbor_voucher creates cbor_voucher                     		     
		     TEST_NOK(brski_create_cbor_voucher(NULL, NULL));
		     TEST_NOK(brski_create_cbor_voucher(NULL, parsed_empty));	
		     TEST_NOK(brski_create_cbor_voucher(&cbor_voucher, NULL));
             TEST_OK(brski_create_cbor_voucher(&cbor_voucher, parsed_empty));
             if (cbor_voucher.s != NULL){
				 coap_free(cbor_voucher.s);
				 cbor_voucher.s = NULL;
				 cbor_voucher.length = 0;
		     }  
		     else fprintf(stderr, "brski_create_cbor_voucher did not return expected data \n");  
		     TEST_OK(brski_create_cbor_voucher(&cbor_voucher, P_PVR)); 
             if (cbor_voucher.s == NULL) fprintf(stderr, "brski_create_cbor_voucher did not return expected data \n");		                   
//brski_cose_sign_payload creates cose_sign_PVR
		     char pkf[] = PLEDGE_KEY;
             char *key_file = pkf;
             char crt[] = PLEDGE_CRT;
             char *cert_file = crt;
             coap_free(cose_sign_PVR.s);
             TEST_NOK(brski_cose_sign_payload(NULL, NULL, empty));  
             TEST_NOK(brski_cose_sign_payload(NULL, NULL, key_file)); 
             TEST_NOK(brski_cose_sign_payload(NULL, NULL, cert_file)); 
             TEST_NOK(brski_cose_sign_payload(NULL, NULL, comb_file));
             TEST_NOK(brski_cose_sign_payload(NULL, &cbor_PVR, comb_file));
             TEST_NOK(brski_cose_sign_payload(&cose_sign_PVR, NULL, comb_file));                  
             TEST_NOK(brski_cose_sign_payload(&nothing, &nothing, file_name));
             TEST_NOK(brski_cose_sign_payload(&nothing, &cbor_PVR, file_name));  
             TEST_NOK(brski_cose_sign_payload(&cose_sign_PVR, &nothing,file_name));                            
             TEST_NOK(brski_cose_sign_payload(&cose_sign_PVR, &cbor_PVR,file_name));                                                        
             TEST_OK(brski_cose_sign_payload(&cose_sign_PVR,&cbor_PVR,comb_file));
             if (cose_sign_PVR.s == NULL)fprintf(stderr, "       brski_cose_sign_payload did not return cbor voucher_request data \n");                             
//brski_verify_cose_signature
             TEST_NULL(brski_verify_cose_signature(NULL, empty, pledge_ca )); 
             TEST_NULL(brski_verify_cose_signature(&cose_sign_PVR, empty, pledge_ca)); 
             TEST_NULL(brski_verify_cose_signature(NULL, pledge_crt, pledge_ca)); 
             TEST_NULL(brski_verify_cose_signature(&cose_sign_PVR, file_name, pledge_ca)); 
             TEST_PT(brski_verify_cose_signature(&cose_sign_PVR, pledge_crt, pledge_ca)); 
             if(pt != NULL) {
				 coap_string_t *sp = pt;
				 if (sp->s != NULL)coap_free(sp->s);
				 coap_free(sp);
			 } else fprintf(stderr, "       brski_verify_cose_signature did not return cbor voucher_request data \n");        			 
//brski_create_cbor_masa_request creates cbor_RVR and P_RVR
             TEST_NOK(brski_create_cbor_masa_request(NULL, NULL, NULL, empty));	
             TEST_NOK(brski_create_cbor_masa_request(NULL, P_PVR, NULL, empty));
             TEST_NOK(brski_create_cbor_masa_request(NULL, NULL, &cose_sign_PVR, empty));	
             TEST_NOK(brski_create_cbor_masa_request(NULL, NULL, NULL, pledge_crt));	
             TEST_NOK(brski_create_cbor_masa_request(NULL, P_PVR, &cose_sign_PVR, file_name));
             TEST_NOK(brski_create_cbor_masa_request(NULL, P_PVR, &cose_sign_PVR, pledge_crt));  
             TEST_NOK(brski_create_cbor_masa_request(&cbor_RVR, NULL, NULL, empty));	
             TEST_NOK(brski_create_cbor_masa_request(&cbor_RVR, P_PVR, NULL, empty));
             TEST_NOK(brski_create_cbor_masa_request(&cbor_RVR, NULL, &cose_sign_PVR, empty));	
             TEST_NOK(brski_create_cbor_masa_request(&cbor_RVR, NULL, NULL, pledge_crt));	
             TEST_NOK(brski_create_cbor_masa_request(&cbor_RVR,P_PVR,&cose_sign_PVR,file_name));                       			              			              		              		              			              		 
             TEST_OK(brski_create_cbor_masa_request(&cbor_RVR,P_PVR,&cose_sign_PVR,pledge_crt));
             if (cbor_RVR.s == NULL) fprintf(stderr, "       brski_create_cbor_masa_request did not return Registrar voucher_request data \n");
             else { 
			    TEST_PT(brski_parse_cbor_voucher(&cbor_RVR));
                P_RVR = (voucher_t *)pt;
                if (pt == NULL)fprintf(stderr, "        brski_parse_cbor_voucher does not return parsed Registrar voucher request data \n"); 
		     }
//brski_check_voucher           
             TEST_NOK(brski_check_voucher(NULL, NULL));	
             TEST_NOK(brski_check_voucher(NULL, &cbor_voucher));
             TEST_NOK(brski_check_voucher(&cbor_voucher, NULL));	
             TEST_NOK(brski_check_voucher(&any, &cbor_voucher));	
             TEST_NOK(brski_check_voucher(&cbor_voucher, &any));	
             TEST_NOK(brski_check_voucher(&any, &any));	
             TEST_NOK(brski_check_voucher(&json_voucher, &json_voucher));	 
             TEST_NOK(brski_check_voucher(&json_voucher, &cbor_voucher));
             TEST_NOK(brski_check_voucher(&cbor_voucher, &json_voucher));	             	             	             	                         	
             TEST_OK(brski_check_voucher(&cbor_voucher, &cbor_voucher));
//brski_cbor_voucherstatus creates cbor_status
             TEST_NOK(brski_cbor_voucherstatus(NULL));                        
             TEST_OK(brski_cbor_voucherstatus(&cbor_status));
             if (cbor_status.s == NULL)fprintf(stderr,"     brski_cbor_voucherstatus did not return expected data \n");   
//brski_cbor_readstatus creates parsed_status
  status_t      *parsed_status  = coap_malloc(sizeof(status_t));
  memset(parsed_status, 0, sizeof(status_t));   /* parsed status from json- or cbor-status */  
             TEST_NOK(brski_cbor_readstatus(NULL, NULL));
             TEST_NOK(brski_cbor_readstatus(&any, parsed_status));
             TEST_NOK(brski_cbor_readstatus(&nothing , parsed_status));                          
             TEST_OK(brski_cbor_readstatus(&cbor_status, parsed_status));                                             

                        /* liberate created test space  */
 
             if(csr.s != NULL)coap_free(csr.s);
             csr.s = NULL;
             if (certificate.s != NULL)coap_free(certificate.s); 
             certificate.s = NULL;	
             if(cbor_PVR.s != NULL)coap_free(cbor_PVR.s);
             cbor_PVR.s = NULL;
             if(cose_sign_PVR.s != NULL)coap_free(cose_sign_PVR.s);
             cose_sign_PVR.s = NULL;
             if(cbor_voucher.s != NULL)coap_free(cbor_voucher.s);
             cbor_voucher.s = NULL;
             if(cbor_RVR.s != NULL)coap_free(cbor_RVR.s); 
             cbor_RVR.s = NULL;               			 
             if(cbor_status.s != NULL)coap_free(cbor_status.s);
             cbor_status.s = NULL;
             if (P_PVR !=  NULL)remove_voucher(P_PVR);
             P_PVR = NULL;
             if (P_RVR !=  NULL)remove_voucher(P_RVR); 
             P_RVR = NULL;            
             if(parsed_status != NULL)remove_status(parsed_status); 
             parsed_status = NULL;             
       /* create csr and certificate needed by JSON, CMS routines  */         		
             int ok = brski_create_csr(&csr);          
             if (csr.s == NULL)fprintf(stderr, "    brski_create_csr did not return csr \n");   
             ok = brski_create_crt(&certificate, csr.s, csr.length);                
             if (certificate.s == NULL) fprintf(stderr, "     brski_create_crt did not return certificate data  \n"); 
             if (ok != 0){
				 printf("certificate is not created \n");
				 exit(1);
			 }
			                                         
/* test all procedures in brski.c which are exported in brski.h */             			 
                                     
/*          JSON routines  */

    printf(" start JSON routines \n");
	set_JSON(JSON_ON);	
//brski_json_voucherrequest: creates json_PVR  
             TEST_NOK(brski_json_voucherrequest(NULL, NULL, pledge_crt));
             TEST_NOK(brski_json_voucherrequest(&ret_data, NULL, pledge_crt));
             if (ret_data.s != NULL){
				 fprintf(stderr,"      ERROR: ret_data.s points to data and should be empty\n");
				 coap_free(ret_data.s);
				 ret_data.s = NULL;
				 ret_data.length = 0;				  
			 }
             TEST_NOK(brski_json_voucherrequest(NULL, &certificate, pledge_crt));
             TEST_NOK(brski_json_voucherrequest(&ret_data, &any, pledge_crt)); 
             if (ret_data.s != NULL){
				 fprintf(stderr,"      ERROR: ret_data.s points to data and should be empty\n");
				 coap_free(ret_data.s);
				 ret_data.s = NULL;
				 ret_data.length = 0;				  
			 }                                                               
             TEST_OK(brski_json_voucherrequest(&json_PVR, &certificate, pledge_crt)); 
             if (json_PVR.s == NULL)
				        fprintf(stderr,"      ERROR: json_PVR.s is empty, should contain json voucher_request\n");
			 else coap_free(json_PVR.s);
			 json_PVR.s = NULL;
//brski_make_signed_rv creates cms_sign_PVR	and json_PVR	
             TEST_NOK(brksi_make_signed_rv(&nothing, &ret_data, file_name, comb_file)); 
             if (ret_data.s != NULL){
				 fprintf(stderr,"     brksi_make_signed_rv returns unexpected data \n"); 
				 coap_free(ret_data.s);
				 ret_data.s = NULL;
				 ret_data.length = 0;				  
			 }
             TEST_NOK(brksi_make_signed_rv(NULL, NULL, empty, comb_file)); 
             TEST_NOK(brksi_make_signed_rv(NULL, NULL, pledge_crt, comb_file)); 
             TEST_NOK(brksi_make_signed_rv(&any, NULL, pledge_crt, comb_file));             
             TEST_NOK(brksi_make_signed_rv(NULL, &ret_data, pledge_crt, comb_file)); 
             if (ret_data.s != NULL){
				 fprintf(stderr,"     brksi_make_signed_rv returns unexpected data \n");
				 coap_free(ret_data.s); 
				 ret_data.s = NULL;
				 ret_data.length = 0;				  
			 } 			 	                         			     			 
             TEST_OK(brksi_make_signed_rv(&cms_sign_PVR, &json_PVR, pledge_crt, comb_file)); 
             if ((cms_sign_PVR.s == NULL) || (json_PVR.s == NULL)) fprintf(stderr, "     brksi_make_signed_rv did not return expected data  \n");          
//brski_parse_json_voucher creates P_PVR         
             TEST_NULL(brski_parse_json_voucher(NULL));
             TEST_PT(brski_parse_json_voucher(&json_PVR));            
             P_PVR = (voucher_t *)pt;
             if (pt == NULL)fprintf(stderr, "        brski_parse_json_voucher does not return parsed voucher \n");           
//brski_create_json_voucher	creates json_voucher	           
		     TEST_NOK(brski_create_json_voucher(NULL, NULL));	
		     TEST_NOK(brski_create_json_voucher(NULL, parsed_empty));	
		     TEST_NOK(brski_create_json_voucher(&json_voucher, NULL));		     
             TEST_OK(brski_create_json_voucher(&json_voucher, parsed_empty));
             if (json_voucher.s != NULL){
				 coap_free(json_voucher.s);
				 json_voucher.s = NULL;
				 json_voucher.length = 0;
		     }  
		     else fprintf(stderr, "brski_create_json_voucher did not return expected data \n");  
		     TEST_OK(brski_create_json_voucher(&json_voucher, P_PVR));
             if (json_voucher.s == NULL) fprintf(stderr, "      brski_create_json_voucher did not return expected data \n");
//brski_cms_sign_payload creates cms_sign_PVR  
             free(cms_sign_PVR.s);    /* allocated by openssl */ 
             cms_sign_PVR.s = NULL;  
             TEST_NOK(brski_cms_sign_payload(NULL, NULL, empty));  
             TEST_NOK(brski_cms_sign_payload(NULL, NULL, comb_file)); 
             TEST_NOK(brski_cms_sign_payload(NULL, &json_PVR, comb_file));       			                           
             TEST_NOK(brski_cms_sign_payload(&cms_sign_PVR, NULL, comb_file));                                   
             TEST_NOK(brski_cms_sign_payload(&nothing, &nothing, file_name));                      
             TEST_NOK(brski_cms_sign_payload(&nothing, &json_PVR, file_name));                         
             TEST_NOK(brski_cms_sign_payload(&cms_sign_PVR, &nothing, file_name));                                                        
             TEST_NOK(brski_cms_sign_payload(&cms_sign_PVR, &json_PVR, file_name));                                          
             TEST_OK(brski_cms_sign_payload(&cms_sign_PVR, &json_PVR, comb_file)); 
//brski_verify_cms_signature
             TEST_NULL(brski_verify_cms_signature(NULL, empty, empty));            
             TEST_NULL(brski_verify_cms_signature(&cose_sign_PVR, empty, empty));              
             TEST_NULL(brski_verify_cms_signature(NULL, pledge_ca, file_name)); 
             TEST_NULL(brski_verify_cms_signature(NULL, file_name, pledge_crt));              
             TEST_NULL(brski_verify_cms_signature(&cose_sign_PVR, file_name, file_name)); 
             TEST_NULL(brski_verify_cms_signature(&cose_sign_PVR, file_name, pledge_crt));
             TEST_NULL(brski_verify_cms_signature(&cose_sign_PVR, pledge_ca, file_name));                                                                  
             TEST_PT(brski_verify_cms_signature(&cms_sign_PVR, pledge_ca, pledge_crt));
             if(pt != NULL) {
				 coap_string_t *sp = pt;
				 if (sp->s != NULL)coap_free(sp->s);
				 coap_free(sp);
				 sp->s = NULL;
				 sp->length = 0;
			 } else fprintf(stderr, "       brski_verify_cms_signature did not return cbor voucher_request data \n");                                                                                     			              		   
//brski_create_json_masa_request creates json_RVR and P_RVR
             TEST_NOK(brski_create_json_masa_request(NULL, NULL, NULL, empty));	
             TEST_NOK(brski_create_json_masa_request(NULL, P_PVR, NULL, empty));
             TEST_NOK(brski_create_json_masa_request(NULL, NULL, &cms_sign_PVR, empty));	
             TEST_NOK(brski_create_json_masa_request(NULL, NULL, NULL, pledge_crt));	
             TEST_NOK(brski_create_json_masa_request(NULL, P_PVR, &cms_sign_PVR, file_name));
             TEST_NOK(brski_create_json_masa_request(NULL, P_PVR, &cms_sign_PVR, pledge_crt));  
             TEST_NOK(brski_create_json_masa_request(&json_RVR, NULL, NULL, empty));	
             TEST_NOK(brski_create_json_masa_request(&json_RVR, P_PVR, NULL, empty));
             TEST_NOK(brski_create_json_masa_request(&json_RVR, NULL, &cms_sign_PVR, empty));	
             TEST_NOK(brski_create_json_masa_request(&json_RVR, NULL, NULL, pledge_crt));	
             TEST_NOK(brski_create_json_masa_request(&json_RVR,P_PVR,&cms_sign_PVR,file_name));     
             TEST_OK(brski_create_json_masa_request(&json_RVR,P_PVR,&cms_sign_PVR,pledge_crt));
             if (json_RVR.s == NULL) fprintf(stderr, "       brski_create_json_masa_request did not return cbor voucher_request data \n");
             else { 
			    TEST_PT(brski_parse_json_voucher(&json_RVR));
                P_RVR = (voucher_t *)pt;
                if (pt == NULL)fprintf(stderr, "        brski_parse_json_voucher does not return parsed Registrar voucher request data \n"); 
		     }	
//brski_check_voucher             
             TEST_OK(brski_check_voucher(&json_voucher, &json_voucher));
             TEST_NOK(brski_check_voucher(&cbor_voucher, &cbor_voucher));	
//brski_json_voucherstatus creates json_status
             TEST_NOK(brski_json_voucherstatus(NULL));                        
             TEST_OK(brski_json_voucherstatus(&json_status));
//brski_json_readstatus creates parsed_status
  parsed_status  = coap_malloc(sizeof(status_t));
  memset(parsed_status, 0, sizeof(status_t));   /* parsed status from json- or cbor-status */  
             TEST_NOK(brski_json_readstatus(NULL, NULL));
             TEST_NOK(brski_json_readstatus(&any, parsed_status));
             TEST_NOK(brski_json_readstatus(&nothing , parsed_status));                          
             TEST_OK(brski_json_readstatus(&json_status, parsed_status));             
          printf("end of JSON routines \n");                                        
      
/*         parsed item routines  */
         printf("\ntest parsed items \n\n");                     
//brski_check_pledge_request            
             TEST_NOK(brski_check_pledge_request(NULL)); 
             TEST_NOK(brski_check_pledge_request(parsed_empty));  
             TEST_NOK(brski_check_pledge_request(P_PVR)); 
             TEST_OK(brski_check_pledge_request(P_RVR)); 
//brski_audit_response creates log
             TEST_NULL(brski_audit_response(NULL));  
             TEST_PT(brski_audit_response(P_RVR));              
             if (pt != NULL){
				 coap_string_t *temp = (coap_string_t *)pt;
				 if (temp->s != NULL)coap_free(temp->s);
				 coap_free(temp);
		     }           
             TEST_PT(brski_audit_response(P_PVR));  
             if (pt == NULL)fprintf(stderr,"     brski_audit_response did not return expected data \n");
             else log = (coap_string_t *)pt;         
//brski_parse_audit creates audit
             TEST_NULL(brski_parse_audit(NULL));
             TEST_NULL(brski_parse_audit(&any));
             TEST_NULL(brski_parse_audit(&nothing));                                              
             TEST_PT(brski_parse_audit(log)); 
             if (pt == NULL)fprintf(stderr,"     brski_parse_audit did not return expected data \n");          
             else audit = (audit_t *)pt;                          
//remove_status
             TEST_VOID(remove_status(NULL));
             fprintf(stderr,"OK return \n");                
             TEST_VOID(remove_status(parsed_status));
             fprintf(stderr,"OK return \n");                             
             parsed_status  = coap_malloc(sizeof(status_t));
             memset(parsed_status, 0, sizeof(status_t));         
//brski_validate
             TEST_VOID(brski_validate(NULL, NULL));
             fprintf(stderr,"OK return \n");                            
             TEST_VOID(brski_validate(NULL, audit));
             fprintf(stderr,"OK return \n");                            
             TEST_VOID(brski_validate(parsed_status, NULL));
             fprintf(stderr,"OK return \n");                                                             
             TEST_VOID(brski_validate(parsed_status, audit)); 
             fprintf(stderr,"OK return \n");                                         
//remove_audit 
  audit_t       *empty_audit      = coap_malloc(sizeof(audit_t));
  memset(empty_audit, 0, sizeof(audit_t));      /* empty audit */
             TEST_VOID(remove_audit(NULL));
             fprintf(stderr,"OK return \n");               
             TEST_VOID(remove_audit(audit)); 
             fprintf(stderr,"OK return \n"); 
             audit = NULL;                            
             TEST_VOID(remove_audit(empty_audit));
             fprintf(stderr,"OK return \n");  
             empty_audit = NULL;                                  		             		            		             		 
//remove_voucher
  voucher_t     *empty_voucher     = coap_malloc(sizeof(voucher_t));
  memset(empty_voucher, 0, sizeof(voucher_t));   /* empty parsed voucher */
             TEST_VOID(remove_voucher(NULL));
             fprintf(stderr,"OK return \n");              
             TEST_VOID(remove_voucher(P_PVR));
             P_PVR = NULL;
             fprintf(stderr,"OK return \n");             
             TEST_VOID(remove_voucher(P_RVR));
             P_RVR = NULL;
             fprintf(stderr,"OK return \n");              
             TEST_VOID(remove_voucher(empty_voucher));
             empty_voucher = NULL;
             fprintf(stderr,"OK return \n");      
                               /* liberate created test space  */

             if(csr.s != NULL)coap_free(csr.s);
             csr.s = NULL;
             if (certificate.s != NULL)coap_free(certificate.s); 
             certificate.s = NULL;	
             if(cbor_PVR.s != NULL)coap_free(cbor_PVR.s);
             cbor_PVR.s = NULL;
             if (json_PVR.s != NULL)coap_free(json_PVR.s);
             json_PVR.s = NULL;
             if(cose_sign_PVR.s != NULL)coap_free(cose_sign_PVR.s);
             cose_sign_PVR.s = NULL;
             if(cbor_voucher.s != NULL)coap_free(cbor_voucher.s);
             cbor_voucher.s = NULL;
             if(json_voucher.s != NULL)coap_free(json_voucher.s);
             json_voucher.s = NULL;            
             if(cbor_RVR.s != NULL)coap_free(cbor_RVR.s); 
             cbor_RVR.s = NULL; 
             if (json_RVR.s != NULL)coap_free(json_RVR.s);
             json_RVR.s = NULL;             			 
             if(cbor_status.s != NULL)coap_free(cbor_status.s);
             cbor_status.s = NULL;
             if (P_PVR !=  NULL)remove_voucher(P_PVR);
             P_PVR = NULL;
             if (P_RVR !=  NULL)remove_voucher(P_RVR); 
             P_RVR = NULL;  
             if (audit != NULL)remove_audit(audit);
             audit = NULL;          
             if(parsed_status != NULL)remove_status(parsed_status); 
             parsed_status = NULL;
             if (json_status.s != NULL)coap_free(json_status.s);
             json_status.s = NULL;			 
			 free(cms_sign_PVR.s); /* allocated by openssl */  
			 if (log != NULL){                                   
		        if (log->s != NULL)coap_free(log->s);
			    coap_free(log); 
			    log = NULL; 
			}   
			if (parsed_empty != NULL) coap_free(parsed_empty);  
			parsed_empty = NULL;    
      fprintf(stderr,"     END of BRSKI procedure test \n");                                                                      
}


/**
 * Sets global URI options according to the URI passed as @p arg.
 * This function returns 0 on success or -1 on error.
 *
 * @param arg             The URI string.
 * @param create_uri_opts Flags that indicate whether Uri-Host and
 *                        Uri-Port should be suppressed.
 * @return 0 on success, -1 otherwise
 */
static int
cmdline_uri(client_request_t *client, char *arg, int create_uri_opts) {

  coap_uri_t uri;
  uri.scheme = COAP_URI_SCHEME_COAP;
  uri.port = COAP_DEFAULT_PORT;
  if (strlen(arg) > 1){
    if (coap_split_uri((unsigned char *)arg, strlen(arg), &uri) < 0) {
      coap_log(LOG_ERR, "invalid CoAP URI\n");
      return -1;
    }
    if (uri.scheme==COAP_URI_SCHEME_COAPS && !RELIABLE && !coap_dtls_is_supported()) {
      coap_log(LOG_EMERG,
               "coaps URI scheme not supported in this version of libcoap\n");
      return -1;
    }

    if ((uri.scheme==COAP_URI_SCHEME_COAPS_TCP || (uri.scheme==COAP_URI_SCHEME_COAPS && RELIABLE)) && !coap_tls_is_supported()) {
      coap_log(LOG_EMERG,
            "coaps+tcp URI scheme not supported in this version of libcoap\n");
      return -1;
    }

    if (uri.scheme==COAP_URI_SCHEME_COAP_TCP && !coap_tcp_is_supported()) {
      /* coaps+tcp caught above */
      coap_log(LOG_EMERG,
            "coap+tcp URI scheme not supported in this version of libcoap\n");
      return -1;
    } /* if uri.scheme  */
  }  /* if strlen(arg)  */
  set_scheme( client, uri.scheme); 
  coap_string_t *tmp = (coap_string_t *) &(uri.host); /* uri.host is const */
  set_host( client, tmp);
  tmp = (coap_string_t *) &(uri.path); /* uri.path is const */
  set_path( client, tmp);
  set_port( client, uri.port);

  return 0;
}

typedef enum {START, REQUEST_VOUCHER, VOUCHER_STATUS, CRTS, ENROLL, CLOSE} test_state_t;

int
main(int argc, char **argv) {
  /* start application */
  test_state_t     testing = START;
  client_request_t *client = NULL;
  client_request_t *server = NULL;   /* not needed */ 
  coap_tick_t now;
  char addr_str[NI_MAXHOST] = "::";
  char port_str[NI_MAXSERV] = COAP_PORT;
  int opt;
  unsigned wait_ms;
  coap_time_t t_last = 0;
//  int coap_fd;
//  fd_set m_readfds;
//  int nfds = 0; 

#ifndef _WIN32
  struct sigaction sa;
#endif
  client = client_request_init();
  server = client_request_init();  /* not needed */  
  clock_offset = time(NULL);
  set_JSON(JSON_OFF); /* can be set on with -J option */  	
  coap_log_t log_level = LOG_WARNING;
  coap_dtls_set_log_level(log_level);
  coap_set_log_level(log_level);

  /* initalize time storage on heap */
    time_t rawtime;
    time(&rawtime); 
    struct tm tm_buf;
    memset(&tm_buf, 0, sizeof(struct tm));   
    gmtime_r(&rawtime, &tm_buf);  
  while ((opt = getopt(argc, argv, "v:h:")) != -1) {
    switch (opt) {
    case 'v' :
      log_level = strtol(optarg, NULL, 10);
      coap_set_log_level(log_level);
      break;
    case 'h' :           
    default:
      usage( argv[0], LIBCOAP_PACKAGE_VERSION );
      exit( 1 );
    }
  }

/* do tests locally in this process */ 
 
    do_local_tests();
 
/* do tests by invoking registrar remotely */
  coap_startup();
  coap_string_t *tmp_host = NULL;
  uint16_t tmp_port = 0;
  if (optind < argc) {
     if (cmdline_uri(client, argv[optind], CREATE_URI_OPTS) < 0) {
       usage( argv[0], LIBCOAP_PACKAGE_VERSION );
       exit(1);
     }
     tmp_host = get_host( client);
     tmp_port = get_port( client);    
  }  else {
     usage( argv[0], LIBCOAP_PACKAGE_VERSION );
     exit(1);
  }
  set_certificates(client, int_cert_file, int_ca_file); /* set certificate files */ 
  set_certificates(server, int_cert_file, int_ca_file); /* set certificate files */   
  int ok = pledge_get_contexts(client, server, addr_str, port_str);
  if (ok == 1) return -1;
#ifdef _WIN32
  signal(SIGINT, handle_sigint);
#else
  memset (&sa, 0, sizeof(sa));
  sigemptyset(&sa.sa_mask);
  sa.sa_handler = handle_sigint;
  sa.sa_flags = 0;
  sigaction (SIGINT, &sa, NULL);
  sigaction (SIGTERM, &sa, NULL);
  /* So we do not exit on a SIGPIPE */
  sa.sa_handler = SIG_IGN;
  sigaction (SIGPIPE, &sa, NULL);
#endif
  int silent = 1;
  wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
    coap_string_t new_host;
    new_host.length = tmp_host->length;
    new_host.s = coap_malloc(tmp_host->length+1);
    memcpy(new_host.s, tmp_host->s, tmp_host->length); /* const pointer */
    new_host.s[tmp_host->length] = 0;
    set_host( client, &new_host);
    set_port( client, tmp_port);
    set_JSON(JSON_OFF);
    make_ready();
    int cnt = 0;    /* divisor for payload */
    int ct  = COAP_MEDIATYPE_APPLICATION_CBOR;
    char *register_cert = NULL;
    char *pledge_comb = NULL;
    char cmc[]       = CA_MASA_CRT;
    char msc[]       = MASA_SRV_CRT;
    char psd[]       = PLEDGE_SERVER_DER;    /* contains registrar certificate in DER */  
    char pec[]       = PLEDGE_ED25519_CRT;    /* contains random certificate */ 
    char nokey[]     = PLEDGE_CRT;
    char nocrt[]     = PLEDGE_KEY;
    char noES256[]   = PLEDGE_ED25519_COMB;
    char wr_issuer[] = "./certificates/wrong_certificates/certs/pledge_wr_issuer-comb.crt";
    char wr_url[]    = "./certificates/wrong_certificates/certs/pledge_wr_url-comb.crt";
    char no_url[]    = "./certificates/wrong_certificates/certs/pledge_no_url-comb.crt";  
    char wr_valid[]  = "./certificates/wrong_certificates/certs/pledge_wr_valid-comb.crt"; 
   
/* certificates for DTLS connection  */ 
  static char cert_nm[] = PLEDGE_COMB; 
  static char ca_nm[] = CA_MASA_CRT;
  char *ca = ca_nm;
  char *cert = cert_nm;
  set_certificates( client, cert, ca);
  
/* test all procedures in brski.c which are exported in brski.h */                 
    while ( !quit ) {
      int result;
      if (is_ready()){ /* remote action is done */
	    switch (testing) {
		   case START:
/*   connect pledge to registrar  */ 
             TEST_OK(test_connect_pledge( client)); /* make DTLS connection */                        
/* test /.well-known/brski/rv with differen payload sizes */
             register_cert = pec;	/* file name is wrong  */
             cnt = 1;   /* 0 < cnt < 11; determines that cnt/10 of payload is transmitted  */
 	         TEST_NOK(test_voucher_request( client, register_cert, pledge_comb, cnt));         	                   
	         register_cert = psd; /* correct file name */ 
	         pledge_comb = cert_nm;
 //            testing = REQUEST_VOUCHER;	
             testing = REQUEST_VOUCHER;              
	         TEST_OK(test_voucher_request( client, register_cert, pledge_comb, cnt));  	         
	         break;
	       case REQUEST_VOUCHER: 
	         cnt++;  
	         if (cnt > 1 && cnt < 11){
		         TEST_NOK(pledge_arrived(registrar_code, &registrar_response));
		         TEST_OK(test_voucher_request( client, register_cert, pledge_comb, cnt));       
             } else if (cnt == 11){
		         TEST_OK(pledge_arrived(registrar_code, &registrar_response));	
/* test returned voucher  */		                      	      		                  	            		      
		         char *ca_name = cmc;
                 char *masa_serv_name = msc;
		         TEST_OK(test_status_response( client, ca_name, masa_serv_name));      		      
                 masa_serv_name = cmc;
		         TEST_NOK(test_status_response( client, ca_name, masa_serv_name));     		      
		          ca_name = msc;
                  masa_serv_name = cmc;	
 		          TEST_NOK(test_status_response( client, ca_name, masa_serv_name));               
		          ca_name = cmc;
                  masa_serv_name = msc;
		          TEST_NOK(test_status_response( client, ca_name, masa_serv_name)); 
/* test /.well-known/brski/vs   */                  
                  testing = VOUCHER_STATUS;
                  cnt  = 1;
	              TEST_OK(test_status_voucher( client, cnt));  
	          } else  goto exit;
	         break;
	       case VOUCHER_STATUS: 	       
	          cnt++;
			  if (cnt == 11)TEST_OK(pledge_arrived(registrar_code, &registrar_response));
			  else 	TEST_NOK(pledge_arrived(registrar_code, &registrar_response));
			  if ( cnt > 0 && cnt < 11)TEST_OK(test_status_voucher( client, cnt));  
			  else {
/* test /.well-known/est/crts  */
			    testing = CRTS;
			    TEST_OK( test_get_certificate( client));
		  	  }
			  break;
		   case CRTS:
		     TEST_OK(pledge_arrived(registrar_code, &registrar_response));
/* test /.well-knwon/est/sen    */
             testing = 	ENROLL;
             ct = COAP_MEDIATYPE_APPLICATION_CBOR;
             cnt = 1;
		     TEST_OK( test_enroll_certificate( client, ct, cnt));
		     break;
		   case ENROLL:
		     cnt++;
		     if (cnt == 11)
		           TEST_OK(pledge_arrived(registrar_code, &registrar_response));
		     else  TEST_NOK(pledge_arrived(registrar_code, &registrar_response));
		     if ( cnt > 0 && cnt < 11)TEST_OK(test_enroll_certificate( client, ct, cnt));
		     else if (cnt == 11){
				 TEST_OK(test_enroll_certificate( client, COAP_MEDIATYPE_TEXT_PLAIN, 10));
			 }
			 if (cnt > 11) {
/* conclude with invalid pledge certificates   */
   fprintf(stderr, "\nTEST wrong Pledge certificates \n\n");
				 testing = CLOSE;
				 pledge_comb = nokey;  /* no key included  */
				 fprintf(stderr,"No key included in comb file \n");
				 TEST_NOK(test_voucher_request( client, register_cert, pledge_comb, 10)); 
				 fprintf(stderr,"No certificate included in comb file \n");
				 pledge_comb = nocrt;  /* no certificate included  */
				 TEST_NOK(test_voucher_request( client, register_cert, pledge_comb, 10)); 
		         fprintf(stderr,"NO ES256 key used in certificate \n");
		         Clean_client_request();
	             client = client_request_init();
                 server = client_request_init();  /* not needed */  		
		         pledge_comb = noES256;  /* ED25519 not supported crypto algo */
		         set_certificates( client, pledge_comb, ca);
                 ok = pledge_get_contexts(client, server, addr_str, port_str);
                 if (ok == 1) return -1;
                 set_host( client, &new_host);
                 set_port( client, tmp_port);      		
		         ok = test_connect_pledge( client); /* make DTLS connection */                        
				 TEST_NOK(test_voucher_request( client, register_cert, pledge_comb, 10));
				 cnt = 0;
			 }   
             else break;
		   case CLOSE:
		   /* make new dtls connections with new connection files  */
		     cnt++;
		     if (cnt < 6)TEST_NOK(pledge_arrived(registrar_code, &registrar_response));
		     if (cnt == 1) {
				 Clean_client_request();
				 pledge_comb = wr_issuer;  /* wrong issuer: Registrar */
				 fprintf(stderr,"Certificate is issued by Registrar     .................");
			 }
		     if (cnt == 2) {
				 Clean_client_request();
				 pledge_comb = wr_url;  /* wrong MASAurl */
				 fprintf(stderr,"Certificate contains unknown MASAurl    .................");
			 }
		     if (cnt == 3) {
                 Clean_client_request(); 				 
				 pledge_comb = no_url;  /* no MASAurl    */
				 fprintf(stderr,"Certificate does not contain MASAurl    ................");
			 }
		     if (cnt == 4) {
                 Clean_client_request(); 				 
				 pledge_comb = wr_valid;  /* no valid expiration date    */
				 fprintf(stderr,"Certificate has invalid expiration date ..................");
			 }			 
		     if (cnt > 4) goto exit;
		     client = client_request_init();
             server = client_request_init();  /* not needed */  
		     set_certificates( client, pledge_comb, ca);
		     set_certificates( server, pledge_comb, ca);	     
             ok = pledge_get_contexts(client, server, addr_str, port_str);
             if (ok == 1) return -1;
             set_host( client, &new_host);
             set_port( client, tmp_port);
		     fprintf(stderr,"make new DTLS connection \n");
		     ok = test_connect_pledge( client); /* make DTLS connection */                        	    		     
		     TEST_OK(test_voucher_request( client, register_cert, pledge_comb, 10)); 
		     break;
		   default:
		      goto exit;            	            
        }  /* switch */
        reset_ready();
	}  /*if is ready */
     /* result is time spent in coap_io_process()  */
      result = coap_io_process( client->ctx, wait_ms );
      if ( result < 0 ) {
         break;
      } else if ( result && (unsigned)result < wait_ms ) {
      /* decrement if there is a result wait time returned */
         wait_ms -= result;
      } else {
      /*
       * result == 0, or result >= wait_ms
       * (wait_ms could have decremented to a small value, below
       * the granularity of the timer in coap_io_process() and hence
       * result == 0)
       */
        wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
      }
    if (time_resource) {
      coap_time_t t_now;
      unsigned int next_sec_ms;

      coap_ticks(&now);
      t_now = coap_ticks_to_rt(now);
      if (t_last != t_now) {
        /* Happens once per second */
        t_last = t_now;
        coap_resource_notify_observers(time_resource, NULL);
      }
      /* need to wait until next second starts if wait_ms is too large */
      next_sec_ms = 1000 - (now % COAP_TICKS_PER_SECOND) *
                           1000 / COAP_TICKS_PER_SECOND;
      if (next_sec_ms && next_sec_ms < wait_ms)
        wait_ms = next_sec_ms;
    }

  }  /* while !quit */
exit:
  if (request_voucher.s != NULL)coap_free(request_voucher.s);
  if( registrar_response.s != NULL) coap_free(registrar_response.s);
  coap_free(new_host.s);
  Clean_client_request();
  fprintf(stderr,"end of client: coap_malloc loss is %d  \n", (int)coap_nr_of_alloc());                                                  
}

