/*
 *  SSL server demonstration program
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
 * adaptations to masa server by Peter van der stok
 * vanderstok consultancy
 *
 */

#include "mbedtls/config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/certs.h"
#include "mbedtls/x509.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"
#include "mbedtls/base64.h"
#include "mbedtls/ssl_cache.h"
#include "mbedtls/oid.h"

#include "brski.h"
#include "str.h"
#include "brski_util.h"
#include "pdu.h"

#if defined(MBEDTLS_SSL_CACHE_C)
#include "mbedtls/ssl_cache.h"
#endif

#define RESULT_LEN  130    /* maximum length of htpp result */
#define HTTP_RESPONSE    "HTTP/1.0 "
#define HTTP_FOLLOW_CMS  "\r\nContent-Type: application/voucher-cms+json\r\n\r\n"
#define HTTP_FOLLOW_COSE "\r\nContent-Type: application/voucher-cose+cbor\r\n\r\n"
#define HTTP_FOLLOW_CBOR "\r\nContent-Type: application/cbor\r\n\r\n"
#define HTTP_FOLLOW_JSON "\r\nContent-Type: application/json\r\n\r\n"
#define HTTP_FOLLOW_TEXT "\r\nContent-Type: application/text\r\n\r\n"
#define MASA_PORT        "4433" 
#define NI_MAXSERV       6
char port_str[NI_MAXSERV] = MASA_PORT;

#define DEBUG_LEVEL 0   /* for mbedtls debugging traces */
int masa_debug = 0;

#define PUT    "PUT"
#define POST   "POST"
#define GET    "GET"
#define DELETE "DELETE"

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

#define CHECK( x )                                                      \
    do {                                                                \
        int CHECK__ret_ = ( x );                                        \
        if( CHECK__ret_ < 0 )                                          \
        {                                                               \
            char CHECK__error_[100];                                    \
            mbedtls_strerror( CHECK__ret_,                              \
                              CHECK__error_, sizeof( CHECK__error_ ) ); \
            coap_log(LOG_ERR, "%s -> %s\n", #x, CHECK__error_ );        \
            goto exit;                                                  \
        }                                                               \
    } while( 0 )


typedef struct pki_sni_entry {
  char *sni;
  mbedtls_x509_crt *cacert;
  mbedtls_x509_crt *public_cert;
  mbedtls_pk_context *private_key;
} pki_sni_entry;


char*
get_san_or_cn_from_cert(mbedtls_x509_crt *crt)
{
  if (crt) {
    mbedtls_asn1_named_data * cn_data = NULL;

    if (crt->ext_types & MBEDTLS_X509_EXT_SUBJECT_ALT_NAME) {
      mbedtls_asn1_sequence *seq = &crt->subject_alt_names;
      while (seq && seq->buf.p == NULL) {
        seq = seq->next;
      }
      if (seq) {
        // Return the Subject Alt Name 
        return strndup((const char *)seq->buf.p,
                             seq->buf.len);
      }
    }
    cn_data = mbedtls_asn1_find_named_data(&crt->subject,
                                           MBEDTLS_OID_AT_CN,
                                           MBEDTLS_OID_SIZE(MBEDTLS_OID_AT_CN));
    if (cn_data) {
//       Return the Common Name 
      return (char *)strndup((const char *)cn_data->val.p,
                             cn_data->val.len);
    }
  }
  return NULL;
}

int 
cert_verify_callback_mbedtls(void *data UNUSED_PARAM, 
                             mbedtls_x509_crt *crt,
                             int depth, 
                             uint32_t *flags UNUSED_PARAM)
{
  char *cn = get_san_or_cn_from_cert(crt);
  if (masa_debug > 0)
     printf( "CN '%s' presented by client (%s)\n",
                  cn, depth ? "CA" : "Certificate");
  if (depth == 0){
	if (masa_debug > 0)printf(" certificate to be written to %s \n", MASA_CLIENT_DER);
    char file[] = MASA_CLIENT_DER;
    coap_string_t contents = {.length = crt->raw.len, .s = NULL};
    contents.s = malloc(crt->raw.len);
    memcpy(contents.s, crt->raw.p, crt->raw.len);
    uint8_t ok = write_file_mem(file, &contents); 
    free(contents.s); 
    if (ok != 0)printf( "certificate is not written to %s \n", MASA_CLIENT_DER); 
  }   
  return 0;
}

int sni_callback( void *p_info, mbedtls_ssl_context *ssl,
              const unsigned char *name, size_t name_len )
{
	if (masa_debug > 0){
	  printf("\n\nsni_callback with name:  ");
	  for (uint8_t qq = 0; qq < (uint8_t)name_len; qq++)printf("%c",name[qq]);
	  printf("\n");
    }
    pki_sni_entry *cur = (pki_sni_entry *)p_info;
    mbedtls_ssl_set_hs_ca_chain( ssl, cur->public_cert, NULL );
    return( mbedtls_ssl_set_hs_own_cert( ssl, cur->public_cert, cur->private_key ) );

    /* certificate not found: return an error code */
    return( -1 );
}


int
min(int a, int b){
	if (a < b) return a;
	else return b;
}

const char *attributes[] = { "Content-Type", "Content-Length", "Text", "Status",  "Host", "Accept", "Connection","UKNOWN attribute"};
#define n_att  (sizeof (attributes) / sizeof (const char *)) - 1
enum http_att { ct, cl, txt, sts, host, ac, cnt, unknown_att};

const char *content_type[] = {"application/voucher-cose+cbor", "application/voucher-cms+json", "application/ace+cbor", 
	                          "application/cbor", "application/json", "application/text", "UNKNOWN content_type"};
#define n_ct (sizeof (content_type) / sizeof (const char *)) -1
enum http_ct {MEDIATYPE_APPLICATION_VOUCHER_COSE_CBOR, MEDIATYPE_APPLICATION_VOUCHER_CMS_JSON,
	            MEDIATYPE_APPLICATION_ACE_CBOR, MEDIATYPE_APPLICATION_CBOR, MEDIATYPE_APPLICATION_JSON, MEDIATYPE_TEXT_PLAIN, unknown_ct};
const uint16_t ct_defs[] = {COAP_MEDIATYPE_APPLICATION_VOUCHER_COSE_CBOR, COAP_MEDIATYPE_APPLICATION_VOUCHER_CMS_JSON,
	                        COAP_MEDIATYPE_APPLICATION_ACE_CBOR, COAP_MEDIATYPE_APPLICATION_CBOR, COAP_MEDIATYPE_APPLICATION_JSON, 
	                        COAP_MEDIATYPE_TEXT_PLAIN, 0};

const char *http_version[] = { "HTTP/1.0", "HTTP/1.1", "HTTP/1.2", "UNKNOWN HTTP version"};
#define n_http (sizeof (http_version) / sizeof (const char *)) - 1
enum http_vers {http_1_0, http_1_1, http_1_2, unknown_version};

const char *command[] = { PUT, POST, GET, DELETE, "UNKNOWN command"};
#define n_comm (sizeof (command) / sizeof (const char *)) - 1
enum http_comm { Put, Post, Get, Delete, unknown_command};

const char *path[] = {"/.well-known/brski/requestvoucher","/.well-known/brski/requestauditlog","/unknown/path"};
#define n_path (sizeof (path) / sizeof (const char *)) -1
enum resource {rv, ra, unknown_resource};


/*
 * Return error and error message
 */
static const char    *errmes = NULL;
static int16_t response_code = 200; 
static void
error_return(int16_t error, const char *message){
   printf("  %d --- %s \n", error, message);
   response_code = error;
   errmes = message;
}


static void
skip_blanks(char ** buf, char *end){
	while ((**buf == ' ') && (*buf < end))(*buf)++; /* skip blanks */
}

static void
skip_separator(char ** buf, char *end){
	while( (**buf != '\r') && (*buf < end))(*buf)++;
	if (*buf < end) if (**buf == '\r')(*buf)++;
	if (*buf < end) if (**buf == '\n')(*buf)++;
}

static enum http_vers
parse_httpversion(char ** buf, char * end){
	 skip_blanks(buf, end);
     int cmp = 1; 
     int i = 0;
     while (cmp != 0 && i < (int)n_http){
		 int len = min(strlen(http_version[i]), (end - (*buf)));
		 cmp = strncmp(http_version[i], *buf, len);
		 if (cmp != 0)i++;
	 }
	 if (cmp == 0)*buf = (*buf) + strlen(http_version[i]);
	 return i;
}

static int
test_separator(char *buf, char *end){
	if (end < buf + 3) return 1;
	if ((buf[0] == '\r') && (buf[1] == '\n')) return 0;
	return 1;
}

static int
read_number(char **buf, char *end){
	skip_blanks(buf, end);
	int result = 0;
	while ((**buf < '9'+1) && (**buf > '0' - 1) && (*buf < end)){
		result = result*10 + (**buf - '0');
		(*buf)++;
	}
	return result;
}

static uint
response_text(char **buf,char *end, char *text){
	skip_blanks(buf, end);
	uint cnt = 0;
	while ((**buf < 127) && (**buf > 31)
	        && (*buf < end) && (cnt < RESULT_LEN)){		
		text[cnt] = **buf;
		cnt++;
		(*buf)++;
	}
	text[cnt] = 0;
	return cnt;
}

static enum http_comm
parse_command(char **buf, char * end){
	 skip_blanks(buf, end);
     int cmp = 1; 
     int i = 0;
     while (cmp != 0 && i < (int)n_comm){
		 int len = min(strlen(command[i]), (end - (*buf)));		 
		 cmp = strncmp(command[i], *buf, len);
		 if (cmp != 0)i++;
	 }
	 if (cmp == 0)*buf = (*buf) + strlen(command[i]);
	 return i;
}

static enum resource
parse_resource(char **buf, char *end){
	 skip_blanks(buf, end);
     int cmp = 1; 
     int i = 0;
     while (cmp != 0 && i < (int)n_path){
		 int len = min(strlen(path[i]), (end - (*buf)));		 
		 cmp = strncmp(path[i], *buf, len);
		 if (cmp != 0)i++;
	 }
	 if (cmp == 0)*buf = (*buf) + strlen(path[i]);
	 return i;
}

static enum http_ct
parse_ct(char **buf, char *end){
	 skip_blanks(buf, end);
     int cmp = 1; 
     int i = 0;
     while (cmp != 0 && i < (int)n_ct){
		 int len = min(strlen(content_type[i]), (end - (*buf)));		 
		 cmp = strncmp(content_type[i], *buf, len);
		 if (cmp != 0)i++;
	 }
	 if (cmp == 0)*buf = (*buf) + strlen(content_type[i]);
	 return i;
}

static int
parse_cl(char **buf, char *end){
	 skip_blanks(buf, end);
     int pl = 1; 
     int n = sscanf(*buf, " %d", &pl);
     if (n != 1)return 0;
	 return pl;
}

static enum http_att
parse_attribute(char **buf, char *end){
	 skip_blanks(buf, end);
     int cmp = 1; 
     int i = 0;
     while (cmp != 0 && i < (int)n_att){
		 int len = min(strlen(attributes[i]), (end - (*buf)));		 
		 cmp = strncmp(attributes[i], *buf, len);
		 if (cmp != 0)i++;
	 }
	 if (cmp == 0){
		 *buf = (*buf) + strlen(attributes[i]);
		 skip_blanks(buf, end);
		 if ((**buf == ':') && (*buf < end))(*buf)++;
	 }
	 return i;
}

/*
 * POST handler - /est/rv
 * receives request with MASA request voucher
 * sends back signed voucher
 * protected via DTLS
 */
void
MS_hnd_post_rv(coap_string_t *signed_voucher_request, uint16_t ct,
                   coap_string_t *signed_voucher)
{
  coap_string_t *voucher_request = NULL;
  char cpc[] = MASA_CLIENT_DER;  /* request is signed by registrar  */
  char *file_name = cpc;
  char ca_name[]  = CA_REGIS_CRT;
  voucher_t *req_contents = NULL;
  if (ct == COAP_MEDIATYPE_APPLICATION_VOUCHER_COSE_CBOR){
	  /* cose signed voucher_request  */  
	  voucher_request = brski_verify_cose_signature(signed_voucher_request, file_name);
  } else if (ct == COAP_MEDIATYPE_APPLICATION_VOUCHER_CMS_JSON){
      /* cms signed voucher_request */
      voucher_request = brski_verify_cms_signature(signed_voucher_request, ca_name, file_name);
//      fprintf(stderr,"voucher request with length %d \n",(int)voucher_request->length);
//      for (uint qq = 0; qq < voucher_request->length; qq++)fprintf(stderr,"%c",voucher_request->s[qq]);
 //     fprintf(stderr,"\n");
  }  else if (ct == COAP_MEDIATYPE_APPLICATION_CBOR){
	  voucher_request = malloc(sizeof(coap_string_t));
	  voucher_request->length = signed_voucher_request->length;
	  voucher_request->s = malloc(signed_voucher_request->length);
	  memcpy(voucher_request->s, signed_voucher_request->s, signed_voucher_request->length);	
  }  
  if (voucher_request != NULL){
	  if (ct == COAP_MEDIATYPE_APPLICATION_VOUCHER_COSE_CBOR)
	     req_contents = brski_parse_cbor_voucher(voucher_request);
	  else if  (ct == COAP_MEDIATYPE_APPLICATION_VOUCHER_CMS_JSON)  
	     req_contents = brski_parse_json_voucher(voucher_request);
	  if (voucher_request->s != NULL) free(voucher_request->s);
	  free(voucher_request);
  }
  if (req_contents == NULL){
		  error_return( 406, "voucher request cannot be parsed\n");
	      return;
  }
  int8_t ok = brski_check_pledge_request(req_contents);
  if (ok ==1){
	  error_return(403, "signature of prior voucher request is invalid\n");
      remove_voucher(req_contents);       
	  return;
  }

  coap_string_t voucher = {.s = NULL, .length = 0};
  char cmk[] = MASA_SRV_KEY;
  char *key_file = cmk;
  char mkc[] = MASA_SRV_COMB;
  char *comb_file = mkc;
  if (JSON_set() == JSON_OFF)
            ok = brski_create_cbor_voucher(&voucher, req_contents);
  else  
            ok = brski_create_json_voucher(&voucher, req_contents);
  remove_voucher(req_contents);
  if (ok != 0){
	  error_return(406, "voucher is not generated\n");
      if (voucher.s != NULL)free(voucher.s);
	  return;
  }
  if (masa_debug > 0)printf("masa signs voucher with key_file %s \n", comb_file);
  if (ct == COAP_MEDIATYPE_APPLICATION_VOUCHER_COSE_CBOR)
     ok = brski_cose_sign_payload(signed_voucher, &voucher, key_file, file_name);
  else
     ok = brski_cms_sign_payload(signed_voucher, &voucher, comb_file);
  if (voucher.s != NULL)free(voucher.s);
  if (ok != 0){
	 error_return(406, "cannot sign voucher\n");
	 return; 
  }
}

/*
 * POST handler - /est/ra
 * receives request with request auditing
 * protected via TLS
 */
void
MS_hnd_post_ra(coap_string_t *voucher_request, coap_string_t *log)
{

  /* try to find domainid in request-voucher  */
  uint8_t *domain_id = NULL;
  voucher_t *req_contents = NULL;
  if (JSON_set() == JSON_OFF)
      req_contents = brski_parse_cbor_voucher(voucher_request);
  else
      req_contents = brski_parse_json_voucher(voucher_request);
  if (req_contents == NULL){
		  error_return(404, "received voucher request is wrong\n");
	      return;
  }
  coap_string_t prior_signed = {.s = req_contents->prior_signed, .length = req_contents->prior_signed_len};
  voucher_t *req2 = NULL;
  if ((req_contents->domainid == NULL) && (req_contents->prior_signed != NULL)){
	  if (JSON_set() == JSON_OFF)
	      req2 = brski_parse_cbor_voucher(&prior_signed);
	  else{
	  	  req2 = brski_parse_json_voucher(&prior_signed);
	  }
	  if (req2 == NULL){
		  error_return(404, "received embedded voucher request is wrong\n");
          remove_voucher( req_contents);
	      return;
	  }
	  domain_id = req2->domainid;
	  remove_voucher(req_contents);
	  req_contents = req2;
  } else {
	  domain_id = req_contents->domainid;
  }
  if (domain_id == NULL){
	  error_return(406, "domainid cannot be found\n");
      remove_voucher( req_contents);
	  return;
  }
  coap_string_t *temp = brski_audit_response(req_contents);
  remove_voucher(req_contents);
  if (temp == NULL){
	  error_return(406, "request voucher is unknown or wrong\n");
	   return;
  }
  log->s = temp->s;
  log->length = temp->length;
  free(temp);
}

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);

    fprintf( (FILE *) ctx, "%s:%04d: %s", file, line, str );
    fflush(  (FILE *) ctx  );
}

static int 
masa_server( void )
{
    int ret = 0;
    int len = 0;
    mbedtls_net_context listen_fd, client_fd;
    unsigned char buf[4096];
    const char *pers = "ssl_server";
    char  passwd[] = "watnietweet";
    char  ca_file_name[]     = CA_MASA_CRT;
    char  server_file_name[] = MASA_SRV_CRT;
    char  key_file_name[]    = MASA_SRV_KEY;
    pki_sni_entry entry;
    
    enum http_comm curr_com = 0;
    enum resource cur_res = 0;   

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_x509_crt cacert;    
    mbedtls_pk_context pkey;
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_context cache;
#endif

    mbedtls_net_init( &listen_fd );
    mbedtls_net_init( &client_fd );
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init( &cache );
#endif
    mbedtls_x509_crt_init( &srvcert );
    mbedtls_x509_crt_init( &cacert );   
    mbedtls_pk_init( &pkey );
    mbedtls_entropy_init( &entropy );
    mbedtls_ctr_drbg_init( &ctr_drbg );

#if defined(MBEDTLS_DEBUG_C)
    mbedtls_debug_set_threshold( DEBUG_LEVEL );
#endif

    /*
     * 1. Load the certificates and private key
     */
    if(masa_debug > 0)printf( "  . Loading the server certificate ... name %s \n", server_file_name);
    fflush( stdout );
    CHECK(mbedtls_x509_crt_parse_file( &srvcert, server_file_name ));
    if (masa_debug > 0)printf( "  . Loading the CA root certificate ... name %s \n", ca_file_name);
    CHECK(mbedtls_x509_crt_parse_file( &cacert, ca_file_name ));
    if (masa_debug > 0)printf( "  . Loading the server key file ... name %s \n", key_file_name);
    CHECK(mbedtls_pk_parse_keyfile( &pkey, key_file_name, passwd ));

    /*
     * 2. Setup the listening TCP socket
     */
    CHECK(mbedtls_net_bind( &listen_fd, NULL, port_str, MBEDTLS_NET_PROTO_TCP ) );
    /*
     * 3. Seed the RNG
     */

    CHECK(mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,strlen( pers ) ) );

    /*
     * 4. Setup stuff
     */

    CHECK(mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_SERVER,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) );

    /* OPTIONAL is not optimal for security,
     * but makes interop easier in this simplified example */
    mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
    mbedtls_ssl_conf_ca_chain( &conf, &srvcert, NULL );
    mbedtls_ssl_conf_verify(&conf,
                          cert_verify_callback_mbedtls, &entry);

    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );
    entry.cacert = &cacert;
    entry.public_cert = &srvcert;
    entry.private_key = &pkey;
    mbedtls_ssl_conf_sni( &conf, sni_callback, &entry );

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache( &conf, &cache, mbedtls_ssl_cache_get, mbedtls_ssl_cache_set );
#endif

    CHECK(mbedtls_ssl_setup( &ssl, &conf ) );

reset:

    mbedtls_net_free( &client_fd );

    mbedtls_ssl_session_reset( &ssl );

    /*
     * 3. Wait until a client connects
     */
    if (masa_debug > 0)printf( "  . Waiting for a remote connection ...\n" );
    fflush( stdout );

    CHECK(mbedtls_net_accept( &listen_fd, &client_fd, NULL, 0, NULL ) );
 
    mbedtls_ssl_set_bio( &ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, NULL );

    /*
     * 5. Handshake
     */
    while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            printf( " failed\n  ! mbedtls_ssl_handshake returned %d\n\n", ret );
            goto reset;
        }
    }

    /*
     * 6. Read the HTTP Request
     */
    do
    {
        len = sizeof( buf ) - 1;
        memset( buf, 0, sizeof( buf ) );
        ret = mbedtls_ssl_read( &ssl, buf, len );

        if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
            continue;

        if( ret <= 0 )
        {
            switch( ret )
            {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    if (masa_debug > 0)printf( " connection was closed gracefully\n" );
                    break;

                case MBEDTLS_ERR_NET_CONN_RESET:
                    if (masa_debug > 0)printf( " connection was reset by peer\n" );
                    break;

                default:
                    if (masa_debug > 0)printf( " mbedtls_ssl_read returned -0x%x\n", (unsigned int) -ret );
                    break;
            }

            break;
        }

        len = ret;
        if( ret > 0 )
            break;
    }
    while( 1 );
    
    /*
     * 8. decode the http request
     */
     char *sbuf = (char *)buf;
     char *end  = sbuf + len;
     char explain[RESULT_LEN];
     int  pl_length = 0;   
     uint16_t ct_def = 0;  
        skip_blanks(&sbuf, end);
        curr_com = parse_command(&sbuf, end);
        if (masa_debug > 0)printf( "found command    %s \n",command[(int)curr_com]);
        cur_res = parse_resource(&sbuf, end);
        if (masa_debug > 0)printf( "found resource   %s \n", path[(int)cur_res]);
        enum http_vers cur_version = parse_httpversion(&sbuf, end);
        if (masa_debug > 0)printf( "found version    %s \n",http_version[(int)cur_version]);
        response_code = read_number(&sbuf, end);
        if (masa_debug > 0)printf( "response_code is %d   with text: ", response_code);
        response_text(&sbuf, end, explain);
        if (masa_debug > 0)printf( "%s \n",explain);        
        skip_separator(&sbuf, end);       
        enum http_ct ct_found = unknown_ct; 
        while ((test_separator(sbuf, end) == 1) && (sbuf+3 < end)){
		  enum http_att cur_att = parse_attribute(&sbuf, end);
          if (cur_att == ct){
		     ct_found = parse_ct(&sbuf, end);
		     if (masa_debug > 0)printf( " found content_type  %s \n", content_type[(int)ct_found]);
		     ct_def = ct_defs[(int)ct_found];
		  } else if  (cur_att == txt){ 
			  response_text(&sbuf, end, explain);
			  if (masa_debug > 0)printf( " found Text  %s \n", explain);
		  } else if  (cur_att == host){ 
			  response_text(&sbuf, end, explain);
			  if (masa_debug > 0)printf( " found Host  %s \n", explain);		
		  } else if  (cur_att == ac){ 
		     ct_found = parse_ct(&sbuf, end);
		     if (masa_debug > 0)printf( " found Accept  %s \n", content_type[(int)ct_found]);			  	  
		  } else if  (cur_att == sts){ 
			  response_text(&sbuf, end, explain);
			  if (masa_debug > 0)printf( " found Status  %s \n", explain);	
		  } else if  (cur_att == cnt){ 
			  response_text(&sbuf, end, explain);
			  if (masa_debug > 0)printf( " found Connection  %s \n", explain);			  		  
		  } else if (cur_att == cl){
		    pl_length = parse_cl(&sbuf, end);
		    if (masa_debug > 0)printf("Content_length is %d \n",pl_length);
		  }  
		  skip_separator(&sbuf, end);
	    }
		skip_separator(&sbuf, end);
		
     uint8_t *pbuf = (uint8_t *)sbuf;
     if (masa_debug > 0){
	    printf("payload is :\n");
	    for ( uint qq = 0; qq < (int)(end-sbuf); qq++)printf("%c",pbuf[qq]);
	    printf("\n");
	 }
	 /*
	  * 9. invoke server
	  */
     coap_string_t  response = {.s = NULL, .length = 0};
     if ((ct_found == MEDIATYPE_APPLICATION_VOUCHER_CMS_JSON) ||
         (ct_found == MEDIATYPE_APPLICATION_JSON)){
		 set_JSON(JSON_ON);
	 }
     else if ((ct_found == MEDIATYPE_APPLICATION_VOUCHER_COSE_CBOR) ||
              (ct_found == MEDIATYPE_APPLICATION_CBOR)){
         set_JSON(JSON_OFF);
    } else {
		fprintf(stderr,"Invalid media type \n");
		response_code = 400;
		goto end;
	}
     
     response_code = 200;
	 if ((curr_com == Post) && (cur_res == rv)){
		coap_string_t signed_voucher_request = { .s = (uint8_t *)sbuf, .length = pl_length};
		coap_string_t signed_voucher = {.s = NULL, .length = 0};
	    MS_hnd_post_rv(&signed_voucher_request, ct_def, &signed_voucher);
        response.s =  signed_voucher.s;
        response.length = signed_voucher.length;
	}
	else if ((curr_com == Post) && (cur_res == ra)){
		 coap_string_t log = {.s = NULL, .length = 0};
		 coap_string_t voucher_request = { .s = (uint8_t *)sbuf, .length = pl_length};
	     MS_hnd_post_ra(&voucher_request, &log);
	     response.s = log.s;
	     response.length = log.length;
    } else response_code = 404;
    /*
     * 10. Write the Response
     */
end:
    len = sprintf( (char *) buf, HTTP_RESPONSE);
    len += sprintf((char *) buf+len, " %d ", response_code);
    if (response_code < 300){
	  len += sprintf((char *) buf+len, " OK ");
      if (ct_found == MEDIATYPE_APPLICATION_VOUCHER_CMS_JSON)
         len += sprintf((char *) buf+len, HTTP_FOLLOW_CMS );
      else if (ct_found == MEDIATYPE_APPLICATION_VOUCHER_COSE_CBOR)
         len += sprintf((char *) buf+len, HTTP_FOLLOW_COSE );
      else if (ct_found == MEDIATYPE_APPLICATION_CBOR)
         len += sprintf((char *) buf+len, HTTP_FOLLOW_CBOR );
      else if (ct_found == MEDIATYPE_APPLICATION_JSON)
         len += sprintf((char *) buf+len, HTTP_FOLLOW_JSON );                  
	}
    else {  /* error return */
      len += sprintf((char *) buf+len, " HTTP error ");
      len += sprintf((char *) buf+len, HTTP_FOLLOW_TEXT ); 
    }
    if (masa_debug > 0){ 
       printf("HTTP response header is: ");
       for (uint qq = 0; qq < len;qq++)printf( "%c",buf[qq]);  
       printf("\n"); 
   }   
    if ((response_code > 299) || (cur_version ==  unknown_version)  || (curr_com == unknown_command)){
		/* error occurred */
	    memcpy(buf+len, response.s, response.length);
	    len = len + response.length;
	} else{
		/* ok return */
	    memcpy(buf+len, response.s, response.length);
	    len = len + response.length;
	    if (masa_debug > 0){
			printf("HTTP payload is :\n");
	        for (uint qq = 0; qq <response.length; qq++)printf(" %02x",buf[len+qq]);
	        printf("\n");
		}
    }
    

    while( ( ret = mbedtls_ssl_write( &ssl, buf, len ) ) <= 0 )
    {
        if( ret == MBEDTLS_ERR_NET_CONN_RESET )
        {
            printf( " failed\n  ! peer closed the connection\n\n" );
            goto reset;
        }

        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            printf( " failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
            goto exit;
        }
    }

    len = ret;
    if (masa_debug > 0)printf( " %d bytes written\n", len );

    while( ( ret = mbedtls_ssl_close_notify( &ssl ) ) < 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            printf( " failed\n  ! mbedtls_ssl_close_notify returned %d\n\n", ret );
            goto reset;
        }
    }

    ret = 0;
    goto reset;

exit:
    mbedtls_net_free( &client_fd );
    mbedtls_net_free( &listen_fd );

    mbedtls_x509_crt_free( &srvcert );
    mbedtls_x509_crt_free( &cacert );    
    mbedtls_pk_free( &pkey );
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_free( &cache );
#endif
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    return ret;
}

static void
usage( const char *program) {
  const char *p;
  const char version[] = " version 0.0 ";
  p = strrchr( program, '/' );
  if ( p ) program = ++p;
  printf( "%s v%s -- a small MASA http server implementation\n"
     "(c) 2021 Peter van der Stok and others\n\n"
     "%s\n\n"
     "Usage: %s [-v num] [-p port] \n"
     "General Options\n"
     "\t-v num \t\tVerbosity level (default 3, maximum is 9). Above 7,\n"
     "\t       \t\tthere is increased verbosity in GnuTLS and OpenSSL logging\n"
     "\t-p port\t\tPort of the MASA http server\n"
     "\t       \t\tif not specified, default http server port is %s used \n"
     "\t-h     \t\tHelp, produces this output\n"
     "\texamples:\t  %s -p 443 \n"
     "\t       \t\t  %s \n"
     "\t       \t\t  %s -v 7 \n"
    , program, version,
    program, program, MASA_PORT,
    program, program, program);
}

int
main(int argc, char **argv) {
    int opt;
	while ((opt = getopt(argc, argv, "p:h:v:")) != -1) {
    switch (opt) {
    case 'p' :
      strncpy(port_str, optarg, NI_MAXSERV-1);
      port_str[NI_MAXSERV - 1] = '\0';
      break;
    case 'v' :
      masa_debug = strtol(optarg, NULL, 10);
      break;
    case 'h' :
    default:
      usage( argv[0] );
      exit( 1 );
    }
  }

	
  int ret = masa_server();
  exit(ret);
}

