/* Registrar-server -- implementation of Registrar using
 * a simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 * Registrar Server (RS) is added by:
 * Peter van der Stok <consultancy@vanderstok.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 *
 * Registrar conforms to est-coaps and constrained-voucher drafts
 * to realize BRSKI
 * 
 * This is server only process, which uses shared static data
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/types.h>
#include <ifaddrs.h>
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
#endif

#include "oscore_oauth.h"
#include "coap_server.h"
#include "oscore.h"
#include "oscore-context.h"
#include "cbor.h"
#include "cose.h"
#include "coap_session.h"
#include "coap_internal.h"
#include "Registrar_server.h"
#include "JP_server.h"
#include "brski.h"
#include "utlist.h"
#include "brski_util.h"
#include "edhoc.h"
#include "client_request.h"
#include <coap.h>

#include "mbedtls/net_sockets.h"
#include "mbedtls/debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"
#include "mbedtls/oid.h"

#define BUFLEN 4096        /* max length of message buffer to send */
#define RESULT_LEN  130    /* maximum length of htpp result */
#define SERVER_PORT "443"  /* default https port */

/* counters for statistics  */
static int srv_cnt = 0;                      /* total number of server invocations */
static int srv_index_cnt = 0;                /* index invocations */
static int srv_time_cnt = 0;                 /* time invocations */
static int srv_async_cnt = 0;                /* async invocations  */
static int srv_delete_cnt = 0;               /* delete invocations */
static int srv_get_cnt = 0;                  /* get invocations */
static int srv_put_cnt = 0;                  /* put invocations */
static int srv_post_vs_cnt = 0;              /* post_vs invocations */
static int srv_get_es_cnt = 0;               /* get_es invocations */
static int srv_post_rv_cnt = 0;              /* post_rv invocations */
static int srv_post_sen_cnt = 0;             /* post_sen invocations */
static int srv_post_sren_cnt = 0;            /* post_sren invocations */
static int srv_post_skg_cnt = 0;             /* post_skg invocations */
static int srv_get_att_cnt = 0;              /* get_att invocations */
static int srv_proxy_cnt = 0;                /* proxy -> Registrar invocations */
static int srv_get_crts_cnt = 0;             /* get_crts invocations */


#define CHECK( x )                                                      \
    do {                                                                \
        int CHECK__ret_ = ( x );                                        \
        if( CHECK__ret_ < 0 )                                          \
        {                                                               \
            char CHECK__error_[100];                                    \
            mbedtls_strerror( CHECK__ret_,                              \
                              CHECK__error_, sizeof( CHECK__error_ ) ); \
            coap_log(LOG_ERR, "%s -> %s\n", #x, CHECK__error_ );        \
            ok = 1;                                                     \
            goto exit;                                                  \
        }                                                               \
    } while( 0 )


#ifndef WITHOUT_ASYNC
/* This variable is used to mimic long-running tasks that require
 * asynchronous responses. */
static coap_async_state_t *async = NULL;

/* A typedef for transfering a value in a void pointer */
typedef union {
  unsigned int val;
  void *ptr;
} async_data_t;
#endif /* WITHOUT_ASYNC */


#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */


static uint8_t join_proxy_supported = 1;                  /* join proxy endpoint to be defined  */

int quit;
int ready = 0;
         
/* changeable clock base (see handle_put_time()) */
time_t clock_offset;
time_t my_clock_base;

struct coap_resource_t *time_resource;
int resource_flags;


/* temporary storage for dynamic resource representations */
int support_dynamic;           
int dynamic_count = 0;
dynamic_resource_t *dynamic_entry = NULL;

static char int_cert_file[] = REGIS_SRV_COMB;      /* Combined certificate and private key in PEM Registrar server*/
static char int_ca_file[] = CA_REGIS_CRT;          /* CA for Registrar server - for cert checking in PEM */
char *cert_file = int_cert_file;                   /* Combined certificate and private key in PEM */
char *ca_file = int_ca_file;                       /* CA for cert_file - for cert checking in PEM */
char *root_ca_file = NULL;                         /* List of trusted Root CAs in PEM */
static int use_pem_buf = 0; /* Map these cert/key files into memory to test
                               PEM_BUF logic if set */
static uint8_t *cert_mem = NULL; /* certificate and private key in PEM_BUF */
static uint8_t *ca_mem = NULL;   /* CA for cert checking in PEM_BUF */
static size_t cert_mem_len = 0;
static size_t ca_mem_len = 0;

uint8_t key[MAX_KEY];
ssize_t key_length;
int key_defined;
const char *hint = "CoAP";

typedef struct psk_sni_def_t {
  char* sni_match;
  coap_bin_const_t *new_key;
  coap_bin_const_t *new_hint;
} psk_sni_def_t;

typedef struct valid_psk_snis_t {
  size_t count;
  psk_sni_def_t *psk_sni_list;
} valid_psk_snis_t;

static valid_psk_snis_t valid_psk_snis = {0, NULL};

typedef struct id_def_t {
  char *hint_match;
  coap_bin_const_t *identity_match;
  coap_bin_const_t *new_key;
} id_def_t;

typedef struct valid_ids_t {
  size_t count;
  id_def_t *id_list;
} valid_ids_t;

static valid_ids_t valid_ids = {0, NULL};
typedef struct pki_sni_def_t {
  char* sni_match;
  char *new_cert;
  char *new_ca;
} pki_sni_def_t;

typedef struct valid_pki_snis_t {
  size_t count;
  pki_sni_def_t *pki_sni_list;
} valid_pki_snis_t;

static valid_pki_snis_t valid_pki_snis = {0, NULL};

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

/* SIGINT handler: set quit to 1 for graceful termination */
void
handle_sigint(int signum UNUSED_PARAM) {
  quit = 1;
}

/* local MASA invocation */
#define CN_NAME "MASA server"

/* global coap_start variables */
#define MAX_USER 128 /* Maximum length of a user name (i.e., PSK
                      * identity) in bytes. */
#define MAX_KEY   64 /* Maximum length of a key (i.e., PSK) in bytes. */

#define FLAGS_BLOCK 0x01

/* name and IP address of switch to be used in AS */
static coap_string_t IP_RG = {.length =0, .s = NULL};
static coap_string_t RG_identifier = {.length =0, .s = NULL};

/* stores data for block2 return */
static coap_string_t RG_ret_data = {
	.length = 0,
	.s = NULL
};

static status_t  *STATUS = NULL;
static uint8_t multiple_pledge_entries = 1;       /* multiple enroll of a pledge is not allowed  */

void set_multiple_pledge_entries(void){
  multiple_pledge_entries = 0;
}


/* regular server handler for blocked request
 * no block used: return 1
 * block used but not complete: return 2
 * block missing: return 3
 * all blocks received: return 0;
 * uses resource->userdata to store intermediate results
 * coap_handle_block
 */
 uint8_t
 coap_handle_block(
           struct coap_resource_t *resource,
           coap_pdu_t *request,
           coap_pdu_t *response)
 {
   coap_block_t block1;
   size_t size;
   uint8_t *data;
   if (coap_get_block(request, COAP_OPTION_BLOCK1, &block1)) {
    /* handle BLOCK1 */
    if (coap_get_data(request, &size, &data) && (size > 0)) {
      size_t offset = block1.num << (block1.szx + 4);
      coap_string_t *value = (coap_string_t *)resource->user_data;
      if (offset == 0) {
        if (value) {
          coap_delete_string(value);
          value = NULL;
        }
      }
      else if (offset >
            (value ? value->length : 0)) {
        /* Upload is not sequential - block missing */
        response->code = COAP_RESPONSE_CODE(408);
        return 3;
      }
      else if (offset <
            (value ? value->length : 0)) {
        /* Upload is not sequential - block duplicated */
        goto just_respond;
      }
      /* Add in new block to end of current data */
      coap_string_t *new_value = coap_new_string(offset + size);
      memcpy (&new_value->s[offset], data, size);
      new_value->length = offset + size;
      if (value) {
        memcpy (new_value->s, value->s, value->length);
        coap_delete_string(value);
      }
      resource->user_data = new_value;
    }
    uint8_t ret = 0;
just_respond:
    if (block1.m) {
      unsigned char buf[4];
      response->code = COAP_RESPONSE_CODE(231);
      coap_add_option(response, COAP_OPTION_BLOCK1, coap_encode_var_safe(buf, sizeof(buf),
                                                  ((block1.num << 4) |
                                                   (block1.m << 3) |
                                                   block1.szx)),
                  buf);
      ret = 2;
    } 
    return ret;
    }
  return 1;
}


/* assemble_data
 * assemble data from received block in request
 * ok: returns data
 * nok: returns null
 */
uint8_t *
assemble_data(struct coap_resource_t *resource,
           coap_pdu_t *request,
           coap_pdu_t *response,
           size_t *size)
{
  uint8_t ret = coap_handle_block(resource, request, response);
  uint8_t * data = NULL;
  if (ret == 1){
  /* NOT BLOCK1 */  
    if (!coap_get_data(request, size, &data) && (*size > 0)) {
    /* Not a BLOCK1 and no data */
       brski_error_return(COAP_RESPONSE_CODE(400), 
                    response, "Cannot find request data");
    }
  }
  else if (ret == 0){
	/* BLOCK1 complete */
	coap_string_t *value = (coap_string_t *)resource->user_data;
	if (value != NULL){
       data = value->s;
       *size = value->length;
    }else {
	   data = NULL;
	   *size = 0;
    }
  }
  else if (ret == 3){
  /* BLOCK1 with missing block  */
    return NULL;
  }
  else if (ret == 2){
	/* wait for more blocks  */
	return (void *)-1;
  }
  return data;
}


typedef struct ih_def_t {
  char* hint_match;
  coap_bin_const_t *new_identity;
  coap_bin_const_t *new_key;
} ih_def_t;


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
  coap_log(LOG_INFO, "CN '%s' presented by server (%s)\n",
           cn, depth ? "CA" : "Certificate");
  if (depth == 0){
	  coap_log(LOG_INFO, " certificate to be written to %s \n", REGIS_SERVER_DER);
      char file[] = REGIS_SERVER_DER;
      coap_string_t contents = {.length = crt->raw.len, .s = NULL};
      contents.s = malloc(crt->raw.len);
      memcpy(contents.s, crt->raw.p, crt->raw.len);
      uint8_t ok = write_file_mem(file, &contents); 
      free(contents.s); 
      if (ok != 0)coap_log(LOG_ERR, "certificate is not written to %s \n", REGIS_SERVER_DER); 
  }   
  return 0;
}

int sni_callback( void *p_info, mbedtls_ssl_context *ssl,
              const unsigned char *name, size_t name_len )
{ 
	 if (coap_get_log_level() > LOG_INFO){
		 printf("sni_callback \n");
	   for (uint8_t qq = 0; qq < (uint8_t)name_len; qq++)printf("%c",name[qq]);
	   printf("\n");
    }
     pki_sni_entry *cur = (pki_sni_entry *)p_info;
     mbedtls_ssl_set_hs_ca_chain( ssl, cur->public_cert, NULL );      
     return( mbedtls_ssl_set_hs_own_cert( ssl, cur->public_cert, cur->private_key ) );

    /* return not-OK code */   
    return( -1 );
}

const char *attributes[] = { "Content-Type", "Content-Length", "Text", "Status", "Connection","UKNOWN attribute"};
#define n_att  (sizeof (attributes) / sizeof (const char *)) - 1
enum http_att { ct, cl, txt, sts, cnt, unknown_att};

const char *http_version[] = { "HTTP/1.0", "HTTP/1.1", "HTTP/1.2", "UNKNOWN HTTP version"};
#define n_http (sizeof (http_version) / sizeof (const char *)) - 1
enum http_vers {http_1_0, http_1_1, http_1_2, unknown_version};

const char *content_type[] = {"application/voucher-cose+cbor", "application/voucher-cms+json",
	                           "application/ace+cbor", "application/json", "application/cbor", "application/text", "UNKNOWN content_type"};
#define n_ct (sizeof (content_type) / sizeof (const char *)) -1
enum http_ct {MEDIATYPE_APPLICATION_VOUCHER_COSE_CBOR, MEDIATYPE_APPLICATION_VOUCHER_CMS_JSON,
	          MEDIATYPE_APPLICATION_ACE_CBOR, MEDIATYPE_APPLICATION_JSON, MEDIATYPE_APPLICATION_CBOR, MEDIATYPE_APPLICATION_TEXT, unknown_ct};

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

static int
test_separator(char *buf, char *end){
	if (end < buf + 3) return 1;
	if ((buf[0] == '\r') && (buf[1] == '\n')) return 0;
	return 1;
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


static void
hnd_get_index(coap_context_t *ctx UNUSED_PARAM,
              struct coap_resource_t *resource,
              coap_session_t *session,
              coap_pdu_t *request,
              coap_binary_t *token,
              coap_string_t *query UNUSED_PARAM,
              coap_pdu_t *response) {
  srv_cnt++;
  srv_index_cnt++;
  fprintf(stderr," Index server invoked %d  times; all servers invoked %d times, number of open coap_malloc is %d \n", srv_index_cnt, srv_cnt, (int)coap_nr_of_alloc());
  coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_TEXT_PLAIN, 0x2ffff,
                                 strlen(INDEX),
                                 (const uint8_t *)INDEX);
}

static void
hnd_get_time(coap_context_t  *ctx UNUSED_PARAM,
             struct coap_resource_t *resource,
             coap_session_t *session,
             coap_pdu_t *request,
             coap_binary_t *token,
             coap_string_t *query,
             coap_pdu_t *response) {
  unsigned char buf[40];
  size_t len;
  time_t now;
  coap_tick_t t;
  (void)request;
  srv_cnt++;
  srv_time_cnt++;
  /* FIXME: return time, e.g. in human-readable by default and ticks
   * when query ?ticks is given. */

  if (my_clock_base) {

    /* calculate current time */
    coap_ticks(&t);
    now = my_clock_base + (t / COAP_TICKS_PER_SECOND);

    if (query != NULL
        && coap_string_equal(query, coap_make_str_const("ticks"))) {
          /* output ticks */
          len = snprintf((char *)buf, sizeof(buf), "%u", (unsigned int)now);

    } else {      /* output human-readable time */
      struct tm *tmp;
      tmp = gmtime(&now);
      if (!tmp) {
        /* If 'now' is not valid */
        response->code = COAP_RESPONSE_CODE(404);
        return;
      }
      else {
        len = strftime((char *)buf, sizeof(buf), "%b %d %H:%M:%S", tmp);
      }
    }
    coap_add_data_blocked_response(resource, session, request, response, token,
                                   COAP_MEDIATYPE_TEXT_PLAIN, 1,
                                   len,
                                   buf);
  }
  else {
    /* if my_clock_base was deleted, we pretend to have no such resource */
    response->code = COAP_RESPONSE_CODE(404);
  }
  fprintf(stderr," Time server invoked %d  times; all servers invoked %d times, number of open coap_malloc is %d \n", srv_time_cnt, srv_cnt, (int)coap_nr_of_alloc());
}

static void
hnd_put_time(coap_context_t *ctx UNUSED_PARAM,
             struct coap_resource_t *resource,
             coap_session_t *session UNUSED_PARAM,
             coap_pdu_t *request,
             coap_binary_t *token UNUSED_PARAM,
             coap_string_t *query UNUSED_PARAM,
             coap_pdu_t *response) {
  coap_tick_t t;
  size_t size;
  unsigned char *data;
  srv_cnt++;
  srv_time_cnt++;
  /* FIXME: re-set my_clock_base to clock_offset if my_clock_base == 0
   * and request is empty. When not empty, set to value in request payload
   * (insist on query ?ticks). Return Created or Ok.
   */

  /* if my_clock_base was deleted, we pretend to have no such resource */
  response->code =
    my_clock_base ? COAP_RESPONSE_CODE(204) : COAP_RESPONSE_CODE(201);

  coap_resource_notify_observers(resource, NULL);

  /* coap_get_data() sets size to 0 on error */
  (void)coap_get_data(request, &size, &data);

  if (size == 0)        /* re-init */
    my_clock_base = clock_offset;
  else {
    my_clock_base = 0;
    coap_ticks(&t);
    while(size--)
      my_clock_base = my_clock_base * 10 + *data++;
    my_clock_base -= t / COAP_TICKS_PER_SECOND;

    /* Sanity check input value */
    if (!gmtime(&my_clock_base)) {
      unsigned char buf[3];
      response->code = COAP_RESPONSE_CODE(400);
      coap_add_option(response,
                      COAP_OPTION_CONTENT_FORMAT,
                      coap_encode_var_safe(buf, sizeof(buf),
                      COAP_MEDIATYPE_TEXT_PLAIN), buf);
      coap_add_data(response, 22, (const uint8_t*)"Invalid set time value");
      /* re-init as value is bad */
      my_clock_base = clock_offset;
    }
  }
  fprintf(stderr," Time server invoked %d  times; all servers invoked %d times, number of open coap_malloc is %d \n", srv_time_cnt, srv_cnt, (int)coap_nr_of_alloc());  
}

static void
hnd_delete_time(coap_context_t *ctx UNUSED_PARAM,
                struct coap_resource_t *resource UNUSED_PARAM,
                coap_session_t *session UNUSED_PARAM,
                coap_pdu_t *request UNUSED_PARAM,
                coap_binary_t *token UNUSED_PARAM,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response UNUSED_PARAM) {
  my_clock_base = 0;    /* mark clock as "deleted" */
  srv_cnt++;
  srv_time_cnt++;
  /* type = request->hdr->type == COAP_MESSAGE_CON  */
  /*   ? COAP_MESSAGE_ACK : COAP_MESSAGE_NON; */
  fprintf(stderr," Time server invoked %d  times; all servers invoked %d times, number of open coap_malloc is %d \n", srv_time_cnt, srv_cnt, (int)coap_nr_of_alloc());  
}

#ifndef WITHOUT_ASYNC
static void
hnd_get_async(coap_context_t *ctx,
              struct coap_resource_t *resource UNUSED_PARAM,
              coap_session_t *session,
              coap_pdu_t *request,
              coap_binary_t *token UNUSED_PARAM,
              coap_string_t *query UNUSED_PARAM,
              coap_pdu_t *response) {
  unsigned long delay = 5;
  size_t size;
  srv_cnt++;
  srv_async_cnt++;
  if (async) {
    if (async->id != request->tid) {
      coap_opt_filter_t f;
      coap_option_filter_clear(f);
      response->code = COAP_RESPONSE_CODE(503);
    }
    return;
  }

  if (query) {
    const uint8_t *p = query->s;

    delay = 0;
    for (size = query->length; size; --size, ++p)
      delay = delay * 10 + (*p - '0');
  }

  /*
   * This is so we can use a local variable to hold the remaining time.
   * The alternative is to malloc the variable and set COAP_ASYNC_RELEASE_DATA
   * in the flags parameter in the call to coap_register_async() and handle
   * the required time as appropriate in check_async() below.
   */
  async_data_t data;
  data.val = COAP_TICKS_PER_SECOND * delay;
  async = coap_register_async(ctx,
                              session,
                              request,
                              COAP_ASYNC_SEPARATE | COAP_ASYNC_CONFIRM,
                              data.ptr);
  fprintf(stderr," Async server invoked %d  times; all servers invoked %d times, number of open coap_malloc is %d \n", srv_async_cnt, srv_cnt, (int)coap_nr_of_alloc());			      
}

static void
check_async(coap_context_t *ctx,
            coap_tick_t now) {
  coap_pdu_t *response;
  coap_async_state_t *tmp;
  async_data_t data;

  size_t size = 13;

  if (!async)
    return;

  data.ptr = async->appdata;
  if (now < async->created + data.val)
    return;

  response = coap_pdu_init(async->flags & COAP_ASYNC_CONFIRM
             ? COAP_MESSAGE_CON
             : COAP_MESSAGE_NON,
             COAP_RESPONSE_CODE(205), 0, size);
  if (!response) {
    coap_log(LOG_DEBUG, "check_async: insufficient memory, we'll try later\n");
    data.val = data.val + 15 * COAP_TICKS_PER_SECOND;
    async->appdata = data.ptr;
    return;
  }

  response->tid = coap_new_message_id(async->session);

  if (async->tokenlen)
    coap_add_token(response, async->tokenlen, async->token);

  coap_add_data(response, 4, (const uint8_t *)"done");

  if (coap_send(async->session, response) == COAP_INVALID_TID) {
    coap_log(LOG_DEBUG, "check_async: cannot send response for message\n");
  }
  coap_remove_async(ctx, async->session, async->id, &tmp);
  coap_free_async(async);
  async = NULL;
}
#endif /* WITHOUT_ASYNC */
/*
 * Regular DELETE handler - used by resources created by the
 * Unknown Resource PUT handler
 */

static void
hnd_delete(coap_context_t *ctx,
           coap_resource_t *resource,
           coap_session_t *session UNUSED_PARAM,
           coap_pdu_t *request UNUSED_PARAM,
           coap_binary_t *token UNUSED_PARAM,
           coap_string_t *query UNUSED_PARAM,
           coap_pdu_t *response UNUSED_PARAM
) {
  srv_cnt++;
  srv_delete_cnt++;
  int i;
  coap_string_t *uri_path;

  /* get the uri_path */
  uri_path = coap_get_uri_path(request);
  if (!uri_path) {
    response->code = COAP_RESPONSE_CODE(404);
    return;
  }

  for (i = 0; i < dynamic_count; i++) {
    if (coap_string_equal(uri_path, dynamic_entry[i].uri_path)) {
      /* Dynamic entry no longer required - delete it */
      coap_delete_string(dynamic_entry[i].value);
      if (dynamic_count-i > 1) {
         memmove (&dynamic_entry[i],
                  &dynamic_entry[i+1],
                 (dynamic_count-i-1) * sizeof (dynamic_entry[0]));
      }
      dynamic_count--;
      break;
    }
  }

  /* Dynamic resource no longer required - delete it */
  coap_delete_resource(ctx, resource);
  response->code = COAP_RESPONSE_CODE(202);
  fprintf(stderr," Delete server invoked %d  times; all servers invoked %d times, number of open coap_malloc is %d \n", srv_delete_cnt, srv_cnt, (int)coap_nr_of_alloc());  
  return;
}

/*
 * Regular GET handler - used by resources created by the
 * Unknown Resource PUT handler
 */

static void
hnd_get(coap_context_t *ctx UNUSED_PARAM,
        coap_resource_t *resource,
        coap_session_t *session,
        coap_pdu_t *request,
        coap_binary_t *token,
        coap_string_t *query UNUSED_PARAM,
        coap_pdu_t *response
) {
  srv_cnt++;
  srv_get_cnt++;
  coap_str_const_t *uri_path;
  int i;
  dynamic_resource_t *resource_entry = NULL;
  coap_str_const_t value = { 0, NULL };
  /*
   * request will be NULL if an Observe triggered request, so the uri_path,
   * if needed, must be abstracted from the resource.
   * The uri_path string is a const pointer
   */

  uri_path = coap_resource_get_uri_path(resource);
  if (!uri_path) {
    response->code = COAP_RESPONSE_CODE(404);
    return;
  }

  for (i = 0; i < dynamic_count; i++) {
    if (coap_string_equal(uri_path, dynamic_entry[i].uri_path)) {
      break;
    }
  }
  if (i == dynamic_count) {
    response->code = COAP_RESPONSE_CODE(404);
    return;
  }

  resource_entry = &dynamic_entry[i];

  if (resource_entry->value) {
    value.length = resource_entry->value->length;
    value.s = resource_entry->value->s;
  }
  coap_add_data_blocked_response(resource, session, request, response, token,
                                 resource_entry->media_type, -1,
                                 value.length,
                                 value.s);     
  fprintf(stderr,"Get server invoked %d  times; all servers invoked %d times, number of open coap_malloc is %d \n", srv_get_cnt, srv_cnt, (int)coap_nr_of_alloc());				                          
  return;
}

/*
 * Regular PUT handler - used by resources created by the
 * Unknown Resource PUT handler
 */

static void
hnd_put(coap_context_t *ctx UNUSED_PARAM,
        coap_resource_t *resource,
        coap_session_t *session UNUSED_PARAM,
        coap_pdu_t *request,
        coap_binary_t *token UNUSED_PARAM,
        coap_string_t *query UNUSED_PARAM,
        coap_pdu_t *response
) {
  srv_cnt++;
  srv_put_cnt++; 
  coap_string_t *uri_path;
  int i;
  size_t size;
  uint8_t *data;
  coap_block_t block1;
  dynamic_resource_t *resource_entry = NULL;
  unsigned char buf[6];      /* space to hold encoded/decoded uints */
  coap_opt_iterator_t opt_iter;
  coap_opt_t *option;

  /* get the uri_path */
  uri_path = coap_get_uri_path(request);
  if (!uri_path) {
    response->code = COAP_RESPONSE_CODE(404);
    return;
  }

  /*
   * Locate the correct dynamic block for this request
   */
  for (i = 0; i < dynamic_count; i++) {
    if (coap_string_equal(uri_path, dynamic_entry[i].uri_path)) {
      break;
    }
  }
  if (i == dynamic_count) {
    if (dynamic_count >= support_dynamic) {
      /* Should have been caught in hnd_unknown_put() */
      response->code = COAP_RESPONSE_CODE(406);
      coap_delete_string(uri_path);
      return;
    }
    dynamic_count++;
    dynamic_entry = realloc (dynamic_entry, dynamic_count * sizeof(dynamic_entry[0]));
    if (dynamic_entry) {
      dynamic_entry[i].uri_path = uri_path;
      dynamic_entry[i].value = NULL;
      dynamic_entry[i].resource = resource;
      dynamic_entry[i].created = 1;
      response->code = COAP_RESPONSE_CODE(201);
      if ((option = coap_check_option(request, COAP_OPTION_CONTENT_TYPE, &opt_iter)) != NULL) {
        dynamic_entry[i].media_type =
            coap_decode_var_bytes (coap_opt_value (option), coap_opt_length (option));
      }
      else {
        dynamic_entry[i].media_type = COAP_MEDIATYPE_TEXT_PLAIN;
      }
      /* Store media type of new resource in ct. We can use buf here
       * as coap_add_attr() will copy the passed string. */
      memset(buf, 0, sizeof(buf));
      snprintf((char *)buf, sizeof(buf), "%d", dynamic_entry[i].media_type);
      /* ensure that buf is always zero-terminated */
      assert(buf[sizeof(buf) - 1] == '\0');
      buf[sizeof(buf) - 1] = '\0';
      coap_add_attr(resource,
                    coap_make_str_const("ct"),
                    coap_make_str_const((char*)buf),
                    0);
    } else {
      dynamic_count--;
      response->code = COAP_RESPONSE_CODE(500);
      return;
    }
  } else {
    /* Need to do this as coap_get_uri_path() created it */
    coap_delete_string(uri_path);
    response->code = COAP_RESPONSE_CODE(204);
    dynamic_entry[i].created = 0;
    coap_resource_notify_observers(dynamic_entry[i].resource, NULL);
  }

  resource_entry = &dynamic_entry[i];

  if (coap_get_block(request, COAP_OPTION_BLOCK1, &block1)) {
    /* handle BLOCK1 */
    if (coap_get_data(request, &size, &data) && (size > 0)) {
      size_t offset = block1.num << (block1.szx + 4);
      coap_string_t *value = resource_entry->value;
      if (offset == 0) {
        if (value) {
          coap_delete_string(value);
          value = NULL;
        }
      }
      else if (offset >
            (resource_entry->value ? resource_entry->value->length : 0)) {
        /* Upload is not sequential - block missing */
        response->code = COAP_RESPONSE_CODE(408);
        return;
      }
      else if (offset <
            (resource_entry->value ? resource_entry->value->length : 0)) {
        /* Upload is not sequential - block duplicated */
        goto just_respond;
      }
      /* Add in new block to end of current data */
      resource_entry->value = coap_new_string(offset + size);
      memcpy (&resource_entry->value->s[offset], data, size);
      resource_entry->value->length = offset + size;
      if (value) {
        memcpy (resource_entry->value->s, value->s, value->length);
        coap_delete_string(value);
      }
    }
just_respond:
    if (block1.m) {
      response->code = COAP_RESPONSE_CODE(231);
    }
    else if (resource_entry->created) {
      response->code = COAP_RESPONSE_CODE(201);
    }
    else {
      response->code = COAP_RESPONSE_CODE(204);
    }
    coap_add_option(response,
                    COAP_OPTION_BLOCK1,
                    coap_encode_var_safe(buf, sizeof(buf),
                                         ((block1.num << 4) |
                                          (block1.m << 3) |
                                          block1.szx)),
                    buf);
  }
  else if (coap_get_data(request, &size, &data) && (size > 0)) {
    /* Not a BLOCK1 with data */
    if (resource_entry->value) {
      coap_delete_string(resource_entry->value);
      resource_entry->value = NULL;
    }
    resource_entry->value = coap_new_string(size);
    memcpy (resource_entry->value->s, data, size);
    resource_entry->value->length = size;
  }
  else {
    /* Not a BLOCK1 and no data */
    if (resource_entry->value) {
      coap_delete_string(resource_entry->value);
      resource_entry->value = NULL;
    }
  }
  fprintf(stderr,"Put server invoked %d  times; all servers invoked %d times, number of open coap_malloc is %d \n", srv_put_cnt, srv_cnt, (int)coap_nr_of_alloc());  
}

/*
 * Unknown Resource PUT handler
 */

static void
hnd_unknown_put(coap_context_t *ctx,
                coap_resource_t *resource UNUSED_PARAM,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query,
                coap_pdu_t *response
) {
  srv_cnt++;
  srv_put_cnt++;
  coap_resource_t *r;
  coap_string_t *uri_path;

  /* get the uri_path - will will get used by coap_resource_init() */
  uri_path = coap_get_uri_path(request);
  if (!uri_path) {
    response->code = COAP_RESPONSE_CODE(404);
    return;
  }

  if (dynamic_count >= support_dynamic) {
    response->code = COAP_RESPONSE_CODE(406);
    return;
  }

  /*
   * Create a resource to handle the new URI
   * uri_path will get deleted when the resource is removed
   */
  r = coap_resource_init((coap_str_const_t*)uri_path,
        COAP_RESOURCE_FLAGS_RELEASE_URI | resource_flags);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"Dynamic\""), 0);
  coap_register_handler(r, COAP_REQUEST_PUT, hnd_put);
  coap_register_handler(r, COAP_REQUEST_DELETE, hnd_delete);
  /* We possibly want to Observe the GETs */
  coap_resource_set_get_observable(r, 1);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get);
  coap_add_resource(ctx, r);

  /* Do the PUT for this first call */
  hnd_put(ctx, r, session, request, token, query, response);
  fprintf(stderr," Put server invoked %d  times; all servers invoked %d times, number of open coap_malloc is %d \n", srv_put_cnt, srv_cnt, (int)coap_nr_of_alloc());  
  return;
}

/* cr_namenr(uint8_t *result)
 * creates identifier of 6 ciphers for unique name
 */
static void
cr_namenr(uint8_t * result){
   uint32_t numb=rand();
   for (uint8_t qq=0; qq < 6; qq++){
     uint32_t numb10 = numb/10;
     result[qq] = numb -10*numb10 +0x30;
     numb = numb10;
   }
}

#define HANDLE_BLOCK1(Pdu)                                        \
  ((method == COAP_REQUEST_PUT || method == COAP_REQUEST_POST) && \
   ((flags & FLAGS_BLOCK) == 0) &&                                \
   ((Pdu)->hdr->code == COAP_RESPONSE_CODE(201) ||                \
    (Pdu)->hdr->code == COAP_RESPONSE_CODE(204)))

/* find_status_session
 * find status of pledge for current session
 */
static  status_t *
find_status_session(coap_session_t *session){
	status_t *status = STATUS;
	while (status != NULL){
		if (status->session == session) return status;
		status = status->next;
	}
	return NULL;
}

/* unchain status
 * remove status from status queue
 *//*
static void
unchain_status(status_t *status){
	status_t *temp = STATUS;
	if (STATUS == temp){
		STATUS = temp->next;
		return;
	}
	status_t *former = STATUS;	
	temp = former->next;	
	while (temp != NULL){
		if (status == temp){
			former->next = temp->next;
			return;
	    }
	    former = temp;
	    temp = temp->next;
	}
}
*/

/* find_status_request
 * find status of pledge for given request_voucher
 */
static  status_t *
find_status_request(voucher_t *request){
	status_t *status = STATUS;
	while (status != NULL){
		if (request->domainid_len == status->domainid_len){
			if (memcmp(status->domainid, request->domainid, status->domainid_len) == 0)
			      return status;
		}
		if (request->cvr_idevid_len == status->cvr_idevid_len){
			if (memcmp(status->cvr_idevid, request->cvr_idevid, request->cvr_idevid_len) == 0)
			     return status;
		}
		status = status->next;
	}
	return NULL;
}

static int8_t 
insert_status(voucher_t *voucher_request, coap_string_t *request_voucher, coap_session_t *session){
	status_t *status = find_status_request(voucher_request);
	if (status != NULL) return 0;
	status = coap_malloc(sizeof(status_t));
	memset(status, 0, sizeof(status_t));
	status->next = STATUS;
	STATUS = status;
	if (voucher_request->cvr_nonce_len > 0){
      status->cvr_nonce= coap_malloc(voucher_request->cvr_nonce_len);
      status->cvr_nonce_len = voucher_request->cvr_nonce_len;
      memcpy(status->cvr_nonce, voucher_request->cvr_nonce, status->cvr_nonce_len);
    }
    if (voucher_request->cvr_idevid_len > 0){
      status->cvr_idevid = coap_malloc(voucher_request->cvr_idevid_len);
      status->cvr_idevid_len = voucher_request->cvr_idevid_len;
      memcpy(status->cvr_idevid, voucher_request->cvr_idevid, status->cvr_idevid_len);
    }
    if (voucher_request->serial_len > 0){
      status->serial = coap_malloc(voucher_request->serial_len);
      status->serial_len = voucher_request->serial_len;
      memcpy(status->serial, voucher_request->serial, status->serial_len);
    }
    status->session = session;
    if (request_voucher->length > 0){
      status->request_voucher = coap_malloc(request_voucher->length);
      status->rv_len = request_voucher->length;
	  memcpy(status->request_voucher, request_voucher->s, request_voucher->length);
	  status->json_cbor = JSON_set();
    }
	status->acceptable = VOUCHER_ACCEPTABLE;   /* assume it is OK  */
	if (voucher_request->domainid_len > 0){
	  status->domainid = coap_malloc(voucher_request->domainid_len);
	  status->domainid_len = voucher_request->domainid_len;
	  memcpy(status->domainid, voucher_request->domainid, voucher_request->domainid_len);
    }
	return 0;
}

/* return_MASAurl
 * returns MASAurl in x509 v3 ca certificate 
 * returns Ok =0 , Nok 1
 * asn is pointer to subject asn1 string
 *  contains returned key identifier
 */
static int8_t
return_MASAurl( mbedtls_x509_buf *asn, coap_string_t *MASA_url){
	uint8_t   url[8] = {0x2b, 0x06, 0x01, 0x05, 0x05,0x07,0x01,0x20};
	coap_string_t oid_name = {.length = sizeof(url), .s = url};
	coap_string_t temp = {.length = 0, .s = NULL};
	int8_t ok = brski_return_oid( asn, &oid_name, &temp);
	/* in this case return string is preceded by 2 character */
	/* add NULL string at end */
	if (temp.s != NULL){
	  MASA_url->length = temp.length -1;
	  MASA_url->s = coap_malloc(temp.length - 1);
	  memcpy(MASA_url->s, temp.s+2, temp.length -2);
	  MASA_url->s[temp.length - 2] = 0;
	  coap_free(temp.s);
    }
    return ok;
}

static void
create_port(coap_string_t *host_name, coap_string_t *port_name){
	uint8_t fnd = 0;
	for (uint8_t qq = 0; qq < host_name->length; qq++)if (host_name->s[qq] == ':')fnd = qq;
	if (fnd == 0){  /* default port */
		port_name->s = coap_malloc(sizeof(SERVER_PORT)+1);
		port_name->length = sizeof(SERVER_PORT);
		memcpy(port_name->s, SERVER_PORT, sizeof(SERVER_PORT));
		port_name->s[sizeof(SERVER_PORT)] = 0;
	} else {/* use specified port */
	    port_name->s = coap_malloc(host_name->length - fnd);
		port_name->length = host_name->length - fnd;
		memcpy(port_name->s, host_name->s + fnd + 1, host_name->length - fnd - 1);
	    port_name->s[host_name->length - fnd] = 0;
	    host_name->length = fnd;
	    host_name->s[fnd] = 0;
	}
}

#define DEBUG_LEVEL 0

static void my_debug( void *ctx, int level,
                      const char *file, int line,
                      const char *str )
{
    ((void) level);

    fprintf( stderr, "%s:%04d: %s", file, line, str );
}


#define POST_REQUEST_RV "POST /.well-known/brski/requestvoucher HTTP/1.0\r\n"
#define COSE_CBOR "Content-Type: application/voucher-cose+cbor\r\n"
#define JSON_CMS "Content-Type: application/voucher-cms+json\r\n"
#define APP_JSON "Content-Type: application/json\r\n"
#define APP_CBOR "Content-Type: application/cbor\r\n"
#define POST_REQUEST_RA "POST /.well-known/brski/requestauditlog HTTP/1.0\r\n"
#define ACCEPT_COSE_CBOR "Accept: application/voucher-cose+cbor\r\n"
#define ACCEPT_JSON_CMS  "Accept: application/voucher-cms+json\r\n"
#define ACCEPT_APP_CBOR  "Accept: application/cbor\r\n"
#define ACCEPT_APP_JSON  "Accept: application/json\r\n"
#define HOST "Host: "
#define CONTENT_LENGTH "Content-Length: "
#define STARTPL "\r\n\r\n"
/*
* call_http_MASA
* calls MASA http server with POST
* on input, string with MASA resource and MASA host name to invoke
* and POST payload
* on output, returns response_code from MASA
*/
int16_t
call_http_MASA(coap_string_t *payload, coap_string_t *resource, coap_string_t *host_name, coap_string_t *answer){
	int ret = 1, len_t;
	int16_t response_code = 0;
    mbedtls_net_context server_fd;
    uint32_t flags;
    unsigned char buf[BUFLEN];
    const char *pers = "registrar_client";
    char ca_file_name[] = CA_REGIS_CRT;
    char client_file_name[] = REGIS_SRV_CRT;   
    char  key_file_name[]   = REGIS_SRV_KEY; 
    char  passwd[] = "watnietweet";
    pki_sni_entry entry;
    coap_string_t port_name = {.s = NULL, .length = 0};  
    char *sbuf = NULL;
    char *end  = NULL;      
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt cltcert;      
    mbedtls_pk_context pkey;

    /*
     * 0. Initialize the RNG and the session data
     */
    mbedtls_net_init( &server_fd );
    mbedtls_ssl_init( &ssl );
    mbedtls_ssl_config_init( &conf );
    mbedtls_x509_crt_init( &cacert );
    mbedtls_x509_crt_init( &cltcert );    
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_pk_init( &pkey );    
    mbedtls_debug_set_threshold( DEBUG_LEVEL );
    mbedtls_entropy_init( &entropy );
    if( ( ret = mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) ) != 0 )
    {
        coap_log( LOG_ERR, " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret );
        goto exit;
    }
    
    /*
     * -1 Check host name
     */
     
     char unknown[]= "unknownhost";   /* used as test value for non existent masa */
     struct addrinfo hints;
     struct addrinfo *addr;
     memset(&hints, 0, sizeof(hints));
     create_port(host_name, &port_name);
     int s = getaddrinfo((const char *)host_name->s, NULL, &hints, &addr); 
     if (s!= 0){
       coap_log(LOG_ERR," host name %s of Registrar generates error: %s \n", host_name->s, gai_strerror(s));
       freeaddrinfo(addr);
       goto exit;
     }
     freeaddrinfo(addr);
     if (strcmp((char *)host_name->s, unknown) == 0){
       coap_log(LOG_ERR," host name %s of Registrar does not exist per definition\n", host_name->s);
       goto exit;
     }

    /*
     * 0. Initialize certificates
     */
    coap_log(LOG_INFO, "  . Loading the server certificate from %s  to cacert\n", client_file_name );

    ret = mbedtls_x509_crt_parse_file( &cacert, client_file_name );
    if( ret < 0 )
    {
	  coap_log( LOG_ERR, " failed\n  !  mbedtls_x509_crt_parse_file returned -0x%x\n\n", (unsigned int) -ret );
	  goto exit;
    }
    
    coap_log(LOG_INFO, "loading server certificate from %s to cltcert\n", client_file_name);
    ret = mbedtls_x509_crt_parse_file( &cltcert, client_file_name );
    if( ret != 0 )
    {
	  coap_log( LOG_ERR, "failed\n  !  mbedtls_x509_crt_parse_file returned %d\n\n", ret );
      goto exit;
    }
    coap_log(LOG_INFO, "loading the CA root certificate from %s to ca_cert\n", ca_file_name);
    ret = mbedtls_x509_crt_parse_file( &cacert, ca_file_name );
    if( ret != 0 )
    {
	  coap_log( LOG_ERR, "failed\n  !  mbedtls_x509_crt_parse_file returned %d\n\n", ret );
      goto exit;
    }
    
    coap_log(LOG_INFO, "  . Loading the server key file ... name %s ...", key_file_name);
    ret =  mbedtls_pk_parse_keyfile( &pkey, key_file_name, passwd );
    if( ret != 0 )
    {
        coap_log(LOG_ERR, " failed\n  !  mbedtls_pk_parse_keyfile returned %d\n\n", ret );
        goto exit;
    }
    /*
     * 1. Start the connection
     */

    if( ( ret = mbedtls_net_connect( &server_fd, (char *)host_name->s,
                                         (char *)port_name.s, MBEDTLS_NET_PROTO_TCP ) ) != 0 )
    {
       coap_log( LOG_ERR, " failed\n  ! mbedtls_net_connect returned %d\n\n", ret );
       goto exit;
    }
    /*
     * 2. Setup stuff
     */
    if( ( ret = mbedtls_ssl_config_defaults( &conf,
                    MBEDTLS_SSL_IS_CLIENT,
                    MBEDTLS_SSL_TRANSPORT_STREAM,
                    MBEDTLS_SSL_PRESET_DEFAULT ) ) != 0 )
    {
	  coap_log( LOG_ERR, " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
	  goto exit;
    }


    /* OPTIONAL is not optimal for security,
     * but makes but nexessary in Registar <=> MASA exchange */
    mbedtls_ssl_conf_authmode( &conf, MBEDTLS_SSL_VERIFY_OPTIONAL );
    mbedtls_ssl_conf_ca_chain( &conf, &cacert, NULL );
    mbedtls_ssl_conf_verify(&conf,
                          cert_verify_callback_mbedtls, &entry);
    if( ( ret = mbedtls_ssl_conf_own_cert( &conf, &cacert, &pkey ) ) != 0 )
        {
            coap_log(LOG_ERR, " failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n",
                            ret );
            goto exit;
        }
    mbedtls_ssl_conf_rng( &conf, mbedtls_ctr_drbg_random, &ctr_drbg );
    mbedtls_ssl_conf_dbg( &conf, my_debug, stdout );
    entry.cacert = &cacert;
    entry.public_cert = &cltcert;
    entry.private_key = &pkey;
    mbedtls_ssl_conf_sni( &conf, sni_callback, &entry );

    if( ( ret = mbedtls_ssl_setup( &ssl, &conf ) ) != 0 )
    {
	  coap_log( LOG_ERR, " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret );
      goto exit;
    }

    if( ( ret = mbedtls_ssl_set_hostname( &ssl, CN_NAME ) ) != 0 )
    {
      coap_log( LOG_ERR, " failed\n  ! mbedtls_ssl_set_hostname returned %d\n\n", ret );
      goto exit;
    }

    mbedtls_ssl_set_bio( &ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL );
    /*
     * 4. Handshake
     */
    while( ( ret = mbedtls_ssl_handshake( &ssl ) ) != 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
            coap_log( LOG_ERR, "failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", (unsigned int) -ret );
            goto exit;
        }
    }
    /*
     * 5. Verify the server certificate
     */

    /* ret != 0 because Registrar cannot verify server certificate */
    if( ( flags = mbedtls_ssl_get_verify_result( &ssl ) ) != 0 )
    {
        char vrfy_buf[512];
        mbedtls_x509_crt_verify_info( vrfy_buf, sizeof( vrfy_buf ), "  Server certificate :  ", flags );
        coap_log(LOG_WARNING, "%s\n", vrfy_buf );
    }
    /*
     * 6. Write the POST request
     */
    len_t = resource->length + payload->length;   
    if (len_t > BUFLEN){
		coap_log(LOG_ERR,"Payload for POST request is too large \n");
		ret = 1;
		goto exit;
	}
	memcpy( buf, resource->s, resource->length);
	if (coap_get_log_level() > LOG_INFO){
	   fprintf(stderr,"http header contains %d bytes:\n", (int)resource->length);
	   for (uint qq =0; qq < resource->length; qq++)fprintf(stderr,"%c",resource->s[qq]);
	   fprintf(stderr,"\n");
    } 
		
	memcpy(buf + resource->length, payload->s, payload->length);
	if (coap_get_log_level() > LOG_INFO){
       fprintf(stderr,"http payload is :\n");
	   for (uint qq =0; qq < payload->length; qq++)fprintf(stderr,"%02x",payload->s[qq]);
	   fprintf(stderr,"\n");
    }

    while( ( ret = mbedtls_ssl_write( &ssl, buf, len_t ) ) <= 0 )
    {
        if( ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE )
        {
           coap_log( LOG_ERR, "failed\n  ! mbedtls_ssl_write returned %d\n\n", ret );
           goto exit;
        }
    }
    if (len_t == ret)
          coap_log( LOG_DEBUG, " %d bytes written\n", len_t );
    else { 
       coap_log(LOG_ERR," bytes written is unequal to bytes proposed in POST requst \n");
   }
    /*
     * 7. Read the HTTP response
     */

    do
    {
        len_t = sizeof( buf ) - 1;
        memset( buf, 0, sizeof( buf ) );
        ret = mbedtls_ssl_read( &ssl, buf, len_t );

        if( ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE )
            continue;

        if( ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY )
            break;
        if( ret < 0 )
        {
            coap_log( LOG_ERR, "failed\n  ! mbedtls_ssl_read returned %d\n\n", ret );
            goto exit;
        }

        if( ret == 0 )
        {
            coap_log( LOG_ERR, "no data returned from POST request \n" );
            break;
        }
        len_t = ret;
        sbuf = (char *)buf;
        end  = sbuf + len_t;
        char explain[RESULT_LEN];
      
        skip_blanks(&sbuf, end);
        enum http_vers cur_version = parse_httpversion(&sbuf, end);
        coap_log(LOG_INFO, "found version    %s \n",http_version[(int)cur_version]);
        response_code = read_number(&sbuf, end);
        coap_log(LOG_INFO, "response_code is %d   with text: \n", response_code);
        response_text(&sbuf, end, explain);
        coap_log(LOG_INFO, "%s \n",explain);
        skip_separator(&sbuf, end);       
        enum http_ct ct_found = unknown_ct; 
        while ((test_separator(sbuf, end) == 1) && (sbuf+3 < end)){
		  enum http_att cur_att = parse_attribute(&sbuf, end);
          if (cur_att == ct){
		     ct_found = parse_ct(&sbuf, end);
		     if (ct_found == n_ct)coap_log(LOG_INFO, "unknown content type %s \n",sbuf);
		     else coap_log(LOG_INFO, " found content_type  %s \n", content_type[(int)ct_found]);
		  } else if  (cur_att == txt){ 
			  response_text(&sbuf, end, explain);
			  coap_log(LOG_INFO, " found Text  %s \n", explain);
		  } else if  (cur_att == sts){ 
			  response_text(&sbuf, end, explain);
			  coap_log(LOG_INFO, " found Status  %s \n", explain);	
		  } else if  (cur_att == cnt){ 
			  response_text(&sbuf, end, explain);
			  coap_log(LOG_INFO, " found Connection  %s \n", explain);			  		  
		  } else if (cur_att == cl){
		    int pl_length = parse_cl(&sbuf, end);
		    coap_log(LOG_INFO,"Content_length is %d \n",pl_length);
		  }  
		  skip_separator(&sbuf, end);
	    }
		skip_separator(&sbuf, end);
		if (coap_get_log_level() > LOG_INFO){
		   fprintf(stderr, "payload contains %d bytes \n", (int)(end - sbuf));
		   for (uint qq = 0; qq < (end-sbuf); qq++)printf(" %02x", (uint8_t)sbuf[qq]);
		   printf( "\n");
		   for (uint qq = 0; qq < (end-sbuf); qq++){
			   if ((sbuf[qq] > 31) && (sbuf[qq] < 126))printf("%c", (uint8_t)sbuf[qq]);
			   else printf(".");
		   }
		   printf( "\n");
	    }
		if ((ct_found != unknown_ct) && (response_code < 300) && (cur_version != unknown_version)){
		  answer->length = (end - sbuf);
		  answer->s = coap_malloc(end - sbuf);
		  memcpy(answer->s, sbuf,(end - sbuf));
	    }
    }
    while( 1 );
    goto okret;
exit:
    response_code = 400;  /* no access to http server  */
okret:    
    mbedtls_ssl_close_notify( &ssl );
    mbedtls_net_free( &server_fd );
    mbedtls_x509_crt_free( &cacert );
    mbedtls_x509_crt_free( &cltcert );  
    mbedtls_pk_free(&pkey);  
    mbedtls_ssl_free( &ssl );
    mbedtls_ssl_config_free( &conf );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    coap_free(port_name.s);  
    return response_code;
}

/*
 * call_MASA_ra
 * calls to MASA for request audit log (ra) request
 * sends original unsigned request_voucher to MASA
 * modifies contents of status when necessary
 */
int16_t
call_MASA_ra(status_t *status, coap_string_t *answer, char *file_name){
	mbedtls_x509_crt pledge_crt;
    mbedtls_x509_crt_init( &pledge_crt);
#define CRT_BUF_SIZE            1024    
    char err_buf[CRT_BUF_SIZE]; 
    int ret = 1;
    if( ( ret = mbedtls_x509_crt_parse_file( &pledge_crt, file_name ) ) != 0 )
    {
       mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
       coap_log( LOG_ERR, " failed\n  !  mbedtls_x509_crt_parse_file %s: "
                            "returned -0x%04x - %s\n\n", file_name, (unsigned int) -ret, err_buf );
       mbedtls_x509_crt_free(&pledge_crt);                    
       return 400;
     }
     coap_string_t MASA_url = { .s = NULL, .length = 0};
     int16_t ok = return_MASAurl( &pledge_crt.v3_ext, &MASA_url);
     
	if (ok != 0){ 
	  coap_log(LOG_ERR, "no MASAurlextension found \n");
	  return 400;
    }
    if (status->json_cbor != JSON_set()){
		coap_log(LOG_ERR, "stored status uses different cbor/json format \n");
		return 400;
	}
    coap_string_t payload = { .length = status->rv_len, .s = status->request_voucher};
    size_t resource_size = sizeof(POST_REQUEST_RA) + sizeof(HOST) + MASA_url.length + sizeof(ACCEPT_COSE_CBOR) + 
                                  sizeof(COSE_CBOR) + sizeof(CONTENT_LENGTH)+ sizeof(STARTPL) + 10; /* leaves few bytes for length  */                         
    coap_string_t resource = {.length =  resource_size, .s = NULL};	
    resource.s = coap_malloc(resource_size);
    memcpy(resource.s, POST_REQUEST_RA, sizeof(POST_REQUEST_RA)-1);
    uint16_t offset = sizeof(POST_REQUEST_RA)-1;
    memcpy(resource.s + offset, HOST, sizeof(HOST)-1);
    offset += sizeof(HOST)-1;
    memcpy(resource.s + offset, MASA_url.s, MASA_url.length-1);
    offset += MASA_url.length-1;
    resource.s[offset] = '\r'; offset++;
    resource.s[offset] = '\n'; offset++;    
    if (JSON_set() == JSON_ON){
	  memcpy(resource.s + offset, ACCEPT_APP_JSON, sizeof(ACCEPT_APP_JSON)-1);
      offset += sizeof(ACCEPT_APP_JSON)-1;
	  memcpy(resource.s + offset, APP_JSON, sizeof(APP_JSON)-1);
      offset += sizeof(APP_JSON)-1; 
	}
	else {
	  memcpy(resource.s + offset, ACCEPT_APP_CBOR, sizeof(ACCEPT_APP_CBOR)-1);
      offset += sizeof(ACCEPT_APP_CBOR)-1;
      memcpy(resource.s + offset, APP_CBOR, sizeof(APP_CBOR)-1);
      offset += sizeof(APP_CBOR)-1; 
    }
    memcpy(resource.s + offset, CONTENT_LENGTH, sizeof(CONTENT_LENGTH)-1);
    offset += sizeof(CONTENT_LENGTH)-1;  
    offset += sprintf((char *)(resource.s + offset), "%d", (int)status->rv_len);   
    memcpy(resource.s + offset, STARTPL, sizeof(STARTPL)-1);
    offset += sizeof(STARTPL)-1;  
    resource.length = offset;  
    if (offset < resource_size)     
	       ok = call_http_MASA(&payload, &resource, &MASA_url, answer);
	else ok = 400;
    mbedtls_x509_crt_free(&pledge_crt);    	
	if (MASA_url.s != NULL)coap_free(MASA_url.s);
	if (resource.s != NULL)coap_free(resource.s);
    return ok;
}

/*
 * call_MASA_rv
 * prepares call to MASA for request voucher (rv) request
 * and sends masa_request to MASA using TLS
 */
 int16_t
 call_MASA_rv(coap_string_t *masa_request, coap_string_t *masa_voucher, char * file_name){
	mbedtls_x509_crt pledge_crt;
    mbedtls_x509_crt_init( &pledge_crt);
#define CRT_BUF_SIZE            1024    
    char err_buf[CRT_BUF_SIZE]; 
    int ret = 1;
    coap_log(LOG_INFO, "call_MASA_rv pledge file name is %s \n", file_name);
    if( ( ret = mbedtls_x509_crt_parse_file( &pledge_crt, file_name ) ) != 0 )
    {
       mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
       coap_log( LOG_ERR, " failed\n  !  mbedtls_x509_crt_parse_file %s: "
                            "returned -0x%04x - %s\n\n", file_name, (unsigned int) -ret, err_buf );
       mbedtls_x509_crt_free(&pledge_crt);                    
       return 400;
     }
     coap_string_t MASA_url = { .s = NULL, .length = 0};
     int16_t ok = return_MASAurl( &pledge_crt.v3_ext, &MASA_url);
     if (ok != 0){ 
	    coap_log(LOG_ERR, "no MASAurlextension found \n");
        mbedtls_x509_crt_free(&pledge_crt);   	    
	    return 400;
     }
    size_t resource_size = sizeof(POST_REQUEST_RV) + sizeof(HOST) + MASA_url.length + sizeof(ACCEPT_COSE_CBOR) + 
                                  sizeof(COSE_CBOR) + sizeof(CONTENT_LENGTH) + sizeof(STARTPL)+ 10; /* leaves few bytes for length  */
                                  
    coap_string_t resource = {.length =  resource_size, .s = NULL};	
    resource.s = coap_malloc(resource_size);
    memcpy(resource.s, POST_REQUEST_RV, sizeof(POST_REQUEST_RV)-1);
    uint16_t offset = sizeof(POST_REQUEST_RV)-1;
    memcpy(resource.s + offset, HOST, sizeof(HOST)-1);
    offset += sizeof(HOST)-1;
    memcpy(resource.s + offset, MASA_url.s, MASA_url.length-1);
    offset += MASA_url.length-1;
    resource.s[offset] = '\r'; offset++;
    resource.s[offset] = '\n'; offset++;    
    if (JSON_set() == JSON_ON){
	  memcpy(resource.s + offset, ACCEPT_JSON_CMS, sizeof(ACCEPT_JSON_CMS)-1);
      offset += sizeof(ACCEPT_JSON_CMS)-1;
	  memcpy(resource.s + offset, JSON_CMS, sizeof(JSON_CMS)-1);
      offset += sizeof(JSON_CMS)-1; 
	}
	else {
	  memcpy(resource.s + offset, ACCEPT_COSE_CBOR, sizeof(ACCEPT_COSE_CBOR)-1);
      offset += sizeof(ACCEPT_COSE_CBOR)-1;		
      memcpy(resource.s + offset, COSE_CBOR, sizeof(COSE_CBOR)-1);
      offset += sizeof(COSE_CBOR)-1; 
    }
    memcpy(resource.s + offset, CONTENT_LENGTH, sizeof(CONTENT_LENGTH)-1);
    offset += sizeof(CONTENT_LENGTH)-1;  
    offset += sprintf((char *)(resource.s + offset), "%d", (int)masa_request->length);   
    memcpy(resource.s + offset, STARTPL, sizeof(STARTPL)-1);
    offset += sizeof(STARTPL)-1;  
    resource.length = offset; 
    if (offset < resource_size){     
	       ok = call_http_MASA(masa_request, &resource, &MASA_url, masa_voucher);
	}
	else ok = 400;	 	
	if (MASA_url.s != NULL)coap_free(MASA_url.s);
	if (resource.s != NULL)coap_free(resource.s); 
	mbedtls_x509_crt_free(&pledge_crt);  	 
    return ok;
} 

/* SERVER HANDLING routines  */

/*
 * POST handler - /est/vs
 * receives request to obtain voucher status
 * protected via DTLS
 */
void
RG_hnd_post_vs(coap_context_t *ctx,
                coap_resource_t *resource,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response)
{
  uint8_t* data = NULL;
  size_t size = 0; 
  coap_opt_iterator_t opt_iter;
  coap_opt_t *opt = NULL;
  const uint8_t *fm_value = NULL;   /* value of content-format option */  
  uint16_t content_format  =  COAP_MEDIATYPE_TEXT_PLAIN;
		/* check whether data need to be returend */
  if (request) {
	coap_block_t block2 = { 0, 0, 0};
	if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)){	
	  if (JSON_set() == JSON_ON)content_format = COAP_MEDIATYPE_APPLICATION_JSON;
	  else content_format = COAP_MEDIATYPE_APPLICATION_CBOR;
      coap_add_data_blocked_response(resource, session, request, response, token,
                                 content_format, -1,
                                 RG_ret_data.length, RG_ret_data.s);
     return;
     } /* coap_get_block */
  } /* request */
	
  data = assemble_data(resource, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */
  srv_cnt++;
  srv_post_vs_cnt++;  
  /* RG_ret_data has been used for blocked response => can be liberated for new request */
  if (RG_ret_data.s != NULL) coap_free(RG_ret_data.s);
  RG_ret_data.s = NULL;
  RG_ret_data.length = 0; 
  if ((size < 1) | (data == NULL)){
	  brski_error_return(COAP_RESPONSE_CODE(400), 
      response, "log did not arrive\n");
	  return;
  }
  opt = coap_check_option(request, COAP_OPTION_CONTENT_FORMAT, &opt_iter);
  if (opt){
    fm_value = coap_opt_value(opt);
  }
  if (fm_value != NULL)content_format = (fm_value[0]<<8) + fm_value[1];
  if (content_format == COAP_MEDIATYPE_APPLICATION_JSON) set_JSON(JSON_ON);
  else if (content_format == COAP_MEDIATYPE_APPLICATION_CBOR) set_JSON(JSON_OFF);
  else {
	  brski_error_return(COAP_RESPONSE_CODE(404), 
      response, "Illegal content format\n");
	  return;
  }
  char file_name[] = REGIS_CLIENT_DER;    /* contains pledge certificate in DER */
  coap_string_t log = { .length = size, .s = data};
  /* log contains log data from pledge */
  /* session is identical because same DTLS session */
  status_t *status = find_status_session(session);
  if (status == NULL){
	  brski_error_return(COAP_RESPONSE_CODE(404), 
      response, "no status for this DTLS connection\n");
	  return;
  }
  int8_t ok =0;
  if (JSON_set() == JSON_OFF)
        ok = brski_cbor_readstatus(&log, status);
  else
        ok = brski_json_readstatus(&log, status); 
  if (ok != 0){
  	  brski_error_return(COAP_RESPONSE_CODE(404), 
      response, "log cannot be parsed \n");
	  return;
  }
  if (status->acceptable != VOUCHER_ACCEPTABLE){
	  brski_error_return(COAP_RESPONSE_CODE(404), 
      response, "voucher is not acceptable\n");
	  return;
  }
    /* send acknowledgement */
  coap_tid_t tid = coap_send_ack(session, request);
  if (tid == COAP_INVALID_TID)
            coap_log(LOG_DEBUG, "message_handler: error sending intermediate acknowledgement\n");
  response->type = COAP_MESSAGE_CON;	    
  /* invoke MASA */
  int16_t http_resp = call_MASA_ra( status, &RG_ret_data, file_name);
  if (http_resp > 299){
	  brski_error_return(COAP_RESPONSE_CODE(http_resp),response, "call_MASA_ra returned error\n");
	  return;
  }
  coap_add_data_blocked_response(resource, session, request, response, token,
                                 content_format, -1,
                                 RG_ret_data.length, RG_ret_data.s);  
  fprintf(stderr," Post_vs server  invoked %d  times; all servers invoked %d times, number of open coap_malloc is %d \n", srv_post_vs_cnt, srv_cnt, (int)coap_nr_of_alloc());                            
}

/*
 * GET handler - /est/es
 * receives request to obtain enroll status
 * protected via DTLS
 */
void
RG_hnd_get_es(coap_context_t *ctx UNUSED_PARAM,
                coap_resource_t *resource,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response)
{
  srv_cnt++;
  srv_get_es_cnt++;
  uint8_t* data = NULL;
  size_t size = 0; 
		/* check whether data need to be returend */
  if (request) {
	coap_block_t block2 = { 0, 0, 0};
	if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)){	
      coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_CSRATTRS, -1,
                                 RG_ret_data.length, RG_ret_data.s);
     return;
     } /* coap_get_block */
  } /* request */
	
  data = assemble_data(resource, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */ 
  /* RG_ret_data has been used for blocked response => can be liberated for new request */
  if (RG_ret_data.s != NULL) coap_free(RG_ret_data.s);
  RG_ret_data.s = NULL;
  RG_ret_data.length = 0;   
  response->code = COAP_RESPONSE_CODE(205); 
  int8_t ok = brski_cbor_voucherstatus(&RG_ret_data);
  if (ok != 0){
	  brski_error_return(COAP_RESPONSE_CODE(404), 
      response, "enroll status data not available\n");
	  return;
  }
  response->code = COAP_RESPONSE_CODE(203);   
  fprintf(stderr," post_es server invoked %d  times; all servers invoked %d times, number of open coap_malloc is %d \n", srv_get_es_cnt, srv_cnt, (int)coap_nr_of_alloc());
}

/*
 * POST handler - /est/rv
 * receives request with request voucher
 * protected via DTLS
 */
void
RG_hnd_post_rv(coap_context_t *ctx,
                coap_resource_t *resource,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response)
{
  uint8_t* data = NULL;
  size_t size = 0; 
  coap_opt_iterator_t opt_iter;
  coap_opt_t *opt = NULL;
  const uint8_t *fm_value = NULL;   /* value of content-format option */
  uint16_t content_format  =  COAP_MEDIATYPE_TEXT_PLAIN;
		/* check whether data need to be returend */

  if (request) {
	coap_block_t block2 = { 0, 0, 0};
	if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)){
	  if (JSON_set() == JSON_ON)content_format = COAP_MEDIATYPE_APPLICATION_JSON;
	  else content_format = COAP_MEDIATYPE_APPLICATION_CBOR;
      coap_add_data_blocked_response(resource, session, request, response, token,
                                 content_format, -1,
                                 RG_ret_data.length, RG_ret_data.s);
     return;
     } /* coap_get_block */
  } /* request */
  data = assemble_data(resource, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */
  srv_cnt++;
  srv_post_rv_cnt++; 
  /* RG_ret_data has been used for blocked response => can be liberated for new request */
  if (RG_ret_data.s != NULL) coap_free(RG_ret_data.s);
  RG_ret_data.s = NULL;
  RG_ret_data.length = 0; 
  char comb_file[] = REGIS_SRV_COMB;  
  if ((data == NULL) || (size == 0)){
	  brski_error_return(COAP_RESPONSE_CODE(404), 
      response, "Did not find request data\n");
	  return;
  }
  /* data points to request voucher with size */
  response->code = COAP_RESPONSE_CODE(205);
  opt = coap_check_option(request, COAP_OPTION_CONTENT_FORMAT, &opt_iter);
  if (opt){
    fm_value = coap_opt_value(opt);
  }
  coap_string_t *voucher_request = NULL;
  coap_string_t signed_voucher_request = {.s = data, .length = size};
  char file_name[] = REGIS_CLIENT_DER;    /* contains pledge certificate in DER */
  char ca_name[] = PLEDGE_CA;
  voucher_t *req_contents = NULL;
  if (fm_value != NULL)content_format = (fm_value[0]<<8) + fm_value[1];
  if (content_format == COAP_MEDIATYPE_APPLICATION_VOUCHER_COSE_CBOR){
	  /* signed voucher_request  */
	  voucher_request = brski_verify_cose_signature(&signed_voucher_request, file_name, ca_name);
  } else if (content_format == COAP_MEDIATYPE_APPLICATION_VOUCHER_CMS_JSON){
	  /* signed voucher_request  */
	  voucher_request = brski_verify_cms_signature(&signed_voucher_request, ca_name, file_name);  
  }  else if (content_format == COAP_MEDIATYPE_APPLICATION_CBOR){
	  voucher_request = coap_malloc(sizeof(coap_string_t));
	  voucher_request->length = size;
	  voucher_request->s = data;	
  }  else {
	  brski_error_return(COAP_RESPONSE_CODE(406), 
              response, "illegal media format \n");
	  return;
  }
  if (voucher_request != NULL){
	 if (content_format == COAP_MEDIATYPE_APPLICATION_VOUCHER_COSE_CBOR)
	      req_contents = brski_parse_cbor_voucher(voucher_request);
	 else if (content_format == COAP_MEDIATYPE_APPLICATION_VOUCHER_CMS_JSON) 
	 	  req_contents = brski_parse_json_voucher(voucher_request);   
  } 
  if (req_contents == NULL){
		  brski_error_return(COAP_RESPONSE_CODE(404), 
              response, "voucher request cannot be parsed\n");
          if (voucher_request != NULL){
			  if ((voucher_request->s != NULL) && (voucher_request->s != data))coap_free(voucher_request->s);
			  coap_free(voucher_request);
		  }
	      return;
  }  /* if req_contents  */ 
  /* voucher is accepted by registrar    */  
  status_t *status = find_status_request(req_contents);
  if (status != NULL){
	  if (multiple_pledge_entries){ /* check presence of this voucher request if uniqueness wanted */
          if (voucher_request != NULL){
			  if ((voucher_request->s != NULL) && (voucher_request->s != data))coap_free(voucher_request->s);
			  coap_free(voucher_request);
		  }
		  remove_voucher(req_contents);
		  brski_error_return(COAP_RESPONSE_CODE(403), 
                          response, "this pledge is already enrolled\n");
	      return;
	  } /* mutiple request */
	  else status->session = session; /* to allow manipulation during this session */
  } /* status_request */
  /* start a status log for this device identified by its serial number     */
  else insert_status(req_contents, voucher_request, session);
  if ((voucher_request->s != NULL) && (voucher_request->s != data))coap_free(voucher_request->s);
  coap_free(voucher_request);
  coap_string_t masa_request= {.s = NULL, .length = 0}; 
  int8_t ok = 0;
  if (content_format == COAP_MEDIATYPE_APPLICATION_VOUCHER_CMS_JSON)
      ok = brski_create_json_masa_request(&masa_request, req_contents, &signed_voucher_request, file_name);
  else if (content_format == COAP_MEDIATYPE_APPLICATION_VOUCHER_COSE_CBOR)
      ok = brski_create_cbor_masa_request(&masa_request, req_contents, &signed_voucher_request, file_name);
  remove_voucher(req_contents); 
  
  if (ok != 0){
      if (masa_request.s != NULL) coap_free(masa_request.s);
      brski_error_return(COAP_RESPONSE_CODE(406), 
              response, "MASA voucher_request cannot be generated\n");
	  return;
  } 
  coap_string_t masa_request_sign= {.s = NULL, .length = 0};
  if (content_format == COAP_MEDIATYPE_APPLICATION_VOUCHER_CMS_JSON){
      ok = brski_cms_sign_payload(&masa_request_sign, &masa_request, comb_file );
      set_JSON(JSON_ON);
      /*
      fprintf(stderr,"after brski_cms_sign_payload signed masa_request \n");
      for (uint qq =0; qq < masa_request_sign.length; qq++)fprintf(stderr," %02x",masa_request_sign.s[qq]);
      fprintf(stderr,"\n\n");
      * */
  } else if (content_format == COAP_MEDIATYPE_APPLICATION_VOUCHER_COSE_CBOR){
      ok = brski_cose_sign_payload(&masa_request_sign, &masa_request, comb_file);
      set_JSON(JSON_OFF);
  }
  coap_free(masa_request.s);
  if (ok != 0){
	 brski_error_return(COAP_RESPONSE_CODE(406), 
              response, "cannot sign masa voucher_request\n");
     if (masa_request_sign.s != NULL) coap_free(masa_request_sign.s);
	 return; 
  } 
  /* send acknowledgement */
  coap_tid_t tid = coap_send_ack(session, request);
  if (tid == COAP_INVALID_TID)
            coap_log(LOG_DEBUG, "message_handler: error sending intermediate acknowledgement\n");
  response->type = COAP_MESSAGE_CON;
  /* continue return message */
  int16_t http_resp = call_MASA_rv(&masa_request_sign, &RG_ret_data, file_name);
  if (http_resp > 299){
	  coap_free(masa_request_sign.s);
	  brski_error_return(COAP_RESPONSE_CODE(http_resp),response, "call_MASA_rv returned error\n");
	  return;
  }   
  coap_free(masa_request_sign.s);
  fprintf(stderr," Post_rv server  invoked %d  times; all servers invoked %d times, number of open coap_malloc is %d \n", srv_post_rv_cnt, srv_cnt, (int)coap_nr_of_alloc());  
  coap_add_data_blocked_response(resource, session, request, response, token,
                                 content_format, -1,
                                 RG_ret_data.length, RG_ret_data.s);
}

/*
 * GET handler - /est/crts
 * receives request to obtain CA certificate
 * protected via DTLS
 */
void
RG_hnd_get_crts(coap_context_t *ctx UNUSED_PARAM,
                coap_resource_t *resource,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response)
{
  uint8_t* data = NULL;
  size_t size = 0; 
		/* check whether data need to be returend */
  if (request) {
	coap_block_t block2 = { 0, 0, 0};
	if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)){	
      coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_PKCS7_CERTS, -1,
                                 RG_ret_data.length, RG_ret_data.s);
     return;
     } /* coap_get_block */
  } /* request */
	
  data = assemble_data(resource, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */
  srv_cnt++;
  srv_get_crts_cnt++;  
  /* RG_ret_data has been used for blocked response => can be liberated for new request */
  if (RG_ret_data.s != NULL) coap_free(RG_ret_data.s);
  RG_ret_data.s = NULL;
  RG_ret_data.length = 0; 
  response->code = COAP_RESPONSE_CODE(205); 
 
  int ok = brski_return_certificate(&RG_ret_data);
  if (ok != 0){
	  response->code = COAP_RESPONSE_CODE(403);
	  coap_log(LOG_ERR," certficate cannot be returned \n");
	  return;
  }
  coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_PKCS7_CERTS, -1,
                                 RG_ret_data.length, RG_ret_data.s); 
  fprintf(stderr," get_crts server invoked %d  times; all servers invoked %d times, number of open coap_malloc is %d \n", srv_get_crts_cnt, srv_cnt, (int)coap_nr_of_alloc());                                                   
}

/*
 * POST handler - /est/sen
 * receives request to enroll
 * protected via DTLS
 */
void
RG_hnd_post_sen(coap_context_t *ctx UNUSED_PARAM,
                coap_resource_t *resource,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query UNUSED_PARAM, 
                coap_pdu_t *response)
{
  uint8_t* data = NULL;
  size_t size = 0; 
  coap_opt_iterator_t opt_iter;
  coap_opt_t *opt = NULL;
  const uint8_t *fm_value = NULL;   /* value of content-format option */
  int content_format =  COAP_MEDIATYPE_TEXT_PLAIN;
		/* check whether data need to be returend */
  if (request) {
	coap_block_t block2 = { 0, 0, 0};
	if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)){	
      coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_PKCS7_CERTS, -1,
                                 RG_ret_data.length, RG_ret_data.s);
     return;
     } /* coap_get_block */
  } /* request */
  data = assemble_data(resource, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */
  srv_cnt++;
  srv_post_sen_cnt++;  
   /* RG_ret_data has been used for blocked response => can be liberated for new request */
  if (RG_ret_data.s != NULL) coap_free(RG_ret_data.s);
  RG_ret_data.s = NULL;
  RG_ret_data.length = 0; 
  if ((data == NULL) | (size == 0)){
	  brski_error_return(COAP_RESPONSE_CODE(400), 
      response, "Did not find request data\n");
	  return;
  }
  opt = coap_check_option(request, COAP_OPTION_CONTENT_FORMAT, &opt_iter);
  if (opt){
    fm_value = coap_opt_value(opt);
  }
  if (fm_value != NULL) content_format = (fm_value[0]<<8) + fm_value[1]; 
  if (content_format != COAP_MEDIATYPE_APPLICATION_CBOR){
	  brski_error_return(COAP_RESPONSE_CODE(400), 
      response, "Illegal content format\n");
	  return;
  }
  /* data points to csr with size */
  status_t *status = find_status_session(session);
  if (status == NULL){
	  brski_error_return(COAP_RESPONSE_CODE(400), 
      response, "Did not find status belonging to session\n");
	  return;
  }
  if (status->acceptable == VOUCHER_REJECTED){
	  brski_error_return(COAP_RESPONSE_CODE(404), 
      response, "Voucher is not acceptable\n");
	  return;
  }
  response->code = COAP_RESPONSE_CODE(205); 

/* create certificate  */
  int8_t ok = brski_create_crt(&RG_ret_data, data, size);
  if (ok != 0){
	  brski_error_return(COAP_RESPONSE_CODE(404), 
      response, "CRT cannot be created\n");
	  return;
  }
  coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_PKCS7_CERTS, -1,
                                 RG_ret_data.length, RG_ret_data.s); 
  fprintf(stderr," post_sen server invoked %d  times; all servers invoked %d times, number of open coap_malloc is %d \n", srv_post_sen_cnt, srv_cnt, (int)coap_nr_of_alloc());                                                         
}

/*
 * POST handler - /est/sren
 * receives request to re-enroll
 * protected via DTLS
 */
void
RG_hnd_post_sren(coap_context_t *ctx UNUSED_PARAM,
                coap_resource_t *resource,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response)
{
  uint8_t* data = NULL;
  size_t size = 0; 
		/* check whether data need to be returend */
  if (request) {
	coap_block_t block2 = { 0, 0, 0};
	if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)){	
      coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_PKCS7_CERTS, -1,
                                 RG_ret_data.length, RG_ret_data.s);
     return;
     } /* coap_get_block */
  } /* request */
	
  data = assemble_data(resource, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */  
  srv_cnt++;
  srv_post_sren_cnt++; 
  /* RG_ret_data has been used for blocked response => can be liberated for new request */
  if (RG_ret_data.s != NULL) coap_free(RG_ret_data.s);
  RG_ret_data.s = NULL;
  RG_ret_data.length = 0; 
  if ((data == NULL) | (size == 0)){
	  brski_error_return(COAP_RESPONSE_CODE(400), 
      response, "Did not find request data\n");
	  return;
  }
   /* data points to csr with size */
  status_t *status = find_status_session(session);
  if (status->acceptable == VOUCHER_REJECTED){
	  brski_error_return(COAP_RESPONSE_CODE(404), 
      response, "Voucher is not acceptable\n");
	  return;
  }
  response->code = COAP_RESPONSE_CODE(205); 
  int8_t ok = brski_create_crt(&RG_ret_data, data, size);
  if (ok != 0){
	  brski_error_return(COAP_RESPONSE_CODE(404), 
      response, "CRT cannot be created\n");
	  return;
  }
  if (RG_ret_data.s == NULL) response->code = COAP_RESPONSE_CODE(400);
  coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_PKCS7_CERTS, -1,
                                 RG_ret_data.length, RG_ret_data.s);
  fprintf(stderr," post_sren server invoked %d  times; all servers invoked %d times, number of open coap_malloc is %d \n", srv_post_sren_cnt, srv_cnt, (int)coap_nr_of_alloc());                               
}

/*
 * POST handler - /est/skg
 * receives request to generate key
 * protected via DTLS
 */
void
RG_hnd_post_skg(coap_context_t *ctx UNUSED_PARAM,
                coap_resource_t *resource,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response)
{
  uint8_t *data = NULL;
  size_t size = 0; 
  uint8_t *response1 = NULL;
  size_t resp1_len= 0;
  uint8_t *response2 = NULL;
  size_t resp2_len= 0;
		/* check whether data need to be returend */
  if (request) {
	coap_block_t block2 = { 0, 0, 0};
	if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)){	
      coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_MULTIPART_CORE, -1,
                                 RG_ret_data.length, RG_ret_data.s);
     return;
     } /* coap_get_block */
  } /* request */
	
  data = assemble_data(resource, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */ 
  srv_cnt++;
  srv_post_skg_cnt++;   
  /* RG_ret_data has been used for blocked response => can be liberated for new request */
  if (RG_ret_data.s != NULL) coap_free(RG_ret_data.s);
  RG_ret_data.s = NULL;
  RG_ret_data.length = 0;  
  if ((data == NULL) | (size == 0)){
	  brski_error_return(COAP_RESPONSE_CODE(400), 
      response, "Did not find request data\n");
	  return;
  }
  char file1[] = "/home/pi/certificates/8021ar/work/Wt1234.key.der";
  response1 = read_file_mem(file1, &resp1_len); 
  if (resp1_len > 0)resp1_len--;
  char file2[] = "/home/pi/certificates/8021ar/work/empty.cert.der";
  response2 = read_file_mem(file2, &resp2_len); 
  if (resp2_len > 0)resp2_len--;
  if (resp1_len != 0 && resp2_len != 0){
    response->code = COAP_RESPONSE_CODE(204); 
    RG_ret_data.length = resp1_len + resp2_len + 20;
    if (RG_ret_data.s != NULL) coap_free(RG_ret_data.s);
    RG_ret_data.s = coap_malloc(RG_ret_data.length);
    uint8_t *buf = RG_ret_data.s;
    size_t  nr = 0;
    nr += cbor_put_array(&buf, 4);
    nr += cbor_put_number(&buf, COAP_MEDIATYPE_APPLICATION_PKCS8);
    nr += cbor_put_bytes(&buf, response1, resp1_len);
    coap_free(response1);
    nr += cbor_put_number(&buf, COAP_MEDIATYPE_APPLICATION_PKCS7_CERTS);
    nr += cbor_put_bytes(&buf, response2, resp2_len);
    coap_free(response2);
    RG_ret_data.length = nr;
  }
  else {
	if (resp1_len > 0)coap_free(response1);
	if (resp2_len > 0)coap_free(response2);
	response->code = COAP_RESPONSE_CODE(404);
	RG_ret_data.length =  0;
	if (RG_ret_data.s != NULL) coap_free(RG_ret_data.s);
	RG_ret_data.s = NULL;
  }
  coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_MULTIPART_CORE, -1,
                                 RG_ret_data.length, RG_ret_data.s);
  fprintf(stderr," post-skg server invoked %d  times; all servers invoked %d times, number of open coap_malloc is %d \n", srv_post_skg_cnt, srv_cnt, (int)coap_nr_of_alloc());                         
}

/*
 * GET handler - /est/att
 * receives request to return certificate attributes
 * protected via DTLS
 */
void
RG_hnd_get_att(coap_context_t *ctx UNUSED_PARAM,
                coap_resource_t *resource,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response)
{
  uint8_t* data = NULL;
  size_t size = 0; 
		/* check whether data need to be returend */
  if (request) {
	coap_block_t block2 = { 0, 0, 0};
	if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)){	
      coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_CSRATTRS, -1,
                                 RG_ret_data.length, RG_ret_data.s);
     return;
     } /* coap_get_block */
  } /* request */
  
  data = assemble_data(resource, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */
  srv_cnt++;
  srv_get_att_cnt++;  
  /* RG_ret_data has been used for blocked response => can be liberated for new request */
  if (RG_ret_data.s != NULL) coap_free(RG_ret_data.s);
  RG_ret_data.s = NULL;
  RG_ret_data.length = 0; 
  response->code = COAP_RESPONSE_CODE(205); 
  char file[] = CSR_ATTRIBUTES;
  RG_ret_data.s = read_file_mem(file, &RG_ret_data.length); 
  if (RG_ret_data.length > 0)RG_ret_data.length--;
  response->code = COAP_RESPONSE_CODE(201); 
  coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_CSRATTRS, -1,
                                 RG_ret_data.length, RG_ret_data.s);
  fprintf(stderr," get_att server  invoked %d  times; all servers invoked %d times, number of open coap_malloc is %d \n", srv_get_att_cnt, srv_cnt, (int)coap_nr_of_alloc());                            
}


/*
 * GET handler - IP_brski_Port.s
 * receives requests and sends them on
 * receives responses and returns them on
 * encapsulates DTLS
 */
void
RG_hnd_proxy(coap_context_t *ctx UNUSED_PARAM,
                coap_resource_t *resource,
                coap_session_t *session,
                coap_pdu_t *request,
                coap_binary_t *token,
                coap_string_t *query UNUSED_PARAM,
                coap_pdu_t *response)
{
  srv_cnt++;
  srv_proxy_cnt++;
  char  resp[] = "I am a brski join_proxy ";
  uint8_t *data = NULL;
  uint8_t *resp_data = (uint8_t *)resp;
  size_t data_len = strlen(resp); 
  size_t size = 0;
		/* check whether data need to be returend */
  if (request) {
	coap_block_t block2 = { 0, 0, 0};
	if (coap_get_block(request, COAP_OPTION_BLOCK2, &block2)){	
      coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_CSRATTRS, -1,
                                 RG_ret_data.length, RG_ret_data.s);
     return;
     } /* coap_get_block */
  } /* request */
  
  data = assemble_data(resource, request, response, &size);
  if (data == (void *)-1)return;  /* more blocks to arrive */
  srv_cnt++;
  srv_proxy_cnt++; 
  /* RG_ret_data has been used for blocked response => can be liberated for new request */
  if (RG_ret_data.s != NULL) coap_free(RG_ret_data.s);
  RG_ret_data.s = NULL;
  RG_ret_data.length = 0;    
  response->code = COAP_RESPONSE_CODE(201);  
  coap_add_data_blocked_response(resource, session, request, response, token,
                                 COAP_MEDIATYPE_APPLICATION_CSRATTRS, -1,
                                 data_len, resp_data); 
  fprintf(stderr," Proxy server invoked %d  times; all servers invoked %d times, number of open coap_malloc is %d \n", srv_proxy_cnt, srv_cnt, (int)coap_nr_of_alloc());                                                         
}

static int
verify_cn_callback(const char *cn,
                   const uint8_t *asn1_public_cert,
                   size_t asn1_length,
                   coap_session_t *session UNUSED_PARAM,
                   unsigned depth,
                   int validated UNUSED_PARAM,
                   void *arg UNUSED_PARAM
) {
    coap_log(LOG_INFO, "CN '%s' presented by client (%s)\n",
           cn, depth ? "CA" : "Certificate");

	  coap_log(LOG_INFO," certificate to be written to %s \n", REGIS_CLIENT_DER);
    char file[] = REGIS_CLIENT_DER;
    coap_string_t contents = {.length = asn1_length, .s = NULL};
    contents.s = coap_malloc(asn1_length);
    memcpy(contents.s, asn1_public_cert, asn1_length);
    uint8_t ok = write_file_mem(file, &contents); 
    coap_free(contents.s); 
    if (ok != 0)coap_log(LOG_ERR, "certificate is not written to %s \n", REGIS_CLIENT_DER);    
    return 1;
}

static coap_dtls_key_t *
verify_pki_sni_callback(const char *sni,
                    void *arg UNUSED_PARAM
) {
  static coap_dtls_key_t dtls_key;

  /* Preset with the defined keys */
  memset (&dtls_key, 0, sizeof(dtls_key));
  if (!use_pem_buf) {
    dtls_key.key_type = COAP_PKI_KEY_PEM;
    dtls_key.key.pem.public_cert = cert_file;
    dtls_key.key.pem.private_key = cert_file;
    dtls_key.key.pem.ca_file = ca_file;
  }
  else {
    dtls_key.key_type = COAP_PKI_KEY_PEM_BUF;
    dtls_key.key.pem_buf.ca_cert = ca_mem;
    dtls_key.key.pem_buf.public_cert = cert_mem;
    dtls_key.key.pem_buf.private_key = cert_mem;
    dtls_key.key.pem_buf.ca_cert_len = ca_mem_len;
    dtls_key.key.pem_buf.public_cert_len = cert_mem_len;
    dtls_key.key.pem_buf.private_key_len = cert_mem_len;
  }
  if (sni[0]) {
    size_t i;
    coap_log(LOG_INFO, "SNI '%s' requested\n", sni);
    for (i = 0; i < valid_pki_snis.count; i++) {
      /* Test for SNI to change cert + ca */
      if (strcasecmp(sni, valid_pki_snis.pki_sni_list[i].sni_match) == 0) {
        coap_log(LOG_INFO, "Switching to using cert '%s' + ca '%s'\n",
                 valid_pki_snis.pki_sni_list[i].new_cert,
                 valid_pki_snis.pki_sni_list[i].new_ca);
        dtls_key.key_type = COAP_PKI_KEY_PEM;
        dtls_key.key.pem.public_cert = valid_pki_snis.pki_sni_list[i].new_cert;
        dtls_key.key.pem.private_key = valid_pki_snis.pki_sni_list[i].new_cert;
        dtls_key.key.pem.ca_file = valid_pki_snis.pki_sni_list[i].new_ca;
        break;
      }
    }
  }
  else {
    coap_log(LOG_DEBUG, "SNI not requested\n");
  }
  return &dtls_key;
}

static const coap_dtls_spsk_info_t *
verify_psk_sni_callback(const char *sni,
                    coap_session_t *c_session UNUSED_PARAM,
                    void *arg UNUSED_PARAM
) {
  static coap_dtls_spsk_info_t psk_info;

  /* Preset with the defined keys */
  memset (&psk_info, 0, sizeof(psk_info));
  psk_info.hint.s = (const uint8_t *)hint;
  psk_info.hint.length = hint ? strlen(hint) : 0;
  psk_info.key.s = key;
  psk_info.key.length = key_length;
  if (sni) {
    size_t i;
    coap_log(LOG_INFO, "SNI '%s' requested\n", sni);
    for (i = 0; i < valid_psk_snis.count; i++) {
      /* Test for identity match to change key */
      if (strcasecmp(sni,
                 valid_psk_snis.psk_sni_list[i].sni_match) == 0) {
        coap_log(LOG_INFO, "Switching to using '%.*s' hint + '%.*s' key\n",
                 (int)valid_psk_snis.psk_sni_list[i].new_hint->length,
                 valid_psk_snis.psk_sni_list[i].new_hint->s,
                 (int)valid_psk_snis.psk_sni_list[i].new_key->length,
                 valid_psk_snis.psk_sni_list[i].new_key->s);
        psk_info.hint = *valid_psk_snis.psk_sni_list[i].new_hint;
        psk_info.key = *valid_psk_snis.psk_sni_list[i].new_key;
        break;
      }
    }
  }
  else {
    coap_log(LOG_DEBUG, "SNI not requested\n");
  }
  return &psk_info;
}

static const coap_bin_const_t *
verify_id_callback(coap_bin_const_t *identity,
                   coap_session_t *c_session,
                   void *arg UNUSED_PARAM
) {
  static coap_bin_const_t psk_key;
  size_t i;

  coap_log(LOG_INFO, "Identity '%.*s' requested, current hint '%.*s'\n", (int)identity->length,
           identity->s,
           c_session->psk_hint ? (int)c_session->psk_hint->length : 0,
           c_session->psk_hint ? (const char *)c_session->psk_hint->s : "");

  for (i = 0; i < valid_ids.count; i++) {
    /* Check for hint match */
    if (c_session->psk_hint &&
        strcmp((const char *)c_session->psk_hint->s,
               valid_ids.id_list[i].hint_match)) {
      continue;
    }
    /* Test for identity match to change key */
    if (coap_binary_equal(identity, valid_ids.id_list[i].identity_match)) {
      coap_log(LOG_INFO, "Switching to using '%.*s' key\n",
               (int)valid_ids.id_list[i].new_key->length,
               valid_ids.id_list[i].new_key->s);
      return valid_ids.id_list[i].new_key;
    }
  }

  if (c_session->psk_key) {
    /* Been updated by SNI callback */
    psk_key = *c_session->psk_key;
    return &psk_key;
  }

  /* Just use the defined keys for now */
  psk_key.s = key;
  psk_key.length = key_length;
  return &psk_key;
}

static void
RG_fill_keystore(coap_context_t *ctx) {
  if (cert_file == NULL && key_defined == 0) {
    if (coap_dtls_is_supported() || coap_tls_is_supported()) {
      coap_log(LOG_DEBUG,
               "(D)TLS not enabled as neither -k or -c options specified\n");
    }
  }
  if (cert_file) {
    coap_dtls_pki_t dtls_pki;
    memset (&dtls_pki, 0, sizeof(dtls_pki));
    dtls_pki.version = COAP_DTLS_PKI_SETUP_VERSION;
    if (ca_file) {
      /*
       * Add in additional certificate checking.
       * This list of enabled can be tuned for the specific
       * requirements - see 'man coap_encryption'.
       */
      dtls_pki.verify_peer_cert        = 1;
      dtls_pki.require_peer_cert       = 0;   /* does not require peer checking */
      dtls_pki.allow_self_signed       = 1;
      dtls_pki.allow_expired_certs     = 1;
      dtls_pki.cert_chain_validation   = 1;
      dtls_pki.cert_chain_verify_depth = 2;
      dtls_pki.check_cert_revocation   = 1;
      dtls_pki.allow_no_crl            = 1;
      dtls_pki.allow_expired_crl       = 1;
      dtls_pki.validate_cn_call_back   = verify_cn_callback;
      dtls_pki.cn_call_back_arg        = NULL;
      dtls_pki.validate_sni_call_back  = verify_pki_sni_callback;
      dtls_pki.sni_call_back_arg       = NULL;
    }
    if (!use_pem_buf) {
      dtls_pki.pki_key.key_type = COAP_PKI_KEY_PEM;
      dtls_pki.pki_key.key.pem.public_cert = cert_file;
      dtls_pki.pki_key.key.pem.private_key = cert_file;
      dtls_pki.pki_key.key.pem.ca_file = ca_file;
    }
    else {
      ca_mem = read_file_mem(ca_file, &ca_mem_len);
      cert_mem = read_file_mem(cert_file, &cert_mem_len);
      dtls_pki.pki_key.key_type = COAP_PKI_KEY_PEM_BUF;
      dtls_pki.pki_key.key.pem_buf.ca_cert = ca_mem;
      dtls_pki.pki_key.key.pem_buf.public_cert = cert_mem;
      dtls_pki.pki_key.key.pem_buf.private_key = cert_mem;
      dtls_pki.pki_key.key.pem_buf.ca_cert_len = ca_mem_len;
      dtls_pki.pki_key.key.pem_buf.public_cert_len = cert_mem_len;
      dtls_pki.pki_key.key.pem_buf.private_key_len = cert_mem_len;
    }

    /* If general root CAs are defined */
    if (root_ca_file) {
      struct stat stbuf;
      if ((stat(root_ca_file, &stbuf) == 0) && S_ISDIR(stbuf.st_mode)) {
        coap_context_set_pki_root_cas(ctx, NULL, root_ca_file);
      } else {
        coap_context_set_pki_root_cas(ctx, root_ca_file, NULL);
      }
    }
    coap_context_set_pki(ctx, &dtls_pki);
  }
  if (key_defined) {
    coap_dtls_spsk_t dtls_psk;
    memset (&dtls_psk, 0, sizeof(dtls_psk));
    dtls_psk.version = COAP_DTLS_SPSK_SETUP_VERSION;
    dtls_psk.validate_id_call_back = valid_ids.count ?
                                      verify_id_callback : NULL;
    dtls_psk.validate_sni_call_back = valid_psk_snis.count ?
                                       verify_psk_sni_callback : NULL;
    dtls_psk.psk_info.hint.s = (const uint8_t *)hint;
    dtls_psk.psk_info.hint.length = hint ? strlen(hint) : 0;
    dtls_psk.psk_info.key.s = key;
    dtls_psk.psk_info.key.length = key_length;
    coap_context_set_psk2(ctx, &dtls_psk);
  }
}

 
/*
 * init resources for RG
 */
void
RG_init_resources(coap_context_t *ctx) {
	
/* initialize of Authorization server issuer address*/
  struct ifaddrs *ifaddr, *ifa;
  int family, s;
  if (getifaddrs(&ifaddr) != -1) {
	 char host[NI_MAXHOST];
     ifa = ifaddr;
     while (ifa){
		 if (ifa->ifa_addr){
			family = ifa->ifa_addr->sa_family;
			s = getnameinfo(ifa->ifa_addr,
                 (family == AF_INET) ? sizeof(struct sockaddr_in) :
                                      sizeof(struct sockaddr_in6),
                     host, NI_MAXHOST,
                     NULL, 0, NI_NUMERICHOST);
            if (s == 0 && strlen(host) > 3){
			  uint8_t lan_att = 0;
			  for (uint8_t k = 0; k < strlen(host); k++) {
				  char ch = host[k];
				  if (ch == '%') lan_att = 1;
			  }
			  if (lan_att == 0){
				char prefix[] = "coap://[";
				uint8_t pre_len = strlen(prefix);
				uint8_t ep_len = strlen(prefix) + strlen(host) +1;
				char wlan0[] = "wlan0";
				if (strcmp(wlan0, ifa->ifa_name)  == 0){
			      IP_RG.s = malloc(ep_len+1);
			      IP_RG.length = ep_len;
			      memcpy(IP_RG.s, prefix, pre_len);
			      memcpy(IP_RG.s + pre_len, host, strlen(host));
			      IP_RG.s[ep_len-1] = ']';
			      IP_RG.s[ep_len] = 0;
			    }
		      }  /* lan_att */
	        }  /* s==0 */
		  } /* ifa->if_addr */
          ifa = ifa->ifa_next;
	 } /* while */        
  } /* getifaddrs  */
  freeifaddrs( ifaddr);	
  
  char uu_pre[] = "uu_RG";
  RG_identifier.length = 11;
  RG_identifier.s = coap_malloc(RG_identifier.length);
  memcpy(RG_identifier.s, uu_pre, 5);
  cr_namenr(RG_identifier.s + 5);
	
	/* creates resources
	 */
  coap_resource_t *r = coap_resource_init(NULL, 0);
  
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_index);

  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"General Info\""), 0);
  coap_add_resource(ctx, r);

  /* store clock base to use in /time */
  my_clock_base = clock_offset;

  r = coap_resource_init(coap_make_str_const("time"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_time);
  coap_register_handler(r, COAP_REQUEST_PUT, hnd_put_time);
  coap_register_handler(r, COAP_REQUEST_DELETE, hnd_delete_time);
  coap_resource_set_get_observable(r, 1);

  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"Internal Clock\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ticks\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"clock\""), 0);

  coap_add_resource(ctx, r);
  time_resource = r;

  if (support_dynamic > 0) {
    /* Create a resource to handle PUTs to unknown URIs */
    r = coap_resource_unknown_init(hnd_unknown_put);
    coap_add_resource(ctx, r);
  }
#ifndef WITHOUT_ASYNC
  r = coap_resource_init(coap_make_str_const("async"), 0);
  coap_register_handler(r, COAP_REQUEST_GET, hnd_get_async);

  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("0"), 0);
  coap_add_resource(ctx, r);
#endif /* WITHOUT_ASYNC */
  
  r = coap_resource_init(coap_make_str_const("est/crts"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_GET, RG_hnd_get_crts);
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("60"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"Obtain CA certificate\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.est.crts\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"est-coaps\""), 0);
  coap_add_resource(ctx, r);
  
r = coap_resource_init(coap_make_str_const(".well-known/est/crts"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_GET, RG_hnd_get_crts);
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("60"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"Obtain CA certificate\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.est.crts\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"est-coaps\""), 0);
  coap_add_resource(ctx, r);

r = coap_resource_init(coap_make_str_const("est/sen"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_POST, RG_hnd_post_sen); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("286"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"Initial enrollment\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.est.sen\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"est-coaps\""), 0);
  coap_add_resource(ctx, r);
  
r = coap_resource_init(coap_make_str_const(".well-known/est/sen"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_POST, RG_hnd_post_sen); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("286"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"Initial enrollment\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.est.sen\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"est-coaps\""), 0);
  coap_add_resource(ctx, r);
  
r = coap_resource_init(coap_make_str_const("est/sren"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_POST, RG_hnd_post_sren); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("286"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"Certificate reissuance\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.est.sren\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"est-coaps\""), 0);
  coap_add_resource(ctx, r);
   
r = coap_resource_init(coap_make_str_const(".well-known/est/sren"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_POST, RG_hnd_post_sren); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("286"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"Certificate reissuance\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.est.sren\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"est-coaps\""), 0);
  coap_add_resource(ctx, r);
   
r = coap_resource_init(coap_make_str_const("est/skg"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_POST, RG_hnd_post_skg); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("286"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"Server key generation\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.est.skg\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"est-coaps \""), 0);
  coap_add_resource(ctx, r);
  
r = coap_resource_init(coap_make_str_const(".well-known/est/skg"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_POST, RG_hnd_post_skg); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("286"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"Server key generation\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.est.skg\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"est-coaps \""), 0);
  coap_add_resource(ctx, r);
  
r = coap_resource_init(coap_make_str_const("est/att"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_GET, RG_hnd_get_att); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("285"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"csr attributes\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.est.att\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"est-coaps \""), 0);
  coap_add_resource(ctx, r);

r = coap_resource_init(coap_make_str_const(".well-known/est/att"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_GET, RG_hnd_get_att); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("285"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"csr attributes\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.est.att\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"est-coaps \""), 0);
  coap_add_resource(ctx, r);
    
  r = coap_resource_init(coap_make_str_const("brski/rv"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_POST, RG_hnd_post_rv); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("500"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"request voucher\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.est.rv\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"est-constrained-voucher \""), 0);
  coap_add_resource(ctx, r);
  
  r = coap_resource_init(coap_make_str_const(".well-known/brski/rv"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_POST, RG_hnd_post_rv); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("500"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"request voucher\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.est.rv\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"est-constrained-voucher \""), 0);
  coap_add_resource(ctx, r);
    
  r = coap_resource_init(coap_make_str_const("est/vs"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_POST, RG_hnd_post_vs); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("60"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"voucher status\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.est.vs\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"est-constrained-voucher\""), 0);
  coap_add_resource(ctx, r);
      
  r = coap_resource_init(coap_make_str_const(".well-known/est/vs"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_POST, RG_hnd_post_vs); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("60"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"voucher status\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.est.vs\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"est-constrained-voucher\""), 0);
  coap_add_resource(ctx, r);
  
  r = coap_resource_init(coap_make_str_const(".well-known/brski/vs"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_POST, RG_hnd_post_vs); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("60"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"voucher status\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.est.vs\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"est-constrained-voucher\""), 0);
  coap_add_resource(ctx, r);
  
  r = coap_resource_init(coap_make_str_const("brski/es"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_GET, RG_hnd_get_es); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("60"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"enroll status\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.est.es\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"est-constrained-voucher\""), 0);
  coap_add_resource(ctx, r);
  
  r = coap_resource_init(coap_make_str_const(".well-known/brski/es"), resource_flags);
  coap_register_handler(r, COAP_REQUEST_GET, RG_hnd_get_es); 
  coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("60"), 0);
  coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"enroll status\""), 0);
  coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"ace.est.es\""), 0);
  coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"est-constrained-voucher\""), 0);
  coap_add_resource(ctx, r);
    
  coap_string_t *uri_port = getURI(JP_BRSKI_PORT);
  if (uri_port != NULL){
	  if (uri_port->s != NULL){
         r = coap_resource_init(coap_make_str_const((const char *)uri_port->s), resource_flags);
         coap_register_handler(r, COAP_REQUEST_GET, RG_hnd_proxy); 
         coap_add_attr(r, coap_make_str_const("ct"), coap_make_str_const("62"), 0);
         coap_add_attr(r, coap_make_str_const("title"), coap_make_str_const("\"brski-proxy\""), 0);
         coap_add_attr(r, coap_make_str_const("rt"), coap_make_str_const("\"brski-port\""), 0);
         coap_add_attr(r, coap_make_str_const("if"), coap_make_str_const("\"join-proxy\""), 0);
         coap_add_resource(ctx, r);
      } else coap_log(LOG_WARNING,"brski URI does not exist  \n");
  } else coap_log(LOG_WARNING,"brski URI does not exist  \n");
}


static void
usage( const char *program, const char *version) {
  const char *p;
  char buffer[64];

  p = strrchr( program, '/' );
  if ( p )
    program = ++p;

  fprintf( stderr, "%s v%s -- a small CoAP server implementation\n"
     "(c) 2010,2011,2015-2020 Olaf Bergmann <bergmann@tzi.org> and others\n\n"
     "%s\n\n"
     "Usage: %s [-M] [-d max] [-v num] [-p port] MASA address\n"
     "General Options\n"
     "\t-M     \t\tAllow multiple entries of the same pledge to enroll \n"
     "\t       \t\tBeware: logs are only valid within same DTLS connections \n"
     "\t-d max \t\tAllow dynamic creation of up to a total of max\n"
     "\t       \t\tresources. If max is reached, a 4.06 code is returned\n"
     "\t       \t\tuntil one of the dynamic resources has been deleted\n"
     "\t-l loss%%\tRandomly fail to send datagrams with the specified\n"
     "\t       \t\tprobability - 100%% all datagrams, 0%% no datagrams\n"
     "\t       \t\t(for debugging only)\n"
     "\t-v num \t\tVerbosity level (default 3, maximum is 9). Above 7,\n"
     "\t       \t\tthere is increased verbosity in GnuTLS and OpenSSL logging\n"
     "\t       \t\t-v 0 suppresses all warining and error messages \n"
     "\t-p port\t\tPort of the coap Registrar server\n"
     "\t       \t\tPort+1 is used for coaps Registrar server \n"
     "\t       \t\tPort+2 is used for stateless Join_Proxy acces \n"
     "\t       \t\tvalue of stateless Join_Proxy port can discovered with rt=brski-proxy \n"
     "\t       \t\tif not specified, default coap/coaps server ports are used \n"
     "\t-h     \t\tHelp displays this message \n"
     "\texamples:\t  %s -p 5663 -v 0\n"
     "\t       \t\t  %s -p 5663 -M\n"
     "\t       \t\t  %s -M -v 7\n"
    , program, version, coap_string_tls_version(buffer, sizeof(buffer)),
    program, program, program, program);
}

#ifdef WITH_OSCORE
static void
oscore_set_contexts(void){
   /* empty  */
}
#endif /* WITH_OSCORE */

coap_context_t *
get_context(const char *node, const char *port) {
  coap_context_t *ctx = NULL;
  int s;
  struct addrinfo hints;
  struct addrinfo *result, *rp;

  ctx = coap_new_context(NULL);
  if (!ctx) {
    return NULL;
  }
  /* Need PSK set up before we set up (D)TLS endpoints */

  RG_fill_keystore(ctx);
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
  hints.ai_socktype = SOCK_DGRAM; /* Coap uses UDP */
  hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST;

  s = getaddrinfo(node, port, &hints, &result);
  if ( s != 0 ) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s));
    coap_free_context(ctx);
    return NULL;
  }

  /* iterate through results until success */
  for (rp = result; rp != NULL; rp = rp->ai_next) {
    coap_address_t addr, addrs, addrj;
    coap_endpoint_t *ep_udp = NULL, *ep_dtls = NULL, *ep_jp = NULL;

    if (rp->ai_addrlen <= sizeof(addr.addr)) {
      coap_address_init(&addr);
      addr.size = (socklen_t)rp->ai_addrlen;
      memcpy(&addr.addr, rp->ai_addr, rp->ai_addrlen);
      addrs = addr;
      addrj = addr;
      if (addr.addr.sa.sa_family == AF_INET) {
        uint16_t temp = ntohs(addr.addr.sin.sin_port) + 1;
        addrs.addr.sin.sin_port = htons(temp);
        temp++;
        addrj.addr.sin6.sin6_port = htons(temp);
      } else if (addr.addr.sa.sa_family == AF_INET6) {
        uint16_t temp = ntohs(addr.addr.sin6.sin6_port) + 1;
        addrs.addr.sin6.sin6_port = htons(temp);
        temp++;
        addrj.addr.sin6.sin6_port = htons(temp);
      } else {
        goto finish;
      }

      ep_udp = coap_new_endpoint(ctx, &addr, COAP_PROTO_UDP);
      if (ep_udp) {
        if (coap_dtls_is_supported() && (key_defined || cert_file)) {
          ep_dtls = coap_new_endpoint(ctx, &addrs, COAP_PROTO_DTLS);
          if (ep_dtls){
			  if (join_proxy_supported){
				 ep_jp = coap_new_endpoint(ctx, &addrj, COAP_PROTO_DTLS);
				 jp_set_brskifd(ep_jp->sock.fd);
				 init_URIs(&addrj, COAP_PROTO_DTLS, JP_BRSKI_PORT);
			  }
			  if (!ep_jp)coap_log(LOG_CRIT, "cannot create JP endpoint \n");
		  }
          else
            coap_log(LOG_CRIT, "cannot create DTLS endpoint\n");
        }
      } else {
        coap_log(LOG_CRIT, "cannot create UDP endpoint\n");
        continue;
      }
      if (coap_tcp_is_supported()) {
        coap_endpoint_t *ep_tcp;
        ep_tcp = coap_new_endpoint(ctx, &addr, COAP_PROTO_TCP);
        if (ep_tcp) {
          if (coap_tls_is_supported() && (key_defined || cert_file)) {
            coap_endpoint_t *ep_tls;
            ep_tls = coap_new_endpoint(ctx, &addrs, COAP_PROTO_TLS);
            if (!ep_tls)
              coap_log(LOG_CRIT, "cannot create TLS endpoint\n");
          }
        } else {
          coap_log(LOG_CRIT, "cannot create TCP endpoint\n");
        }
      }
      if (ep_udp){
		  jp_registrar();
        goto finish;
	  }
    }
  }
  coap_free_context(ctx);
  ctx = NULL;

finish:
  freeaddrinfo(result);
  return ctx;
}

int
main(int argc, char **argv) {
  coap_context_t  *ctx;
  char *group4 = NULL;
  char *group6 = NULL;
  coap_tick_t now;
  char addr_str[NI_MAXHOST] = "::";
  char port_str[NI_MAXSERV] = COAP_PORT;
  int opt;
  coap_log_t log_level = LOG_WARNING;
  unsigned wait_ms;
  coap_time_t t_last = 0;
  int coap_fd;
  fd_set m_readfds;
  int nfds = 0;

#ifndef _WIN32
  struct sigaction sa;
#endif

  clock_offset = time(NULL);

  while ((opt = getopt(argc, argv, "Md:l:v:h:p:")) != -1) {
    switch (opt) {
    case 'M' :
       set_multiple_pledge_entries();
       break;
    case 'd' :
      support_dynamic = atoi(optarg);
      break;
    case 'p' :
      strncpy(port_str, optarg, NI_MAXSERV-1);
      port_str[NI_MAXSERV - 1] = '\0';
      break;
    case 'l':
      if (!coap_debug_set_packet_loss(optarg)) {
        usage(argv[0], LIBCOAP_PACKAGE_VERSION);
        exit(1);
      }
      break;
    case 'v' :
      log_level = strtol(optarg, NULL, 10);
      break;
    case 'h' :
    default:
      usage( argv[0], LIBCOAP_PACKAGE_VERSION );
      exit( 1 );
    }
  }

  coap_startup();
  coap_dtls_set_log_level(log_level);
  coap_set_log_level(log_level);
  
  /* server joins MC address: all link-local coap nodes */ 
  char all_ipv6_coap_ll[] = ALL_COAP_LOCAL_IPV6_NODES;
  char all_ipv4_coap_ll[] = ALL_COAP_LOCAL_IPV4_NODES;
  group6 = all_ipv6_coap_ll;
  group4 = all_ipv4_coap_ll;

  ctx = get_context(addr_str, port_str);
  if (!ctx)
    return -1;

  RG_init_resources(ctx);
  init_edhoc_resources(ctx);
#ifdef WITH_OSCORE
  oscore_ctx_t *osc_ctx = oscore_init();
  oscore_set_contexts();
/* osc_ctx  points to default oscore context  */
  ctx->osc_ctx = osc_ctx;
  char key_256[]   = REGIS_ES256_SRV_KEY;
  char crt_256[]   = REGIS_ES256_SRV_CRT;
  char key_25519[] =  REGIS_ED25519_SRV_KEY;
  char crt_25519[] =  REGIS_ED25519_SRV_CRT;
  edhoc_init_suite_files(key_25519, key_256, crt_25519, crt_256);
#endif /* WITH_OSCORE */

  /* join multicast group if requested at command line */
 
  if (group6){
    if (coap_join_mcast_group(ctx, group6) == 0)
         coap_log(LOG_INFO," group  %s  is joint\n", group6);
  }

  if (group4){
    if (coap_join_mcast_group(ctx, group4) == 0)
            coap_log(LOG_INFO," group  %s  is joint\n", group4);
  }
  coap_fd = coap_context_get_coap_fd(ctx);
  if (coap_fd != -1) {
    /* if coap_fd is -1, then epoll is not supported within libcoap */
    FD_ZERO(&m_readfds);
    FD_SET(coap_fd, &m_readfds);
    nfds = coap_fd + 1;
  }

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

  wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;

  while ( !quit ) {
    int result;

/* when isready, the client call has terminated  */    

    if (coap_fd != -1) {
      /*
       * Using epoll.  It is more usual to call coap_io_process() with wait_ms
       * (as in the non-epoll branch), but doing it this way gives the
       * flexibility of potentially working with other file descriptors that
       * are not a part of libcoap.
       */
      fd_set readfds = m_readfds;
      struct timeval tv;
      coap_tick_t begin, end;

      coap_ticks(&begin);

      tv.tv_sec = wait_ms / 1000;
      tv.tv_usec = (wait_ms % 1000) * 1000;
      /* Wait until any i/o takes place or timeout */
      result = select (nfds, &readfds, NULL, NULL, &tv);
      if (result == -1) {
        if (errno != EAGAIN) {
          coap_log(LOG_DEBUG, "select: %s (%d)\n", coap_socket_strerror(), errno);
          break;
        }
      }
      if (result > 0) {
        if (FD_ISSET(coap_fd, &readfds)) {
          result = coap_io_process(ctx, COAP_IO_NO_WAIT);
        }
      }
      if (result >= 0) {
        coap_ticks(&end);
        /* Track the overall time spent in select() and coap_io_process() */
        result = (int)(end - begin);
      }
    }
    else {
      /*
       * epoll is not supported within libcoap
       *
       * result is time spent in coap_io_process()
       */
       
      result = coap_io_process( ctx, wait_ms );
    }
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

#ifndef WITHOUT_ASYNC
    /* check if we have to send asynchronous responses */
    coap_ticks( &now );
    check_async(ctx, now);
#endif /* WITHOUT_ASYNC */
  }

  coap_free_context(ctx);
  coap_cleanup();

  return 0;
}

