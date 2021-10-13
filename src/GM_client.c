/* -*- Mode: C; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2 -*- */

/* coap-client -- simple CoAP client
 *
 * Copyright (C) 2010--2019 Olaf Bergmann <bergmann@tzi.org> and others
 *
 * This file is part of the CoAP library libcoap. Please see README for terms of
 * use.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifdef _WIN32
#define strcasecmp _stricmp
#include "getopt.c"
#if !defined(S_ISDIR)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif
static char* strndup(const char* s1, size_t n)
{
  char* copy = (char*)malloc(n + 1);
  if (copy) {
    memcpy(copy, s1, n);
    copy[n] = 0;
  }
  return copy;
};
#else
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#endif
#ifdef WITH_OSCORE
#include "oscore.h"
#include "oscore-context.h"
#include "net.h"
#endif /* WITH_OSCORE */
#include "oscore-group.h"
#include "oscore_oauth.h"
#include "cbor.h"
#include "cose.h"
#include "utlist.h"

#include <coap.h>

#define MAX_USER 128 /* Maximum length of a user name (i.e., PSK
                      * identity) in bytes. */
#define MAX_KEY   64 /* Maximum length of a key (i.e., PSK) in bytes. */

int flags = 0;

static unsigned char _token_data[8];
coap_binary_t the_token = { 0, _token_data };

#define FLAGS_BLOCK 0x01

static coap_optlist_t *optlist = NULL;
/* Request URI.
 * TODO: associate the resources with transaction id and make it expireable */
static coap_uri_t uri;
static coap_string_t proxy = { 0, NULL };
static uint16_t proxy_port = COAP_DEFAULT_PORT;
static unsigned int ping_seconds = 0;

/* reading is done when this flag is set */
static int ready = 0;

/* processing a block response when this flag is set */
static int doing_getting_block = 0;

static coap_string_t output_file = { 0, NULL };   /* output file name */
static FILE *file = NULL;               /* output file stream */

static coap_string_t payload = { 0, NULL };       /* optional payload to send */

static int reliable = 0;

unsigned char msgtype = COAP_MESSAGE_CON; /* usually, requests are sent confirmable */

static char *cert_file = NULL; /* Combined certificate and private key in PEM */
static char *ca_file = NULL;   /* CA for cert_file - for cert checking in PEM */
static char *root_ca_file = NULL; /* List of trusted Root CAs in PEM */

typedef struct ih_def_t {
  char* hint_match;
  coap_bin_const_t *new_identity;
  coap_bin_const_t *new_key;
} ih_def_t;

typedef struct valid_ihs_t {
  size_t count;
  ih_def_t *ih_list;
} valid_ihs_t;

static valid_ihs_t valid_ihs = {0, NULL};

static int GM_choice = 100; /* default indicates no GM request */

#define    STANDARD_RETURN    1      /* contents of returned packet is printed */
#define    AUTHZ_INFO_RETURN  2      /* contents of returned packet contains info from GM /authz-info  */
#define    MANAGE_RETURN      3      /* contents of returned packet contains info from /GM/manage  */
#define    JOIN_RETURN        4      /* contents of returned packet contains info from /GM/join/group xx  */   
static uint8_t enable_output = STANDARD_RETURN;    
                   /* if STANDARD_RETURN print to output */

/* this computer has clients AD, c1, c2 and c0
 * further there are servers AS and GM
 * connections are made between
 * C1 <-> GM
 * C2 <-> GM
 * C0 <-> GM
 * AD <-> GM         -- for group creation
 * AS <-> GM         -- for token encryption/decryption 
 * m_01 <-> GRP
 * m_02 <-> GRP
 * m_03 <-> GR
 */

/* return of uri to join a group in GM */
/* assumption that path is shorter than 6 !!!!! */
coap_string_t join_uri[5];
size_t join_uri_len = 0;

/* uri_path for group create */
uint8_t uri_GM[]    = "GM";
uint8_t uri_manage[]= "manage";
uint8_t uri_GRP[]   = "GRP";



uint8_t sender_c1[] = {0x43, 0x31};
uint8_t sender_c2[] = {0x43, 0x32};
uint8_t sender_c0[] = {0x43, 0x30};
uint8_t sender_AD[] = {0x41, 0x44};
uint8_t sender_AS[] = {0x41, 0x53};
uint8_t *sender_xx = NULL;       /* is AD, C1, C2, or C0  */

uint8_t receiver_GM[] = {0x47, 0x4d};

oscore_ctx_t *LAST_ctx = NULL;   /* cx <==> GM context for join or create */

#define NONCE_LEN   8   /* temporary definition  */

unsigned char 
    public_key_C0[COSE_ALGORITHM_Ed25519_PUB_KEY_LEN] =
{0x01,  0x0a,  0x5b,  0xd2,  0x0a,  0xf0,  0xed,  0x21,  0x04,  0xcd,  0x23,  0x2f,  0x7f,  0x92,  0x8d,  0xda,  0x08,  0xc2,  0x79,  0xdc,  0x81,  0xf0,  0x56,  0x2b,  0x20,  0x14,  0xef,  0x71,  0x37,  0x46,  0x68,  0x71
};

unsigned char 
    public_key_C1[COSE_ALGORITHM_Ed25519_PUB_KEY_LEN] =
{0xae,  0xf1,  0x63,  0x00,  0xf6,  0x38,  0xec,  0x44,  0xd9,  0xf4,  0x47,  0x4f,  0x6d,  0xc0,  0xc4,  0xa4,  0x8b,  0x89,  0xb1,  0x4b,  0xe5,  0xef,  0xec,  0x09,  0xab,  0x18,  0x82,  0x57,  0x4e,  0xb0,  0x55,  0x26
};


unsigned char 
    public_key_C2[COSE_ALGORITHM_Ed25519_PUB_KEY_LEN] =
{0x29,  0x77,  0x86,  0x0a,  0x9a,  0xdb,  0xdd,  0xcf,  0x82,  0x11,  0xb1,  0xc9,  0x7f,  0xc2,  0x98,  0x44,  0xd8,  0x10,  0x5f,  0x96,  0x33,  0xdb,  0x82,  0x8a,  0xdf,  0xae,  0xba,  0x4c,  0x1e,  0x5f,  0xd1,  0xd2
};

unsigned char 
    private_key_C0[COSE_ALGORITHM_Ed25519_PRIV_KEY_LEN] =
{0x88,  0x91,  0x42,  0xbe,  0x02,  0x7e,  0x76,  0x30,  0xed,  0x6f,  0x1a,  0xb7,  0xd2,  0x90,  0xac,  0xd2,  0x43,  0x50,  0x30,  0x18,  0x39,  0x93,  0x99,  0x73,  0x83,  0x59,  0x14,  0xa9,  0x30,  0x13,  0x57,  0x7c,  0x4a,  0xc9,  0xcf,  0x74,  0x1a,  0x72,  0x47,  0x1a,  0xaf,  0x9e,  0xd0,  0x17,  0x44,  0x39,  0xf3,  0x9b,  0x97,  0xef,  0xc6,  0x3d,  0x0f,  0x86,  0xf2,  0x45,  0x4b,  0xe7,  0x54,  0xd1,  0xd9,  0xc8,  0x5e,  0x43
};

unsigned char
    private_key_C1[COSE_ALGORITHM_Ed25519_PRIV_KEY_LEN] =
{0xf0,  0xa1,  0x51,  0x21,  0xa5,  0x71,  0x92,  0x54,  0x6e,  0x67,  0x2d,  0x7e,  0x7a,  0x3f,  0xcb,  0x76,  0xd0,  0xbf,  0x2e,  0x03,  0xc9,  0x95,  0x41,  0x2e,  0x38,  0x56,  0x43,  0xba,  0x64,  0x31,  0xa5,  0x64,  0x9a,  0xd1,  0xcc,  0xf6,  0x25,  0x19,  0xe5,  0xc8,  0x9a,  0xff,  0x99,  0xaa,  0xad,  0xc2,  0x0d,  0xf8,  0xbc,  0x45,  0xef,  0xf3,  0x41,  0x02,  0x48,  0xfa,  0xb9,  0x51,  0xe6,  0x92,  0x78,  0x2d,  0x2b,  0x23
};

unsigned char 
   private_key_C2[COSE_ALGORITHM_Ed25519_PRIV_KEY_LEN] =
{0xf0,  0x76,  0xd2,  0xb1,  0x42,  0x33,  0xd0,  0x97,  0x94,  0x26,  0x60,  0x9d,  0x13,  0x1a,  0xe7,  0x43,  0xcc,  0xdd,  0x85,  0xbe,  0x21,  0xbc,  0xb3,  0x32,  0x1b,  0x9f,  0xb5,  0x7c,  0xca,  0x43,  0x84,  0x57,  0x27,  0x0d,  0x20,  0x29,  0xca,  0x59,  0xbb,  0x8d,  0xfc,  0x1c,  0xbe,  0x09,  0xc9,  0x21,  0x68,  0x02,  0x68,  0xc2,  0x12,  0x68,  0x01,  0xcd,  0x36,  0xd9,  0x7d,  0x40,  0xbd,  0x5c,  0xde,  0x9f,  0x04,  0x51
};

/* master_secret and salt for AS<=>GM context  */
uint8_t CxGM_master_secret[COSE_algorithm_AES_CCM_16_64_128_KEY_LEN] = {0x12, 0x22, 0x32, 0x42, 0x52, 0x62, 0x72, 0x82, 0x92, 0xa2, 0xb2, 0xc2, 0xd2, 0xe2, 0xf2, 0x22};

uint8_t CxGM_salt[NONCE_LEN] = {0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40}; 

/* shared key between AS and GM  */
uint8_t ASGM_KEY[COSE_algorithm_AES_CCM_16_64_128_KEY_LEN] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10};

/* master_secret and salt for AD<=>GM context  */
uint8_t ADGM_master_secret[COSE_algorithm_AES_CCM_16_64_128_KEY_LEN] = {0x15, 0x25, 0x35, 0x45, 0x55, 0x65, 0x75, 0x85, 0x95, 0xa5, 0xb5, 0xc5, 0xd5, 0xe5, 0xf5, 0x05};

uint8_t ADGM_salt[NONCE_LEN] = {0x7e, 0x7c, 0xa8, 0xb8, 0xd3, 0xd8, 0xe3, 0xe0}; 

/* the encryption keys are derived from salt, master-secret
 * and client server identifiers
 */

/* temporary storage of sent nonce */
uint8_t GM_nonce1[NONCE_LEN]; /*sent in authz-info request */
uint8_t *kdcchallenge = NULL;      /* returned in authz-info response */
                             /* both reused in oscore-context specification */
                              /* kdcchallenge reused in join request signature */


typedef unsigned char method_t;
method_t method = 1;                    /* the method we are using in our requests */

coap_block_t block = { .num = 0, .m = 0, .szx = 6 };
uint16_t last_block1_tid = 0;


unsigned int wait_seconds = 90;                /* default timeout in seconds */
unsigned int wait_ms = 0;
int wait_ms_reset = 0;
int obs_started = 0;
unsigned int obs_seconds = 30;          /* default observe time */
unsigned int obs_ms = 0;                /* timeout for current subscription */
int obs_ms_reset = 0;

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

static int quit = 0;

/* SIGINT handler: set quit to 1 for graceful termination */
static void
handle_sigint(int signum UNUSED_PARAM) {
  quit = 1;
}

static int
append_to_output(const uint8_t *data, size_t len) {
  size_t written;

  if (!file) {
    if (!output_file.s || (output_file.length && output_file.s[0] == '-'))
      file = stdout;
    else {
      if (!(file = fopen((char *)output_file.s, "w"))) {
        perror("fopen");
        return -1;
      }
    }
  }

  do {
    written = fwrite(data, 1, len, file);
    len -= written;
    data += written;
  } while ( written && len );
  fflush(file);

  return 0;
}

static void
close_output(void) {
  if (file) {

    /* add a newline before closing if no option '-o' was specified */
    if (!output_file.s)
      fwrite("\n", 1, 1, file);

    fflush(file);
    fclose(file);
  }
}

static coap_pdu_t *
coap_new_request(coap_context_t *ctx,
                 coap_session_t *session,
                 method_t m,
                 coap_optlist_t **options,
                 unsigned char *data,
                 size_t length) {
  coap_pdu_t *pdu;
  (void)ctx;

  if (!(pdu = coap_new_pdu(session)))
    return NULL;

  pdu->type = msgtype;
  pdu->tid = coap_new_message_id(session);
  pdu->code = m;

  if ( !coap_add_token(pdu, the_token.length, the_token.s)) {
    coap_log(LOG_DEBUG, "cannot add token to request\n");
  }

  if (options)
    coap_add_optlist_pdu(pdu, options);

  if (length) {
    if ((flags & FLAGS_BLOCK) == 0)
      coap_add_data(pdu, length, data);
    else {
      unsigned char buf[4];
      coap_add_option(pdu,
                      COAP_OPTION_SIZE1,
                      coap_encode_var_safe8(buf, sizeof(buf), length),
                      buf);

      coap_add_block(pdu, length, data, block.num, block.szx);
    }
  }

  return pdu;
}

static coap_tid_t
clear_obs(coap_context_t *ctx, coap_session_t *session) {
  coap_pdu_t *pdu;
  coap_optlist_t *option;
  coap_tid_t tid = COAP_INVALID_TID;
  unsigned char buf[2];
  (void)ctx;

  /* create bare PDU w/o any option  */
  pdu = coap_pdu_init(msgtype,
                      COAP_REQUEST_GET,
                      coap_new_message_id(session),
                      coap_session_max_pdu_size(session));

  if (!pdu) {
    return tid;
  }

  if (!coap_add_token(pdu, the_token.length, the_token.s)) {
    coap_log(LOG_CRIT, "cannot add token\n");
    goto error;
  }

  for (option = optlist; option; option = option->next ) {
    if (option->number == COAP_OPTION_URI_HOST) {
      if (!coap_add_option(pdu, option->number, option->length,
                           option->data)) {
        goto error;
      }
      break;
    }
  }

  if (!coap_add_option(pdu,
      COAP_OPTION_OBSERVE,
      coap_encode_var_safe(buf, sizeof(buf), COAP_OBSERVE_CANCEL),
      buf)) {
    coap_log(LOG_CRIT, "cannot add option Observe: %u\n", COAP_OBSERVE_CANCEL);
    goto error;
  }

  for (option = optlist; option; option = option->next ) {
    switch (option->number) {
    case COAP_OPTION_URI_PORT :
    case COAP_OPTION_URI_PATH :
    case COAP_OPTION_URI_QUERY :
      if (!coap_add_option(pdu, option->number, option->length,
                           option->data)) {
        goto error;
      }
      break;
      default:
      ;
    }
  }

  if (flags & FLAGS_BLOCK) {
    block.num = 0;
    block.m = 0;
    coap_add_option(pdu,
      COAP_OPTION_BLOCK2,
      coap_encode_var_safe(buf, sizeof(buf), (block.num << 4 | block.m << 3 | block.szx)),
      buf);
  }

  if (coap_get_log_level() < LOG_DEBUG)
    coap_show_pdu(LOG_INFO, pdu);


  tid = coap_send(session, pdu);

  if (tid == COAP_INVALID_TID)
    coap_log(LOG_DEBUG, "clear_obs: error sending new request\n");

  return tid;
 error:

  coap_delete_pdu(pdu);
  return tid;
}

static int
resolve_address(const coap_str_const_t *server, struct sockaddr *dst) {

  struct addrinfo *res, *ainfo;
  struct addrinfo hints;
  static char addrstr[256];
  int error, len=-1;

  memset(addrstr, 0, sizeof(addrstr));
  if (server->length)
    memcpy(addrstr, server->s, server->length);
  else
    memcpy(addrstr, "localhost", 9);

  memset ((char *)&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = AF_UNSPEC;

  error = getaddrinfo(addrstr, NULL, &hints, &res);

  if (error != 0) {
    fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(error));
    return error;
  }

  for (ainfo = res; ainfo != NULL; ainfo = ainfo->ai_next) {
    switch (ainfo->ai_family) {
    case AF_INET6:
    case AF_INET:
      len = (int)ainfo->ai_addrlen;
      memcpy(dst, ainfo->ai_addr, len);
      goto finish;
    default:
      ;
    }
  }

 finish:
  freeaddrinfo(res);
  return len;
}

#define HANDLE_BLOCK1(Pdu)                                        \
  ((method == COAP_REQUEST_PUT || method == COAP_REQUEST_POST) && \
   ((flags & FLAGS_BLOCK) == 0) &&                                \
   ((Pdu)->hdr->code == COAP_RESPONSE_CODE(201) ||                \
    (Pdu)->hdr->code == COAP_RESPONSE_CODE(204)))

static inline int
check_token(coap_pdu_t *received) {
  return received->token_length == the_token.length &&
    memcmp(received->token, the_token.s, the_token.length) == 0;
}

static int
event_handler(coap_context_t *ctx UNUSED_PARAM,
              coap_event_t event,
              struct coap_session_t *session UNUSED_PARAM) {

  switch(event) {
  case COAP_EVENT_DTLS_CLOSED:
  case COAP_EVENT_TCP_CLOSED:
  case COAP_EVENT_SESSION_CLOSED:
    quit = 1;
    break;
  default:
    break;
  }
  return 0;
}

static void
nack_handler(coap_context_t *context UNUSED_PARAM,
             coap_session_t *session UNUSED_PARAM,
             coap_pdu_t *sent UNUSED_PARAM,
             coap_nack_reason_t reason,
             const coap_tid_t id UNUSED_PARAM) {

  switch(reason) {
  case COAP_NACK_TOO_MANY_RETRIES:
  case COAP_NACK_NOT_DELIVERABLE:
  case COAP_NACK_RST:
  case COAP_NACK_TLS_FAILED:
    quit = 1;
    break;
  case COAP_NACK_ICMP_ISSUE:
  default:
    break;
  }
  return;
}


/* GM_add_publickey
 * generates group context from configuration
 */
static oscore_ctx_t *
GM_add_publickey(oauth_cnf_t *cnf){
  /* find common context with recipient-id */
  oscore_ctx_t *osc_ctx = oscore_find_context(
     cnf->client_id, cnf->client_id_len,
     cnf->server_id, cnf->server_id_len,   
     cnf->context_id , cnf->context_id_len);
  if (osc_ctx != NULL) return osc_ctx; /* exists already  */
  /* find common context to which recipient can be added */
  osc_ctx = oscore_find_context(
     cnf->client_id, cnf->client_id_len,
     NULL, 0,   
     cnf->context_id , cnf->context_id_len);
  if( osc_ctx == NULL){
	  uint8_t *ms = coap_malloc(cnf->ms_len);
	  memcpy(ms, cnf->ms, cnf->ms_len);
	  uint8_t *salt = coap_malloc(cnf->salt_len);
	  memcpy(salt, cnf->salt, cnf->salt_len);
	  uint8_t *client_id = NULL;
	  uint8_t *server_id = NULL;
	  uint8_t *context_id = NULL;	  	  
	  if (cnf->client_id != NULL){
		  client_id = coap_malloc(cnf->client_id_len);
	      memcpy(client_id, cnf->client_id, cnf->client_id_len);
	  }
	  if (cnf->server_id != NULL){
	     server_id = coap_malloc(cnf->server_id_len);
	     memcpy(server_id, cnf->server_id, cnf->server_id_len);
      }	  
	  if (cnf->context_id != NULL){
	     context_id = coap_malloc(cnf->context_id_len);
	     memcpy(context_id, cnf->context_id, cnf->context_id_len);	
	  }  
  /* create new context  */
    osc_ctx = oscore_derive_ctx(
        ms, cnf->ms_len, salt, cnf->salt_len, 
        cnf->alg,
        client_id, cnf->client_id_len, 
        server_id, cnf->server_id_len, 
        context_id , cnf->context_id_len,
        cnf->rpl);
    if (osc_ctx != NULL)oscore_enter_context(osc_ctx);
  } else {
	 uint8_t *server_id = NULL;
	 if (cnf->server_id != NULL){
		 server_id = coap_malloc(cnf->server_id_len);
		 memcpy(server_id, cnf->server_id, cnf->server_id_len);
	 }
     /* add new recipient to context */
     oscore_recipient_ctx_t *rec_ctx = 
        oscore_add_recipient(osc_ctx, 
                 server_id, cnf->server_id_len);
     if (rec_ctx == NULL) return NULL;
  } /* if osc_ctx  */
  oscore_add_group_keys(osc_ctx,
        public_key_C0,
        private_key_C0,
        public_key_C1,
        NULL);
  /* receiver public key added */
  size_t cs_params_len = 0;
  uint8_t *cs_params = coap_malloc(cnf->cs_params_len);
  memcpy(cs_params,cnf->cs_params, cnf->cs_params_len);
  oscore_add_group_algorithm(osc_ctx,  
        cnf->cs_alg, 
        cs_params, cs_params_len);
  coap_free(cs_params);
  return osc_ctx;
}

/* GM_group_context
 * generates group context from configuration
 */
static oscore_ctx_t *
GM_group_context(oauth_cnf_t *cnf){
  /* create context for group communication  */
  oscore_ctx_t *osc_ctx = oscore_find_context(
     cnf->client_id, cnf->client_id_len, 
     cnf->server_id, cnf->server_id_len, 
     cnf->context_id , cnf->context_id_len);
  if (osc_ctx == NULL){
    osc_ctx = oscore_find_context(
       cnf->client_id, cnf->client_id_len, 
       NULL, 0, 
       cnf->context_id , cnf->context_id_len);
    if (osc_ctx != NULL){
	  uint8_t *server_id = NULL;
	  if (cnf->server_id != NULL){
		  server_id = coap_malloc(cnf->server_id_len);
		  memcpy(server_id, cnf->server_id, cnf->server_id_len);
	  }
        /* add a recipient to the context  */
      oscore_recipient_ctx_t *rec_ctx = 
        oscore_add_recipient(osc_ctx, 
                 server_id, cnf->server_id_len);
      if (rec_ctx == NULL) return NULL;
    } else {
	  uint8_t *ms = coap_malloc(cnf->ms_len);
	  memcpy(ms, cnf->ms, cnf->ms_len);
	  uint8_t *salt = coap_malloc(cnf->salt_len);
	  memcpy(salt, cnf->salt, cnf->salt_len);
	  uint8_t *client_id = NULL;
	  uint8_t *server_id = NULL;
	  uint8_t *context_id = NULL;	  	  
	  if (cnf->client_id != NULL){
		  client_id = coap_malloc(cnf->client_id_len);
	      memcpy(client_id, cnf->client_id, cnf->client_id_len);
	  }
	  if (cnf->server_id != NULL){
		  server_id = coap_malloc(cnf->server_id_len);
	      memcpy(server_id, cnf->server_id, cnf->server_id_len);
	  }	  
	  if (cnf->context_id != NULL){
		  context_id = coap_malloc(cnf->context_id_len);
	      memcpy(context_id, cnf->context_id, cnf->context_id_len);	  
	  }
        /* create new context  */
      osc_ctx = oscore_derive_ctx(
        ms, cnf->ms_len, salt, cnf->salt_len, 
        cnf->alg,
        client_id, cnf->client_id_len, 
        server_id, cnf->server_id_len, 
        context_id , cnf->context_id_len,
        cnf->rpl);
      oscore_enter_context(osc_ctx);
    } /* if osc_ctx */
  } /* if osc_ctx  */
  return osc_ctx;  /* OK return  */
}

/* construct_uri_join(group_ri)
 * contructs join_uri from group_uri string
 * NOT used, possibly needed for GET /GRP/node
 */
/* static void
construct_uri_join(coap_string_t group_uri)
{
  join_uri_len =0;
  size_t ll = 0;
  uint8_t pos =0;
  for (uint qq = 0; qq < group_uri.length; qq++){ 
    if (group_uri.s[qq] != 47) ll++;
    else {
      join_uri[join_uri_len].s = coap_malloc(ll);
      join_uri[join_uri_len].length = ll;
      for (uint qr = 0; qr < ll; qr++)
        join_uri[join_uri_len].s[qr] = group_uri.s[qr + pos];
      pos = pos + ll + 1;
      ll = 0;
      join_uri_len++;
    }
  }
  if (ll > 0){    
    join_uri[join_uri_len].s = coap_malloc(ll);
    join_uri[join_uri_len].length = ll;
    for (uint qr = 0; qr < ll; qr++)
        join_uri[join_uri_len].s[qr] = group_uri.s[qr + pos];
    join_uri_len++;
  }
}
*/

/* handle_manage_return(void)
 * reads data returned from request to manage resource of GM
 */
static void
handle_manage_return(void){
	/*
   empty return message
  */
  return;
}

/* handle_join_return(databuf)
 * reads data returned from request to join/xxxx resource of GM
 */
static void
handle_join_return(unsigned char *databuf){
  uint8_t *keys = NULL;
  uint8_t nr_of_keys = 0;
  oauth_cnf_t *conf = GM_read_object_keys(&databuf, &keys);
  if (conf == NULL){
    coap_log(LOG_WARNING,"Could not read OSCORE security object \n");
    return;
  }
  if (GM_choice != 1){  /* GM_choice == 1 means: C1 joins  */
    /* for m_02 and m_03 server_id is client_id */
    /* m_01 server_id is empty  */
    if (conf->server_id != NULL) free(conf->server_id);
    conf->server_id = coap_malloc(conf->client_id_len);
    conf->server_id_len = conf->client_id_len;
    for (uint qq = 0; qq < conf->client_id_len; qq++)
                      conf->server_id[qq] = conf->client_id[qq];
  } 
  oscore_ctx_t *osc_ctx = GM_group_context(conf);
  if (osc_ctx == NULL){
    coap_log(LOG_WARNING,"No context created or found \n");
    oauth_delete_conf(conf);
    return;
  }
  if (GM_choice == 2){
         oscore_add_group_keys(osc_ctx,
            NULL, NULL,  
            conf->pub_key, NULL);
  /* receiver public key added */
           oscore_add_group_algorithm(osc_ctx,  
              conf->cs_alg, 
              conf->cs_params, conf->cs_params_len);
	  }
  if (GM_choice == 3){
         oscore_add_group_keys(osc_ctx,
            NULL, NULL, 
            conf->pub_key, NULL);
  /* receiver public key added */
           oscore_add_group_algorithm(osc_ctx,  
              conf->cs_alg, 
              conf->cs_params, conf->cs_params_len);
	   }
  if (keys != NULL) nr_of_keys = GM_decode_pubkeys(&keys);
  for (int qq = 0; qq < nr_of_keys; qq++){
    if (GM_decode_pubkey(&keys, conf) == 0){
/* conf->server_id is set to recipient of the public key */
      osc_ctx = GM_add_publickey(conf);
      if (osc_ctx == NULL){
        oauth_delete_conf(conf);
        coap_log(LOG_WARNING,
                       "No context created for public keys \n");
        return;
      } /* if osc_ctx  */
    }/* if GM_decode_ */
  }  /* for  */
  oauth_delete_conf(conf);
}

/* handle_authz_return(databuf)
 * reads data returned from request to authz-info resource of GM
 */
static void
handle_authz_return(unsigned char *databuf){
  uint8_t *ms = NULL;
  size_t  ms_len = 0;
  uint8_t *local_salt = coap_malloc(24);
  uint8_t *local_nonce = NULL;
  if(kdcchallenge != NULL){
	  free(kdcchallenge);
	  kdcchallenge = NULL;
  }
  uint8_t ok = oauth_read_nonce(databuf, &local_nonce, &kdcchallenge);
/* local_nonce is used for salt extension */
  if (ok != 0 || kdcchallenge == NULL || local_nonce == NULL){
    coap_log(LOG_WARNING,"bad or no nonces returned \n");
    return;
  }
  /* for group creation use ADGM_salt, ADGM_master_secret */
  /* for join member use CxGM_salt, CxGM_master_secret    */
  if (GM_choice == 4){
    for (int qq =0; qq < 8; qq++) local_salt[qq] = ADGM_salt[qq];
    ms_len = sizeof(ADGM_master_secret);
    ms = coap_malloc(sizeof(ADGM_master_secret));
    memcpy(ms,ADGM_master_secret, ms_len);
  }else {
    ms_len = sizeof(CxGM_master_secret);
    ms = coap_malloc(sizeof(CxGM_master_secret));
    memcpy(ms,CxGM_master_secret, ms_len);
    for (int qq =0; qq < 8; qq++){
      local_salt[qq] = CxGM_salt[qq];
    }  /* for */ 
  }
  for (int qq =0; qq < 8; qq++) 
                 local_salt[qq+8]  = GM_nonce1[qq];
  for (int qq =0; qq < 8; qq++) 
                 local_salt[qq+16] = local_nonce[qq];
  free(local_nonce);

/* set correct sender in sender_xx  */
  switch (GM_choice){
    case 0:
    case 4:
      sender_xx = &sender_AD[0];
      break;
    case 1:
    case 5:
      sender_xx = &sender_c1[0];
      break;
    case 2:
    case 6:
      sender_xx = &sender_c2[0];
      break;
    case 3:
    case 7:
      sender_xx = &sender_c0[0];
      break;
    default:
      break;
   }

/* cx -> GM without group context */  
  oscore_ctx_t *osc_ctx = oscore_derive_ctx(
      ms, ms_len, local_salt, 24, 
      COSE_Algorithm_AES_CCM_16_64_128,
      sender_xx, 2, 
      receiver_GM, sizeof(receiver_GM), 
      NULL , 0,
      OSCORE_DEFAULT_REPLAY_WINDOW);
  oscore_enter_context(osc_ctx);
  LAST_ctx = osc_ctx;
}


static void
message_handler(struct coap_context_t *ctx,
                coap_session_t *session,
                coap_pdu_t *sent,
                coap_pdu_t *received,
                const coap_tid_t id UNUSED_PARAM) {

  coap_pdu_t *pdu = NULL;
  coap_opt_t *block_opt;
  coap_opt_iterator_t opt_iter;
  unsigned char buf[4];
  coap_optlist_t *option;
  size_t len;
  unsigned char *databuf;
  coap_tid_t tid;

  coap_log(LOG_DEBUG, "** process incoming %d.%02d response:\n",
           (received->code >> 5), received->code & 0x1F);
  if (coap_get_log_level() < LOG_DEBUG)
    coap_show_pdu(LOG_INFO, received);

  /* check if this is a response to our original request */
  if (!check_token(received)) {
    /* drop if this was just some message, or send RST in case of notification */
    if (!sent && (received->type == COAP_MESSAGE_CON ||
                  received->type == COAP_MESSAGE_NON))
      coap_send_rst(session, received);
    return;
  }

  if (received->type == COAP_MESSAGE_RST) {
    coap_log(LOG_INFO, "got RST\n");
    return;
  }

  /* output the received data, if any */
  if (COAP_RESPONSE_CLASS(received->code) == 2) {

    /* set obs timer if we have successfully subscribed a resource */
    if (!obs_started && coap_check_option(received, COAP_OPTION_OBSERVE, &opt_iter)) {
      coap_log(LOG_DEBUG,
               "observation relationship established, set timeout to %d\n",
               obs_seconds);
      obs_started = 1;
      obs_ms = obs_seconds * 1000;
      obs_ms_reset = 1;
    }

    /* Got some data, check if block option is set. Behavior is undefined if
     * both, Block1 and Block2 are present. */
    block_opt = coap_check_option(received, COAP_OPTION_BLOCK2, &opt_iter);
    if (block_opt) { /* handle Block2 */
      uint16_t blktype = opt_iter.type;

      /* TODO: check if we are looking at the correct block number */
      if (coap_get_data(received, &len, &databuf)){
        switch(enable_output){
             case STANDARD_RETURN:
               append_to_output(databuf, len);
               break;
             case AUTHZ_INFO_RETURN: 
               handle_authz_return(databuf);
               break;
             case MANAGE_RETURN:
               handle_manage_return();
               break;
             case JOIN_RETURN:
               handle_join_return(databuf);
               break;
             default:
               append_to_output(databuf, len);
               break;
           } /* switch  */
      } /* coap_get_data  */

      if (coap_opt_block_num(block_opt) == 0) {
        /* See if observe is set in first response */
        ready = coap_check_option(received,
                                  COAP_OPTION_OBSERVE, &opt_iter) == NULL;
      }
      if(COAP_OPT_BLOCK_MORE(block_opt)) {
        /* more bit is set */
        coap_log(LOG_DEBUG, "found the M bit, block size is %u, block nr. %u\n",
              COAP_OPT_BLOCK_SZX(block_opt),
              coap_opt_block_num(block_opt));

        /* create pdu with request for next block */
        pdu = coap_new_request(ctx, session, method, NULL, NULL, 0); /* first, create bare PDU w/o any option  */
        if ( pdu ) {
          /* add URI components from optlist */
          for (option = optlist; option; option = option->next ) {
            switch (option->number) {
              case COAP_OPTION_URI_HOST :
              case COAP_OPTION_URI_PORT :
              case COAP_OPTION_URI_PATH :
              case COAP_OPTION_URI_QUERY :
                coap_add_option(pdu, option->number, option->length,
                                option->data);
                break;
              default:
                ;     /* skip other options */
            }
          }

          /* finally add updated block option from response, clear M bit */
          /* blocknr = (blocknr & 0xfffffff7) + 0x10; */
          coap_log(LOG_DEBUG, "query block %d\n",
                   (coap_opt_block_num(block_opt) + 1));
          coap_add_option(pdu,
                          blktype,
                          coap_encode_var_safe(buf, sizeof(buf),
                                 ((coap_opt_block_num(block_opt) + 1) << 4) |
                                  COAP_OPT_BLOCK_SZX(block_opt)), buf);

          tid = coap_send(session, pdu);

          if (tid == COAP_INVALID_TID) {
            coap_log(LOG_DEBUG, "message_handler: error sending new request\n");
          } else {
            wait_ms = wait_seconds * 1000;
            wait_ms_reset = 1;
            doing_getting_block = 1;
          }

          return;
        }
      }
      /* Failure of some sort */
      doing_getting_block = 0;
      return;
    } else { /* no Block2 option */
      block_opt = coap_check_option(received, COAP_OPTION_BLOCK1, &opt_iter);

      if (block_opt) { /* handle Block1 */
        unsigned int szx = COAP_OPT_BLOCK_SZX(block_opt);
        unsigned int num = coap_opt_block_num(block_opt);
        coap_log(LOG_DEBUG,
                 "found Block1 option, block size is %u, block nr. %u\n",
                 szx, num);
        if (szx != block.szx) {
          unsigned int bytes_sent = ((block.num + 1) << (block.szx + 4));
          if (bytes_sent % (1 << (szx + 4)) == 0) {
            /* Recompute the block number of the previous packet given the new block size */
            num = block.num = (bytes_sent >> (szx + 4)) - 1;
            block.szx = szx;
            coap_log(LOG_DEBUG,
                     "new Block1 size is %u, block number %u completed\n",
                     (1 << (block.szx + 4)), block.num);
          } else {
            coap_log(LOG_DEBUG, "ignoring request to increase Block1 size, "
            "next block is not aligned on requested block size boundary. "
            "(%u x %u mod %u = %u != 0)\n",
                  block.num + 1, (1 << (block.szx + 4)), (1 << (szx + 4)),
                  bytes_sent % (1 << (szx + 4)));
          }
        }

        if (last_block1_tid == received->tid) {
          /*
           * Duplicate BLOCK1 ACK
           *
           * RFCs not clear here, but on a lossy connection, there could
           * be multiple BLOCK1 ACKs, causing the client to retransmit the
           * same block multiple times.
           *
           * Once a block has been ACKd, there is no need to retransmit it.
           */
          return;
        }
        last_block1_tid = received->tid;

        if (payload.length <= (block.num+1) * (1 << (block.szx + 4))) {
          coap_log(LOG_DEBUG, "upload ready\n");
          if (coap_get_data(received, &len, &databuf))
            append_to_output(databuf, len);
          ready = 1;
          return;
        }

       /* create pdu with request for next block */
        pdu = coap_new_request(ctx, session, method, NULL, NULL, 0); /* first, create bare PDU w/o any option  */
        if (pdu) {

          /* add URI components from optlist */
          for (option = optlist; option; option = option->next ) {
            switch (option->number) {
              case COAP_OPTION_URI_HOST :
              case COAP_OPTION_URI_PORT :
              case COAP_OPTION_URI_PATH :
              case COAP_OPTION_CONTENT_FORMAT :
              case COAP_OPTION_URI_QUERY :
                coap_add_option(pdu, option->number, option->length,
                                option->data);
                break;
              default:
              ;     /* skip other options */
            }
          }

          /* finally add updated block option from response, clear M bit */
          /* blocknr = (blocknr & 0xfffffff7) + 0x10; */
          block.num = num + 1;
          block.m = ((block.num+1) * (1 << (block.szx + 4)) < payload.length);

          coap_log(LOG_DEBUG, "send block %d\n", block.num);
          coap_add_option(pdu,
                          COAP_OPTION_BLOCK1,
                          coap_encode_var_safe(buf, sizeof(buf),
                          (block.num << 4) | (block.m << 3) | block.szx), buf);

          coap_add_option(pdu,
                          COAP_OPTION_SIZE1,
                          coap_encode_var_safe8(buf, sizeof(buf), payload.length),
                          buf);

          coap_add_block(pdu,
                         payload.length,
                         payload.s,
                         block.num,
                         block.szx);
          if (coap_get_log_level() < LOG_DEBUG)
            coap_show_pdu(LOG_INFO, pdu);

          tid = coap_send(session, pdu);

          if (tid == COAP_INVALID_TID) {
            coap_log(LOG_DEBUG, "message_handler: error sending new request\n");
          } else {
            wait_ms = wait_seconds * 1000;
            wait_ms_reset = 1;
          }

          return;
        }
      } else {
        /* There is no block option set, just read the data and we are done. */
        if (coap_get_data(received, &len, &databuf)){
          switch(enable_output){
             case STANDARD_RETURN:
               append_to_output(databuf, len);
               break;
             case AUTHZ_INFO_RETURN: 
               handle_authz_return(databuf);
               break;
             case MANAGE_RETURN:
               handle_manage_return();
               break;
             case JOIN_RETURN:
               handle_join_return(databuf);
               break;
             default:
               append_to_output(databuf, len);
               break;
           } /* switch  */
        } /* coap_get_data  */
      }
    }
  } else {      /* no 2.05 */

    /* check if an error was signaled and output payload if so */
    if (COAP_RESPONSE_CLASS(received->code) >= 4) {
      fprintf(stderr, "%d.%02d",
              (received->code >> 5), received->code & 0x1F);
      if (coap_get_data(received, &len, &databuf)) {
        fprintf(stderr, " ");
        while(len--)
        fprintf(stderr, "%c", *databuf++);
      }
      fprintf(stderr, "\n");
    }

  }

  /* any pdu that has been created in this function must be sent by now */
  assert(pdu == NULL);

  /* our job is done, we can exit at any time */
  ready = coap_check_option(received, COAP_OPTION_OBSERVE, &opt_iter) == NULL;
}

static void
GM_fill_group_values(oauth_cnf_t *cnf, int choice){
  char group_name[] = "GRP";
  char C0[]         = "C0";
  char C1[]         = "C1";
  char C2[]         = "C2";
  char AD[]         = "AD";
  char GM[]         = "GM";
  cnf->alg = COSE_Algorithm_AES_CCM_16_64_128;
  cnf->hkdf = COSE_Algorithm_HKDF_SHA_256;
  cnf->context_id = NULL;
  cnf->context_id_len = 0;
  cnf->server_id_len = strlen(GM);
  cnf->server_id = coap_malloc(cnf->server_id_len);
  strncpy((char *)cnf->server_id, GM, cnf->server_id_len);
  cnf->rpl = OSCORE_DEFAULT_REPLAY_WINDOW;
  cnf->cs_alg = COSE_Algorithm_EdDSA;
  cnf->crv = COSE_Elliptic_Curve_Ed25519;
  cnf->profile = OAUTH_PROF_COAP_OSCORE; 
  cnf->exp = 1444064944;
  cnf->kty = COSE_KTY_OKP;

/* GM application defines salt and master-secret for join  */
    cnf->ms = coap_malloc(COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);
    prng(cnf->ms,COSE_algorithm_AES_CCM_16_64_128_KEY_LEN);
    cnf->ms_len = COSE_algorithm_AES_CCM_16_64_128_KEY_LEN;
    cnf->salt = coap_malloc(NONCE_LEN);
    prng(cnf->salt, NONCE_LEN);
    cnf->salt_len = NONCE_LEN;
    if (choice == 0 || choice == 4){
/* copy values to ADGM mastersecret and salt for later oscore context creation  */
      for (uint qq = 0; qq < COSE_algorithm_AES_CCM_16_64_128_KEY_LEN; qq++)
             ADGM_master_secret[qq] = cnf->ms[qq];
      for (uint qq = 0; qq < NONCE_LEN; qq++)
             ADGM_salt[qq] = cnf->salt[qq];
	} else {
/* copy values to CXGM mastersecret and salt for later oscore context creation  */
      for (uint qq = 0; qq < COSE_algorithm_AES_CCM_16_64_128_KEY_LEN; qq++)
             CxGM_master_secret[qq] = cnf->ms[qq];
      for (uint qq = 0; qq < NONCE_LEN; qq++)
             CxGM_salt[qq] = cnf->salt[qq];
    }
  switch (choice){
    case 0:  /* create group  */
    case 4:
      cnf->group_id_len = strlen(group_name);
      cnf->group_id = coap_malloc(cnf->group_id_len);
      strncpy((char *)cnf->group_id, 
                                 group_name, cnf->group_id_len);
      cnf->client_id_len = strlen(AD);                                 
      cnf->client_id = coap_malloc(cnf->client_id_len);
      strncpy((char *)cnf->client_id, AD, cnf->client_id_len);
      break;
    case 1:  /* C1 joins */
    case 5:
      cnf->client_id_len = strlen(C1);   
      cnf->client_id = coap_malloc(cnf->client_id_len);
      strncpy((char *)cnf->client_id, C1, cnf->client_id_len);
      break;
    case 2:  /* C2 joins */
    case 6:
      cnf->client_id_len = strlen(C2);   
      cnf->client_id = coap_malloc(cnf->client_id_len);
      strncpy((char *)cnf->client_id, C2, cnf->client_id_len);
      break;
    case 3:  /* C0 joins  */
    case 7:
      cnf->client_id_len = strlen(C0);    
      cnf->client_id = coap_malloc(cnf->client_id_len);
      strncpy((char *)cnf->client_id, C0, cnf->client_id_len);
      break;
    default:
      break;
  } /* switch  */
}


/* GM_fill_group_request
 * fills request to GM for group creation into payload
*/
static uint8_t
GM_fill_group_request(coap_string_t *GMrequest)
{
  uint16_t nr = 0;
  char GRP[] = "GRP";
  char as_uri[] = "coap://as.example.com/token";
  uint8_t *req_buf = coap_malloc(500);
  uint8_t *buf = req_buf;
  nr += cbor_put_map(&buf, 11);
  nr += cbor_put_number( &buf, GM_ADMIN_group_name);
  nr += cbor_put_text  ( &buf, GRP, strlen(GRP));
  nr += cbor_put_number( &buf, GM_ADMIN_hkdf);
  nr += cbor_put_number( &buf, COSE_Algorithm_HKDF_SHA_256);
  nr += cbor_put_number( &buf, GM_ADMIN_alg);
  nr += cbor_put_number( &buf, COSE_Algorithm_AES_CCM_16_64_128);
  nr += cbor_put_number( &buf, GM_ADMIN_cs_alg);
  nr += cbor_put_number( &buf, COSE_Algorithm_EdDSA);
  nr += cbor_put_number( &buf, GM_ADMIN_cs_key_enc);
  nr += cbor_put_number( &buf, CWT_KEY_COSE_KEY);
  nr += cbor_put_number( &buf, CWT_CLAIM_EXP);
  nr += cbor_put_number( &buf, 1444060944);
  nr += cbor_put_number( &buf, GM_ADMIN_as_uri);
  nr += cbor_put_text  ( &buf, as_uri, strlen(as_uri));
  nr += cbor_put_number( &buf, GM_ADMIN_active);
  nr += cbor_put_simple_value( &buf, CBOR_TRUE);
  size_t cs_params_len = 0;
  size_t cs_key_params_len = 0;
  uint8_t *cs_params = GM_cs_params( COSE_Elliptic_Curve_Ed25519, COSE_KTY_OKP, &cs_params_len);
  uint8_t *cs_key_params = GM_cs_key_params( COSE_Elliptic_Curve_Ed25519, COSE_KTY_OKP, &cs_key_params_len);
  nr += cbor_put_number( &buf, GM_ADMIN_cs_params);
  nr += cbor_put_bytes( &buf, cs_params, cs_params_len);
  nr += cbor_put_number( &buf, GM_ADMIN_cs_key_params);
  nr += cbor_put_bytes( &buf, cs_key_params, cs_key_params_len); 
  coap_free(cs_params);
  coap_free(cs_key_params); 
  nr += cbor_put_number( &buf, GRP_TAG_GROUPPOLICIES);
  nr += cbor_put_map( &buf, 4);
  nr += cbor_put_number( &buf, POLICY_EXPIRATION_DELTA);
  nr += cbor_put_number( &buf, 0);
  nr += cbor_put_number( &buf, POLICY_CHECK_INTERVAL);
  nr += cbor_put_number( &buf, 3600);
  nr += cbor_put_number( &buf, POLICY_SYNCHRO_METHOD);
  nr += cbor_put_number( &buf, POL_SM_BEST_EFFORT);
  nr += cbor_put_number( &buf, POLICY_PAIRWISE_MODE);
  nr += cbor_put_simple_value( &buf, CBOR_FALSE);
  GMrequest->s = coap_malloc(nr);
  memcpy(GMrequest->s, req_buf, nr);
  GMrequest->length = nr;
  free(req_buf);
  return 0;
}

/* GM_fill_member_request
 * fills request to GM for goup creation into payload
*/
static uint8_t
GM_fill_member_request(coap_string_t *GMrequest)
{
  uint16_t nr = 0;
  cose_sign1_t sign[1]; 
  uint8_t *req_buf = coap_malloc(500);
  uint8_t *buf = req_buf;
  uint8_t scope_buf[100];
  uint8_t *scopep = scope_buf;
  size_t  scope_len = 0;
  uint8_t clientcred_buf[100];
  uint8_t *clientcredp = clientcred_buf;
  size_t  clientcred_len = 0;
  char return_uri[] = "coap://client.vanderstok.org/group_control";

  cose_sign1_init(sign);  /* clear sign memory */
  scope_len = GM_create_scope(&scopep, GM_choice);
  switch (GM_choice){
    case 1:  /* C1 joins */
      break;
    case 2:  /* C2 joins */
      clientcred_len = 
               GM_create_credp(&clientcredp, public_key_C2);
      cose_sign1_set_private_key(sign, private_key_C2); 
      cose_sign1_set_public_key(sign, public_key_C2);
      break;
    case 3:  /* C0 joins  */
      clientcred_len = 
               GM_create_credp(&clientcredp, public_key_C0);
      cose_sign1_set_private_key(sign, private_key_C0); 
      cose_sign1_set_public_key(sign, public_key_C0);
      break;
    default:
      break;
  } /* switch  */
  if (clientcred_len > 0) nr += cbor_put_map(&buf, 6);
  else nr += cbor_put_map(&buf, 3);
  nr += cbor_put_number(&buf, GRP_TAG_GETPUBKEYS);
  nr += cbor_put_array(&buf, 0);
  nr += cbor_put_number( &buf, GRP_TAG_SCOPE);
  nr += cbor_put_bytes( &buf, scope_buf, scope_len);
  nr += cbor_put_number(&buf, GRP_TAG_CONTROLPATH);
  nr += cbor_put_text(&buf, return_uri, strlen(return_uri));
  
  if (clientcred_len > 0){
/* prepare cose_sign1 
  for signature of kdcchallenge | cnonce */
    uint8_t local_nonce[NONCE_LEN];
    uint8_t *veri_nonce = coap_malloc( (2*NONCE_LEN) + scope_len);
    uint8_t double_nonce_sig[COSE_ALGORITHM_Ed25519_SIG_LEN];
    prng(local_nonce, NONCE_LEN);
    for (uint qq = 0; qq < scope_len; qq++)
	     veri_nonce[qq] = scope_buf[qq];
    for (uint qq = 0; qq < NONCE_LEN; qq++){
	  veri_nonce[qq + scope_len] = kdcchallenge[qq];
	  veri_nonce[qq + NONCE_LEN + scope_len] = local_nonce[qq];
    }
    cose_sign1_set_alg(sign, COSE_Algorithm_EdDSA,
                     COSE_Elliptic_Curve_Ed25519, COSE_KTY_OKP);
    cose_sign1_set_signature(sign, double_nonce_sig);
    cose_sign1_set_ciphertext(sign, veri_nonce, (2*NONCE_LEN) + scope_len);
    int sign_res = cose_sign1_sign(sign);
    coap_free(veri_nonce);
    if (sign_res == 0){
      coap_log(LOG_WARNING,"double nonce signature Failure");
      free(req_buf);
      free(GMrequest->s);
      return 1;
    }

     nr += cbor_put_number( &buf, GRP_TAG_CLIENTCRED);
     nr += cbor_put_bytes( &buf, clientcred_buf, clientcred_len);
     nr += cbor_put_number( &buf, GRP_TAG_CLIENTCREDVERIFY);
     nr += cbor_put_bytes( &buf, double_nonce_sig, 
                                COSE_ALGORITHM_Ed25519_SIG_LEN);
     nr += cbor_put_number(&buf, GRP_TAG_CNONCE);
     nr += cbor_put_bytes(&buf, local_nonce, NONCE_LEN);
  } 
  GMrequest->length = nr;
  GMrequest->s = coap_malloc(nr);
  memcpy(GMrequest->s, req_buf, nr);
  free(req_buf);
  return 0;
}


/* GM_fill_token_request
 * fills request to GM for group join authorization 
*/
static uint8_t
GM_fill_token_request(coap_string_t *GMrequest)
{
  uint8_t  ASGM_IV[COSE_algorithm_AES_CCM_16_64_128_IV_LEN];
  char     Sym128[]="Symmetric128";
  uint8_t  *token_buf = coap_malloc(450);
  uint8_t  *token = token_buf;
  uint8_t  *envelop_buf = coap_malloc(450);
  uint8_t  *envelop = envelop_buf;
  size_t   ciphertext_len;
  size_t   len = 0;
  oauth_cnf_t    *conf = coap_malloc(sizeof(oauth_cnf_t));
  memset(conf, 0, sizeof(oauth_cnf_t));
  GMrequest->length = 0;
  GM_fill_group_values( conf, GM_choice); 
  prng(ASGM_IV, COSE_algorithm_AES_CCM_16_64_128_IV_LEN);
  len = oauth_create_encrypt_header(&envelop, 
                       ASGM_IV, sizeof(ASGM_IV), (uint8_t *) Sym128, strlen(Sym128));
  size_t token_len = GM_create_token(&token_buf, conf, GM_choice);
  oauth_delete_conf(conf);
  uint8_t aad_buffer[35];
  uint8_t aad_len = GM_prepare_aad(
                   COSE_Algorithm_AES_CCM_16_64_128, aad_buffer);
  uint8_t *ciphertext = oauth_encrypt_token(token, token_len, ASGM_KEY,
        aad_buffer, aad_len, 
        ASGM_IV, &ciphertext_len); 

  if (ciphertext == NULL){
    free(token);
    free(envelop_buf);
    return 2;
  }
  len += cbor_put_bytes(&envelop, ciphertext, ciphertext_len);
  free(token);
  free(ciphertext);
/* create new random GM_nonce1          */
  prng(GM_nonce1, NONCE_LEN);
  uint8_t  *mes_buf = coap_malloc(450);
  uint8_t  *mes = mes_buf;
  size_t   mes_len = 0;
/* fill message  */
  mes_len += cbor_put_map( &mes, 2);
  mes_len += cbor_put_number( &mes, OAUTH_CLAIM_ACCESSTOKEN);
  mes_len += cbor_put_bytes( &mes, envelop_buf, len);
  mes_len += cbor_put_number( &mes, OAUTH_OSC_PROF_NONCE1);
  mes_len += cbor_put_bytes( &mes, GM_nonce1, NONCE_LEN);
  GMrequest->length = mes_len;
  GMrequest->s = coap_malloc(mes_len); 
  memcpy(GMrequest->s, mes_buf, mes_len);
  free(mes_buf);
  free(envelop_buf);
  uint8_t opt_buf[4];
  coap_insert_optlist(&optlist,
                   coap_new_optlist(COAP_OPTION_CONTENT_FORMAT,
                   coap_encode_var_safe(opt_buf, sizeof(opt_buf),
                   COAP_MEDIATYPE_APPLICATION_ACE_CBOR),
                   opt_buf));
  return 0;
}


static void
usage( const char *program, const char *version) {
  const char *p;
  char buffer[64];

  p = strrchr( program, '/' );
  if ( p )
    program = ++p;

  fprintf( stderr, "%s v%s -- a small CoAP implementation\n"
     "Copyright (C) 2010-2019 Olaf Bergmann <bergmann@tzi.org> and others\n\n"
     "%s\n\n"
     "Usage: %s [-a addr] [-b [num,]size] [-e text] [-f file] [-l loss]\n"
     "\t\t[-m method] [-o file] [-p port] [-r] [-s duration] [-t type]\n"
     "\t\t[-v num] [-A type] [-B seconds] [-K interval] [-N] [-O num,text]\n"
#ifdef WITH_OSCORE
     "\t\t[-P addr[:port]] [-T token] [-U] [-E pkt_nr]\n"
#else
     "\t\t[-P addr[:port]] [-T token] [-U]\n"
#endif /* WITH_OSCORE */
     "\t\t[[-h match_hint_file] [-k key] [-u user]]\n"
     "\t\t[[-c certfile] [-C cafile] [-R root_cafile]] URI\n\n"
     "\tURI can be an absolute URI or a URI prefixed with scheme and host\n\n"
     "General Options\n"
     "\t-a addr\t\tThe local interface address to use\n"
     "\t-b [num,]size\tBlock size to be used in GET/PUT/POST requests\n"
     "\t       \t\t(value must be a multiple of 16 not larger than 1024)\n"
     "\t       \t\tIf num is present, the request chain will start at\n"
     "\t       \t\tblock num\n"
     "\t-e text\t\tInclude text as payload (use percent-encoding for\n"
     "\t       \t\tnon-ASCII characters)\n"
     "\t-f file\t\tFile to send with PUT/POST (use '-' for STDIN)\n"
     "\t-l list\t\tFail to send some datagrams specified by a comma\n"
     "\t       \t\tseparated list of numbers or number ranges\n"
     "\t       \t\t(for debugging only)\n"
     "\t-l loss%%\tRandomly fail to send datagrams with the specified\n"
     "\t       \t\tprobability - 100%% all datagrams, 0%% no datagrams\n"
     "\t-m method\tRequest method (get|put|post|delete|fetch|patch|ipatch),\n"
     "\t       \t\tdefault is 'get'\n"
     "\t-o file\t\tOutput received data to this file (use '-' for STDOUT)\n"
     "\t-p port\t\tListen on specified port\n"
     "\t-r     \t\tUse reliable protocol (TCP or TLS); requires TCP support\n"
     "\t-s duration\tSubscribe to / Observe resource for given duration\n"
     "\t       \t\tin seconds\n"
     "\t-t type\t\tContent format for given resource for PUT/POST\n"
     "\t-v num \t\tVerbosity level (default 3, maximum is 9). Above 7,\n"
     "\t       \t\tthere is increased verbosity in GnuTLS logging\n"
     "\t-A type\t\tAccepted media type\n"
     "\t-B seconds\tBreak operation after waiting given seconds\n"
     "\t       \t\t(default is %d)\n"
     "\t-K interval\tsend a ping after interval seconds of inactivity\n"
     "\t-N     \t\tSend NON-confirmable message\n"
     "\t-O num,text\tAdd option num with contents text to request. If the\n"
     "\t       \t\ttext begins with 0x, then the hex text is converted to\n"
     "\t       \t\tbinary data\n"
     "\t-P addr[:port]\tUse proxy (automatically adds Proxy-Uri option to\n"
     "\t       \t\trequest)\n"
#ifdef WITH_OSCORE
     "\t-E num \tOSCORE encryption wanted\n"
     "\t       \t\tnum is sequence number of first OSCORE packet\n"   
#endif /* WITH_OSCORE */
     "\t-T token\tInclude specified token\n"
     "\t-U     \t\tNever include Uri-Host or Uri-Port options\n"
     "PSK Options (if supported by underlying (D)TLS library)\n"
     "\t-h match_hint_file\n"
     "\t       \t\tThis is a file that contains one or more lines of Identity\n"
     "\t       \t\tHints to match for new user and new pre-shared key\n"
     "\t       \t\t(PSK) (comma separated) to be used. E.g., per line\n"
     "\t       \t\t hint_to_match,new_user,new_key\n"
     "\t       \t\tNote: -k and -u still need to be defined for the default\n"
     "\t       \t\tcase\n"
     "\t-k key \t\tPre-shared key for the specified user\n"
     "\t-u user\t\tUser identity for pre-shared key mode\n"
     "PKI Options (if supported by underlying (D)TLS library)\n"
     "\t-c certfile\tPEM file containing both CERTIFICATE and PRIVATE KEY\n"
     "\t       \t\tThis argument requires (D)TLS with PKI to be available\n"
     "\t-C cafile\tPEM file containing the CA Certificate that was used to\n"
     "\t       \t\tsign the certfile. This will trigger the validation of\n"
     "\t       \t\tthe server certificate.  If certfile is self-signed (as\n"
     "\t       \t\tdefined by '-c certfile'), then you need to have on the\n"
     "\t       \t\tcommand line the same filename for both the certfile and\n"
     "\t       \t\tcafile (as in '-c certfile -C certfile') to trigger\n"
     "\t       \t\tvalidation\n"
     "\t-R root_cafile\tPEM file containing the set of trusted root CAs that\n"
     "\t       \t\tare to be used to validate the server certificate.\n"
     "\t       \t\tThe '-C cafile' does not have to be in this list and is\n"
     "\t       \t\t'trusted' for the verification.\n"
     "\t       \t\tAlternatively, this can point to a directory containing\n"
     "\t       \t\ta set of CA PEM files\n"
     "\n"
     "Examples:\n"
     "\tcoap-client -m get coap://[::1]/\n"
     "\tcoap-client -m get coap://[::1]/.well-known/core\n"
     "\tcoap-client -m get coap+tcp://[::1]/.well-known/core\n"
     "\tcoap-client -m get coaps://[::1]/.well-known/core\n"
     "\tcoap-client -m get coaps+tcp://[::1]/.well-known/core\n"
     "\tcoap-client -m get -T cafe coap://[::1]/time\n"
     "\techo -n 1000 | coap-client -m put -T cafe coap://[::1]/time -f -\n"
     ,program, version, coap_string_tls_version(buffer, sizeof(buffer))
     ,program, wait_seconds);
}

#ifdef WITH_OSCORE
static void
oscore_set_contexts(void){
   /* empty  */
}
#endif /* WITH_OSCORE */

typedef struct {
  unsigned char code;
  const char *media_type;
} content_type_t;

static void
cmdline_content_type(char *arg, uint16_t key) {
  static content_type_t content_types[] = {
    {  0, "plain" },
    {  0, "text/plain" },
    { 40, "link" },
    { 40, "link-format" },
    { 40, "application/link-format" },
    { 41, "xml" },
    { 41, "application/xml" },
    { 42, "binary" },
    { 42, "octet-stream" },
    { 42, "application/octet-stream" },
    { 47, "exi" },
    { 47, "application/exi" },
    { 50, "json" },
    { 50, "application/json" },
    { 60, "cbor" },
    { 60, "application/cbor" },
    { 255, NULL }
  };
  coap_optlist_t *node;
  unsigned char i;
  uint16_t value;
  uint8_t buf[2];

  if (isdigit(*arg)) {
    value = atoi(arg);
  } else {
    for (i=0;
         content_types[i].media_type &&
           strncmp(arg, content_types[i].media_type, strlen(arg)) != 0 ;
         ++i)
      ;

    if (content_types[i].media_type) {
      value = content_types[i].code;
    } else {
      coap_log(LOG_WARNING, "W: unknown content-format '%s'\n",arg);
      return;
    }
  }

  node = coap_new_optlist(key, coap_encode_var_safe(buf, sizeof(buf), value), buf);
  if (node) {
    coap_insert_optlist(&optlist, node);
  }
}

static uint16_t
get_default_port(const coap_uri_t *u) {
  return coap_uri_scheme_is_secure(u) ? COAPS_DEFAULT_PORT : COAP_DEFAULT_PORT;
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
cmdline_uri(char *arg, int create_uri_opts) {
  unsigned char portbuf[2];
#define BUFSIZE 100
  unsigned char _buf[BUFSIZE];
  unsigned char *buf = _buf;
  size_t buflen;
  int res;

  if (proxy.length) {   /* create Proxy-Uri from argument */
    size_t len = strlen(arg);
    while (len > 270) {
      coap_insert_optlist(&optlist,
                  coap_new_optlist(COAP_OPTION_PROXY_URI,
                  270,
                  (unsigned char *)arg));

      len -= 270;
      arg += 270;
    }

    coap_insert_optlist(&optlist,
                coap_new_optlist(COAP_OPTION_PROXY_URI,
                len,
                (unsigned char *)arg));

  } else {      /* split arg into Uri-* options */
    if (coap_split_uri((unsigned char *)arg, strlen(arg), &uri) < 0) {
      coap_log(LOG_ERR, "invalid CoAP URI\n");
      return -1;
    }

    if (uri.scheme==COAP_URI_SCHEME_COAPS && !reliable && !coap_dtls_is_supported()) {
      coap_log(LOG_EMERG,
               "coaps URI scheme not supported in this version of libcoap\n");
      return -1;
    }

    if ((uri.scheme==COAP_URI_SCHEME_COAPS_TCP || (uri.scheme==COAP_URI_SCHEME_COAPS && reliable)) && !coap_tls_is_supported()) {
      coap_log(LOG_EMERG,
            "coaps+tcp URI scheme not supported in this version of libcoap\n");
      return -1;
    }

    if (uri.scheme==COAP_URI_SCHEME_COAP_TCP && !coap_tcp_is_supported()) {
      /* coaps+tcp caught above */
      coap_log(LOG_EMERG,
            "coap+tcp URI scheme not supported in this version of libcoap\n");
      return -1;
    }

    if (uri.port != get_default_port(&uri) && create_uri_opts) {
      coap_insert_optlist(&optlist,
                  coap_new_optlist(COAP_OPTION_URI_PORT,
                                   coap_encode_var_safe(portbuf, sizeof(portbuf),
                                                        (uri.port & 0xffff)),
                  portbuf));
    }

    if (uri.path.length) {
      buflen = BUFSIZE;
      if (uri.path.length > BUFSIZE)
        coap_log(LOG_WARNING, "URI path will be truncated (max buffer %d)\n", BUFSIZE);
      res = coap_split_path(uri.path.s, uri.path.length, buf, &buflen);

      while (res--) {
        coap_insert_optlist(&optlist,
                    coap_new_optlist(COAP_OPTION_URI_PATH,
                    coap_opt_length(buf),
                    coap_opt_value(buf)));

        buf += coap_opt_size(buf);
      }
    }

    if (uri.query.length) {
      buflen = BUFSIZE;
      buf = _buf;
      res = coap_split_query(uri.query.s, uri.query.length, buf, &buflen);

      while (res--) {
        coap_insert_optlist(&optlist,
                    coap_new_optlist(COAP_OPTION_URI_QUERY,
                    coap_opt_length(buf),
                    coap_opt_value(buf)));

        buf += coap_opt_size(buf);
      }
    }
  }

  return 0;
}

static int
cmdline_blocksize(char *arg) {
  uint16_t size;

  again:
  size = 0;
  while(*arg && *arg != ',')
    size = size * 10 + (*arg++ - '0');

  if (*arg == ',') {
    arg++;
    block.num = size;
    goto again;
  }

  if (size)
    block.szx = (coap_fls(size >> 4) - 1) & 0x07;

  flags |= FLAGS_BLOCK;
  return 1;
}

/* Called after processing the options from the commandline to set
 * Block1 or Block2 depending on method. */
static void
set_blocksize(void) {
  static unsigned char buf[4];        /* hack: temporarily take encoded bytes */
  uint16_t opt;
  unsigned int opt_length;

  if (method != COAP_REQUEST_DELETE) {
    opt = method == COAP_REQUEST_GET ? COAP_OPTION_BLOCK2 : COAP_OPTION_BLOCK1;

    block.m = (opt == COAP_OPTION_BLOCK1) &&
      ((1ull << (block.szx + 4)) < payload.length);

    opt_length = coap_encode_var_safe(buf, sizeof(buf),
          (block.num << 4 | block.m << 3 | block.szx));

    coap_insert_optlist(&optlist, coap_new_optlist(opt, opt_length, buf));
  }
}

static void
cmdline_subscribe(char *arg) {
  obs_seconds = atoi(arg);
  coap_insert_optlist(&optlist, coap_new_optlist(COAP_OPTION_OBSERVE,
                      COAP_OBSERVE_ESTABLISH, NULL));
}

static int
cmdline_proxy(char *arg) {
  char *proxy_port_str = strrchr((const char *)arg, ':'); /* explicit port ? */
  if (proxy_port_str) {
    char *ipv6_delimiter = strrchr((const char *)arg, ']');
    if (!ipv6_delimiter) {
      if (proxy_port_str == strchr((const char *)arg, ':')) {
        /* host:port format - host not in ipv6 hexadecimal string format */
        *proxy_port_str++ = '\0'; /* split */
        proxy_port = atoi(proxy_port_str);
      }
    } else {
      arg = strchr((const char *)arg, '[');
      if (!arg) return 0;
      arg++;
      *ipv6_delimiter = '\0'; /* split */
      if (ipv6_delimiter + 1 == proxy_port_str++) {
        /* [ipv6 address]:port */
        proxy_port = atoi(proxy_port_str);
      }
    }
  }

  proxy.length = strlen(arg);
  if ( (proxy.s = coap_malloc(proxy.length + 1)) == NULL) {
    proxy.length = 0;
    return 0;
  }

  memcpy(proxy.s, arg, proxy.length+1);
  return 1;
}

static inline void
cmdline_token(char *arg) {
  the_token.length = min(sizeof(_token_data), strlen(arg));
  if (the_token.length > 0) {
    memcpy((char *)the_token.s, arg, the_token.length);
  }
}

/**
 * Utility function to convert a hex digit to its corresponding
 * numerical value.
 *
 * param c  The hex digit to convert. Must be in [0-9A-Fa-f].
 *
 * return The numerical representation of @p c.
 */
static uint8_t
hex2char(char c) {
  assert(isxdigit(c));
  if ('a' <= c && c <= 'f')
    return c - 'a' + 10;
  else if ('A' <= c && c <= 'F')
    return c - 'A' + 10;
  else
    return c - '0';
}

/**
 * Converts the sequence of hex digits in src to a sequence of bytes.
 *
 * This function returns the number of bytes that have been written to
 * @p dst.
 *
 * param[in]  src  The null-terminated hex string to convert.
 * param[out] dst  Conversion result.
 *
 * return The length of @p dst.
 */
static size_t
convert_hex_string(const char *src, uint8_t *dst) {
  uint8_t *p = dst;
  while (isxdigit(src[0]) && isxdigit(src[1])) {
    *p++ = (hex2char(src[0]) << 4) + hex2char(src[1]);
    src += 2;
  }
  if (src[0] != '\0') { /* error in hex input */
    coap_log(LOG_WARNING, "invalid hex string in option '%s'\n", src);
  }
  return p - dst;
}

#ifdef WITH_OSCORE
static inline unsigned int
cmdline_oscore(char *arg) {
  unsigned int num = 0;
  while (*arg) {
    num = num * 10 + (*arg - '0');
    ++arg;
  }
  return num;
}
#endif /* WITH_OSCORE */

static inline unsigned int
cmdline_GM(char *arg) {
  unsigned int num = 0;
  while (*arg) {
    num = num * 10 + (*arg - '0');
    ++arg;
  }
  return num;
}

static void
cmdline_option(char *arg) {
  unsigned int num = 0;

  while (*arg && *arg != ',') {
    num = num * 10 + (*arg - '0');
    ++arg;
  }
  if (*arg == ',')
    ++arg;

   /* read hex string when arg starts with "0x" */
  if (arg[0] == '0' && arg[1] == 'x') {
    /* As the command line option is part of our environment we can do
     * the conversion in place. */
    size_t len = convert_hex_string(arg + 2, (uint8_t *)arg);

    /* On success, 2 * len + 2 == strlen(arg) */
    coap_insert_optlist(&optlist,
                        coap_new_optlist(num, len, (unsigned char *)arg));
  } else { /* null-terminated character string */
    coap_insert_optlist(&optlist,
                        coap_new_optlist(num, strlen(arg), (unsigned char *)arg));
  }
}

/**
 * Calculates decimal value from hexadecimal ASCII character given in
 * @p c. The caller must ensure that @p c actually represents a valid
 * heaxdecimal character, e.g. with isxdigit(3).
 *
 * @hideinitializer
 */
#define hexchar_to_dec(c) ((c) & 0x40 ? ((c) & 0x0F) + 9 : ((c) & 0x0F))

/**
 * Decodes percent-encoded characters while copying the string @p seg
 * of size @p length to @p buf. The caller of this function must
 * ensure that the percent-encodings are correct (i.e. the character
 * '%' is always followed by two hex digits. and that @p buf provides
 * sufficient space to hold the result. This function is supposed to
 * be called by make_decoded_option() only.
 *
 * @param seg     The segment to decode and copy.
 * @param length  Length of @p seg.
 * @param buf     The result buffer.
 */
static void
decode_segment(const uint8_t *seg, size_t length, unsigned char *buf) {

  while (length--) {

    if (*seg == '%') {
      *buf = (hexchar_to_dec(seg[1]) << 4) + hexchar_to_dec(seg[2]);

      seg += 2; length -= 2;
    } else {
      *buf = *seg;
    }

    ++buf; ++seg;
  }
}

/**
 * Runs through the given path (or query) segment and checks if
 * percent-encodings are correct. This function returns @c -1 on error
 * or the length of @p s when decoded.
 */
static int
check_segment(const uint8_t *s, size_t length) {

  int n = 0;

  while (length) {
    if (*s == '%') {
      if (length < 2 || !(isxdigit(s[1]) && isxdigit(s[2])))
        return -1;

      s += 2;
      length -= 2;
    }

    ++s; ++n; --length;
  }

  return n;
}

static int
cmdline_input(char *text, coap_string_t *buf) {
  int len;
  len = check_segment((unsigned char *)text, strlen(text));

  if (len < 0)
    return 0;

  buf->s = (unsigned char *)coap_malloc(len);
  if (!buf->s)
    return 0;

  buf->length = len;
  decode_segment((unsigned char *)text, strlen(text), buf->s);
  return 1;
}

static int
cmdline_input_from_file(char *filename, coap_string_t *buf) {
  FILE *inputfile = NULL;
  ssize_t len;
  int result = 1;
  struct stat statbuf;

  if (!filename || !buf)
    return 0;

  if (filename[0] == '-' && !filename[1]) { /* read from stdin */
    buf->length = 20000;
    buf->s = (unsigned char *)coap_malloc(buf->length);
    if (!buf->s)
      return 0;

    inputfile = stdin;
  } else {
    /* read from specified input file */
    inputfile = fopen(filename, "r");
    if ( !inputfile ) {
      perror("cmdline_input_from_file: fopen");
      return 0;
    }

    if (fstat(fileno(inputfile), &statbuf) < 0) {
      perror("cmdline_input_from_file: stat");
      fclose(inputfile);
      return 0;
    }

    buf->length = statbuf.st_size;
    buf->s = (unsigned char *)coap_malloc(buf->length);
    if (!buf->s) {
      fclose(inputfile);
      return 0;
    }
  }

  len = fread(buf->s, 1, buf->length, inputfile);

  if (len < 0 || ((size_t)len < buf->length)) {
    if (ferror(inputfile) != 0) {
      perror("cmdline_input_from_file: fread");
      coap_free(buf->s);
      buf->length = 0;
      buf->s = NULL;
      result = 0;
    } else {
      buf->length = len;
    }
  }

  if (inputfile != stdin)
    fclose(inputfile);

  return result;
}

static method_t
cmdline_method(char *arg) {
  static const char *methods[] =
    { 0, "get", "post", "put", "delete", "fetch", "patch", "ipatch", 0};
  unsigned char i;

  for (i=1; methods[i] && strcasecmp(arg,methods[i]) != 0 ; ++i)
    ;

  return i;     /* note that we do not prevent illegal methods */
}

static ssize_t
cmdline_read_user(char *arg, unsigned char *buf, size_t maxlen) {
  size_t len = strnlen(arg, maxlen);
  if (len) {
    memcpy(buf, arg, len);
  }
  /* 0 length Identity is valid */
  return len;
}

static ssize_t
cmdline_read_key(char *arg, unsigned char *buf, size_t maxlen) {
  size_t len = strnlen(arg, maxlen);
  if (len) {
    memcpy(buf, arg, len);
    return len;
  }
  /* Need at least one byte for the pre-shared key */
  return -1;
}

static int cmdline_read_hint_check(const char *arg) {
  FILE *fp = fopen(arg, "r");
  static char tmpbuf[256];
  if (fp == NULL) {
    coap_log(LOG_ERR, "Hint file: %s: Unable to open\n", arg);
    return 0;
  }
  while (fgets(tmpbuf, sizeof(tmpbuf), fp) != NULL) {
    char *cp = tmpbuf;
    char *tcp = strchr(cp, '\n');

    if (tmpbuf[0] == '#')
      continue;
    if (tcp)
      *tcp = '\000';

    tcp = strchr(cp, ',');
    if (tcp) {
      ih_def_t *new_ih_list;
      new_ih_list = realloc(valid_ihs.ih_list,
                          (valid_ihs.count + 1)*sizeof (valid_ihs.ih_list[0]));
      if (new_ih_list == NULL) {
        break;
      }
      valid_ihs.ih_list = new_ih_list;
      valid_ihs.ih_list[valid_ihs.count].hint_match = strndup(cp, tcp-cp);
      cp = tcp+1;
      tcp = strchr(cp, ',');
      if (tcp) {
        valid_ihs.ih_list[valid_ihs.count].new_identity =
                               coap_new_bin_const((const uint8_t *)cp, tcp-cp);
        cp = tcp+1;
        valid_ihs.ih_list[valid_ihs.count].new_key =
                           coap_new_bin_const((const uint8_t *)cp, strlen(cp));
        valid_ihs.count++;
      }
      else {
        /* Badly formatted */
        free(valid_ihs.ih_list[valid_ihs.count].hint_match);
      }
    }
  }
  fclose(fp);
  return valid_ihs.count > 0;
}

static int
verify_cn_callback(const char *cn,
                   const uint8_t *asn1_public_cert UNUSED_PARAM,
                   size_t asn1_length UNUSED_PARAM,
                   coap_session_t *session UNUSED_PARAM,
                   unsigned depth,
                   int validated UNUSED_PARAM,
                   void *arg UNUSED_PARAM
) {
  coap_log(LOG_INFO, "CN '%s' presented by server (%s)\n",
           cn, depth ? "CA" : "Certificate");
  return 1;
}

static const coap_dtls_cpsk_info_t *
verify_ih_callback(coap_str_const_t *hint,
                   coap_session_t *c_session UNUSED_PARAM,
                   void *arg
) {
  coap_dtls_cpsk_info_t *psk_info = (coap_dtls_cpsk_info_t *)arg;
  char lhint[COAP_DTLS_HINT_LENGTH];
  static coap_dtls_cpsk_info_t psk_identity_info;
  size_t i;

  snprintf(lhint, sizeof(lhint), "%.*s", (int)hint->length, hint->s);
  coap_log(LOG_INFO, "Identity Hint '%s' provided\n", lhint);

  /* Test for hint to possibly change identity + key */
  for (i = 0; i < valid_ihs.count; i++) {
    if (strcmp(lhint, valid_ihs.ih_list[i].hint_match) == 0) {
      /* Preset */
      psk_identity_info = *psk_info;
      if (valid_ihs.ih_list[i].new_key) {
        psk_identity_info.key = *valid_ihs.ih_list[i].new_key;
      }
      if (valid_ihs.ih_list[i].new_identity) {
        psk_identity_info.identity = *valid_ihs.ih_list[i].new_identity;
      }
      coap_log(LOG_INFO, "Switching to using '%s' identity + '%s' key\n",
               psk_identity_info.identity.s, psk_identity_info.key.s);
      return &psk_identity_info;
    }
  }
  /* Just use the defined key for now as passed in by arg */
  return psk_info;
}

static coap_dtls_pki_t *
setup_pki(coap_context_t *ctx) {
  static coap_dtls_pki_t dtls_pki;
  static char client_sni[256];

  /* If general root CAs are defined */
  if (root_ca_file) {
    struct stat stbuf;
    if ((stat(root_ca_file, &stbuf) == 0) && S_ISDIR(stbuf.st_mode)) {
      coap_context_set_pki_root_cas(ctx, NULL, root_ca_file);
    } else {
      coap_context_set_pki_root_cas(ctx, root_ca_file, NULL);
    }
  }

  memset(client_sni, 0, sizeof(client_sni));
  memset (&dtls_pki, 0, sizeof(dtls_pki));
  dtls_pki.version = COAP_DTLS_PKI_SETUP_VERSION;
  if (ca_file || root_ca_file) {
    /*
     * Add in additional certificate checking.
     * This list of enabled can be tuned for the specific
     * requirements - see 'man coap_encryption'.
     *
     * Note: root_ca_file is setup separately using
     * coap_context_set_pki_root_cas(), but this is used to define what
     * checking actually takes place.
     */
    dtls_pki.verify_peer_cert        = 1;
    dtls_pki.require_peer_cert       = 1;
    dtls_pki.allow_self_signed       = 1;
    dtls_pki.allow_expired_certs     = 1;
    dtls_pki.cert_chain_validation   = 1;
    dtls_pki.cert_chain_verify_depth = 2;
    dtls_pki.check_cert_revocation   = 1;
    dtls_pki.allow_no_crl            = 1;
    dtls_pki.allow_expired_crl       = 1;
    dtls_pki.validate_cn_call_back   = verify_cn_callback;
    dtls_pki.cn_call_back_arg        = NULL;
    dtls_pki.validate_sni_call_back  = NULL;
    dtls_pki.sni_call_back_arg       = NULL;
  }
  if (uri.host.length)
    memcpy(client_sni, uri.host.s, min(uri.host.length, sizeof(client_sni)-1));
  else
    memcpy(client_sni, "localhost", 9);
  dtls_pki.client_sni = client_sni;
  dtls_pki.pki_key.key_type = COAP_PKI_KEY_PEM;
  dtls_pki.pki_key.key.pem.public_cert = cert_file;
  dtls_pki.pki_key.key.pem.private_key = cert_file;
  dtls_pki.pki_key.key.pem.ca_file = ca_file;
  return &dtls_pki;
}

static coap_dtls_cpsk_t *
setup_psk(
  const uint8_t *identity,
  size_t identity_len,
  const uint8_t *key,
  size_t key_len
) {
  static coap_dtls_cpsk_t dtls_psk;
  static char client_sni[256];

  memset(client_sni, 0, sizeof(client_sni));
  memset (&dtls_psk, 0, sizeof(dtls_psk));
  dtls_psk.version = COAP_DTLS_CPSK_SETUP_VERSION;
  dtls_psk.validate_ih_call_back = verify_ih_callback;
  dtls_psk.ih_call_back_arg = &dtls_psk.psk_info;
  if (uri.host.length)
    memcpy(client_sni, uri.host.s,
           min(uri.host.length, sizeof(client_sni) - 1));
  else
    memcpy(client_sni, "localhost", 9);
  dtls_psk.client_sni = client_sni;
  dtls_psk.psk_info.identity.s = identity;
  dtls_psk.psk_info.identity.length = identity_len;
  dtls_psk.psk_info.key.s = key;
  dtls_psk.psk_info.key.length = key_len;
  return &dtls_psk;
}

#ifdef _WIN32
#define S_ISDIR(x) (((x) & S_IFMT) == S_IFDIR)
#endif

static coap_session_t*
open_session(
  coap_context_t *ctx,
  coap_proto_t proto,
  coap_address_t *bind_addr,
  coap_address_t *dst,
  const uint8_t *identity,
  size_t identity_len,
  const uint8_t *key,
  size_t key_len
) {
  coap_session_t *session;

  if (proto == COAP_PROTO_DTLS || proto == COAP_PROTO_TLS) {
    /* Encrypted session */
    if (root_ca_file || ca_file || cert_file) {
      /* Setup PKI session */
      coap_dtls_pki_t *dtls_pki = setup_pki(ctx);
      session = coap_new_client_session_pki(ctx, bind_addr, dst, proto, dtls_pki);
    }
    else if (identity || key) {
      /* Setup PSK session */
      coap_dtls_cpsk_t *dtls_psk = setup_psk(identity, identity_len,
                                               key, key_len);
      session = coap_new_client_session_psk2(ctx, bind_addr, dst, proto,
                                           dtls_psk);
    }
    else {
      /* No PKI or PSK defined, as encrypted, use PKI */
      coap_dtls_pki_t *dtls_pki = setup_pki(ctx);
      session = coap_new_client_session_pki(ctx, bind_addr, dst, proto, dtls_pki);
    }
  }
  else {
    /* Non-encrypted session */
    session = coap_new_client_session(ctx, bind_addr, dst, proto);
  }
  return session;
}

static coap_session_t *
get_session(
  coap_context_t *ctx,
  const char *local_addr,
  const char *local_port,
  coap_proto_t proto,
  coap_address_t *dst,
  const uint8_t *identity,
  size_t identity_len,
  const uint8_t *key,
  size_t key_len
) {
  coap_session_t *session = NULL;

  if ( local_addr ) {
    int s;
    struct addrinfo hints;
    struct addrinfo *result = NULL, *rp;

    memset( &hints, 0, sizeof( struct addrinfo ) );
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = COAP_PROTO_RELIABLE(proto) ? SOCK_STREAM : SOCK_DGRAM; /* Coap uses UDP */
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV | AI_ALL;

    s = getaddrinfo( local_addr, local_port, &hints, &result );
    if ( s != 0 ) {
      fprintf( stderr, "getaddrinfo: %s\n", gai_strerror( s ) );
      return NULL;
    }

    /* iterate through results until success */
    for ( rp = result; rp != NULL; rp = rp->ai_next ) {
      coap_address_t bind_addr;
      if ( rp->ai_addrlen <= sizeof( bind_addr.addr ) ) {
        coap_address_init( &bind_addr );
        bind_addr.size = (socklen_t)rp->ai_addrlen;
        memcpy( &bind_addr.addr, rp->ai_addr, rp->ai_addrlen );
        session = open_session(ctx, proto, &bind_addr, dst,
                               identity, identity_len, key, key_len);
        if ( session )
          break;
      }
    }
    freeaddrinfo( result );
  } else {
    session = open_session(ctx, proto, NULL, dst,
                               identity, identity_len, key, key_len);
  }
  return session;
}

static void
insert_join_optlist(void){

  coap_insert_optlist(&optlist,
                    coap_new_optlist(COAP_OPTION_URI_PATH,
                    2,
                    uri_GM));
coap_insert_optlist(&optlist,
                    coap_new_optlist(COAP_OPTION_URI_PATH,
                    3,
                    uri_GRP));

  uint8_t opt_buf[4];
        coap_insert_optlist(&optlist,
                   coap_new_optlist(COAP_OPTION_CONTENT_FORMAT,
                   coap_encode_var_safe(opt_buf, sizeof(opt_buf),
                   COAP_MEDIATYPE_APPLICATION_ACE_CBOR),
                   opt_buf));
}

static void
insert_manage_optlist(void){
  coap_insert_optlist(&optlist,
                    coap_new_optlist(COAP_OPTION_URI_PATH,
                    2,
                    uri_GM));
  coap_insert_optlist(&optlist,
                    coap_new_optlist(COAP_OPTION_URI_PATH,
                    6,
                    uri_manage));
   uint8_t opt_buf[4];
        coap_insert_optlist(&optlist,
                   coap_new_optlist(COAP_OPTION_CONTENT_FORMAT,
                   coap_encode_var_safe(opt_buf, sizeof(opt_buf),
                   COAP_MEDIATYPE_APPLICATION_ACE_GROUPCOMM_CBOR),
                   opt_buf));
}


int
main(int argc, char **argv) {
  coap_context_t  *ctx = NULL;
  coap_session_t *session = NULL;
  coap_address_t dst;
  static char addr[INET6_ADDRSTRLEN];
  void *addrptr = NULL;
  int result = -1;
  coap_pdu_t  *pdu;
  static coap_str_const_t server;
  uint16_t port = COAP_DEFAULT_PORT;
  char port_str[NI_MAXSERV] = "0";
  char node_str[NI_MAXHOST] = "";
  int opt, res;
  coap_log_t log_level = LOG_WARNING;
  unsigned char user[MAX_USER + 1], key[MAX_KEY];
  ssize_t user_length = -1, key_length = 0;
  int create_uri_opts = 1;
  size_t i;
#ifndef _WIN32
  struct sigaction sa;
#endif
#ifdef WITH_OSCORE
  uint8_t oscore_secure = 0;
  uint16_t oscore_sequence = 0;

  while ((opt = getopt(argc, argv, "NrUa:b:c:d:e:f:h:k:m:p:s:t:o:v:A:B:C:O:P:R:E:T:u:l:K:")) != -1) {
#else
  while ((opt = getopt(argc, argv, "NrUa:b:c:d:e:f:h:k:m:p:s:t:o:v:A:B:C:O:P:R:T:u:l:K:")) != -1) {
#endif /* WITH_OSCORE */
    switch (opt) {
    case 'a':
      strncpy(node_str, optarg, NI_MAXHOST - 1);
      node_str[NI_MAXHOST - 1] = '\0';
      break;
    case 'b':
      cmdline_blocksize(optarg);
      break;
    case 'B':
      wait_seconds = atoi(optarg);
      break;
    case 'c':
      cert_file = optarg;
      break;
    case 'C':
      ca_file = optarg;
      break;
    case 'd':
      GM_choice = cmdline_GM(optarg);   
      break;
    case 'R':
      root_ca_file = optarg;
      break;
    case 'e':
      if (!cmdline_input(optarg, &payload))
        payload.length = 0;
      break;
    case 'f':
      if (!cmdline_input_from_file(optarg, &payload))
        payload.length = 0;
      break;
    case 'k':
      key_length = cmdline_read_key(optarg, key, MAX_KEY);
      break;
    case 'p':
      strncpy(port_str, optarg, NI_MAXSERV - 1);
      port_str[NI_MAXSERV - 1] = '\0';
      break;
    case 'm':
      method = cmdline_method(optarg);
      break;
    case 'N':
      msgtype = COAP_MESSAGE_NON;
      break;
    case 's':
      cmdline_subscribe(optarg);
      break;
    case 'o':
      output_file.length = strlen(optarg);
      output_file.s = (unsigned char *)coap_malloc(output_file.length + 1);

      if (!output_file.s) {
        fprintf(stderr, "cannot set output file: insufficient memory\n");
        exit(-1);
      } else {
        /* copy filename including trailing zero */
        memcpy(output_file.s, optarg, output_file.length + 1);
      }
      break;
    case 'A':
      cmdline_content_type(optarg, COAP_OPTION_ACCEPT);
      break;
    case 't':
      cmdline_content_type(optarg, COAP_OPTION_CONTENT_TYPE);
      break;
    case 'O':
      cmdline_option(optarg);
      break;
    case 'P':
      if (!cmdline_proxy(optarg)) {
        fprintf(stderr, "error specifying proxy address\n");
        exit(-1);
      }
      break;
    case 'T':
      cmdline_token(optarg);
      break;
    case 'u':
      user_length = cmdline_read_user(optarg, user, MAX_USER);
      if (user_length >= 0)
        user[user_length] = 0;
      break;
    case 'U':
      create_uri_opts = 0;
      break;
    case 'v':
      log_level = strtol(optarg, NULL, 10);
      break;
    case 'l':
      if (!coap_debug_set_packet_loss(optarg)) {
        usage(argv[0], LIBCOAP_PACKAGE_VERSION);
        exit(1);
      }
      break;
    case 'r':
      reliable = coap_tcp_is_supported();
      break;
#ifdef WITH_OSCORE
    case 'E':
      oscore_secure =1;
      oscore_sequence = cmdline_oscore(optarg);                
      break;
#endif
    case 'K':
      ping_seconds = atoi(optarg);
      break;
    case 'h':
      if (!cmdline_read_hint_check(optarg)) {
        usage(argv[0], LIBCOAP_PACKAGE_VERSION);
        exit(1);
      }
      break;
    default:
      usage( argv[0], LIBCOAP_PACKAGE_VERSION );
      exit( 1 );
    }
  }

  coap_startup();
  coap_dtls_set_log_level(log_level);
  coap_set_log_level(log_level);

  if (optind < argc) {
    if (cmdline_uri(argv[optind], create_uri_opts) < 0) {
      exit(1);
    }
  } else {
    usage( argv[0], LIBCOAP_PACKAGE_VERSION );
    exit( 1 );
  }

  if (key_length < 0) {
    coap_log( LOG_CRIT, "Invalid pre-shared key specified\n" );
    goto finish;
  }

  if (proxy.length) {
    server.length = proxy.length;
    server.s = proxy.s;
    port = proxy_port;
  } else {
    server = uri.host;
    port = uri.port;
  }

  /* resolve destination address where server should be sent */
  res = resolve_address(&server, &dst.addr.sa);

  if (res < 0) {
    fprintf(stderr, "failed to resolve address\n");
    exit(-1);
  }

  ctx = coap_new_context( NULL );
  if ( !ctx ) {
    coap_log( LOG_EMERG, "cannot create context\n" );
    goto finish;
  }

  coap_context_set_keepalive(ctx, ping_seconds);

  dst.size = res;
  dst.addr.sin.sin_port = htons( port );

  session = get_session(
    ctx,
    node_str[0] ? node_str : NULL, port_str,
    uri.scheme==COAP_URI_SCHEME_COAP_TCP ? COAP_PROTO_TCP :
    uri.scheme==COAP_URI_SCHEME_COAPS_TCP ? COAP_PROTO_TLS :
    (reliable ?
        uri.scheme==COAP_URI_SCHEME_COAPS ? COAP_PROTO_TLS : COAP_PROTO_TCP
      : uri.scheme==COAP_URI_SCHEME_COAPS ? COAP_PROTO_DTLS : COAP_PROTO_UDP),
    &dst,
    user_length >= 0 ? user : NULL,
    user_length >= 0 ? user_length : 0,
    key_length > 0 ? key : NULL,
    key_length > 0 ? key_length : 0
  );

#ifdef WITH_OSCORE
  oscore_set_contexts();
  session->oscore_encryption = oscore_secure; 
  oscore_ctx_t *osc_ctx = oscore_init();
/* osc_ctx  points to default oscore context  */
/* introduce oscore_group parameters */
  oscore_add_group_keys(osc_ctx,
        public_key_C0, private_key_C0,  
        public_key_C1, NULL);
  /* receiver public key added */
  size_t cs_params_len = 0;
  uint8_t *cs_params = GM_cs_params(COSE_Elliptic_Curve_Ed25519, COSE_KTY_OKP, &cs_params_len);
  oscore_add_group_algorithm(osc_ctx,  
        COSE_Algorithm_EdDSA, 
        cs_params, cs_params_len);
  coap_free(cs_params);
  if (oscore_secure == 1){
    ctx->osc_ctx = osc_ctx;
    osc_ctx->sender_context->seq = oscore_sequence;
  }
  else ctx->osc_ctx = NULL;
#endif /* WITH_OSCORE */

  if ( !session ) {
    coap_log( LOG_EMERG, "cannot create client session\n" );
    goto finish;
  }

  /* add Uri-Host if server address differs from uri.host */

  switch (dst.addr.sa.sa_family) {
  case AF_INET:
    addrptr = &dst.addr.sin.sin_addr;
    /* create context for IPv4 */
    break;
  case AF_INET6:
    addrptr = &dst.addr.sin6.sin6_addr;
    break;
  default:
    ;
  }

  coap_register_option(ctx, COAP_OPTION_BLOCK2);
  coap_register_response_handler(ctx, message_handler);
  coap_register_event_handler(ctx, event_handler);
  coap_register_nack_handler(ctx, nack_handler);

  /* construct CoAP message */

  if (!proxy.length && addrptr
      && (inet_ntop(dst.addr.sa.sa_family, addrptr, addr, sizeof(addr)) != 0)
      && (strlen(addr) != uri.host.length
      || memcmp(addr, uri.host.s, uri.host.length) != 0)
      && create_uri_opts) {
        /* add Uri-Host */

        coap_insert_optlist(&optlist,
                    coap_new_optlist(COAP_OPTION_URI_HOST,
                    uri.host.length,
                    uri.host.s));
  }

  /* set block option if requested at commandline */
  if (flags & FLAGS_BLOCK)
    set_blocksize();
/* Two requests are sent
 * first with GM_choice = x, with 4 <= x <= 7 or x == 100
 * without oscore encryption
 * second if (x != 0) with GM_choice = x - 4
 * with oscore encryption
 */

while (GM_choice >= 0){
  uint8_t ok = 0;
  if (GM_choice < 4){
/* encryption is used  */
    session->oscore_encryption = 1; 
/* sequence must be set for oscore  */
    LAST_ctx->sender_context->seq = 3*GM_choice;
    ctx->osc_ctx = LAST_ctx;
  }
   
/*  create requests to Group Manager (GM)  */
  switch (GM_choice){
    case 0:
/* manage request   */
      enable_output = MANAGE_RETURN;
      ok = GM_fill_group_request(&payload);
      break;
    case 1:
    case 2:
    case 3:
      enable_output = JOIN_RETURN;
      ok = GM_fill_member_request(&payload);
      break;
    case 4:
    case 5:
    case 6:
    case 7:
      enable_output = AUTHZ_INFO_RETURN;
      oscore_secure = 0;
      ok = GM_fill_token_request(&payload);
    default:
      break;
  } /* switch  */
 
  if(ok != 0){
    coap_log( LOG_EMERG, "cannot create client session\n" );
    goto finish;
  }

  if (! (pdu = coap_new_request(ctx, session, method, &optlist, payload.s, payload.length))) {
    goto finish;
  }

  coap_log(LOG_DEBUG, "sending CoAP request:\n");
  if (coap_get_log_level() < LOG_DEBUG)
    coap_show_pdu(LOG_INFO, pdu);

  coap_send(session, pdu);

  wait_ms = wait_seconds * 1000;
  coap_log(LOG_DEBUG, "timeout is set to %u seconds\n", wait_seconds);

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

  while (!quit && !(ready && !doing_getting_block && coap_can_exit(ctx)) ) {

    result = coap_io_process( ctx, wait_ms == 0 ?
                                 obs_ms : obs_ms == 0 ?
                                 min(wait_ms, 1000) : min( wait_ms, obs_ms ) );

    if ( result >= 0 ) {
      if ( wait_ms > 0 && !wait_ms_reset ) {
        if ( (unsigned)result >= wait_ms ) {
          coap_log(LOG_INFO, "timeout\n");
          break;
        } else {
          wait_ms -= result;
        }
      }
      if ( obs_ms > 0 && !obs_ms_reset ) {
        if ( (unsigned)result >= obs_ms ) {
          coap_log(LOG_DEBUG, "clear observation relationship\n" );
          clear_obs( ctx, session ); /* FIXME: handle error case COAP_TID_INVALID */

          /* make sure that the obs timer does not fire again */
          obs_ms = 0;
          obs_seconds = 0;
        } else {
          obs_ms -= result;
        }
      }
      wait_ms_reset = 0;
      obs_ms_reset = 0;
    }
  }
if (GM_choice == 100) GM_choice = 0; /* no GM request  */
  GM_choice = GM_choice - 4;
/* verify if context has been created in call to authz-info  */
  if (LAST_ctx == NULL) GM_choice = -1;
  if (GM_choice >= 0){
    coap_delete_optlist(optlist);
    optlist = NULL;
    if (GM_choice == 0)insert_manage_optlist();
    else insert_join_optlist();
  }
} /* end while over GM_choice  */

  result = 0;

 finish:

  for (i = 0; i < valid_ihs.count; i++) {
    free(valid_ihs.ih_list[i].hint_match);
    coap_delete_bin_const(valid_ihs.ih_list[i].new_identity);
    coap_delete_bin_const(valid_ihs.ih_list[i].new_key);
  }
  if (valid_ihs.count)
    free(valid_ihs.ih_list);
  coap_delete_optlist(optlist);
  coap_session_release( session );
  coap_free_context( ctx );
  coap_cleanup();
  close_output();

  return result;
}
