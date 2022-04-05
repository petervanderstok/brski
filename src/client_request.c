/* Client_request -- implementation of starting a client request
 * a simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 * Client_request is added by:
 * Peter van der Stok <consultancy@vanderstok.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 * This file does not set up raw keys, only certificates  
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
#include "resource.h"
#include "oscore.h"
#include "oscore-context.h"
#include "cbor.h"
#include "cose.h"
#include "coap_internal.h"
#include "Registrar_server.h"
#include "brski.h"
#include "utlist.h"
#include "client_request.h"
#include <coap.h>

/* global coap_start variables */
#define MAX_USER 128 /* Maximum length of a user name (i.e., PSK
                      * identity) in bytes. */
#define MAX_KEY   64 /* Maximum length of a key (i.e., PSK) in bytes. */
#define MAX_TOKEN  8 /* Maximum size of a token  */

#define FLAGS_BLOCK 0x01

static int      quit = 0;          /* leave program  */
static uint16_t last_code = 0;     /* last recived pdu->code */
static unsigned int ping_seconds = 0;

/* coap request is done when ready flag is set and all blocks are treated */
static int8_t   ready = 0;         /* response arrived */
static int doing_getting_block = 0;/* processing a block response when this flag is set */

int8_t is_ready(void){
	/* message received and no more blocks expected  */
	return ready && !doing_getting_block;
}

void make_ready(void){
  ready = 1;
}

void reset_ready(void){
	ready = 0;
}


/* parameters for setting up pki */

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


client_request_t *CLIENT_REQUEST = NULL;

client_request_t *
client_request_init(void){
	client_request_t *temp = coap_malloc(sizeof(client_request_t));
	memset(temp, 0, sizeof(client_request_t));
	temp->next = CLIENT_REQUEST;
	CLIENT_REQUEST = temp;
	CLIENT_REQUEST->ctx = NULL;
	CLIENT_REQUEST->verify_cn_callback = NULL; 
	CLIENT_REQUEST->use_pem_buf = CERTIFICATES_ON_FILE;
 	CLIENT_REQUEST->cert_file = NULL; /* Combined certificate and private key in PEM */
	CLIENT_REQUEST->ca_file = NULL;   /* CA for cert_file - for cert checking in PEM */
	CLIENT_REQUEST->root_ca_file = NULL; /* List of trusted Root CAs in PEM */
	CLIENT_REQUEST->cert_mem = NULL; /* certificate and private key in PEM_BUF */
	CLIENT_REQUEST->ca_mem = NULL;   /* CA for cert checking in PEM_BUF */
	CLIENT_REQUEST->cert_mem_len = 0;
	CLIENT_REQUEST->ca_mem_len = 0;
	CLIENT_REQUEST->create_uri_opts = 1;
	CLIENT_REQUEST->method = COAP_REQUEST_GET;        /* the method we are using in our requests, ussually GET */
	CLIENT_REQUEST->msgtype = COAP_MESSAGE_CON; /* usually, requests are sent confirmable */
 	CLIENT_REQUEST->block_size = 6;
	CLIENT_REQUEST->MC_wait_loops = 0;
	CLIENT_REQUEST->flags = 0;
	CLIENT_REQUEST->reliable  = 0;
	CLIENT_REQUEST->optlist = NULL;
    unsigned char *token_data = coap_malloc(MAX_TOKEN);
	CLIENT_REQUEST->the_token.s = token_data;
	CLIENT_REQUEST->the_token.length = 0;
	CLIENT_REQUEST->proxy.length = 0;
	CLIENT_REQUEST->proxy.s = NULL;
	CLIENT_REQUEST->payload.length = 0;
	CLIENT_REQUEST->payload.s = NULL;       /* optional payload to send */
	CLIENT_REQUEST->session    = NULL;
	return CLIENT_REQUEST;
}

static client_request_t *
client_context(coap_context_t *ctx){
	client_request_t *temp = CLIENT_REQUEST;
	while (temp != NULL){
		if (temp->ctx == ctx) return temp;
		temp = temp->next;
	}
	return NULL;
}

static coap_string_t output_file = { 0, NULL };   /* output file name */
static FILE *file = NULL;               /* output file stream */


#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

#define BOOT_KEY    1
#define BOOT_NAME   2


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


typedef struct MC_return_t {
	void * next;
	coap_string_t *address;
	uint16_t      port;
} MC_return_t;

/* coap_start variables made global */

static coap_address_t dst;
static char addr[INET6_ADDRSTRLEN];
static void *addrptr = NULL;
static coap_pdu_t  *pdu;
static char port_str[NI_MAXSERV] = "0";
static char node_str[NI_MAXHOST] = "";

static coap_block_t block = { .num = 0, .m = 0, .szx = 6 };
static uint16_t last_block1_tid = 0;

/* variables used by message handler  */
static unsigned int wait_seconds = 90;                /* default timeout in seconds */
static unsigned int wait_ms = 0;
static int wait_ms_reset = 0;
static int obs_started = 0;
static unsigned int obs_seconds = 30;          /* default observe time */
static unsigned int obs_ms = 0;                /* timeout for current subscription */
static int obs_ms_reset = 0;

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

/* ports and IP address of this server for /.well-known/core discovery */
static coap_string_t IP_coap_Port  = {.length = 0, .s = NULL};
static coap_string_t IP_coaps_Port = {.length = 0, .s = NULL};
static coap_string_t IP_brski_Port = {.length = 0, .s = NULL};

/* discovery variable indicates whether discovery  responses are expected  * 
 * discovery = 0;  discovery is thrown away
 * discovery = 1; discovery handler is active
 */
 
static uint8_t     discovery = 0;             /* no discovery ongoing  */
static uint16_t    discovery_tid  = 0;        /* transactio ident of discovery request */
static MC_return_t *DISCOVER = NULL;

coap_string_t *getURI( uint8_t port_type){
   switch (port_type){
      case JP_STANDARD_PORT:
	    return &IP_coap_Port;
	    break;
	  case JP_DTLS_PORT:
	    return &IP_coaps_Port;
	    break;
	  case JP_BRSKI_PORT:
		return &IP_brski_Port;
		break;
	  default:
	    return NULL;
		break;	
	}  /* switch */	
}

static void
remove_URIs( void ){
	coap_string_t *temp = getURI(JP_STANDARD_PORT);
	if (temp->s != NULL)coap_free(temp->s);
	temp->s = NULL;
	temp = getURI(JP_DTLS_PORT);	
	if (temp->s != NULL)coap_free(temp->s);
	temp->s = NULL;
	temp = getURI(JP_BRSKI_PORT);
	if (temp->s != NULL)coap_free(temp->s);
	temp->s = NULL;	
}

void
init_URIs(coap_address_t *addr, uint8_t proto, uint8_t port_type){
/* initialize address and port for wel_known/core */
/* type is COAP_PROTO_DTLS and COAP_PROTO_UDP */

/* Determine port  */
  uint16_t port = 0;
  if (addr->addr.sa.sa_family == AF_INET) {
        port = ntohs(addr->addr.sin.sin_port);
  } else if (addr->addr.sa.sa_family == AF_INET6) {
        port = ntohs(addr->addr.sin6.sin6_port);
  }
  char coap[] = "coap://[";
  char coaps[] = "coaps://[";
  coap_string_t *dest = NULL;
  size_t pre_len = 0;
  
  struct ifaddrs *ifaddr, *ifa;
  int family, ret;
  if (getifaddrs(&ifaddr) != -1) {
	 char host[NI_MAXHOST];
     ifa = ifaddr;
     while (ifa){
		 if (ifa->ifa_addr){
			family = ifa->ifa_addr->sa_family;
			ret = getnameinfo(ifa->ifa_addr,
                 (family == AF_INET) ? sizeof(struct sockaddr_in) :
                                      sizeof(struct sockaddr_in6),
                     host, NI_MAXHOST,
                     NULL, 0, NI_NUMERICHOST);
            if (ret == 0 && strlen(host) > 3){
			  uint8_t host_len = 0;
			  for (uint8_t k = 0; k < strlen(host); k++) {
				  char ch = host[k];
				  if (ch == '%') host_len = k;
			  }
			  if (host_len == 0)host_len = strlen(host);
			  char *prefix = NULL;
			  if ((family == AF_INET6)){
				switch (proto){
				  case COAP_PROTO_UDP:
				    prefix = coap;
				    pre_len = strlen(coap);
				    break;
				  case COAP_PROTO_DTLS:
				    prefix = coaps;
				    pre_len = strlen(coaps);	
				    break;
				  default:
				    return;
				    break;	
				}  /* switch */	
			   switch (port_type){
				  case JP_STANDARD_PORT:
				    dest = &IP_coap_Port;
				    break;
				  case JP_DTLS_PORT:
				    dest = &IP_coaps_Port;
				    break;
				  case JP_BRSKI_PORT:
				    dest = 	&IP_brski_Port;
				    break;
				  default:
				    return;
				    break;	
				}  /* switch */		    				    				
				uint8_t port_len = pre_len + 2 + host_len + 5;
				char wlan0[] = "wlan0";
				char wifi0[] = "wifi0";
				char lln[] = "fe80";
				if (strncmp(lln, host, 4) == 0){
				  if ((strcmp(wlan0, ifa->ifa_name)  == 0) || (strcmp(wifi0, ifa->ifa_name) == 0))
				  {
				  dest->s = coap_malloc(port_len);
				  dest->length = port_len;
				  memcpy(dest->s, prefix, pre_len);
				  memcpy(dest->s + pre_len, host, host_len);
				  dest->s[pre_len + host_len]     = ']';
				  dest->s[pre_len + host_len + 1] = ':';
				  int temp = port;
				    for (uint qq = 0 ; qq < 4; qq++){  /* write port number  */
					  uint8_t cipher = temp - 10*(temp/10);
					  dest->s[port_len -2 - qq] = cipher + '0';
					  temp = temp/10;
				    } /* for*/
				  dest->s[port_len-1] = 0;
			      } /* strcmp ifa_name */
			    }  /* strcmp lln */
		      }  /* lan_att */
	        }  /* s==0 */
		  } /* ifa->if_addr */
          ifa = ifa->ifa_next;
	 } /* while */        
  } /* getifaddrs  */
  freeifaddrs( ifaddr);	
}

/* store_discovery_payload
 * stores payload returned by discovery 
 */
static int16_t
store_discovery_payload(coap_session_t *session, unsigned char *data, size_t len, uint16_t code) 
{	
   last_code = code;
   uint8_t found = 0;  /* indicates presence of [  ] around address */
   static unsigned char alternative[INET6_ADDRSTRLEN +32];
   uint8_t *p = data;
   uint8_t *end = p + len;
   while ((*p != '[') && (p < end)){
	   p++;
   }
   if (p == end){ /* host and port can be taken from session  */
	   found = 1;
	   p = alternative;
	   if (coap_print_addr(&session->addr_info.remote, p, INET6_ADDRSTRLEN +32)){
		   /* test on presence of '['  */
		   end = p + INET6_ADDRSTRLEN +32;
		   uint8_t * t= p;
		   while ((t < end) && (*t != '['))t++;
		   if (t != end){
			    p = t;
			    found = 0;
		   }
	   }
   }
   if (found == 0)p++;   /* position after [ */
   uint8_t *pe = p;
   if (found == 0){
      while  ((*pe != ']') && (pe < end))pe++;
      if (pe == end) return -1;
   }else {
	  while  ((*pe != ':') && (pe < end))pe++; 
   }
   MC_return_t *temp = coap_malloc(sizeof (MC_return_t));
   memset(temp, 0, sizeof(MC_return_t));
   temp->next = DISCOVER;
   DISCOVER = temp;
   uint16_t port = COAP_DEFAULT_PORT;
   coap_string_t *host = coap_malloc(sizeof(coap_string_t));
   host->s = coap_malloc(pe -p);
   host->length = pe-p;
   memcpy(host->s, p, pe-p);
   host->s[pe-p] = 0;
   temp->address = host;
   temp->port = port;
   while (*pe != ':' && pe < end)pe++;
   if (pe == end)return 0;  /* no port, default port is stored */
   p = pe + 1;   /* p ponts to port after ':' */
   port = 0;
   while ((*p < '9'+1) && *p > '0'-1 && p <end){
	   port = port*10 + *p-'0';
	   p++;
   }
   temp->port = port;
   return 0;
}


static int16_t
append_to_output(unsigned char *data, size_t len, uint16_t code, uint16_t block_num, uint16_t more) {
  size_t written = 0;
  last_code = code;
  if ((data == NULL) || (len = 0))return 0;
  if (!file) {
    if (!output_file.s || (output_file.length && output_file.s[0] == '-'))
      file = stdout;
    else {
	  if (block_num == 0){
        if (!(file = fopen((char *)output_file.s, "w"))) {
           perror("fopen");
           return -1;
	    } 
	  } else {
		if (!(file = fopen((char *)output_file.s, "a"))) {
           perror("fopen");
           return -1;
		}
      }  /* block_num */
    }
  }

  do {
    written = fwrite(data, 1, len, file);
    len -= written;
    data += written;
  } while ( written && len );
  const char *cr = "\n";
  written = fwrite(cr, 1, 1, file);
  fflush(file);

  return 0;
}

static coap_resp_handler_t cur_resp_handler = append_to_output;

       
static void reset_discovery(void){
	MC_return_t *temp = DISCOVER;
	while (temp != NULL){
		MC_return_t *next = temp->next;
		coap_free(temp->address->s);
		coap_free(temp->address);
		temp = next;
	}
	DISCOVER = NULL;
}
    
void set_discovery_wanted(void){
	/* remove old discovery entries */
	reset_discovery();
	discovery = 1;   /* discovery is ongoing  */
}


coap_string_t *get_discovered_host_port(uint16_t *port){
	MC_return_t *temp = DISCOVER;
	*port = 0;
	if (temp == NULL) return NULL;
	coap_string_t *host = temp->address;
	*port = temp->port;
	DISCOVER = temp->next;
	coap_free(temp);
	if (host != NULL) discovery = 0;
	/* discovery message may still arrive, but application is not informed */
	return host;
}


#define HANDLE_BLOCK1(Pdu)                                        \
  ((client->method == COAP_REQUEST_PUT || method == COAP_REQUEST_POST) && \
   ((client->flags & FLAGS_BLOCK) == 0) &&                                \
   ((Pdu)->hdr->code == COAP_RESPONSE_CODE(201) ||                \
    (Pdu)->hdr->code == COAP_RESPONSE_CODE(204)))

static inline int
check_token(client_request_t *client, coap_pdu_t *received) {
  return received->token_length == client->the_token.length &&
  memcmp(received->token, client->the_token.s, client->the_token.length) == 0;
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

coap_pdu_t *
coap_new_request(client_request_t *client,
                 coap_session_t *session,
                 uint8_t m,
                 coap_optlist_t **options,
                 unsigned char *data,
                 size_t length) {
  coap_context_t *ctx = client->ctx;			 
  coap_pdu_t *pdu;
  (void)ctx;

  if (!(pdu = coap_new_pdu(session)))
    return NULL;

  pdu->type = client->msgtype;
  pdu->tid = coap_new_message_id(session);
  pdu->code = m;

  if ( !coap_add_token(pdu, client->the_token.length, client->the_token.s)) {
    coap_log(LOG_DEBUG, "cannot add token to request\n");
  }

  if (options)
    coap_add_optlist_pdu(pdu, options);

  if (length) {
    if ((client->flags & FLAGS_BLOCK) == 0)
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
  client_request_t *client = client_context(ctx);
  if (client == NULL) {
	  coap_log(LOG_ERR,"unknown client context in mesage_handler\n");
	  return;
  }
  coap_log(LOG_DEBUG, "** process incoming %d.%02d response:\n",
           (received->code >> 5), received->code & 0x1F);
  if (coap_get_log_level() < LOG_DEBUG)
    coap_show_pdu(LOG_INFO, received);
  /* check if this is a response to our original request */
  if (!check_token(client, received)) {
    /* drop if this was just some message, or send RST in case of notification */
    if (!sent && (received->type == COAP_MESSAGE_CON ||
                  received->type == COAP_MESSAGE_NON))
      coap_send_rst(session, received);
    return;
  }
  
/* check if this was a discovery response  */
  if ((received->tid == discovery_tid) ){
	  if ((received->code >> 5) == 2){
        if (coap_get_data(received, &len, &databuf)){  
	       store_discovery_payload(session, databuf, len, received->code);
	    }
        if (discovery == 0)reset_ready();
        else make_ready();
      }
      else if ((received->code >> 5) == 4){
		    reset_ready();
		    return;
	  }
  }  /* if discovery tid  */

  if (received->type == COAP_MESSAGE_RST) {
    coap_log(LOG_INFO, "got RST \n");
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
        cur_resp_handler(databuf, len, received->code, 
                  coap_opt_block_num(block_opt), COAP_OPT_BLOCK_MORE(block_opt));
      } /* coap_get_data  */
      if (coap_opt_block_num(block_opt) == 0) {
        /* See if observe is set in first response */
        int tmp = coap_check_option(received,
                                  COAP_OPTION_OBSERVE, &opt_iter) == NULL;                      
        if (tmp == 0)reset_ready();
        else make_ready();
      }
      if(COAP_OPT_BLOCK_MORE(block_opt)) {
        /* more bit is set */
        coap_log(LOG_DEBUG, "found the M bit, block size is %u, block nr. %u\n",
              COAP_OPT_BLOCK_SZX(block_opt),
              coap_opt_block_num(block_opt));

        /* create pdu with request for next block */
        pdu = coap_new_request(client, session, client->method, NULL, NULL, 0); /* first, create bare PDU w/o any option  */
        if ( pdu ) {
          /* add URI components from optlist */
          for (option = client->optlist; option; option = option->next ) {
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
      }  /* (COAP_OPT_BLOCK_MORE(block_opt)) */
      /* M bit is not set, last block */
      doing_getting_block = 0;
      if (session->con_active)session->con_active--;
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

        if (client->payload.length <= (block.num+1) * (1 << (block.szx + 4))) {
          coap_log(LOG_DEBUG, "upload ready\n");
          if (coap_get_data(received, &len, &databuf)){
              cur_resp_handler(databuf, len, received->code, block.num, COAP_OPT_BLOCK_MORE(block_opt));
		  } else cur_resp_handler( NULL, 0, received->code, block.num, COAP_OPT_BLOCK_MORE(block_opt));
          make_ready();
          return;
        }

       /* create pdu with request for next block */
        pdu = coap_new_request(client, session, client->method, NULL, NULL, 0); /* first, create bare PDU w/o any option  */
        if (pdu) {

          /* add URI components from optlist */
          for (option = client->optlist; option; option = option->next ) {
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
          block.m = ((block.num+1) * (1 << (block.szx + 4)) < client->payload.length);

          coap_log(LOG_DEBUG, "send block %d\n", block.num);
          coap_add_option(pdu,
                          COAP_OPTION_BLOCK1,
                          coap_encode_var_safe(buf, sizeof(buf),
                          (block.num << 4) | (block.m << 3) | block.szx), buf);

          coap_add_option(pdu,
                          COAP_OPTION_SIZE1,
                          coap_encode_var_safe8(buf, sizeof(buf), client->payload.length),
                          buf);

          coap_add_block(pdu,
                         client->payload.length,
                         client->payload.s,
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
		if (received->type == COAP_MESSAGE_CON){
           if (session->con_active)session->con_active--;
		}
        /* There is no block option set, just read the data and we are done. */
        if (coap_get_data(received, &len, &databuf)){
          cur_resp_handler( databuf, len, received->code, 0, 0);
        } else cur_resp_handler( NULL, 0, received->code, 0, 0);
      }
    }
  } else {      /* no 2.05 */

    /* check if an error was signaled and output payload if so */
      if (COAP_RESPONSE_CLASS(received->code) >= 4) {
	     len = 0;
	     if (coap_get_data(received, &len, &databuf)){
		   if (len > 0){
		        databuf[len] = 0;
                coap_log(LOG_WARNING, "%d.%02d:  %s", (received->code >> 5), received->code & 0x1F, databuf);
           } else 
                coap_log(LOG_WARNING, "%d.%02d: ", (received->code >> 5), received->code & 0x1F);
	     }
         cur_resp_handler(databuf, len, received->code, 0, 0);
      }
  }

  /* any pdu that has been created in this function must be sent by now */
  assert(pdu == NULL);

  /* our job is done, we can exit at any time */
  int tmp = (coap_check_option(received, COAP_OPTION_OBSERVE, &opt_iter) == NULL);
  if (tmp == 0)reset_ready();
  else make_ready();
  /* check on empty ack  */
  if ((received->code == 0) && (received->type == COAP_MESSAGE_ACK)){
	   reset_ready();
   }
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

static uint16_t
get_default_port(const coap_uri_t *u) {
  return coap_uri_scheme_is_secure(u) ? COAPS_DEFAULT_PORT : COAP_DEFAULT_PORT;
}

void 
create_uri_options(client_request_t *client, uint16_t ct){
  unsigned char portbuf[2];
#define BUFSIZE 100
  unsigned char _buf[BUFSIZE];
  unsigned char *buf = _buf;
  size_t buflen;
  int res;
      if (client->uri.port != get_default_port((const void *)&client->uri) && client->create_uri_opts) {
      coap_insert_optlist(&client->optlist,
                  coap_new_optlist(COAP_OPTION_URI_PORT,
                                   coap_encode_var_safe(portbuf, sizeof(portbuf),
                                                        (client->uri.port & 0xffff)),
                  portbuf));
    }

    if (client->uri.path.length) {
      buflen = BUFSIZE;
      if (client->uri.path.length > BUFSIZE)
        coap_log(LOG_WARNING, "URI path will be truncated (max buffer %d)\n", BUFSIZE);
      res = coap_split_path(client->uri.path.s, client->uri.path.length, buf, &buflen);

      while (res--) {
        coap_insert_optlist(&client->optlist,
                    coap_new_optlist(COAP_OPTION_URI_PATH,
                    coap_opt_length(buf),
                    coap_opt_value(buf)));

        buf += coap_opt_size(buf);
      }
    }

    if (client->uri.query.length) {
      buflen = BUFSIZE;
      buf = _buf;
      res = coap_split_query(client->uri.query.s, client->uri.query.length, buf, &buflen);

      while (res--) {
        coap_insert_optlist(&client->optlist,
                    coap_new_optlist(COAP_OPTION_URI_QUERY,
                    coap_opt_length(buf),
                    coap_opt_value(buf)));

        buf += coap_opt_size(buf);
      }
    }
    if (ct != 0){
		buf [0] = ct >> 8;
		buf [1] = ct &0xff;
		coap_insert_optlist(&client->optlist,
                    coap_new_optlist(COAP_OPTION_CONTENT_TYPE,
                    2,
                    buf));
	}
}


static coap_dtls_key_t *
verify_pki_sni_callback(const char *sni, void *arg) 
{
  /* Preset with the defined keys */
  client_request_t *client =   (client_request_t *)arg;
  coap_dtls_key_t *dtls_key = &client->dtls_key;
  memset(dtls_key, 0, sizeof(coap_dtls_key_t));
  if (client->use_pem_buf == CERTIFICATES_ON_FILE) {
    dtls_key->key_type = COAP_PKI_KEY_PEM;
    dtls_key->key.pem.public_cert = client->cert_file;
    dtls_key->key.pem.private_key = client->cert_file;
    dtls_key->key.pem.ca_file =     client->ca_file;
  }
  else {
    dtls_key->key_type = COAP_PKI_KEY_PEM_BUF;
    dtls_key->key.pem_buf.ca_cert =         client->ca_mem;
    dtls_key->key.pem_buf.public_cert =     client->cert_mem;
    dtls_key->key.pem_buf.private_key =     client->cert_mem;
    dtls_key->key.pem_buf.ca_cert_len =     client->ca_mem_len;
    dtls_key->key.pem_buf.public_cert_len = client->cert_mem_len;
    dtls_key->key.pem_buf.private_key_len = client->cert_mem_len;
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
        dtls_key->key_type = COAP_PKI_KEY_PEM;
        dtls_key->key.pem.public_cert = valid_pki_snis.pki_sni_list[i].new_cert;
        dtls_key->key.pem.private_key = valid_pki_snis.pki_sni_list[i].new_cert;
        dtls_key->key.pem.ca_file = valid_pki_snis.pki_sni_list[i].new_ca;
        break;
      }
    }
  }
  else {
    coap_log(LOG_DEBUG, "SNI not requested\n");
  }
  return dtls_key;
}

static coap_dtls_pki_t *
setup_pki(client_request_t *client) {
  /* If general root CAs are defined */
  if (client->root_ca_file) {
    struct stat stbuf;
    if ((stat(client->root_ca_file, &stbuf) == 0) && S_ISDIR(stbuf.st_mode)) {
      coap_context_set_pki_root_cas(client->ctx, NULL, client->root_ca_file);
    } else {
      coap_context_set_pki_root_cas(client->ctx, client->root_ca_file, NULL);
    }
  }

  memset(client->client_sni, 0, sizeof(client->client_sni));
  memset (&client->dtls_pki, 0, sizeof(client->dtls_pki));
  client->dtls_pki.version = COAP_DTLS_PKI_SETUP_VERSION;
  if (client->ca_file || client->root_ca_file) {
    /*
     * Add in additional certificate checking.
     * This list of enabled can be tuned for the specific
     * requirements - see 'man coap_encryption'.
     *
     * Note: root_ca_file is setup separately using
     * coap_context_set_pki_root_cas(), but this is used to define what
     * checking actually takes place.
     */
    client->dtls_pki.verify_peer_cert        = 1;
    client->dtls_pki.require_peer_cert       = 0;  /* (=0) do not require peer checking */
    client->dtls_pki.allow_self_signed       = 1;
    client->dtls_pki.allow_expired_certs     = 1;
    client->dtls_pki.cert_chain_validation   = 1;
    client->dtls_pki.cert_chain_verify_depth = 2;
    client->dtls_pki.check_cert_revocation   = 1;
    client->dtls_pki.allow_no_crl            = 1;
    client->dtls_pki.allow_expired_crl       = 1;
    client->dtls_pki.validate_cn_call_back   = client->verify_cn_callback;
    client->dtls_pki.cn_call_back_arg        = NULL;
    client->dtls_pki.validate_sni_call_back  = verify_pki_sni_callback;
    client->dtls_pki.sni_call_back_arg       = (void *)client;
  }
  if (client->uri.host.length)
    memcpy(client->client_sni, client->uri.host.s, min(client->uri.host.length, sizeof(client->client_sni)-1));
  else
    memcpy(client->client_sni, "localhost", 9);
  client->dtls_pki.client_sni = client->client_sni;
  client->dtls_pki.pki_key.key_type = COAP_PKI_KEY_PEM;
  client->use_pem_buf = CERTIFICATES_ON_FILE;
  client->dtls_pki.pki_key.key.pem.public_cert = client->cert_file;
  client->dtls_pki.pki_key.key.pem.private_key = client->cert_file;
  client->dtls_pki.pki_key.key.pem.ca_file =     client->ca_file;
  return &client->dtls_pki;
}

static coap_dtls_cpsk_t *
setup_cpsk(
  client_request_t *client,
  const uint8_t *identity,
  size_t identity_len,
  const uint8_t *key,
  size_t key_len
) {
 // static coap_dtls_cpsk_t dtls_psk;
//  static char client_sni[256];

  memset(client->client_sni, 0, sizeof(client->client_sni));
  memset (&client->dtls_psk, 0, sizeof(client->dtls_psk));
  client->dtls_psk.version = COAP_DTLS_CPSK_SETUP_VERSION;
  client->dtls_psk.validate_ih_call_back = verify_ih_callback;
  client->dtls_psk.ih_call_back_arg = &client->dtls_psk.psk_info;
  if (client->uri.host.length)
    memcpy(client->client_sni, client->uri.host.s,
           min(client->uri.host.length, sizeof(client->client_sni) - 1));
  else
    memcpy(client->client_sni, "localhost", 9);
  client->dtls_psk.client_sni = client->client_sni;
  client->dtls_psk.psk_info.identity.s = identity;
  client->dtls_psk.psk_info.identity.length = identity_len;
  client->dtls_psk.psk_info.key.s = key;
  client->dtls_psk.psk_info.key.length = key_len;
  return &client->dtls_psk;
}

/* fill keystore
 * defines certificate- and key file 
 * no raw keys used */

void
fill_keystore(client_request_t *client) {
  if (client->cert_file == NULL) {
    if (coap_dtls_is_supported() || coap_tls_is_supported()) {
      coap_log(LOG_DEBUG,
               "(D)TLS not enabled as neither -k or -c options specified\n");
    }
  }
  coap_dtls_pki_t *dtls_pki = setup_pki( client);
  coap_context_set_pki(client->ctx, dtls_pki); 
}

#ifdef _WIN32
#define S_ISDIR(x) (((x) & S_IFMT) == S_IFDIR)
#endif


static coap_session_t*
open_session(
  client_request_t *client,
  coap_proto_t proto,
  coap_address_t *bind_addr,
  coap_address_t *dst,
  const uint8_t *identity,
  size_t identity_len,
  const uint8_t *key,
  size_t key_len
) {
  coap_context_t *ctx = client->ctx;
  coap_session_t *session;
  if (proto == COAP_PROTO_DTLS || proto == COAP_PROTO_TLS) {
    /* Encrypted session */
    if (client->root_ca_file || client->ca_file || client->cert_file) {
      /* Setup PKI session */
      coap_dtls_pki_t *dtls_pki = setup_pki( client);
      session = coap_new_client_session_pki(ctx, bind_addr, dst, proto, dtls_pki);
    }
    else if (identity || key) {
      /* Setup PSK session */
      coap_dtls_cpsk_t *dtls_psk = setup_cpsk(client, identity, identity_len,
                                               key, key_len);
      session = coap_new_client_session_psk2(ctx, bind_addr, dst, proto,
                                           dtls_psk);
    }
    else {
      /* No PKI or PSK defined, as encrypted, use PKI */
      coap_dtls_pki_t *dtls_pki = setup_pki( client);  
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
  client_request_t *client,
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
        session = open_session(client, proto, &bind_addr, dst,
                               identity, identity_len, key, key_len);
        if ( session )
          break;
      }
    }
    freeaddrinfo( result );
  } else {
    session = open_session(client, proto, NULL, dst,
                               identity, identity_len, key, key_len);
  }
  return session;
}

 
/* Called after processing the options from the commandline to set
 * Block1 */
void
set_blocksize(client_request_t *client) {
  static unsigned char buf[4];        /* hack: temporarily take encoded bytes */
  uint16_t opt;
  unsigned int opt_length;

  if (client->method != COAP_REQUEST_DELETE) {
    opt = COAP_OPTION_BLOCK1;
    block.m = (opt == COAP_OPTION_BLOCK1) &&
      ((1ull << (block.szx + 4)) < client->payload.length);

    opt_length = coap_encode_var_safe(buf, sizeof(buf),
          (block.num << 4 | block.m << 3 | block.szx));

    coap_insert_optlist(&client->optlist, coap_new_optlist(opt, opt_length, buf));
  }
}

void set_block(client_request_t *client, uint16_t size){
  block.szx = (coap_fls(size >> 4) - 1) & 0x07;
  client->block_size = block.szx;
  client->flags |= FLAGS_BLOCK;
}

void set_path( client_request_t *client, coap_string_t * path){
  if (client->uri.path.s != NULL) coap_free(client->uri.path.s);
  if (path == NULL){
	  client->uri.path.s = NULL;
	  client->uri.path.length = 0;
	  return;
  }
  client->uri.path.length = path->length;
  uint8_t *pt = coap_malloc(client->uri.path.length);
  memcpy(pt, path->s, client->uri.path.length);
  client->uri.path.s = pt;
}

void get_path( client_request_t *client, coap_string_t *path){
  if (path == NULL) return;
  path->length = client->uri.path.length;
  uint8_t *pt = coap_malloc(client->uri.path.length + 1);
  memcpy(pt, client->uri.path.s, client->uri.path.length);
  pt[client->uri.path.length] = 0;
  path->s = pt;
}

void set_flags(client_request_t *client, uint16_t flag){
	client->flags |= flag;  
}

void remove_flags(client_request_t *client, uint16_t flag){
	client->flags &=  ~ flag;  
}

void set_token(client_request_t *client, coap_binary_t *token){
	if (token->length > MAX_TOKEN){
		coap_log(LOG_ERR,"set-token:_Token is too large \n");
		return;
	}
	memset(client->the_token.s, 0, MAX_TOKEN);
	memcpy(client->the_token.s, token->s, token->length);
	client->the_token.length = token->length;
}

coap_string_t * get_host(client_request_t *client){
	return &client->uri.host;
}


void set_host(client_request_t *client, coap_string_t *host){
  if( client->uri.host.s != NULL) coap_free( client->uri.host.s);
  if (host == NULL){
	  client->uri.host.s = NULL;
	  client->uri.host.length = 0;
	  return;
  }
  client->uri.host.length = host->length;
  uint8_t *pt = coap_malloc(client->uri.host.length+1);
  memcpy(pt, host->s, client->uri.host.length);
  pt[client->uri.host.length] = 0;
  client->uri.host.s = pt;
}


void set_query(client_request_t *client, coap_string_t *query){
  if (client->uri.query.s != NULL) coap_free(client->uri.query.s);
  if (query == NULL){
	  client->uri.query.s = NULL;
	  client->uri.query.length = 0;
	  return;
  }
  client->uri.query.length = query->length;
  uint8_t *pt = coap_malloc(client->uri.query.length);
  memcpy(pt, query->s, client->uri.query.length);
  client->uri.query.s = pt;
}

void uri_options_on(client_request_t *client){
   client->create_uri_opts = 1;
}

void uri_options_off(client_request_t *client){
   client->create_uri_opts = 0;
}

void set_port(client_request_t *client, uint16_t port){
    if (port == 0){
	  return;
  }
  client->uri.port = port;
}

uint16_t get_port(client_request_t *client){
  return client->uri.port;
}

void set_scheme( client_request_t *client, uint8_t scheme){
	client->uri.scheme=scheme;
}

void set_method( client_request_t *client, uint8_t mth){
	client->method = mth;
}

void set_resp_handler(coap_resp_handler_t handler){
	cur_resp_handler = handler;
}


void reset_resp_handler(void){
	cur_resp_handler = append_to_output;
	discovery = 0;  /* end of discovery   */
}

void set_message_type(client_request_t *client, unsigned char type){
    client->msgtype = type;
}

void set_MC_wait_loops(client_request_t *client, uint8_t loops){
	client->MC_wait_loops = loops;
	if (!client->MC_wait_loops) client->MC_wait_loops = 1; /* minimum of one loop */
}

void set_certificates(client_request_t *client, char *cert, char *ca){
    client->cert_file    = cert;   /* Combined certificate and private key in PEM */
    client->ca_file      = ca;     /* CA for cert_file - for cert checking in PEM */
    coap_log(LOG_DEBUG," ca_certificate file is %s,\n    certificate file is %s \n", ca, cert);
}

void set_pki_callback(client_request_t *client, coap_dtls_cn_callback_t function){
      client->verify_cn_callback = function;
}

void set_payload(client_request_t *client, coap_string_t *pl){
	if (client->payload.s != NULL)coap_free(client->payload.s);
	client->payload.length = pl->length;
	client->payload.s = coap_malloc(client->payload.length);
	memcpy(client->payload.s, pl->s, client->payload.length);
}

coap_session_t *client_return_session(client_request_t *client){
	return client->session;
}

void
reset_block(client_request_t *client){
  block.num = 0;
  block.m = 0;
  block.szx = client->block_size;
}

coap_session_t *
coap_start_session(client_request_t *client){
  coap_context_t *ctx = client->ctx;
  unsigned char user[MAX_USER + 1], key[MAX_KEY];
  ssize_t user_length = -1, key_length = 0;
  reset_block(client);
  coap_string_t server;  
  server = client->uri.host;

  /* resolve destination address where server should be sent */
    int res = resolve_address((coap_str_const_t *)&server, &dst.addr.sa);

    if (res < 0) {
      coap_log(LOG_WARNING, "failed to resolve address\n");
      exit(-1);
    }


    if ( !ctx ) {
      coap_log( LOG_EMERG, "missing context\n" );
      return NULL;
    }
    coap_context_set_keepalive(ctx, ping_seconds);
    dst.size = res;
    dst.addr.sin.sin_port = htons( client->uri.port );

    client->session =  get_session(
      client,
      node_str[0] ? node_str : NULL, port_str,
      client->uri.scheme==COAP_URI_SCHEME_COAP_TCP ? COAP_PROTO_TCP :
      client->uri.scheme==COAP_URI_SCHEME_COAPS_TCP ? COAP_PROTO_TLS :
      (client->reliable ?
          client->uri.scheme==COAP_URI_SCHEME_COAPS ? COAP_PROTO_TLS : COAP_PROTO_TCP
        : client->uri.scheme==COAP_URI_SCHEME_COAPS ? COAP_PROTO_DTLS : COAP_PROTO_UDP),
      &dst,
      user_length >= 0 ? user : NULL,
      user_length >= 0 ? user_length : 0,
      key_length > 0 ? key : NULL,
      key_length > 0 ? key_length : 0
    );
    if ( !client->session ) {
       coap_log( LOG_EMERG, "cannot create client session\n" );
       return NULL;
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

  return client->session;
} 

int8_t
coap_start_request(client_request_t *client, uint16_t ct){
  /* resolve destination address where server should be sent */
  if (client->optlist != NULL){
	    coap_delete_optlist(client->optlist);
        client->optlist = NULL;
	}
	
	block.num =0;
 
  /* construct CoAP message */
  if (!client->proxy.length && addrptr
      && (inet_ntop(dst.addr.sa.sa_family, addrptr, addr, sizeof(addr)) != 0)
      && (strlen(addr) != client->uri.host.length
      || memcmp(addr, client->uri.host.s, client->uri.host.length) != 0)
      && client->create_uri_opts) {
        /* add Uri-Host */
        coap_insert_optlist(&client->optlist,
                    coap_new_optlist(COAP_OPTION_URI_HOST,
                    client->uri.host.length,
                    client->uri.host.s));
  }
  
   create_uri_options(client, ct);
  /* set block option if FLAGS_BLOCK is set */
  if (client->flags & FLAGS_BLOCK){
    set_blocksize(client);
  }
  if (! (pdu = coap_new_request(client, client->session, client->method, &client->optlist, 
                                   client->payload.s, client->payload.length))) {
    return -1;;
  }
  if (discovery) discovery_tid = pdu->tid; /* set discovery transaction ident */
  coap_log(LOG_DEBUG, "sending CoAP request:\n");
  if (coap_get_log_level() < LOG_DEBUG)
         coap_show_pdu(LOG_INFO, pdu);
  coap_send(client->session, pdu);
  return 0;
}


static void 
end_coap_client(client_request_t *client){
  size_t i;
  for (uint i = 0; i < valid_ihs.count; i++) {
    free(valid_ihs.ih_list[i].hint_match);
    coap_delete_bin_const(valid_ihs.ih_list[i].new_identity);
    coap_delete_bin_const(valid_ihs.ih_list[i].new_key);
  }
  if (valid_ihs.count) free(valid_ihs.ih_list);
    if (client->ca_mem)
    free(client->ca_mem);
  if (client->cert_mem)
    free(client->cert_mem);
  for (i = 0; i < valid_psk_snis.count; i++) {
    free(valid_psk_snis.psk_sni_list[i].sni_match);
    coap_delete_bin_const(valid_psk_snis.psk_sni_list[i].new_hint);
    coap_delete_bin_const(valid_psk_snis.psk_sni_list[i].new_key);
  }
  if (valid_psk_snis.count)
    free(valid_psk_snis.psk_sni_list);

  for (i = 0; i < valid_ids.count; i++) {
    free(valid_ids.id_list[i].hint_match);
    coap_delete_bin_const(valid_ids.id_list[i].identity_match);
    coap_delete_bin_const(valid_ids.id_list[i].new_key);
  }
  if (valid_ids.count)
    free(valid_ids.id_list);
  for (i = 0; i < valid_pki_snis.count; i++) {
    free(valid_pki_snis.pki_sni_list[i].sni_match);
    free(valid_pki_snis.pki_sni_list[i].new_cert);
    free(valid_pki_snis.pki_sni_list[i].new_ca);
  }
  if (valid_pki_snis.count)
    free(valid_pki_snis.pki_sni_list);

  coap_cleanup();
  coap_delete_optlist(client->optlist);
  client->optlist = NULL;
  if (client->session != NULL)
           coap_session_release( client->session );
  if (client->ctx != NULL){
	  coap_free_context( client->ctx );
  }
  if (client->proxy.s != NULL)coap_free(client->proxy.s);
  if (client->payload.s != NULL) coap_free(client->payload.s); 
  if (client->uri.path.s != NULL) coap_free(client->uri.path.s); 
  if (client->uri.query.s != NULL) coap_free(client->uri.query.s);
  if( client->uri.host.s != NULL){
	 uint8_t *temp = NULL;
	 memcpy(&temp, &(client->uri.host.s), sizeof(uint8_t *));
	 coap_free( temp);
  }
  coap_free(client->the_token.s);
  coap_free(client);  
  coap_cleanup();
}

void
Clean_client_request(void){  
  client_request_t *temp = CLIENT_REQUEST;	
  while (temp != NULL) {
	  CLIENT_REQUEST = temp->next;
      end_coap_client(temp);
      temp = CLIENT_REQUEST;
  }   
  remove_URIs();  
}
