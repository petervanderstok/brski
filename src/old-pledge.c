/* pledge -- implementation of 
 * the Constrained Application Protocol (CoAP) server interface
 *         as defined in RFC 7252
 * Peter van der Stok <consultancy@vanderstok.org>
 * file includes coap server.c and imports coap_server.h
 * application discovers join_proxy and enrolls via join_proxy
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
#endif
#include "oscore.h"
#include "oscore-context.h"
#include "oscore-group.h"
#include "cbor.h"
#include "cose.h"


#include "coap.h"
#include "coap_server.h"
#include "JP_server.h"
#include "brski.h"
#include "client_request.h"
#include "file_mem.h"

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

#define COAP_PING        0  /* specified 0 command */

#ifdef __GNUC__
#define UNUSED_PARAM __attribute__ ((unused))
#else /* not a GCC */
#define UNUSED_PARAM
#endif /* GCC */

#define DISCOVER_JOIN_PROXY    0
#define DISCOVER_REGISTRAR     1

static coap_string_t payload = { 0, NULL };       /* optional payload to send */
int quit;
         
/* changeable clock base (see handle_put_time()) */
time_t clock_offset;
time_t my_clock_base;

struct coap_resource_t *time_resource;
int resource_flags;

static int create_uri_opts = 1;
static int reliable = 0;

#define FLAGS_BLOCK 0x01
coap_block_t block = { .num = 0, .m = 0, .szx = 6 };
uint16_t last_block1_tid = 0;

/* temporary storage for dynamic resource representations */
int support_dynamic;           
int dynamic_count = 0;
dynamic_resource_t *dynamic_entry = NULL;

static char int_cert_file[] = PLEDGE_COMB;         /* Combined certificate and private key in PEM */
static char int_ca_file[] = PLEDGE_CA  ;           /* CA for cert_file - for cert checking in PEM */
char *cert_file = int_cert_file;                   /* Combined certificate and private key in PEM */
char *ca_file = int_ca_file;                       /* CA for cert_file - for cert checking in PEM */
char *root_ca_file = NULL;                         /* List of trusted Root CAs in PEM */

uint8_t join_proxy_supported = 1;                  /* join proxy endpoint to be defined  */
uint16_t brksi_fd = 0;

uint8_t key[MAX_KEY];
ssize_t key_length;
int key_defined;
const char *hint = "CoAP";


/* Need to refresh time once per sec */

#ifndef min
#define min(a,b) ((a) < (b) ? (a) : (b))
#endif

/* SIGINT handler: set quit to 1 for graceful termination */
void
handle_sigint(int signum UNUSED_PARAM) {
  quit = 1;
}

static uint16_t cert_code = 0;
static coap_string_t registrar_cert = {
	.length = 0,
	.s = NULL
};

static uint16_t masa_code = 0;
static coap_string_t masa_voucher = {
	.length = 0,
	.s = NULL
};

static uint16_t audit_code = 0;
static coap_string_t registrar_audit = {
	.length = 0,
	.s = NULL
};

/* stores audit returned by /brski/vs */
static int16_t
add_audit(unsigned char *data, size_t len, uint16_t code, 
                      uint16_t block_num, uint16_t more) {
  if (code >> 5 != 2){
    if (registrar_audit.s != NULL)coap_free(registrar_audit.s);
    registrar_audit.length = 0;
    registrar_audit.s = NULL;
    audit_code = code;
    return 0;
  }
  if (block_num == 0){   /* newly arrived message */
	if (registrar_audit.s != NULL)coap_free(registrar_audit.s);
    registrar_audit.length = 0;
    registrar_audit.s = NULL;
  }
  size_t offset = registrar_audit.length;
      /* Add in new block to end of current data */
  coap_string_t new_mess = {.length = registrar_audit.length, .s = registrar_audit.s};
  registrar_audit.length = offset + len;
  registrar_audit.s = coap_malloc(offset+len);
  if (offset != 0) 
     memcpy (registrar_audit.s, new_mess.s, offset);  /* copy old contents  */
  if (new_mess.s != NULL)coap_free(new_mess.s);
  memcpy(registrar_audit.s + offset, data, len);         /* add new contents  */
  audit_code = code;
  return 0;
}


/* stores masa voucher returned by /brski/rv */
static int16_t
add_voucher(unsigned char *data, size_t len, uint16_t code, 
                            uint16_t block_num, uint16_t more) {
    if (code >> 5 != 2){
    if (masa_voucher.s != NULL)coap_free(masa_voucher.s);
    masa_voucher.length = 0;
    masa_voucher.s = NULL;
    masa_code = code;
    return 0;
  }
  if (block_num == 0){   /* newly arrived message */
	if (masa_voucher.s != NULL)coap_free(masa_voucher.s);
    masa_voucher.length = 0;
    masa_voucher.s = NULL;
  }
  size_t offset = masa_voucher.length;
      /* Add in new block to end of current data */
  coap_string_t new_mess = {.length = masa_voucher.length, .s = masa_voucher.s};
  masa_voucher.length = offset + len;
  masa_voucher.s = coap_malloc(offset+len);
  if (offset != 0) 
     memcpy (masa_voucher.s, new_mess.s, offset);  /* copy old contents  */
  if (new_mess.s != NULL)coap_free(new_mess.s);
  memcpy(masa_voucher.s + offset, data, len);         /* add new contents  */ 
  masa_code = code;
  return 0;
}

/* stores registrar certificate returned by /est/crts */
static int16_t
add_certificate(unsigned char *data, size_t len, uint16_t code, 
                          uint16_t block_num, uint16_t more){
  if (code >> 5 != 2){
    if (registrar_cert.s != NULL)coap_free(registrar_cert.s);
    registrar_cert.length = 0;
    registrar_cert.s = NULL;
    cert_code = code;
    return 0;
  }
  if (block_num == 0){   /* newly arrived message */
	if (registrar_cert.s != NULL)coap_free(registrar_cert.s);
    registrar_cert.length = 0;
    registrar_cert.s = NULL;
  }
  size_t offset = registrar_cert.length;
      /* Add in new block to end of current data */
  coap_string_t new_mess = {.length = registrar_cert.length, .s = registrar_cert.s};
  registrar_cert.length = offset + len;
  registrar_cert.s = coap_malloc(offset+len);
  if (offset != 0) 
     memcpy (registrar_cert.s, new_mess.s, offset);  /* copy old contents  */
  if (new_mess.s != NULL)coap_free(new_mess.s);
  memcpy(registrar_cert.s + offset, data, len);         /* add new contents  */
  cert_code = code;
  return 0;
}

/* arrived
 * returns 0 when code < 300 and arrived->s != null
 * else returns 1
 */
static uint8_t
arrived(uint16_t code, coap_string_t *arrived){
	if ((code >> 5 == 2) && arrived->s != NULL)return 0;
	if (arrived->s != NULL)coap_log(LOG_ERR," Returned error %d.%d: %s \n",code>>5, code & 0x1f, arrived->s);
	else coap_log(LOG_ERR," Returned error %d%d \n",code>>5, code & 0x1f); 
	return 1;
}

/*
 * Return error and error message
 */
void
oscore_error_return(uint8_t error, coap_pdu_t *response,
                                       const char *message){
   unsigned char opt_buf[5];
  coap_log(LOG_WARNING,"%s",message);
  response->code = error;
  response->data = NULL;
  response->used_size = response->token_length;
  coap_add_option(response,
                COAP_OPTION_CONTENT_FORMAT,
                coap_encode_var_safe(opt_buf, sizeof(opt_buf),
                COAP_MEDIATYPE_TEXT_PLAIN), opt_buf);
  coap_add_data(response, strlen(message), 
                                  (const uint8_t *)message);
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
       oscore_error_return(COAP_RESPONSE_CODE(400), 
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


static void
hnd_get_index(coap_context_t *ctx UNUSED_PARAM,
              struct coap_resource_t *resource,
              coap_session_t *session,
              coap_pdu_t *request,
              coap_binary_t *token,
              coap_string_t *query UNUSED_PARAM,
              coap_pdu_t *response) {

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

  /* type = request->hdr->type == COAP_MESSAGE_CON  */
  /*   ? COAP_MESSAGE_ACK : COAP_MESSAGE_NON; */
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

  return;
}

/* verify_discovery
 * returns 1 when no discovery address available
 * returns 0 when host contains discovered address
 */
static int8_t verify_discovery(coap_context_t *ctx){
	uint16_t port;
	coap_string_t *host = get_discovered_host_port(&port);
    fprintf(stderr,"discovered port is %d \n", port);
	if (host == NULL) return 1;
	/* coaps is wanted do, coaps port */
	if (port == 5683) port++;
    set_port(port);
	set_host(host);
	return 0;
}

/* connect_pledge
 * starts DTLS connection with Registrar
 * returns 0; when enrolled
 * returns 1: when failure
 */
static int8_t
connect_pledge(coap_context_t *ctx){

/* start new session to registrar with discovered host*/
  set_message_type(COAP_MESSAGE_CON);
  
/* DTLS preparations */
  set_scheme( COAP_URI_SCHEME_COAPS);
  static char cert_nm[] = PLEDGE_COMB; 
  static char ca_nm[] = CA_MASA_CRT;
  char *ca = ca_nm;
  char *cert = cert_nm;
  set_certificates( cert, ca);
  
  /* Start DTLS connection with ping  */ 

  coap_session_t *session = coap_start_session(ctx);
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

coap_string_t  signed_request_voucher = { .length = 0 , .s = NULL};
coap_string_t request_voucher = {.length =0, .s = NULL};
   
static int8_t  
voucher_request(coap_context_t *ctx){ 
     
	/* continue session to registrar with returned registrar certificate*/
  set_message_type(COAP_MESSAGE_CON);
  coap_string_t path = { .length =0 , .s = NULL};
  /* est/rv  with signed requestvoucher to registrar */ 
  set_resp_handler(add_voucher);
  uri_options_on();
  set_flags( FLAGS_BLOCK); 
  char rv[] = ".well-known/brski/rv";
  set_method( COAP_REQUEST_POST);
  path.s = (uint8_t *)rv;
  path.length = strlen(rv);
  set_path( &path);
  if (request_voucher.s != NULL) coap_free(request_voucher.s);
  request_voucher.s = NULL;
  if (masa_voucher.s != NULL) coap_free(masa_voucher.s);
  masa_voucher.s = NULL;
  masa_code = 0;
  char cpc[] = PLEDGE_SERVER_DER;    /* contains registrar certificate in DER */
  char *file_name = cpc;
  int8_t ok = brksi_make_signed_rv(&signed_request_voucher, &request_voucher, file_name);
  set_payload(&signed_request_voucher);
  if (ok != 0) return 1;
  if (JSON_set() == 1)
     return coap_start_request(COAP_MEDIATYPE_APPLICATION_VOUCHER_CMS_JSON, ctx);
  else
     return coap_start_request(COAP_MEDIATYPE_APPLICATION_VOUCHER_COSE_CBOR, ctx);
}

static int8_t
status_voucher(coap_context_t *ctx){
  coap_string_t path = { .length =0 , .s = NULL};
  int8_t result;
  if (signed_request_voucher.s != NULL)coap_free(signed_request_voucher.s);
  signed_request_voucher.s = NULL;  
  /* local MASA test */  
  char cmc[] = MASA_SRV_CRT;
  char *masa_cert_name = cmc;
  if (masa_voucher.s == NULL){
	 coap_log(LOG_ERR," No MASA voucher returned \n");
	 return 1;
  }
  coap_string_t *voucher = NULL;
  if (JSON_set() == JSON_OFF)
      voucher = brski_verify_cose_signature(&masa_voucher, masa_cert_name);
  else
      voucher = brski_verify_cms_signature(&masa_voucher, masa_cert_name);
  if (voucher == NULL){
	  coap_log(LOG_ERR," signature of returned masa voucher is wrong \n");
	  if (request_voucher.s != NULL)coap_free(request_voucher.s); 
	  request_voucher.s = NULL;  
	  return 1;
  }
  result = brski_check_voucher(voucher, &request_voucher);
  if (voucher->s != NULL)coap_free(voucher->s);
  coap_free(voucher);
  if (request_voucher.s != NULL)coap_free(request_voucher.s);
  request_voucher.s = NULL;    
  if (result != 0){
	  coap_log(LOG_ERR, "voucher request and masa returned voucher do not correspond \n");
	  return 1;
  }
  /* est/vs  */
  int16_t ct = COAP_MEDIATYPE_APPLICATION_CBOR;
  if (registrar_audit.s != NULL) coap_free(registrar_audit.s);
  registrar_audit.s = NULL;
  audit_code = 0;
  set_resp_handler(add_audit);
  char vs[] = ".well-known/brski/vs";
  path.s = (uint8_t *)vs;
  path.length = strlen(vs);
  set_path( &path);
  remove_flags( FLAGS_BLOCK);
  set_method (COAP_REQUEST_GET);
  coap_string_t status = { .length = 0, .s = NULL};
  if (JSON_set() == JSON_OFF){
      brski_cbor_voucherstatus(&status);
      ct = COAP_MEDIATYPE_APPLICATION_CBOR;
  } else {
	  brski_json_voucherstatus(&status);
	  ct = COAP_MEDIATYPE_APPLICATION_JSON;
  }
  if (status.length > 0){
	  set_payload(&status);
	  result = coap_start_request(ct, ctx); 
      coap_free(status.s);
  }  /* if status.length  */   
   return result;
}


static int8_t
get_certificate(coap_context_t *ctx){
  coap_string_t path = { .length =0 , .s = NULL};
 /* est/crts    */
 /* get certificate from registrar  */
  if (registrar_cert.s != NULL)coap_free(registrar_cert.s);
  registrar_cert.s = NULL;
  cert_code =0;
  char crts[] = ".well-known/est/crts";
  path.s = (uint8_t *)crts;
  path.length = strlen(crts);
  set_path( &path);
  payload.length = 0;
  if (payload.s != NULL)coap_free(payload.s);
  payload.s = NULL;
  set_payload(&payload);
  set_resp_handler(add_certificate);
  set_method (COAP_REQUEST_GET);
  return coap_start_request(0, ctx);
}


static int8_t
get_attributes(coap_context_t *ctx){
  coap_string_t path = { .length =0 , .s = NULL};
  /* write returned registrar_certificate to pledge trust anchor file */
  char trust[] = PLEDGE_TRUST;
  int8_t result = write_file_mem(trust, &registrar_cert);
  if (result != 0){
	  coap_log(LOG_WARNING," cannot write registrar certificate  to file\n");
	  return 1;
  }
 /* est/att   */
  set_resp_handler(add_certificate);
  remove_flags( FLAGS_BLOCK);
  payload.length = 0;
  if (payload.s != NULL)coap_free(payload.s);
  payload.s = NULL;
  set_payload(&payload);
  if (registrar_cert.s != NULL)coap_free(registrar_cert.s);
  registrar_cert.s = NULL;
  cert_code = 0;
  char att[] = ".well-known/est/att";
  path.s = (uint8_t *)att;
  path.length = strlen(att);
  set_path( &path);
  set_method (COAP_REQUEST_GET);
  return coap_start_request(0, ctx); 
}
  
static int8_t 
enroll_certificate(coap_context_t *ctx){
  coap_string_t path = { .length =0 , .s = NULL};
  int8_t result = 0;
 /* est/sen   enroll certificate  */
  if (payload.s != NULL)coap_free(payload.s);
  payload.length =0;
  payload.s = NULL;
  set_resp_handler(add_certificate);
  if (registrar_cert.s != NULL)coap_free(registrar_cert.s);
  registrar_cert.s = NULL;
  cert_code = 0; 
  char sen[] = ".well-known/est/sen";
  path.s = (uint8_t *)sen;
  path.length = strlen(sen);
  set_path( &path);
  set_method( COAP_REQUEST_POST);
  result = brski_create_csr(&payload);
  if (result == 0){
    if (payload.length > 0){
	  set_payload(&payload);
	  result = coap_start_request(COAP_MEDIATYPE_APPLICATION_CBOR, ctx); 
      coap_free(payload.s);
      payload.s = NULL;
    }  /* if payload.length  */
  }  /* if result  */
  return result;
}

/* discover_join_proxy
 * discover the join-proxy to connect to registrar that may own the network */
static uint8_t
discover_join_proxy(coap_context_t *ctx, coap_string_t *MC_coap){
   coap_string_t query = {.length = 0, .s = NULL};
   coap_string_t path = { .length =0 , .s = NULL};  
/* discover registrar */
  char qr[] = "rt=ace.est.sen";
  query.s = (uint8_t *)qr;
  query.length = strlen(qr);
  set_message_type(COAP_MESSAGE_NON);
  set_query(&query);
  char wk[] = ".well-known/core";
  path.s = (uint8_t *)wk;
  path.length = strlen(wk);
  set_discovery_wanted();
  set_host(MC_coap);       /* discovery address */
  set_path( &path);
  set_method( COAP_REQUEST_GET);
  set_scheme( COAP_URI_SCHEME_COAP); 
  if (coap_start_session(ctx) == NULL){
	  coap_log(LOG_WARNING," start-session discovery address illegal\n");
	  return 0;
  };
  if (payload.s != NULL)coap_free(payload.s);
  payload.s = NULL;
  payload.length = 0; 
  uri_options_off();
  return coap_start_request(0, ctx); 
}


/* discover_registrar
 * discover the registrar that may own the network */
static uint8_t
discover_registrar(coap_context_t *ctx, coap_string_t *MC_coap){
   coap_string_t query = {.length = 0, .s = NULL};
   coap_string_t path = { .length =0 , .s = NULL};  
/* discover registrar */
  char qr[] = "rt=brski-port";
  query.s = (uint8_t *)qr;
  query.length = strlen(qr);
  set_message_type(COAP_MESSAGE_NON);
  set_query(&query);
  char wk[] = ".well-known/core";
  path.s = (uint8_t *)wk;
  path.length = strlen(wk);
  set_discovery_wanted();
  set_host(MC_coap);       /* discovery address */
  set_path( &path);
  set_method( COAP_REQUEST_GET);
  set_scheme( COAP_URI_SCHEME_COAP); 
  if (coap_start_session(ctx) == NULL){
	  coap_log(LOG_WARNING," start-session discovery address illegal\n");
	  return 0;
  };
  if (payload.s != NULL)coap_free(payload.s);
  payload.s = NULL;
  payload.length = 0; 
  uri_options_off();
  return coap_start_request(0, ctx); 
}
static void
init_resources(coap_context_t *ctx) {
  coap_resource_t *r;

  r = coap_resource_init(NULL, 0);
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
  coap_log(LOG_INFO, "CN '%s' presented by server (%s) depth is %d\n",
           cn, depth ? "CA" : "Certificate", depth);
//  if (depth == 0){
	coap_log(LOG_INFO," certificate to be written to %s \n", PLEDGE_SERVER_DER);
    char file[] = PLEDGE_SERVER_DER;
    coap_string_t contents;
    coap_str_const_t constnm = {.length = asn1_length, .s = asn1_public_cert};
    memcpy(&contents, &constnm, sizeof(contents));  /* to avoid compilation warning */
    uint8_t ok = write_file_mem(file, &contents);  
    if (ok != 0)coap_log(LOG_ERR, "certificate is not written to %s \n", PLEDGE_SERVER_DER);    
 // }     
  return 1;
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
     "Usage: %s [-d max] [-v num] [-p port] [registrar address]\n"
     "General Options\n"
     "\t-b [num,]size\tBlock size to be used in GET/PUT/POST requests\n"
     "\t       \t\t(value must be a multiple of 16 not larger than 1024)\n"
     "\t       \t\tIf num is present, the request chain will start at\n"
     "\t       \t\tblock num\n"          
     "\t-d max \t\tAllow dynamic creation of up to a total of max\n"
     "\t       \t\tresources. If max is reached, a 4.06 code is returned\n"
     "\t       \t\tuntil one of the dynamic resources has been deleted\n"
     "\t-l loss%%\tRandomly fail to send datagrams with the specified\n"
     "\t       \t\tprobability - 100%% all datagrams, 0%% no datagrams\n"
     "\t       \t\t(for debugging only)\n"
     "\t-v num \t\tVerbosity level (default 3, maximum is 9). Above 7,\n"
     "\t       \t\tthere is increased verbosity in GnuTLS and OpenSSL logging\n"
     "\t-J     \t\tJSON is used replacing CBOR using media-type application/voucher-cms+json\n"
     "\t-R     \t\tDiscover Registrar, if not set, Join-Proxy is discovered \n"
     "\t-p port\t\tPort of the coap device server\n"
     "\t       \t\tPort+1 is used for coaps device server \n"
     "\t       \t\tif not specified, default coap/coaps server ports are used \n"
     "\tJoin_proxy address\t specifieds the IP address and [port] of Join_proxy Registrar \n"
     "\t       \t\t  If not specified , join_proxy is discovered with multicast request \n"
     "\t-h     \t\tHelp displays this message \n"
     "\texamples:\t  %s -p 5663 \n"
     "\t       \t\t  %s \n"
     "\t       \t\t  %s -v 7 coap://[192.168.1.75] \n"
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
  set_pki_callback(verify_cn_callback);  /* set the call back   */
  fill_keystore(ctx);

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
    coap_address_t addr, addrs;
    coap_endpoint_t *ep_udp = NULL, *ep_dtls = NULL;

    if (rp->ai_addrlen <= sizeof(addr.addr)) {
      coap_address_init(&addr);
      addr.size = (socklen_t)rp->ai_addrlen;
      memcpy(&addr.addr, rp->ai_addr, rp->ai_addrlen);
      addrs = addr;
      if (addr.addr.sa.sa_family == AF_INET) {
        uint16_t temp = ntohs(addr.addr.sin.sin_port) + 1;
        addrs.addr.sin.sin_port = htons(temp);
        temp++;
      } else if (addr.addr.sa.sa_family == AF_INET6) {
        uint16_t temp = ntohs(addr.addr.sin6.sin6_port) + 1;
        addrs.addr.sin6.sin6_port = htons(temp);
        temp++;
      } else {
        goto finish;
      }
      ep_udp = coap_new_endpoint(ctx, &addr, COAP_PROTO_UDP);
      if (ep_udp) {
		init_URIs(&addr, COAP_PROTO_UDP, JP_STANDARD_PORT);
        if (coap_dtls_is_supported() && (key_defined || cert_file)) {
          ep_dtls = coap_new_endpoint(ctx, &addrs, COAP_PROTO_DTLS);
          if (ep_dtls){
			  init_URIs(&addrs, COAP_PROTO_DTLS, JP_DTLS_PORT);
		  } /* if (ep_dtls) */
          else
            coap_log(LOG_CRIT, "cannot create DTLS endpoint\n");
        } /* if coap_dtls  */
      } else {
        coap_log(LOG_CRIT, "cannot create UDP endpoint\n");
        continue;
      } /* if (!ep_udp) */
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
		jp_proxy();
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
  if (size) set_block( size);

  return 1;
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

  coap_uri_t uri;
  uri.scheme = COAP_URI_SCHEME_COAP;
  uri.port = COAP_DEFAULT_PORT;
  if (strlen(arg) > 1){
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
    } /* if uri.scheme  */
  }  /* if strlen(arg)  */
  set_scheme( uri.scheme); 
  coap_string_t *tmp = (coap_string_t *) &(uri.host); /* uri.host is const */
  set_host( tmp);
  tmp = (coap_string_t *) &(uri.path); /* uri.path is const */
  set_path( tmp);
  set_port( uri.port);

  return 0;
}

/* define pledge states to join_proxy */
typedef enum {START, DISCOVERED, CONNECTED, RV_DONE, VS_DONE, CERTIFIED, ATTRIBUTES, ENROLLED} pledge_state_t;

int
main(int argc, char **argv) {
  coap_context_t  *ctx;
  char *group6 = NULL;
  char *group4 = NULL;
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
  uint8_t discovery = DISCOVER_JOIN_PROXY;

#ifndef _WIN32
  struct sigaction sa;
#endif

  clock_offset = time(NULL);
  set_JSON(JSON_OFF); /* can be set on with -J option */

  while ((opt = getopt(argc, argv, "JRd:b:p:l:v:h:")) != -1) {
    switch (opt) {
    case 'b':
      cmdline_blocksize(optarg);
      break;
    case 'd' :
      support_dynamic = atoi(optarg);
      break;
    case 'l':
      if (!coap_debug_set_packet_loss(optarg)) {
        usage(argv[0], LIBCOAP_PACKAGE_VERSION);
        exit(1);
      }
      break;
    case 'p' :
      strncpy(port_str, optarg, NI_MAXSERV-1);
      port_str[NI_MAXSERV - 1] = '\0';
      break;
    case 'v' :
      log_level = strtol(optarg, NULL, 10);
      break;
    case 'J' :
      set_JSON(JSON_ON);
      break;
    case 'R' :
      discovery = DISCOVER_REGISTRAR;
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
  /* all coap_local_nodes is used for discovery *
   * unless addres is specified in command line  */
  char acln[] = ALL_COAP_LOCAL_IPV4_NODES;
  coap_string_t MC_coap = {.s = (uint8_t *)acln,.length = strlen(acln)};
  coap_str_const_t *tmp_host = NULL;
  uint16_t tmp_port = 0;
  
  if (optind < argc) {
     if (cmdline_uri(argv[optind], create_uri_opts) < 0) {
       usage( argv[0], LIBCOAP_PACKAGE_VERSION );
       exit(1);
     }
     tmp_host = get_host();
     tmp_port = get_port();    
     if (tmp_host != NULL){
		   if (tmp_host->s != NULL && tmp_host->length != 0){
			   MC_coap.s = malloc(tmp_host->length);
			   memcpy(MC_coap.s, tmp_host->s, tmp_host->length);
			   MC_coap.length = tmp_host->length;
/*  copied over address from comandline  */
		   }
	   }
   }
  set_certificates(int_cert_file, int_ca_file); /* set certificate files */ 
  ctx = get_context(addr_str, port_str);
  if (!ctx) return -1;
  
 /* server joins MC address: all link-local coap nodes */ 
  char all_ipv6_coap_ll[] = ALL_COAP_LOCAL_IPV6_NODES;
  char all_ipv4_coap_ll[] = ALL_COAP_LOCAL_IPV4_NODES;
  group6 = all_ipv6_coap_ll;
  group4 = all_ipv4_coap_ll;
  if (group6){
    if (coap_join_mcast_group(ctx, group6) == 0)
          coap_log(LOG_INFO," joint mulicast group with address: %s \n", group6);
  }
  if (group4){
    if (coap_join_mcast_group(ctx, group4) == 0)
          coap_log(LOG_INFO," joint mulicast group with address: %s \n", group4);
  }
  jp_set_context(ctx);
  init_resources(ctx);
  JP_init_resources(ctx);
#ifdef WITH_OSCORE
  oscore_ctx_t *osc_ctx = oscore_init();
  oscore_set_contexts();
/* osc_ctx  points to default oscore context  */
  ctx->osc_ctx = osc_ctx;
#endif /* WITH_OSCORE */
     
  /* force epoll not supported */
     coap_fd = -1;
     
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
  pledge_state_t state = START;  
  if (tmp_host == NULL){ /* registrar is not set in command line, so discover with MC */
    if (discovery == DISCOVER_JOIN_PROXY) discover_join_proxy( ctx, &MC_coap);
    else if (discovery == DISCOVER_REGISTRAR) discover_registrar( ctx, &MC_coap);
  } else { /* set registrar parameters  */
    coap_string_t new_host;
    new_host.length = tmp_host->length;
    new_host.s = coap_malloc(tmp_host->length);
    memcpy(new_host.s, tmp_host->s, tmp_host->length); /* const pointer */
    set_host(&new_host);
    set_port(tmp_port);
         /* for DTLS, specified port is coaps port */
    coap_free(new_host.s);
    state = DISCOVERED;    /*  registrar has been set  in command line, no discovery  */
    make_ready();
  }

  while ( !quit ) {
    int result;
    int8_t ok = 0;
    if (is_ready()){ /* remote action is done */
	   switch (state) {
		   case START:
		     ok = verify_discovery( ctx);
             state++;
		   case DISCOVERED:
		     ok = connect_pledge(ctx); 
		     state++;
		   case CONNECTED:
		     ok = voucher_request(ctx);
		     break;
		   case RV_DONE:
		     ok = arrived(masa_code, &masa_voucher);
		     if (ok == 0)ok = status_voucher(ctx);
		     break;
		   case VS_DONE:
		     ok = arrived(audit_code, &registrar_audit);
		   	 if (ok == 0)ok = get_certificate(ctx);
		   	 break;		       
		   case CERTIFIED:
		     ok = arrived(cert_code, &registrar_cert);
		     if (ok == 0)ok = get_attributes(ctx);
		     break;
		   case ATTRIBUTES:
		     ok = arrived(cert_code, &registrar_cert);
		     if (ok == 0)ok = enroll_certificate(ctx);
		     break;
		   case ENROLLED:
		   	 ok = arrived(cert_code, &registrar_cert);
		     char file_name[] = PLEDGE_ENROLL_CRT;
             if (ok == 0)ok =  write_file_mem(file_name, &registrar_cert);
		     break;
		   default:
		     ok = 1;
		     break;
	   }  /* switch */
	   if (ok == 0) state ++;
	   else {
		   ok = 0;
		   state = START; /* something went wrong; start again */
	   }
	   fprintf(stderr," in main, OK is %d    state is %d \n", ok, state);
	   ok =0;
	   reset_ready();
    }  /* if is_ready */
    if (coap_fd != -1) {
      /*
       * Using epoll.  It is more usual to call coap_io_process() with wait_ms
       * (as in the non-epoll branch), but doing it this way gives the
       * flexibility of potentially working with other file descriptors that
       * are not a part of libcoap.
       */
      fprintf(stderr,"using e_poll\n");
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

  return 0;
}

