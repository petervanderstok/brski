/* _util.c -- implementation of 
 * the Constrained Application Protocol (CoAP) server interface
 *         as defined in RFC 7252
 * Peter van der Stok <consultancy@vanderstok.org>
 * this file supports reading/writing form/to file and memory,
 * multi user block reconstruction per session
 * error return for server
 *
 * Copyright (C) 2021 Peter van der Stok and others
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
#include <stdint.h>
#include "str.h"
#include "sv_cl_util.h"
#include "coap_internal.h"


/* Routines to do multiple block input
 * and multpile block output 
 */

static ret_data_t *SC_data_queue = NULL;

static void
SC_unchain_item(ret_data_t *item){
  if (SC_data_queue == item) {
    SC_data_queue = item->next;
    return;
  }
  ret_data_t *temp = SC_data_queue;
  while (temp != NULL){
    if (temp->next == item){
      temp->next = item->next;
      return;
    }
    temp = temp->next;
  }
}

ret_data_t *
SC_corresponding_data(coap_session_t *session){
  ret_data_t *item = SC_data_queue;
  while (item != NULL){
    if (item->session == session){
       return item;
     }
     item = item->next;
  }
  return NULL;
}

coap_string_t *
SC_new_return_data(coap_session_t *session){
    ret_data_t *item = SC_corresponding_data(session);
    if (item != NULL) return item->SC_ret_data;
    return NULL;
}

static coap_string_t *
SC_new_input_data(coap_session_t *session){
    ret_data_t *item = SC_corresponding_data(session);
    if (item != NULL) return item->SC_in_data;
    return NULL;
}

static void
free_SC_data(coap_session_t *session){
  ret_data_t *item = SC_corresponding_data(session);
  if (item == NULL) return;
  SC_unchain_item(item);
  if (item->SC_ret_data != NULL){
      if (item->SC_ret_data->s != NULL){
	coap_free(item->SC_ret_data->s);
      }
      coap_free(item->SC_ret_data);
  }
  if (item->SC_in_data != NULL){
	coap_delete_string(item->SC_in_data);
  }
  coap_free(item);  
}

static ret_data_t *
SC_corresponding_item(coap_session_t *session){
  ret_data_t *item = SC_corresponding_data(session);
  if (item != NULL) return item;
/*  new item entered */
  item = coap_malloc(sizeof(ret_data_t));
  if (item == NULL) return NULL;
  item->next = SC_data_queue;
  SC_data_queue = item;
  item->SC_ret_data = coap_malloc(sizeof(coap_string_t));
  memset(item->SC_ret_data, 0, sizeof(coap_string_t));
  item->SC_in_data = NULL;
  item->session = session;
  return item;
}

void
SC_verify_release(coap_session_t *session, coap_pdu_t *response){
  coap_opt_iterator_t opt_iter;  
  coap_opt_t *block_opt = coap_check_option(response, COAP_OPTION_BLOCK2, &opt_iter);
  if (block_opt) { /* handle Block2 */
    if(!COAP_OPT_BLOCK_MORE(block_opt)) free_SC_data(session);  /* last block */
  }
  else {
    free_SC_data(session); /* no more data to send  */
  }
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
           coap_session_t *session,
           coap_pdu_t *request,
           coap_pdu_t *response)
 {
   coap_block_t block1;
   size_t size = 0;
   uint8_t *data = NULL;
   ret_data_t *item = SC_corresponding_item(session);
   if (item == NULL) return 3;   
   if (coap_get_block(request, COAP_OPTION_BLOCK1, &block1)) {
    /* handle BLOCK1 */
    if (coap_get_data(request, &size, &data) && (size > 0)) {
      size_t offset = block1.num << (block1.szx + 4);

      coap_string_t *value = item->SC_in_data;
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
      item->SC_in_data = new_value;
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
assemble_data(coap_session_t *session,
           coap_pdu_t *request,
           coap_pdu_t *response,
           size_t *size)
{
  uint8_t ret = coap_handle_block(session, request, response);
  uint8_t *data = NULL;
  if (ret == 1){
  /* NOT BLOCK1 */  
    if (!coap_get_data(request, size, &data) && (*size > 0)) {
    /* Not a BLOCK1 and no data */
       server_error_return(COAP_RESPONSE_CODE(400), 
                    response, "Cannot find request data");
    }
  }
  else if (ret == 0){
	/* BLOCK1 complete */
	coap_string_t *value = SC_new_input_data(session);
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

/*
 * Return error and error message
 */
void
server_error_return(uint8_t error, coap_pdu_t *response,
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

/* write_file_mem
 * write from memory contained in contents to file
 * returns ok = 0; nok = 1;
 */
uint8_t 
write_file_mem(const char* file, coap_string_t *contents) {
  FILE *f = fopen(file, "w");
  
  if (f == NULL){
      fprintf(stderr, "file %s cannot be opened\n", file);
	  return 1;
  }
  size_t size = fwrite( contents->s, contents->length, 1, f);
  fclose( f);
  if (size == 1)return 0;
  return 1;
}


/* read_file_mem
 * reads file into memory 
 * returns data with length + 1
 */
uint8_t *read_file_mem(const char* file, size_t *length) {
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

