/* file_mem.c -- implementation of 
 * the Constrained Application Protocol (CoAP) server interface
 *         as defined in RFC 7252
 * Peter van der Stok <consultancy@vanderstok.org>
 * file includes coap server.c and imports coap_server.h
 * application discovers join_proxy and enrolls via join_proxy
 * This file relies on mbedtls DTLS
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
#include "coap_internal.h"

int32_t NR_of_malloc = 0;
int32_t NR_of_free   = 0;

void *
COAP_MALLOC(size_t size){
	NR_of_malloc++;
	return coap_malloc(size);
}
	
void 
COAP_FREE(void *adr){
	if (adr != NULL){
	   NR_of_free++;
	   coap_free(adr);
   }
}

int32_t
coap_malloc_loss(void){
	return NR_of_malloc - NR_of_free;
}

/*
 * Return error and error message
 */
void
brski_error_return(uint8_t error, coap_pdu_t *response,
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

