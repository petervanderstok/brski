/*
 * Copyright (c) 2020, vanderstok consultancy
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

/**
 * \file cbor_decode.c
 *      Decoding of the Concise Binary Object Representation (RFC).
 * \author
 *    Peter van der Stok
 *                         <consultancy@vanderstok.org>
 *
 */

#include "cbor.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "coap_debug.h"
#include "cbor_decode.h"

uint8_t *output = NULL;
char    *wp = NULL; /* write_pointer */


void output_unsigned_integer(uint8_t **data){
	uint64_t number = cbor_get_unsigned_integer(data);
	wp += sprintf(wp," %llu",(long long unsigned int)number);
}

void output_negative_integer(uint8_t **data){
	int64_t number = cbor_get_negative_integer(data);
	wp += sprintf(wp," %lld",(long long int)number);
}

void output_byte_string(uint8_t **data){
	uint64_t size = cbor_get_element_size(data);
    uint8_t *pt = coap_malloc(size);
	wp[0] = 'h'; wp++;
	wp[0] = 39; wp++;
	cbor_get_array(data, pt, size);
	for (uint64_t qq = 0; qq < size; qq++){
		sprintf(wp,"%02x",pt[qq]);
		wp = wp +2;
	}
	coap_free(pt);
	wp[0]= 39;
	wp ++;
}

void output_text_string(uint8_t **data){
	uint64_t size = cbor_get_element_size(data);
	wp[0] = 34;
	wp ++;
	cbor_get_array(data, (uint8_t *)wp, size);
	wp = wp + size;
	wp[0] = 34;
	wp++;
}

void output_array(uint8_t **data){
	uint64_t arr_size = cbor_get_element_size(data);
	wp[0] = '[';
	wp++;
	for (uint64_t q = 0 ; q < arr_size; q++) {
		decode_cbor(data);
		wp[0] = ','; wp++;
	}
	wp--;
	wp[0] = ']';
	wp++;
}

void output_map(uint8_t **data){
	uint64_t map_size = cbor_get_element_size(data);
	wp[0] = '{';
	wp++;
	for (uint64_t q = 0 ; q < map_size; q++) {
		decode_cbor(data);
		wp[0] = ':'; wp++;
		wp[0] = ' '; wp++;
		decode_cbor(data);
		wp[0] = ','; wp++;
	}
	wp--;
	wp[0] = '}';
	wp++;
}

void output_simple_value(uint8_t **data){
	uint8_t val;
	uint8_t ok = cbor_get_simple_value( data, &val);
	if (ok == 0){
	  if (val == CBOR_FALSE){
		  sprintf(wp," false");
		  wp = wp + 6;
	  } else if (val  == CBOR_TRUE){
		  sprintf(wp, " true");
		  wp = wp + 5;
	  }
	  else{
		  sprintf(wp," ??");
		  wp = wp +3;
	  }
	}  
}
 
void output_tag(uint8_t **data){
	output_unsigned_integer(data);
	sprintf(wp,"(");
	wp++;
	decode_cbor( data);
	sprintf(wp,")");
	wp++;
}
     
      
void decode_cbor(uint8_t **data){
  uint8_t elem = cbor_get_next_element(data);
  switch (elem)
  {
	case CBOR_UNSIGNED_INTEGER:
	  output_unsigned_integer(data);
	  break;
    case CBOR_NEGATIVE_INTEGER:
      output_negative_integer(data);
      break;
    case CBOR_BYTE_STRING:
      output_byte_string(data);
      break;
    case CBOR_TEXT_STRING:
      output_text_string(data);
      break;
    case CBOR_ARRAY:
      output_array(data);
      break;
    case CBOR_MAP:
      output_map(data);
      break;
    case CBOR_TAG:
      output_tag(data);
      break;
    case CBOR_SIMPLE_VALUE:
      output_simple_value(data);
      break;
    default:
      break;
  }
}
  
void print_cbor(uint8_t **data){
  if(output != NULL)coap_free(output);
  output = coap_malloc(500);
  wp = (char *)output;
  decode_cbor(data);
  char *st = (char *)output;
  while (st < wp){
	  fprintf(stderr,"%c",st[0]);
	  st++;
  }
}


size_t sfprint_cbor(uint8_t **data, uint8_t **out){
  if(output != NULL)coap_free(output);
  output = coap_malloc(500);
  wp = (char *)output;
  decode_cbor(data);
  size_t len = (uint8_t *)wp - output;
  return len;
}
