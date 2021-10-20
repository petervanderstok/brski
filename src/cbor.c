/*
 * Copyright (c) 2018, SICS, RISE AB
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
 * \file
 *      An implementation of the Concise Binary Object Representation (RFC).
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 * extended for coaplib by Peter van der Stok
 *                         <consultancy@vanderstok.org>
 * on request of Fairhair alliance.
 *
 */


#include "cbor.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "coap_debug.h"
#include "brski_util.h"


int
cbor_put_nil(uint8_t **buffer){
  **buffer = 0xF6;
  (*buffer)++;
  return 1;
}

int
cbor_put_text(uint8_t **buffer, char *text, uint64_t text_len)
{
  uint8_t *pt = *buffer;
  int nb = cbor_put_unsigned(buffer, text_len);
  *pt = (*pt | 0x60);
  memcpy(*buffer, text, text_len);
  (*buffer) += text_len;
  return nb + text_len;
}

int
cbor_put_array(uint8_t **buffer, uint64_t elements)
{
  uint8_t *pt = *buffer;
  int nb = cbor_put_unsigned(buffer, elements);
  *pt = (*pt | 0x80);
  return nb;
}

int
cbor_put_bytes(uint8_t **buffer, uint8_t *bytes, uint64_t bytes_len)
{
  uint8_t *pt = *buffer;
  int nb = cbor_put_unsigned(buffer, bytes_len);
  *pt = (*pt | 0x40);
  memcpy(*buffer, bytes, bytes_len);
  (*buffer) += bytes_len;
  return nb + bytes_len;
}

int
cbor_put_map(uint8_t **buffer, uint64_t elements)
{
  uint8_t *pt = *buffer;
  int nb = cbor_put_unsigned(buffer, elements);
  *pt = (*pt | 0xa0);
  return nb;
}

int
cbor_put_number(uint8_t **buffer, int64_t value){
  if (value < 0)return cbor_put_negative(buffer, -value);
  else return cbor_put_unsigned(buffer, value);
}

int cbor_put_simple_value(uint8_t **buffer, uint8_t value){
  uint8_t *pt = *buffer;
  int nb = cbor_put_unsigned(buffer, value);
  *pt = (*pt | 0xe0);
  return nb;
}

int
cbor_put_tag(uint8_t **buffer, uint64_t value){
  uint8_t *pt = *buffer;
  int nb = cbor_put_unsigned(buffer, value);
  *pt = (*pt | 0xc0);
  return nb;
}


int
cbor_put_negative(uint8_t **buffer, int64_t value)
{
  value--;
  uint8_t *pt = *buffer;
  int nb = cbor_put_unsigned(buffer, value);
  *pt = (*pt | 0x20);
  return nb;
}

static void
put_b_f(uint8_t **buffer, uint64_t value, uint8_t nr)
{
  uint8_t *pt = *buffer-1;
  uint64_t vv = value;
  for (int q = nr; q > -1; q--){
    (*pt--) = (uint8_t)( vv & 0xff);
     vv = (vv >>8);
  }
}

int
cbor_put_unsigned(uint8_t **buffer, uint64_t value)
{
  if(value < 0x18 ) {  /* small value half a byte */
    (**buffer) = (uint8_t)value;
    (*buffer)++;
    return 1;
  } else if((value > 0x17) && (value < 0x100)) { 
/* one byte uint8_t  */
    (**buffer) = (0x18);
    *buffer = (*buffer) + 2;
    put_b_f(buffer, value, 0);
    return 2;
  } else if((value > 0xff) && (value < 0x10000)){
/* 2 bytes uint16_t     */
    (**buffer) = (0x19);
    *buffer = (*buffer) + 3;
    put_b_f(buffer, value, 1);
    return 3;
  } else if((value > 0xffff) && (value < 0x100000000)){
/* 4 bytes uint32_t   */
    (**buffer) = (0x1a);
    *buffer = (*buffer) + 5;
    put_b_f(buffer, value, 3);
    return 5;
  } else /*if(value > 0xffffffff)*/{
/* 8 bytes uint64_t  */
    (**buffer) = (0x1b);
    *buffer = (*buffer) + 9;
    put_b_f(buffer, value, 7);
    return 9;
  }
}


/* temporary routine to read ascii hex dump */
static uint8_t 
gethex_byte(uint8_t *buffer){
/*
   uint8_t temp1 = *buffer;
   if ('0' <= temp1 && temp1 <= '9') temp1 = temp1 - '0';
   else if ('A' <= temp1 && temp1 <= 'F') 
                                temp1 = 10 + temp1 - 'A';
   else if ('a' <= temp1 && temp1 <= 'f') 
                                temp1 = 10 + temp1 - 'a';
   else return 255;
   uint8_t temp2 = *buffer;
   if ('0' <= temp2 && temp2 <= '9') temp2 = temp2 - '0';
   else if ('A' <= temp2 && temp2 <= 'F') 
                                temp2 = 10 + temp2 - 'A';
   else if ('a' <= temp2 && temp2 <= 'f')
                                temp2 = 10 + temp2 - 'a';
   else return 255;
   return (temp1<<4) + temp2;
*/
   return *buffer;
}

uint8_t 
cbor_get_next_element(uint8_t **buffer){
  uint8_t element = gethex_byte(*buffer);
  return element>>5;
}

/* cbor_get_element_size returns 
 *   - size of byte strings of character strings
 *   - size of array
 *   - size of map
 *   - value of unsigned integer
 */

uint64_t 
cbor_get_element_size(uint8_t **buffer){
  uint8_t control = gethex_byte((*buffer)) & 0x1f;
  uint64_t size = gethex_byte((*buffer)++);
  if (control < 0x18) size = (uint64_t)control;
  else {
    control = control & 0x3;
    int num =  1 << control;
    size = 0;
    uint64_t getal;
    for (int i = 0; i < num; i++){
      getal = (uint64_t)gethex_byte((*buffer)++);
      size = (size<<8) + getal;
    }
  }
  return size;
}

uint8_t
cbor_elem_contained(uint8_t *data, uint8_t *end){
	uint8_t *buf = data; 
	uint8_t *last = data + cbor_get_element_size(&buf);
	if (last > end){
		return 1;
	}
	else return 0;
}

int64_t 
cbor_get_negative_integer(uint8_t **buffer){
  return -cbor_get_element_size(buffer) -1;
}

uint64_t 
cbor_get_unsigned_integer(uint8_t **buffer){
  return cbor_get_element_size(buffer);
}


// cbor_get_number
// gets a negative or positive number from data
// OK: return 0 ; NOK: return 1
uint8_t
cbor_get_number(uint8_t **data, int64_t *value){
  uint8_t elem = cbor_get_next_element(data);
  if (elem == CBOR_UNSIGNED_INTEGER){
    *value = cbor_get_unsigned_integer(data);
    return 0;
  }
  else if (elem == CBOR_NEGATIVE_INTEGER){
    *value = cbor_get_negative_integer(data);
    return 0;
  }
  else return 1;
}

// cbor_get_simple_value
// gets a simple value from data
// OK: return 0 ; NOK: return 1
uint8_t
cbor_get_simple_value( uint8_t **data, uint8_t *value){
  uint8_t elem = cbor_get_next_element(data);
    if (elem == CBOR_SIMPLE_VALUE){
      *value = gethex_byte((*data)++) & 0x1f;   
      return 0;
    }
    else return 1;
}

void
cbor_get_string(uint8_t **buffer, char *str, uint64_t size){
  for( uint64_t i=0; i < size; i++){
    *str++ = (char)gethex_byte((*buffer)++);
  }
}

void
cbor_get_array(uint8_t **buffer, uint8_t *arr, uint64_t size){
  for( uint64_t i=0; i < size; i++){
    *arr++ = gethex_byte((*buffer)++);
  }
}

/* cbor_get_string_array
 * fills the the size and the array from the cbor element
 */
uint8_t
cbor_get_string_array(uint8_t **data, uint8_t **result, size_t *len){

  uint8_t elem = cbor_get_next_element(data);
  *len = cbor_get_element_size(data);
  *result = NULL;
  void *rs = coap_malloc( *len);
  *result = (uint8_t *) rs;
  if (elem == CBOR_TEXT_STRING){ 
       cbor_get_string(data, (char *)*result, *len);
       return 0;
  }
  else if (elem == CBOR_BYTE_STRING){
       cbor_get_array(data, *result, *len);
       return 0;  /* all is well */
  }
  else {
    coap_free(*result);
    *result = NULL;
    return 1;  /* failure */
  }
}

/* cbor_skip value
 *  returns number of CBOR bytes
 */
static size_t
cbor_skip_value(uint8_t **data){
   uint8_t elem = cbor_get_next_element(data);
   uint8_t control = gethex_byte((*data)) & 0x1f;
   uint16_t nb = 0;  /* number of elements in array or map */
   size_t num = 0;  /* number of bytes of length or number */
   size_t size = 0; /* size of value to be skipped */
   if (control < 0x18) num = 1;
   else { 
     control = control & 0x3;
     num = 1 + (1 << control);
   }
   switch (elem){
     case CBOR_UNSIGNED_INTEGER:
     case CBOR_NEGATIVE_INTEGER:
	   *data = *data + num;
	   size =  num;
       break;
     case CBOR_BYTE_STRING:
     case CBOR_TEXT_STRING:
       size = num;
       size += cbor_get_element_size(data);
       (*data) = (*data) + size - num;
       break;
     case CBOR_ARRAY:
        nb = cbor_get_element_size(data);
        size = num;
        for (uint16_t qq = 0; qq < nb; qq++)
             size += cbor_skip_value(data);
        break;
     case CBOR_MAP:
        nb = cbor_get_element_size(data);
        size = num;
        for (uint16_t qq = 0; qq < nb; qq++){
          size += cbor_skip_value(data);
          size += cbor_skip_value(data);
        }
        break;
     case CBOR_TAG:
       (*data)++;
       size = 1;
       break;
     default:
       return 0;
       break;
  } /* switch */
  return size;
}

/* cbor_strip value
 * strips the value of the cbor element into result
 *  and returns size
 */
uint8_t
cbor_strip_value(uint8_t **data, uint8_t **result, size_t *len){
   uint8_t *st_data = *data;
   size_t size = cbor_skip_value(data);
   *result = coap_malloc(size);
   for (uint16_t qq = 0; qq < size; qq++)(*result)[qq] = st_data[qq];
   *len = size;
   return 0;
}

