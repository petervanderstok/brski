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
 *      An implementation of the JavaScript Object Notation (JSON) (RFC 8259).
 * \author
 *     Peter van der Stok <consultancy@vanderstok.org>
 *     on request of OCF
 *
 */

#define JSON_CONTROL_OBJECT_START      0
#define JSON_CONTROL_OBJECT_END        1
#define JSON_CONTROL_OBJECT_SEPARATOR  2
#define JSON_CONTROL_ARRAY_START       3
#define JSON_CONTROL_ARRAY_END         4
#define JSON_CONTROL_NEXT              5   
#define JSON_UNDEFINED                 6 

static char json_controls[] = {'{', '}', ':', '[', ']', ','};

#include <json.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include "coap_internal.h"


static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static char decoding_table[256];
static int table_built = 0;
static int mod_table[] = {0, 2, 1};

static void 
build_decoding_table() {
//    decoding_table = coap_malloc(256);
    for (int i = 0; i < 64; i++)
        decoding_table[(unsigned char) encoding_table[i]] = i;
    table_built = 1;
}


static char *
base64_encode(const uint8_t *data,
                    size_t input_length,
                    size_t *output_length) {

    *output_length = 4 * ((input_length + 2) / 3);

    char *encoded_data = coap_malloc(*output_length);
    if (encoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

       uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
       uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
       uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;
       uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
    }

    for (int i = 0; i < mod_table[input_length % 3]; i++)
        encoded_data[*output_length - 1 - i] = '=';

    return encoded_data;
}


static uint8_t *
base64_decode(const uint8_t *data,
                             size_t input_length,
                             size_t *output_length) {

    if (table_built == 0) build_decoding_table();

    if (input_length % 4 != 0) return NULL;

    *output_length = input_length / 4 * 3;
    if (data[input_length - 1] == '=') (*output_length)--;
    if (data[input_length - 2] == '=') (*output_length)--;

    unsigned char *decoded_data = coap_malloc(*output_length);
    if (decoded_data == NULL) return NULL;

    for (int i = 0, j = 0; i < input_length;) {

        uint32_t sextet_a = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_b = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_c = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];
        uint32_t sextet_d = data[i] == '=' ? 0 & i++ : decoding_table[data[i++]];

        uint32_t triple = (sextet_a << 3 * 6)
        + (sextet_b << 2 * 6)
        + (sextet_c << 1 * 6)
        + (sextet_d << 0 * 6);

        if (j < *output_length) decoded_data[j++] = (triple >> 2 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 1 * 8) & 0xFF;
        if (j < *output_length) decoded_data[j++] = (triple >> 0 * 8) & 0xFF;
    }

    return decoded_data;
}

/*
static void base64_cleanup() {
    free(decoding_table);
}*/


static void json_skip_blanks(uint8_t **buffer){
	while ((**buffer) == ' ')
	        (*buffer)++;
}

int json_put_nil(uint8_t **buffer){
	(**buffer) = 'n'; (*buffer)++;
	(**buffer) = 'u'; (*buffer)++;
	(**buffer) = 'l'; (*buffer)++;
	(**buffer) = 'l'; (*buffer)++;
	return 4;		
}

int json_put_false(uint8_t **buffer){
    (**buffer) = 'f'; (*buffer)++;
	(**buffer) = 'a'; (*buffer)++;
	(**buffer) = 'l'; (*buffer)++;
	(**buffer) = 's'; (*buffer)++;
	(**buffer) = 'e'; (*buffer)++;	
	return 5;		
}

int json_put_true(uint8_t **buffer){
	(**buffer) = 't'; (*buffer)++;
	(**buffer) = 'r'; (*buffer)++;
	(**buffer) = 'u'; (*buffer)++;
	(**buffer) = 'e'; (*buffer)++;
	return 4;		
}

int json_put_text(uint8_t **buffer, char *text, uint64_t text_len){
	**buffer = '"';
	for (uint16_t qq = 0; qq < text_len; qq++)(*buffer)[qq+1] = text[qq];
	*buffer = (*buffer)+ text_len + 1;
	**buffer = '"';
	(*buffer)++;
	return text_len + 2;
}

int json_put_constext(uint8_t **buffer, const char *text, uint64_t text_len){
	**buffer = '"';
	for (uint16_t qq = 0; qq < text_len; qq++)(*buffer)[qq+1] = text[qq];
	*buffer = (*buffer)+ text_len + 1;
	**buffer = '"';
	(*buffer)++;
	return text_len+2;
}

int json_put_binary(uint8_t **buffer, uint8_t *bytes, uint64_t byte_len){
	size_t base64_len = 0;
	char *base64_pt = base64_encode(bytes, byte_len, &base64_len); 
	if (base64_pt == NULL) return 0;      
	**buffer = '"';
	(*buffer)++;
	for (uint16_t qq = 0; qq < base64_len; qq++){
	    (**buffer) = base64_pt[qq];
	    (*buffer)++;
    }
	**buffer = '"';
	(*buffer)++;
	coap_free(base64_pt);
	return base64_len +2;	
}

int json_put_hex(uint8_t **buffer, uint8_t *bytes, uint64_t byte_len){
	**buffer = '"';
	(*buffer)++;
	for (uint16_t qq = 0; qq < byte_len; qq++){
	    sprintf((char *)(*buffer), "%02x",bytes[qq]);
	    (*buffer)++;
	    (*buffer)++;
    }
	**buffer = '"';
	(*buffer)++;
	return 2*byte_len + 2;	
}

int json_put_array(uint8_t **buffer){
		(**buffer) = '['; (*buffer)++;
		return 1;
}

int json_put_object(uint8_t **buffer){
		(**buffer) = '{'; (*buffer)++;
		return 1;	
}

int json_put_number(uint8_t **buffer, int64_t number){
	int len = sprintf((char *)(*buffer), "%d", (int)number);
	(*buffer) = (*buffer) + len;
	return len;
}

int json_put_next(uint8_t **buffer){
		(**buffer) = ','; (*buffer)++;
		return 1;	
}

int json_put_value(uint8_t **buffer){
		(**buffer) = ':'; (*buffer)++;
		return 1;
}

int json_end_object(uint8_t **buffer){
		(**buffer) = '}'; (*buffer)++;
		return 1;	
}

int json_end_array(uint8_t **buffer){
		(**buffer) = ']'; (*buffer)++;
		return 1;	
}

int json_get_control(uint8_t **buffer){
	json_skip_blanks(buffer);
	for (uint8_t qq = 0; qq < JSON_UNDEFINED; qq++){
		if ((**buffer) == json_controls[qq]){
			(*buffer)++;
			return qq;
		}
	} 
	return JSON_UNDEFINED;
}

int json_get_text(uint8_t ** buffer, coap_string_t *text){
	json_skip_blanks(buffer);
	if (**buffer != '"')return 1;
	(*buffer)++;
	uint8_t cnt = 0;
	while ( (cnt < JSON_TEXT_LENGTH) && ((**buffer) != '"')) {
		text->s[cnt] = (**buffer);
		cnt++;
		(*buffer)++;
	}
	if ((**buffer) != '"')return 1;
	(*buffer)++;
	text->s[cnt] = 0;
	text->length = cnt;
	return 0;
}

int json_get_number(uint8_t **buffer, int64_t *number){
	json_skip_blanks(buffer);
	(*number) = 0;
	while (((**buffer) > '0' - 1) && ((**buffer) < '9' + 1)){
		(*number) = (*number) *10 + ((**buffer) - '0');
		(*buffer)++;
	}
	return 0;
}

int json_get_length(uint8_t **buffer, size_t *len, uint8_t *end){
	uint8_t *data = *buffer;
	json_skip_blanks(&data);
	if ((*data) != '"')return 1;
	(data)++;
	uint16_t cnt = 0;
	while (((*data) != '"') && (data < end )){
		cnt ++;
		data++;
	}
	if (data == end)return 1;
	*len = cnt;
	return 0;
}


int json_get_bytes(uint8_t **buffer, uint8_t *dest, size_t len){
	json_skip_blanks(buffer);
	if (**buffer != '"')return 1;
	(*buffer)++;
	memcpy(dest, (*buffer), len);
	(*buffer) = (*buffer) + len;
	if ((**buffer) != '"')return 1;
	(*buffer)++;
	return 0;
}


int json_get_binary(uint8_t **buffer, uint8_t **dest, size_t *len, uint8_t *end){
	json_skip_blanks(buffer);
	size_t base64_len = 0;
	if (json_get_length(buffer, &base64_len, end) != 0) return 1;
	if (**buffer != '"')return 1;
	(*buffer)++;
	*dest = base64_decode((*buffer), base64_len, len);
	(*buffer) = (*buffer) + base64_len;
	if ((**buffer) != '"')return 1;
	(*buffer)++;
	return 0;
}
