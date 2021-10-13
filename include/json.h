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


#ifndef _JSON_H
#define _JSON_H
#include <stddef.h>
#include <stdint.h>
#include "str.h"

#define JSON_CONTROL_OBJECT_START      0
#define JSON_CONTROL_OBJECT_END        1
#define JSON_CONTROL_OBJECT_SEPARATOR  2
#define JSON_CONTROL_ARRAY_START       3
#define JSON_CONTROL_ARRAY_END         4
#define JSON_CONTROL_NEXT              5

#define JSON_TEXT_LENGTH             256


int json_put_nil(uint8_t **buffer);

int json_put_false(uint8_t **buffer);

int json_put_true(uint8_t **buffer);

int json_put_text(uint8_t **buffer, char *text, uint64_t text_len);

int json_put_constext(uint8_t **buffer, const char *text, uint64_t text_len);

int json_put_hex(uint8_t **buffer, uint8_t *bytes, uint64_t byte_len);

int json_put_binary(uint8_t **buffer, uint8_t *bytes, uint64_t byte_len);

int json_put_array(uint8_t **buffer);

int json_put_object(uint8_t **buffer);

int json_put_number(uint8_t **buffer, int64_t value);

int json_put_next(uint8_t **buffer);

int json_put_value(uint8_t **buffer);

int json_end_object(uint8_t **buffer);

int json_end_array(uint8_t **buffer);

int json_get_control(uint8_t **buffer);

int json_get_text(uint8_t **buffer, coap_string_t *text);

int json_get_number(uint8_t **buffer, int64_t *number);

int json_get_length(uint8_t **buffer, size_t *len, uint8_t *end);

int json_get_bytes(uint8_t **buffer, uint8_t *dest, size_t len);

int json_get_binary(uint8_t **buffer, uint8_t **dest, size_t *len, uint8_t *end);

#endif /* _JSON_H */
