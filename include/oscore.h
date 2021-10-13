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
 *      An implementation of the Object Security for Constrained RESTful Enviornments (Internet-Draft-12) .
 * \author
 *      Martin Gunnarsson  <martin.gunnarsson@ri.se>
 * major rewrite for libcoap 
 *      Peter van der Stok <consultancy@vanderstok.org>
 *      on request of Fairhair alliance 
 *
 */


#ifndef _OSCORE_H
#define _OSCORE_H

#include "coap.h"
#include "cose.h"
#include "oscore-context.h"

#define OSCORE_DEFAULT_REPLAY_WINDOW 32

/* Estimate your header size, especially when using Proxy-Uri. */
#define COAP_MAX_HEADER_SIZE          70

/* OSCORE error messages  (to be moved elsewhere  */
#define OSCORE_DECRYPTION_ERROR       100
#define PACKET_SERIALIZATION_ERROR    102

#define OSCORE_SINGLE 0
#define OSCORE_GROUP  1
#define OSCORE_PAIR   2

/* oscore_cs_params
 * returns cbor array [[param_type], [paramtype, param]]
 */
uint8_t *
oscore_cs_params(int8_t param, int8_t param_type, size_t *len);

/* oscore_cs_key_params
 * returns cbor array [paramtype, param]
 */
uint8_t *
oscore_cs_key_params(int8_t param, int8_t param_type, size_t *len);

//
//  oscore_pdu_print
//  prints contents of pdu
//
void
oscore_pdu_print(coap_pdu_t *pdu, const char *s);

//
// oscore_payload_copy
//  copies the contentents of source_pdu to destination_pdu
// used size and data are adapted
// test on available space in destination is done
// returns error > 0 when no space available
void
oscore_payload_copy( coap_pdu_t *source, coap_pdu_t *destination);

//
// coap_is_request
//
uint8_t
coap_is_request(coap_pdu_t *coap_pkt);

//
// u64tob
//
uint8_t
u64tob(uint64_t in, uint8_t *buffer);

//
// btou64
//
uint64_t
btou64(uint8_t *bytes, size_t len);

//
// oscore_external_option_copy
// acts on external options not to be encrypted
// external options from source are copied to destination
// COAP_OPTION_OSCORE is added to destination at ordered place
int
oscore_external_option_copy( cose_encrypt0_t *cose, uint8_t group,
          coap_pdu_t *source, 
          coap_pdu_t *storage, coap_pdu_t *destination);

//
// oscore_merge_options_payload
/* options from decrypted are merged (ordered) 
 *        with options from source
 * payload from decrypted data is added to destination   */
/* no error return because source is larger than 
 * decrypted or destination                              */
/* error returns 0; OK returns 1                         */
int8_t
oscore_merge_options_payload( uint8_t *decrypted, 
                   size_t decrypt_length, coap_pdu_t *source, 
                                   coap_pdu_t *destination);

//
// oscore_encode_option_value
//
int
oscore_encode_option_value(uint8_t *option_buffer, cose_encrypt0_t *cose, uint8_t group);

//
// oscore_message_decrypt
/* decrypts encrypt_pdu and returns decrypted encrypt_pdu */
coap_pdu_t *
oscore_message_decrypt(coap_pdu_t *pdu, coap_session_t *session);
/* pdu contains incoming message with encrypted payload *
 * returns decrypted message   */

/*Decodes the OSCORE option value and places decoded values into the provided code structure */
int 
oscore_decode_option_value(uint8_t *option_value, int option_len, cose_encrypt0_t *cose);

/* new function for libcoap
 * oscore_message_encrypt
 * encrypts pdu and
 * returns encrypted message    */
coap_pdu_t *
oscore_message_encrypt(coap_pdu_t *pdu, coap_session_t *session);

//
// oscore_dec_fill_cose
/* called from oscore_message_decrypt                   
 * fills cose fields from context and sender context           *
 * oscore_option_decode fills cose fields from oscore option   */
void
oscore_dec_fill_cose(uint8_t coap_request, cose_encrypt0_t *cose, oscore_ctx_t *osc_ctx);


//
// oscore_enc_fill_cose
/* called from oscore_message_encrypt                   
 * fills cose fields from context and sender context           *
 * oscore_option_decode fills cose fields from oscore option   */
void
oscore_enc_fill_cose(uint8_t coap_request, cose_encrypt0_t *cose, oscore_ctx_t *osc_ctx);


 
/*Sets Alg, Partial IV Key ID and Key in COSE. Returns status*/
void
oscore_populate_cose(uint8_t coap_request, cose_encrypt0_t *cose, oscore_ctx_t *ctx);

/* Sets alg and keys in COSE SIGN  */
void
oscore_populate_sign(uint8_t coap_request, cose_sign1_t *sign, oscore_ctx_t *ctx);

//
// oscore_prepare_sig_structure
// creates and sets structure to be signed
size_t
oscore_prepare_sig_structure(uint8_t *sigptr,
uint8_t *aad_buffer, uint16_t aad_len,
uint8_t *text, uint16_t text_len);

/* Creates AAD, creates External AAD and serializes it into the complete AAD structure. Returns serialized size. */
size_t
oscore_prepare_aad(uint8_t group, oscore_ctx_t *ctx, cose_encrypt0_t *cose,
uint8_t *oscore_option, size_t oscore_option_len, uint8_t *buffer);

/* Creates Nonce */
void
oscore_generate_nonce(cose_encrypt0_t *ptr, oscore_ctx_t *ctx, uint8_t *buffer, uint8_t size);

/*Return 1 if OK, Error code otherwise */
uint8_t oscore_validate_sender_seq(oscore_recipient_ctx_t *ctx, cose_encrypt0_t *cose);

/* Return 0 if SEQ MAX, return 1 if OK */
uint8_t oscore_increment_sender_seq(oscore_ctx_t *ctx);

/* Restore the sequence number and replay-window to the previous state. This is to be used when decryption fail. */
void oscore_roll_back_seq(oscore_recipient_ctx_t *ctx);

/* Initialize the context storage and the protected resource storage. */
oscore_ctx_t *oscore_init(void);

#endif /* _OSCORE_H */
