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
 * adapted to libcoap; added group communication 
 *     Peter van der Stok <consultancy@vanderstok.org>
 *     on request of Fairhair alliance
 *
 */



#ifndef _OSCORE_CONTEXT_H
#define _OSCORE_CONTEXT_H

#include "coap.h"
#include "net.h"

#define CONTEXT_KEY_LEN 16
#define COAP_TOKEN_LEN 8   // added
#define TOKEN_SEQ_NUM  2     // to be set by application
#define EP_CTX_NUM  10       // to be set by application
#define CONTEXT_INIT_VECT_LEN 13
#define CONTEXT_SEQ_LEN sizeof(uint64_t)
#define Ed25519_PRIVATE_KEY_LEN 64
#define Ed25519_PUBLIC_KEY_LEN 32
#define Ed25519_SEED_LEN 32
#define Ed25519_SIGNATURE_LEN 64

#define OSCORE_SEQ_MAX (((uint64_t)1 << 40) - 1)

typedef struct oscore_sender_ctx_t oscore_sender_ctx_t;
typedef struct oscore_recipient_ctx_t oscore_recipient_ctx_t;
typedef struct oscore_ctx_t oscore_ctx_t;

struct oscore_ctx_t {
  oscore_ctx_t *next;
  uint8_t *master_secret;
  uint8_t *master_salt;
  uint8_t common_iv[CONTEXT_INIT_VECT_LEN];
  uint8_t *id_context;  /* contains GID in case of group */
  oscore_sender_ctx_t *sender_context;
  oscore_recipient_ctx_t *recipient_context;
  uint8_t master_secret_len;
  uint8_t master_salt_len;
  uint8_t id_context_len;
  int8_t alg;
  oscore_recipient_ctx_t *recipient_chain;
/* addition for group communication   */
  int8_t  counter_signature_algorithm;
  uint8_t *counter_signature_parameters;      /* binary CBOR array */
  uint8_t counter_signature_parameters_len;
  uint8_t mode;                     /* OSCORE_SINGLE, OSCORE_GROUP, OSCORE_PAIR */

};

struct oscore_sender_ctx_t {
  uint8_t sender_key[CONTEXT_KEY_LEN];
  uint8_t token[COAP_TOKEN_LEN];
  uint64_t seq;
  uint8_t *sender_id;
  uint8_t sender_id_len;
  uint8_t token_len;
/* addition to group communication   */
  uint8_t *public_key;
  uint8_t public_key_len;
  uint8_t *private_key;
  uint8_t private_key_len;
/* addition for pairwise communication */
  uint8_t *pairwise_sender_key;
  uint8_t pairwise_sender_key_len;
};

struct oscore_recipient_ctx_t {
  uint64_t last_seq;
//  uint64_t highest_seq;
  uint32_t sliding_window;
  uint32_t rollback_sliding_window;
  uint32_t rollback_last_seq;
  uint8_t recipient_key[CONTEXT_KEY_LEN];
  uint8_t *recipient_id;
  uint8_t recipient_id_len;
  uint8_t replay_window_size;
  uint8_t initial_state;
  oscore_recipient_ctx_t *next_recipient; 
            /* This field allows recipient chaining */
/* addition to group communication  */
  uint8_t *public_key;
  uint8_t public_key_len;
  uint8_t *private_key;
  uint8_t private_key_len;
/* addition for pairwise communication */
  uint8_t *pairwise_recipient_key;
  uint8_t pairwise_recipient_key_len;
};

//replay window default is 32

void
oscore_enter_context(oscore_ctx_t *context);

oscore_ctx_t *oscore_derive_ctx(uint8_t *master_secret, uint8_t master_secret_len, uint8_t *master_salt, uint8_t master_salt_len, 
int8_t alg, uint8_t *sid, uint8_t sid_len, uint8_t *rid, uint8_t rid_len, uint8_t *id_context, uint8_t id_context_len, uint8_t replay_window);


oscore_recipient_ctx_t *
oscore_add_recipient(oscore_ctx_t *ctx, 
        uint8_t *rid, uint8_t rid_len);

void
oscore_add_pair_keys(oscore_ctx_t *ctx,  
  uint8_t *pairwise_recipient_key,
  uint8_t pairwise_recipient_key_len,
  uint8_t *pairwise_sender_key,
  uint8_t pairwise_sender_key_len);
   
   
void
oscore_add_group_keys(oscore_ctx_t *ctx,  
   uint8_t *snd_public_key, 
   uint8_t *snd_private_key,
   uint8_t *rcv_public_key,
   uint8_t *rcv_private_key);
   
   void
oscore_add_group_algorithm(oscore_ctx_t *ctx,  
   int8_t  counter_signature_algorithm,
   uint8_t *counter_signature_parameters,
   uint8_t counter_signature_parameters_len);
   
int _strcmp(const char *a, const char *b);

uint8_t
bytes_equal(uint8_t *a_ptr, uint8_t a_len, uint8_t *b_ptr, uint8_t b_len);

//
//  oscore_find_context
// finds context for received send_id, reciever_id, or context_id
// that is stored in cose->key_id
// used by client interface
oscore_ctx_t *
oscore_find_context(
  uint8_t *srckey_id, uint8_t srckey_id_len,
  uint8_t *dstkey_id, uint8_t dstkey_id_len,
  uint8_t *ct_key_id, uint8_t ct_key_id_len);

#endif /* _OSCORE_CONTEXT_H */
