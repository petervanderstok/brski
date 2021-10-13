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
 * \adapted for libcoap
 *      Peter van der Stok <consultancy@vanderstok.org>
 *      on request of Fairhair alliance
 */


#include "oscore-context.h"
#include <stddef.h>
#include <stdlib.h>
#include "coap.h"
#include "cbor.h"
#include "mem.h"
#include <string.h>
#include "oscore-crypto.h"
#include "oscore.h"
#include "coap_debug.h"

#include <stdio.h>

oscore_ctx_t * contexts = NULL;

static uint8_t
compose_info(uint8_t *buffer, uint8_t alg, uint8_t *id, uint8_t id_len, uint8_t *id_context, uint8_t id_context_len, uint8_t out_len)
{
  uint8_t ret = 0;
  ret += cbor_put_array(&buffer, 5);
  ret += cbor_put_bytes(&buffer, id, id_len);
  if(id_context_len + 12 > 30){
    coap_log(LOG_WARNING,"compose_info buffer overflow.\n");
    return 0;
  }
  if(id_context != NULL && id_context_len > 0){
  	ret += cbor_put_bytes(&buffer, id_context, id_context_len);
  } else {
	ret += cbor_put_nil(&buffer); 
  }
  ret += cbor_put_unsigned(&buffer, alg);
  char *text;
  char key[] = "Key";
  char iv[] = "IV";
  uint8_t text_len;
  if(out_len != 16) {
    text = iv;
    text_len = 2;
  } else {
    text = key;
    text_len = 3;
  }

  ret += cbor_put_text(&buffer, text, text_len);
  ret += cbor_put_unsigned(&buffer, out_len);
  return ret;
}

uint8_t
bytes_equal(uint8_t *a_ptr, uint8_t a_len, uint8_t *b_ptr, uint8_t b_len)
{
  if(a_len != b_len) {
    return 0;
  }

  if(memcmp(a_ptr, b_ptr, a_len) == 0) {
    return 1;
  } else {
    return 0;
  }
}

void
oscore_enter_context(oscore_ctx_t *context)
{
   context->next = contexts;
   contexts = context;
}


//
//  oscore_find_context
// finds context for received send_id, reciever_id, or context_id
// any of the arguments may be NULL
oscore_ctx_t *
oscore_find_context(
  uint8_t *sndkey_id, uint8_t sndkey_id_len,
  uint8_t *rcpkey_id, uint8_t rcpkey_id_len,
  uint8_t *ctkey_id, uint8_t ctkey_id_len)
{
   oscore_ctx_t * pt = contexts;
   while (pt != NULL){
     int ok = 0;
     oscore_sender_ctx_t *spt = pt->sender_context;
     oscore_recipient_ctx_t *rpt = pt->recipient_chain;
     if ((sndkey_id_len == spt->sender_id_len) && 
         (ctkey_id_len == pt->id_context_len)){
       if (sndkey_id != NULL)
         ok = strncmp((char *)spt->sender_id, 
                          (char *)sndkey_id, sndkey_id_len);
       if (ctkey_id != NULL)
         ok = ok + strncmp((char *)pt->id_context, 
                          (char *)ctkey_id, ctkey_id_len);
       if (ok == 0){ /* context and sender id are the same  */
         if (rcpkey_id == NULL) return pt; /* context found */
         while (rpt != NULL){
           if (rcpkey_id_len == rpt->recipient_id_len){
             if(strncmp((char *)rpt->recipient_id, 
                         (char *)rcpkey_id, rcpkey_id_len)==0){
               pt->recipient_context = rpt;
               return pt;
               }
           } /* if rcpkey_id_len  */
           rpt = rpt->next_recipient;
         }  /* while rpt */
       } /* if sender_id  */
     } /* large if */
     pt= pt->next;
   }  /* end while */
   return NULL;
}

static void
convert_to_hex(uint8_t *src, char *dest, uint8_t len){
	for (uint qq = 0; qq < len ; qq++){
		char tmp = src[qq]>>4;
		if (tmp > 9)tmp = tmp + 0x61 - 10;
		else tmp = tmp + 0x30;
		dest[qq*3]= tmp;
		tmp = src[qq] & 0xf;
		if (tmp > 9)tmp = tmp +0x61 - 10;
		else tmp = tmp + 0x30;
		dest[qq*3+1]= tmp;
		dest[qq*3+2] = 0x20;
	}
	dest[len*3] = 0;
}

oscore_ctx_t *
oscore_derive_ctx(uint8_t *master_secret, uint8_t master_secret_len, uint8_t *master_salt, uint8_t master_salt_len, 
int8_t alg, uint8_t *sid, uint8_t sid_len, uint8_t *rid, uint8_t rid_len, uint8_t *id_context, uint8_t id_context_len, uint8_t replay_window)
{
  oscore_ctx_t *common_ctx = (oscore_ctx_t *)
       coap_malloc_type(COAP_OSCORE_COM, sizeof(oscore_ctx_t));
       memset(common_ctx, 0, sizeof(oscore_ctx_t));
  oscore_recipient_ctx_t *recipient_ctx =  
  (oscore_recipient_ctx_t *)coap_malloc_type(COAP_OSCORE_REC,
                           sizeof(oscore_recipient_ctx_t));
        memset(recipient_ctx, 0, sizeof(oscore_recipient_ctx_t));
  if(recipient_ctx == NULL) return NULL;

  oscore_sender_ctx_t *sender_ctx = (oscore_sender_ctx_t *)
  coap_malloc(sizeof(oscore_sender_ctx_t ));
  memset(sender_ctx, 0, sizeof(oscore_sender_ctx_t));

  if(sender_ctx == NULL) return NULL;
/* no group; to be changed when required  */
  common_ctx->counter_signature_algorithm = 0;
  common_ctx->counter_signature_parameters = NULL;
  common_ctx->counter_signature_parameters_len = 0;
  recipient_ctx->public_key = NULL;
  recipient_ctx->pairwise_recipient_key = NULL;
  sender_ctx->private_key = NULL;
  sender_ctx->public_key = NULL;
  sender_ctx->pairwise_sender_key = NULL;
  recipient_ctx->public_key_len = 0;
  recipient_ctx->pairwise_recipient_key_len = 0;
  sender_ctx->private_key_len = 0;
  sender_ctx->public_key_len = 0;
  sender_ctx->pairwise_sender_key_len = 0;
  common_ctx->mode = OSCORE_SINGLE;

  common_ctx->next = NULL;

  uint8_t info_buffer[30];

  uint8_t info_len;

  /* sender_ key */
  info_len = compose_info(info_buffer, alg, sid, sid_len, id_context, id_context_len, CONTEXT_KEY_LEN);
  if(info_len == 0) return NULL;
  hkdf(master_salt, master_salt_len, master_secret, master_secret_len, info_buffer, info_len, sender_ctx->sender_key, CONTEXT_KEY_LEN);

  /* Receiver key */
  info_len = compose_info(info_buffer, alg, rid, rid_len, id_context, id_context_len, CONTEXT_KEY_LEN);
  if(info_len == 0) return NULL;
  hkdf(master_salt, master_salt_len, master_secret, master_secret_len, info_buffer, info_len, recipient_ctx->recipient_key, CONTEXT_KEY_LEN);

  /* common IV */
  info_len = compose_info(info_buffer, alg, NULL, 0, id_context, id_context_len, CONTEXT_INIT_VECT_LEN);
  if(info_len == 0) return NULL;
  hkdf(master_salt, master_salt_len, master_secret, master_secret_len, info_buffer, info_len, common_ctx->common_iv, CONTEXT_INIT_VECT_LEN);

	char number[100];
    coap_log(LOG_INFO, "\nCommon context \n");
    convert_to_hex(sid, number, sid_len);
    coap_log(LOG_INFO, "    senderid         %s\n", number);
    convert_to_hex(rid, number, rid_len);
    coap_log(LOG_INFO, "    recipientid      %s\n", number);
    if (id_context != NULL){
	  convert_to_hex(id_context, number, id_context_len);
      coap_log(LOG_INFO, "    contextid        %s\n", number);
    }
    convert_to_hex(master_secret, number, master_secret_len);
    coap_log(LOG_INFO, "    Master secret:   %s\n", number);
    convert_to_hex(master_salt, number, master_salt_len);
    coap_log(LOG_INFO, "    Master salt      %s\n", number);
    convert_to_hex(common_ctx->common_iv, number, CONTEXT_INIT_VECT_LEN);    
    coap_log(LOG_INFO, "    Common IV        %s\n", number);
    convert_to_hex(sender_ctx->sender_key, number, CONTEXT_KEY_LEN);    
    coap_log(LOG_INFO, "    sender key       %s\n", number);
    convert_to_hex(recipient_ctx->recipient_key, number, CONTEXT_KEY_LEN);    
    coap_log(LOG_INFO, "    recipient key    %s\n", number);  

  common_ctx->master_secret = master_secret;
  common_ctx->master_secret_len = master_secret_len;
  common_ctx->master_salt = master_salt;
  common_ctx->master_salt_len = master_salt_len;
  common_ctx->alg = alg;
  common_ctx->id_context = id_context;
  common_ctx->id_context_len = id_context_len;
  common_ctx->mode = OSCORE_SINGLE;

  common_ctx->recipient_context = recipient_ctx;
  common_ctx->sender_context = sender_ctx;
  common_ctx->recipient_chain = recipient_ctx;

  sender_ctx->sender_id = sid;
  sender_ctx->sender_id_len = sid_len;
  sender_ctx->seq = 0;
  recipient_ctx->recipient_id = rid;
  recipient_ctx->recipient_id_len = rid_len;
  recipient_ctx->last_seq = 0;
  recipient_ctx->replay_window_size = replay_window;
  recipient_ctx->rollback_last_seq = 0;
  recipient_ctx->sliding_window = 0;
  recipient_ctx->rollback_sliding_window = 0;
  recipient_ctx->initial_state = 1;
  recipient_ctx->next_recipient = NULL; /* first in chain */

  return common_ctx;
}


oscore_recipient_ctx_t *
oscore_add_recipient(oscore_ctx_t *ctx, 
        uint8_t *rid, uint8_t rid_len){

  uint8_t info_buffer[30];
  uint8_t info_len;
  oscore_recipient_ctx_t *recipient_ctx =  
  (oscore_recipient_ctx_t *)coap_malloc_type(COAP_OSCORE_REC,
                           sizeof(oscore_recipient_ctx_t));
  if(recipient_ctx == NULL) return NULL;

  info_len = compose_info(info_buffer, ctx->alg, rid, rid_len, 
       ctx->id_context, ctx->id_context_len, CONTEXT_KEY_LEN);
  if(info_len == 0) return NULL;
  hkdf(ctx->master_salt, ctx->master_salt_len, 
     ctx->master_secret, ctx->master_secret_len, 
     info_buffer, info_len, 
     recipient_ctx->recipient_key, CONTEXT_KEY_LEN);

  if (coap_get_log_level() >= LOG_INFO){ 
    fprintf(stderr, "\nRecipient context \n");
    fprintf(stderr, "  recieverid ");
    for (int qq = 0 ; qq < rid_len; qq++)
      fprintf(stderr," %02x", rid[qq]);
    fprintf(stderr, " \n");
    fprintf(stderr,"  recipient key   ");
    for (int qq=0; qq<CONTEXT_KEY_LEN; qq++)
      fprintf(stderr," %02x",recipient_ctx->recipient_key[qq]);
    fprintf(stderr, " \n");
  } 

  oscore_recipient_ctx_t *ctx_rcp = ctx->recipient_chain;
  recipient_ctx->recipient_id = rid;
  recipient_ctx->recipient_id_len = rid_len;
  recipient_ctx->last_seq = 0;
  recipient_ctx->replay_window_size = 
                               ctx_rcp->replay_window_size;
  recipient_ctx->rollback_last_seq = 0;
  recipient_ctx->sliding_window = 0;
  recipient_ctx->rollback_sliding_window = 0;
  recipient_ctx->initial_state = 1;
  recipient_ctx->next_recipient = ctx_rcp; 
  ctx->recipient_chain = recipient_ctx;
  ctx->recipient_context = recipient_ctx;
  return recipient_ctx;
}
 
void
oscore_add_pair_keys(oscore_ctx_t *ctx,  
  uint8_t *pairwise_recipient_key,
  uint8_t pairwise_recipient_key_len,
  uint8_t *pairwise_sender_key,
  uint8_t pairwise_sender_key_len)
{
  ctx->mode = OSCORE_PAIR;
  if (pairwise_recipient_key != NULL){
	ctx->recipient_context->pairwise_recipient_key = 
	                          coap_malloc(pairwise_recipient_key_len);
	memcpy(ctx->recipient_context->pairwise_recipient_key, 
	             pairwise_recipient_key, pairwise_recipient_key_len);
	ctx->recipient_context->pairwise_recipient_key_len = 
	                                      pairwise_recipient_key_len;
  }
  if (pairwise_sender_key != NULL){
	ctx->sender_context->pairwise_sender_key = 
	                          coap_malloc(pairwise_sender_key_len);
	memcpy(ctx->sender_context->pairwise_sender_key, 
	             pairwise_sender_key, pairwise_sender_key_len);
	ctx->sender_context->pairwise_sender_key_len = 
	                                      pairwise_sender_key_len;
  }
  if (coap_get_log_level() >= LOG_INFO){ 
      int key_len= 0;
      key_len = ctx->sender_context->pairwise_sender_key_len;
      if (key_len > 0) {
        fprintf(stderr,"   sender pairwise key:\n");
        for (int qq = 0; qq <key_len; qq++)
             fprintf(stderr,"%02x",
                     ctx->sender_context->pairwise_sender_key[qq]);
        fprintf(stderr,"\n");
      }
      key_len = ctx->recipient_context->pairwise_recipient_key_len;
      if (key_len > 0) {
        fprintf(stderr,"recipient pairwise key:\n");
        for (int qq = 0; qq <key_len; qq++)
             fprintf(stderr,"%02x",
                     ctx->recipient_context->pairwise_recipient_key[qq]);
        fprintf(stderr,"\n");
      }
  }
}
   
   
void
oscore_add_group_keys(oscore_ctx_t *ctx,  
   uint8_t *snd_public_key, 
   uint8_t *snd_private_key,
   uint8_t *rcv_public_key,
   uint8_t *rcv_private_key)
{                       
    ctx->mode = OSCORE_GROUP;

    if (snd_private_key != NULL){
	  ctx->sender_context->private_key = 
	                        coap_malloc(Ed25519_PRIVATE_KEY_LEN);
      memcpy(ctx->sender_context->private_key, snd_private_key,  
                                        Ed25519_PRIVATE_KEY_LEN);
      ctx->sender_context->private_key_len = 
                                         Ed25519_PRIVATE_KEY_LEN;
    }
    if (snd_public_key != NULL){
	  ctx->sender_context->public_key = 
	                        coap_malloc(Ed25519_PUBLIC_KEY_LEN);
      memcpy(ctx->sender_context->public_key, snd_public_key,  
                                        Ed25519_PUBLIC_KEY_LEN);
      ctx->sender_context->public_key_len = 
                                          Ed25519_PUBLIC_KEY_LEN;
    }

    if (rcv_public_key != NULL){
	  ctx->recipient_context->public_key = 
	                        coap_malloc(Ed25519_PUBLIC_KEY_LEN);
      memcpy(ctx->recipient_context->public_key, rcv_public_key,  
                                        Ed25519_PUBLIC_KEY_LEN); 
      ctx->recipient_context->public_key_len = 
                                          Ed25519_PUBLIC_KEY_LEN;
    } 
    if (rcv_private_key != NULL){
	  ctx->recipient_context->private_key = 
	                        coap_malloc(Ed25519_PRIVATE_KEY_LEN);
      memcpy(ctx->recipient_context->private_key, rcv_private_key,  
                                        Ed25519_PRIVATE_KEY_LEN); 
      ctx->recipient_context->private_key_len = 
                                          Ed25519_PRIVATE_KEY_LEN;
    } 
    if (coap_get_log_level() >= LOG_INFO){ 
      int key_len= 0;
      key_len = ctx->sender_context->private_key_len;
      if (key_len > 0) {
        fprintf(stderr,"sender private key:\n");
        for (int qq = 0; qq <key_len; qq++)
             fprintf(stderr,"%02x",
                     ctx->sender_context->private_key[qq]);
        fprintf(stderr,"\n");
      }
      key_len = ctx->sender_context->public_key_len;
      if (key_len > 0) {
        fprintf(stderr,"sender public key:\n");
        for (int qq = 0; qq <key_len; qq++)
             fprintf(stderr,"%02x",
                     ctx->sender_context->public_key[qq]);
        fprintf(stderr,"\n");
      }
      key_len = ctx->recipient_context->public_key_len;
      if (key_len > 0) {
        fprintf(stderr,"recipient public key:\n");
        for (int qq = 0; qq <key_len; qq++)
             fprintf(stderr,"%02x",
                     ctx->recipient_context->public_key[qq]);
        fprintf(stderr,"\n");
      }
      key_len = ctx->recipient_context->private_key_len;
      if (key_len > 0) {
        fprintf(stderr,"recipient private key:\n");
        for (int qq = 0; qq <key_len; qq++)
             fprintf(stderr,"%02x",
                     ctx->recipient_context->private_key[qq]);
        fprintf(stderr,"\n");
      }
    }  
}

   
void
oscore_add_group_algorithm(oscore_ctx_t *ctx,  
   int8_t  counter_signature_algorithm,
   uint8_t *counter_signature_parameters,
   uint8_t counter_signature_parameters_len)
{
    ctx->counter_signature_algorithm = 
                            counter_signature_algorithm;
    ctx->counter_signature_parameters = coap_malloc(
                            counter_signature_parameters_len); 
    memcpy(ctx->counter_signature_parameters, counter_signature_parameters,
              counter_signature_parameters_len);
    ctx->counter_signature_parameters_len = counter_signature_parameters_len;
    size_t cbor_len = 0;                       
    if (coap_get_log_level() >= LOG_INFO){ 
	    cbor_len = counter_signature_parameters_len;
      if (cbor_len > 0) {
        fprintf(stderr,"counter signature parameters:\n");
        for (int qq = 0; qq <cbor_len; qq++)
             fprintf(stderr,"%02x",
                     ctx->counter_signature_parameters[qq]);
        fprintf(stderr,"\n");
      }
   }  
}


int _strcmp(const char *a, const char *b){
  if( a == NULL && b != NULL){
    return -1;
  } else if ( a != NULL && b == NULL) {
    return 1;
  } else if ( a == NULL && b == NULL) {
    return 0;
  }
  return strcmp(a,b);
}		

