/*
 * Copyright (c) 2018, Fairhair
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
 * THIS SOFTWARE IS PROVIDED BY THE ALLIANCE AND CONTRIBUTORS ``AS IS'' AND
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
 *      An implementation of the GROUP handling of OSCORE .
 * \author
 *      Peter van der Stok <consultancy@vanderstok.org>
 *      on request of Fairhair alliance
 */
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <ctype.h>
#include "oscore.h"
#include "oscore-context.h"
#include "cbor.h"
#include "cose.h"
#include "utlist.h"
#include "coap.h"
#include <stddef.h>
#include "coap.h"
#include "cbor.h"
#include "mem.h"
#include "oscore-crypto.h"
#include "oscore-group.h"
#include "coap_debug.h"
#include "oscore_oauth.h"
#include "cbor_decode.h"

static GM_group_t *GM_groups = NULL;


/* GM_enter_group
 * enters new group into set of groups
 */
void
GM_enter_group(GM_group_t *group)
{
   group->next = GM_groups;
   GM_groups = group;
}

/* GM_delete_group
 * deletes group and members
 */
void
GM_delete_group(GM_group_t *group){
	
	GM_member_t *memb = group->members;
    GM_member_t *curm = NULL;
    GM_policy_t *pol = group->group_policies;
    GM_policy_t *polm = NULL;
	while (memb != NULL){
      curm = memb;
	  memb = memb->next;
	  if (curm->return_uri != NULL)coap_free(curm->return_uri);
	  if (curm->client_id != NULL) coap_free(curm->client_id);
	  if(curm->public_key != NULL) coap_free(curm->public_key);
	  coap_free(curm);
	}
	while (pol != NULL){
		polm = pol;
		pol = pol->next;
		coap_free(polm);
	}
	if (group->attributes != NULL)oauth_delete_conf(group->attributes);
	if (group->group_name != NULL)coap_free(group->group_name);
    if (group->group_title != NULL)coap_free(group->group_title);
	if (group->joining_uri != NULL)coap_free(group->joining_uri);
	if (group->as_uri != NULL)coap_free(group->as_uri);			
	coap_free(group);
}

/* GM_return_kty
 * returns crv from cbor array [ kty, crv]
 */
int8_t 
GM_return_kty(uint8_t *data){
	uint8_t     elem = cbor_get_next_element(&data);
	if (elem != CBOR_ARRAY) return 255;
	size_t len = cbor_get_element_size(&data);
	if (len != 2) return 255;
	/* array with two elements expected */
    int64_t mm = 0;
	uint8_t ok = cbor_get_number(&data, &mm);
    if (ok == 0) return (uint8_t)mm;
    else return 255;
}

/* GM_return_crv
 * returns crv from cbor array [ kty, crv]
 */
int8_t
GM_return_crv(uint8_t *data){
    uint8_t     elem = cbor_get_next_element(&data);
	if (elem != CBOR_ARRAY) return 255;
	size_t len = cbor_get_element_size(&data);
	if (len != 2) return 255;
	/* array with two elements expected */
    int64_t mm = 0;
	uint8_t ok = cbor_get_number(&data, &mm);
	if (ok == 0)ok = cbor_get_number(&data, &mm);
    if (ok == 0) return (uint8_t)mm;
    else return 255;
}

/* GM_decode_pubkey
 * Decodes map of a single public key used in the group
 */
uint8_t
GM_decode_pubkey(unsigned char **databuf, oauth_cnf_t *conf)
{ 
  uint8_t  ok = 0;
  int16_t  tag = 0;
  int64_t  mm = 0;
  uint8_t  *kid = NULL;
  uint8_t  *pub_key = NULL;
  int8_t   op;
  uint8_t elem = cbor_get_next_element(databuf);
  if (elem == CBOR_MAP){ 
    uint64_t map_size = cbor_get_element_size(databuf);
    for (uint16_t i=0 ; i < map_size; i++){
      tag = cose_get_tag(databuf);
      switch (tag){
        case COSE_KCP_KTY:
          ok = cbor_get_number(databuf, &mm);
          if (ok == 0){
            conf->kty = (int8_t)mm;
          }
          break;
        case COSE_KTP_CRV:
          ok = cbor_get_number(databuf, &mm);
          if (ok == 0){
            conf->crv = (int8_t)mm;
          }
          break;
        case COSE_KCP_KID:
          ok = cbor_get_string_array(databuf, &kid, 
                                           &conf->server_id_len);
          conf->server_id = kid;
          break;
        case COSE_KTP_X: 
          ok = cbor_get_string_array(databuf, &pub_key,
                                            &conf->pub_key_len);
          conf->pub_key = pub_key;
          if (conf->pub_key_len != 32) return 1;
          break;
        case COSE_KCP_ALG:
          if(cbor_get_number(databuf, &mm) == 1)  return 1;
          conf->cs_alg = (int8_t)mm;
          break;
        case COSE_KCP_KEYOPS:
          elem = cbor_get_next_element(databuf);
          if (elem == CBOR_ARRAY){
            uint64_t sz = cbor_get_element_size(databuf);
            if (sz != 2) return 1;
            for (uint16_t qq = 0; qq < sz; qq++){
              if(cbor_get_number(databuf, &mm) == 1) return 1;
              op = (int8_t)mm;
              if (op != COSE_KOP_SIGN && op != COSE_KOP_VERIFY)
                                                        return 1;
            } /* for sz */
          } /* if elem */
          else return 1;
          break;
        default:
          ok = 1;
          break;
      } /* switch  */ 
      if (ok != 0){
        coap_log(LOG_WARNING," cannot decode key array element \n");
        return ok;
      } /* if ok */
    } /* for   map_size  */
  } /* CBOR_MAP */
  else{
    coap_log(LOG_WARNING," no map returned \n");
    return 1;
  }
  return ok;
}

/* GM_decode_pubkeys
 * returns the number of public keys that are present
 */
uint8_t
GM_decode_pubkeys(unsigned char **databuf)
{ 
  uint8_t elem = cbor_get_next_element(databuf);
  if (elem != CBOR_BYTE_STRING) return 1;
  cbor_get_element_size(databuf);
/* size of BYTE STRING size is irrelevant here */
  elem = cbor_get_next_element(databuf);
  if (elem != CBOR_ARRAY) return 0; 
  return cbor_get_element_size(databuf);
}


/* GM_read_policy
 * reads the policies from databuf
 * returns policy when policies found
 */
static GM_policy_t *
GM_read_policy(unsigned char **databuf){
  uint8_t  elem = cbor_get_next_element(databuf);
  uint8_t  ok =0;
  int64_t  mm = 0;
  uint8_t  bl = 0;
  GM_policy_t *policy = coap_malloc(sizeof(GM_policy_t));
  memset(policy, 0, sizeof(GM_policy_t));
  if (elem == CBOR_MAP){ 
    uint64_t map_size = cbor_get_element_size(databuf);
    for (uint16_t i=0 ; i < map_size; i++){
      int16_t tag = cose_get_tag(databuf);
      switch (tag){
        case POLICY_SYNCHRO_METHOD:
          ok = cbor_get_number(databuf, &mm);
          if(ok == 0)policy->synch_method = mm;
          break;
        case POLICY_CHECK_INTERVAL:
          ok = cbor_get_number(databuf,&mm);
          if(ok == 0)policy->check_interval = mm;
          break;
        case POLICY_PAIRWISE_MODE:
          ok = cbor_get_simple_value(databuf, &bl);
          if(ok == 0){
			  if (bl == CBOR_FALSE)policy->pairwise_mode = 1;
			  else policy->pairwise_mode = 0;
		  }
          break;
        case POLICY_EXPIRATION_DELTA:
          ok = cbor_get_number(databuf, &mm);
          if(ok == 0)policy->expiration_delta = mm;
          break;                    
        default:
          ok = 1;
          break;
      } /* switch  */ 
      if(ok != 0){
        coap_log(LOG_WARNING," policies could not be read \n");
        coap_free(policy);
        return NULL;
      }	/* if ok */
    }  /* for */ 
    return policy;
  }  /* if elem  */
  coap_free(policy);
  return NULL;
}

/* GM_read_object_keys
 * reads configuration of object security object
 * followed by configurations of public keys
 */
oauth_cnf_t *
GM_read_object_keys(unsigned char **databuf,uint8_t **keys){
  int64_t     mm = 0;
  size_t      size = 0;
  uint8_t     ok = 0;
  int16_t     tag = 0;
  oauth_cnf_t *conf = NULL;
  GM_policy_t *policy = NULL;
  
  *keys = NULL;
  uint8_t  elem = cbor_get_next_element(databuf);
  if (elem == CBOR_MAP){ 
    uint64_t map_size = cbor_get_element_size(databuf);
    for (uint16_t i=0 ; i < map_size; i++){
      tag = cose_get_tag(databuf);
      switch (tag){
        case GRP_TAG_GKTY: 
          ok = cbor_get_number(databuf, &mm);
          if (ok == 0) if (mm != Group_OSCORE_Security_Context_Object) ok = 1;
          break;
        case GRP_TAG_KEY:
          conf = oauth_read_OSCORE_security_context(databuf);
          if( conf == NULL) return NULL;
          break;
        case GRP_TAG_PUBKEYS:
          *keys = *databuf;  /* remember start of keys */
          elem = cbor_get_next_element(databuf);
          size = cbor_get_element_size(databuf);
          *databuf = *databuf + size; 
          break;
        case GRP_TAG_NUM:
          ok = cbor_get_number(databuf, &mm);
          if (ok == 0) conf->num = (size_t)mm;
          break;
        case GRP_TAG_ACEGROUPCOMMPROFILE:
          ok = cbor_get_number(databuf, &mm);
          if (ok == 0) if (mm != COAP_GROUP_OSCORE_APP) ok = 1;
          break;
        case GRP_TAG_EXP:
          ok = cbor_get_number(databuf, &mm);
          if (ok == 0){
            conf->exp = (uint64_t)mm;
            if (conf->exp == 0) ok = 1;
		  }
		  break;
        case GRP_TAG_GROUPPOLICIES:
          policy = GM_read_policy(databuf);
 /* not clear what to with policy  */
          coap_free(policy);
          break;
        default:
          ok = 1;
          break;
      } /* switch  */ 
      if(ok != 0){
        coap_log(LOG_WARNING," Join decode routine could not process payload \n");
        if (conf != NULL)oauth_delete_conf(conf);
        return NULL;
      }
    } /* for   map_size  */
  } /* CBOR_MAP */
  else{
    coap_log(LOG_WARNING," no map returned \n");
    return NULL;
  }
  return conf;
}


/* GM_create_scope
 * fills scope for C0, C1 and C2
 */
size_t
GM_create_scope(uint8_t **scopep, uint8_t client){
  char group[] = "GRP";
  size_t scope_len = 0;

  scope_len += cbor_put_array(scopep, 2);
  scope_len += cbor_put_text(scopep, group, strlen(group));
  switch (client){
    case 4: /* create group authorization  */
    case 0: /* create group  */
      scope_len += cbor_put_number(scopep, SCOPE_ROLE_ADMINISTRATOR);
      break;
    case 5:  /* C1 authorization  */
    case 1:  /* C1 joins */
      scope_len += cbor_put_number(scopep, SCOPE_ROLE_MONITOR);
      break;
    case 6:  /* C2 authorization  */
    case 2:  /* C2 joins */
      scope_len += cbor_put_number(scopep, 
              SCOPE_ROLE_RESPONDER | SCOPE_ROLE_REQUESTER);
      break;
    case 7:  /* C0 authorization  */
    case 3:  /* C0 joins  */
      scope_len += cbor_put_number(scopep, SCOPE_ROLE_REQUESTER);
      break;
    default:
      break;
  }/* case */
  return scope_len;
}
   

/* GM_create_OSCORE_Security_context
 * fills OSCORE security context into CBOR map
*/
static size_t
GM_create_OSCORE_Security_context(uint8_t **buf, oauth_cnf_t *param){
  size_t  nr = 0;
  size_t  map_size = 3;
  uint8_t *map_buf = *buf;
  uint8_t **bufpt = &map_buf;
  nr += cbor_put_map(buf, map_size); /* provisional  */
  nr += cbor_put_number(buf, OSCORE_CONTEXT_ALG);
  nr += cbor_put_number(buf, param->alg);
  if ((param->ms != NULL) && (param->ms_len > 0)){
    nr += cbor_put_number(buf, OSCORE_CONTEXT_MS);
    nr += cbor_put_bytes(buf,  param->ms, param->ms_len);
    map_size++;
  }
  nr += cbor_put_number(buf, OSCORE_CONTEXT_HKDF);
  nr += cbor_put_number(buf, param->hkdf);
  if ((param->salt != NULL) && (param->salt_len > 0)){
    nr += cbor_put_number(buf, OSCORE_CONTEXT_SALT);
    nr += cbor_put_bytes(buf,  param->salt, param->salt_len);
    map_size++;
  }
  if ((param->context_id != NULL) && (param->context_id_len> 0)){
    nr += cbor_put_number(buf, OSCORE_CONTEXT_CONTEXTID);
    nr += cbor_put_bytes(buf,  (uint8_t *)param->context_id, 
                                (uint8_t)param->context_id_len);
    map_size++;
  }
  if ((param->client_id != NULL) && (param->client_id_len > 0)){
    nr += cbor_put_number(buf, OSCORE_CONTEXT_CLIENTID);
    nr += cbor_put_bytes(buf,  (uint8_t *)param->client_id, 
                                 (uint8_t)param->client_id_len);
    map_size++;
  }
  if ((param->server_id != NULL) && (param->server_id_len > 0)){
    nr += cbor_put_number(buf, OSCORE_CONTEXT_SERVERID);
    nr += cbor_put_bytes(buf,  (uint8_t *)param->server_id, 
                                 (uint8_t)param->server_id_len);
    map_size++;
  }
  nr += cbor_put_number(buf, OSCORE_CONTEXT_RPL);
  nr += cbor_put_number(buf, param->rpl);
  if (param->profile == COAP_GROUP_OSCORE_APP){
    nr += cbor_put_number(buf, OSCORE_CONTEXT_CSALG);
    nr += cbor_put_number(buf, param->cs_alg);
    nr += cbor_put_number(buf, OSCORE_CONTEXT_CSPARAMS);
    nr += cbor_put_bytes(buf, param->cs_params, param->cs_params_len);
    nr += cbor_put_number(buf, OSCORE_CONTEXT_CSKEYPARAMS);
    nr += cbor_put_bytes(buf, param->cs_key_params, param->cs_key_params_len);
    nr += cbor_put_number(buf, OSCORE_CONTEXT_CSKEYENC);
    nr += cbor_put_number(buf, CWT_KEY_COSE_KEY);
    map_size = map_size + 4;
  }
  cbor_put_map(bufpt, map_size); /* definite map size  */
  return nr;
}


/* GM_create_OSCORE_Security_context_object
 * fills OSCORE security context object in group request to GM
*/
size_t
GM_create_OSCORE_Security_context_object(uint8_t **buf, 
           size_t map_size, GM_group_t *group){
  int nr = 0;
  oauth_cnf_t *attributes = group->attributes;
  nr += cbor_put_map   (buf, map_size);
  nr += cbor_put_number(buf, GRP_TAG_GKTY);
  nr += cbor_put_number  (buf, Group_OSCORE_Security_Context_Object);
  nr += cbor_put_number(buf, GRP_TAG_KEY);
/* the key tag has as value 
 * the contents of the Group_OSORE_SECURITY Context object
 */
  nr += GM_create_OSCORE_Security_context(buf, attributes);
  nr += cbor_put_number(buf, GRP_TAG_ACEGROUPCOMMPROFILE);
  nr += cbor_put_number(buf, COAP_GROUP_OSCORE_APP);
  nr += cbor_put_number(buf, GRP_TAG_EXP);
  nr += cbor_put_number(buf, 1444060944);
  nr += cbor_put_number(buf, GRP_TAG_NUM);
  nr += cbor_put_number(buf, attributes->num);
  if (group->group_policies != NULL){
	  /* assume that there is only one policy */
    nr += cbor_put_number(buf, GRP_TAG_GROUPPOLICIES);
    nr += cbor_put_map   (buf, 4);
    nr += cbor_put_number(buf, POLICY_SYNCHRO_METHOD);
    nr += cbor_put_number(buf, group->group_policies->synch_method);
    nr += cbor_put_number(buf, POLICY_CHECK_INTERVAL);
    nr += cbor_put_number(buf, group->group_policies->check_interval);
    nr += cbor_put_number(buf, POLICY_EXPIRATION_DELTA);
    nr += cbor_put_number(buf, group->group_policies->expiration_delta);
    nr += cbor_put_number(buf, POLICY_PAIRWISE_MODE);
    if (group->group_policies->pairwise_mode == 0)
      nr += cbor_put_simple_value(buf, CBOR_FALSE);
    else 
      nr += cbor_put_simple_value(buf, CBOR_TRUE);
  }
  return nr;
}


/* GM_create_token
 * fills request to GM for group join authorization
*/
size_t
GM_create_token(uint8_t **token, oauth_cnf_t *conf, int GM_choice)
{
  char    issuer[] = "coap://as.vanderstok.org";
  char    audience[] = "coap://gm.vanderstok.org";
  uint16_t cti_cont = (uint16_t)rand();
  uint8_t *cti_pt  = (uint8_t *)&cti_cont;
  uint8_t scope_buf[100];
  uint8_t *scopep = scope_buf;
  uint8_t scope_len = 0;

  size_t len = 0;
  len += cbor_put_map(token, 8);
  len += cbor_put_number(token, CWT_CLAIM_ISS);
  len += cbor_put_text(token, issuer, strlen(issuer));
  len += cbor_put_number(token, CWT_CLAIM_AUD);
  len += cbor_put_text(token, audience, strlen(audience));
  len += cbor_put_number(token, CWT_CLAIM_EXP);
  len += cbor_put_number(token, 1444060944);
  len += cbor_put_number(token, CWT_CLAIM_IAT);
  len += cbor_put_number(token, 1444060944);
  len += cbor_put_number(token, CWT_CLAIM_CTI);
  len += cbor_put_bytes(token, cti_pt, 2);
  len += cbor_put_number(token, CWT_CLAIM_SCOPE);
  scope_len = GM_create_scope(&scopep, GM_choice);
  len += cbor_put_bytes(token, scope_buf, scope_len);
  len += cbor_put_number(token, CWT_CLAIM_PROFILE);
  len += cbor_put_number(token, conf->profile);
  len += cbor_put_number(token, CWT_CLAIM_CNF);
/* establishes oscore security context between Client and GM */
  len += cbor_put_map(token, 1);
  len += cbor_put_number(token, CWT_OSCORE_SECURITY_CONTEXT);
  len += GM_create_OSCORE_Security_context(token, conf);
  return len;
}

/* GM_create_credp
 * fills credp with public_key parameter
 */
size_t
GM_create_credp(uint8_t **credp, uint8_t *public_key){
  size_t clientcred_len = 0;
  clientcred_len += cbor_put_map(credp, 5);
  clientcred_len += cbor_put_number(credp, COSE_KCP_KTY);
  clientcred_len += cbor_put_number(credp, COSE_KTY_OKP);
  clientcred_len += cbor_put_number(credp, COSE_KTP_CRV);
  clientcred_len += cbor_put_number(credp,
                                   COSE_Elliptic_Curve_Ed25519);
  clientcred_len += cbor_put_number(credp, COSE_KCP_ALG);
  clientcred_len += cbor_put_array(credp, 2);
  clientcred_len += cbor_put_number(credp,
                                         COSE_Algorithm_EdDSA);
  clientcred_len += cbor_put_number(credp,
                                    COSE_Elliptic_Curve_Ed25519);
  clientcred_len += cbor_put_number(credp, COSE_KCP_KEYOPS);
  clientcred_len += cbor_put_array(credp, 2);
  clientcred_len += cbor_put_number(credp, COSE_KOP_VERIFY);
  clientcred_len += cbor_put_number(credp, COSE_KOP_SIGN);
  clientcred_len += cbor_put_number(credp, COSE_KTP_X);
  clientcred_len += cbor_put_bytes(credp, public_key, 32);
  return clientcred_len;
}

 
/* GM_get_clientcred
 * fills the join_request with public key info
 * from the received CBOR map
 */
static uint8_t
GM_get_clientcred(uint8_t **data, joinreq_t *jr){
  int16_t tag = 0;
  uint8_t elem = cbor_get_next_element(data);
  if (elem == CBOR_BYTE_STRING ){
     cbor_get_element_size(data); 
                    /* length of byte array is irrelevant  */
  }else return 1;
  elem = cbor_get_next_element(data);
  if (elem == CBOR_MAP){
    uint64_t cred_map_size = cbor_get_element_size(data);
       /*size of map */
    for (uint16_t i=0 ; i < cred_map_size; i++){
      tag = cose_get_tag(data);
      int64_t mm;
      if (tag == UNDEFINED_TAG){
        coap_log(LOG_WARNING, "Illegal CBOR contents\n");
        return 1;
      }
      size_t len = 0;
      switch (tag){
        case COSE_KCP_KTY: 
        default:
          elem = cbor_get_next_element(data);
          if (elem == CBOR_UNSIGNED_INTEGER)
                       jr->kty = cbor_get_unsigned_integer(data);
          else return 1;
          break;
        case COSE_KCP_ALG:
          elem = cbor_get_next_element(data);
          if (elem == CBOR_ARRAY){
            uint64_t sz = cbor_get_element_size(data);
            if (sz == 2){
              if(cbor_get_number(data, &mm) == 1) return 1;
              jr->cs_alg = (int8_t)mm;
              if(cbor_get_number(data, &mm) == 1) return 1; 
              jr->cs_param = (int8_t)mm;            
            } /* if sz */
          } /* if elem */
          break;
        case COSE_KTP_CRV:
          if (cbor_get_number(data, &mm) != 0) return 1;
          if (mm != COSE_Elliptic_Curve_Ed25519) return 1;
          break;
        case COSE_KCP_KEYOPS: 
          elem = cbor_get_next_element(data);
          if (elem == CBOR_ARRAY){
            jr->key_ops_len = cbor_get_element_size(data);
            jr->key_ops = coap_malloc(jr->key_ops_len);
            jr->key_ops[0] = cbor_get_unsigned_integer(data);
            jr->key_ops[1] = cbor_get_unsigned_integer(data);
          } 
          else return 1;
          break;
        case COSE_KTP_X: 
          if(cbor_get_string_array(data, &(jr->pub_key), &len)
                                                 == 1) return 1;
          jr->pub_key_len = (size_t)len;
          break;
      } /* switch */
    } /* for */
  }  /* if */
  return 0;
}


/* GM_delete_jr
 * frees memory of join_request
 */
void
GM_delete_jr( joinreq_t *jr){
  if (jr != NULL){
    if(jr->pub_keys_repos != NULL) coap_free(jr->pub_keys_repos);
    if(jr->get_pub_keys != NULL) coap_free(jr->get_pub_keys);
    if(jr->scope != NULL)coap_free(jr->scope);
    if(jr->pub_key != NULL)coap_free(jr->pub_key);
    if(jr->signature != NULL)coap_free(jr->signature);
    if(jr->key_ops != NULL)coap_free(jr->key_ops);
    if(jr->return_uri != NULL)coap_free(jr->return_uri);
    coap_free(jr);
  }
}


/* GM_get_scope
 * returns scope from data
 */
GM_scope_t *
GM_get_scope(uint8_t *data){
	uint8_t     elem = cbor_get_next_element(&data);
	if (elem != CBOR_BYTE_STRING ) return NULL;
	uint64_t  len = cbor_get_element_size(&data);
	elem = cbor_get_next_element(&data);
	if (elem != CBOR_ARRAY) return NULL;
	len = cbor_get_element_size(&data);
	if (len != 2) return NULL;
	/* array with two elements expected */
	GM_scope_t *scope = coap_malloc(sizeof(GM_scope_t));
    uint8_t ok = cbor_get_string_array(&data, &scope->group_id, &scope->group_id_len);
    if (ok == 0){
		int64_t mm = 0;
		ok = cbor_get_number(&data, &mm);
		scope->roles = (uint32_t)mm;
	}
    if (ok != 0 ) {
		coap_free(scope);
		return NULL;
	}
	return scope;
}

/* GM_print_group
 * prints contents of group and members
 */
void
GM_print_group(GM_group_t *group){
  if (coap_get_log_level() < LOG_INFO) return;
  GM_member_t *member;
  fprintf(stderr,"-------------- GROUP ----------\n");
  if (group == NULL)fprintf(stderr, "empty group \n");
  else {
    fprintf(stderr," group name  ");
    for (size_t i=0; i < group->group_name_len; i++)
                         fprintf(stderr,"%c",group->group_name[i]);
    fprintf(stderr,"\n group epoch  %d \n",(int)group->epoch);
    fprintf(stderr," group active ");
    if (group->active == 0) fprintf(stderr," FALSE ");
    else fprintf(stderr, " TRUE ");
    fprintf(stderr,"\n group title  ");
    if (group->group_title == NULL) fprintf(stderr, "  (NIL) ");
    else {
       for (size_t i=0; i < group->group_title_len; i++)
                         fprintf(stderr,"%c",group->group_title[i]);
    }
    fprintf(stderr,"\n group profile  ");
       fprintf(stderr,"    %d ", group->group_profile);
    fprintf(stderr,"\n joining uri  ");
    if (group->joining_uri == NULL) fprintf(stderr, "  (NIL) ");
    else {
       for (size_t i=0; i < group->joining_uri_len; i++)
                         fprintf(stderr,"%c",group->joining_uri[i]);                         
    }
    fprintf(stderr,"\n Authorization Server (AS) uri  ");
    if (group->as_uri == NULL) fprintf(stderr, "  (NIL) ");
    else {
       for (size_t i=0; i < group->as_uri_len; i++)
                         fprintf(stderr,"%c",group->as_uri[i]);                         
    }   
    fprintf(stderr,"\n"); 
    oauth_print_conf(group->attributes);
    member = group->members;
    fprintf(stderr," number of members  %d \n", 
                                       (int)group->members_len);
    fprintf(stderr,"members:   \n");
    while (member != NULL){
      fprintf(stderr,"      client_id:  ");
      for (uint16_t q = 0; q < member->client_id_len; q++)
        fprintf(stderr,"%c",member->client_id[q]);
      fprintf(stderr,"\n");
      fprintf(stderr,"      server_id:  ");
      for (uint16_t q = 0; q < member->server_id_len; q++)
                      fprintf(stderr,"%c",member->server_id[q]);
      fprintf(stderr,"\n");
      fprintf(stderr,"      key_ops:  ");
      for (uint16_t q = 0; q < member->key_ops_len; q++)
                    fprintf(stderr," %d  ",member->key_ops[q]);
      fprintf(stderr," \n");
      fprintf(stderr,"      public_key:  ");
      for (uint16_t q = 0; q < member->public_key_len; q++)
                    fprintf(stderr,"%02x",member->public_key[q]);
      fprintf(stderr,"\n Return uri  ");
      if (member->return_uri == NULL) fprintf(stderr, "  (NIL) ");
      else {
        for (size_t i=0; i < member->return_uri_len; i++)
                         fprintf(stderr,"%c",member->return_uri[i]);                         
      }
      if (member->scope != NULL){
		uint8_t *pt = (uint8_t *)member->scope;
        fprintf(stderr,"\n      scope: ");
        print_cbor(&pt);
        fprintf(stderr,"\n");
      }
      fprintf(stderr," member -> next   %p \n",
                                   (void *)member->next);
      member = member->next;
    } /* while member */
    if (group->group_policies != NULL){
	  fprintf(stderr,"number of  group policies  %d \n",(int)group->group_policies_nr);
	  GM_policy_t *policy = group->group_policies;
	  int8_t nr = 1;
	  while (policy != NULL){
	    fprintf(stderr,"    policy  %d \n", (int)nr);
	    fprintf(stderr,"       synch_method   %d  with  check_interval  %d  seconds\n", (int)policy->synch_method, (int)policy->check_interval);
	    fprintf(stderr,"       expiration delta %d     pairwise mode  %d  (T/F)\n", (int)policy->expiration_delta, (int)policy->pairwise_mode);
	    policy = policy->next;
	    nr ++;
	  }   /* while */
	} /* if group policies  */
	else 
    fprintf(stderr,"no group policies present\n");
  } /* if group */
}

/* GM_print_jr
 * prints contents of join request
 */
void
GM_print_jr(joinreq_t *jr){
  if (coap_get_log_level() < LOG_DEBUG) return;
  if (jr != NULL){
    fprintf(stderr,"--------------Join request ----------\n");
    fprintf(stderr, "  kty:        %d \n", (int)jr ->kty);
    fprintf(stderr, "  cs_alg:     %d \n", (int)jr ->cs_alg);
    fprintf(stderr, "  cs_param:   %d \n", (int)jr ->cs_param);
    fprintf(stderr," get_pub_keys:  ");
    for (uint16_t q = 0; q < jr->get_pub_keys_len; q++)
      fprintf(stderr,"%02x",jr->get_pub_keys[q]);
    fprintf(stderr,"\n");
    fprintf(stderr," pub_key: ");
    for (uint16_t q = 0; q < jr->pub_key_len; q++)
      fprintf(stderr,"%02x",jr->pub_key[q]);
    fprintf(stderr,"\n");      
    fprintf(stderr," return_uri: ");
    for (uint16_t q = 0; q < jr->return_uri_len; q++)
      fprintf(stderr,"%c",jr->return_uri[q]);
    fprintf(stderr,"\n");
    fprintf(stderr," signature: ");
    for (uint16_t q = 0; q < jr->signature_len; q++)
      fprintf(stderr,"%02x",jr->signature[q]);
    fprintf(stderr,"\n");
    fprintf(stderr," cnonce: ");
    for (uint16_t q = 0; q < jr->cnonce_len; q++)
      fprintf(stderr,"%02x",jr->cnonce[q]);
    fprintf(stderr,"\n");
    fprintf(stderr," pub_keys_repos: ");
    for (uint16_t q = 0; q < jr->pub_keys_repos_len; q++)
      fprintf(stderr,"%02x",jr->pub_keys_repos[q]);
    fprintf(stderr,"\n");
    fprintf(stderr," keys_ops: ");
    for (uint16_t q = 0; q < jr->key_ops_len; q++)
      fprintf(stderr,"  %d  ",jr->key_ops[q]);
    fprintf(stderr,"\n");
    if (jr->scope != NULL){
      fprintf(stderr, " scope:  "); 
      uint8_t *pt = (uint8_t *)jr->scope;
      print_cbor(&pt);
    }
    fprintf(stderr,"\n");
  } /* if */
}

/* GM_jr_to_member
 * moves contents of join-request to group-member
 * sets corresponding join-request pointers to NULL
 */
void
GM_jr_to_member(joinreq_t *jr, GM_member_t *member,
                                 GM_group_t *group){

  uint8_t monitor_only = 0; /* test on monitor */
  if (jr->scope != NULL){
	 GM_scope_t *scope = GM_get_scope(jr->scope);
	 if (scope != NULL){
         if(scope->roles == SCOPE_ROLE_MONITOR) monitor_only = 1;
         coap_free(scope);
	 }
  } /* if scope  */
  oauth_cnf_t *cnf = group->attributes;
  member->scope = jr->scope;
  member->scope_len = jr->scope_len;
  jr->scope = NULL;
  jr->scope_len = 0;
  member->public_key = jr->pub_key;
  member->public_key_len = jr-> pub_key_len;
  jr->pub_key = NULL;
  jr->pub_key_len = 0;
  member->key_ops = jr->key_ops;
  member->key_ops_len = jr->key_ops_len;
  jr->key_ops = NULL;
  jr->key_ops_len = 0;
  member->return_uri = jr->return_uri;
  member->return_uri_len = jr->return_uri_len;
  jr->return_uri = NULL;
  jr->return_uri_len =0;
  cnf->num++;  /* next version of group  */
  int number = cnf->num/10;
/* assign client_id to member  */
  char member_id[] = "m_00";
  char GRP[] = "GRP00";
  member->server_id_len = 0;
  if (member->client_id != NULL)coap_free(member->client_id);
  if (member->server_id != NULL)coap_free(member->server_id);
  member->server_id = NULL;
  if (cnf->client_id != NULL) coap_free(cnf->client_id);
  cnf->client_id_len = 0;
  cnf->client_id = NULL;
  member->client_id_len = strlen(member_id);
  member->client_id = coap_malloc(member->client_id_len);
  strncpy((char *)member->client_id, member_id,
                                         member->client_id_len);
  
  member->client_id[2] = '0' + number;
  member->client_id[3] = '0' + (cnf->num - 10*number);
  if (monitor_only == 1){
/* client_id is not relevant and not sent back */
    cnf->client_id_len = member->client_id_len;
    cnf->client_id = coap_malloc(member->client_id_len);
    strncpy((char *)cnf->client_id, 
              (char *)member->client_id, member->client_id_len);
  } /* if monitor_only */
/* change group context_id and client_id*/
  if (cnf->context_id != NULL) coap_free(cnf->context_id);
  cnf->context_id_len = strlen(GRP);
  cnf->context_id = coap_malloc(cnf->context_id_len);
  strncpy((char *)cnf->context_id, GRP, cnf->context_id_len);
  int l = strlen(GRP) - 2;
  cnf->context_id[l]   = '0' + number;
  cnf->context_id[l+1] = '0' + (cnf->num - 10*number);
/* change master_secret and master_salt  */
  prng(cnf->ms, cnf->ms_len);
  prng(cnf->salt, cnf->salt_len);
}

 /* Read configuration information from group handle request 
 * data points to map
 */
GM_group_t *
GM_manage_request(uint8_t **databuf)
{
  uint8_t  ok = 0;
  int64_t  mm = 0;
  uint8_t  sv = 0;
  GM_group_t     *group = coap_malloc(sizeof(GM_group_t));
  memset(group, 0, sizeof(GM_group_t)); 
  oauth_cnf_t    *conf = coap_malloc(sizeof(oauth_cnf_t));
  memset(conf, 0, sizeof(oauth_cnf_t));
  uint8_t *local = NULL;
  group->attributes = conf;
  group->group_profile = COAP_GROUP_OSCORE_APP;
  uint16_t  tag = 0;
  uint8_t  elem = cbor_get_next_element(databuf);
  if (elem == CBOR_MAP){ 
    uint64_t map_size = cbor_get_element_size(databuf);
    for (uint16_t i=0 ; i < map_size; i++){
      tag = cose_get_tag(databuf);
      switch (tag){
        case GM_ADMIN_group_name:
          ok = cbor_get_string_array(databuf, &group->group_name, &group->group_name_len);
          break;
        case CWT_CLAIM_EXP:
          ok = cbor_get_number(databuf, &mm);
          if (ok == 0){
            conf->exp = (uint64_t)mm;
            if (conf->exp == 0) ok = 1;
          }
          break;
        case GM_ADMIN_hkdf:
          ok = cbor_get_number(databuf, &mm);
          if (ok == 0){
			  conf->hkdf = (int8_t)mm;
		  }
          break;
        case GM_ADMIN_alg:
          ok = cbor_get_number(databuf, &mm);
          if (ok == 0){
			  conf->alg = (int8_t)mm;
		  }        
          break;
        case GM_ADMIN_cs_alg:
          ok = cbor_get_number(databuf, &mm);
          if (ok == 0){
			  conf->cs_alg = (int8_t)mm;
		  }                
          break;
        case GM_ADMIN_cs_params:
          ok = cbor_get_string_array(databuf, &(conf->cs_params), &(conf->cs_params_len));
          break;
        case GM_ADMIN_cs_key_params:
          ok = cbor_get_string_array(databuf, &(conf->cs_key_params), &(conf->cs_key_params_len));   
          conf->crv = GM_return_crv(conf->cs_params);
          conf->kty = GM_return_kty(conf->cs_params);    
          break;
        case GM_ADMIN_active:
          ok = cbor_get_simple_value(databuf, &sv);
          if (ok == 0){
			  if (sv == CBOR_FALSE){
			      group->active = 0;
			  }
			  else{
				   group->active = 1;
			  }
		  }                
          break;
        case GM_ADMIN_cs_key_enc:
          ok = cbor_get_number(databuf, &mm);
          if (ok == 0){
			  conf->cs_key_enc = (uint8_t)mm;
		  }                
          break;          
        case GM_ADMIN_group_title:
          local = (uint8_t *)group->group_title;
          ok = cbor_get_string_array(databuf, &local, &(group->group_title_len));        
          break;
        case GM_ADMIN_as_uri:
          ok = cbor_get_string_array(databuf, (uint8_t **)&group->as_uri, &(group->as_uri_len));     
          break;
        case GRP_TAG_GROUPPOLICIES:
          group->group_policies = GM_read_policy(databuf);
          group->group_policies_nr = 1;
          break;                                                                               
        default:
          ok = 1;
          break;
      } /* switch  */ 
      if(ok != 0){
        coap_log(LOG_WARNING," GM_manage_request routine could not process payload \n");
        if(group != NULL) GM_delete_group(group);
        return NULL;
      }
    } /* for   map_size  */
  } /* CBOR_MAP */
  else{
    coap_log(LOG_WARNING," no map returned \n");
    return NULL;
  }
  return group;
}


/* REad join request from request map
 * data points to map
 */
joinreq_t *
GM_join_request(uint8_t **data)
{
  int16_t tag = 0;
  uint8_t ok = 0;
  joinreq_t *jr = coap_malloc(sizeof(joinreq_t));
  memset(jr, 0, sizeof(joinreq_t));

  uint8_t elem = cbor_get_next_element(data);
  if (elem == CBOR_MAP){
    uint64_t map_size = cbor_get_element_size(data);
    for (uint16_t i=0; i < map_size; i++){
      tag = cose_get_tag(data);
      ok = 0;
      if (tag == UNDEFINED_TAG){
        coap_log(LOG_WARNING, "Illegal CBOR contents\n");
        ok = 1;
      }
      switch (tag){
        case GRP_TAG_GETPUBKEYS:
          elem = cbor_get_next_element(data);
          if (elem == CBOR_ARRAY){
            jr->get_pub_keys_len = cbor_get_element_size(data);
            jr->get_pub_keys = NULL;
            if (jr->get_pub_keys_len > 0){
              jr->get_pub_keys = coap_malloc(
                                         jr->get_pub_keys_len);
              cbor_get_string(data, (char *)jr->get_pub_keys,
                                 (uint64_t)jr->get_pub_keys_len);
            }  /* jr->pub_key_len  */
          } else ok = 1;
          break;
        case GRP_TAG_PUBKEYSREPOS:
          ok = cbor_get_string_array(data, 
              &(jr->pub_keys_repos), &(jr->pub_keys_repos_len));
          break;
        case GRP_TAG_SCOPE:
          ok = cbor_get_string_array(data, 
                        &(jr->scope), &(jr->scope_len));
          break;
        case GRP_TAG_CLIENTCRED:
          ok = GM_get_clientcred(data, jr);
          break;
        case GRP_TAG_CLIENTCREDVERIFY:
          ok = cbor_get_string_array(data, 
              &(jr->signature), &(jr->signature_len));
          break;
        case GRP_TAG_CNONCE:
          ok = cbor_get_string_array(data, 
              &(jr->cnonce), &(jr->cnonce_len));
          break;
        case GRP_TAG_CONTROLPATH:
           ok = cbor_get_string_array(data,
              (uint8_t **)&(jr->return_uri), &(jr->return_uri_len));
          break;
        default:
          ok = 1;
          break;
      }  /* switch */
      if (ok != 0){
        GM_delete_jr(jr);
        return NULL;
      }
    } /* for loop  */
  } /* CBOR_MAP  */
  return jr;
}

/* GM_cs_params
 * returns cbor array [param_type, [paramtype, param]]
 */
uint8_t *
GM_cs_params(int8_t param, int8_t param_type, size_t *len){
	uint8_t buf[50];
	uint8_t *pt = buf;
    *len = 0;
    *len += cbor_put_array(&pt, 2);
    *len += cbor_put_number(&pt, param_type);
    *len += cbor_put_array(&pt, 2);
    *len += cbor_put_number(&pt, param_type);
    *len += cbor_put_number(&pt, param);
    uint8_t *result = coap_malloc(*len);
    memcpy(result, buf, *len);
    return result;
}

/* GM_cs_key_params
 * returns cbor array [paramtype, param]
 */
uint8_t *
GM_cs_key_params(int8_t param, int8_t param_type, size_t *len){
fprintf(stderr, "address len %p\n", (void *)len);
	uint8_t buf[50];
	uint8_t *pt = buf;
    *len = 0;
    *len += cbor_put_array(&pt, 2);
    *len += cbor_put_number(&pt, param_type);
    *len += cbor_put_number(&pt, param);
    uint8_t *result = coap_malloc(*len);
    memcpy(result, buf, *len);
    return result;
}	

/* GM_prepare_aad
 * prepares aad for GM client and server 
 * to encrypt and decrypt
 */
size_t
GM_prepare_aad(int8_t alg, uint8_t *aad_buffer){
  size_t ret = 0;
  uint8_t buffer[10];
  uint8_t *buf = buffer;
  size_t buf_len = 0;
  buf_len += cbor_put_map(&buf, 1);
  buf_len += cbor_put_number(&buf, COSE_HP_ALG);
  buf_len += cbor_put_number(&buf, alg);
  char encrypt0[] = "Encrypt0";
  /* Begin creating the AAD */
  ret += cbor_put_array(&aad_buffer, 3);
  ret += cbor_put_text(&aad_buffer, encrypt0, strlen(encrypt0));
  ret += cbor_put_bytes(&aad_buffer, buffer, buf_len);
  ret += cbor_put_bytes(&aad_buffer, NULL, 0); 
  return ret;
}

/* GM_find_group
 * find a group with specified name
 */
struct GM_group_t *
GM_find_group(char *name, size_t name_len)
{
  GM_group_t *current = GM_groups;
  while (current != NULL){
    if(current->group_name_len == name_len){
      if(strncmp((char *)current->group_name, name, name_len) == 0)
        return current;
    }
    current = current->next;
  }
  return current;
}

static uint8_t
GM_put_keys( uint8_t **data, GM_group_t *group, 
                               GM_member_t *current)
{
  GM_member_t *member = group->members;
  oauth_cnf_t   *grpatt  = group->attributes;
  uint8_t *key_buf = coap_malloc(500);
  uint8_t *buf = key_buf;
  uint8_t number = 0;
  while (member != NULL){
    if ((member->public_key_len != 0) && (member != current)) 
                                                       number++;
    member = member->next;
  }
  if (number == 0) return cbor_put_array(data,0);
  int sz = cbor_put_array(&buf, number);
  member = group->members;
  while( member != NULL){
    if ((member->public_key_len != 0) && (member != current)){
      sz += cbor_put_map(&buf, 6);
      sz += cbor_put_number(&buf, COSE_KCP_KTY);
      sz += cbor_put_number(&buf, grpatt->kty);
      sz += cbor_put_number(&buf, COSE_KTP_CRV);
      sz += cbor_put_number(&buf, grpatt->crv);
      sz += cbor_put_number(&buf, COSE_KCP_KID);
      sz += cbor_put_bytes(&buf, (uint8_t *)member->client_id, 
                                         member->client_id_len);
      sz += cbor_put_number(&buf, COSE_KCP_ALG);
      sz += cbor_put_number(&buf, grpatt->cs_alg);
      sz += cbor_put_number(&buf, COSE_KCP_KEYOPS);
      sz += cbor_put_array(&buf, member->key_ops_len);
      for (uint16_t q = 0; q < member->key_ops_len; q++)
               sz += cbor_put_number(&buf, member->key_ops[q]);
      sz += cbor_put_number(&buf, COSE_KTP_X);
      sz += cbor_put_bytes(&buf, member->public_key,
                                        member->public_key_len);
    }
    member = member->next;
  }
  size_t ret=cbor_put_bytes(data, key_buf, sz);
  coap_free(key_buf);
  return ret;
}

/* GM_return_nonce
 * returns nonce  
 */
void
GM_return_nonce(coap_pdu_t *response, uint8_t *nonce,
                                      uint8_t *kdcchallenge)
{
  unsigned char opt_buf[5];
  int nr =0;
  uint8_t req_buf[30];
  uint8_t *buf = req_buf;
 
  if (nonce != NULL){
    nr += cbor_put_map(&buf, 2);
    nr += cbor_put_number(&buf, OAUTH_OSC_PROF_NONCE2);
    nr += cbor_put_bytes(&buf, nonce, 8);
  }
  else nr += cbor_put_map(&buf, 1);
  if (kdcchallenge != NULL){ 
    nr += cbor_put_number(&buf, OAUTH_CLAIM_KDCCHALLENGE);
    nr += cbor_put_bytes(&buf, kdcchallenge, 8);
  }
  coap_add_option(response,
                COAP_OPTION_CONTENT_FORMAT,
                coap_encode_var_safe(opt_buf, sizeof(opt_buf),
                COAP_MEDIATYPE_APPLICATION_ACE_CBOR), opt_buf);
  coap_add_data(response, nr, req_buf);
}


/* GM_join_response
 * writes join response  
 */
void
GM_join_response(coap_pdu_t *response, GM_group_t *group, 
                                       GM_member_t *member)
{
  uint8_t *req_buf = coap_malloc(500);
  uint8_t *buf = req_buf;

/* determine presence of keys */
  uint8_t number = 0;
  size_t  nr = 0;
  size_t  map_size = 5;
  GM_member_t *local_memb = group->members;
  while (local_memb != NULL){
    if ((local_memb->public_key_len != 0) && 
                     (local_memb != member)) number++;
    local_memb = local_memb->next;
  }
  if (number != 0)map_size++;
  if (group->group_policies != NULL) map_size ++;
  nr += GM_create_OSCORE_Security_context_object(&buf, 
           map_size, group);
  if (number != 0){
    nr += cbor_put_number(&buf, GRP_TAG_PUBKEYS);
    nr += GM_put_keys(&buf, group, member);
  }
  unsigned char opt_buf[5];
  char uri_GM[] = "GM";
  char nodes[] = "nodes";
      coap_add_option(response,
                    COAP_OPTION_LOCATION_PATH,
                    2,
                    (uint8_t *)uri_GM);
      coap_add_option(response,
                    COAP_OPTION_LOCATION_PATH,
                    group->group_name_len,
                    group->group_name);
      coap_add_option(response,
                    COAP_OPTION_LOCATION_PATH,
                    5,
                    (uint8_t *)nodes);                 
      coap_add_option(response,
                    COAP_OPTION_LOCATION_PATH,
                    member->client_id_len,
                    member->client_id);
  coap_add_option(response,
                 COAP_OPTION_CONTENT_FORMAT,
                 coap_encode_var_safe(opt_buf, sizeof(opt_buf),
                 COAP_MEDIATYPE_APPLICATION_ACE_CBOR), opt_buf);
  coap_add_data(response, nr, req_buf);
  coap_free(req_buf);
}


/* GM_group_response
 * creates manage response after group creation
 */
void
GM_group_response(coap_pdu_t *response, GM_group_t *group){

  uint8_t *req_buf = coap_malloc(500);
  uint8_t *buf = req_buf;
  size_t  nr =0;
  nr += cbor_put_map(&buf, 3);
  nr += cbor_put_number(&buf, GM_ADMIN_group_name);
  nr += cbor_put_bytes(&buf, group->group_name, group->group_name_len);
  nr += cbor_put_number(&buf, GM_ADMIN_joining_uri);
  nr += cbor_put_text(&buf, group->joining_uri, group->joining_uri_len);
  nr += cbor_put_number(&buf, GM_ADMIN_as_uri);
  nr += cbor_put_text(&buf, group->as_uri, group->as_uri_len);
  coap_add_data(response, nr, req_buf);
  coap_free(req_buf);
}

