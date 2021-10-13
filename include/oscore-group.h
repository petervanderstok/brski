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

#ifndef _OS_GROUP_H
#define _OS_GROUP_H
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>
#include <ctype.h>
#include <stddef.h>
#include "coap.h"
#include "oscore_oauth.h"


/* COSE group tags   */
#define GRP_TAG_SCOPE                9
#define GRP_TAG_GETPUBKEYS           101
#define GRP_TAG_CLIENTCRED           102
#define GRP_TAG_CNONCE               39
#define GRP_TAG_CLIENTCREDVERIFY     109
#define GRP_TAG_PUBKEYSREPOS         110
#define GRP_TAG_CONTROLPATH          111
#define GRP_TAG_GKTY                 1
#define GRP_TAG_KEY                  2
#define GRP_TAG_NUM                  206
#define GRP_TAG_ACEGROUPCOMMPROFILE  38
#define GRP_TAG_EXP                  4
#define GRP_TAG_PUBKEYS              3
#define GRP_TAG_GROUPPOLICIES        207
#define GRP_TAG_MGTKEYMATERIAL       119

/* POLICY definitions */

#define POLICY_EXPIRATION_DELTA      3
#define POLICY_CHECK_INTERVAL        2
#define POLICY_SYNCHRO_METHOD        1
#define POLICY_PAIRWISE_MODE         4

/* policy synchro methods  */
#define POL_SM_BEST_EFFORT               1
#define POL_SM_BASELINE                  2
#define POL_SM_ECHO_CHALLENGE            3

/* GM admin definitions */

#define GM_ADMIN_hkdf                  130
#define GM_ADMIN_alg                   131
#define GM_ADMIN_cs_alg                132
#define GM_ADMIN_cs_params             133
#define GM_ADMIN_cs_key_params         134
#define GM_ADMIN_cs_key_enc            135
#define GM_ADMIN_active                136
#define GM_ADMIN_group_name            137
#define GM_ADMIN_group_title           138
#define GM_ADMIN_joining_uri           139
#define GM_ADMIN_as_uri                140

/* scope definitions */
#define SCOPE_ROLE_REQUESTER                     0x2
#define SCOPE_ROLE_RESPONDER                     0x4
#define SCOPE_ROLE_MONITOR                       0x8
#define SCOPE_ROLE_VERIFIER                      0x10
#define SCOPE_ROLE_ADMINISTRATOR                 0x20

/*values for gkty */
#define Group_OSCORE_Security_Context_Object     1

/* values for ace groupcomm profile  */
#define COAP_GROUP_OSCORE_APP                    1

/* values for content formats  */
#define COAP_MEDIATYPE_APPLICATION_ACE_CBOR            10001
#define COAP_MEDIATYPE_APPLICATION_ACE_GROUPCOMM_CBOR  10002

typedef struct GM_member_t GM_member_t;
typedef struct GM_group_t GM_group_t;
typedef struct GM_policy_t GM_policy_t;
typedef struct GM_scope_t GM_scope_t;

struct GM_policy_t{
  GM_policy_t  *next;
  uint64_t     check_interval;
  int16_t      synch_method;
  uint64_t     expiration_delta;
  uint8_t      pairwise_mode;
};

struct GM_scope_t{
  uint8_t  *group_id;
  size_t   group_id_len;
  uint32_t roles;
};


struct GM_member_t {
  GM_member_t *next;
  uint8_t  *client_id; /* Sender ID: allocated by GM */
  size_t   client_id_len;
  uint8_t  *server_id; /* Recipient ID: allocated by GM */
  size_t   server_id_len;
  uint8_t  *public_key ; /* One PKey per sender ID  */
  size_t   public_key_len;
  uint8_t  *key_ops;
  uint8_t  key_ops_len;
  uint8_t  *scope;
  size_t   scope_len;
  char     *return_uri;
  size_t   return_uri_len;
};


typedef struct joinreq_t{
  uint8_t  *pub_keys_repos;
  size_t   pub_keys_repos_len;
  uint8_t  *get_pub_keys;
  size_t   get_pub_keys_len;
  uint8_t  *scope;
  size_t   scope_len;
  uint8_t  *pub_key;
  uint8_t  pub_key_len;
  uint8_t  *signature;
  size_t   signature_len;
  uint8_t  *cnonce;
  size_t   cnonce_len;
  uint8_t  *key_ops;
  uint8_t  key_ops_len;
  char     *return_uri;
  size_t   return_uri_len;
  uint8_t  kty;
  int8_t   cs_alg;
  int8_t   cs_param;
}joinreq_t;
  

struct GM_group_t{
  GM_group_t     *next;             /* chain of groups */
  GM_member_t    *members;          /* members of group */
  size_t         members_len;       /* number of group members */
  oauth_cnf_t    *attributes;       /* oscore security parameters */
  uint8_t        active;            /* group active (T/F) */
  uint32_t       epoch;             /* group version  */
  uint8_t        *group_name;       /* group name */
  size_t         group_name_len;    /* group name length  */
  char           *group_title;      /* human readable group title */
  size_t         group_title_len;   /* group title length  */
  uint16_t       group_profile;     /* group profile = coap_group_oscore_app */
  char           *joining_uri;      /* uri of group member resource */
  size_t         joining_uri_len;   /* joining uri length */
  GM_policy_t    *group_policies;   /* list of policies */
  size_t         group_policies_nr; /* number of policy elements  */ 
  char           *as_uri;           /* uri of authorization server */
  size_t         as_uri_len;        /* as_uri length  */
};

/* GM_enter_group
 * enters new group into set of groups
 */
void
GM_enter_group(GM_group_t *group);


/* GM_decode_pubkey
 * Decodes map of a single public key used in the group
 */
uint8_t
GM_decode_pubkey(unsigned char **databuf, oauth_cnf_t *conf);


/* GM_decode_pubkeys
 * Decodes the array of public keys used in the group
 */
uint8_t
GM_decode_pubkeys(unsigned char **databuf);

/* GM_read_object_keys
 * reads configuration of object security object
 * followed by configurations of public keys
 */
oauth_cnf_t *
GM_read_object_keys(unsigned char **databuf, uint8_t **keys);


/* GM_read_nonce(databuf, len)
 * reads 8-byte nonce and rsnonce from databuf
 */
uint8_t 
GM_read_nonce(unsigned char *databuf, 
                       uint8_t **cnonce, uint8_t **rsnonce);

/* GM_create_scope
 * fills scope for C0, C1 and C2
 */
size_t
GM_create_scope(uint8_t **scopep, uint8_t client);


/* GM_get_scope
 * returns scope from data
 */
GM_scope_t *
GM_get_scope(uint8_t *data);


/* GM_create_OSCORE_Security_context_object
 * fills OSCORE security context object in group request to GM
*/
size_t
GM_create_OSCORE_Security_context_object(uint8_t **buf, 
           size_t map_size, GM_group_t *group);


/* GM_create_token
 * fills request to GM for group join authorization
*/
size_t
GM_create_token(uint8_t **token, oauth_cnf_t *conf, int GM_choice);

/* GM_create_credp
 * fills credp with public_key parameter
 */
size_t
GM_create_credp(uint8_t **credp, uint8_t *public_key);


/* GM_delete_jr
 * frees memory of join_request
 */
void
GM_delete_jr( joinreq_t *jr);


/* GM_delete_group
 * deletes group and members
 */
void
GM_delete_group(GM_group_t *group);


/* GM_print_group
 * prints contents of group and members
 */
void
GM_print_group(GM_group_t *group);

/* GM_print_jr
 * prints contents of join request
 */
void
GM_print_jr(joinreq_t *jr);


/* GM_jr_to_member
 * moves contents of join-request to group-member
 * sets corresponding join-request pointers to NULL
 */
void 
GM_jr_to_member(joinreq_t *jr, GM_member_t *member,
                                 GM_group_t *group);


/* GM_manage_request
 * Read configuration information from group handle request 
 * data points to map
 */
GM_group_t *
GM_manage_request(uint8_t **data);

/* GM__cs_key_params
 * returns cbor array [param_type, [paramtype, param]]
 */
uint8_t *
GM_cs_key_params(int8_t param, int8_t param_type, size_t *len);

/* GM__cs_params
 * returns cbor array [paramtype, param]
 */
uint8_t *
GM_cs_params(int8_t param, int8_t param_type, size_t *len);

/* GM_prepare_aad
 * prepaares aad for GM client and server 
 * to encrypt and decrypt
 */
size_t
GM_prepare_aad(int8_t alg, uint8_t *aad_buffer);

/* REad join request from request map
 * data points to map
 */
joinreq_t *
GM_join_request(uint8_t **data);


/* GM_find_group
 * find a group with specified name
 */
struct GM_group_t *
GM_find_group(char *name, size_t name_len);


/* GM_return_nonce
 * returns nonce 
 */
void
GM_return_nonce(coap_pdu_t *response, uint8_t *nonce, 
                                      uint8_t *rsnonce);


/* GM_join_response
 * creates join response
 */
void
GM_join_response(coap_pdu_t *response, GM_group_t *group, 
                                       GM_member_t *member);
                                       

/* GM_group_response
 * creates manage response after group creation
 */
void
GM_group_response(coap_pdu_t *response, GM_group_t *group);


#endif /* _OS_GROUP_H */

