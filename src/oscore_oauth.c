/* oscore_oauth -- implementation of authorization using
 * a simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 * this file is added by:
 * Peter van der Stok <consultancy@vanderstok.org>
 * This file relies on oscore
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
#ifdef _WIN32
#define strcasecmp _stricmp
#include "getopt.c"
#if !defined(S_ISDIR)
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#endif
#else
#include <unistd.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <dirent.h>
#include <time.h>
#endif

#include "coap_server.h"
#include "oscore.h"
#include "oscore-context.h"
#include "cbor.h"
#include "cose.h"
#include "coap.h"
#include "oscore_oauth.h"
#include "cbor_decode.h"

typedef struct oauth_scope_t oauth_scope_t;

struct oauth_scope_t{
  size_t  role_len;
  uint8_t *role;
};

/* oauth_delete_token
 * liberates memory space occupied by token
 */
void
oauth_delete_token(oauth_token_t *token){
  if(token != NULL){
    if(token->iss != NULL)free(token->iss);
    if(token->sub != NULL)free(token->sub);
    if(token->aud != NULL)free(token->aud);
    if(token->cti != NULL)free(token->cti);
    if(token->client_cred != NULL)free(token->client_cred);
    if(token->scope != NULL)free(token->scope); 
    if(token->key_info != NULL)free(token->key_info);
    oauth_delete_conf(token->osc_sec_config); 
    free(token);
  }
}

/* oauth_print_cwt_key
 * prints contents of cwt_key
 */
void
oauth_print_cwt_key(oauth_cwtkey_t *ck){
  if (coap_get_log_level() < LOG_DEBUG) return;
  if(ck != NULL){
  
    fprintf(stderr,"----------------cwt-key ----------\n");

    fprintf(stderr, "       alg:  ");
    fprintf(stderr,"%d \n",(int)ck->alg);
    fprintf(stderr, "       crv:  ");
    fprintf(stderr,"%d \n",(int)ck->crv);
    fprintf(stderr, "       kty:  ");
    fprintf(stderr,"%d \n",(int)ck->kty);

    fprintf(stderr, "        iv: ");
    for (uint k=0; k < ck->iv_len; k++){
        fprintf(stderr,"%02x", (int)ck->iv[k]);
    }
    fprintf(stderr,"\n");

    fprintf(stderr, "  signature: ");
    for (uint k=0; k < ck->signature_len; k++){
        fprintf(stderr,"%02x", (int)ck->signature[k]);
    }
    fprintf(stderr,"\n");

    fprintf(stderr, "       kid: ");
    for (uint k=0; k < ck->kid_len; k++){
        fprintf(stderr,"%c", (char)ck->kid[k]);
    }
    fprintf(stderr,"\n");
    fprintf(stderr, "     token:  ");
    fprintf(stderr,"%p \n",(void *)ck->token);
    fprintf(stderr, "      data:  ");
    fprintf(stderr,"%p \n",(void *)ck->data);
  }
}


/* oauth_delete_cwt_key
 * frees memory of cwt_key
 */
void
oauth_delete_cwt_key(oauth_cwtkey_t *ck){
  if (ck->kid != NULL) free(ck->kid);
  if (ck->iv != NULL) free(ck->iv);
  if (ck->token != NULL)oauth_delete_token(ck->token);
/* ck->data and ck->signature point to data in request packet;
 *    not to be freed  */
  free(ck);
}


/* oauth_print_conf
 * prints configuration for print_conf 
 */
void
oauth_print_conf(oauth_cnf_t *conf){
  if (coap_get_log_level() < LOG_DEBUG) return;
  if(conf != NULL){
    fprintf(stderr,"----------------configuration ----------\n");
    fprintf(stderr, "       alg:  ");
    fprintf(stderr,"%d \n",(int)conf->alg);
    if (conf->cs_params != NULL){
      fprintf(stderr, "        cs_params:  ");
      uint8_t  *pt = (uint8_t  *)conf->cs_params;
      print_cbor(&pt);
      fprintf(stderr," \n");
    }
    if (conf->cs_key_params != NULL){
      fprintf(stderr, "    cs_key_params:  ");
      uint8_t  *pt = (uint8_t  *)conf->cs_key_params;
      print_cbor(&pt);
      fprintf(stderr," \n");
    }
    fprintf(stderr, "       cs_alg:  ");
       fprintf(stderr,"%d \n",(int)conf->cs_alg);
     fprintf(stderr, "   cs_key_enc:  ");
       fprintf(stderr,"%d \n",(int)conf->cs_key_enc);      
    fprintf(stderr, "       hkdf:  ");
       fprintf(stderr,"%d \n",(int)conf->hkdf);
    fprintf(stderr, "       exp:   ");
       fprintf(stderr,"%d \n",(int)conf->exp);
    fprintf(stderr, "       kty:   ");
       fprintf(stderr,"%d \n",(int)conf->kty);
    fprintf(stderr, "       crv:   ");
       fprintf(stderr,"%d \n",(int)conf->crv);      
    fprintf(stderr, "       rpl:   ");
       fprintf(stderr,"%d \n",(int)conf->rpl);
    fprintf(stderr, "       num:   ");
       fprintf(stderr,"%d \n",(int)conf->num);

    fprintf(stderr, "       client_id: ");
    for (uint k=0; k < conf->client_id_len; k++){
        fprintf(stderr,"%c", (char)conf->client_id[k]);
    }
    fprintf(stderr,"\n");

    fprintf(stderr, "       server_id: ");
    for (uint k=0; k < conf->server_id_len; k++){
        fprintf(stderr,"%c", (char)conf->server_id[k]);
    }
    fprintf(stderr,"\n");

    fprintf(stderr, "       context_id: ");
    for (uint k=0; k < conf->context_id_len; k++){
        fprintf(stderr,"%c", (char)conf->context_id[k]);
    }
    fprintf(stderr,"\n");
    if (conf->group_id != NULL){
      fprintf(stderr, "       group_id: ");
      for (uint k=0; k < conf->group_id_len; k++){
        fprintf(stderr,"%c", (char)conf->group_id[k]);
      }
      fprintf(stderr,"\n");
    }
    fprintf(stderr, "       profile: ");
    fprintf(stderr,"  %d  \n", conf->profile);
    if (conf->ms != NULL){
      fprintf(stderr, "       ms: ");
      for (uint k=0; k < conf->ms_len; k++){
        fprintf(stderr,"%02x", (uint8_t)conf->ms[k]);
      }
      fprintf(stderr,"\n");
    }
    if (conf->salt != NULL){
      fprintf(stderr, "       salt: ");
      for (uint k=0; k < conf->salt_len; k++){
        fprintf(stderr,"%02x", (uint8_t)conf->salt[k]);
      }
      fprintf(stderr,"\n");
    }
    if (conf->pub_key != NULL){    
      fprintf(stderr, "       pub_key: ");
      for (uint k=0; k < conf->pub_key_len; k++){
        fprintf(stderr,"%02x", (uint8_t)conf->pub_key[k]);
      }
      fprintf(stderr,"\n");
    }
  } 
}


/* oauth_delete_conf
 * frees memory of oscore_configuration
 */
void
oauth_delete_conf(oauth_cnf_t *cf){
  if (cf != NULL){
    if (cf->client_id  != NULL) coap_free(cf->client_id);
    if (cf->server_id  != NULL) coap_free(cf->server_id);
    if (cf->context_id != NULL) coap_free(cf->context_id);
    if (cf->cs_params  != NULL) coap_free(cf->cs_params);   
    if (cf->cs_key_params != NULL) coap_free(cf->cs_key_params);     
    if (cf->group_id   != NULL) coap_free(cf->group_id);
    if (cf->ms         != NULL) coap_free(cf->ms);
    if (cf->salt       != NULL) coap_free(cf->salt);
    if (cf->pub_key    != NULL) coap_free(cf->pub_key);
    free(cf);
  }
}
 
 
/* oauth_print_token
 * prints contents of token (followed by configuration)
 */
void
oauth_print_token(oauth_token_t *token){
  if (coap_get_log_level() < LOG_DEBUG) return;
  if(token != NULL){
    fprintf(stderr,"----------------token -------------\n");
    uint8_t *pt = token->iss;
    if (pt != NULL){     
      fprintf(stderr, " iss:  ");
      for (uint k=0; k < token->iss_len; k++)
        fprintf(stderr,"%c",*(char *)pt++);
      fprintf(stderr,"\n");
    }

    pt = token->sub;
    if (pt != NULL){   
      fprintf(stderr, " sub:  ");
      for (uint k=0; k < token->sub_len; k++)
        fprintf(stderr,"%c",*(char *)pt++);
      fprintf(stderr,"\n");
    }

    pt = token->aud;
    if (pt != NULL){       
      fprintf(stderr, " aud:  ");
      for (uint k=0; k < token->aud_len; k++)
        fprintf(stderr,"%c",*(char *)pt++);
      fprintf(stderr,"\n");
    }

    pt = token->cti;
    if (pt != NULL){       
      fprintf(stderr, " cti:  ");
      for (uint k=0; k < token->cti_len; k++)
        fprintf(stderr,"%02x",*pt++);
      fprintf(stderr,"\n");
    }
    
    pt = token->client_cred;
    if (pt != NULL){      
      fprintf(stderr, " client_cred:  ");
      for (uint k=0; k < token->client_cred_len; k++)
        fprintf(stderr,"%02x",*pt++);
      fprintf(stderr,"\n");
    }

    pt = token->scope;
    if (pt != NULL){
      fprintf(stderr, " scope: ");
      print_cbor((uint8_t **)&pt);
      fprintf(stderr,"\n");
    }

    if (token->key_info != NULL){   
      fprintf(stderr, " key_info: \n");
      for (uint k=0; k < token->key_info_len; k++){
        fprintf(stderr,"      %d  \n", (int)token->key_info[k]);
      }
    }
 
    fprintf(stderr, " profile:   %d", token->profile);
    fprintf(stderr,"\n");

    fprintf(stderr, " iat:  ");
       fprintf(stderr,"%d",(int)token->iat);
    fprintf(stderr,"\n");

    fprintf(stderr, " exp:  ");
       fprintf(stderr,"%d",(int)token->exp);
    fprintf(stderr,"\n");
    oauth_cnf_t *conf = token->osc_sec_config; 
    if (conf != NULL) oauth_print_conf(conf);
  }  
}

 
/* oauth_create_OSCORE_Security_context
 * fills OSCORE security context into CBOR map
 ** filled in by AS for PoP  ****
*/
size_t
oauth_create_OSCORE_Security_context(uint8_t **buf, oauth_cnf_t *param){
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
  cbor_put_map(bufpt, map_size); /* definite map size  */
  return nr;
}


/* oauth_read_OSCORE_security_context
 * Decodes the map following the key info
 * expects map with Group Security Context
 * returns configuration
 */
oauth_cnf_t *
oauth_read_OSCORE_security_context(unsigned char **databuf){
  uint8_t *pt = NULL;
  uint8_t  ok = 0;
  uint8_t  tag = 0;
  int64_t  mm = 0;
  oauth_cnf_t    *conf = coap_malloc(sizeof(oauth_cnf_t));
  memset(conf, 0, sizeof(oauth_cnf_t));
  uint8_t  elem = cbor_get_next_element(databuf);
  if (elem == CBOR_MAP){ 
    uint64_t map_size = cbor_get_element_size(databuf);
    for (uint i=0 ; i < map_size; i++){
      tag = cose_get_tag(databuf);
      switch (tag){
        case OSCORE_CONTEXT_ALG:
          ok = cbor_get_number(databuf, &mm);
          if (ok == 0)conf->alg = (int8_t)mm;
          break;
        case OSCORE_CONTEXT_MS:
          ok = cbor_get_string_array(databuf, &pt, 
                                                &conf->ms_len);
          conf->ms =pt;
          break;
        case OSCORE_CONTEXT_CLIENTID:
          ok = cbor_get_string_array(databuf, &pt, 
                                          &conf->client_id_len);
          conf->client_id = pt;
          break;
        case OSCORE_CONTEXT_SERVERID:
          ok = cbor_get_string_array(databuf, &pt, 
                                          &conf->server_id_len);
          conf->server_id = pt;
          break;
        case OSCORE_CONTEXT_HKDF:
          ok = cbor_get_number(databuf, &mm);
          if (ok == 0){
            conf->hkdf = (int8_t)mm;
            if (conf->hkdf != COSE_Algorithm_HKDF_SHA_256)ok = 1;
          }
          break;
        case OSCORE_CONTEXT_SALT:
          ok = cbor_get_string_array(databuf, &pt, 
                                          &conf->salt_len );
          conf->salt = pt;
          break;
        case OSCORE_CONTEXT_CONTEXTID:
          ok = cbor_get_string_array(databuf, &pt,    
                                         &conf->context_id_len);
          conf->context_id = pt;
          break;
        case OSCORE_CONTEXT_RPL:
          ok = cbor_get_number(databuf, &mm);
          if (ok == 0)conf->rpl = (int8_t)mm;
          break;
        case OSCORE_CONTEXT_CSALG:
          ok = cbor_get_number(databuf, &mm);
          if (ok == 0)conf->cs_alg = (int8_t)mm;
          break;
        case OSCORE_CONTEXT_CSPARAMS:
          ok = cbor_get_string_array(databuf, (uint8_t **)&conf->cs_params, &conf->cs_params_len);
          break;
        case OSCORE_CONTEXT_CSKEYPARAMS:
          ok = cbor_get_string_array(databuf, (uint8_t **)&conf->cs_key_params, &conf->cs_key_params_len);
          break;
        case OSCORE_CONTEXT_CSKEYENC:
          ok = cbor_get_number(databuf, &mm);
          if (mm != CWT_KEY_COSE_KEY){
			 coap_log(LOG_WARNING," CSKEY encoding has unknown value \n");
			 ok = 1;
		  }
          break;
        default:
          ok = 1;
          break;
      } /* switch  */ 
      if(ok != 0){
        coap_log(LOG_WARNING," Decode error in oscore context specification \n");
        free(conf);
        return NULL;
      }
    } /* for   map_size  */
  } /* CBOR_MAP */
  else{
    coap_log(LOG_WARNING," no map returned \n");
    free(conf);
    return NULL;
  }
  return conf;  /* OK return  */
}

/* Read configuration information from CWT_CNF map
 * data points to map
 */
oauth_cnf_t *
oauth_cwt_configuration(uint8_t **data)
{
   uint8_t ok = 0;
   int16_t tag = 0;
   oauth_cnf_t *config = NULL;
   uint8_t elem = cbor_get_next_element(data);
   if (elem == CBOR_MAP){ 
     uint64_t cnf_map_size = cbor_get_element_size(data);
       /*size of map */
     for (uint i=0 ; i < cnf_map_size; i++){
       tag = cose_get_tag(data);
       switch (tag){
         case CWT_OSCORE_SECURITY_CONTEXT: 
           elem = cbor_get_next_element(data);
           if (elem == CBOR_MAP){ 
             config = oauth_read_OSCORE_security_context(data);
             if (config == NULL) return NULL;
           } else return NULL;  /* if CBOR_MAP  */
           break;
         case UNDEFINED_TAG:
           coap_log(LOG_WARNING, "Illegal CBOR contents\n");
           oauth_delete_conf(config);
           return NULL;
         default:
           coap_log(LOG_WARNING,"Illegal COSE tag \n");
           oauth_delete_conf(config);
           return NULL;
       } /* switch */
       if (ok != 0){
         free( config);
         return NULL;
       }  /* ok */
     }  /* for CBOR_MAP loop */
     return config;
   } /* if CBOR_MAP */ 
   return config;
}

/* oauth_read_nonce(databuf, cnonce, rssnonce)
 * reads 8-byte nonce and kdcchallenge from databuf
 */
uint8_t 
oauth_read_nonce(unsigned char *databuf, 
                       uint8_t **cnonce, uint8_t **kdcchallenge){
  size_t size = 0;
  size_t rssize = 0;
  uint8_t ok = 0;
  uint8_t tag = 0;
  uint8_t elem = cbor_get_next_element(&databuf);
  if (elem == CBOR_MAP){ 
    uint64_t map_size = cbor_get_element_size(&databuf);
    for (uint i=0 ; i < map_size; i++){
      tag = cose_get_tag(&databuf);
      switch (tag){
        case OAUTH_OSC_PROF_NONCE2: 
          ok = cbor_get_string_array(&databuf, cnonce, &size);
          if (size != 8) ok =1;
          break;
        case OAUTH_CLAIM_KDCCHALLENGE:
          ok = cbor_get_string_array(&databuf, kdcchallenge, &rssize);
          if(rssize != 8) ok = 1;
          break;
        default:
          coap_log(LOG_WARNING," too many items in map \n");
          ok = 1;
          break;
      } /* switch  */ 
    } /* for   map_size  */
  } /* CBOR_MAP */
  else{
    coap_log(LOG_WARNING," no map returned \n");
    return 1;
  } /* CBOR map */

  if (ok != 0){
    coap_log(LOG_WARNING, "Returned nonce has problems  %d \n", (int)size);
    if (*cnonce != NULL)free(*cnonce);
    if (*kdcchallenge != NULL)free(*kdcchallenge);
    *kdcchallenge = NULL;
    *cnonce = NULL;
  }
  return ok;
}
  

/* oauth_read_token
 * read the CWT token from input data
 */
struct oauth_token_t *
oauth_read_token(uint8_t **data){
  int16_t tag = 0;
  uint8_t ok = 0;
  int64_t  mm = 0;
  oauth_token_t  *token = NULL;
  uint8_t elem = cbor_get_next_element(data);
  if (elem != CBOR_MAP)return NULL;
  
  uint64_t map_size = cbor_get_element_size(data);
    token = coap_malloc(sizeof(oauth_token_t));
    memset (token, 0, sizeof(oauth_token_t));
    for (uint i=0; i < map_size; i++){
      tag = cose_get_tag(data);
      ok = 0;
      if (tag == UNDEFINED_TAG){
        coap_log(LOG_WARNING, "Illegal CBOR contents\n");
        ok = 1;
      }
      switch (tag){
        case CWT_CLAIM_AUD:
             ok = cbor_get_string_array(data, 
                          &token->aud, &token->aud_len);
             break;
        case CWT_CLAIM_SUB:
             ok = cbor_get_string_array(data, 
                          &token->sub, &token->sub_len);
             break;
        case CWT_CLAIM_ISS:
             ok = cbor_get_string_array(data, 
                          &token->iss, &token->iss_len);
             break;
        case CWT_CLAIM_SCOPE:
             ok = cbor_strip_value(data, 
                        &token->scope, &token->scope_len);
             break;
        case CWT_CLAIM_IAT:
            elem = cbor_get_next_element(data);
            if (elem == CBOR_UNSIGNED_INTEGER){
              token->iat = cbor_get_unsigned_integer(data);
            } else ok = 1;
            break;
        case CWT_CLAIM_EXP:
            elem = cbor_get_next_element(data);
            if (elem == CBOR_UNSIGNED_INTEGER){
              token->exp = cbor_get_unsigned_integer(data);
            } else ok = 1;
            break;
        case CWT_CLAIM_CTI:
            ok = cbor_get_string_array(data, 
                          &token->cti, &token->cti_len);
            break;
        case GRP_TAG_CLIENTCRED:
            ok = cbor_get_string_array(data, 
                  &token->client_cred, &token->client_cred_len);
            break;
        case GRP_TAG_ACEGROUPCOMMPROFILE:
            ok = cbor_get_number(data, &mm);
            if (ok == 0)token->profile = mm;
            break;
        case CWT_CLAIM_CNF:
            elem = cbor_get_next_element(data);
            if (elem == CBOR_MAP)
              token->osc_sec_config = 
                               oauth_cwt_configuration(data);
            break;
        default:
            coap_log(LOG_WARNING, "Unexpected TOKEN tag\n");
            ok = 1;
            break;
      }  /* switch */
      if (ok != 0){
        oauth_delete_token(token);
        return NULL;
      }
    } /* for loop  */
  return token;
}

/* key_map
 * reads map that describes key in CWT
 * if error: returns 1 
 * no error: returns 0
*/
static uint8_t
key_map(uint8_t **data, oauth_cwtkey_t *cwtkey){
  uint8_t ok = 0;
  int16_t tag = 0;
  int64_t mm = 0;
  uint8_t elem = cbor_get_next_element(data);
  if (elem != CBOR_MAP)return 1;
  uint64_t map_size = cbor_get_element_size(data);
  for (uint k=0; k < map_size; k++){
    tag = cose_get_tag(data);
    switch (tag){
      case UNDEFINED_TAG:
      default:
        coap_log(LOG_WARNING, "Illegal CBOR contents\n");
        ok = 1;
        break;
      case COSE_HP_KID:
        ok = cbor_get_string_array(data,
                            &cwtkey->kid, &cwtkey->kid_len);
        break;
      case COSE_KTP_CRV:
        ok = cbor_get_number(data, &mm);
        if (ok == 0) cwtkey->crv = (int8_t)mm;
        break;
      case COSE_HP_IV:
        ok = cbor_get_string_array(data,
                            &cwtkey->iv, &cwtkey->iv_len);
        break;
    } /* switch  */
    if (ok == 1) return 1;
  } /* for size  */
  return 0;
}

/* read_alg_map
 * reads algorithm field of token header
 * 0 = OK, 1 = NOK
 */
static uint8_t
read_alg_map(uint8_t **data, oauth_cwtkey_t *cwtkey){
  uint8_t ok = 0;
  int64_t mm = 0;
  uint8_t elem = cbor_get_next_element(data);
  if (elem != CBOR_MAP)return 1;
  uint64_t map_size = cbor_get_element_size(data);
  for (uint k=0; k < map_size; k++){
    int16_t tag = cose_get_tag(data);
    switch (tag){
      case UNDEFINED_TAG:
      default:
        coap_log(LOG_WARNING, "Illegal CBOR contents\n");
        ok = 1;
        break;
      case COSE_HP_ALG:
        ok = cbor_get_number(data, &mm);
        if (ok == 0) cwtkey->alg = (int8_t)mm;
        break;
    } /* switch  */
    if (ok == 1) return 1;
  } /* for map_size  */
  return 0;
}

/* oauth_read_CWT_key
 * returns cwtkey information
 * first element is CBOR_TAG
 * if error: returns NULL
 */
oauth_cwtkey_t *
oauth_read_CWT_key(uint8_t **data){
  uint8_t ok = 0;
  oauth_token_t *token = NULL;
  oauth_cwtkey_t  *cwtkey = NULL;
  uint64_t tag_value = cbor_get_element_size(data);
  uint8_t elem = cbor_get_next_element(data);
  if (elem == CBOR_ARRAY){
    uint64_t arr_size = cbor_get_element_size(data);
/* id arr_size = 4; then signed CWT                     *
                with tag_value CBOR_TAG_COSE_ENCRYPT0   *
 * if arr_size = 3; then encrypted CWT                  *
                with tag_value CBOR_TAG_COSE_SIGN1      *
 */
    cwtkey = coap_malloc( sizeof(oauth_cwtkey_t));
    memset (cwtkey, 0, sizeof(oauth_cwtkey_t));
    for (uint i=0; i < arr_size; i++){
      elem = cbor_get_next_element(data);
      if (elem == CBOR_BYTE_STRING){
        uint8_t *start_bytes = *data;
        uint64_t len = cbor_get_element_size(data);
        switch (i+1){
        default:
          ok = 1;
          break;
        case 4:
  /* data points to signature  */
          cwtkey->signature_len = len;
          cwtkey->signature = *data;
          break;
        case 1:
/* data points to alg field  */
          ok = read_alg_map(data, cwtkey);
          break;
        case 2:
/* data point to key info map  */
          ok = key_map(data, cwtkey);
          break;
        case 3:
          if (tag_value == CBOR_TAG_COSE_SIGN1){
/* start_bytes points to start of bytes array 
 * data points to token map */ 
            token = oauth_read_token(data);
            if (token == NULL){
              oauth_delete_cwt_key(cwtkey);
              return NULL;
            } /* if token  */
            cwtkey->token = token;
            cwtkey->data = start_bytes;
            cwtkey->data_len = *data - start_bytes;
          } else if (tag_value == CBOR_TAG_COSE_ENCRYPT0){ 
            if (elem != CBOR_BYTE_STRING){
               oauth_delete_cwt_key(cwtkey);
               return NULL;
            }
            cwtkey->data = *data;
            cwtkey->data_len = len;
          } else {
            oauth_delete_cwt_key(cwtkey);
            return NULL;
          } /* if tag_value   ) */
        } /* switch (i+1)  */
      } /* If CBOR_BYTE_STRING */
      if (ok == 1){
        oauth_delete_cwt_key(cwtkey);
        return NULL;
      }
    }  /* for arr_size  */
    oauth_print_cwt_key(cwtkey);
    return cwtkey;
  } /* if CBOR_ARRAY  */
  return NULL;
}

/* oauth_encrypt_token
 * encrypts token using encrypt_key
 * cipher_text = oauth_encrypt_token(token, ASGM_KEY,
        aad_buffer, aad_len, &ciphertext_len){ 
 */
 
uint8_t *
oauth_encrypt_token(uint8_t *token, size_t token_len, uint8_t *encrypt_key,
        uint8_t *aad_buffer, size_t aad_len, 
        uint8_t *iv, size_t *ciphertext_len){ 
  uint8_t *ciphertext = coap_malloc(450);
  *ciphertext_len = 0;
  cose_encrypt0_t cose[1];
  cose_encrypt0_init(cose);  /* clears cose memory */
  cose_encrypt0_set_alg(cose, COSE_Algorithm_AES_CCM_16_64_128);
  cose_encrypt0_set_key(cose, encrypt_key, 
                      COSE_algorithm_AES_CCM_16_64_128_KEY_LEN );
  cose_encrypt0_set_aad(cose, aad_buffer, aad_len);
  cose_encrypt0_set_nonce(cose, iv, 
                        COSE_algorithm_AES_CCM_16_64_128_IV_LEN);
  cose_encrypt0_set_plaintext(cose, token, token_len);
  int len = cose_encrypt0_encrypt(cose,
         ciphertext, 
         token_len + COSE_algorithm_AES_CCM_16_64_128_TAG_LEN);
  if (len < 0){
    free(ciphertext);
    return NULL;
  }
  *ciphertext_len = (size_t)len;
  return ciphertext;
}

/* oauth_decrypt_token
 * decrypts token using decrypt_key
 */
oauth_token_t *
oauth_decrypt_token(uint8_t **enc_token, uint8_t *decrypt_key,
        uint8_t *aad_buffer, size_t aad_len){
  oauth_cwtkey_t *key_enc = NULL;
  oauth_token_t *token = NULL;
  /*  enc_token points to PoP CWT */
  uint8_t *plaintext = coap_malloc(450);
  uint8_t *plaintext_st = plaintext;
  key_enc = oauth_read_CWT_key(enc_token);
  if (key_enc == NULL){
    free(plaintext_st);
    return NULL;
  }
  cose_encrypt0_t cose[1];
  cose_encrypt0_init(cose);  /* clears cose memory */
  cose_encrypt0_set_alg(cose, COSE_Algorithm_AES_CCM_16_64_128);
  cose_encrypt0_set_key(cose, decrypt_key, 
                      COSE_algorithm_AES_CCM_16_64_128_KEY_LEN );
  cose_encrypt0_set_aad(cose , aad_buffer, aad_len);
  cose_encrypt0_set_nonce(cose, key_enc->iv, key_enc->iv_len);
  cose_encrypt0_set_ciphertext(cose, key_enc->data, 
                                          key_enc->data_len);
  int plaintext_len = cose_encrypt0_decrypt(cose, plaintext,
     key_enc->data_len - COSE_algorithm_AES_CCM_16_64_128_TAG_LEN);
  
  oauth_delete_cwt_key(key_enc);
  if (plaintext_len == -2){
	coap_log(LOG_WARNING,"Decryption failed \n");
    free(plaintext_st);
    return NULL;
  }
  token = oauth_read_token(&plaintext);
  free(plaintext_st);
  oauth_print_token(token);
  return token;
}


/* oauth_strip
 * separates access_token and nonce text
 * returns accesstoken in data, and nonce is cnonce
 * return 0 is OK; 1 is Nok
 */
uint8_t
oauth_strip(uint8_t **data, uint8_t **nonce, oauth_cwtkey_t **key_enc){
  uint8_t ok = 0;
  int16_t tag = 0;
  uint8_t elem = cbor_get_next_element(data);
  if (elem == CBOR_MAP){
    uint64_t map_size = cbor_get_element_size(data);
    if (map_size != 2) return 1;
    for (uint i=0; i < map_size; i++){
      tag = cose_get_tag(data);
      if (tag == OAUTH_CLAIM_ACCESSTOKEN){
        ok++;
        elem = cbor_get_next_element(data);
        if (elem != CBOR_BYTE_STRING) return 1;
        uint64_t CWT_size = cbor_get_element_size(data);
        *key_enc = coap_malloc(sizeof(oauth_cwtkey_t));
        memset(*key_enc, 0, sizeof(oauth_cwtkey_t));
        (*key_enc)->data = *data;
        (*key_enc)->data_len = (size_t)CWT_size;
        *data = *data + CWT_size;
      }  /* if access_token  */
      if (tag == OAUTH_OSC_PROF_NONCE1){
        ok++;
        size_t len;
        if(cbor_get_string_array(data, nonce, &len) == 1) 
                                                     return 1; 
        if (len != 8 ) return 1;
      } /* if */
    } /* for map_size  */
  }  /* if elem CBOR_MAP  */
  if (ok != 2) return 1;
  return 0;
}

/* fill_info_encrypt_field
 * fills info field for Cose header
 * returns size of field
 */
static size_t
fill_info_encrypt_field(uint8_t *field, 
             uint8_t *iv, size_t iv_len, uint8_t *kid, size_t kid_len){
  size_t len = 0;
  len += cbor_put_map(&field, 2);
  len += cbor_put_number(&field, COSE_HP_KID);
  len += cbor_put_bytes(&field, kid, kid_len);
  len += cbor_put_number(&field, COSE_HP_IV);
  len += cbor_put_bytes(&field, iv, iv_len);
  return len;
}


/* fill_info_sign_field
 * fills info field for Cose header
 * returns size of field
 */
static size_t
fill_info_sign_field(uint8_t *field, int8_t crv){
  char AsymmetricEd25519[] = "AsymmetricEd25519";
  size_t len = 0;
  len += cbor_put_map(&field, 2);
  len += cbor_put_number(&field, COSE_HP_KID);
  len += cbor_put_bytes(&field, 
     (uint8_t *)AsymmetricEd25519, strlen(AsymmetricEd25519));
  len += cbor_put_number(&field, COSE_KTP_CRV);
  len += cbor_put_number(&field, crv);
  return len;
}

/* fill_alg_field
 * fills alg field for Cose header
 * returns size of field
 */
static size_t
fill_alg_field(uint8_t *field, int8_t alg){
  size_t len = 0;
  len += cbor_put_map(&field, 1);
  len += cbor_put_number(&field, COSE_HP_ALG);
  len += cbor_put_number(&field, alg);
  return len;
}
   
/* oauth_create_encrypt_header
 * fills description of encryption algorithm
 */
size_t 
oauth_create_encrypt_header(uint8_t **token, 
             uint8_t *iv, size_t iv_len, uint8_t *kid, size_t kid_len){
  uint8_t field[100];
  size_t len = 0;
  len += cbor_put_tag(token, CBOR_TAG_COSE_ENCRYPT0);
  len += cbor_put_array(token, 3);
/* fills array of 3 elements  */
  size_t size = fill_alg_field(field, 
                            COSE_Algorithm_AES_CCM_16_64_128); 
  len += cbor_put_bytes(token, field, size);
  size = fill_info_encrypt_field(field, iv, iv_len, kid, kid_len);                              
  len += cbor_put_bytes(token, field, size);
  return len;
}

   
/* oauth_create_signature_header
 * fills description of signature algorithm
 */
size_t 
oauth_create_signature_header(uint8_t **token){
  uint8_t field[100];
  size_t len = 0;
  len += cbor_put_tag(token, CBOR_TAG_COSE_SIGN1);
  len += cbor_put_array(token, 4);
/* fills array of 4 elements  */
  size_t size = fill_alg_field(field, COSE_Algorithm_EdDSA); 
  len += cbor_put_bytes(token, field, size);
  size = fill_info_sign_field(field,
                                COSE_Elliptic_Curve_Ed25519);
  len += cbor_put_bytes(token, field, size);
  return len;
}



