/* Join_stateful.c -- implementation of join-proxy transmission using
 * a simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 * JOIN_Proxy is added by:
 * Peter van der Stok <consultancy@vanderstok.org>
 *
 * This file is part of the CoAP library libcoap. Please see README for terms
 * of use.
 *
 * Join_proxy routines are defined in JP_server.h
 */

#include <string.h>
#include <stdio.h>
#include "cbor.h"
#include "client_request.h"
#include "JP_server.h"
#include "brski.h"

#include <coap.h>

static uint8_t transfer_type = JP_NOT_DEFINED;

/* a client sends request to registrar via join-proxy; 
 * jp_send_out:      join-proxy encapsulates and sends to registrar
 * jp_receive_in:    registrar decapsulates and invokes resource
 * jp_send_back:     registrar encapsulates response and sends to join_proxy
 * jp_pass_back:     join_proxy decapsulates response and sends response to client.
 */
/* brskfd is the file-descriptor of the server_port of the join_proxy to write to client  */
/* registrar_session is the fixed session to the registrar
 * only one registrar - used for enrollment of join_proxy */
 
static uint16_t brskifd = 0;
static coap_session_t *registrar_session; 

uint16_t 
jp_get_brskifd(void){
	return brskifd;
}

void 
jp_set_brskifd(uint16_t fd){
	brskifd = fd;
	coap_log(LOG_DEBUG,"brskifd is %d \n", brskifd);
}

static coap_session_t * 
jp_get_registrar_session(void){
	return registrar_session;
}

uint16_t 
jp_get_registrar_fd(void){
coap_session_t * session = jp_get_registrar_session();
   if (session != NULL)return session->sock.fd;
   else return 0;
}

uint8_t
is_registrar(void){
	return (transfer_type == JP_SERVER);
}
 
void 
jp_set_registrar_session(coap_session_t *s){
	registrar_session = s;
	s->proto = COAP_PROTO_DTLS;
	coap_log(LOG_DEBUG,"registrar_session is set to %p \n", s);
}


typedef struct relation_t {
  void * next;
  coap_session_t *session_in;
  coap_session_t *session_out;
  uint8_t *IP_address;
  size_t address_len;
  uint16_t port;
} relation_t;
      

static relation_t *RELATIONS = NULL;


static relation_t *
create_relation(coap_session_t * session_in, coap_session_t *session_out){
	relation_t *temp = coap_malloc(sizeof(relation_t));
	memset(temp, 0, sizeof(relation_t));
	temp->next = RELATIONS;
	temp->session_in = session_in;
	temp->session_out = session_out;
	if (session_in != NULL){
	   coap_address_t *address = &(session_in->addr_info.remote); 
	   temp->port = coap_address_get_port(address);   
	}
	RELATIONS = temp;
	return temp;
}

static void
remove_relation(relation_t *relation){
    if (RELATIONS == relation){
		RELATIONS = relation->next;
		if (relation->session_in != NULL)coap_session_release(relation->session_out);  
		if (relation->session_in != NULL)coap_session_release(relation->session_in);  
		coap_free(relation);
		return;
	}
	relation_t * temp = RELATIONS;
    while (temp != NULL){
       if (temp->next == relation){
		   temp->next = relation->next;
		   if (relation->session_in != NULL)coap_session_release(relation->session_out);  
		   if (relation->session_in != NULL)coap_session_release(relation->session_in);  
		   coap_free(relation);
		   return;
	   } 
       temp = temp->next;
   } /* while */

}

/* find_corresponding_in
 * finds the corresponding in_session with specified session_in in relation
 */
static relation_t *
find_corresponding_in(coap_session_t *session){
	relation_t *temp = RELATIONS;
	while (temp != NULL){
		if (session == temp->session_in)return temp;
		temp = temp->next;
	}
	return NULL;
}

/* find_corresponding_out
 * finds the corresponding session with specified session_out in relation
 */
static relation_t *
find_corresponding_out(coap_session_t *session){
	relation_t *temp = RELATIONS;
	while (temp != NULL){
		if (session == temp->session_out)return temp;
		temp = temp->next;
	}
	return NULL;
}

/* relation exists
 * finds the corresponding session with specified session in relation
 */
static relation_t *
relation_exists(coap_session_t *session){
	relation_t *temp = RELATIONS;
	while (temp != NULL){
		if ((session == temp->session_out) || (session == temp->session_in)){
		   if (session == temp->session_in){
		     coap_address_t *address = &(session->addr_info.remote); 
	         uint16_t port = coap_address_get_port(address);   
		     if (temp->port == port) return temp;
	/* ports are unequal, consequently this is an outdated session_in */ 
		     temp->session_in = NULL;
		     remove_relation(temp);
		     return NULL;
		   }
		   return temp;
		}
		temp = temp->next;
	}
	return NULL;
}


uint8_t
jp_is_proxy(coap_session_t *session){
  uint16_t  fd = session->sock.fd;
  if (session->endpoint != NULL) fd = session->endpoint->sock.fd; /* session->sock.fd van be zero */
  if (brskifd == fd)return 1;
  if (find_corresponding_out(session) != NULL) return 1;
  return 0;
}


uint8_t
jp_not_registrar(uint16_t fd){

	return (fd != 0);
}


void
jp_registrar(void){
	transfer_type = JP_SERVER;
}

void
jp_proxy(void){
	transfer_type = JP_PROXY;
}

/* jp_send_back
 * sends data back from registrar to join_proxy using stored sessions
 */
static int  
jp_send_back(relation_t *relation, const uint8_t *payload, size_t len){
	coap_session_t *session_out = relation->session_in;
	coap_socket_t *sock = &session_out->sock;
	if (sock->flags == COAP_SOCKET_EMPTY) {
       assert(session_out->endpoint != NULL);
       sock = &session_out->endpoint->sock;
    }
    uint8_t *newp = (uint8_t *)payload;
    ssize_t bytes_written = coap_socket_send(sock, session_out, newp, len);
    return bytes_written;
}


/* jp_pass_back
 * join_proxy sends data back received from registrar to client
 */
static int  
jp_pass_back(relation_t *relation, const uint8_t *payload, size_t len){
	coap_session_t *session_in = relation->session_in;
	coap_socket_t *sock = &session_in->sock;
	if (sock->flags == COAP_SOCKET_EMPTY) {
       assert(session_in->endpoint != NULL);
       sock = &session_in->endpoint->sock;
    }
    uint8_t *newp = (uint8_t *)payload;
    ssize_t bytes_written = coap_socket_send(sock, session_in, newp, len);
    return bytes_written;
}

/* jp_receive_in
 * receives data locally over session from join_proxy
 * invokes dtls_hello and dtls_receive on registrar
 */
static int  
jp_receive_in(coap_session_t *session_in, uint8_t *payload, size_t len,
                                        relation_t *relation){

   relation->session_in = session_in;        /* on registrar, session_in and session_out are equal */

   if (session_in->type == COAP_SESSION_TYPE_HELLO){
         int result = coap_dtls_hello(session_in, payload, len);
         return result;
   }
   else if (session_in->tls){
       int result = coap_dtls_receive(session_in, payload, len);
       return result;
   }
   else return -1;
}     

/* jp_send_out
 * invoked by join-Proxy to send to registrar
 * sends data over new session to be created 
 */
static int  
jp_send_out(coap_session_t *session_in, uint8_t *payload, size_t len,
                                       relation_t *relation){
    coap_context_t *ctx = session_in->context;
    if (ctx == NULL){
		coap_log(LOG_ERR,"no context associated with incoming session \n");
		return -1;
	}
    coap_session_t *session_out = NULL;
    if (relation->session_out == NULL){
      session_out = coap_start_session(ctx);
      relation->session_out = session_out;
    } else session_out = relation->session_out;
    coap_socket_t *sock = &session_out->sock;
    if (sock->flags == COAP_SOCKET_EMPTY) {
      assert(session_out->endpoint != NULL);
      sock = &session_out->endpoint->sock;
    }
    ssize_t bytes_written = coap_socket_send(sock, session_out, payload, len);
    if (bytes_written == (ssize_t)len) {
       coap_ticks(&session_out->last_rx_tx);
       coap_log(LOG_DEBUG, "*  %s: sent %zd bytes\n",
             coap_session_str(session_out), len);
    } else {
       coap_log(LOG_DEBUG, "*  %s: failed to send %zd bytes\n",
             coap_session_str(session_out), len);
    }
    return bytes_written;
}


/* jp_return_transfer is invoked on return of response to COAP_BRSKI_PORT
 * function determined by value of tranfer_type variable
 * JP_PROXY is the join-Proxy
 * JP_SERVER is the Registrar
 */
int
jp_return_transfer(coap_session_t *in_session, const uint8_t *payload, size_t len){
	relation_t *relation = find_corresponding_in(in_session);
	if (relation == NULL){
        coap_log(LOG_ERR,"no relation found for this session \n");
        return -1;
	}
    switch (transfer_type){
		case JP_NOT_DEFINED:
		  coap_log(LOG_WARNING,"join-proxy code is not initialized  \n");
		  return -1;
		  break;
        case JP_PROXY:
          return jp_pass_back(relation, payload, len);
          break;
        case JP_SERVER:
          return jp_send_back(relation, payload, len);
          break;
        default:
          coap_log(LOG_ERR,"Serious impossible situation in join_proxy code \n");
          break;
	}
	return -1;
}


/* jp_transfer is invoked
 * on reception from COAP_PROTO_BRSKI port
 * function determined by value of tranfer_type variable
 * JP_PROXY is the join-Proxy
 * JP_SERVER is the Registrar
 */
int
jp_transfer (coap_session_t *session, uint8_t *payload, size_t len){
	relation_t *relation = relation_exists(session);
	if (relation == NULL){
		relation = create_relation(session, NULL);
	}
	switch (transfer_type){
		case JP_NOT_DEFINED:
		  coap_log(LOG_WARNING,"join-proxy code is not initialized  \n");
		  return -1;
		  break;
        case JP_PROXY:
          relation = find_corresponding_in(session);
          if (relation != NULL){
             return jp_send_out(session, payload, len, relation);
          } else {
			 relation = find_corresponding_out (session);
             return jp_pass_back(relation, payload, len);			  
		  }
          break;
        case JP_SERVER:
          return jp_receive_in(session, payload, len, relation);
          break;
        default:
          coap_log(LOG_ERR,"Serious impossible situation in join_proxy code \n");
          break;
	}
	return -1;
}


