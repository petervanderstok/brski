/* Join_stateless.c -- implementation of join-proxy stateless transmission using
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
#include <arpa/inet.h>
#include "cbor.h"
#include "client_request.h"
#include "JP_server.h"
#include "coap_internal.h"
#include "brski.h"

#include <coap.h>

uint8_t debug_counter = 0;

/* brskfd is the file-descriptor of the server_port of the join_proxy to write to client  */
/* registrar_session is the fixed session to the registrar
 * only one registrar - used for enrollment of join_proxy */
static uint16_t brskifd = 0;
static coap_session_t *registrar_session;

void 
jp_set_brskifd(uint16_t fd){
	brskifd = fd;
	coap_log(LOG_DEBUG,"brskifd is %d \n", brskifd);
}


static coap_session_t * 
jp_get_registrar_session(void){
	return registrar_session;
}

static uint16_t 
jp_get_registrar_fd(void){
coap_session_t * session = jp_get_registrar_session();
   if (session != NULL)return session->sock.fd;
   else return 0;
}

void 
jp_set_registrar_session(coap_session_t *s){
	registrar_session = s;
	s->proto = COAP_PROTO_DTLS;
	coap_log(LOG_DEBUG,"registrar_session is set to %p \n", s);
}

uint8_t
jp_is_proxy(coap_session_t *session){
  uint16_t  fd = session->sock.fd;
  if (session->endpoint != NULL) fd = session->endpoint->sock.fd; /* session->sock.fd van be zero */
  if (brskifd == fd)return 1;
  if (jp_get_registrar_fd() == fd) return 1;
  return 0;
}
/* a client sends request to registrar via join-proxy; 
 * jp_send_out:      join-proxy encapsulates and sends to registrar
 * jp_receive_in:    registrar decapsulates and invokes resource
 * jp_send_back:     registrar encapsulates response and sends to join_proxy
 * jp_pass_back:     join_proxy decapsulates response and sends response to client.
 */

typedef struct jp_relation_t {
  void * next;
  coap_session_t *session_in;
  coap_addr_tuple_t addr_info; 
  coap_tick_t last_xs;
} jp_relation_t;
      

static uint8_t transfer_type = JP_NOT_DEFINED;

uint8_t
jp_not_registrar(uint16_t fd){
	if ((brskifd == fd) || jp_get_registrar_fd() == fd)
	       return (transfer_type != JP_SERVER);
	else return 1;
}


static jp_relation_t *RELATIONS = NULL;



static void
empty_relation(jp_relation_t *relation){
	if (relation->session_in != NULL)coap_free(relation->session_in); 
	coap_free(relation);
}

static jp_relation_t *
remove_relation(jp_relation_t *relation){
	jp_relation_t *next_ret = NULL;
    if (RELATIONS == relation){
		RELATIONS = relation->next;
		next_ret = relation->next;
		empty_relation(relation);
		return next_ret;
	}
	jp_relation_t * temp = RELATIONS;
    while (temp != NULL){
       if (temp->next == relation){
		   temp->next = relation->next;
		   next_ret = relation->next;
		   empty_relation(relation);
		   return next_ret;
	   } 
       temp = temp->next;
   } /* while */
   return next_ret;
}

static char *
jp_relation_str(jp_relation_t *relation){
  static char szSession[2 * (INET6_ADDRSTRLEN + 8) + 24];
  char *p = szSession, *end = szSession + sizeof(szSession);
  memset(p,0,sizeof(szSession));
  if (coap_print_addr(&relation->addr_info.local,
                      (unsigned char*)p, end - p) > 0)
    p += strlen(p);
  if (p + 6 < end) {
    strcpy(p, " <-> ");
    p += 5;
  }
  if (p + 1 < end) {
    if (coap_print_addr(&relation->addr_info.remote,
                        (unsigned char*)p, end - p) > 0)
      p += strlen(p);
  }

  if (p + 6 < end) {
      strcpy(p, "BRSKI");
      p += 6;     
  }
  return szSession;
}

  
static void
print_relation(jp_relation_t *relation){
    coap_log(LOG_DEBUG, "relation %s   \n",jp_relation_str( relation));
}


void
enter_relation(jp_relation_t *relation, coap_session_t * session_in){
	relation->next = RELATIONS;
	coap_ticks(&relation->last_xs);
    coap_session_t *session = coap_malloc(sizeof(coap_session_t));
    memcpy(session, session_in, sizeof(coap_session_t));
    session->type = COAP_SESSION_TYPE_HELLO;
    relation->session_in = session;
	RELATIONS = relation;
	print_relation(relation);
}

/*
static void
print_relations(void){
	jp_relation_t * temp = RELATIONS;
	while (temp != NULL){
		print_relation( temp);
	}
}
* */


/* find_corresponding_IP
 * finds the corresponding relation with specified remote IP address
 */
static jp_relation_t *
find_corresponding_IP(coap_address_t *addr){
	coap_tick_t now;
	coap_ticks(&now);
	jp_relation_t *found = NULL;
	jp_relation_t *temp = RELATIONS;
	while (temp != NULL){
        if (coap_address_equals(addr, &temp->addr_info.remote)) {
			found = temp;
			coap_ticks(&temp->last_xs);
			temp = temp->next;
		}
        else if (temp->last_xs + COAP_PARTIAL_SESSION_TIMEOUT_TICKS < now){
			coap_log(LOG_DEBUG,"*** %s relation removed \n",jp_relation_str(temp));
			temp = remove_relation(temp);
		} else 
		    temp = temp->next;
	}
	return found;
}


/* find_corresponding_in
 * finds the corresponding in_session with specified session_in in relation
 */
static jp_relation_t *
find_corresponding_in(coap_session_t *session){
	jp_relation_t *temp = RELATIONS;
	while (temp != NULL){
		if (session == temp->session_in)return temp;
		temp = temp->next;
	}
	return NULL;
}


void
jp_registrar(void){
	transfer_type = JP_SERVER;
}

void
jp_proxy(void){
	transfer_type = JP_PROXY;
}

/* jp_encapsulate
 * creates the message header for encapsulation
 * returns header size
 */
static int
jp_encapsulate(uint8_t * jp_hdr, uint16_t port, uint8_t *IP_address, size_t address_len, uint16_t family, uint8_t if_index){
	uint8_t *hdr = jp_hdr;
	size_t nr = 0;
	nr += cbor_put_array(&hdr, 5);
	nr += cbor_put_bytes( &hdr, (uint8_t *)IP_address, address_len);
	nr += cbor_put_number(&hdr, port);
	nr += cbor_put_number(&hdr, family);    /* address family (ipv4/IPv6) */
	nr += cbor_put_number(&hdr, if_index);  /* interface index  */
    return nr;
}


/* jp_enter_local
 * enter local address in registrar->addr
 * copied from session
 * used for debugging
 */
void
jp_enter_local(jp_relation_t *relation, coap_session_t *session){
    coap_address_init(&relation->addr_info.local);   
    coap_address_copy(&relation->addr_info.local, &(session->addr_info.local));
}

/* jp_decapsulate
 * Receives a cbor structure with payload and header
 * removes the join-proxy header description, stores the return address/port in relation
 * and returns the remaining amount of data to send
 * returns 0 when received data does not contain the correct cbor structure
 */
static size_t
jp_decapsulate (uint8_t *payload, size_t len,
                                      jp_relation_t *relation){
	uint8_t  *data = payload;
	int64_t  mm = 0;
	size_t   data_len = 0;
	char     *IP_address = NULL;
	size_t   IP_address_len = 0;
	uint16_t port = 0;
	uint16_t family;
	uint8_t  if_index;
    uint8_t elem = cbor_get_next_element(&data);
    if (elem != CBOR_ARRAY) return 0;
	size_t arr_size = cbor_get_element_size(&data);
    if (arr_size != 5) return 0;
    /* read IP address, Port, family and index  */
	uint8_t ok = cbor_get_string_array(&data, (uint8_t **)&IP_address, &IP_address_len);
	if (ok != 0)return 0;
	ok = cbor_get_number(&data, &mm);
	if (ok != 0)return 0;
	port = (uint16_t)mm;
	ok = cbor_get_number(&data, &mm);
	if (ok !=0)return 0;
	family = (uint32_t)mm;  /* family */
	ok = cbor_get_number(&data, &mm);
	if_index = (uint8_t)mm;
	if (ok !=0)return 0;
	/* set data to start of DTLS data and data_len to size of DTLS data*/
	elem = cbor_get_next_element(&data);
	if (elem != CBOR_BYTE_STRING)return 0; 
	data_len = cbor_get_element_size(&data);
    coap_address_init(&relation->addr_info.remote);
    relation->addr_info.remote.addr.sa.sa_family = family;
    if (relation->addr_info.remote.addr.sa.sa_family == AF_INET) {
        relation->addr_info.remote.addr.sin.sin_port = htons(port);
        relation->addr_info.remote.size =  sizeof(struct sockaddr_in);   
        memcpy(&(relation->addr_info.remote.addr.sin.sin_addr),IP_address, IP_address_len);
    } else if (relation->addr_info.remote.addr.sa.sa_family == AF_INET6) {
        relation->addr_info.remote.addr.sin6.sin6_port = htons(port);
        relation->addr_info.local.size =  sizeof(struct sockaddr_in6);
        memcpy(&(relation->addr_info.remote.addr.sin6.sin6_addr),IP_address, IP_address_len);
        relation->addr_info.remote.addr.sin6.sin6_scope_id = if_index;
    }
	/* payload is decapsulated  */
	coap_free(IP_address);
    return data_len;
}

/*    CODE executed by REGISTRAR */

/* jp_send_back
 * sends data back from registrar to join_proxy over stored session
 */
static int  
jp_send_back(coap_session_t *session_in, const uint8_t *payload, size_t len){
    jp_relation_t *relation = find_corresponding_in(session_in);
	if (relation == NULL){
		coap_log(LOG_ERR,"relation not found \n");
        return -1;
	}
	coap_session_t *session_out = relation->session_in;
	coap_socket_t *sock = &session_out->sock;
	if (sock->flags == COAP_SOCKET_EMPTY) {
       assert(session_out->endpoint != NULL);
       sock = &session_out->endpoint->sock;
    }
	char hdr[200];
	size_t nr = 0;
	if (relation->addr_info.remote.addr.sa.sa_family == AF_INET) {
		nr = jp_encapsulate((uint8_t *)hdr, 
		    ntohs(relation->addr_info.remote.addr.sin.sin_port),
		    (uint8_t *)&relation->addr_info.remote.addr.sin.sin_addr,
		    sizeof(struct in_addr),
		    relation->addr_info.remote.addr.sa.sa_family,
            0 );
    } else if (relation->addr_info.remote.addr.sa.sa_family == AF_INET6) {
		nr = jp_encapsulate((uint8_t *)hdr, 
		    ntohs(relation->addr_info.remote.addr.sin6.sin6_port),
		    (uint8_t *)&relation->addr_info.remote.addr.sin6.sin6_addr,
		    sizeof(struct in6_addr),
		    relation->addr_info.remote.addr.sa.sa_family,
            relation->addr_info.remote.addr.sin6.sin6_scope_id);
    }

    uint8_t *start = coap_malloc(nr + len + 5);
    memcpy(start, hdr, nr);             /* copy header */
    uint8_t *data = start + nr;
    uint8_t *buf  = NULL;
    memcpy(&buf, &payload, sizeof(buf));     /* remove compiler warning  */
    size_t data_len = cbor_put_bytes(&data, buf, len);   /* copy payload */
    data_len = data_len + nr;
    assert(data_len < nr + len + 5);
    ssize_t bytes_written = coap_socket_send(sock, session_out, start, data_len);
    coap_log(LOG_DEBUG, "*  %s: sent %zd bytes to join_proxy on fd: %d\n",
            coap_session_str(session_out), data_len, sock->fd);
    coap_free(start);
    if (bytes_written == data_len) return len;
    else return (bytes_written);
}


/* jp_receive_in
 * receives data locally over session from join_proxy
 * invokes dtls_hello and dtls_receive on registrar
 */
static int  
jp_receive_in(coap_session_t *session_in, uint8_t *payload, size_t len){
   jp_relation_t *temp = coap_malloc(sizeof(jp_relation_t));
   memset(temp, 0, sizeof(jp_relation_t));
   size_t data_len = jp_decapsulate(payload, len, temp);
   jp_enter_local(temp, session_in);
   /* find relation for this IP_address  */
   jp_relation_t *relation = find_corresponding_IP(&temp->addr_info.remote);
   if (relation == NULL){
      relation = temp;
      enter_relation(relation, session_in);
   } else coap_free( temp);
   /* take over port number of client  */
   session_in = relation->session_in;
   memcpy(payload, payload + len - data_len, data_len);
   if (session_in->type == COAP_SESSION_TYPE_HELLO){
         int result = coap_dtls_hello(session_in, payload, data_len);
         if (result == 1) coap_session_new_dtls_session(session_in, relation->last_xs);
         return result;
   }
   else if (session_in->tls){
       int result = coap_dtls_receive(session_in, payload, data_len);
       return result;
   }
   else return -1;
}     

/*      CODE executed by PROXY  */

/* jp_pass_back
 * join_proxy sends data back received from registrar to client
 */
static int  
jp_pass_back(coap_session_t *session_in, const uint8_t *payload, size_t len){
	jp_relation_t relation_buf;
	jp_relation_t *relation = &relation_buf;
	memset(relation, 0, sizeof(jp_relation_t));
	uint8_t *newpl = NULL;  
	memcpy(&newpl, &payload, sizeof(newpl));  /* remove compiler warning */
    size_t data_len = jp_decapsulate (newpl, len, relation);
    jp_enter_local(relation, session_in);
    memcpy( newpl, payload + len - data_len, data_len);
    ssize_t bytes_written = sendto(brskifd, newpl, data_len, 0,
                           (void *)&relation->addr_info.remote.addr.sa, relation->addr_info.remote.size);
    if (bytes_written == (ssize_t)data_len) {
       coap_log(LOG_DEBUG, "*  %s: sent %zd bytes to client on fd: %d\n",
              jp_relation_str(relation), data_len, brskifd);
    } else {
       coap_log(LOG_DEBUG, "*  %s: failed to send %zd bytes on fd: %d\n",
             jp_relation_str(relation), data_len, brskifd);
    }
    if (bytes_written == data_len) return len;
    else return bytes_written;
}



/* jp_send_out
 * invoked by join-Proxy to send to registrar
 * sends data over new session to be created 
 */
static int  
jp_send_out(coap_session_t *session_in, uint8_t *payload, size_t len){
	size_t address_len;
	char hdr[200];
	/* find IP_address and IP_port */
    /* and save them in message and relation  */
	coap_address_t *address = &(session_in->addr_info.remote); 
 	char *IP_address = NULL;
 	uint8_t  if_index = 0;
	uint16_t port = coap_address_get_port(address); 
    switch (address->addr.sa.sa_family) {
      case AF_INET:
          address_len = sizeof(struct in_addr);
          IP_address = coap_malloc(address_len);
          memcpy(IP_address, (void *)&(address->addr.sin.sin_addr), address_len);
          break;
      case AF_INET6:
          address_len = sizeof(struct in6_addr);
          IP_address = coap_malloc(address_len);
          memcpy(IP_address, (void *)&(address->addr.sin6.sin6_addr), address_len);
          if_index = address->addr.sin6.sin6_scope_id;
          break;
      default: /* fall through and signal error */
          return -1;
    }
/* host and port are already defined in cmdline or via discovery */	  
    coap_socket_t *sock_in = &session_in->sock;
    if (sock_in->flags == COAP_SOCKET_EMPTY) {
      assert(session_in->endpoint != NULL);
      sock_in = &session_in->endpoint->sock;
    }  
    size_t hdr_len = jp_encapsulate((uint8_t *)hdr, port, (uint8_t *)IP_address, 
                   address_len, address->addr.sa.sa_family, if_index);      
    uint8_t *start = coap_malloc(hdr_len + len + 4);
    memcpy(start, hdr, hdr_len);                       /* copy header */
    uint8_t *data = start + hdr_len;
    size_t nr = cbor_put_bytes(&data, payload, len);   /* copy payload */
    assert(nr < len + 4);
    coap_context_t *ctx = session_in->context;
    if (ctx == NULL){
		coap_log(LOG_ERR,"no context associated with incoming session \n");
		return -1;
	}
	/* get_registrar_session returns session for all transports to registrar */
	 
    coap_session_t *session_out = jp_get_registrar_session();
    coap_socket_t *sock = &session_out->sock;
    if (sock->flags == COAP_SOCKET_EMPTY) {
      assert(session_out->endpoint != NULL);
      sock = &session_out->endpoint->sock;
    }
    ssize_t bytes_written = send(sock->fd, start, nr + hdr_len, 0);
    coap_free(start);
    if (bytes_written == (ssize_t)nr + hdr_len) {
       coap_ticks(&session_out->last_rx_tx);
       coap_log(LOG_DEBUG, "*  %s: sent %zd bytes to registrar on fd:  %d\n",
             coap_session_str(session_out), len, sock->fd);

    } else {
       coap_log(LOG_DEBUG, "*  %s: failed to send %zd bytes\n",
             coap_session_str(session_out), len);
    }
    return bytes_written;
}


/* jp_return_transfer is invoked 
 * on return of response to COAP_BRSKI_PORT
 * function determined by value of tranfer_type variable
 * JP_PROXY is the join-Proxy
 * JP_SERVER is the Registrar
 */
int
jp_return_transfer(coap_session_t *in_session, const uint8_t *payload, size_t len){
    switch (transfer_type){
		case JP_NOT_DEFINED:
		  coap_log(LOG_WARNING,"join-proxy code is not initialized  \n");
		  return -1;
		  break;
        case JP_PROXY:
          return jp_pass_back( in_session, payload, len);
          break;
        case JP_SERVER:
          return jp_send_back( in_session, payload, len);
          break;
        default:
          coap_log(LOG_ERR,"Serious impossible situation  in join_proxy code \n");
          break;
	}
	return -1;
}


/* jp_transfer is invoked
 * on reception of request from a join_proxy port
 * function determined by value of tranfer_type variable
 * JP_PROXY is the join-Proxy
 * JP_SERVER is the Registrar
 */
int
jp_transfer (coap_session_t *session, uint8_t *payload, size_t len){
	switch (transfer_type){
		case JP_NOT_DEFINED:
		  coap_log(LOG_WARNING,"join-proxy code is not initialized  \n");
		  return -1;
		  break;
        case JP_PROXY:
          if (session == jp_get_registrar_session()){
			 return jp_pass_back(session, payload, len);	
          } else {
             return jp_send_out(session, payload, len);	  
		  }
          break;
        case JP_SERVER:
          return jp_receive_in(session, payload, len);
          break;
        default:
          coap_log(LOG_ERR,"Serious impossible situation in join_proxy code \n");
          break;
	}
	return -1;
}



