/* JP-join-proxy -- implementation of dummy join_proxy using
 * a simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 * Dummy Join_proxy is added by:
 * Peter van der Stok <consultancy@vanderstok.org>
 * This file is loaded and liked when compiled with WITH_JOIN_PROXY but no join_proxy or regsitrar server is targeted
 */


#include <coap.h>

int
jp_transfer (coap_session_t *session, uint8_t *payload, size_t len){
	coap_log(LOG_WARNING,"jp_transfer join-proxy dummy code is not supposed to be invoked ever \n");
	return -1;
}

int
jp_return_transfer(coap_session_t *in_session, uint8_t *payload, size_t len){
    coap_log(LOG_WARNING,"jp_return_transfer join-proxy dummy code is not supposed to be invoked ever \n");
	return -1;
}

uint8_t
jp_not_registrar(uint16_t fd){
	return (fd != 0);
}

uint8_t jp_is_proxy(coap_session_t *session){
	return 0;
}
