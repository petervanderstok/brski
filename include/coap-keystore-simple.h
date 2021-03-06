/*
 * Copyright (c) 2017, RISE SICS AB.
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
 * 3. Neither the name of the copyright holder nor the names of its
 *    contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDER AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *         A simple keystore with fixed credentials.
 * \author
 *         Niclas Finne <nfi@sics.se>
 *         Joakim Eriksson <joakime@sics.se>
 * adapted to libcoap 
 *     Peter van der Stok <consultancy@vanderstok.org>
 *     on request of Fairhair alliance
 */

/**
 * \addtogroup coap-keystore
 * @{
 */

#ifndef COAP_KEYSTORE_SIMPLE_H_
#define COAP_KEYSTORE_SIMPLE_H_

/**
 * \brief Registers a simple CoAP DTLS keystore with fixed pre-shared key
 * credentials.
 *
 * The credentials can be configured in project-conf.h as shown in the
 * following example:
 *
 * ~~~~~~~~~~~~~~~{.c}
 * #define COAP_DTLS_PSK_DEFAULT_IDENTITY "user"
 * #define COAP_DTLS_PSK_DEFAULT_KEY      "password"
 * ~~~~~~~~~~~~~~~
 */
void
coap_keystore_simple_init(void);

#endif /* COAP_KEYSTORE_SIMPLE_H_ */
/** @} */
