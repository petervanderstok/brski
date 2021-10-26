# brski

##BRSKI implementation

Instructions to set up BRSKI test
The brski .c files can be found under: https://github.com/petervanderstok/brski/src
The brski .h files can be found under: https://github.com/petervanderstok/brski/include
They are complemented with the libcoap development files under:
https://gitlab.informatik.uni-bremen.de/obergman/libcoap/-/tree/develop

Regularly new libcoap files will be copied to the vanderstok/brski github repositories

Instruction to setup on PC or Raspberry PI-4

* On the PI test processors and the PC assume a directory ./coap.
- Under ./coap, create ./coap/src, ./coap/include and .coap/out
- Al .h files need to be stored under ./coap/include/. and all .c files under ./coap/src/.
- The generated .o files will be stored under ./coap/out/.
- The Makefile needs to be stored directly under ./coap.
- Create directories ./coap/certificates, ./coap/certificates/brski and ./coap/certificates/conf
- Under ./coap/certificates store brski-cert.sh, wrong_cert.sh and vendor-cert.sh
- Under /.coap/certificates/conf store the openssl-masa.cnf, openssl-regis.cnf, openssl-pledge.cnf, and openssl_wrong.cnf
- Run brski-certs.sh under ./coap. This should generate all certificates
- For interop tests, run vendor-cert.sh under ./coap
- Run make under ./coap.
- A number of executables are created under ./coap: registrar, masa, join_proxy, pledge and coap_client.
- Execute the installation software installation procedure on for example three processors: 2 x PI and 1 x PC. Copy the certificates from one processor to the other two.
- On a PI processor, start a window and under ./coap, invoke ./masa or ./masa -v 7 for debug info.
- On the same PI processor start another window and under ./coap invoke: ./registrar -v 7 -M; the -v 7 can be omitted. The -M is needed when the same pledge certificate is enrolled multiple times for test.
- On another PI processor, start a window and under ./coap  invoke ./pledge -v 7 or ./pledge.
- Join_proxy uses DTLS, and will discover the Registrar and pass through 9 states to enroll itself, and from pledge becomes a join_proxy
- If discovery does not work, try ./pledge -v 7 coaps://[address of registrar processor]
- When registrar is started with -M option; Retry several times the pledge. Without -M, the Registrar should refuse the second and following pledge enrolls.
- When pledge has gone to state 9, start ./pledge -v7 on the PC.
- The pledge should discover the join_proxy, go to state 9 and be enrolled.
- To use EDHOC instead of DTLS for the join_proxy, use ./pledge -v 7 -E 21.
- To see the resources of the join_proxy device under ./coap, invoke ./coap_client -m get coap://[pledge address]/.well-known/core; this will return the resources of the join_proxy device (former pledge).
- To see the resources of the Registrar under ./coap, invoke ./coap_client -m get coap://[registrar address]/.well-known/core; this will return the resources of the Registrar.
- To see the resources of the Registrar via the join_proxy, invoke ./coap_client -m get coaps://[join_proxy address]:5685/.well-known/core. Via this port 5685, the join_proxy directs all DTLS packets to Registrar and directs packets from registrar back to client.

## test program
   
  * test.c contains the test programs compiled to "test" executable.
  * test certificates with error are generated with wrong_cert.s.
  * start up registrar and masa.
  * execute test with ./test coaps://IP_registrar -v 0 without alarm messages.
  * execute test with ./test coaps://IP_registrar to visualize alarm messages returned by Registrar.
   

##changes to libcoap

###Changes done with “#ifdef WITH_OSCORE” to LIBCOAP files

    (1)	In coap_server.c
    Invoked oscore_init to create default oscore context and group oscore context.
    (2)	In coap_client.c 
    Introduces option “-E pkt_nr” with oscore-secure = 1 and oscore_sequence = seqnum;
    E pkt_nr specifies to use default  oscore context starting with packet number pkt_n
    Invoked oscore_init to create default oscore context and group oscore context
    (3)	In mem.h
    Added the malloc types for OSCORE and COSE
    (4)	In pdu.h
    Added COAP_OPTION_OSCORE
    Added COAP_MAX_CHUNK_SIZE and OSCORE_CRYPTO_BUFFER_SIZE
    Added COAP_MEDIATYPE_APPLICATION_OSCORE 
    Added COAP_MEDIATYPE_APPLICATION_ACE_CBOR (preliminary)
    (5)	In coap_session.h
    Added  oscore_encryption to coap_session_t
    (6)	In net.h
    Added osc_ctx to in coap_context_t
    (7)	In net.c
    Added initialization of oscore field in coap_context_t
    Added call to oscore_message_encrypt in coap-send_pdu
    Added oscore_message_decrypt in coap_handle_dgram
    (8)	In resource.c
    Added “;osc” to link description
    (9)	In coap_debug.c 
    Added COAP_OPTION_OSCORE for debug print

###Changes done with #ifdef  JOIN_PROXY to LIBCOAP files

1.	In net.c, include JP_server.h
2.	In net.c coap_handle-dgram, test of jin-proxy session
3.	In coap_session.c coap_endpoint_get_session, test on registrar

Change done for debugging, not recommended for libcoap:

 - Added coap_malloc and coap_free counters for debugging.

###NEW files are:

Developed from Kontiki files are:

    (1)	ccm-star.c removed 256 byte limit at several places
    (2)	OSCORE.c redone almost completely
    (3)	CBOR.c added 70% more functions
    (4)	COSE.c added 30% more functions 
    (5) JSON.c completely new
    (6)	oscore-crypto.c added 30% more functions
    (7)	oscore-context.c added more functionality
    (8)	in all files adapted memory handling to libcoap and compiler characteristics

No changes done to ED25519 signature  files.
ED25519 signature  files are:

    * Ed25519.h
    * edDSA_fixint.h
    * edDSA_precomp_data.h
    * edDSA_add_scalar.c
    * edDSA_ge.h and -.c
    * edDSA_keypair.c
    * edDSA_seed.c
    * edDSA_verify.c
    * edDSA_fe.h and -.c
    * edDSA_key_exchange.h and -.c
    * edDSA_sc.h and -.c
    * edDSA_sign.c
    * sha512.h and -.c


new unchanged KONTIKI files are:

     *	aes-128.h and -.c
     *	coap-keystore-simple.h and -.c
     *	dtls-hmac.h and -.c
     *	coap-keystore.h
     *	sha256.h and -.c

Miscellaneous crypto info:

    * Security library mbedtls is interfaced with libcoap using coap_mbedtls.c
    * All oscore file are currently integrated into libcoap
    * The ed25519 files are to be ignored when supported by mbedtls
    * CMS signing needs the openssl library

