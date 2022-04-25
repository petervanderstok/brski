/* handle_voucher -- implementation of voucher handling routines using
 * a simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 * handle voucher is added by:
 * Peter van der Stok <consultancy@vanderstok.org>
 */
#ifndef __HV_H__
#define __HV_H__

#include "coap_internal.h"
#include <mbedtls/x509_crt.h>
#include <mbedtls/asn1.h>
#include "str.h"

#define COAP_MEDIATYPE_APPLICATION_MULTIPART_CORE            62
#define COAP_MEDIATYPE_APPLICATION_JSON                      50
#define COAP_MEDIATYPE_APPLICATION_CBOR                      60
#define COAP_MEDIATYPE_APPLICATION_ACE_CBOR               10001

#define COAP_MEDIATYPE_APPLICATION_PKCS7_GENKEY             280
#define COAP_MEDIATYPE_APPLICATION_PKCS7_CERTS              281
#define COAP_MEDIATYPE_APPLICATION_PKCS8                    284
#define COAP_MEDIATYPE_APPLICATION_CSRATTRS                 285
#define COAP_MEDIATYPE_APPLICATION_PKCS10                   286
#define COAP_MEDIATYPE_APPLICATION_PKIX                     287
#define COAP_MEDIATYPE_APPLICATION_VOUCHER_CMS_JSON         836 /* application/voucher-cms+json   */
#define COAP_MEDIATYPE_APPLICATION_VOUCHER_COSE_CBOR      65502 /* application/voucher-cose+cbor   */

#define CVR_VERIFIED       0
#define CVR_LOGGED         1
#define CVR_PROXIMITY      2

#define CV_VERIFIED        0
#define CV_LOGGED          1
#define CV_PROXIMITY       2

/* text values for JSON constrained voucher request */
#define JVR_VOUCHERREQUEST                    "ietf-voucher-request:voucher"
#define JVR_ASSERTION                         "assertion"
#define JVR_CREATEDON                         "createdon"
#define JVR_DOMAINCERTREVOCATIONCHECKS        "domaincertrevocationscheck"
#define JVR_EXPIRESON                         "expireson"
#define JVR_IDEVIDUSER                        "ideviduser"
#define JVR_LASTRENEWALDATE                   "lastrenewaldate"
#define JVR_NONCE                             "nonce"
#define JVR_PINNEDDOMAINCERT                  "pinneddomaincert"
#define JVR_PRIORSIGNEDVOUCHERREQUEST         "priorsignedvoucherrequest"
#define JVR_PROXIMITYREGISTRARCERT            "proximityregistrarcert"
#define JVR_PROXIMITYREGISTRARPUBK            "proximityregistrarpubk"
#define JVR_PROXIMITYREGISTRARPUBKSHA256      "proximityregistrarpubksha256"
#define JVR_SERIALNUMBER                      "serialnumber"

/* text values for JSON constrained voucher          */
#define JV_VOUCHER                           "ietf-voucher:voucher"
#define JV_ASSERTION                         "assertion"
#define JV_CREATEDON                         "createdon"
#define JV_DOMAINCERTREVOCATIONCHECKS        "domaincertrevocationchecks"
#define JV_EXPIRESON                         "expireson"
#define JV_IDEVIDUSER                        "ideviduser"
#define JV_LASTRENEWALDATE                   "lastrenewaldate"
#define JV_NONCE                             "nonce"
#define JV_PINNEDDOMAINCERT                  "pinneddomaincert"
#define JV_PINNEDDOMAINPUBK                  "pinneddomainpubk"
#define JV_PINNEDDOMAINPUBKSHA256            "pinneddomainpubksha256"
#define JV_SERIALNUMBER                      "serialnumber"
#define JV_FALSE                             "false"

/* SID values for CBOR constrained voucher request  */
#define CVR_VOUCHERREQUEST                    2501
#define CVR_ASSERTION                         2502
#define CVR_CREATEDON                         2503
#define CVR_DOMAINCERTREVOCATIONCHECKS        2504
#define CVR_EXPIRESON                         2505
#define CVR_IDEVIDUSER                        2506
#define CVR_LASTRENEWALDATE                   2507
#define CVR_NONCE                             2508
#define CVR_PINNEDDOMAINCERT                  2509
#define CVR_PRIORSIGNEDVOUCHERREQUEST         2510
#define CVR_PROXIMITYREGISTRARCERT            2511
#define CVR_PROXIMITYREGISTRARPUBK            2513
#define CVR_PROXIMITYREGISTRARPUBKSHA256      2512
#define CVR_SERIALNUMBER                      2514

/* SID values for CBOR constrained voucher          */
#define CV_VOUCHER                           2451
#define CV_ASSERTION                         2452
#define CV_CREATEDON                         2453
#define CV_DOMAINCERTREVOCATIONCHECKS        2454
#define CV_EXPIRESON                         2455
#define CV_IDEVIDUSER                        2456
#define CV_LASTRENEWALDATE                   2457
#define CV_NONCE                             2458
#define CV_PINNEDDOMAINCERT                  2459
#define CV_PINNEDDOMAINPUBK                  2460
#define CV_PINNEDDOMAINPUBKSHA256            2461
#define CV_SERIALNUMBER                      2462

/* files exchanged during DTLS/TLS/EDHOC certificate exchange */
#define MASA_CLIENT_DER            "./certificates/transport/masa/client.der"
#define MASA_SERVER_DER            "./certificates/transport/masa/server.der"
#define REGIS_CLIENT_DER           "./certificates/transport/registrar/client.der"
#define REGIS_SERVER_DER           "./certificates/transport/registrar/server.der"
#define PLEDGE_CLIENT_DER          "./certificates/transport/pledge/client.der"
#define PLEDGE_SERVER_DER          "./certificates/transport/pledge/server.der"

/* names of ES256 based CA-files */
#define CA_REGIS_CRT          "./certificates/brski/certs/ca-regis.crt"
#define CA_REGIS_KEY          "./certificates/brski/private/ca-regis.key"
#define CA_REGIS_COMB         "./certificates/brski/certs/ca-regis-comb.crt"
#define CA_MASA_KEY           "./certificates/brski/private/ca-masa.key"
#define CA_MASA_COMB          "./certificates/brski/certs/ca-masa-comb.crt"
#define PLEDGE_CA             "./certificates/brski/certs/ca-masa.crt"

/* definitions of pledge and masa files needed for different vendor tests */
/* local test */
#define CA_MASA_CRT           "./certificates/brski/certs/ca-masa.crt"
#define PLEDGE_CRT            "./certificates/brski/intermediate/certs/pledge_ES256.crt"
#define PLEDGE_KEY            "./certificates/brski/intermediate/private/pledge_ES256.key"
#define PLEDGE_COMB           "./certificates/brski/intermediate/certs/pledge_ES256-comb.crt"
#define MASA_SRV_CRT          "./certificates/brski/intermediate/certs/masa_server.crt"
/* end local test */

/* sandelman test */
//#define CA_MASA_CRT           "./certificates/brski/certs/sandelman_masa.crt"
//#define PLEDGE_CRT            "./certificates/brski/intermediate/certs/sandelman_pledge.crt"
//#define PLEDGE_KEY            "./certificates/brski/intermediate/private/sandelman_pledge.key"
//#define PLEDGE_COMB           "./certificates/brski/intermediate/certs/sandelman_pledge-comb.crt"
//#define MASA_SRV_CRT          "./certificates/brski/intermediate/certs/sandelman_masa_srv.crt"
/* end sandelman test */

/* esko test */
//#define CA_MASA_CRT           "./certificates/brski/certs/esko_masa.crt"
//#define PLEDGE_CRT            "./certificates/brski/intermediate/certs/esko_pledge.crt"
//#define PLEDGE_KEY            "./certificates/brski/intermediate/private/esko_pledge.key"
//#define PLEDGE_COMB           "./certificates/brski/intermediate/certs/esko_pledge-comb.crt"
//#define MASA_SRV_CRT          "./certificates/brski/intermediate/certs/esko_masa_srv.crt"
/* end esko test */

/* siemens test */
//#define CA_MASA_CRT           "./certificates/brski/certs/siemens_masa.crt"
//#define PLEDGE_CRT            "./certificates/brski/intermediate/certs/siemens_pledge.crt"
//#define PLEDGE_KEY            "./certificates/brski/intermediate/private/siemens_pledge.key"
//#define PLEDGE_COMB           "./certificates/brski/intermediate/certs/siemens_pledge-comb.crt"
//#define MASA_SRV_CRT          "./certificates/brski/intermediate/certs/siemens_masa_srv.crt"
/* end siemens test */

#define REGIS_SRV_CRT         "./certificates/brski/intermediate/certs/regis_server.crt"
#define REGIS_SRV_KEY         "./certificates/brski/intermediate/private/regis_server.key"
#define REGIS_SRV_COMB        "./certificates/brski/intermediate/certs/regis_server-comb.crt"
#define MASA_SRV_KEY          "./certificates/brski/intermediate/private/masa_server.key"
#define MASA_SRV_COMB         "./certificates/brski/intermediate/certs/masa_server-comb.crt"

/* names of derived ED25519 based certificates */
#define PLEDGE_ED25519_CRT            "./certificates/brski/intermediate/certs/pledge_ed25519.crt"
#define PLEDGE_ED25519_KEY            "./certificates/brski/intermediate/private/pledge_ed25519.key"
#define PLEDGE_ED25519_COMB           "./certificates/brski/intermediate/certs/pledge_ed25519-comb.crt"
#define REGIS_ED25519_SRV_CRT         "./certificates/brski/intermediate/certs/regis_server_ed25519.crt"
#define REGIS_ED25519_SRV_KEY         "./certificates/brski/intermediate/private/regis_server_ed25519.key"
#define REGIS_ED25519_SRV_COMB        "./certificates/brski/intermediate/certs/regis_server_ed25519-comb.crt"
#define MASA_ED25519_SRV_CRT          "./certificates/brski/intermediate/certs/masa_server_ed25519.crt"
#define MASA_ED25519_SRV_KEY          "./certificates/brski/intermediate/private/masa_server_ed25519.key"
#define MASA_ED25519_SRV_COMB         "./certificates/brski/intermediate/certs/masa_server_ed25519-comb.crt"
//
/* names for EDHOC */
#define REGIS_ES256_SRV_CRT  REGIS_SRV_CRT
#define REGIS_ES256_SRV_KEY  REGIS_SRV_KEY
#define MASA_ES256_SRV_CRT   MASA_SRV_CRT
#define MASA_ES256_SRV_KEY   MASA_SRV_KEY
#define PLEDGE_ES256_KEY     PLEDGE_KEY
#define PLEDGE_ES256_CRT     PLEDGE_CRT

/* BRSKI end result enrolled certificates */
#define PLEDGE_TRUST                "./certificates/brski/certs/pledge_trust.crt"
#define PLEDGE_ENROLL_CRT           "./certificates/brski/intermediate/certs/pledge_enroll.crt"

/* dummy files with csr-att contents  */
#define CSR_ATTRIBUTES        "./certificates/estatt.bin"

/* passwords used during certificate generation  */
#define PLEDGE_PWD            "watnietweet"
#define EMPTY_PWD             NULL;

#define COAP_PORT                  "5683"
#define ALL_COAP_LOCAL_IPV6_NODES  "FF02::FD"
#define ALL_COAP_LOCAL_IPV4_NODES  "224.0.1.187"

/* port discovery for Registrar and Join Proxy */
#define REGISTRAR_RT               "brski.rjp"
#define JOIN_PROXY_RT              "brski.jp"

#define VOUCHER_ACCEPTABLE       0
#define VOUCHER_REJECTED         1

#define JSON_OFF                 0
#define JSON_ON                  1

typedef enum {PLEDGE, REGISTRAR, MASA} certificate_state_t;

/* contains results of parsed voucher (-request */
typedef struct voucher_t{
	char       *created_on;
	size_t     creation_len;
	char       *expires_on;
	size_t     expires_len;
	char       *lst_renewal;
	size_t     lst_renewal_len;
	int8_t     assertion;
	uint8_t    *proxy_registrar;
	size_t     proxy_registrar_len;
	uint8_t    *cvr_nonce;
	size_t     cvr_nonce_len;
	uint8_t    *cvr_idevid;
	size_t     cvr_idevid_len;
	uint16_t   revoc_checks;
	uint8_t    *pinned_domain;
	size_t     pinned_domain_len;
	uint8_t    *prior_signed ;
	size_t     prior_signed_len;
	uint8_t    *sha256_subject;
	size_t     sha256_subject_len;
	uint8_t    *regis_subject;
	size_t     regis_subject_len;
	uint8_t    *pinned_domain_public;
	size_t     pinned_domain_public_len;
	uint8_t    *pinned_domain_sha256;
	size_t     pinned_domain_sha256_len;	
	uint8_t    *serial;
	size_t     serial_len;
	uint8_t    *domainid;
	size_t     domainid_len;
}voucher_t;

/* maintains the status of a given pledge */
typedef struct status_t{
	void            *next;
	uint8_t         acceptable;    /* 0 is not; 1 is acceptable */
	uint8_t         json_cbor;
	char            *reason;
	size_t          reason_len;
	char            *additional_text;
	size_t          additional_text_len;
	uint8_t         *cvr_nonce;
	size_t          cvr_nonce_len;
	uint8_t         *cvr_idevid;
	size_t          cvr_idevid_len;
	uint8_t         *serial;
	size_t          serial_len;
	uint8_t         *request_voucher;
	size_t          rv_len;
    uint8_t         *domainid;
	size_t          domainid_len;
	coap_session_t  *session;
}status_t;


/* contains result of audit log */
typedef struct audit_t{
	uint8_t         acceptable;    /* VOUCHER_ACCEPTABLE or VOUCHER_REJECTED */
	uint8_t         *vr_nonce;
	size_t          vr_nonce_len;
	uint8_t         *vr_idevid;
	size_t          vr_idevid_len;
    uint8_t         *domainid;
	size_t          domainid_len;
}audit_t;

void
remove_voucher(voucher_t *voucher);

void
remove_audit(audit_t *audit);

void
remove_status(status_t *status);

int8_t
brski_create_certificate( char *issuer_crt_file,
                              char *subject_crt_file,
                              char *issuer_key_name,
                              char *subject_key_name,
                              certificate_state_t cert_st);
                              
int8_t
brski_create_key( char *key_filename);                              
                              
int8_t
brski_combine_cert_key( const char *key_file, const char *cert_file, const char *comb_file);                            

int8_t
brski_create_crt(coap_string_t *return_cert, uint8_t *data, size_t len);
 
int8_t
brski_create_csr(coap_string_t *return_crs);

int8_t
brski_return_certificate(coap_string_t *return_crt);

int8_t
brksi_make_signed_rv(coap_string_t *payload, coap_string_t *request_voucher, char *registrar_file, char *pledge_comb);

int8_t
brski_json_voucherstatus(coap_string_t *status);

int8_t
brski_cbor_voucherstatus(coap_string_t *status);

voucher_t *
brski_parse_cbor_voucher(coap_string_t *voucher_req);

voucher_t *
brski_parse_json_voucher(coap_string_t *voucher_req);

int8_t
brski_cbor_voucherrequest(coap_string_t *voucherrequest, coap_string_t *certificate, char *pledge_file);

int8_t
brski_json_voucherrequest(coap_string_t *voucherrequest, coap_string_t *certificate, char *pledge_file);

int8_t
brski_create_cbor_voucher(coap_string_t *voucher, voucher_t *request);

int8_t
brski_create_json_voucher(coap_string_t *voucher, voucher_t *request);

int8_t
brski_cose_sign_payload(coap_string_t *signedpl, coap_string_t *tobesignedpl, char *comb_name);

int8_t
brski_cms_sign_payload(coap_string_t *signedpl, coap_string_t *tobesignedpl, char *key_file );

coap_string_t *
brski_verify_cose_signature(coap_string_t *signed_document, char *cert_file_name, char *ca_name);

coap_string_t *
brski_verify_cms_signature(coap_string_t *signed_document, char *ca_name, char *server_cert);

int8_t
brski_check_voucher(coap_string_t *masa_voucher, coap_string_t *request_voucher);

coap_string_t *
brski_audit_response(voucher_t *voucher);

int8_t
brski_check_pledge_request(voucher_t *req_contents);

int8_t
brski_create_cbor_masa_request(coap_string_t *masa_request, voucher_t *req_contents, coap_string_t *regis_request, char *file_name);

int8_t
brski_create_json_masa_request(coap_string_t *masa_request, voucher_t *req_contents, coap_string_t *regis_request, char *file_name);

int8_t 
brski_json_readstatus(coap_string_t *log, status_t *status);

int8_t 
brski_cbor_readstatus(coap_string_t *log, status_t *status);

audit_t *
brski_parse_audit(coap_string_t *audit_log);

void
brski_validate(status_t *status, audit_t *audit);

int8_t
brski_return_oid( mbedtls_x509_buf *asn, coap_string_t *oid_name, coap_string_t *oid_value);

void set_JSON(uint8_t onoff);

int8_t
JSON_set(void);

#endif /* __AS_H__  */

