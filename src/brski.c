/* handle_voucher -- implementation of voucher handling routines using
 * a simple implementation of the Constrained Application Protocol (CoAP)
 *         as defined in RFC 7252
 * handle voucher is added by:
 * Peter van der Stok <consultancy@vanderstok.org>
 */

#include "coap_internal.h"
#include "brski.h"
#include "stdio.h"
#include "cbor.h"
#include "json.h"
#include "cose.h"

#include "client_request.h"
#include "sv_cl_util.h"
#include "oscore-mbedtls.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <ctype.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <mbedtls/x509_crt.h>
#include <mbedtls/asn1.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/ecp.h>
#include <mbedtls/pk.h>
#include <mbedtls/md.h>
#include <mbedtls/sha256.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/error.h>
#include <mbedtls/config.h>
#include <mbedtls/oid.h>

#include <openssl/pem.h>
#include <openssl/cms.h>
#include <openssl/err.h>

#define VS_SUCCESS  1    /* voucher status ok */
#define VS_FAIL     0    /* voucher status not OK */

#define ED_BYTES             32
#define HASH256_BYTES        32
#define NONCE_LEN            16

#define VALIDITY_YEARS       2

#define OID_SERIAL_NUMBER    5
#define OID_KEY_IDENTIFIER   14

/* RET_CHECK returns ret which is sometimes needed for size considerations 
 * CHECK uses ret to signal mbedtls function errors */
#define RET_CHECK( x )                                                  \
    do {                                                                \
        int CHECK__ret_ = ( x );                                        \
        ret = CHECK__ret_;                                              \
        if( CHECK__ret_ < 0 )                                          \
        {                                                               \
            char CHECK__error_[100];                                    \
            mbedtls_strerror( CHECK__ret_,                              \
                              CHECK__error_, sizeof( CHECK__error_ ) ); \
            coap_log(LOG_ERR, "%s -> %s\n", #x, CHECK__error_ );        \
            ok = 1;                                                     \
            goto exit;                                                  \
        }                                                               \
    } while( 0 )
    
#define CHECK( x )                                                      \
    do {                                                                \
        int CHECK__ret_ = ( x );                                        \
        if( CHECK__ret_ < 0 )                                          \
        {                                                               \
            char CHECK__error_[100];                                    \
            mbedtls_strerror( CHECK__ret_,                              \
                              CHECK__error_, sizeof( CHECK__error_ ) ); \
            coap_log(LOG_ERR, "%s -> %s\n", #x, CHECK__error_ );        \
            ok = 1;                                                     \
            goto exit;                                                  \
        }                                                               \
    } while( 0 )


static int8_t JSON_for_voucher_request    = 0;

static void
empty_voucher(voucher_t *voucher){
	if (voucher == NULL)return;
	if (voucher->created_on != NULL)coap_free(voucher->created_on);
    if (voucher->expires_on != NULL)coap_free(voucher->expires_on);
    if (voucher->lst_renewal != NULL)coap_free(voucher->lst_renewal);
    if (voucher->proxy_registrar != NULL)coap_free(voucher->proxy_registrar);
    if (voucher->cvr_nonce != NULL)coap_free(voucher->cvr_nonce);
    if (voucher->cvr_idevid != NULL)coap_free(voucher->cvr_idevid);  
    if (voucher->pinned_domain != NULL)coap_free(voucher->pinned_domain);
    if (voucher->prior_signed != NULL)coap_free(voucher->prior_signed);
    if (voucher->sha256_subject != NULL)coap_free(voucher->sha256_subject);  
    if (voucher->regis_subject != NULL)coap_free(voucher->regis_subject);
    if (voucher->pinned_domain_public != NULL)coap_free(voucher->pinned_domain_public);
    if (voucher->pinned_domain_sha256 != NULL)coap_free(voucher->pinned_domain_sha256);  
    if (voucher->serial != NULL)coap_free(voucher->serial);
    if (voucher->domainid != NULL)coap_free(voucher->domainid);
}

void 
remove_voucher(voucher_t *voucher){
	if (voucher == NULL)return;
	empty_voucher(voucher);	
	coap_free(voucher);
}

void
remove_audit(audit_t *audit){
	if (audit == NULL) return;
	if(audit->vr_nonce != NULL)coap_free(audit->vr_nonce);
	if(audit->vr_idevid != NULL)coap_free(audit->vr_idevid);
    if(audit->domainid != NULL)coap_free(audit->domainid);
	coap_free(audit);
}

void
remove_status(status_t *status){
	if (status == NULL)return;
    if (status->reason != NULL) coap_free(status->reason);
	if (status->additional_text != NULL) coap_free(status->additional_text);
	if (status->cvr_nonce != NULL) coap_free(status->cvr_nonce);
	if (status->cvr_idevid != NULL) coap_free(status->cvr_idevid);
    if (status->serial != NULL) coap_free(status->serial);
	if (status->request_voucher != NULL) coap_free(status->request_voucher);
    if (status->domainid != NULL) coap_free(status->domainid);
    coap_free(status);
}


#define CRT_BUF_SIZE   1024
#define KEY_END        ""
#define SID_END        0
#define REQUEST_VOUCHER_ONLY         0
#define VOUCHER_ONLY                 1
#define VOUCHER_AND_REQUEST_VOUCHER  2

const char *voucher_request_key[] = {
JVR_VOUCHERREQUEST,
JVR_ASSERTION,
JVR_CREATEDON,
JVR_DOMAINCERTREVOCATIONCHECKS,
JVR_EXPIRESON,
JVR_IDEVIDUSER,
JVR_LASTRENEWALDATE,
JVR_NONCE,
JVR_PINNEDDOMAINCERT,
JVR_PRIORSIGNEDVOUCHERREQUEST,
JVR_PROXIMITYREGISTRARCERT,
JVR_PROXIMITYREGISTRARPUBKSHA256,
JVR_PROXIMITYREGISTRARPUBK,
JVR_SERIALNUMBER,
KEY_END};

uint16_t voucher_request_sid[] = {
CVR_VOUCHERREQUEST,
CVR_ASSERTION,
CVR_CREATEDON,
CVR_DOMAINCERTREVOCATIONCHECKS,
CVR_EXPIRESON,
CVR_IDEVIDUSER,
CVR_LASTRENEWALDATE,
CVR_NONCE,
CVR_PINNEDDOMAINCERT,
CVR_PRIORSIGNEDVOUCHERREQUEST,
CVR_PROXIMITYREGISTRARCERT,
CVR_PROXIMITYREGISTRARPUBKSHA256,
CVR_PROXIMITYREGISTRARPUBK,
CVR_SERIALNUMBER,
SID_END};

uint16_t voucher_sid[] = {
CV_VOUCHER,
CV_ASSERTION,
CV_CREATEDON,
CV_DOMAINCERTREVOCATIONCHECKS,
CV_EXPIRESON,
CV_IDEVIDUSER,
CV_LASTRENEWALDATE,
CV_NONCE,
CV_PINNEDDOMAINCERT,
CV_PINNEDDOMAINPUBK,
CV_PINNEDDOMAINPUBKSHA256,
CV_SERIALNUMBER,
SID_END};


const char *voucher_key[] = {
JV_VOUCHER,
JV_ASSERTION,
JV_CREATEDON,
JV_DOMAINCERTREVOCATIONCHECKS,
JV_EXPIRESON,
JV_IDEVIDUSER,
JV_LASTRENEWALDATE,
JV_NONCE,
JV_PINNEDDOMAINCERT,
JV_PINNEDDOMAINPUBK,
JV_PINNEDDOMAINPUBKSHA256,
JV_SERIALNUMBER,
SID_END};

static int8_t 
binary_value(coap_string_t *text, int8_t *tf){
	if (strncmp((char *)text->s, "FALSE", text->length) == 0) *tf = 0;          /* false */
    else if (strncmp((char *)text->s, "false", text->length) == 0) *tf = 0;     /* false */
	else if (strncmp((char *)text->s, "TRUE", text->length) == 0) *tf = 1;      /* true */
	else if (strncmp((char *)text->s, "true", text->length) == 0) *tf = 1;      /* true */	
	else return 1;
	return 0;
}


static uint16_t
find_sid(coap_string_t *text,uint8_t type){
	uint16_t cnt =0;
	if (type != VOUCHER_ONLY){
	  while (strlen(voucher_request_key[cnt]) != 0){
		if (strncmp(voucher_request_key[cnt], (char *)text->s, text->length) == 0)
		        return voucher_request_sid[cnt];
	    cnt++;
	  }
    }
	cnt = 0;
	if (type != REQUEST_VOUCHER_ONLY){
       while (strlen(voucher_key[cnt]) != 0){
	      if (strncmp(voucher_key[cnt], (char *)text->s, text->length) == 0)
		        return voucher_sid[cnt];
	      cnt++;
      }
	}
	return 0;
}

/* ROUTINES to generate CERTIFICATE and KEY */

#define FORMAT_PEM              0
#define FORMAT_DER              1
// also used to define CA = TRUE/FALSE in certificate
#define CREATE_CA               1
#define CREATE_CERT             0
#define HEX_RADIX               16

#define DFL_NOT_BEFORE          "20010101000000"
#define DFL_NOT_AFTER           "20301231235959"
#define ISSUER_NAME             "CN=registrar.vanderstok.tech,O=vanderstok,OU=home,L=Helmond,C=NL";
#define SUBJECT_NAME            "CN=registrar.vanderstok.tech,O=vanderstok,OU=home_ops,L=Helmond,C=NL";
#define SERIAL_NUMBER_FILE      "./certificates/brski/serial"

/* filter_time
 * filters YYYYMMDDhhmmss form date and store intp filter
 */
static void
filter_time(char *date, char *filter){
    int in = 0;
    int out = 0;
    while (date[in] != 0){
	if (('0'-1 < date[in]) && (date[in] < '9'+1)){
	    filter[out] = date[in];
	    out++;
	}
	in++;
    }
    filter[out] = 0;
}

   
/* 
 * read-serial
 * returns certificate serial number 
 */
static char *
read_serial(){
#define BN_LEN      64
  size_t length = 0;
  char serial_file[] = SERIAL_NUMBER_FILE;
  uint8_t *buf = read_file_mem(serial_file, &length);
  if (buf == NULL) return NULL;
  length = length -1;
  while (buf[length -1] < '0'){ /* remove spurious cr, lf and 0 */
     length = length -1;
     buf[length] = 0;
  }
  char obuf[BN_LEN+1]; 
  memset(obuf,'0',BN_LEN);
  memcpy(obuf + BN_LEN -length, buf, length); 
 
  char tmp[BN_LEN+1];
  tmp[BN_LEN] = 0;
  struct bn big;
  struct bn one;
  struct bn res;
  bignum_init(&big);
  bignum_init(&one);
  bignum_init(&res);
  bignum_from_int(&one, (DTYPE_TMP)1);
  bignum_from_string(&big, obuf, BN_LEN);
  bignum_to_string(&big, tmp, BN_LEN);
  bignum_add(&big, &one, &res);
  bignum_to_string(&res, tmp, BN_LEN);
  coap_string_t contents = { .s = (uint8_t *)tmp, .length = strlen(tmp)};
  write_file_mem(serial_file, &contents);
  return (char *)buf;
}

/*
 * brski_combine_cert_key
 * appends Registrar key in key-file to registrar certificate in cert_file to comb_file
 * returns o => Ok;  else error number
 */

int8_t
brski_combine_cert_key( const char *key_file, const char *cert_file, const char *comb_file)
{
    int ok = -1;  /* error return */
    FILE *kf = fopen(key_file, "r");;
    FILE *cf = fopen(cert_file, "r");;
    FILE *of = fopen(comb_file, "w");;
  uint8_t ch = 0;
  struct stat statbuf_k;
  struct stat statbuf_c;

  if (!kf){
    coap_log(LOG_ERR,"cannot open for read  file %s \n",key_file);
    return ok;
  }
  if (!cf){
    coap_log(LOG_ERR,"cannot open for read  file %s \n",cert_file);
    return ok;
  }
  if (!of){
    coap_log(LOG_ERR,"cannot open for write  file %s \n",comb_file);
    return ok; 
  }  
  if (fstat(fileno(kf), &statbuf_k) == -1) {
    coap_log(LOG_ERR,"cannot read  file %s \n",key_file);
    fclose(kf); fclose(cf); fclose(of);
    return ok;
  }
  if (fstat(fileno(cf), &statbuf_c) == -1) {
    coap_log(LOG_ERR,"cannot read  file %s \n",cert_file);
    fclose(kf); fclose(cf); fclose(of);
    return ok;
  }  
  /* copy certificate to combined file */
  for (uint qq = 0; qq < statbuf_c.st_size; qq++){
    if (fread(&ch, 1, 1, cf) != 1) {
      coap_log(LOG_ERR,"cannot read  file %s \n",cert_file);
      fclose(kf); fclose(cf); fclose(of);
      return ok;
    }
    if (fwrite( &ch, 1, 1, of) != 1){
      coap_log(LOG_ERR,"cannot write to  file %s \n",comb_file);
      fclose(kf); fclose(cf); fclose(of);
      return ok;
    }
  }
  fclose(cf);
  /* copy key file to combined file */
  for (uint qq = 0; qq < statbuf_k.st_size; qq++){
    if (fread(&ch, 1, 1, kf) != 1) {
      coap_log(LOG_ERR,"cannot read  file %s \n",key_file);
      fclose(kf); fclose(of);
      return ok;
    }
    if (fwrite( &ch, 1, 1, of) != 1){
      coap_log(LOG_ERR,"cannot write to  file %s \n",comb_file);
      fclose(kf); fclose(of);
      return ok;
    }
  } 
  ok = 0; 
  fclose(kf); fclose(of);
  return ok;
}

/*
 * write_private_key
 * Writes  Registrar key to file
 * returns o => Ok;  else error number
 */

static int8_t
write_private_key( mbedtls_pk_context *key, const char *output_file, int format)
{
#define MEM_SIZE    16000
    int ok = -1;
    FILE *f;
    unsigned char output_buf[MEM_SIZE];
    unsigned char *c = output_buf;
    size_t len = 0;

    memset(output_buf, 0, MEM_SIZE);
    if( format == FORMAT_PEM )
    {
        CHECK(mbedtls_pk_write_key_pem( key, output_buf, MEM_SIZE ) );
        len = strlen( (char *) output_buf );
    }
    else
    {
        CHECK(mbedtls_pk_write_key_der( key, output_buf, MEM_SIZE ) );
        len = ok;
        c = output_buf + sizeof(output_buf) - len;
    }
    if( ( f = fopen( output_file, "wb" ) ) == NULL ) {
      coap_log(LOG_ERR," cannot open key file %s\n", output_file);
      goto exit;
    }
    if( fwrite( c, 1, len, f ) != len ) {
      coap_log(LOG_ERR," cannot write to key file %s \n", output_file);
      goto exit1;
    }
    ok = 0;
exit1:
    fclose( f );
exit:
   return ok;
}

    
/*
 * brski_create_key
 * creates and ecp key for Registrar
 * uses secp256r1
 * returns 0 => Ok; else returns 1
 */

int8_t
brski_create_key( char *key_filename)
{
    int ok = 1;
    mbedtls_pk_context key;
    char buf[1024];    /* buf for drbg */
    mbedtls_mpi N, P, Q, D, E, DP, DQ, QP;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "gen_key";

    /*
     * Set to sane values
     */

    mbedtls_mpi_init( &N ); mbedtls_mpi_init( &P ); mbedtls_mpi_init( &Q );
    mbedtls_mpi_init( &D ); mbedtls_mpi_init( &E ); mbedtls_mpi_init( &DP );
    mbedtls_mpi_init( &DQ ); mbedtls_mpi_init( &QP );

    mbedtls_pk_init( &key );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    memset( buf, 0, sizeof( buf ) );
    int opt_format              = FORMAT_PEM;
    
    const mbedtls_ecp_curve_info *curve_info = mbedtls_ecp_curve_info_from_name( "secp256r1");
    if (curve_info == NULL){
      coap_log(LOG_ERR,"Cannot find ecp curve secp256r1 \n");
      goto exit;
    }
    int opt_ec_curve = curve_info->grp_id;
    mbedtls_entropy_init( &entropy );

    CHECK( mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) );
 
    /*
     * 1.1. Generate the key
     */
    CHECK(mbedtls_pk_setup( &key,
            mbedtls_pk_info_from_type( MBEDTLS_PK_ECKEY ) ) );
    CHECK(mbedtls_ecp_gen_key( (mbedtls_ecp_group_id) opt_ec_curve,
                                   mbedtls_pk_ec( key ),
                                   mbedtls_ctr_drbg_random, &ctr_drbg ));
    /*
     * 1.2 show the key for debugging
     */
    if( mbedtls_pk_get_type( &key ) == MBEDTLS_PK_ECKEY )
    {
        mbedtls_ecp_keypair *ecp = mbedtls_pk_ec( key ); 
        coap_log(LOG_DEBUG, "private key uses curve: %s\n",
                mbedtls_ecp_curve_info_from_grp_id( ecp->grp.id )->name );
	if (coap_get_log_level() > LOG_DEBUG-1){
          mbedtls_mpi_write_file( "X_Q:   ", &ecp->Q.X, 16, NULL );
          mbedtls_mpi_write_file( "Y_Q:   ", &ecp->Q.Y, 16, NULL );
          mbedtls_mpi_write_file( "D:     ", &ecp->d  , 16, NULL );
        }
    }
    else {
        coap_log(LOG_WARNING,"  ! key type not supported\n");
	goto exit;
    }
    /*
     * 1.3 Export key
     */
    CHECK(write_private_key( &key, key_filename, opt_format ) );
     ok = 0;
exit:
    mbedtls_mpi_free( &N ); mbedtls_mpi_free( &P ); mbedtls_mpi_free( &Q );
    mbedtls_mpi_free( &D ); mbedtls_mpi_free( &E ); mbedtls_mpi_free( &DP );
    mbedtls_mpi_free( &DQ ); mbedtls_mpi_free( &QP );
    mbedtls_pk_free( &key );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    return ok;
}

/* write-certificate
 * writes certificate for registrar to output_file
 */
static
int write_certificate( mbedtls_x509write_cert *crt, const char *output_file,
                       int (*f_rng)(void *, unsigned char *, size_t),
                       void *p_rng )
{
    int ok = -1;
    FILE *f;
    unsigned char output_buf[4096];
    size_t len = 0;
    memset( output_buf, 0, sizeof(output_buf) );
    CHECK(mbedtls_x509write_crt_pem( crt, output_buf, 4096,
                                           f_rng, p_rng ) );
    len = strlen( (char *) output_buf );
    if( ( f = fopen( output_file, "w" ) ) == NULL ){
        coap_log(LOG_ERR,"could not open file %s \n", output_file);
	goto exit;
    }
    if( fwrite( output_buf, 1, len, f ) != len )
    {
        coap_log(LOG_ERR,"could not write to %s \n", output_file);
	goto exit1;
    }
    ok = 0;
exit1:
    fclose( f );
exit:
    return( ok);
}

#define     DATE_SIZE    100

/*       
 * create certificate 
 * is_ca = 0: self_signed  certicate
 * is_ca = 1: certificate to be signed by issuer
 * returns 0 => Ok
 */
 int8_t
 brski_create_certificate( char *issuer_crt_file,
                              char *subject_crt_file,
                              char *issuer_key_name,
                              char *subject_key_name)
 {
    int ok = 1;  /* failure return values */
    int is_ca = CREATE_CERT;
    if (subject_crt_file == NULL) is_ca = CREATE_CA;
    mbedtls_x509_crt issuer_crt;
    mbedtls_pk_context loaded_issuer_key, loaded_subject_key;
    mbedtls_pk_context *issuer_key = &loaded_issuer_key,
                *subject_key = &loaded_subject_key;
    char buf[1024];
    char ret_issuer_name[256];
    mbedtls_x509write_cert crt;
    mbedtls_mpi serial;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers  = "crt example app";
    const char *issuer_name = NULL;
    const char *subject_name = NULL;
    int version       = 2;
    mbedtls_md_type_t md_alg = MBEDTLS_MD_SHA256;
    char *serial_nb = NULL;
    char not_before[DATE_SIZE];
    char not_after[DATE_SIZE];
    char tm_temp[DATE_SIZE];
    int max_pathlen  = -1;
    unsigned char  key_usage =  0;
    char issuer_pwd[] = "watnietweet";
    char subject_pwd[] = "watnietweet";
    char *output_file  = NULL;
    key_usage  |= MBEDTLS_X509_KU_DIGITAL_SIGNATURE;
    key_usage  |= MBEDTLS_X509_KU_KEY_CERT_SIGN;
    key_usage  |= MBEDTLS_X509_KU_CRL_SIGN;

    /*
     * Set to sane values
     */
    mbedtls_x509write_crt_init( &crt );
    mbedtls_pk_init( issuer_key );
    mbedtls_pk_init( subject_key );
    mbedtls_mpi_init( &serial );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
    mbedtls_x509_crt_init( &issuer_crt );
    memset( buf, 0, sizeof(buf) );
    issuer_name  = ISSUER_NAME;
    subject_name = SUBJECT_NAME;
    /*
     * read serial number from file and increase
     */
    serial_nb = read_serial();
    /*
     * set start and end dates
     */
    time_t rawtime;
    time(&rawtime);
    struct tm tm_buf;
    memset(&tm_buf, 0, sizeof(struct tm));   
    struct tm *current = gmtime_r(&rawtime, &tm_buf); 
    strftime(tm_temp, DATE_SIZE, "%Y-%m-%dT%H:%M:%SZ", current);
    filter_time(tm_temp, not_before);
    current->tm_year = current->tm_year + VALIDITY_YEARS;
    strftime(tm_temp, DATE_SIZE, "%Y-%m-%dT%H:%M:%SZ", current);   
    filter_time(tm_temp, not_after);    
    /*
     * 0. Seed the PRNG
     */
    CHECK(mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ) );
    // Parse hexadecimal serial to MPI
    //
    CHECK(mbedtls_mpi_read_string( &serial, HEX_RADIX, serial_nb ) );
    /*
     * 1.1. Load the keys
     */
    if( is_ca == CREATE_CERT  )
    {
    // Check if key and issuer certificate match when not self-signed
    //
        CHECK(mbedtls_x509_crt_parse_file( &issuer_crt, issuer_crt_file ) );
        CHECK(mbedtls_x509_dn_gets( ret_issuer_name, sizeof(ret_issuer_name),
                                 &issuer_crt.subject ));
        issuer_name = ret_issuer_name;
        CHECK(mbedtls_pk_parse_keyfile( subject_key, subject_key_name,
                                 subject_pwd ));	
    }
    CHECK(mbedtls_pk_parse_keyfile( issuer_key, issuer_key_name,
                             issuer_pwd ));
    if( is_ca== CREATE_CERT) {
      CHECK(mbedtls_pk_check_pair( &issuer_crt.pk, issuer_key ));
    }		              
    if (is_ca == CREATE_CA){
/* self sign:  issuer and subject are identical */
        subject_name = issuer_name;
        subject_key = issuer_key;
	output_file = issuer_crt_file;
    } else output_file = subject_crt_file;

    mbedtls_x509write_crt_set_subject_key( &crt, subject_key );
    mbedtls_x509write_crt_set_issuer_key( &crt, issuer_key );
    /*
     * 1.0. Check the names for validity
     */
    CHECK(mbedtls_x509write_crt_set_subject_name( &crt, subject_name ) );
    CHECK(mbedtls_x509write_crt_set_issuer_name( &crt, issuer_name ) );
    mbedtls_x509write_crt_set_version( &crt, version );
    mbedtls_x509write_crt_set_md_alg( &crt, md_alg );
    CHECK(mbedtls_x509write_crt_set_serial( &crt, &serial ));
    CHECK(mbedtls_x509write_crt_set_validity( &crt, not_before, not_after ));
    CHECK(mbedtls_x509write_crt_set_basic_constraints( &crt, is_ca,
							     max_pathlen ));
    CHECK(mbedtls_x509write_crt_set_subject_key_identifier (&crt));	
    CHECK(mbedtls_x509write_crt_set_authority_key_identifier (&crt));
    CHECK(mbedtls_x509write_crt_set_key_usage( &crt, key_usage ));   
     
/* construct the asn_buf for extended key usage */       
 #define MBEDTLS_OID_REGIS_AUTH                 MBEDTLS_OID_KP "\x1c"
       uint8_t asn_buf[46];
       memset(asn_buf, 0, sizeof(asn_buf));
       uint8_t *p = asn_buf + sizeof(asn_buf);
       CHECK(mbedtls_asn1_write_oid( &p, asn_buf,
                            MBEDTLS_OID_SERVER_AUTH, sizeof(MBEDTLS_OID_SERVER_AUTH)-1 ));
       CHECK(mbedtls_asn1_write_oid( &p, asn_buf,
                            MBEDTLS_OID_CLIENT_AUTH, sizeof(MBEDTLS_OID_CLIENT_AUTH)-1 ));
       CHECK(mbedtls_asn1_write_oid( &p, asn_buf,
                            MBEDTLS_OID_REGIS_AUTH, sizeof(MBEDTLS_OID_REGIS_AUTH)-1 ));
       CHECK(mbedtls_asn1_write_tag( &p, asn_buf, MBEDTLS_ASN1_BMP_STRING ));
       CHECK(mbedtls_asn1_write_tag( &p, asn_buf, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE ));	    		    			    
       size_t asn_len = sizeof(asn_buf) - (size_t)(p - asn_buf);      
       CHECK(mbedtls_x509_set_extension( &crt.extensions, MBEDTLS_OID_EXTENDED_KEY_USAGE, sizeof(MBEDTLS_OID_EXTENDED_KEY_USAGE) - 1,
				 0 , p, asn_len));
    /*
     * 1.2. Writing the certificate
     */
    CHECK(write_certificate( &crt, output_file,
                                   mbedtls_ctr_drbg_random, &ctr_drbg ) );  // to certificate file
  
    ok = 0;

exit:
    coap_free(serial_nb);
    mbedtls_x509_crt_free( &issuer_crt );
    mbedtls_x509write_crt_free( &crt );
    mbedtls_pk_free( subject_key );
    mbedtls_pk_free( issuer_key );
    mbedtls_mpi_free( &serial );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    return ok;
}

/* return_oid
 * returns value of specified OID of x509 v3 ca certificate 
 * returns Ok =0 , Nok 1
 * IN:  asn is pointer to certificate asn1 string
 * IN:  oid_name contains oid identifier
 * OUT: oid_value contains returned oid value
 */
int8_t
brski_return_oid( mbedtls_x509_buf *asn, coap_string_t *oid_name, coap_string_t *oid_value){
	if ((asn == NULL) || (oid_name == NULL) || (oid_value == NULL))return 1;
	if (oid_name->s == NULL) return 1;
    char err_buf[CRT_BUF_SIZE];       
    int     ret = 0;
    int tag = asn->tag;                /**< ASN1 type, e.g. MBEDTLS_ASN1_UTF8_STRING. */
    size_t len = asn->len;             /**< ASN1 length, in octets. */
    unsigned char *p = asn->p;         /**< ASN1 data, e.g. in ASCII. */
    const unsigned char *end = p + len;  
/* sequence of sequences expected */
    ret = mbedtls_asn1_get_tag(&p, end, &len ,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
	if (ret != 0){
            mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
            coap_log(LOG_ERR, " failed\n  !  mbedtls_asn1_get_tag finding sequence of sequences; "
                            "returned -0x%04x - %s\n\n", (unsigned int) -ret, err_buf );
	}

    while (p < end){
		int found = 0;
		size_t qlen = 0;
		/* get a sequence from the sequence of sequences */
	    ret = mbedtls_asn1_get_tag(&p, end, &qlen ,
        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
		if ( ret == 0){
			unsigned char *q = p;
	        unsigned char *qend = q + qlen;
	        while (q < qend){
		       size_t plen;
		       q++;
	           ret = mbedtls_asn1_get_len(&q, end, &plen);
	           if (ret != 0){
                   mbedtls_strerror( ret, err_buf, sizeof(err_buf) );
                   coap_log(LOG_ERR, " failed\n  !  mbedtls_asn1_get_len "
                            "returned -0x%04x - %s\n\n", (unsigned int) -ret, err_buf );
	           }
	           tag = *(q-2);
	           if (tag == MBEDTLS_ASN1_OID){
				  if (*(q-1) == oid_name->length){
					found = 1;
	                for ( uint qq = 0; qq < oid_name->length; qq++){
	                  if (oid_name->s[qq] != q[qq])found = 0;
				    }
				 }
			   } 
			   if ((found == 1) && (tag == MBEDTLS_ASN1_OCTET_STRING)){
				   oid_value->length = plen;
		           oid_value->s = coap_malloc(plen);
				   memcpy(oid_value->s, q, plen);
				   return 0;
			   }
	           q = q + plen;
	        }
	    }  /* if */
	    p = p + qlen;   
	}  
	return 1;  
}  


/* return_subject_ski
 * returns subject key identifier in subject of x509 v3 ca certificate 
 * returns Ok =0 , Nok 1
 * IN:  asn is pointer to subject asn1 string
 * OUT: key_id contains returned key identifier
 */
static int8_t
return_subject_ski( mbedtls_x509_buf *asn, coap_string_t *key_id){
	uint8_t   ski[3] = {0x55, 0x1d, 0xe};
	coap_string_t oid_name = {.length = sizeof(ski), .s = ski};
	int8_t ok = brski_return_oid( asn, &oid_name, key_id);
	if (ok != 0)coap_log(LOG_WARNING," Subject Key Identifier OID is not found \n");
    return ok;
}

/* return_authority_aki
 * returns authority key identifier in subject of x509 v3 ca certificate 
 * returns Ok =0 , Nok 1
 * IN:  asn is pointer to subject asn1 string
 * OUT: key_id contains returned key identifier
 */
static int8_t
return_authority_aki( mbedtls_x509_buf *asn, coap_string_t *key_id){
	uint8_t   aki[3] = {0x55, 0x1d, 0x23};
	coap_string_t oid_name = {.length = sizeof(aki), .s = aki};
	int8_t ok = brski_return_oid( asn, &oid_name, key_id);
	if (ok != 0){
		coap_log(LOG_WARNING," Authority Key Identifier OID is not found \n");
		return 1;
	}
	/* prefix OCTET STRING size 24 */
	uint8_t *tmp = coap_malloc(key_id->length+2);
	tmp[0] = MBEDTLS_ASN1_OCTET_STRING;
	tmp[1] = key_id->length;
	memcpy(tmp+2, key_id->s, key_id->length);
	key_id->length = key_id->length+2;
	coap_free(key_id->s);
	key_id->s = tmp;
	return 0;
}

 
/* return_subject_sn
 * returns serial number contained in subject of x509 v3 ca certificate
 * returns Ok =0 , Nok 1
 * name is pointer to subject asn1 string
 * sn and sn_len contain returned serial number
 */
static int8_t
return_subject_sn( mbedtls_x509_name *asn, char **sn, size_t *sn_len){

   while (asn != NULL){
        mbedtls_asn1_buf val  = asn->val;     
	    mbedtls_asn1_buf oid  = asn->oid;
        unsigned char *oidptr = oid.p;
        unsigned char *valptr = oid.p;
        uint8_t        oidval = oidptr[2];
        if (oidval == OID_SERIAL_NUMBER){
			char *ptr = coap_malloc(val.len);
			*sn_len = val.len;
			for (uint qq = oid.len + 2; qq < oid.len+ 2 + val.len; qq++){
				ptr[qq - oid.len -2] = valptr[qq];
			}
			*sn = ptr;
			return 0;
		}
        asn = asn->next;
	}
	return 1;
}

/* create_certificate
 * create_crt(coap_string_t *return_cert, uint8_t *data, size_t len))
 * data with length len contains CSR
 * request file is to store pem as temporary CSR file
 * return signed certificate into return_cert 
 * return: OK = 0; NOK =1
 */
#define MBEDTLS_EXIT_SUCCESS    EXIT_SUCCESS
#define MBEDTLS_EXIT_FAILURE    EXIT_FAILURE

 int8_t
brski_create_crt(coap_string_t *return_cert, uint8_t *data, size_t len){
#define CRT_SUBJECT_PWD         NULL
#define CRT_ISSUER_PWD          "watnietweet"
#define CRT_SELFSIGN            0
#define CRT_IS_CA               0
#define CRT_MAX_PATHLEN         -1
#define CRT_KEY_USAGE           0
#define CRT_NS_CERT_TYPE        0
#define CRT_VERSION             2
#define CRT_AUTH_IDENT          1
#define CRT_SUBJ_IDENT          1
#define CRT_CONSTRAINTS         1
#define CRT_DIGEST              MBEDTLS_MD_SHA256
#define CRT_BUF_SIZE            1024
    if (return_cert == NULL)return 1;
	int ret = 1;
    const char               *issuer_pwd;               /* password for the issuer key file     */
    const char               *issuer_crt_name;          /* filename for the crt file            */
    const char               *issuer_key_name;          /* filename of the issuer key file      */
    char                     tm_temp[DATE_SIZE];        /* long value of time string            */
    char                     not_before[DATE_SIZE];     /* validity period not before           */
    char                     not_after[DATE_SIZE];      /* validity period not after            */
    int                      is_ca;                     /* is a CA certificate                  */
    int                      max_pathlen;               /* maximum CA path length               */
    unsigned char            ns_cert_type;              /* NS cert type                         */
    mbedtls_x509_crt         issuer_crt;
    mbedtls_pk_context       loaded_issuer_key, loaded_subject_key;
    mbedtls_pk_context       *issuer_key = &loaded_issuer_key,
                             *subject_key = &loaded_subject_key;
    char                      issuer_name[256];
    char                      subject_name[256];
    mbedtls_x509_csr          csr;
    mbedtls_x509write_cert    crt;
    mbedtls_mpi               serial;
    char                      *serial_nb = NULL;
    mbedtls_entropy_context   entropy;
    mbedtls_ctr_drbg_context  ctr_drbg;
    mbedtls_md_type_t         md;
    int                       version;
    const char                *pers = "BRSKI registrar";
    char                      buf[CRT_BUF_SIZE];
    int8_t                    ok = 0;

    /*
     * Initialize structures and values
     */
    mbedtls_x509write_crt_init( &crt );
    mbedtls_pk_init( &loaded_issuer_key );
    mbedtls_pk_init( &loaded_subject_key );
    mbedtls_mpi_init( &serial );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
    mbedtls_x509_csr_init( &csr );
    mbedtls_x509_crt_init( &issuer_crt );

    issuer_crt_name = CA_REGIS_CRT;
    issuer_key_name = CA_REGIS_KEY;
    issuer_pwd      = CRT_ISSUER_PWD;
    subject_name[0] = 0;
    issuer_name[0]  = 0;
    version         = CRT_VERSION;
    md              = CRT_DIGEST;
    ns_cert_type    = CRT_NS_CERT_TYPE;  
    is_ca           = CRT_IS_CA;
    max_pathlen     = CRT_MAX_PATHLEN;
   /*
    * read serial number from file and increase
    */
    serial_nb = read_serial();   
    /*
     * set start and end dates
     */
    time_t rawtime;
    time(&rawtime);
    struct tm tm_buf;
    memset(&tm_buf, 0, sizeof(struct tm));   
    struct tm *current = gmtime_r(&rawtime, &tm_buf); 
    strftime(tm_temp, DATE_SIZE, "%Y-%m-%dT%H:%M:%SZ", current);
    filter_time(tm_temp, not_before);
    current->tm_year = current->tm_year + VALIDITY_YEARS;
    strftime(tm_temp, DATE_SIZE, "%Y-%m-%dT%H:%M:%SZ", current);  
    filter_time(tm_temp,not_after);
    /*
     * 0. Seed the PRNG
     */
    CHECK(mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers,
                               strlen( pers ) ));
    // Parse serial to MPI
    //
    CHECK(mbedtls_mpi_read_string( &serial, HEX_RADIX, serial_nb ) );
    /*      
     * 1.0.a. Load the issuer certificates
     */

    CHECK(mbedtls_x509_crt_parse_file( &issuer_crt, issuer_crt_name));

    CHECK(mbedtls_x509_dn_gets( issuer_name, sizeof(issuer_name),
                                 &issuer_crt.subject ));
    // Parse certificate request from data 
    //
    CHECK(mbedtls_x509_csr_parse_der( &csr, data, len ) );

    CHECK(mbedtls_x509_dn_gets( subject_name, sizeof(subject_name),
                                &csr.subject ));
    subject_key = &csr.pk;
    /*
     * 1.1. Load the keys
     */
    CHECK(mbedtls_pk_parse_keyfile( &loaded_issuer_key, issuer_key_name,
                             issuer_pwd ));

    // Check if key and issuer certificate match
    //
    if( strlen( issuer_crt_name ) > 0 )
    {
                 CHECK( mbedtls_pk_check_pair( &issuer_crt.pk, issuer_key ) );
	}
    mbedtls_x509write_crt_set_subject_key( &crt, subject_key );
    mbedtls_x509write_crt_set_issuer_key( &crt, issuer_key );

    /*
     * 1.0. Check the names for validity
     */
    CHECK( mbedtls_x509write_crt_set_subject_name( &crt, subject_name ) );

    CHECK( mbedtls_x509write_crt_set_issuer_name( &crt, issuer_name ) );
 
    mbedtls_x509write_crt_set_version( &crt, version );
    mbedtls_x509write_crt_set_md_alg( &crt, md );
    CHECK(mbedtls_x509write_crt_set_serial( &crt, &serial ));

    CHECK( mbedtls_x509write_crt_set_validity( &crt, not_before, not_after ));

    CHECK( mbedtls_x509write_crt_set_basic_constraints( &crt, is_ca,
                                                           max_pathlen ));
    CHECK(mbedtls_x509write_crt_set_subject_key_identifier( &crt ));

    CHECK(mbedtls_x509write_crt_set_authority_key_identifier( &crt ));

    if( ns_cert_type != 0 )
    {
        CHECK(mbedtls_x509write_crt_set_ns_cert_type( &crt, ns_cert_type ));
    }
/* store certificate in memory of return-cert 
 */
    RET_CHECK(mbedtls_x509write_crt_der( &crt, (unsigned char *)buf, CRT_BUF_SIZE,
                       NULL, NULL ));
    assert(ret < CRT_BUF_SIZE);
    return_cert->s = coap_malloc(ret);
    return_cert->length = ret;
    memcpy(return_cert->s, buf + CRT_BUF_SIZE - ret, ret);

exit:
    mbedtls_x509_csr_free( &csr );
    mbedtls_x509_crt_free( &issuer_crt );
    mbedtls_x509write_crt_free( &crt );
    mbedtls_pk_free( &loaded_subject_key );
    mbedtls_pk_free( &loaded_issuer_key );
    mbedtls_mpi_free( &serial );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    return ok;
} 

int8_t
brksi_make_signed_rv(coap_string_t *payload, coap_string_t *request_voucher, char *registrar_file, char *pledge_comb){
   if ((request_voucher == NULL) || (payload == NULL)) return 1;
   mbedtls_x509_crt registrar_crt;
   mbedtls_x509_crt_init( &registrar_crt);
   int8_t   ok = 0;
   /* fill regis_crt with registrar certificate needed in request_voucher */
   coap_string_t regis_crt = {.length = 0, .s = NULL};
   CHECK( mbedtls_x509_crt_parse_file( &registrar_crt, registrar_file ) );
   mbedtls_x509_buf *der = &registrar_crt.raw;
   unsigned char *ptr = der->p;
   size_t raw_len = der->len;
   regis_crt.s = coap_malloc(raw_len);
   regis_crt.length = raw_len;
   memcpy(regis_crt.s, ptr, raw_len);  
  /* regis_crt contains certificate in der from file SERVER_DER  */ 
   if (JSON_set() == JSON_ON){    
            ok = brski_json_voucherrequest(request_voucher, &regis_crt, pledge_comb);
   } else 
            ok = brski_cbor_voucherrequest(request_voucher, &regis_crt, pledge_comb);   
   if (ok != 0){
      coap_log(LOG_ERR, "voucher request is not generated \n");
      goto exit;
   }
   if (JSON_set() == JSON_ON){
	  ok = brski_cms_sign_payload(payload, request_voucher, pledge_comb );
   } else{
      ok = brski_cose_sign_payload(payload, request_voucher, pledge_comb );
   }

 exit:  
   if (regis_crt.s != NULL)coap_free(regis_crt.s);
   mbedtls_x509_crt_free( &registrar_crt ); 
   return ok;   
}


/* brksi_return_certificate
 * returns the registrar certificate
 * return der structure in return_crt
 * uses registrar certificate file CA_REGIS_CRT;
 */
int8_t
brski_return_certificate(coap_string_t *return_crt){
   if (return_crt == NULL)return 1;
   const char registrar_crt_name[] = CA_REGIS_CRT;         /* filename for the crt file */
   mbedtls_x509_crt                  registrar_crt;
   mbedtls_ctr_drbg_context          ctr_drbg;
   mbedtls_ctr_drbg_init( &ctr_drbg );
   mbedtls_x509_crt_init( &registrar_crt );
   int8_t  ok = 0;
	/*
     * load registrar certificate
     */
     CHECK(mbedtls_x509_crt_parse_file( &registrar_crt, registrar_crt_name));
     mbedtls_x509_buf *der = &registrar_crt.raw;
     unsigned char *ptr = der->p;
     size_t raw_len = der->len;
     return_crt->s = coap_malloc(raw_len);
     return_crt->length = raw_len;
     memcpy(return_crt->s, ptr, raw_len);
	
exit:	
    mbedtls_x509_crt_free(&registrar_crt);
	mbedtls_ctr_drbg_free( &ctr_drbg );
	return ok;

}

/* brksi_create_csr
 * create csr and return der structure in return_csr
 * use key input file PLEDGE_KEY
 * use certificate file PLEDGE_CRT
 */

int8_t
brski_create_csr(coap_string_t *return_crs){
#define CSR_SUBJECT_PWD         "NULL\n"
#define CSR_DEBUG_LEVEL         0
#define CSR_KEY_USAGE           0
#define CSR_FORCE_KEY_USAGE     0
#define CSR_NS_CERT_TYPE        0
#define CSR_FORCE_NS_CERT_TYPE  0
#define CSR_MD_ALG              MBEDTLS_MD_SHA256
    if (return_crs == NULL) return 1;
    const char filename[]        = PLEDGE_KEY;             /* filename of the key file             */
    const char password[]        = CSR_SUBJECT_PWD;        /* password for the key file            */
    const char issuer_crt_name[] = PLEDGE_CRT;             /* filename for the crt file            */
    int8_t  ok = 0;
    int ret = 1;
    mbedtls_pk_context       key;
    char buf[CRT_BUF_SIZE];
    mbedtls_x509write_csr    req;
    mbedtls_x509_crt         issuer_crt;
    mbedtls_entropy_context  entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "BRSKI pledge";
    char  issuer_name[256];

    /*
     * initialize structures and set values
     */
    mbedtls_x509write_csr_init( &req );
    mbedtls_pk_init( &key );
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_x509_crt_init( &issuer_crt );
    memset( buf, 0, sizeof( buf ) );

    mbedtls_x509write_csr_set_md_alg( &req, CSR_MD_ALG );
    mbedtls_x509write_csr_set_key_usage( &req, CSR_KEY_USAGE);
    mbedtls_x509write_csr_set_ns_cert_type( &req, CSR_NS_CERT_TYPE );  
    /*
     * 0. Seed the PRNG
     */
    mbedtls_entropy_init( &entropy );
    CHECK( mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers, strlen( pers ) ) );
    /*
     * 1.0. Load the key
     */

    CHECK(mbedtls_pk_parse_keyfile( &key, filename, password ));

    mbedtls_x509write_csr_set_key( &req, &key );

    /*
     * 1.1 load pledge certificate
     */
        CHECK(mbedtls_x509_crt_parse_file( &issuer_crt, issuer_crt_name ) );

       CHECK( mbedtls_x509_dn_gets( issuer_name, sizeof(issuer_name),
                                 &issuer_crt.subject ));

    /*
     * 1.2 Check the subject name for validity
     */
    CHECK(mbedtls_x509write_csr_set_subject_name( &req, issuer_name ) );

    /*
     * 1.3  Writing the request to return_crs
     */
    RET_CHECK(mbedtls_x509write_csr_der( &req, (unsigned char *)buf, CRT_BUF_SIZE,
                       NULL, NULL ));
	assert(ret < CRT_BUF_SIZE);
    return_crs->s = coap_malloc(ret);
    return_crs->length = ret;
    memcpy(return_crs->s, buf + CRT_BUF_SIZE - ret, ret);

exit:
    mbedtls_x509write_csr_free( &req );
    mbedtls_pk_free( &key );
    mbedtls_ctr_drbg_free( &ctr_drbg );
    mbedtls_entropy_free( &entropy );
    mbedtls_x509_crt_free( &issuer_crt );
    return ok;
}

/* return_domainid
 * returns domainid from der registrar certificate 
 * returns NULL when error
 */
coap_string_t *
return_domainid( uint8_t *registrar, size_t registrar_len){	
	int8_t  ok = 0;
	mbedtls_x509_crt  registrar_cert;
	mbedtls_x509_crt_init( &registrar_cert );
	coap_string_t *domainid = coap_malloc(sizeof(coap_string_t));
	CHECK(mbedtls_x509_crt_parse_der( &registrar_cert, registrar, registrar_len ));
 /* subject key identifier in x509 v3 extensions */
    ok = return_subject_ski( &registrar_cert.v3_ext, domainid);   
    if (ok != 0) goto exit;
    mbedtls_x509_crt_free(&registrar_cert);               
	return domainid;
exit:
    coap_free(domainid);
    mbedtls_x509_crt_free(&registrar_cert);
    return NULL;
}

static  char sts_version[]   = "version";
static  char sts_Status[]    = "Status";
static  char sts_Reason[]    = "Reason";	
static  char sts_context[]   = "reason-context";
static  char log_events[]    = "events";
static  char log_date[]      = "date";
static  char log_domainID[]  = "domainID";
static  char log_nonce[]     = "nonce";
static  char log_assertion[] = "assertion";
static  char log_truncated[] = "truncated";

#define LOG_VERSION         1
#define STS_VERSION         1
#define STS_STATUS          2
#define STS_REASON          3
#define STS_CONTEXT         4
#define LOG_EVENTS          5
#define LOG_DATE            6
#define LOG_DOMAINID        7
#define LOG_NONCE           8
#define LOG_ASSERTION       9
#define LOG_TRUNCATED       10
#define LOG_STS_END        11


static char *tag_string(uint8_t tag){
  switch (tag){
    case STS_VERSION :
      return sts_version;
      break;
    case STS_STATUS:
      return sts_Status;
      break;
    case STS_REASON:
      return sts_Reason;
      break;
    case STS_CONTEXT:
      return sts_context;
      break;
    case LOG_EVENTS:
      return log_events;
      break;
    case LOG_DATE:
      return log_date;
      break;
    case LOG_DOMAINID:
      return log_domainID;
      break;
    case LOG_NONCE:
      return log_nonce;
      break;
    case LOG_ASSERTION:
      return log_assertion;
      break;
    case LOG_TRUNCATED:
      return log_truncated;
      break;
    default:
      return NULL;
  } /* switch  */
  return NULL;
}


/* compare_tag
 * returns tag number for status message 
 * ok: 1 <= tag <= 4
 * Nok tag = 0
 */
static uint8_t compare_tag(uint8_t  *data){
	char *    candidate;	
	for (uint i = 1; i < LOG_STS_END; i++){
		candidate = tag_string(i);
		if (strcmp((char *)data, candidate) == 0) return i;
	} 
	return 0;
}

/* read_tag
 * returns tag number for status message 
 * ok: 1 <= tag <= 4
 * Nok tag = 0
 */
static uint8_t read_tag(uint8_t  **data){
	uint8_t * tagname = NULL;
	size_t    taglength;
	char *    candidate;
	int8_t ok = cbor_get_string_array(data, &tagname, &taglength);
	if (ok == 1) return 0;
	for (uint i = 1; i < LOG_STS_END; i++){
		candidate = tag_string(i);
		if (strncmp((char *)tagname, candidate, taglength)  == 0){
		   coap_free(tagname);
		   return i;
	   }
	} 
	coap_free(tagname);
	return 0;
}

/* brski_json_voucherstatus
 * returns json status
 */
int8_t
brski_json_voucherstatus(coap_string_t *status){
	if (status == NULL)return 1;	
	uint8_t tmp_buf[500];
	uint8_t *buf = tmp_buf;
	char One[] = "1";
	char text[] = "Informative human readable message";
	char additional[] = "Additional information";
	uint8_t nr = 0;
	nr += json_put_object(&buf);
	nr += json_put_constext(&buf, sts_version, sizeof(sts_version)-1); nr += json_put_value(&buf);
	nr += json_put_constext(&buf, One, sizeof(One)-1); nr += json_put_next(&buf);
	nr += json_put_constext(&buf, sts_Status, sizeof(sts_Status)-1); nr += json_put_value(&buf);
	nr += json_put_number(&buf, VS_SUCCESS); nr += json_put_next(&buf);
	nr += json_put_constext(&buf, sts_Reason, sizeof(sts_Reason)-1); nr += json_put_value(&buf);
	nr += json_put_constext(&buf, text, sizeof(text)-1); nr += json_put_next(&buf); 	
	nr += json_put_constext(&buf, sts_context, sizeof(sts_context)-1); nr += json_put_value(&buf);
	nr += json_put_constext(&buf, additional, sizeof(additional)-1);	
	nr += json_end_object(&buf);
	status->length = nr;
	status->s = coap_malloc(nr);
	memcpy(status->s, tmp_buf, nr);	
	return 0;
}

/* brski_cbor_voucherstatus
 * returns cbor status
 */
int8_t
brski_cbor_voucherstatus(coap_string_t *status){	
	if (status == NULL)return 1;
	uint8_t tmp_buf[500];
	uint8_t *buf = tmp_buf;
	char One[] = "1";
	char text[] = "Informative human readable message";
	char additional[] = "Additional information";
	uint8_t nr = 0;
	nr += cbor_put_map(& buf, 4);
	nr += cbor_put_text(&buf, sts_version, strlen(sts_version));
	nr += cbor_put_text(&buf, One, strlen(One));
	nr += cbor_put_text(&buf, sts_Status, strlen(sts_Status));
	nr += cbor_put_number(&buf, VS_SUCCESS);
	nr += cbor_put_text(&buf, sts_Reason, strlen(sts_Reason));	
	nr += cbor_put_text(&buf, text, strlen(text));	
	nr += cbor_put_text(&buf, sts_context, strlen(sts_context));
	nr += cbor_put_text(&buf, additional, strlen(additional));
	status->length = nr;
	status->s = coap_malloc(nr);
	memcpy(status->s, tmp_buf, nr);	
	return 0;
}

/* verify_cert_date
 * verifies validity of certificate dates 
 * returns 1 when not valid, else returns 0
 */
static uint8_t
verify_cert_date( mbedtls_x509_crt *crt, mbedtls_x509_crt *ca){
  uint32_t flags;	
  int ret = mbedtls_x509_crt_verify( crt, ca, NULL, NULL, &flags, NULL, NULL );
  if( ret != 0 ){
	 char txt_buf[512];
     if( ret == MBEDTLS_ERR_X509_CERT_VERIFY_FAILED ){
        mbedtls_x509_crt_verify_info( txt_buf, sizeof( txt_buf ), "  ! ", flags );
        coap_log( LOG_ERR,"%s\n", txt_buf );
     } else {
        mbedtls_strerror( ret, txt_buf, sizeof( txt_buf) );
        coap_log(LOG_ERR, "%s \n", txt_buf);
     }
     return 1;
  }
  return 0;
}


/* brski_json_voucherrequest
 * returns the payload for voucherrequest
 * certificate parameter contains the registrar certificate in der
 */
int8_t
brski_json_voucherrequest(coap_string_t *voucherrequest, coap_string_t *certificate, char *pledge_file){
   if ((voucherrequest == NULL) ||(certificate == NULL))return 1;
   mbedtls_x509_crt               pledge_crt;
   mbedtls_x509_crt               input_crt;   
   char    *serial = NULL;
   char    created[100];
   char    expiry[100];
   uint8_t nonce[NONCE_LEN];
   prng(nonce, NONCE_LEN);
   size_t  serial_len = 0;
   memset(created, 0, 100);
   memset(expiry, 0, 100);
   size_t nr = 0;
   int8_t ok = 0;
   mbedtls_x509_crt_init( &pledge_crt);
   mbedtls_x509_crt_init( &input_crt);
/* check input certificate */
   CHECK(mbedtls_x509_crt_parse_der( &input_crt, certificate->s, certificate->length ));   
/* read pledge certificate and find serial number*/   
   CHECK(mbedtls_x509_crt_parse_file( &pledge_crt, pledge_file ) );
   return_subject_sn(&(pledge_crt.subject), &serial, &serial_len);

   /* define createdon, expireson  and noce*/
	
    time_t rawtime;
    time(&rawtime);
    struct tm tm_buf;
    memset(&tm_buf, 0, sizeof(struct tm));   
    struct tm *current = gmtime_r(&rawtime, &tm_buf); 
    strftime(created, 200, "%Y-%m-%dT%H:%M:%SZ", current);
    current->tm_year = current->tm_year + VALIDITY_YEARS;
    strftime(expiry, 200, "%Y-%m-%dT%H:%M:%SZ", current);                                                          
	size_t len = (certificate->length * 4)/3 + NONCE_LEN + serial_len + 300;
	uint8_t *tmp_buf = coap_malloc(len);
	uint8_t *buf = tmp_buf;
	nr += json_put_object(&buf);
	nr += json_put_constext(&buf, JVR_VOUCHERREQUEST, sizeof(JVR_VOUCHERREQUEST)-1);
	nr += json_put_value(&buf);
	nr += json_put_object(&buf);
	nr += json_put_constext(&buf, JVR_ASSERTION, sizeof(JVR_ASSERTION)-1); nr += json_put_value(&buf);
	nr += json_put_number(&buf, CVR_PROXIMITY); nr += json_put_next(&buf);
	nr += json_put_constext(&buf, JVR_CREATEDON, sizeof(JVR_CREATEDON)-1); nr += json_put_value(&buf);
	nr += json_put_text(&buf, created, strlen(created)); nr += json_put_next(&buf);
//	nr += json_put_constext(&buf, JVR_EXPIRESON, sizeof(JVR_EXPIRESON)-1); nr += json_put_value(&buf);	
//	nr += json_put_text(&buf, expiry, strlen(expiry)); nr += json_put_next(&buf);
	/* either expires on or nonce is used */
	nr += json_put_constext(&buf, JVR_NONCE, sizeof(JVR_NONCE)-1); nr += json_put_value(&buf);
	nr += json_put_binary(&buf, nonce, NONCE_LEN); nr += json_put_next(&buf);	
	nr += json_put_constext(&buf, JVR_SERIALNUMBER, sizeof(JVR_SERIALNUMBER)-1); nr += json_put_value(&buf);	
	nr += json_put_text(&buf, (char *)serial, serial_len); nr += json_put_next(&buf);
	nr += json_put_constext(&buf, JVR_PROXIMITYREGISTRARCERT, sizeof(JVR_PROXIMITYREGISTRARCERT)-1); nr += json_put_value(&buf);
	nr += json_put_binary(&buf, certificate->s, certificate->length);	
	nr += json_end_object(&buf);
	nr += json_end_object(&buf);
		
//	fprintf(stderr, "JSON voucher_request looks like:\n");
//	for (uint qq = 0; qq < nr; qq++) fprintf(stderr,"%c",tmp_buf[qq]);
//	fprintf(stderr,"\n");
	
	coap_free(serial);
	assert(nr < len);	
	voucherrequest->length = nr;
	voucherrequest->s = coap_malloc(nr);
	memcpy(voucherrequest->s, tmp_buf, nr);
	coap_free(tmp_buf);
    mbedtls_x509_crt_free(&pledge_crt);
    mbedtls_x509_crt_free(&input_crt);
	return ok;
exit:
    mbedtls_x509_crt_free(&pledge_crt);
    mbedtls_x509_crt_free(&input_crt);    
	return ok;
}

/* brski_cbor_voucherrequest
 * returns the payload for voucherrequest
 * certificate parameter contains the registrar certificate in der
 */
int8_t
brski_cbor_voucherrequest(coap_string_t *voucherrequest, coap_string_t *certificate, char *pledge_file){
   if ((voucherrequest == NULL) ||(certificate == NULL))return 1;
   mbedtls_x509_crt               pledge_crt;
   mbedtls_x509_crt               input_crt;
   char    *serial = NULL;
   char    created[100];
   char    expiry[100];
   uint8_t nonce[NONCE_LEN];
   prng(nonce, NONCE_LEN);
   size_t  serial_len = 0;  
   memset(created, 0, 100);
   memset(expiry, 0, 100);
   size_t nr = 0;
   int8_t ok = 0;
   mbedtls_x509_crt_init( &pledge_crt);
   mbedtls_x509_crt_init( &input_crt);   
/* check input certificate */
   CHECK(mbedtls_x509_crt_parse_der( &input_crt, certificate->s, certificate->length ));
/* read pledge certificate and find serial number*/
   CHECK(mbedtls_x509_crt_parse_file( &pledge_crt, pledge_file ) );
   return_subject_sn(&(pledge_crt.subject), &serial, &serial_len);
   /* define createdon, expireson and nonce */	
    time_t rawtime;
    time(&rawtime);
    struct tm *tmpt; 
    struct tm tm_buf;
    memset(&tm_buf, 0, sizeof(struct tm));   
    tmpt = gmtime_r(&rawtime, &tm_buf);       
    strftime(created, 100, "%Y-%m-%dT%H:%M:%SZ", tmpt);   
    tmpt->tm_year = tmpt->tm_year + VALIDITY_YEARS;
    strftime(expiry, 100, "%Y-%m-%dT%H:%M:%SZ", tmpt);
    uint8_t *tmp_buf = coap_malloc(certificate->length + 300);
    uint8_t *buf = tmp_buf;
	nr += cbor_put_map(&buf, 1);
	nr += cbor_put_number(&buf, CVR_VOUCHERREQUEST);
	nr += cbor_put_map(&buf, 5);
	nr += cbor_put_number(&buf, CVR_CREATEDON - CVR_VOUCHERREQUEST);
	nr += cbor_put_text(&buf, created, strlen(created));
//	nr += cbor_put_number(&buf, CVR_EXPIRESON - CVR_VOUCHERREQUEST);	
//	nr += cbor_put_text(&buf, expiry, strlen(expiry));	
/* either expires_on or nonce is used */
	nr += cbor_put_number(&buf, CVR_NONCE - CVR_VOUCHERREQUEST);	
	nr += cbor_put_bytes(&buf, nonce, NONCE_LEN);	
	nr += cbor_put_number(&buf, CVR_ASSERTION - CVR_VOUCHERREQUEST);
    nr += cbor_put_number(&buf, CVR_PROXIMITY);
	nr += cbor_put_number(&buf, CVR_SERIALNUMBER - CVR_VOUCHERREQUEST);	
	nr += cbor_put_text(&buf, serial, serial_len);
	nr += cbor_put_number(&buf, CVR_PROXIMITYREGISTRARCERT - CVR_VOUCHERREQUEST);
	nr += cbor_put_bytes(&buf, certificate->s, certificate->length);
	assert(certificate->length + 300 > nr);

    mbedtls_x509_crt_free(&pledge_crt);
    mbedtls_x509_crt_free(&input_crt);
	voucherrequest->length = nr;
	voucherrequest->s = coap_malloc(nr);
	memcpy(voucherrequest->s, tmp_buf, nr);	
	coap_free(tmp_buf);
	coap_free(serial);
	return ok;
exit:
    mbedtls_x509_crt_free(&pledge_crt);
    mbedtls_x509_crt_free(&input_crt);    
    return ok;
}


/* brski_create_json_voucher
 * returns the payload for voucher
 */
int8_t
brski_create_json_voucher(coap_string_t *voucher, voucher_t *request){
   if ((voucher == NULL) || (request == NULL))return 1;
   char expiry[100];
   char created[100];
   int8_t ok = 0;
   memset(expiry, 0, 100);
   memset(created, 0, 100);
   time_t rawtime;
   time(&rawtime);
   struct tm *tmpt; 
   struct tm tm_buf;
   memset(&tm_buf, 0, sizeof(struct tm));   
   tmpt = gmtime_r(&rawtime, &tm_buf);       
   strftime(created, 100, "%Y-%m-%dT%H:%M:%SZ", tmpt);
   time_t exptime = rawtime + 20*60;  /* 20 minute  */
   tmpt = gmtime_r(&exptime, &tm_buf);   
   strftime(expiry, 100, "%Y-%m-%dT%H:%M:%SZ", tmpt);
   const char registrar_crt_name[] = CA_REGIS_CRT;         /* filename for the registrar crt file */
   mbedtls_x509_crt                 registrar_crt;
   mbedtls_x509_crt_init( &registrar_crt);
   CHECK(mbedtls_x509_crt_parse_file( &registrar_crt, registrar_crt_name ) );
    mbedtls_x509_buf *der = &registrar_crt.issuer_raw;
    unsigned char *raw_ptr = der->p;
    size_t raw_len = der->len;
    size_t spec_len = 4*(raw_len + request->cvr_nonce_len + request->serial_len)/3;
	uint8_t *tmp_buf = coap_malloc(spec_len + 300);;
	uint8_t *buf = tmp_buf;
	uint16_t nr = 0;
	nr += json_put_object(&buf);
	nr += json_put_constext(&buf, JV_VOUCHER, sizeof(JV_VOUCHER)-1);
	nr += json_put_value(&buf);
	nr += json_put_object(&buf);
	nr += json_put_constext(&buf, JV_ASSERTION, sizeof(JV_ASSERTION)-1); nr += json_put_value(&buf);
	nr += json_put_number(&buf, CV_VERIFIED); nr += json_put_next(&buf);
	nr += json_put_constext(&buf, JV_CREATEDON, sizeof(JV_CREATEDON)-1); nr += json_put_value(&buf);
	nr += json_put_text(&buf, created, strlen(created)); nr += json_put_next(&buf);
	nr += json_put_constext(&buf, JV_EXPIRESON, sizeof(JV_EXPIRESON)-1); nr += json_put_value(&buf);	
	nr += json_put_text(&buf, expiry, strlen(expiry)); nr += json_put_next(&buf);
	nr += json_put_constext(&buf, JV_NONCE, sizeof(JV_NONCE)-1); nr += json_put_value(&buf);
	nr += json_put_binary(&buf, request->cvr_nonce, request->cvr_nonce_len); nr += json_put_next(&buf);	
	nr += json_put_constext(&buf, JV_SERIALNUMBER, sizeof(JV_SERIALNUMBER)-1); nr += json_put_value(&buf);	
	nr += json_put_text(&buf, (char *)request->serial, request->serial_len); nr += json_put_next(&buf);
	nr += json_put_constext(&buf, JV_PINNEDDOMAINCERT, sizeof(JV_PINNEDDOMAINCERT)-1); nr += json_put_value(&buf);
	nr += json_put_binary(&buf, raw_ptr, raw_len); nr += json_put_next(&buf);	
	nr += json_put_constext(&buf, JV_DOMAINCERTREVOCATIONCHECKS, sizeof(JV_DOMAINCERTREVOCATIONCHECKS)-1); nr += json_put_value(&buf);
	nr += json_put_constext(&buf, JV_FALSE, sizeof(JV_FALSE)-1);	
	nr += json_end_object(&buf);
	nr += json_end_object(&buf);	
	mbedtls_x509_crt_free(&registrar_crt);
	assert(nr < spec_len + 300);	
	voucher->length = nr;
	voucher->s = coap_malloc(nr);
	memcpy(voucher->s, tmp_buf, nr);
	coap_free(tmp_buf);
	return 0;
exit:
 	mbedtls_x509_crt_free(&registrar_crt); 
 	return ok;  
}

/* brski_create_cbor_voucher
 * returns the payload for voucher
 */
int8_t
brski_create_cbor_voucher(coap_string_t *voucher, voucher_t *request){
	if ((voucher == NULL) || (request == NULL))return 1;
   int8_t ok = 0;
   char expiry[100];
   char created[100];
   memset(expiry, 0, 100);
   memset(created, 0, 100);
   time_t rawtime;
   time(&rawtime);
   struct tm *tmpt; 
   struct tm tm_buf;
   memset(&tm_buf, 0, sizeof(struct tm));   
   tmpt = gmtime_r(&rawtime, &tm_buf);       
   strftime(created, 100, "%Y-%m-%dT%H:%M:%SZ", tmpt);
   time_t exptime = rawtime + 20*60;  /* 20 minute  */
   tmpt = gmtime_r(&exptime, &tm_buf);       
   strftime(expiry, 100, "%Y-%m-%dT%H:%M:%SZ", tmpt);
   const char registrar_crt_name[] = CA_REGIS_CRT;         /* filename for the registrar crt file */
   mbedtls_x509_crt                 registrar_crt;
   mbedtls_x509_crt_init( &registrar_crt);
   CHECK(mbedtls_x509_crt_parse_file( &registrar_crt, registrar_crt_name ) );
    mbedtls_x509_buf *der = &registrar_crt.issuer_raw;
    unsigned char *raw_ptr = der->p;
    size_t raw_len = der->len;
	uint8_t *tmp_buf = coap_malloc(raw_len +200);;
	uint8_t *buf = tmp_buf;
	uint16_t nr = 0;
	nr += cbor_put_map(&buf, 1);
	nr += cbor_put_number(&buf, CV_VOUCHER);
	nr += cbor_put_map(&buf, 7);
	nr += cbor_put_number(&buf, CV_CREATEDON - CV_VOUCHER);
	nr += cbor_put_text(&buf, created, strlen(created));
	nr += cbor_put_number(&buf, CV_EXPIRESON - CV_VOUCHER);	
	nr += cbor_put_text(&buf, expiry, strlen(expiry));	
	nr += cbor_put_number(&buf, CV_ASSERTION - CV_VOUCHER);
	nr += cbor_put_number(&buf, CV_VERIFIED);
	nr += cbor_put_number(&buf, CV_NONCE - CV_VOUCHER);
	nr += cbor_put_bytes(&buf, request->cvr_nonce, request->cvr_nonce_len);
	nr += cbor_put_number(&buf, CV_SERIALNUMBER - CV_VOUCHER);	
	nr += cbor_put_text(&buf, (char *)request->serial, request->serial_len);
	nr += cbor_put_number(&buf, CV_PINNEDDOMAINCERT - CV_VOUCHER);	
	nr += cbor_put_bytes(&buf, raw_ptr, raw_len);
	nr += cbor_put_number(&buf, CV_DOMAINCERTREVOCATIONCHECKS - CV_VOUCHER);	
	nr += cbor_put_simple_value(&buf, CBOR_FALSE);
	mbedtls_x509_crt_free(&registrar_crt);
	assert(nr < raw_len + 200);	
	voucher->length = nr;
	voucher->s = coap_malloc(nr);
	memcpy(voucher->s, tmp_buf, nr);
	coap_free(tmp_buf);
	return 0;
exit:
	mbedtls_x509_crt_free(&registrar_crt);
    return ok;
}

/* fill_prot_field
 * fills alg field for Cose header
 * returns size of field
 */
static size_t
fill_prot_field(uint8_t **field, int8_t alg){
  size_t len = 0;
  uint8_t *buffer = coap_malloc(30);
  uint8_t *buf = buffer;
  len += cbor_put_map( &buf, 1);
  len += cbor_put_number( &buf, COSE_HP_ALG);
  len += cbor_put_number( &buf, alg);
  assert(len < 30);
  size_t size = cbor_put_bytes(field, buffer, len);
  coap_free(buffer);
  return size;
}


/* get_prot
 * get alg from field 
 * if present get certificate into crt
 * returns alg value; if alg == 0 => error
 */
static int8_t
get_prot(uint8_t **field, uint8_t *end){
	int64_t alg = 0;
	int64_t hp_type =0;
	uint8_t res_buf[30];
	uint8_t *buf = res_buf;
	size_t size = 0;
    uint8_t  elem = cbor_get_next_element(field);
    if (elem == CBOR_BYTE_STRING){
	  size = cbor_get_element_size( field);
	  if (size + *field > end)return 0;
	  cbor_get_array( field, buf, size);
	  uint8_t  elem = cbor_get_next_element(&buf);
      if (elem == CBOR_MAP){ 
        uint64_t map_size = cbor_get_element_size(&buf);
        if (map_size != 1) return 0;
        cbor_get_number( &buf, &hp_type);
        if (hp_type == COSE_HP_ALG) {
		  cbor_get_number( &buf, &alg);
		  return alg;
	    }  /* if hp_type */
      } /* if elem == CBOR_MAP */
    } /* if elem == CBOR_BYTE_STRING  */
    return 0;
}
   
/* fill unprot field
 * fills the hash and the certificate if present
 */
static size_t 
fill_unprot_field(uint8_t **field, uint8_t *hash, size_t hash_len, coap_string_t *der){
  size_t len = 0;
  size_t map_len = 1;
  len += cbor_put_map( field, map_len);
  if (der == NULL){
      /* add kid */
      len += cbor_put_number( field, COSE_HP_KID);
      len += cbor_put_bytes( field, hash, hash_len);
  } else if (der->s != NULL) { /* add x5bag */
	  len += cbor_put_number( field, COSE_HP_X5BAG);
	  len += cbor_put_bytes( field, der->s, der->length);
  } else {
	  coap_log(LOG_ERR, "no certificate present \n");
	  /* fill in empty "kid" */
	  len += cbor_put_number( field, COSE_HP_KID);
      len += cbor_put_bytes( field, hash, 0);
  }
  return len;
}

/* get_unprot
 * get hash and certifcate from field 
 * returns = hash_size OK, returns 1 NOK
 */
static size_t
get_unprot(uint8_t **field, uint8_t **hash, coap_string_t *der, uint8_t *end){
	size_t len = 0;
	int64_t hp_type =0;
    size_t hash_size = 0;	
	uint8_t  elem = cbor_get_next_element(field);
    if (elem == CBOR_MAP){ 
      uint64_t map_size = cbor_get_element_size(field);
      uint8_t cnt = 0;
      while (cnt < map_size){
        len += cbor_get_number( field, &hp_type);
        switch (hp_type){
          case COSE_HP_KID :
            hash_size = (size_t)cbor_get_element_size(field);
            *hash = coap_malloc(hash_size);
            if (cbor_elem_contained(*field, end) != 0)return 1;
            cbor_get_array( field, *hash, hash_size);
            break;
          case COSE_HP_X5BAG :
            der->length = (size_t)cbor_get_element_size(field);
            der->s = NULL;
            if (*field + der->length > end)return 1;
            der->s = coap_malloc(der->length);
            cbor_get_array( field, der->s, der->length);
            break;
          default:
            return 1;
        }  /* switch */  
        cnt++;
	  }  /* while */
      return hash_size;
    }
    return 0;
}

/* brski_cms_sign_payload
 * cms signs tobsesignedpl which contains voucher or voucher_request to be signed 
 * key_file contains name of file that contains key to be used
 * cose signed payload returned in signedpl
 * keys are taken from REGIS_SRV_COMB
 * OK: returns 0; NOK returns 1
 */  
int8_t
brski_cms_sign_payload(coap_string_t *signedpl, coap_string_t *tobesignedpl, char *comb_file ){
	if ((signedpl == NULL) || (tobesignedpl == NULL))return 1;
	if (tobesignedpl->s == NULL) return 1;
	BIO *in = NULL;
	BIO_free(in);
    unsigned char *pt = NULL;	
	X509 *scert = NULL;
	X509_free(scert);
	EVP_PKEY *skey = NULL;
	EVP_PKEY_free(skey);
	CMS_ContentInfo *cms = NULL;
	int ok = 1;
//    int flags = CMS_STREAM | CMS_BINARY | CMS_NOSMIMECAP | CMS_NOATTR;
    int flags = CMS_NOATTR;
	OpenSSL_add_all_algorithms();
	ERR_load_crypto_strings();
	/* Read in signer certificate and private key */
	FILE *FP = fopen( comb_file, "r" );
	if (!FP){
		coap_log(LOG_ERR,"cannot find key and certificate file %s \n", comb_file);
		goto err1;
	}
    scert = PEM_read_X509(FP, NULL, 0, NULL);
    skey = PEM_read_PrivateKey(FP, NULL, 0, NULL);
	if (!scert || !skey){
	     coap_log(LOG_ERR,"file %s did not contain key and/or certificate\n", comb_file);
		 goto err;
	}
	in = BIO_new(BIO_s_mem());
    if (!in){
		coap_log(LOG_ERR," cannot create BIO s_mem\n");
        goto err;
    }
	BIO_write(in,(void *) tobesignedpl->s, tobesignedpl->length);
	/* Sign content */
	cms = CMS_sign(scert, skey, NULL, in, flags);
	if (!cms) {
		coap_log(LOG_ERR,"cannot cms sign the voucher_request \n");
		goto err;
	}
        /* write out the cms signed contents to hexadecimal */
    int ret3 = i2d_CMS_ContentInfo(cms, &pt);
    if (!pt){
		coap_log(LOG_ERR, "CMS_content_info structure is not decodeed into memoery block \n");
		goto err;
	}
    signedpl->length = ret3;
    signedpl->s = coap_malloc(ret3);
    memcpy(signedpl->s, pt, ret3);
    ok = 0;
err:
    fclose( FP);
err1:
	if (cms)
		CMS_ContentInfo_free(cms);		
	if (scert){
		X509_free(scert);
	}	
	if (skey)
		EVP_PKEY_free(skey);		
	if (in)
		BIO_free(in);			
	if (pt) coap_free(pt);
	return ok;
}

/* create_x5bag
 * creates x5bag with der of certificate
 * returns 1 when NOK; else returns 0
 */
static uint8_t
create_x5bag(coap_string_t *cert_raw, char *cert_name){
	uint8_t  ok = 0;
	mbedtls_x509_crt file_crt;
    mbedtls_x509_crt_init( &file_crt);	
    size_t raw_len = 0;    
    if (cert_name != NULL){  /* x5bag contents added */
      CHECK(mbedtls_x509_crt_parse_file( &file_crt, cert_name ) );
      mbedtls_x509_buf *der = &file_crt.raw;
      unsigned char *ptr = der->p;
      raw_len = der->len;
      cert_raw->s = coap_malloc(raw_len);
      cert_raw->length = raw_len;
      memcpy(cert_raw->s, ptr, raw_len);  
      mbedtls_x509_crt_free(&file_crt);
    }
    return 0;
exit:
    mbedtls_x509_crt_free(&file_crt);
    return ok;
}

/* create_pubkey_hash
 * makes 256 hash of pub key in key_pair 
 * returns hash
 * returns 0 => OK; returns 1 => NOK
 */	
static uint8_t 
create_pubkey_hash(mbedtls_ecp_keypair *key_pair, uint8_t *hash){
	int8_t  ok = 0;
	unsigned char public_key[100];
    size_t pub_len;
    CHECK(mbedtls_ecp_point_write_binary( &key_pair->grp, &key_pair->Q,
                MBEDTLS_ECP_PF_UNCOMPRESSED, &pub_len, public_key, sizeof(public_key) ) );
    CHECK(mbedtls_sha256_ret( public_key, pub_len, hash, 0 ) );
    return 0;
exit:
    return ok;
}

/* sign_sig_structure
 * creates a Sig structure
 * calculates a hash over the sigstructure, follwed by signing of the hash
 * return 0=> OK; returns 1 => NOK
 */
static uint8_t
sign_sig_structure(mbedtls_ecdsa_context *key, int cose_alg, coap_string_t *tobesignedpl, 
            uint8_t *signature, size_t *sig_len, coap_string_t *der){
	uint8_t ok = 1;  /* ok return */
    uint8_t hash[HASH256_BYTES];
    char Signature1[] = "Signature1";    
    size_t nr = 0; 
    size_t  struct_len = 20 + tobesignedpl->length + der->length + sizeof(Signature1);
    uint8_t *Sig_structure = coap_malloc(struct_len);
    
	const char *pers = "mbedtls_ecdsa_write_signature";    
 	mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;	   
    mbedtls_ctr_drbg_init( &ctr_drbg );
    mbedtls_entropy_init( &entropy );
 /* seed the random number  */
    CHECK(mbedtls_ctr_drbg_seed( &ctr_drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *) pers, strlen( pers ) ) );
    uint8_t *buf = Sig_structure;  /* buf is increased by cbor functions */
    nr += cbor_put_array( &buf, 4); 
    nr += cbor_put_text( &buf, Signature1, sizeof(Signature1) -1);
    nr += fill_prot_field(&buf, cose_alg);
    /* empty external_aad added as well  */
    nr += cbor_put_bytes(&buf, NULL, 0);    
    nr += cbor_put_bytes( &buf, tobesignedpl->s, tobesignedpl->length);
    assert(nr < struct_len);
/*    
    fprintf(stderr,"structure to be signed :\n");
    for (uint qq = 0; qq < nr; qq++)fprintf(stderr," %02x",Sig_structure[qq]);
    fprintf(stderr,"\n");
*/
    CHECK( mbedtls_sha256_ret( Sig_structure, nr, hash, 0 ) );
/*   
    fprintf(stderr,"hash value is \n");
    for (uint qq = 0; qq < HASH256_BYTES; qq++)fprintf(stderr," %02x",hash[qq]);
    fprintf(stderr,"\n");
 */ 
    size_t asn_len = MBEDTLS_ECDSA_MAX_LEN;
    unsigned char asn_sig[MBEDTLS_ECDSA_MAX_LEN];
	CHECK(mbedtls_ecdsa_write_signature( key, MBEDTLS_MD_SHA256, hash, sizeof(hash), asn_sig, &asn_len,
                         mbedtls_ctr_drbg_random, &ctr_drbg ) );
/*   
    fprintf(stderr,"generated asn signature with length %d \n",(int)asn_len);
    for (uint qq =0 ; qq < asn_len; qq++)fprintf(stderr," %02x", asn_sig[qq]);
    fprintf(stderr,"\n");
  */  
    extract_asn_signature(asn_sig, asn_sig + asn_len, signature);
    *sig_len = 64;
 /*  
    fprintf(stderr,"extracted signature with length %d \n",(int)*sig_len);
    for (uint qq =0 ; qq < *sig_len; qq++)fprintf(stderr," %02x", signature[qq]);
    fprintf(stderr,"\n");
  */ 
  /* 
    unsigned char asn_signature[MBEDTLS_ECDSA_MAX_LEN]; 
    memset(asn_signature,0,MBEDTLS_ECDSA_MAX_LEN);
    create_asn_signature(signature, asn_signature, &asn_len); 
    
    CHECK(mbedtls_ecdsa_read_signature( key , hash, sizeof(hash),
                           asn_signature, asn_len));
     fprintf(stderr,"signed and verified ok \n");
     * */                      
    ok = 0;
exit:
    coap_free(Sig_structure);
    mbedtls_ctr_drbg_free( &ctr_drbg );  
    mbedtls_entropy_free( &entropy );
    return ok;
}

/* brski_cose_sign_payload
 * cose signs tobsesignedpl which contains voucher or voucher_request to be signed 
 * key_file contains name of file that contains key to be used
 * cose signed payload returned in signedpl
 * keys are taken from key_name
 * OK: returns 0; NOK returns 1
 */
int8_t
brski_cose_sign_payload(coap_string_t *signedpl, coap_string_t *tobesignedpl, 
            char *comb_name){
    if ((signedpl == NULL) || (tobesignedpl == NULL))return 1;
    int8_t   ok = 1;  /* error */
    int     cose_alg = 0;  /* type of cose alg  */
	mbedtls_pk_context       loaded_key;
	mbedtls_pk_context       *key = &loaded_key;
	char  pledge_pwd[]      = PLEDGE_PWD;
    mbedtls_pk_init( key );
	uint16_t nr = 0;
	uint8_t key_hash[HASH256_BYTES];
	unsigned char signature[MBEDTLS_ECDSA_MAX_LEN];
	size_t   sig_len = 0;
    /* load keys of pledge certificate  */
    coap_log(LOG_INFO,"parse key file with name : %s \n", comb_name);    
    CHECK(mbedtls_pk_parse_keyfile( key, comb_name, pledge_pwd ));
    /* determine cose algorithm in alg  */
    mbedtls_pk_type_t  alg = mbedtls_pk_get_type(key );
    mbedtls_ecp_keypair *key_pair = key->pk_ctx;
    if (alg == MBEDTLS_PK_ECKEY){
		if (key_pair->grp.id == MBEDTLS_ECP_DP_SECP256R1)cose_alg = COSE_ALGORITHM_ES256;
	}
	if (cose_alg != COSE_ALGORITHM_ES256){
		coap_log(LOG_ERR, "cannot handle the key types \n");
		goto exit;
	}
	ok = create_pubkey_hash(key_pair, key_hash);
    if (ok ==1 )goto exit;
    coap_string_t cert_raw = {.length =0, .s = NULL};
    ok = create_x5bag(&cert_raw, comb_name);
    if (ok== 1)goto exit;
    ok = sign_sig_structure(key_pair, cose_alg, tobesignedpl, signature, &sig_len, &cert_raw);
	if (ok == 1)goto exit;
    size_t buf_len = cert_raw.length + sig_len + tobesignedpl->length + HASH256_BYTES + 30;
    uint8_t *tmp_buf = coap_malloc(buf_len);
	uint8_t *buf = tmp_buf;
    nr += cbor_put_tag(&buf, CBOR_TAG_COSE_SIGN1);
    nr += cbor_put_array( &buf, 4);
    nr += fill_prot_field(&buf, cose_alg);
    nr += fill_unprot_field( &buf, key_hash, HASH256_BYTES, &cert_raw);
    nr += cbor_put_bytes(
                    &buf, tobesignedpl->s, tobesignedpl->length);
    nr += cbor_put_bytes( &buf, signature, sig_len);  
    coap_free(cert_raw.s);
    assert(nr < buf_len); 
	signedpl->length = nr;
	signedpl->s = tmp_buf;
/*	
	fprintf(stderr,"signed voucher_request is \n");
	for (uint qq = 0; qq < signedpl->length; qq++)fprintf(stderr, " %02x",signedpl->s[qq]);
	fprintf(stderr,"\n");	
*/
	ok = 0;
exit:           
    mbedtls_pk_free( key);
    return ok;
}


static int8_t
brski_VR_json(uint16_t sid, uint8_t  **data, voucher_t *contents, uint8_t *end){
	int8_t ok = 0;
	int64_t  mm;
	uint8_t  array[JSON_TEXT_LENGTH];
	coap_string_t text = {.s = array, .length = 0};	
	        switch (sid){
            case CVR_ASSERTION:
               ok = json_get_number(data, &mm);
               if (ok == 0)contents->assertion = (int8_t)mm;
               break;
            case CVR_CREATEDON:  
               ok = json_get_text(data, &text);
               contents->created_on = coap_malloc(text.length);
               memcpy(contents->created_on, text.s, text.length);
               contents->creation_len = text.length;              
               break;
            case CVR_DOMAINCERTREVOCATIONCHECKS:  
               ok = json_get_text(data, &text);
               if (ok == 0){
				   int8_t tf = 0;
				   ok = binary_value(&text, &tf);
				   contents->revoc_checks = tf;
			   }
               break;
            case CVR_EXPIRESON:   
               ok = json_get_text(data, &text);
               contents->expires_on = coap_malloc(text.length); 
               contents->expires_len = text.length;
               memcpy(contents->expires_on, text.s, text.length); 
               break;
            case CVR_IDEVIDUSER: 
               ok = json_get_text(data, &text);
               contents->cvr_idevid = coap_malloc(text.length); 
               contents->cvr_idevid_len = text.length;
               memcpy(contents->cvr_idevid, text.s, text.length);                       
               break;
            case CVR_LASTRENEWALDATE: 
               ok = json_get_text(data, &text);
               contents->lst_renewal = coap_malloc(text.length); 
               contents->lst_renewal_len = text.length;
               memcpy(contents->lst_renewal, text.s, text.length);   
               break;
            case CVR_NONCE:  
               ok = json_get_binary(data, &contents->cvr_nonce, &contents->cvr_nonce_len, end);  
               break;
            case CVR_PINNEDDOMAINCERT: 
               ok = json_get_binary(data, &contents->pinned_domain, &contents->pinned_domain_len, end);                     
               break;
            case CVR_PRIORSIGNEDVOUCHERREQUEST:
               ok = json_get_binary(data, &contents->prior_signed, &contents->prior_signed_len, end);                     
               break;
            case CVR_PROXIMITYREGISTRARCERT:
               ok = json_get_binary(data, &contents->proxy_registrar, &contents->proxy_registrar_len, end);                                                            
               break;
            case CVR_PROXIMITYREGISTRARPUBKSHA256:
               ok = json_get_binary(data, &contents->sha256_subject, &contents->sha256_subject_len, end);                                                       
               break;
            case CVR_PROXIMITYREGISTRARPUBK: 
               ok = json_get_binary(data, &contents->regis_subject, &contents->regis_subject_len, end);                                  
               break;
            case CVR_SERIALNUMBER:
               ok = json_get_text(data, &text);
               contents->serial = coap_malloc(text.length); 
               contents->serial_len = text.length;                      
               memcpy(contents->serial, text.s, text.length);
               break;        
            default:
              ok = 1;
              break;
         } /* switch  */ 
    return ok;
}


static int8_t
brski_VR_elem(uint16_t tag, uint8_t  **data, voucher_t *contents, uint8_t *end){
	int8_t ok = 0;
	int64_t  mm;
	         switch (tag){
            case CVR_ASSERTION - CVR_VOUCHERREQUEST:
               ok = cbor_get_number(data, &mm);
               if (ok == 0)contents->assertion = (int8_t)mm;
               break;
            case CVR_CREATEDON - CVR_VOUCHERREQUEST:  
               if (cbor_elem_contained(*data, end) != 0) return 1;
               ok = cbor_get_string_array(data, (uint8_t **)&contents->created_on, &contents->creation_len);             
               break;
            case CVR_DOMAINCERTREVOCATIONCHECKS - CVR_VOUCHERREQUEST:  
               ok = cbor_get_number(data, &mm);
               if (ok == 0)contents->revoc_checks = (int8_t)mm;
               break;
            case CVR_EXPIRESON - CVR_VOUCHERREQUEST:   
               if (cbor_elem_contained(*data, end) != 0) return 1;            
               ok = cbor_get_string_array(data, (uint8_t **)&contents->expires_on, &contents->expires_len);
               break;
            case CVR_IDEVIDUSER - CVR_VOUCHERREQUEST: 
               if (cbor_elem_contained(*data, end) != 0) return 1;                       
               ok = cbor_get_string_array(data, (uint8_t **)&contents->cvr_idevid, &contents->cvr_idevid_len);
               break;
            case CVR_LASTRENEWALDATE - CVR_VOUCHERREQUEST:
               if (cbor_elem_contained(*data, end) != 0) return 1;                         
               ok = cbor_get_string_array(data, (uint8_t **)&contents->lst_renewal, &contents->lst_renewal_len);            
               break;
            case CVR_NONCE - CVR_VOUCHERREQUEST:
               if (cbor_elem_contained(*data, end) != 0) return 1;                          
               ok = cbor_get_string_array(data, (uint8_t **)&contents->cvr_nonce, &contents->cvr_nonce_len);     
               break;
            case CVR_PINNEDDOMAINCERT - CVR_VOUCHERREQUEST: 
               if (cbor_elem_contained(*data, end) != 0) return 1;                        
               ok = cbor_get_string_array(data, (uint8_t **)&contents->pinned_domain, &contents->pinned_domain_len);     
               break;
            case CVR_PRIORSIGNEDVOUCHERREQUEST - CVR_VOUCHERREQUEST:
               if (cbor_elem_contained(*data, end) != 0) return 1;                        
               ok = cbor_get_string_array(data, (uint8_t **)&contents->prior_signed, &contents->prior_signed_len);                 
               break;
            case CVR_PROXIMITYREGISTRARCERT - CVR_VOUCHERREQUEST:
               if (cbor_elem_contained(*data, end) != 0) return 1;                        
               ok = cbor_get_string_array(data, (uint8_t **)&contents->proxy_registrar, &contents->proxy_registrar_len); 
               break;
            case CVR_PROXIMITYREGISTRARPUBKSHA256 - CVR_VOUCHERREQUEST:
               if (cbor_elem_contained(*data, end) != 0) return 1;                        
               ok = cbor_get_string_array(data, (uint8_t **)&contents->sha256_subject, &contents->sha256_subject_len);                 
               break;
            case CVR_PROXIMITYREGISTRARPUBK - CVR_VOUCHERREQUEST:
               if (cbor_elem_contained(*data, end) != 0) return 1;                        
               ok = cbor_get_string_array(data, (uint8_t **)&contents->regis_subject, &contents->regis_subject_len);                
               break;
            case CVR_SERIALNUMBER - CVR_VOUCHERREQUEST:
               if (cbor_elem_contained(*data, end) != 0) return 1;                        
               ok = cbor_get_string_array(data, (uint8_t **)&contents->serial, &contents->serial_len);               
               break;        
            default:
              ok = 1;
              break;
         } /* switch  */ 
    return ok;
}

static int8_t
brski_V_json(uint16_t sid, uint8_t  **data, voucher_t *contents, uint8_t *end){
	int8_t   ok = 0;
	int64_t  mm = 0;
	uint8_t  array[256];
	coap_string_t text = {.s = array, .length = 0};
	      switch (sid){
            case CV_ASSERTION:
               ok = json_get_number(data, &mm);
               if (ok == 0)contents->assertion = (int8_t)mm;
               break;
            case CV_CREATEDON:            
               ok = json_get_text(data, &text);
               contents->created_on = coap_malloc(text.length);
               memcpy(contents->created_on, text.s, text.length);
               contents->creation_len = text.length;             
               break;
            case CV_DOMAINCERTREVOCATIONCHECKS:            
               ok = json_get_text(data, &text);
               if (ok == 0){
				   int8_t tf = 0;
				   ok = binary_value(&text, &tf);
				   contents->revoc_checks = tf;
			   }
               break;
            case CV_EXPIRESON:            
               ok = json_get_text(data, &text);
               contents->expires_on = coap_malloc(text.length); 
               contents->expires_len = text.length;
               memcpy(contents->expires_on, text.s, text.length); 
               break;
            case CV_IDEVIDUSER: 
               ok = json_get_text(data, &text);
               contents->cvr_idevid = coap_malloc(text.length); 
               contents->cvr_idevid_len = text.length;
               memcpy(contents->cvr_idevid, text.s, text.length);                       
               break;
            case CV_LASTRENEWALDATE:  
               ok = json_get_text(data, &text);
               contents->lst_renewal = coap_malloc(text.length); 
               contents->lst_renewal_len = text.length;
               memcpy(contents->lst_renewal, text.s, text.length);                                   
               break;
            case CV_NONCE: 
               ok = json_get_binary(data, &contents->cvr_nonce, &contents->cvr_nonce_len, end);                                                                                          
               break;
            case CV_PINNEDDOMAINCERT:
               ok = json_get_binary(data, &contents->pinned_domain, &contents->pinned_domain_len, end);                                                                                                                       
               break;
            case CV_SERIALNUMBER: 
               ok = json_get_text(data, &text);
               contents->serial = coap_malloc(text.length); 
               contents->serial_len = text.length;                      
               memcpy(contents->serial, text.s, text.length);                
               break;
            case CV_PINNEDDOMAINPUBK:
               ok = json_get_binary(data, &contents->pinned_domain_public, &contents->pinned_domain_public_len, end);              
              break;
            case CV_PINNEDDOMAINPUBKSHA256:
               ok = json_get_binary(data, &contents->pinned_domain_sha256, &contents->pinned_domain_sha256_len, end);                                                                   
              break;               
            default:
              ok = 1;
              break;
         } /* switch  */ 
    return ok;
}


static int8_t
brski_V_elem(uint16_t tag, uint8_t  **data, voucher_t *contents, uint8_t *end){
	int8_t   ok = 0;
	uint8_t  sv = 0;
	int64_t  mm = 0;
	      switch (tag){
            case CV_ASSERTION - CV_VOUCHER:
               ok = cbor_get_number(data, &mm);
               if (ok == 0)contents->assertion = (int8_t)mm;
               break;
            case CV_CREATEDON - CV_VOUCHER:
               if (cbor_elem_contained(*data, end) != 0) return 1;                                   
               ok = cbor_get_string_array(data, (uint8_t **)&contents->created_on, &contents->creation_len);             
               break;
            case CV_DOMAINCERTREVOCATIONCHECKS - CV_VOUCHER:            
               ok = cbor_get_simple_value(data, &sv);
               if (ok == 0)contents->revoc_checks = (int8_t)sv;
               break;
            case CV_EXPIRESON - CV_VOUCHER:
               if (cbor_elem_contained(*data, end) != 0) return 1;                                    
               ok = cbor_get_string_array(data, (uint8_t **)&contents->expires_on, &contents->expires_len);
               break;
            case CV_IDEVIDUSER - CV_VOUCHER:
               if (cbor_elem_contained(*data, end) != 0) return 1;                                   
               ok = cbor_get_string_array(data, (uint8_t **)&contents->cvr_idevid, &contents->cvr_idevid_len);
               break;
            case CV_LASTRENEWALDATE - CV_VOUCHER:
               if (cbor_elem_contained(*data, end) != 0) return 1;                                   
               ok = cbor_get_string_array(data, (uint8_t **)&contents->lst_renewal, &contents->lst_renewal_len);            
               break;
            case CV_NONCE - CV_VOUCHER:
               if (cbor_elem_contained(*data, end) != 0) return 1;                                   
               ok = cbor_get_string_array(data, (uint8_t **)&contents->cvr_nonce, &contents->cvr_nonce_len);     
               break;
            case CV_PINNEDDOMAINCERT - CV_VOUCHER:
               if (cbor_elem_contained(*data, end) != 0) return 1;                                    
               ok = cbor_get_string_array(data, (uint8_t **)&contents->pinned_domain, &contents->pinned_domain_len);     
               break;
            case CV_SERIALNUMBER - CV_VOUCHER:
               if (cbor_elem_contained(*data, end) != 0) return 1;                                  
               ok = cbor_get_string_array(data, (uint8_t **)&contents->serial, &contents->serial_len);               
               break;
            case CV_PINNEDDOMAINPUBK - CV_VOUCHER:
               if (cbor_elem_contained(*data, end) != 0) return 1;                        
               ok = cbor_get_string_array(data, (uint8_t **)&contents->pinned_domain_public, &contents->pinned_domain_public_len);                  
              break;
            case CV_PINNEDDOMAINPUBKSHA256 - CV_VOUCHER:
               if (cbor_elem_contained(*data, end) != 0) return 1;                      
               ok = cbor_get_string_array(data, (uint8_t **)&contents->pinned_domain_sha256, &contents->pinned_domain_sha256_len);                 
              break;               
            default:
              ok = 1;
              break;
         } /* switch  */ 
    return ok;
}


/* voucher_consistency
 * checks the consistency of the parsed voucher(-request) contained in contents
 * if not consistent: frees contents and returns NULL
 * if consistent returns contents
 */
static voucher_t *
voucher_consistency(voucher_t *contents, uint16_t type){
	struct tm  create;
    struct tm  expire; 
    memset(&expire, 0, sizeof(expire));
    memset(&create, 0, sizeof(create));  
      time_t tc;
      time(&tc); 
      struct tm tm_buf;
      memset(&tm_buf, 0, sizeof(struct tm));   
      struct tm *current = gmtime_r(&tc, &tm_buf);            
      char cur_str[100];      
      strftime(cur_str, 100, "%Y-%m-%dT%H:%M:%SZ", current);       
		  /* check presence of time  fields  */
	  if (contents->created_on == NULL){
		  coap_log(LOG_WARNING, " created_on time stamp is missing \n");
		  remove_voucher(contents);
		  return NULL;
	  }	  
	  if ((contents->expires_on == NULL) && (contents->cvr_nonce == NULL)){
		  coap_log(LOG_WARNING, " nonce and expires_on date are missing \n");
		  remove_voucher(contents);
		  return NULL;
	  }
	  if (contents->cvr_nonce == NULL){
/* check time stamps  when nonce is not present */
        char *s = strptime(contents->created_on, "%Y-%m-%dT%T", &create);
        if (s == NULL){
	    coap_log(LOG_WARNING, " voucher creation timestamp is not valid \n");
		  remove_voucher(contents);
		  return NULL;
        }    
        s = strptime(contents->expires_on, "%Y-%m-%dT%T", &expire);
        if (s == NULL){
	      coap_log(LOG_WARNING, " voucher expiration timestamp is not valid \n");
		  remove_voucher(contents);
		  return NULL;
        }
        time_t t1 = mktime(&expire);
        time_t t2 = mktime(&create);
        time_t t3 = mktime(current);
      /* current transformed to same time as t1 and t2 */
 /* take an error of 2 minutes ( = 120 seconds) */     
        if (t1 + 120 < t3 || t2 - 120 > t3){
		  coap_log(LOG_WARNING, " voucher timestamps are not valid \n");
		  remove_voucher(contents);
		  return NULL;
        } /* if t1 */
	  }
   /* check assertion and certificate presence for voucher_request */
      if (type == CVR_VOUCHERREQUEST){
        if ((contents->assertion == CVR_PROXIMITY)  && (contents->proxy_registrar == NULL)
                                                    && (contents->prior_signed == NULL)){
		   coap_log(LOG_WARNING, " proximity registrar certificate prior signed certificate is missing \n");
		   remove_voucher(contents);
		   return NULL;;
        } else if (contents->proxy_registrar != NULL) {/* get domainid from registrar-certificate */
           coap_string_t *domainid = return_domainid( contents->proxy_registrar, contents->proxy_registrar_len);
           if (domainid != NULL){
              contents->domainid = domainid->s;
              contents->domainid_len = domainid->length;
              coap_free(domainid);
		   }  /* if domainid */
        } /* else contents->assertion  */
	  }  /* if type =  */
	  if (contents->cvr_idevid != NULL){
/* check authority key identifier against pledge certificate known to MASA*/
        char pledge_name[] = PLEDGE_CRT;
        int8_t ok = 0;
        mbedtls_x509_crt               pledge_crt;
        mbedtls_x509_crt_init( &pledge_crt);        
        CHECK(mbedtls_x509_crt_parse_file( &pledge_crt, pledge_name ) );
        coap_string_t authority_id = {.s = NULL, .length =0};
        ok = return_authority_aki( &(pledge_crt.v3_ext), &authority_id);
        if (ok != 0){
		  coap_log(LOG_ERR, "cannot find authority key identifier in pldge crt \n");
		  goto exit;
	    }
	    ok = memcmp(authority_id.s, contents->cvr_idevid, contents->cvr_idevid_len);
	    if (ok != 0){
		  coap_log(LOG_ERR, "authority key identifier in pldge crt and voucher_request do not match\n");
		  goto exit;
	    }
exit: if (authority_id.s != NULL)coap_free(authority_id.s);
      mbedtls_x509_crt_free( &pledge_crt);
	  }
	  return contents;
}

/* brski_parse_json_voucher
 * verifies the json voucher(-request) contained in voucher_req
 * returns voucher_request contents if verification is OK
 * else returns NULL;
 */
 voucher_t *
 brski_parse_json_voucher(coap_string_t *voucher_req){
	if (voucher_req == NULL) return NULL;
	voucher_t *contents = coap_malloc(sizeof(voucher_t));	
    memset(contents, 0, sizeof(voucher_t));
    uint8_t json_text[JSON_TEXT_LENGTH];
    uint8_t ok = 0;
    uint8_t *data = voucher_req->s; 
    if (voucher_req->s == NULL)return NULL;
    uint8_t *end  = voucher_req->s + voucher_req->length;
    int ctr = json_get_control(&data); 
    if (ctr != JSON_CONTROL_OBJECT_START){
		coap_log(LOG_ERR, "voucher(_request) JSON does not start with object \n");
		goto err;
	} 
	coap_string_t text = {.s = json_text, .length = 0};
	/* find type voucher(_request) */
	while (ctr != JSON_CONTROL_OBJECT_END){  /* go through whole voucher(_request) */
		/* get key */
		ok = json_get_text(&data, &text);
		if (ok != 0){
			coap_log(LOG_ERR,"Cannot parse JSON voucher(-request) \n");
			goto err;
		}
		uint16_t sid = find_sid(&text, VOUCHER_AND_REQUEST_VOUCHER);
		if (sid == 0){
			coap_log(LOG_ERR,"Unexpected JSON type \n");
			goto err;
		}
		if ((sid != CVR_VOUCHERREQUEST) && (sid != CV_VOUCHER)){
			coap_log(LOG_ERR,"Cannot find JSON voucher(-request) key \n");
			goto err;
	    }
	    int RV_type = 0;
	    if (sid == CVR_VOUCHERREQUEST)RV_type = REQUEST_VOUCHER_ONLY;
	    else RV_type = VOUCHER_ONLY;
	    ctr = json_get_control(&data); 
	    if (ctr != JSON_CONTROL_OBJECT_SEPARATOR){
		   coap_log(LOG_ERR, "voucher(_request) JSON does not contain ':'  \n");
		   goto err;
	   } 
	    ctr = json_get_control(&data); 
	    if (ctr != JSON_CONTROL_OBJECT_START){
		   coap_log(LOG_ERR, "voucher(_request) JSON does not start with object \n");
		   goto err;
	   } 
	   while (ctr != JSON_CONTROL_OBJECT_END){  /* go through voucher(_request) value  */
		  ok = json_get_text(&data, &text);
		  if (ok != 0){
			coap_log(LOG_ERR,"Cannot parse JSON voucher(-request) \n");
			goto err;
		  }
		  sid = find_sid(&text, RV_type);
		  if (sid == 0){
			  coap_log(LOG_ERR,"Unexpected JSON type \n");
			  goto err;
		  }
		  ctr = json_get_control(&data); 
	      if (ctr != JSON_CONTROL_OBJECT_SEPARATOR){
		      coap_log(LOG_ERR, "voucher(_request) JSON does not follow with value \n");
		      goto err;
	      } 
		  if (RV_type == REQUEST_VOUCHER_ONLY){
			 ok = brski_VR_json(sid, &data, contents, end);
		  }
		  else if (RV_type == VOUCHER_ONLY){
			ok = brski_V_json(sid, &data, contents, end);
          }
          if(ok != 0){
             coap_log(LOG_WARNING," Decode error voucher(-request) JSON \n");
             goto err;
		  }  /* if ok */
		  ctr = json_get_control(&data); 
		  if ((ctr != JSON_CONTROL_OBJECT_END) && (ctr != JSON_CONTROL_NEXT)){
			 coap_log(LOG_WARNING," Unexpected JSON control in voucher(-request) \n");
             goto err;
		  }
	   }/* while */
       ctr = json_get_control(&data); 
	   if ((ctr != JSON_CONTROL_OBJECT_END) && (ctr != JSON_CONTROL_NEXT)){
		   coap_log(LOG_WARNING," Unexpected JSON control in voucher(-request) \n");
           goto err;
	   }
	   if (RV_type == VOUCHER_ONLY)
	        contents = voucher_consistency(contents, CV_VOUCHER);
	   else
	        contents = voucher_consistency(contents, CVR_VOUCHERREQUEST);	   
	}  /* while */
	return contents;
err:
    remove_voucher(contents);
	return NULL;
 }

/* brski_parse_cbor_voucher
 * verifies the cbor voucher(-request) contained in voucher_req
 * returns voucher_request contents if verification is OK
 * else returns NULL;
 */
 voucher_t *
 brski_parse_cbor_voucher(coap_string_t *voucher_req){
	 if (voucher_req == NULL) return NULL;
    voucher_t *contents = coap_malloc(sizeof(voucher_t));	
    memset(contents, 0, sizeof(voucher_t));
    uint8_t  *data = voucher_req->s; 
    uint8_t *end = data + voucher_req->length;  
    uint64_t map_size = 0;
    int8_t   ok = 0;
    uint8_t  elem = cbor_get_next_element(&data);
    if (elem != CBOR_MAP){
		remove_voucher(contents);
		return NULL;
    }
    map_size = cbor_get_element_size(&data);
    if (map_size != 1) {
		remove_voucher(contents);
		return NULL;
	}	
    uint16_t type = cose_get_tag(&data);
    if ((type != CVR_VOUCHERREQUEST) && (type != CV_VOUCHER)){
		remove_voucher(contents);
		return NULL;
	}
	elem = cbor_get_next_element(&data);
    if (elem == CBOR_MAP){ 
	   map_size = cbor_get_element_size(&data);
	   for (uint i=0 ; i < map_size; i++){
         uint16_t tag = cose_get_tag(&data);
         if (type == CVR_VOUCHERREQUEST){
			 ok = brski_VR_elem(tag, &data, contents, end);
		 }
		 else if (type == CV_VOUCHER){
			ok = brski_V_elem(tag, &data, contents, end);
         }
         if(ok != 0){
             coap_log(LOG_WARNING," Decode error voucher request CBOR \n");
             remove_voucher(contents);
             return NULL;
		 }  /* if ok */
	  }/* for */ 
	  contents = voucher_consistency(contents, type);
    } /* if elem == CBOR_MAP */ 
    else {
		remove_voucher(contents);
		return NULL;
	}
    return contents;
 }

/* brski_check_pledge_request
 * verifies the signature of the prior signed voucher request
 * returns 0 if ok; else returns 1
 */
int8_t
brski_check_pledge_request(voucher_t *req_contents){
	if (req_contents == NULL)return 1;
   int8_t ok = 0;
   char file_name[] = PLEDGE_CRT;
   char ca_name[]   = CA_MASA_CRT;
   char *pledge_crt_name = file_name;
   if (req_contents->prior_signed == NULL)return 1;
/* check signature of prior signed request  */
   coap_string_t signed_document = { .length = req_contents->prior_signed_len, .s = req_contents->prior_signed};
   coap_string_t *pledge_request = NULL;
   if (JSON_set() == JSON_OFF){
        pledge_request = brski_verify_cose_signature(&signed_document, pledge_crt_name, ca_name);
   } else { 
        pledge_request = brski_verify_cms_signature(&signed_document, pledge_crt_name, ca_name);
   }
   if (pledge_request == NULL){
	   coap_log(LOG_WARNING, " signature of prior signed request does not match \n");
	   return 1;
   }
//   fprintf(stderr,"print idevid in registrar voucher_request \n");
//   for (uint qq =0; qq < req_contents->cvr_idevid_len; qq++)fprintf(stderr," %02x", req_contents->cvr_idevid[qq]);
//   fprintf(stderr,"\n");
//   voucher_t *req_pledge = brski_parse_cbor_voucher(pledge_request);
//   if (req_pledge != NULL){
//       fprintf(stderr,"print idevid in pledge voucher_request \n");
//       for (uint qq =0; qq < req_pledge->cvr_idevid_len; qq++)fprintf(stderr," %02x", req_pledge->cvr_idevid[qq]);
//       fprintf(stderr,"\n"); 
//   } else fprintf(stderr, "req_pledge was not parsed \n");  
/* check serial number  */
   /* unsigned document pledge_request is not used */
   if (pledge_request->s != NULL)coap_free(pledge_request->s);
   coap_free(pledge_request);
   char * serial = NULL;
   size_t serial_len = 0;
   mbedtls_x509_crt pledge_crt;
   mbedtls_x509_crt_init( &pledge_crt);
   CHECK(mbedtls_x509_crt_parse_file( &pledge_crt, pledge_crt_name ) );
    ok = return_subject_sn(&(pledge_crt.subject), &serial, &serial_len);                            
    mbedtls_x509_crt_free(&pledge_crt); 
 /* compare serial number of voucher_request with pledge certificate */
    if (serial_len != req_contents->serial_len){
		coap_free(serial);
		return 1;
	}
	ok = memcmp(serial, req_contents->serial, serial_len);
	coap_free(serial);
	return ok;
exit:
   mbedtls_x509_crt_free(&pledge_crt);  
   return ok; 
}

/* brski_create_json_masa_request
 * create the json voucher_request to be sent to masa by Registrar
 * input is voucher_request contents sent to registrar by pledge
 * regis_request contains the the orignal voucher request from pledge
 * filename contains the name of the pledge certificates sent during DTLS setup
 */
int8_t
brski_create_json_masa_request(coap_string_t *masa_request, voucher_t *request, coap_string_t *regis_request, char *file_name){
		/* load pledge certificate  */
   if ((masa_request == NULL) || (request == NULL) || (regis_request == NULL))return 1;	
   char expiry[200];
   char created[200];
   char *serial = NULL;
   size_t serial_len = 0;
   size_t issuer_len = 0;
   uint8_t *issuer_ct = NULL;
   int8_t ok = 0;
   time_t rawtime;
   time(&rawtime);
   struct tm tm_buf;
   memset(&tm_buf, 0, sizeof(struct tm));   
   struct tm *current = gmtime_r(&rawtime, &tm_buf); 
   strftime(created, 200, "%Y-%m-%dT%H:%M:%SZ", current);
   current->tm_year = current->tm_year + VALIDITY_YEARS;
   strftime(expiry, 200, "%Y-%m-%dT%H:%M:%SZ", current);
   /* check serial number against pledge certificate */
   mbedtls_x509_crt pledge_crt;
   mbedtls_x509_crt_init( &pledge_crt);
   CHECK(mbedtls_x509_crt_parse_file( &pledge_crt, file_name ) );
    coap_string_t authority_id = {.s = NULL, .length =0};
    ok = return_authority_aki( &(pledge_crt.v3_ext), &authority_id);
    ok = return_subject_sn(&(pledge_crt.subject), &serial, &serial_len);                   
 /* compare serial number of voucher_request with pledge certificate */
    if (serial_len != request->serial_len){
		coap_free(serial);
		return 1;
	}

	size_t len = (regis_request->length * 4)/3 + request->cvr_nonce_len + request->serial_len + authority_id.length + 300;
	ok = memcmp(serial, request->serial, serial_len);
	    coap_free(serial);
	if (ok != 0) return 1;
	uint8_t *tmp_buf = coap_malloc(len);
	uint8_t *buf = tmp_buf;
	uint16_t nr = 0;
	nr += json_put_object(&buf);
	nr += json_put_constext(&buf, JVR_VOUCHERREQUEST, sizeof(JVR_VOUCHERREQUEST)-1);
	nr += json_put_value(&buf);
	nr += json_put_object(&buf);
//	nr += json_put_constext(&buf, JVR_ASSERTION, sizeof(JVR_ASSERTION)-1); nr += json_put_value(&buf);
//	nr += json_put_number(&buf, request->assertion); nr += json_put_next(&buf);
	nr += json_put_constext(&buf, JVR_CREATEDON, sizeof(JVR_CREATEDON)-1); nr += json_put_value(&buf);
	nr += json_put_text(&buf, created, strlen(created)); nr += json_put_next(&buf);
	if (request->cvr_nonce == NULL){
	  nr += json_put_constext(&buf, JVR_EXPIRESON, sizeof(JVR_EXPIRESON)-1); nr += json_put_value(&buf);	
	  nr += json_put_text(&buf, expiry, strlen(expiry)); nr += json_put_next(&buf);
    } else {
	  nr += json_put_constext(&buf, JVR_NONCE, sizeof(JVR_NONCE)-1); nr += json_put_value(&buf);
	  nr += json_put_binary(&buf, request->cvr_nonce, request->cvr_nonce_len); nr += json_put_next(&buf);	
    }
	nr += json_put_constext(&buf, JVR_SERIALNUMBER, sizeof(JVR_SERIALNUMBER)-1); nr += json_put_value(&buf);	
	nr += json_put_text(&buf, (char *)request->serial, request->serial_len); nr += json_put_next(&buf);
	nr += json_put_constext(&buf, JVR_IDEVIDUSER, sizeof(JVR_IDEVIDUSER)-1); nr += json_put_value(&buf);
	nr += json_put_text(&buf, (char *)issuer_ct, issuer_len); nr += json_put_next(&buf);
	nr += json_put_constext(&buf, JVR_PRIORSIGNEDVOUCHERREQUEST, sizeof(JVR_PRIORSIGNEDVOUCHERREQUEST)-1); nr += json_put_value(&buf);
	nr += json_put_binary(&buf, regis_request->s, regis_request->length);	
	nr += json_end_object(&buf);
	nr += json_end_object(&buf);
	
	assert(nr < len);	
	masa_request->length = nr;
	masa_request->s = coap_malloc(nr);
	memcpy(masa_request->s, tmp_buf, nr);
	coap_free(tmp_buf);
	coap_free(authority_id.s);	
	mbedtls_x509_crt_free(&pledge_crt); 
	return 0;
exit:
	mbedtls_x509_crt_free(&pledge_crt); 
	return ok;
}

/* brski_create_cbor_masa_request
 * create the cbor voucher_request to be sent to masa by Registrar
 * input is voucher_request contents sent to registrar by pledge
 * regis_request contains the the orignal voucher request from pledge
 * filename contains the name of the pledge certificates sent during DTLS setup
 */
int8_t
brski_create_cbor_masa_request(coap_string_t *masa_request, voucher_t *request, coap_string_t *regis_request, char *file_name){
	/* load pledge certificate  */
   if ((masa_request == NULL) || (request == NULL) || (regis_request == NULL))return 1;
   char expiry[200];
   char created[200];
   char *serial = NULL;
   size_t serial_len = 0;
   int8_t  ok = 0;
   time_t rawtime;
   time(&rawtime);
   struct tm tm_buf;
   memset(&tm_buf, 0, sizeof(struct tm));   
   struct tm *current = gmtime_r(&rawtime, &tm_buf); 
   strftime(created, 200, "%Y-%m-%dT%H:%M:%SZ", current);
   current->tm_year = current->tm_year + VALIDITY_YEARS;
   strftime(expiry, 200, "%Y-%m-%dT%H:%M:%SZ", current);
   /* check serial number against pledge certificate */
   mbedtls_x509_crt pledge_crt;
   mbedtls_x509_crt_init( &pledge_crt);
   CHECK(mbedtls_x509_crt_parse_file( &pledge_crt, file_name ) );
    coap_string_t authority_id = {.s = NULL, .length =0};
    int ret = return_authority_aki( &(pledge_crt.v3_ext), &authority_id);
    ret = return_subject_sn(&(pledge_crt.subject), &serial, &serial_len);                   
 /* compare serial number of voucher_request with pledge certificate */
    if (serial_len != request->serial_len){
		coap_free(serial);
		return 1;
	}
	size_t len = regis_request->length + request->cvr_nonce_len + request->serial_len + authority_id.length + 200;
	ret = memcmp(serial, request->serial, serial_len);
	    coap_free(serial);
	if (ret != 0) return 1;
	uint8_t *tmp_buf = coap_malloc(len);
	uint8_t *buf = tmp_buf;
	uint16_t nr = 0;
	nr += cbor_put_map(&buf, 1);
	nr += cbor_put_number(&buf, CVR_VOUCHERREQUEST);
	nr += cbor_put_map(&buf, 5);
//	nr += cbor_put_number(&buf, CVR_ASSERTION - CVR_VOUCHERREQUEST);
//	nr += cbor_put_number(&buf, request->assertion);
	nr += cbor_put_number(&buf, CVR_CREATEDON - CVR_VOUCHERREQUEST);
	nr += cbor_put_text(&buf, created, strlen(created));
	if (request->cvr_nonce == NULL){
	  nr += cbor_put_number(&buf, CVR_EXPIRESON - CVR_VOUCHERREQUEST);	
	  nr += cbor_put_text(&buf, expiry, strlen(expiry));
	} else {	
	  nr += cbor_put_number(&buf, CVR_NONCE - CVR_VOUCHERREQUEST);
	  nr += cbor_put_bytes(&buf, request->cvr_nonce, request->cvr_nonce_len);
    }
	nr += cbor_put_number(&buf, CVR_SERIALNUMBER - CVR_VOUCHERREQUEST);	
	nr += cbor_put_text(&buf, (char *)request->serial, request->serial_len);
	nr += cbor_put_number(&buf, CVR_IDEVIDUSER - CVR_VOUCHERREQUEST);
	nr += cbor_put_bytes(&buf, (uint8_t *)authority_id.s, authority_id.length);
	nr += cbor_put_number(&buf, CVR_PRIORSIGNEDVOUCHERREQUEST - CVR_VOUCHERREQUEST);	
	nr += cbor_put_bytes(&buf, regis_request->s, regis_request->length);
	assert(nr < len);	
	masa_request->length = nr;
	masa_request->s = coap_malloc(nr);
	memcpy(masa_request->s, tmp_buf, nr);
	coap_free(tmp_buf);
	coap_free(authority_id.s);
	mbedtls_x509_crt_free(&pledge_crt); 
	return 0;
exit:
	mbedtls_x509_crt_free(&pledge_crt); 
	return ok;
}

/* brski_check_signature
 * composes the Sig signature structure 
 * and checks the signature
 * 0 => OK return, 1 => error return
 */
static uint8_t 
brski_check_signature(char *cert_file_name, uint8_t *prot_buf, uint8_t *sig_buf, coap_string_t *document, uint8_t *end){
	mbedtls_x509_crt           crt;   
    mbedtls_x509_crt_init(&crt); 	     
	uint8_t ok = 1;
	int nr = 0;
    uint8_t hash[HASH256_BYTES];
    char Signature1[] = "Signature1"; 	
	size_t prot_len = cbor_get_element_size(&prot_buf);
	if (prot_len + prot_buf > end) goto exit1;
	size_t signature_len = cbor_get_element_size(&sig_buf);
	if (signature_len + sig_buf > end) goto exit1;
    uint8_t *signature = coap_malloc(signature_len);
    cbor_get_array( &sig_buf, signature, signature_len);
    size_t struct_len = 10 + prot_len + signature_len + document->length + sizeof(Signature1);
    uint8_t *Sig_structure = coap_malloc(struct_len);
    uint8_t *buf = Sig_structure;  /* buf is increased by cbor functions */
    nr += cbor_put_array( &buf, 4); 
    nr += cbor_put_text( &buf, Signature1, sizeof(Signature1) -1);
    nr += cbor_put_bytes( &buf, prot_buf, prot_len);
    /* empty external_aad added as well  */
    nr += cbor_put_bytes(&buf, NULL, 0);    
    nr += cbor_put_bytes( &buf, document->s, document->length);
    assert(nr < struct_len);
 /*   
    fprintf(stderr,"structure to be verified :\n");
    for (uint qq = 0; qq < nr; qq++)fprintf(stderr," %02x",Sig_structure[qq]);
    fprintf(stderr,"\n");
*/   
    CHECK(mbedtls_sha256_ret( Sig_structure, nr, hash, 0 ) );
    coap_log(LOG_DEBUG,"brski_check_signature parses cert-file in %s\n",cert_file_name);
    CHECK(mbedtls_x509_crt_parse_file( &crt, cert_file_name)); 
/*     
    fprintf(stderr,"verify_cose_signature with %s \n", cert_file_name);  
    fprintf(stderr,"hash is \n");
    for (uint qq = 0; qq < HASH256_BYTES; qq++) fprintf(stderr," %02x",hash[qq]);
    fprintf(stderr,"\n");     
    fprintf(stderr,"signature is with length %d\n", (int)signature_len);
    for (uint qq = 0; qq < signature_len; qq++) fprintf(stderr," %02x",signature[qq]);
    fprintf(stderr,"\n"); 
 */ 
    /* convert 64 bit signature to asn signature */
    unsigned char asn_signature[MBEDTLS_ECDSA_MAX_LEN]; 
    size_t asn_len = 0;
    memset(asn_signature,0,MBEDTLS_ECDSA_MAX_LEN);
    create_asn_signature(signature, asn_signature, &asn_len); 
/*    
    fprintf(stderr,"asn_signature is with length %d\n", (int)asn_len);
    for (uint qq = 0; qq < asn_len; qq++) fprintf(stderr," %02x",asn_signature[qq]);
    fprintf(stderr,"\n");   
*/                                         
    CHECK(mbedtls_ecdsa_read_signature( mbedtls_pk_ec( crt.pk) , hash, sizeof(hash),
                           asn_signature, asn_len ) );
    ok = 0;
exit:
    coap_free(Sig_structure);
    coap_free(signature);
exit1:
    mbedtls_x509_crt_free(&crt);
    return ok;
}

/* brski_verify_cms_signature
 * verifies the signature of the signed document pointed at by document
 * cert_file_name contains name of the certificate
 * returns the contents of signed document
 * ok returns document else returns NULL
 */
coap_string_t *
brski_verify_cms_signature(coap_string_t *signed_document, char *ca_name, char *server_cert){
	if (signed_document == NULL)return NULL;
	if (signed_document->s == NULL) return NULL;
	BIO *RV_out = NULL, *casrvbio = NULL, *cabio = NULL;
    X509 *ca = NULL, *casrv = NULL;	
    X509_STORE *store = NULL;
    STACK_OF(X509) *stack = NULL;
    coap_string_t *document = NULL;
    /* create a new cms_siged contents from the hex */
    CMS_ContentInfo *cms_out = NULL;
    const unsigned char * pt = (const unsigned char *)signed_document->s;
    cms_out = d2i_CMS_ContentInfo( NULL, &pt, signed_document->length);
    if (cms_out == NULL){
		coap_log(LOG_ERR,"cannot store the signed voucher into CMS structure \n");
		goto exit;
	}
//    flags  = (CMS_NO_SIGNER_CERT_VERIFY | CMS_NO_ATTR_VERIFY | CMS_NOINTERN);
//    flags = (CMS_NO_SIGNER_CERT_VERIFY);
    int flags = (CMS_NO_ATTR_VERIFY | CMS_NO_SIGNER_CERT_VERIFY);
    stack = sk_X509_new_null();
    store = X509_STORE_new();
    if (store == NULL) {
	   coap_log(LOG_ERR, "unable to create new X509 store.\n");
	   goto exit;
    }
    int rc = X509_STORE_load_locations(store, ca_name, NULL);
    if (rc != 1) {
	   coap_log(LOG_ERR, "unable to load certificates from %s to store\n", ca_name);
	   X509_STORE_free(store);
	   goto exit;
    }
    casrvbio = BIO_new(BIO_s_file());
    if (BIO_read_filename(casrvbio, MASA_SRV_CRT) <= 0){
		coap_log(LOG_ERR,"cannot access CA certificate from %s \n", server_cert);
        goto exit;
	}
    casrv = PEM_read_bio_X509(casrvbio, NULL, 0, NULL);
    if (!casrv){
		coap_log(LOG_ERR, "Cannot read CA certificate %s into memory BIO\n", server_cert);
		goto exit;
	}
    cabio = BIO_new(BIO_s_file());
    if (BIO_read_filename(cabio, ca_name) <= 0){
		coap_log(LOG_ERR,"cannot access CA certificate from %s \n", ca_name);		
        goto exit;
	}
    ca = PEM_read_bio_X509(cabio, NULL, 0, NULL);
    if (!ca){
		coap_log(LOG_ERR, "Cannot read CA certificate %s into memory BIO\n", ca_name);		
		goto exit;
	}
    sk_X509_push(stack, ca);
    sk_X509_push(stack, casrv);    
//    print_stack(stack);
    RV_out = BIO_new(BIO_s_mem());
    if (!RV_out){
        coap_log(LOG_ERR,"cannot create request_voucher BIO \n");
        goto exit;
	}
    int ret = CMS_verify(cms_out, stack, store, NULL, RV_out, flags);
    if (ret == 0){
		coap_log(LOG_ERR, "CMS-verify did not create the contents from CMS structure \n");
		goto exit;
	}
	document = coap_malloc(sizeof(coap_string_t));
    char *output = coap_malloc(signed_document->length);
    document->length = BIO_read(RV_out, output, signed_document->length);  
/*    
    for (int qq =0 ; qq < document->length; qq++)printf("%c",output[qq]);
    printf("\n End of returned request-voucher dump \n");
 */   
    document->s = coap_malloc(document->length);
    memcpy(document->s, output, document->length);
    coap_free(output);
 exit:
    CMS_ContentInfo_free(cms_out);
    if(ca)X509_free(ca);
    if(casrv)X509_free(casrv);
    if(cabio)BIO_free(cabio);
    if(casrvbio)BIO_free(casrvbio);
    if(RV_out)BIO_free(RV_out);
    if(stack)sk_X509_free(stack);
    if(store)X509_STORE_free( store);
    return document;
 }

/* brski_verify_cose_signature
 * verifies the signature of the signed document pointed at by document
 * cert_file_name contains name of the certificate
 * optional ca_file_name contains CA file that signed cert_file_name
 * returns the contents of signed document
 * ok returns document else returns NULL
 */
coap_string_t *
brski_verify_cose_signature(coap_string_t *signed_document, char *cert_file_name, char *ca_file_name){
    coap_string_t *document = NULL;
    if(signed_document == NULL) return NULL;
    uint8_t *signature = NULL;
    int8_t cose_alg =0;
    uint8_t *hash = NULL;
    mbedtls_ctr_drbg_context ctr_drbg;	
    mbedtls_ctr_drbg_init( &ctr_drbg ); 
    mbedtls_x509_crt        crt;
    mbedtls_x509_crt_init(&crt);   
    mbedtls_x509_crt        ca;
    mbedtls_x509_crt_init(&ca);   
    int8_t ok = 0;
	   /* load public key of pledge certificate  */
    mbedtls_pk_context  my_key;
    mbedtls_pk_context *key = &my_key;
    mbedtls_pk_init( key);
    coap_log(LOG_DEBUG,"brksi_verify_cose_signatue parses certificate in %s \n", cert_file_name);
    CHECK(mbedtls_x509_crt_parse_file( &crt, cert_file_name));
    if (ca_file_name != NULL){
       coap_log(LOG_DEBUG,"brksi_verify_cose_signatue parses ca certificate in %s \n", ca_file_name);
       CHECK(mbedtls_x509_crt_parse_file( &ca, ca_file_name)); 
       ok = verify_cert_date( &crt, &ca);
       if (ok != 0){
		coap_log(LOG_ERR,"Certificate %s is not valid \n", cert_file_name);
		goto exit;
	}
    }
    key = &crt.pk;
    mbedtls_ecp_keypair *key_pair = key->pk_ctx;
/* get public key for eventual debugging */
    unsigned char public_key[100];
    size_t pub_len;
    CHECK(mbedtls_ecp_point_write_binary( &key_pair->grp, &key_pair->Q,
                MBEDTLS_ECP_PF_UNCOMPRESSED, &pub_len, public_key, sizeof(public_key) ));
    uint8_t *data = signed_document->s;
    uint8_t *end = signed_document->s + signed_document->length;
    uint8_t  elem = cbor_get_next_element(&data);
    uint64_t tag_value = cbor_get_element_size(&data);
    if (tag_value != CBOR_TAG_COSE_SIGN1) return NULL;
    elem = cbor_get_next_element(&data);
    coap_string_t bag_crt = {.length = 0, .s = NULL};
    if (elem == CBOR_ARRAY){ 
      uint64_t arr_size = cbor_get_element_size(&data);
      if (arr_size != 4) return NULL;
      uint8_t *prot_buf = data;    /* points to protected data  */
      cose_alg = get_prot(&data, end);
      if (cose_alg == 0) goto exit;
      if (!((cose_alg == COSE_Algorithm_EdDSA ) || (cose_alg == COSE_ALGORITHM_ES256))) return NULL;
      size_t hash_size = get_unprot(&data, &hash, &bag_crt, end);    
      if (bag_crt.s != NULL)coap_free(bag_crt.s);  /* the certificate is not used  */          
      if (hash_size == 0) coap_log(LOG_INFO,"kid is missing in the COSE_SIGN1 object \n");
      if (hash_size == 1)goto exit;
      document = coap_malloc(sizeof(coap_string_t));
      document->s = NULL;
      ok = 1;
      document->length = cbor_get_element_size(&data);
      if (document->length + data > end)goto exit;
      if (cbor_elem_contained(data, end) != 0)goto exit;
      document->s = coap_malloc(document->length);
      cbor_get_array( &data, document->s, document->length); /* read the voucher(-request) */
      uint8_t *sig_buf = data;      /* points to signature  */
      ok = brski_check_signature( cert_file_name, prot_buf, sig_buf, document, end);
      /* determine if cose algorithm in alg  correponds with certificate key*/
      mbedtls_pk_type_t  alg = mbedtls_pk_get_type(key );
      mbedtls_ecp_keypair *key_pair = key->pk_ctx;
      if (alg == MBEDTLS_PK_ECKEY){
		if ((key_pair->grp.id == MBEDTLS_ECP_DP_SECP256R1) && (cose_alg != COSE_ALGORITHM_ES256)){
		   coap_log(LOG_ERR, " algorithm type of cose_sign and certificate do not coincide \n" );
           ok = 1;
		}
		if ((key_pair->grp.id == MBEDTLS_ECP_DP_CURVE25519) && (cose_alg != COSE_Algorithm_EdDSA)){
		   coap_log(LOG_ERR, " algorithm type of cose_sign and certificate do not coincide \n" );
           ok = 1;
		}
	  }
      coap_free(signature);
      coap_free(hash);
exit:
     if (ok != 0){
	    if (document != NULL){
		  if (document->s != NULL) coap_free(document->s);
		  coap_free(document);
		  document = NULL;
	    }
      }
      mbedtls_ctr_drbg_free( &ctr_drbg );               
      mbedtls_x509_crt_free( &crt);
      mbedtls_x509_crt_free( &ca);
      mbedtls_pk_free(key);
    } /* if elem = */
    return document;
 }
 
 
/* brski_check_voucher
 * compares contents of sent request_voucher with recieved masa voucher
 * return 0 ; masa voucher and reuest voucher correspond
 * return 1: no correspondence
 */
int8_t
brski_check_voucher(coap_string_t *masa_voucher, coap_string_t *request_voucher){
	if ((masa_voucher == NULL) || (request_voucher == NULL))return 1;
	if ((masa_voucher->s == NULL) || (request_voucher->s == NULL))return 1;
	int8_t  ok = 0;
	voucher_t *rq_vc = NULL;
	voucher_t *vc    = NULL;
	if (JSON_set() == JSON_ON){
/*		fprintf(stderr," parse json request_voucher \n");
		for (uint qq = 0; qq < request_voucher->length; qq ++)fprintf(stderr,"%c", request_voucher->s[qq]);
		* */
		rq_vc = brski_parse_json_voucher(request_voucher);
		/*
		fprintf(stderr,"\n parse json voucher \n");		
		for (uint qq = 0; qq < masa_voucher->length; qq ++)fprintf(stderr,"%c", masa_voucher->s[qq]);
		fprintf(stderr,"\n");
		* */
		vc    = brski_parse_json_voucher(masa_voucher);
	} else {
		 rq_vc = brski_parse_cbor_voucher(request_voucher);
	     vc    = brski_parse_cbor_voucher(masa_voucher);
	}
	if ((rq_vc != NULL) && (vc != NULL)){
	     if ((rq_vc->cvr_nonce != NULL) && (vc->cvr_nonce != NULL)){
		   if (rq_vc->cvr_nonce_len != vc->cvr_nonce_len) ok = 1;
		   if (memcmp(rq_vc->cvr_nonce, vc->cvr_nonce , vc->cvr_nonce_len) != 0)ok = 1;
	   } else ok = 1;
	   if ((rq_vc->serial != NULL) && (vc->serial != NULL)){
		   if (rq_vc->serial_len != vc->serial_len) ok = 1;
		   if (memcmp(rq_vc->serial, vc->serial , vc->serial_len) != 0)ok = 1;
	   } else ok = 1;
    } else ok = 1;
	if(rq_vc != NULL)remove_voucher(rq_vc);
	if (vc != NULL)remove_voucher(vc);
	return ok;
}


/* brski_json_readstatus 
 * parses the status of voucher in log sent by pledge 
 * adapts status record pointed at by status
 * returns 0 when all ok
 * returns 1 when voucher unacceptable
 */
int8_t 
brski_json_readstatus(coap_string_t *log, status_t *status){
	if (log == NULL)return 1;
	if (log->s == NULL) return 1;
	if (status == NULL) return 1;
	char One[] = "1";
	int64_t  mm = 0;
	uint8_t  *data = log->s;
	int8_t   ok = 0;
	uint8_t  conclusion = VOUCHER_ACCEPTABLE;
    uint8_t json_text[JSON_TEXT_LENGTH];
    int ctr = json_get_control(&data); 
    if (ctr != JSON_CONTROL_OBJECT_START){
		coap_log(LOG_ERR, "log JSON does not start with object \n");
		return 1;
	} 
	
	coap_string_t text = {.s = json_text, .length = 0};
	/* find type voucher(_request) */
	while (ctr != JSON_CONTROL_OBJECT_END){  /* go through whole voucher(_request) */
		/* get key */
		ok = json_get_text(&data, &text);
		if (ok != 0){
			coap_log(LOG_ERR,"Cannot parse JSON log \n");
		}
		ctr = json_get_control(&data);
		if (ctr != JSON_CONTROL_OBJECT_SEPARATOR){
		    coap_log(LOG_ERR,"Did not find : JSON control in status \n");
		    ok = 1;
		}
        uint8_t tag = compare_tag(text.s);
        switch (tag){
            case STS_VERSION:
              ok = json_get_text(&data, &text);
              if (ok == 0){
                 if (strncmp(One, (char *)text.s, text.length) != 0){
				    /* wrong version   */
				    conclusion = VOUCHER_REJECTED;
				}  /* if strncmp */
			  }  /* if ok  */
              break;
            case STS_STATUS:
              ok = json_get_number(&data, &mm);
              if (mm != VS_SUCCESS){
				  conclusion = VOUCHER_REJECTED;
			  }
              break;
            case STS_REASON:
              ok = json_get_text(&data, &text);
              if (ok == 0){
                 status->reason_len = text.length;
                 if (status->reason != NULL)coap_free(status->reason);
                 status->reason = coap_malloc(text.length);
                 memcpy(status->reason, text.s, text.length);
			  }  /* if ok  */
              break;
            case STS_CONTEXT:
              ok = json_get_text(&data, &text);
              if (ok == 0){
				 if (status->additional_text != NULL)coap_free(status->additional_text);
                 status->additional_text_len = text.length;
                 status->additional_text = coap_malloc(text.length);
                 memcpy(status->additional_text, text.s, text.length);
			  }  /* if ok  */
			  break;
            default:
              coap_log(LOG_ERR,"brski_json_readstatus: unknown key value\n");
              return 1;
		  } /* switch  */
		  if (ok == 1) {
			  return 1;
		  }
		  ctr = json_get_control(&data); 
		  if ((ctr != JSON_CONTROL_OBJECT_END) && (ctr != JSON_CONTROL_NEXT)){
			 coap_log(LOG_WARNING," Unexpected JSON control in voucher(-request) \n");
             return 1;
		  }
	  } /* while */
	status->acceptable = conclusion;  
    return 0;        
}


/* brski_cbor_readstatus 
 * parses the status of voucher in log sent by pledge 
 * adapts status record pointed at by status
 * returns 0 when all ok
 * returns 1 when voucher unacceptable
 */
int8_t 
brski_cbor_readstatus(coap_string_t *log, status_t *status){
	if (log == NULL)return 1;
	if (log->s == NULL) return 1;
	if (status == NULL) return 1;
	char One[] = "1";
	int64_t  mm = 0;
	uint8_t  *data = log->s;
	int8_t   ok = 0;
	uint8_t  *end_data = data + log->length;
    uint8_t  elem = cbor_get_next_element(&data);
    uint8_t  * result;
    size_t   result_len;
    int8_t   conclusion = VOUCHER_ACCEPTABLE;
	if (elem != CBOR_MAP){
		coap_log(LOG_WARNING,"cbor log does not start with cbor map \n");
		return 1;
	}
	uint64_t map_size = cbor_get_element_size(&data);
    for (uint i=0 ; i < map_size; i++){
         uint8_t tag = read_tag(&data);
         if (data > end_data) return 1;
         switch (tag){
            case STS_VERSION:
              ok = cbor_elem_contained(data, end_data);
              if (ok == 1) goto error;
              ok = cbor_get_string_array(&data, &result, &result_len);
              if (ok == 0){
                 if (strncmp(One, (char *)result, result_len) != 0){
				    /* wrong version   */
				    conclusion = VOUCHER_REJECTED;
				}  /* if strncmp */
			  }  /* if ok  */
			  coap_free(result);
              break;
            case STS_STATUS:
              ok = cbor_get_number(&data, &mm);
              if (mm != VS_SUCCESS){
				  conclusion = VOUCHER_REJECTED;
			  }
              break;
            case STS_REASON:
              ok = cbor_elem_contained(data, end_data);
              if (ok == 1) goto error;
              ok = cbor_get_string_array(&data, &result, &result_len);
              if (ok == 0){
				 if( status->reason != NULL) coap_free(status->reason);
                 status->reason = (char *)result;
                 status->reason_len = result_len;
			  }  /* if ok  */
              break;
            case STS_CONTEXT:
              ok = cbor_elem_contained(data, end_data);
              if (ok == 1) goto error;
              ok = cbor_get_string_array(&data, &result, &result_len);
              if (ok == 0){
				 if (status->additional_text != NULL) coap_free(status->additional_text);
                 status->additional_text = (char *)result;
                 status->additional_text_len = result_len;
			  }  /* if ok  */
              break;
            default:
              return 1;
		  } /* switch  */
error:
		  if (ok == 1) {
			  return 1;
		  }
	  }  /* for */
	status->acceptable = conclusion;
    return 0;        
}


  /* brski_audit_response
   * returns fabricated audit log based on voucher_request
   */
 coap_string_t *
 brski_audit_response(voucher_t *voucher){
	 if (voucher == NULL) return NULL;
    uint8_t ass_value[12];
    prng(ass_value, 12);
	uint8_t tmp_buf[500];
	uint8_t *buf = tmp_buf;
	uint16_t nr = 0;
    
	nr += cbor_put_map(&buf, 2);	 
	nr += cbor_put_text(&buf, sts_version, strlen(sts_version));
	nr += cbor_put_number(&buf, 1);
	nr += cbor_put_text(&buf, log_events, strlen(log_events));
	nr += cbor_put_array(&buf, 1);
	
	nr += cbor_put_map(&buf, 5);
	nr += cbor_put_text(&buf, log_date, strlen(log_date));
	nr += cbor_put_text(&buf, voucher->lst_renewal, voucher->lst_renewal_len);
	nr += cbor_put_text(&buf, log_domainID, strlen(log_domainID));
	nr += cbor_put_bytes(&buf, voucher->domainid, voucher->domainid_len);
	nr += cbor_put_text(&buf, log_nonce, strlen(log_nonce));
	nr += cbor_put_bytes(&buf, voucher->cvr_nonce, voucher->cvr_nonce_len);
	nr += cbor_put_text(&buf, log_assertion, strlen(log_assertion));
	nr += cbor_put_number(&buf, voucher->assertion);
	nr += cbor_put_text(&buf, log_truncated, strlen(log_truncated));
	nr += cbor_put_number(&buf, 3);

	coap_string_t *audit = coap_malloc(sizeof(coap_string_t));	
	audit->length = nr;
	audit->s = coap_malloc(nr);
	memcpy(audit->s, tmp_buf, nr);	
	return audit;
 }
 
static void
parse_event(audit_t *audit, uint8_t **data){
	coap_log(LOG_DEBUG,"parse_event \n");
	uint64_t map_size = 0;
	int64_t  mm;
	int8_t   ok = 0;
	uint8_t  elem = cbor_get_next_element(data);
	if (elem != CBOR_MAP) {
		remove_audit(audit);
		return;
	}
	uint8_t *result = NULL;
	size_t result_len = 0;
	map_size = cbor_get_element_size(data);
	  for (uint i=0 ; i < map_size; i++){
         uint8_t tag = read_tag(data);
         switch (tag){
            case LOG_DATE:
              ok = cbor_get_string_array(data, &result, &result_len);
              coap_free(result);
              break;
            case LOG_DOMAINID:
              ok = cbor_get_string_array(data, &audit->domainid, &audit->domainid_len);
              break;
            case LOG_NONCE:
              ok = cbor_get_string_array(data, &audit->vr_nonce, &audit->vr_nonce_len);
              break;
            case LOG_ASSERTION:
              ok = cbor_get_number(data, &mm);
              if (mm != CV_LOGGED)audit->acceptable = VOUCHER_ACCEPTABLE;
			  else audit->acceptable = VOUCHER_REJECTED;
              break;
            case LOG_TRUNCATED:
              ok = cbor_get_number(data, &mm);
              break;
            default:
              break;
         }    /* switch */
         if (ok != 0)return;
	 } /* for */ 
}

/* brski_parse_audit
 * parses the audit log and decides if voucher is acceptable
 * returns prased audirt
 */ 
audit_t *
brski_parse_audit(coap_string_t *audit_log){
	if (audit_log == NULL) return NULL;
	if (audit_log->s == NULL) return NULL;
	audit_t *audit = NULL;
	audit = coap_malloc(sizeof(audit_t));	
    memset(audit, 0, sizeof(audit_t));
	uint8_t  *data = audit_log->s;
	uint8_t  *end_data = data + audit_log->length;
	uint64_t map_size = 0;
	int64_t  mm;
	int8_t   ok = 0;
	uint8_t  elem = cbor_get_next_element(&data);
	if (elem != CBOR_MAP) {
		remove_audit(audit);
		return NULL;
	}
	map_size = cbor_get_element_size(&data);
	  for (uint i=0 ; i < map_size; i++){
         uint8_t tag = read_tag(&data);     
         if (data > end_data) {
			 remove_audit( audit);
			 return NULL;
		 }
         switch (tag){
            case LOG_VERSION:
              ok = cbor_get_number(&data, &mm);
              if (mm != 1){
				  audit->acceptable = VOUCHER_REJECTED;
				  return audit;
			  }
              break;
            case LOG_EVENTS:
              elem = cbor_get_next_element(&data);
              if (elem != CBOR_ARRAY){
				remove_audit(audit);
				return NULL;
			  }
		      uint64_t arr_size = cbor_get_element_size(&data);
		      for (uint ii = 0 ; ii < arr_size; ii++) parse_event(audit, &data);
		      break;
		    default:
		      remove_audit(audit);
		      return NULL;
		 } /* switch */
		 if (ok != 0){
			 remove_audit(audit);
			 return NULL;
		 }
	 } /* for */
	 return audit;
}
			   
void
brski_validate(status_t *status, audit_t *audit){
	if ((status == NULL) || (audit == NULL))return;
	uint8_t ok = 0;
	if (status->domainid_len == audit->domainid_len){
		if (memcmp(status->domainid, audit->domainid, status->domainid_len) != 0)ok =1;
	} else ok =1;
	if (status->cvr_nonce_len == audit->vr_nonce_len){
		if (memcmp(status->cvr_nonce, audit->vr_nonce, status->cvr_nonce_len) != 0)ok = 1;
	} else ok = 1;
	if (ok == 0) /* same voucher is discussed in status and audit */
	if (status->acceptable == VOUCHER_ACCEPTABLE) status->acceptable = audit->acceptable;
}

void set_JSON(uint8_t onoff){
	if ((onoff == JSON_OFF) || (onoff == JSON_ON))
	         JSON_for_voucher_request = onoff;
}

int8_t
JSON_set(void){
	return JSON_for_voucher_request;
}
