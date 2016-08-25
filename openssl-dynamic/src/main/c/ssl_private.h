/* Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 *
 * @author Mladen Turk
 * @version $Id: ssl_private.h 1658728 2015-02-10 14:45:19Z kkolinko $
 */

#ifndef SSL_PRIVATE_H
#define SSL_PRIVATE_H

/* Exclude unused OpenSSL features
 * even if the OpenSSL supports them
 */
#ifndef OPENSSL_NO_IDEA
#define OPENSSL_NO_IDEA
#endif
#ifndef OPENSSL_NO_KRB5
#define OPENSSL_NO_KRB5
#endif
#ifndef OPENSSL_NO_MDC2
#define OPENSSL_NO_MDC2
#endif
#ifndef OPENSSL_NO_RC5
#define OPENSSL_NO_RC5
#endif

#include "apr_thread_rwlock.h"
#include "apr_atomic.h"

/* OpenSSL headers */
#include <openssl/opensslv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h> 
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>

#define ERR_LEN 256

/* Avoid tripping over an engine build installed globally and detected
 * when the user points at an explicit non-engine flavor of OpenSSL
 */
#ifndef OPENSSL_NO_ENGINE
#include <openssl/engine.h>
#endif

#ifndef RAND_MAX
#include <limits.h>
#define RAND_MAX INT_MAX
#endif

#define SSL_ALGO_UNKNOWN (0)
#define SSL_ALGO_RSA     (1<<0)
#define SSL_ALGO_DSA     (1<<1)
#define SSL_ALGO_ALL     (SSL_ALGO_RSA|SSL_ALGO_DSA)

/*
 * Define IDs for the temporary RSA keys and DH params
 */

#define SSL_TMP_KEY_RSA_512     (0)
#define SSL_TMP_KEY_RSA_1024    (1)
#define SSL_TMP_KEY_RSA_2048    (2)
#define SSL_TMP_KEY_RSA_4096    (3)
#define SSL_TMP_KEY_DH_512      (4)
#define SSL_TMP_KEY_DH_1024     (5)
#define SSL_TMP_KEY_DH_2048     (6)
#define SSL_TMP_KEY_DH_4096     (7)
#define SSL_TMP_KEY_MAX         (8)

#define SSL_CRT_FORMAT_UNDEF    (0)
#define SSL_CRT_FORMAT_ASN1     (1)
#define SSL_CRT_FORMAT_TEXT     (2)
#define SSL_CRT_FORMAT_PEM      (3)
#define SSL_CRT_FORMAT_NETSCAPE (4)
#define SSL_CRT_FORMAT_PKCS12   (5)
#define SSL_CRT_FORMAT_SMIME    (6)
#define SSL_CRT_FORMAT_ENGINE   (7)
/* XXX this stupid macro helps us to avoid
 * adding yet another param to load_*key()
 */
#define SSL_KEY_FORMAT_IISSGC   (8)

/*
 * Define the SSL options
 */
#define SSL_OPT_NONE            (0)
#define SSL_OPT_RELSET          (1<<0)
#define SSL_OPT_STDENVVARS      (1<<1)
#define SSL_OPT_EXPORTCERTDATA  (1<<3)
#define SSL_OPT_FAKEBASICAUTH   (1<<4)
#define SSL_OPT_STRICTREQUIRE   (1<<5)
#define SSL_OPT_OPTRENEGOTIATE  (1<<6)
#define SSL_OPT_ALL             (SSL_OPT_STDENVVARS|SSL_OPT_EXPORTCERTDATA|SSL_OPT_FAKEBASICAUTH|SSL_OPT_STRICTREQUIRE|SSL_OPT_OPTRENEGOTIATE)

/*
 * Define the SSL Protocol options
 */
#define SSL_PROTOCOL_NONE       (0)
#define SSL_PROTOCOL_SSLV2      (1<<0)
#define SSL_PROTOCOL_SSLV3      (1<<1)
#define SSL_PROTOCOL_TLSV1      (1<<2)
#define SSL_PROTOCOL_TLSV1_1    (1<<3)
#define SSL_PROTOCOL_TLSV1_2    (1<<4)
/* TLS_*method according to https://www.openssl.org/docs/manmaster/ssl/SSL_CTX_new.html */
#define SSL_PROTOCOL_TLS        (SSL_PROTOCOL_SSLV3|SSL_PROTOCOL_TLSV1|SSL_PROTOCOL_TLSV1_1|SSL_PROTOCOL_TLSV1_2)
#define SSL_PROTOCOL_ALL        (SSL_PROTOCOL_SSLV2|SSL_PROTOCOL_TLS)

#define SSL_MODE_CLIENT         (0)
#define SSL_MODE_SERVER         (1)
#define SSL_MODE_COMBINED       (2)

#define SSL_BIO_FLAG_RDONLY     (1<<0)
#define SSL_BIO_FLAG_CALLBACK   (1<<1)
#define SSL_DEFAULT_CACHE_SIZE  (256)
#define SSL_DEFAULT_VHOST_NAME  ("_default_:443")
#define SSL_MAX_STR_LEN         (2048)
#define SSL_MAX_PASSWORD_LEN    (256)

#define SSL_CVERIFY_UNSET           (-1)
#define SSL_CVERIFY_NONE            (0)
#define SSL_CVERIFY_OPTIONAL        (1)
#define SSL_CVERIFY_REQUIRE         (2)
#define SSL_CVERIFY_OPTIONAL_NO_CA  (3)
#define SSL_VERIFY_PEER_STRICT      (SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT)

#define SSL_SHUTDOWN_TYPE_UNSET     (0)
#define SSL_SHUTDOWN_TYPE_STANDARD  (1)
#define SSL_SHUTDOWN_TYPE_UNCLEAN   (2)
#define SSL_SHUTDOWN_TYPE_ACCURATE  (3)

#define SSL_TO_APR_ERROR(X)         (APR_OS_START_USERERR + 1000 + X)

#define SSL_INFO_SESSION_ID                 (0x0001)
#define SSL_INFO_CIPHER                     (0x0002)
#define SSL_INFO_CIPHER_USEKEYSIZE          (0x0003)
#define SSL_INFO_CIPHER_ALGKEYSIZE          (0x0004)
#define SSL_INFO_CIPHER_VERSION             (0x0005)
#define SSL_INFO_CIPHER_DESCRIPTION         (0x0006)
#define SSL_INFO_PROTOCOL                   (0x0007)

#define SSL_INFO_CLIENT_S_DN                (0x0010)
#define SSL_INFO_CLIENT_I_DN                (0x0020)
#define SSL_INFO_SERVER_S_DN                (0x0040)
#define SSL_INFO_SERVER_I_DN                (0x0080)

#define SSL_INFO_DN_COUNTRYNAME             (0x0001)
#define SSL_INFO_DN_STATEORPROVINCENAME     (0x0002)
#define SSL_INFO_DN_LOCALITYNAME            (0x0003)
#define SSL_INFO_DN_ORGANIZATIONNAME        (0x0004)
#define SSL_INFO_DN_ORGANIZATIONALUNITNAME  (0x0005)
#define SSL_INFO_DN_COMMONNAME              (0x0006)
#define SSL_INFO_DN_TITLE                   (0x0007)
#define SSL_INFO_DN_INITIALS                (0x0008)
#define SSL_INFO_DN_GIVENNAME               (0x0009)
#define SSL_INFO_DN_SURNAME                 (0x000A)
#define SSL_INFO_DN_DESCRIPTION             (0x000B)
#define SSL_INFO_DN_UNIQUEIDENTIFIER        (0x000C)
#define SSL_INFO_DN_EMAILADDRESS            (0x000D)

#define SSL_INFO_CLIENT_MASK                (0x0100)

#define SSL_INFO_CLIENT_M_VERSION           (0x0101)
#define SSL_INFO_CLIENT_M_SERIAL            (0x0102)
#define SSL_INFO_CLIENT_V_START             (0x0103)
#define SSL_INFO_CLIENT_V_END               (0x0104)
#define SSL_INFO_CLIENT_A_SIG               (0x0105)
#define SSL_INFO_CLIENT_A_KEY               (0x0106)
#define SSL_INFO_CLIENT_CERT                (0x0107)
#define SSL_INFO_CLIENT_V_REMAIN            (0x0108)

#define SSL_INFO_SERVER_MASK                (0x0200)

#define SSL_INFO_SERVER_M_VERSION           (0x0201)
#define SSL_INFO_SERVER_M_SERIAL            (0x0202)
#define SSL_INFO_SERVER_V_START             (0x0203)
#define SSL_INFO_SERVER_V_END               (0x0204)
#define SSL_INFO_SERVER_A_SIG               (0x0205)
#define SSL_INFO_SERVER_A_KEY               (0x0206)
#define SSL_INFO_SERVER_CERT                (0x0207)
#define SSL_INFO_CLIENT_CERT_CHAIN          (0x0400)

#define SSL_VERIFY_ERROR_IS_OPTIONAL(errnum) \
   ((errnum == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT) \
    || (errnum == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN) \
    || (errnum == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY) \
    || (errnum == X509_V_ERR_CERT_UNTRUSTED) \
    || (errnum == X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE))

#define SSL_DEFAULT_PASS_PROMPT "Some of your private key files are encrypted for security reasons.\n"  \
                                "In order to read them you have to provide the pass phrases.\n"         \
                                "Enter password :"

#define OCSP_STATUS_OK        0
#define OCSP_STATUS_REVOKED   1
#define OCSP_STATUS_UNKNOWN   2

#define MAX_ALPN_NPN_PROTO_SIZE 65535

static const char* UNKNOWN_AUTH_METHOD = "UNKNOWN";

/* ECC: make sure we have at least 1.0.0 */
#if !defined(OPENSSL_NO_EC) && defined(TLSEXT_ECPOINTFORMAT_uncompressed)
#define HAVE_ECC              1
#endif


#define SSL_SELECTOR_FAILURE_NO_ADVERTISE                       0
#define SSL_SELECTOR_FAILURE_CHOOSE_MY_LAST_PROTOCOL            1

#define SSL_SESSION_TICKET_KEY_NAME_LEN 16
#define SSL_SESSION_TICKET_AES_KEY_LEN  16
#define SSL_SESSION_TICKET_HMAC_KEY_LEN 16
#define SSL_SESSION_TICKET_KEY_SIZE     48

extern void *SSL_temp_keys[SSL_TMP_KEY_MAX];

typedef struct {
    /* client can have any number of cert/key pairs */
    const char  *cert_file;
    const char  *cert_path;
    STACK_OF(X509_INFO) *certs;
} ssl_pkc_t;

typedef struct tcn_ssl_ctxt_t tcn_ssl_ctxt_t;

typedef struct {
    char            password[SSL_MAX_PASSWORD_LEN];
    const char     *prompt;
    tcn_callback_t cb;
} tcn_pass_cb_t;

extern tcn_pass_cb_t tcn_password_callback;

typedef struct {
    unsigned char   key_name[SSL_SESSION_TICKET_KEY_NAME_LEN];
    unsigned char   hmac_key[SSL_SESSION_TICKET_HMAC_KEY_LEN];
    unsigned char   aes_key[SSL_SESSION_TICKET_AES_KEY_LEN];
} tcn_ssl_ticket_key_t;

struct tcn_ssl_ctxt_t {
    apr_pool_t              *pool;
    SSL_CTX                 *ctx;
    BIO                     *bio_os;
    BIO                     *bio_is;

    unsigned char           context_id[SHA_DIGEST_LENGTH];

    int                     protocol;
    /* we are one or the other */
    int                     mode;

    /* certificate revocation list */
    X509_STORE              *crl;
    /* pointer to the context verify store */
    X509_STORE              *store;

    int                     ca_certs;
    int                     shutdown_type;
    char                    *rand_file;

    const char              *cipher_suite;
    /* for client or downstream server authentication */
    int                     verify_depth;
    int                     verify_mode;
    tcn_pass_cb_t           *cb_data;

    /* certificate verifier callback */
    jobject verifier;
    jmethodID verifier_method;

    jobject cert_requested_callback;
    jmethodID cert_requested_callback_method;

    unsigned char           *next_proto_data;
    unsigned int            next_proto_len;
    int                     next_selector_failure_behavior;

    /* Holds the alpn protocols, each of them prefixed with the len of the protocol */
    unsigned char           *alpn_proto_data;
    unsigned int            alpn_proto_len;
    int                     alpn_selector_failure_behavior;

    apr_thread_rwlock_t     *mutex;
    tcn_ssl_ticket_key_t    *ticket_keys;
    unsigned int            ticket_keys_len;

    /* TLS ticket key session resumption statistics */

    // The client did not present a ticket and we issued a new one.
    apr_uint32_t            ticket_keys_new;
    // The client presented a ticket derived from the primary key
    apr_uint32_t            ticket_keys_resume;
    // The client presented a ticket derived from an older key, and we upgraded to the primary key.
    apr_uint32_t            ticket_keys_renew;
    // The client presented a ticket that did not match any key in the list.
    apr_uint32_t            ticket_keys_fail;
};


typedef struct {
    apr_pool_t     *pool;
    tcn_ssl_ctxt_t *ctx;
    SSL            *ssl;
    X509           *peer;
    int             shutdown_type;
    /* Track the handshake/renegotiation state for the connection so
     * that all client-initiated renegotiations can be rejected, as a
     * partial fix for CVE-2009-3555.
     */
    enum { 
        RENEG_INIT = 0, /* Before initial handshake */
        RENEG_REJECT,   /* After initial handshake; any client-initiated
                         * renegotiation should be rejected
                         */
        RENEG_ALLOW,    /* A server-initated renegotiation is taking
                         * place (as dictated by configuration)
                         */
        RENEG_ABORT     /* Renegotiation initiated by client, abort the
                         * connection
                         */
    } reneg_state;
    apr_socket_t   *sock;
    apr_pollset_t  *pollset;
} tcn_ssl_conn_t;


/*
 *  Additional Functions
 */
void        SSL_init_app_data2_3_idx(void);
// The app_data2 is used to store the tcn_ssl_ctxt_t pointer for the SSL instance.
void       *SSL_get_app_data2(SSL *);
void        SSL_set_app_data2(SSL *, void *);
// The app_data3 is used to store the handshakeCount pointer for the SSL instance.
void       *SSL_get_app_data3(SSL *);
void        SSL_set_app_data3(SSL *, void *);
int         SSL_password_prompt(tcn_pass_cb_t *);
int         SSL_password_callback(char *, int, int, void *);
void        SSL_BIO_close(BIO *);
void        SSL_BIO_doref(BIO *);
DH         *SSL_dh_get_tmp_param(int);
DH         *SSL_dh_get_param_from_file(const char *);
RSA        *SSL_callback_tmp_RSA(SSL *, int, int);
DH         *SSL_callback_tmp_DH(SSL *, int, int);
// The following provided callbacks will always return DH of a given length.
// See https://www.openssl.org/docs/manmaster/ssl/SSL_CTX_set_tmp_dh_callback.html
DH         *SSL_callback_tmp_DH_512(SSL *, int, int);
DH         *SSL_callback_tmp_DH_1024(SSL *, int, int);
DH         *SSL_callback_tmp_DH_2048(SSL *, int, int);
DH         *SSL_callback_tmp_DH_4096(SSL *, int, int);
void        SSL_callback_handshake(const SSL *, int, int);
int         SSL_CTX_use_certificate_chain(SSL_CTX *, const char *, int);
int         SSL_CTX_use_certificate_chain_bio(SSL_CTX *, BIO *, int);
int         SSL_use_certificate_chain_bio(SSL *, BIO *, int);
X509        *load_pem_cert_bio(tcn_pass_cb_t *, const BIO *);
EVP_PKEY    *load_pem_key_bio(tcn_pass_cb_t *, const BIO *);
int         tcn_EVP_PKEY_up_ref(EVP_PKEY* pkey);
int         tcn_X509_up_ref(X509* cert);

int         SSL_callback_SSL_verify(int, X509_STORE_CTX *);
int         SSL_rand_seed(const char *file);
int         SSL_callback_next_protos(SSL *, const unsigned char **, unsigned int *, void *);
int         SSL_callback_select_next_proto(SSL *, unsigned char **, unsigned char *, const unsigned char *, unsigned int,void *);
int         SSL_callback_alpn_select_proto(SSL *, const unsigned char **, unsigned char *, const unsigned char *, unsigned int, void *);
void        SSL_init_app_data2_3_idx(void);
const char *SSL_cipher_authentication_method(const SSL_CIPHER *);

#if defined(__GNUC__) || defined(__GNUG__)
    // only supported with GCC, this will be used to support different openssl versions at the same time.
    extern int SSL_CTX_set_alpn_protos(SSL_CTX *ctx, const unsigned char *protos,
           unsigned protos_len) __attribute__((weak));
    extern void SSL_CTX_set_alpn_select_cb(SSL_CTX *ctx, int (*cb) (SSL *ssl, const unsigned char **out,
           unsigned char *outlen, const unsigned char *in, unsigned int inlen,
           void *arg), void *arg) __attribute__((weak));
    extern void SSL_get0_alpn_selected(const SSL *ssl, const unsigned char **data,
           unsigned *len) __attribute__((weak));
#endif

#endif /* SSL_PRIVATE_H */
