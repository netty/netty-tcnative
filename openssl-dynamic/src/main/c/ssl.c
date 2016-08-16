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
 * @version $Id: ssl.c 1649733 2015-01-06 04:42:24Z billbarker $
 */

#include "tcn.h"
#include "apr_file_io.h"
#include "apr_thread_mutex.h"
#include "apr_atomic.h"
#include "apr_poll.h"
#ifdef HAVE_OPENSSL
#include "ssl_private.h"

static int ssl_initialized = 0;
static char *ssl_global_rand_file = NULL;
extern apr_pool_t *tcn_global_pool;

ENGINE *tcn_ssl_engine = NULL;
void *SSL_temp_keys[SSL_TMP_KEY_MAX];
tcn_pass_cb_t tcn_password_callback;

/* Global reference to the pool used by the dynamic mutexes */
static apr_pool_t *dynlockpool = NULL;

/* Dynamic lock structure */
struct CRYPTO_dynlock_value {
    apr_pool_t *pool;
    const char* file;
    int line;
    apr_thread_mutex_t *mutex;
};

/*
 * Handle the Temporary RSA Keys and DH Params
 */

#define SSL_TMP_KEY_FREE(type, idx)                     \
    if (SSL_temp_keys[idx]) {                           \
        type##_free((type *)SSL_temp_keys[idx]);        \
        SSL_temp_keys[idx] = NULL;                      \
    } else (void)(0)

#define SSL_TMP_KEYS_FREE(type) \
    SSL_TMP_KEY_FREE(type, SSL_TMP_KEY_##type##_512);   \
    SSL_TMP_KEY_FREE(type, SSL_TMP_KEY_##type##_1024);  \
    SSL_TMP_KEY_FREE(type, SSL_TMP_KEY_##type##_2048);  \
    SSL_TMP_KEY_FREE(type, SSL_TMP_KEY_##type##_4096)

#define SSL_TMP_KEY_INIT_RSA(bits) \
    ssl_tmp_key_init_rsa(bits, SSL_TMP_KEY_RSA_##bits)

#define SSL_TMP_KEY_INIT_DH(bits)  \
    ssl_tmp_key_init_dh(bits, SSL_TMP_KEY_DH_##bits)

#define SSL_TMP_KEYS_INIT(R)                    \
    SSL_temp_keys[SSL_TMP_KEY_RSA_2048] = NULL; \
    SSL_temp_keys[SSL_TMP_KEY_RSA_4096] = NULL; \
    R |= SSL_TMP_KEY_INIT_RSA(512);             \
    R |= SSL_TMP_KEY_INIT_RSA(1024);            \
    R |= SSL_TMP_KEY_INIT_DH(512);              \
    R |= SSL_TMP_KEY_INIT_DH(1024);             \
    R |= SSL_TMP_KEY_INIT_DH(2048);             \
    R |= SSL_TMP_KEY_INIT_DH(4096)

/*
 * supported_ssl_opts is a bitmask that contains all supported SSL_OP_*
 * options at compile-time. This is used in hasOp to determine which
 * SSL_OP_* options are available at runtime.
 *
 * Note that at least up through OpenSSL 0.9.8o, checking SSL_OP_ALL will
 * return JNI_FALSE because SSL_OP_ALL is a mask that covers all bug
 * workarounds for OpenSSL including future workarounds that are defined
 * to be in the least-significant 3 nibbles of the SSL_OP_* bit space.
 *
 * This implementation has chosen NOT to simply set all those lower bits
 * so that the return value for SSL_OP_FUTURE_WORKAROUND will only be
 * reported by versions that actually support that specific workaround.
 */
static const jint supported_ssl_opts = 0
/*
  Specifically skip SSL_OP_ALL
#ifdef SSL_OP_ALL
     | SSL_OP_ALL
#endif
*/
#ifdef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
     | SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
#endif

#ifdef SSL_OP_CIPHER_SERVER_PREFERENCE
     | SSL_OP_CIPHER_SERVER_PREFERENCE
#endif

#ifdef SSL_OP_CRYPTOPRO_TLSEXT_BUG
     | SSL_OP_CRYPTOPRO_TLSEXT_BUG
#endif

#ifdef SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
     | SSL_OP_DONT_INSERT_EMPTY_FRAGMENTS
#endif

#ifdef SSL_OP_EPHEMERAL_RSA
     | SSL_OP_EPHEMERAL_RSA
#endif

#ifdef SSL_OP_LEGACY_SERVER_CONNECT
     | SSL_OP_LEGACY_SERVER_CONNECT
#endif

#ifdef SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
     | SSL_OP_MICROSOFT_BIG_SSLV3_BUFFER
#endif

#ifdef SSL_OP_MICROSOFT_SESS_ID_BUG
     | SSL_OP_MICROSOFT_SESS_ID_BUG
#endif

#ifdef SSL_OP_MSIE_SSLV2_RSA_PADDING
     | SSL_OP_MSIE_SSLV2_RSA_PADDING
#endif

#ifdef SSL_OP_NETSCAPE_CA_DN_BUG
     | SSL_OP_NETSCAPE_CA_DN_BUG
#endif

#ifdef SSL_OP_NETSCAPE_CHALLENGE_BUG
     | SSL_OP_NETSCAPE_CHALLENGE_BUG
#endif

#ifdef SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG
     | SSL_OP_NETSCAPE_DEMO_CIPHER_CHANGE_BUG
#endif

#ifdef SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
     | SSL_OP_NETSCAPE_REUSE_CIPHER_CHANGE_BUG
#endif

#ifdef SSL_OP_NO_COMPRESSION
     | SSL_OP_NO_COMPRESSION
#endif

#ifdef SSL_OP_NO_QUERY_MTU
     | SSL_OP_NO_QUERY_MTU
#endif

#ifdef SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
     | SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION
#endif

#ifdef SSL_OP_NO_SSLv2
     | SSL_OP_NO_SSLv2
#endif

#ifdef SSL_OP_NO_SSLv3
     | SSL_OP_NO_SSLv3
#endif

#ifdef SSL_OP_NO_TICKET
     | SSL_OP_NO_TICKET
#endif

#ifdef SSL_OP_NO_TLSv1
     | SSL_OP_NO_TLSv1
#endif

#ifdef SSL_OP_PKCS1_CHECK_1
     | SSL_OP_PKCS1_CHECK_1
#endif

#ifdef SSL_OP_PKCS1_CHECK_2
     | SSL_OP_PKCS1_CHECK_2
#endif

#ifdef SSL_OP_NO_TLSv1_1
     | SSL_OP_NO_TLSv1_1
#endif

#ifdef SSL_OP_NO_TLSv1_2
     | SSL_OP_NO_TLSv1_2
#endif

#ifdef SSL_OP_SINGLE_DH_USE
     | SSL_OP_SINGLE_DH_USE
#endif

#ifdef SSL_OP_SINGLE_ECDH_USE
     | SSL_OP_SINGLE_ECDH_USE
#endif

#ifdef SSL_OP_SSLEAY_080_CLIENT_DH_BUG
     | SSL_OP_SSLEAY_080_CLIENT_DH_BUG
#endif

#ifdef SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
     | SSL_OP_SSLREF2_REUSE_CERT_TYPE_BUG
#endif

#ifdef SSL_OP_TLS_BLOCK_PADDING_BUG
     | SSL_OP_TLS_BLOCK_PADDING_BUG
#endif

#ifdef SSL_OP_TLS_D5_BUG
     | SSL_OP_TLS_D5_BUG
#endif

#ifdef SSL_OP_TLS_ROLLBACK_BUG
     | SSL_OP_TLS_ROLLBACK_BUG
#endif
     | 0;

static int ssl_tmp_key_init_rsa(int bits, int idx)
{
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(OPENSSL_USE_DEPRECATED)
    if (!(SSL_temp_keys[idx] =
          RSA_generate_key(bits, RSA_F4, NULL, NULL))) {
#ifdef OPENSSL_FIPS
        /**
         * With FIPS mode short RSA keys cannot be
         * generated.
         */
        if (bits < 1024)
            return 0;
        else
#endif
        return 1;
    }
    else {
        return 0;
    }
#else
    return 0;
#endif
}

static int ssl_tmp_key_init_dh(int bits, int idx)
{
#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || defined(OPENSSL_USE_DEPRECATED)
    if (!(SSL_temp_keys[idx] =
          SSL_dh_get_tmp_param(bits)))
        return 1;
    else
        return 0;
#else
    return 0;
#endif
}


TCN_IMPLEMENT_CALL(jint, SSL, version)(TCN_STDARGS)
{
    UNREFERENCED_STDARGS;
    return (jint) SSLeay();
}

TCN_IMPLEMENT_CALL(jstring, SSL, versionString)(TCN_STDARGS)
{
    UNREFERENCED(o);
    return AJP_TO_JSTRING(SSLeay_version(SSLEAY_VERSION));
}

/*
 *  the various processing hooks
 */
static apr_status_t ssl_init_cleanup(void *data)
{
    UNREFERENCED(data);

    if (!ssl_initialized)
        return APR_SUCCESS;
    ssl_initialized = 0;

    if (tcn_password_callback.cb.obj) {
        JNIEnv *env;
        tcn_get_java_env(&env);
        TCN_UNLOAD_CLASS(env,
                         tcn_password_callback.cb.obj);
    }

    SSL_TMP_KEYS_FREE(RSA);
    SSL_TMP_KEYS_FREE(DH);
    /*
     * Try to kill the internals of the SSL library.
     */
#if OPENSSL_VERSION_NUMBER >= 0x00907001 && !defined(OPENSSL_IS_BORINGSSL)
    /* Corresponds to OPENSSL_load_builtin_modules():
     * XXX: borrowed from apps.h, but why not CONF_modules_free()
     * which also invokes CONF_modules_finish()?
     */
    CONF_modules_unload(1);
#endif
    /* Corresponds to SSL_library_init: */
    EVP_cleanup();
#if HAVE_ENGINE_LOAD_BUILTIN_ENGINES
    ENGINE_cleanup();
#endif
#if OPENSSL_VERSION_NUMBER >= 0x00907001
    CRYPTO_cleanup_all_ex_data();
#endif
    ERR_remove_state(0);

    /* Don't call ERR_free_strings here; ERR_load_*_strings only
     * actually load the error strings once per process due to static
     * variable abuse in OpenSSL. */

    /*
     * TODO: determine somewhere we can safely shove out diagnostics
     *       (when enabled) at this late stage in the game:
     * CRYPTO_mem_leaks_fp(stderr);
     */
    return APR_SUCCESS;
}

#ifndef OPENSSL_NO_ENGINE
/* Try to load an engine in a shareable library */
static ENGINE *ssl_try_load_engine(const char *engine)
{
    ENGINE *e = ENGINE_by_id("dynamic");
    if (e) {
        if (!ENGINE_ctrl_cmd_string(e, "SO_PATH", engine, 0)
            || !ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0)) {
            ENGINE_free(e);
            e = NULL;
        }
    }
    return e;
}
#endif

/*
 * To ensure thread-safetyness in OpenSSL
 */

static apr_thread_mutex_t **ssl_lock_cs;
static int                  ssl_lock_num_locks;

static void ssl_thread_lock(int mode, int type,
                            const char *file, int line)
{
    UNREFERENCED(file);
    UNREFERENCED(line);
    if (type < ssl_lock_num_locks) {
        if (mode & CRYPTO_LOCK) {
            apr_thread_mutex_lock(ssl_lock_cs[type]);
        }
        else {
            apr_thread_mutex_unlock(ssl_lock_cs[type]);
        }
    }
}

static unsigned long ssl_thread_id(void)
{
    /* OpenSSL needs this to return an unsigned long.  On OS/390, the pthread
     * id is a structure twice that big.  Use the TCB pointer instead as a
     * unique unsigned long.
     */
#ifdef __MVS__
    struct PSA {
        char unmapped[540];
        unsigned long PSATOLD;
    } *psaptr = 0;

    return psaptr->PSATOLD;
#elif defined(WIN32)
    return (unsigned long)GetCurrentThreadId();
#else
    return (unsigned long)(apr_os_thread_current());
#endif
}

static apr_status_t ssl_thread_cleanup(void *data)
{
    UNREFERENCED(data);
    CRYPTO_set_locking_callback(NULL);
    CRYPTO_set_id_callback(NULL);
    CRYPTO_set_dynlock_create_callback(NULL);
    CRYPTO_set_dynlock_lock_callback(NULL);
    CRYPTO_set_dynlock_destroy_callback(NULL);

    dynlockpool = NULL;

    /* Let the registered mutex cleanups do their own thing
     */
    return APR_SUCCESS;
}

/*
 * Dynamic lock creation callback
 */
static struct CRYPTO_dynlock_value *ssl_dyn_create_function(const char *file,
                                                     int line)
{
    struct CRYPTO_dynlock_value *value;
    apr_pool_t *p;
    apr_status_t rv;

    /*
     * We need a pool to allocate our mutex.  Since we can't clear
     * allocated memory from a pool, create a subpool that we can blow
     * away in the destruction callback.
     */
    rv = apr_pool_create(&p, dynlockpool);
    if (rv != APR_SUCCESS) {
        /* TODO log that fprintf(stderr, "Failed to create subpool for dynamic lock"); */
        return NULL;
    }

    value = (struct CRYPTO_dynlock_value *)apr_palloc(p,
                                                      sizeof(struct CRYPTO_dynlock_value));
    if (!value) {
        /* TODO log that fprintf(stderr, "Failed to allocate dynamic lock structure"); */
        return NULL;
    }

    value->pool = p;
    /* Keep our own copy of the place from which we were created,
       using our own pool. */
    value->file = apr_pstrdup(p, file);
    value->line = line;
    rv = apr_thread_mutex_create(&(value->mutex), APR_THREAD_MUTEX_DEFAULT,
                                p);
    if (rv != APR_SUCCESS) {
        /* TODO log that fprintf(stderr, "Failed to create thread mutex for dynamic lock"); */
        apr_pool_destroy(p);
        return NULL;
    }
    return value;
}

/*
 * Dynamic locking and unlocking function
 */
static void ssl_dyn_lock_function(int mode, struct CRYPTO_dynlock_value *l,
                           const char *file, int line)
{


    if (mode & CRYPTO_LOCK) {
        apr_thread_mutex_lock(l->mutex);
    }
    else {
        apr_thread_mutex_unlock(l->mutex);
    }
}

/*
 * Dynamic lock destruction callback
 */
static void ssl_dyn_destroy_function(struct CRYPTO_dynlock_value *l,
                          const char *file, int line)
{
    apr_status_t rv;
    rv = apr_thread_mutex_destroy(l->mutex);
    if (rv != APR_SUCCESS) {
        /* TODO log that fprintf(stderr, "Failed to destroy mutex for dynamic lock %s:%d", l->file, l->line); */
    }

    /* Trust that whomever owned the CRYPTO_dynlock_value we were
     * passed has no future use for it...
     */
    apr_pool_destroy(l->pool);
}
static void ssl_thread_setup(apr_pool_t *p)
{
    int i;

    ssl_lock_num_locks = CRYPTO_num_locks();
    ssl_lock_cs = apr_palloc(p, ssl_lock_num_locks * sizeof(*ssl_lock_cs));

    for (i = 0; i < ssl_lock_num_locks; i++) {
        apr_thread_mutex_create(&(ssl_lock_cs[i]),
                                APR_THREAD_MUTEX_DEFAULT, p);
    }

    CRYPTO_set_id_callback(ssl_thread_id);
    CRYPTO_set_locking_callback(ssl_thread_lock);

    /* Set up dynamic locking scaffolding for OpenSSL to use at its
     * convenience.
     */
    dynlockpool = p;
    CRYPTO_set_dynlock_create_callback(ssl_dyn_create_function);
    CRYPTO_set_dynlock_lock_callback(ssl_dyn_lock_function);
    CRYPTO_set_dynlock_destroy_callback(ssl_dyn_destroy_function);

    apr_pool_cleanup_register(p, NULL, ssl_thread_cleanup,
                              apr_pool_cleanup_null);
}

static int ssl_rand_choosenum(int l, int h)
{
    int i;
    char buf[50];

    apr_snprintf(buf, sizeof(buf), "%.0f",
                 (((double)(rand()%RAND_MAX)/RAND_MAX)*(h-l)));
    i = atoi(buf)+1;
    if (i < l) i = l;
    if (i > h) i = h;
    return i;
}

static int ssl_rand_load_file(const char *file)
{
    int n;

    if (file == NULL)
        file = ssl_global_rand_file;
    if (file && (strcmp(file, "builtin") == 0))
        return -1;
// BoringSsl doesn't support RAND_file_name, but RAND_status() returns 1 anyways
#ifndef OPENSSL_IS_BORINGSSL
    if (file == NULL) {
        char buffer[APR_PATH_MAX];
        file = RAND_file_name(buffer, sizeof(buffer));
    }
#endif
    if (file) {
#ifdef HAVE_SSL_RAND_EGD
        if (strncmp(file, "egd:", 4) == 0) {
            if ((n = RAND_egd(file + 4)) > 0)
                return n;
            else
                return -1;
        }
#endif
        if ((n = RAND_load_file(file, -1)) > 0)
            return n;
    }
    return -1;
}

/*
 * writes a number of random bytes (currently 1024) to
 * file which can be used to initialize the PRNG by calling
 * RAND_load_file() in a later session
 */
static int ssl_rand_save_file(const char *file)
{
#ifndef OPENSSL_IS_BORINGSSL
    char buffer[APR_PATH_MAX];
    int n;
    if (file == NULL) {
        file = RAND_file_name(buffer, sizeof(buffer));
#ifdef HAVE_SSL_RAND_EGD
    } else if ((n = RAND_egd(file)) > 0) {
        return 0;
#endif
    }
    if (file == NULL || !RAND_write_file(file))
        return 0;
    else
        return 1;
#else
    // BoringSsl doesn't have RAND_file_name/RAND_write_file and RAND_egd always return 255
    return 0;
#endif
}

int SSL_rand_seed(const char *file)
{
    unsigned char stackdata[256];
    static volatile apr_uint32_t counter = 0;

    if (ssl_rand_load_file(file) < 0) {
        int n;
        struct {
            apr_time_t    t;
            pid_t         p;
            unsigned long i;
            apr_uint32_t  u;
        } _ssl_seed;
        if (counter == 0) {
            apr_generate_random_bytes(stackdata, 256);
            RAND_seed(stackdata, 128);
        }
        _ssl_seed.t = apr_time_now();
        _ssl_seed.p = getpid();
        _ssl_seed.i = ssl_thread_id();
        apr_atomic_inc32(&counter);
        _ssl_seed.u = counter;
        RAND_seed((unsigned char *)&_ssl_seed, sizeof(_ssl_seed));
        /*
         * seed in some current state of the run-time stack (128 bytes)
         */
        n = ssl_rand_choosenum(0, sizeof(stackdata)-128-1);
        RAND_seed(stackdata + n, 128);
    }
    return RAND_status();
}

static int ssl_rand_make(const char *file, int len, int base64)
{
    int r;
    int num = len;
    BIO *out = NULL;

    out = BIO_new(BIO_s_file());
    if (out == NULL)
        return 0;
    if ((r = BIO_write_filename(out, (char *)file)) < 0) {
        BIO_free_all(out);
        return 0;
    }
    if (base64) {
        BIO *b64 = BIO_new(BIO_f_base64());
        if (b64 == NULL) {
            BIO_free_all(out);
            return 0;
        }
        out = BIO_push(b64, out);
    }
    while (num > 0) {
        unsigned char buf[4096];
        int len = num;
        if (len > sizeof(buf))
            len = sizeof(buf);
        r = RAND_bytes(buf, len);
        if (r <= 0) {
            BIO_free_all(out);
            return 0;
        }
        BIO_write(out, buf, len);
        num -= len;
    }
    r = BIO_flush(out);
    BIO_free_all(out);
    return r > 0 ? 1 : 0;
}

TCN_IMPLEMENT_CALL(jint, SSL, initialize)(TCN_STDARGS, jstring engine)
{
    int r = 0;
    jclass clazz;
    jclass sClazz;

    TCN_ALLOC_CSTRING(engine);

    UNREFERENCED(o);
    if (!tcn_global_pool) {
        TCN_FREE_CSTRING(engine);
        tcn_ThrowAPRException(e, APR_EINVAL);
        return (jint)APR_EINVAL;
    }
    /* Check if already initialized */
    if (ssl_initialized++) {
        TCN_FREE_CSTRING(engine);
        return (jint)APR_SUCCESS;
    }

#if OPENSSL_VERSION_NUMBER < 0x10100000L
    if (SSLeay() < 0x0090700L) {
        TCN_FREE_CSTRING(engine);
        tcn_ThrowAPRException(e, APR_EINVAL);
        ssl_initialized = 0;
        return (jint)APR_EINVAL;
    }
#endif

#ifndef OPENSSL_IS_BORINGSSL
#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

    /* We must register the library in full, to ensure our configuration
     * code can successfully test the SSL environment.
     */
    CRYPTO_malloc_init();
#else
    OPENSSL_malloc_init();
#endif
#endif

    ERR_load_crypto_strings();
    SSL_load_error_strings();
    SSL_library_init();
    OpenSSL_add_all_algorithms();
#if HAVE_ENGINE_LOAD_BUILTIN_ENGINES
    ENGINE_load_builtin_engines();
#endif
#if OPENSSL_VERSION_NUMBER >= 0x00907001 && !defined(OPENSSL_IS_BORINGSSL)
    OPENSSL_load_builtin_modules();
#endif

    /* Initialize thread support */
    ssl_thread_setup(tcn_global_pool);

#ifndef OPENSSL_NO_ENGINE
    if (J2S(engine)) {
        ENGINE *ee = NULL;
        apr_status_t err = APR_SUCCESS;
        if(strcmp(J2S(engine), "auto") == 0) {
            ENGINE_register_all_complete();
        }
        else {
            if ((ee = ENGINE_by_id(J2S(engine))) == NULL
                && (ee = ssl_try_load_engine(J2S(engine))) == NULL)
                err = APR_ENOTIMPL;
            else {
#ifdef ENGINE_CTRL_CHIL_SET_FORKCHECK
                if (strcmp(J2S(engine), "chil") == 0)
                    ENGINE_ctrl(ee, ENGINE_CTRL_CHIL_SET_FORKCHECK, 1, 0, 0);
#endif
                if (!ENGINE_set_default(ee, ENGINE_METHOD_ALL))
                    err = APR_ENOTIMPL;
            }
            /* Free our "structural" reference. */
            if (ee)
                ENGINE_free(ee);
        }
        if (err != APR_SUCCESS) {
            TCN_FREE_CSTRING(engine);
            ssl_init_cleanup(NULL);
            tcn_ThrowAPRException(e, err);
            return (jint)err;
        }
        tcn_ssl_engine = ee;
    }
#endif

    memset(&tcn_password_callback, 0, sizeof(tcn_pass_cb_t));
    /* Initialize PRNG
     * This will in most cases call the builtin
     * low entropy seed.
     */
    SSL_rand_seed(NULL);
    /* For SSL_get_app_data2() and SSL_get_app_data3() at request time */
    SSL_init_app_data2_3_idx();

    SSL_TMP_KEYS_INIT(r);
    if (r) {
        TCN_FREE_CSTRING(engine);
        ssl_init_cleanup(NULL);
        tcn_ThrowAPRException(e, APR_ENOTIMPL);
        return APR_ENOTIMPL;
    }
    /*
     * Let us cleanup the ssl library when the library is unloaded
     */
    apr_pool_cleanup_register(tcn_global_pool, NULL,
                              ssl_init_cleanup,
                              apr_pool_cleanup_null);
    TCN_FREE_CSTRING(engine);

    return (jint)APR_SUCCESS;
}

TCN_IMPLEMENT_CALL(jboolean, SSL, randLoad)(TCN_STDARGS, jstring file)
{
    TCN_ALLOC_CSTRING(file);
    int r;
    UNREFERENCED(o);
    r = SSL_rand_seed(J2S(file));
    TCN_FREE_CSTRING(file);
    return r ? JNI_TRUE : JNI_FALSE;
}

TCN_IMPLEMENT_CALL(jboolean, SSL, randSave)(TCN_STDARGS, jstring file)
{
    TCN_ALLOC_CSTRING(file);
    int r;
    UNREFERENCED(o);
    r = ssl_rand_save_file(J2S(file));
    TCN_FREE_CSTRING(file);
    return r ? JNI_TRUE : JNI_FALSE;
}

TCN_IMPLEMENT_CALL(jboolean, SSL, randMake)(TCN_STDARGS, jstring file,
                                            jint length, jboolean base64)
{
    TCN_ALLOC_CSTRING(file);
    int r;
    UNREFERENCED(o);
    r = ssl_rand_make(J2S(file), length, base64);
    TCN_FREE_CSTRING(file);
    return r ? JNI_TRUE : JNI_FALSE;
}

TCN_IMPLEMENT_CALL(void, SSL, randSet)(TCN_STDARGS, jstring file)
{
    TCN_ALLOC_CSTRING(file);
    UNREFERENCED(o);
    if (J2S(file)) {
        ssl_global_rand_file = apr_pstrdup(tcn_global_pool, J2S(file));
    }
    TCN_FREE_CSTRING(file);
}

TCN_IMPLEMENT_CALL(jint, SSL, fipsModeGet)(TCN_STDARGS)
{
    UNREFERENCED(o);
#ifdef OPENSSL_FIPS
    return FIPS_mode();
#else
    /* FIPS is unavailable */
    tcn_ThrowException(e, "FIPS was not available to tcnative at build time. You will need to re-build tcnative against an OpenSSL with FIPS.");

    return 0;
#endif
}

TCN_IMPLEMENT_CALL(jint, SSL, fipsModeSet)(TCN_STDARGS, jint mode)
{
    int r = 0;
    UNREFERENCED(o);

#ifdef OPENSSL_FIPS
    if(1 != (r = (jint)FIPS_mode_set((int)mode))) {
      /* arrange to get a human-readable error message */
      unsigned long err = ERR_get_error();
      char msg[ERR_LEN];

      /* ERR_load_crypto_strings() already called in initialize() */

      ERR_error_string_n(err, msg, ERR_LEN);

      tcn_ThrowException(e, msg);
    }
#else
    /* FIPS is unavailable */
    tcn_ThrowException(e, "FIPS was not available to tcnative at build time. You will need to re-build tcnative against an OpenSSL with FIPS.");
#endif

    return r;
}

/* OpenSSL Java Stream BIO */

typedef struct  {
    int            refcount;
    apr_pool_t     *pool;
    tcn_callback_t cb;
} BIO_JAVA;


static apr_status_t generic_bio_cleanup(void *data)
{
    BIO *b = (BIO *)data;

    if (b) {
        BIO_free(b);
    }
    return APR_SUCCESS;
}

void SSL_BIO_close(BIO *bi)
{
    if (bi == NULL)
        return;
    if (bi->ptr != NULL && (bi->flags & SSL_BIO_FLAG_CALLBACK)) {
        BIO_JAVA *j = (BIO_JAVA *)bi->ptr;
        j->refcount--;
        if (j->refcount == 0) {
            if (j->pool)
                apr_pool_cleanup_run(j->pool, bi, generic_bio_cleanup);
            else
                BIO_free(bi);
        }
    }
    else
        BIO_free(bi);
}

void SSL_BIO_doref(BIO *bi)
{
    if (bi == NULL)
        return;
    if (bi->ptr != NULL && (bi->flags & SSL_BIO_FLAG_CALLBACK)) {
        BIO_JAVA *j = (BIO_JAVA *)bi->ptr;
        j->refcount++;
    }
}


static int jbs_new(BIO *bi)
{
    BIO_JAVA *j;

    if ((j = OPENSSL_malloc(sizeof(BIO_JAVA))) == NULL)
        return 0;
    j->pool      = NULL;
    j->refcount  = 1;
    bi->shutdown = 1;
    bi->init     = 0;
    bi->num      = -1;
    bi->ptr      = (char *)j;

    return 1;
}

static int jbs_free(BIO *bi)
{
    JNIEnv *e = NULL;
    BIO_JAVA *j;

    if (bi == NULL)
        return 0;
    if (bi->ptr != NULL) {
        j = (BIO_JAVA *)bi->ptr;
        if (bi->init) {
            bi->init = 0;
            tcn_get_java_env(&e);
            TCN_UNLOAD_CLASS(e, j->cb.obj);
        }
        OPENSSL_free(bi->ptr);
    }
    bi->ptr = NULL;
    return 1;
}

static int jbs_write(BIO *b, const char *in, int inl)
{
    jint ret = -1;

    if (b->init && in != NULL) {
        BIO_JAVA *j = (BIO_JAVA *)b->ptr;
        JNIEnv   *e = NULL;
        jbyteArray jb;
        tcn_get_java_env(&e);
        jb = (*e)->NewByteArray(e, inl);
        if (!(*e)->ExceptionOccurred(e)) {
            BIO_clear_retry_flags(b);
            (*e)->SetByteArrayRegion(e, jb, 0, inl, (jbyte *)in);
            ret = (*e)->CallIntMethod(e, j->cb.obj,
                                      j->cb.mid[0], jb);
            (*e)->DeleteLocalRef(e, jb);
        }
    }
    if (ret == 0) {
        BIO_set_retry_write(b);
        ret = -1;
    }
    return ret;
}

static int jbs_read(BIO *b, char *out, int outl)
{
    jint ret = 0;
    jbyte *jout;

    if (b->init && out != NULL) {
        BIO_JAVA *j = (BIO_JAVA *)b->ptr;
        JNIEnv   *e = NULL;
        jbyteArray jb;
        tcn_get_java_env(&e);
        jb = (*e)->NewByteArray(e, outl);
        if (!(*e)->ExceptionOccurred(e)) {
            BIO_clear_retry_flags(b);
            ret = (*e)->CallIntMethod(e, j->cb.obj,
                                      j->cb.mid[1], jb);
            if (ret > 0) {
                jout = (*e)->GetPrimitiveArrayCritical(e, jb, NULL);
                memcpy(out, jout, ret);
                (*e)->ReleasePrimitiveArrayCritical(e, jb, jout, 0);
            } else if (outl != 0) {
                ret = -1;
                BIO_set_retry_read(b);
            }
            (*e)->DeleteLocalRef(e, jb);
        }
    }
    return ret;
}

static int jbs_puts(BIO *b, const char *in)
{
    int ret = 0;
    JNIEnv *e = NULL;
    BIO_JAVA *j;

    if (b->init && in != NULL) {
        j = (BIO_JAVA *)b->ptr;
        tcn_get_java_env(&e);
        ret = (*e)->CallIntMethod(e, j->cb.obj,
                                  j->cb.mid[2],
                                  tcn_new_string(e, in));
    }
    return ret;
}

static int jbs_gets(BIO *b, char *out, int outl)
{
    int ret = 0;
    JNIEnv *e = NULL;
    BIO_JAVA *j;
    jobject o;
    int l;

    if (b->init && out != NULL) {
        j = (BIO_JAVA *)b->ptr;
        tcn_get_java_env(&e);
        if ((o = (*e)->CallObjectMethod(e, j->cb.obj,
                            j->cb.mid[3], (jint)(outl - 1)))) {
            TCN_ALLOC_CSTRING(o);
            if (J2S(o)) {
                l = (int)strlen(J2S(o));
                if (l < outl) {
                    strcpy(out, J2S(o));
                    ret = outl;
                }
            }
            TCN_FREE_CSTRING(o);
        }
    }
    return ret;
}

static long jbs_ctrl(BIO *b, int cmd, long num, void *ptr)
{
    int ret = 0;
    switch (cmd) {
        case BIO_CTRL_FLUSH:
            ret = 1;
            break;
        default:
            ret = 0;
            break;
    }
    return ret;
}

static BIO_METHOD jbs_methods = {
    BIO_TYPE_FILE,
    "Java Callback",
    jbs_write,
    jbs_read,
    jbs_puts,
    jbs_gets,
    jbs_ctrl,
    jbs_new,
    jbs_free,
    NULL
};

static BIO_METHOD *BIO_jbs()
{
    return(&jbs_methods);
}


TCN_IMPLEMENT_CALL(jlong, SSL, newMemBIO)(TCN_STDARGS)
{
    BIO *bio = NULL;

    UNREFERENCED(o);

    // TODO: Use BIO_s_secmem() once included in stable release
    if ((bio = BIO_new(BIO_s_mem())) == NULL) {
        tcn_ThrowException(e, "Create BIO failed");
        return 0;
    }
    return P2J(bio);
}

TCN_IMPLEMENT_CALL(jlong, SSL, newBIO)(TCN_STDARGS, jlong pool,
                                       jobject callback)
{
    BIO *bio = NULL;
    BIO_JAVA *j;
    jclass cls;

    UNREFERENCED(o);

    if ((bio = BIO_new(BIO_jbs())) == NULL) {
        tcn_ThrowException(e, "Create BIO failed");
        goto init_failed;
    }
    j = (BIO_JAVA *)bio->ptr;
    if (j == NULL) {
        tcn_ThrowException(e, "Create BIO failed");
        goto init_failed;
    }
    j->pool = J2P(pool, apr_pool_t *);
    if (j->pool) {
        apr_pool_cleanup_register(j->pool, (const void *)bio,
                                  generic_bio_cleanup,
                                  apr_pool_cleanup_null);
    }

    cls = (*e)->GetObjectClass(e, callback);
    j->cb.mid[0] = (*e)->GetMethodID(e, cls, "write", "([B)I");
    j->cb.mid[1] = (*e)->GetMethodID(e, cls, "read",  "([B)I");
    j->cb.mid[2] = (*e)->GetMethodID(e, cls, "puts",  "(Ljava/lang/String;)I");
    j->cb.mid[3] = (*e)->GetMethodID(e, cls, "gets",  "(I)Ljava/lang/String;");
    /* TODO: Check if method id's are valid */
    j->cb.obj    = (*e)->NewGlobalRef(e, callback);

    bio->init  = 1;
    bio->flags = SSL_BIO_FLAG_CALLBACK;
    return P2J(bio);
init_failed:
    BIO_free(bio); // this function is safe to call with NULL.
    return 0;
}


TCN_IMPLEMENT_CALL(jint, SSL, closeBIO)(TCN_STDARGS, jlong bio)
{
    BIO *b = J2P(bio, BIO *);

    UNREFERENCED_STDARGS;

    if (b != NULL) {
        SSL_BIO_close(b);
    }

    return APR_SUCCESS;
}

TCN_IMPLEMENT_CALL(void, SSL, setPasswordCallback)(TCN_STDARGS,
                                                   jobject callback)
{
    jclass cls;

    UNREFERENCED(o);
    if (tcn_password_callback.cb.obj) {
        TCN_UNLOAD_CLASS(e,
                         tcn_password_callback.cb.obj);
    }
    cls = (*e)->GetObjectClass(e, callback);
    tcn_password_callback.cb.mid[0] = (*e)->GetMethodID(e, cls, "callback",
                           "(Ljava/lang/String;)Ljava/lang/String;");
    /* TODO: Check if method id is valid */
    tcn_password_callback.cb.obj    = (*e)->NewGlobalRef(e, callback);

}

TCN_IMPLEMENT_CALL(void, SSL, setPassword)(TCN_STDARGS, jstring password)
{
    TCN_ALLOC_CSTRING(password);
    UNREFERENCED(o);
    if (J2S(password)) {
        strncpy(tcn_password_callback.password, J2S(password), SSL_MAX_PASSWORD_LEN);
        tcn_password_callback.password[SSL_MAX_PASSWORD_LEN-1] = '\0';
    }
    TCN_FREE_CSTRING(password);
}

TCN_IMPLEMENT_CALL(jboolean, SSL, generateRSATempKey)(TCN_STDARGS, jint idx)
{
    int r = 1;
    UNREFERENCED_STDARGS;
    SSL_TMP_KEY_FREE(RSA, idx);
    switch (idx) {
        case SSL_TMP_KEY_RSA_512:
            r = SSL_TMP_KEY_INIT_RSA(512);
        break;
        case SSL_TMP_KEY_RSA_1024:
            r = SSL_TMP_KEY_INIT_RSA(1024);
        break;
        case SSL_TMP_KEY_RSA_2048:
            r = SSL_TMP_KEY_INIT_RSA(2048);
        break;
        case SSL_TMP_KEY_RSA_4096:
            r = SSL_TMP_KEY_INIT_RSA(4096);
        break;
    }
    return r ? JNI_FALSE : JNI_TRUE;
}

TCN_IMPLEMENT_CALL(jboolean, SSL, loadDSATempKey)(TCN_STDARGS, jint idx,
                                                  jstring file)
{
    jboolean r = JNI_FALSE;
    TCN_ALLOC_CSTRING(file);
    DH *dh;
    UNREFERENCED(o);

    if (!J2S(file))
        return JNI_FALSE;
    SSL_TMP_KEY_FREE(DSA, idx);
    if ((dh = SSL_dh_get_param_from_file(J2S(file)))) {
        SSL_temp_keys[idx] = dh;
        r = JNI_TRUE;
    }
    TCN_FREE_CSTRING(file);
    return r;
}

TCN_IMPLEMENT_CALL(jstring, SSL, getLastError)(TCN_STDARGS)
{
    char buf[ERR_LEN];
    UNREFERENCED(o);
    ERR_error_string(ERR_get_error(), buf);
    return tcn_new_string(e, buf);
}

TCN_IMPLEMENT_CALL(jboolean, SSL, hasOp)(TCN_STDARGS, jint op)
{
    return op == (op & supported_ssl_opts) ? JNI_TRUE : JNI_FALSE;
}

/*** Begin Twitter 1:1 API addition ***/
TCN_IMPLEMENT_CALL(jint, SSL, getLastErrorNumber)(TCN_STDARGS) {
    UNREFERENCED_STDARGS;
    return ERR_get_error();
}

static void ssl_info_callback(const SSL *ssl, int where, int ret) {
    int *handshakeCount = NULL;
    if (0 != (where & SSL_CB_HANDSHAKE_START)) {
        handshakeCount = (int*) SSL_get_app_data3((SSL*) ssl);
        if (handshakeCount != NULL) {
            ++(*handshakeCount);
        }
    }
}

TCN_IMPLEMENT_CALL(jlong /* SSL * */, SSL, newSSL)(TCN_STDARGS,
                                                   jlong ctx /* tcn_ssl_ctxt_t * */,
                                                   jboolean server) {
    SSL *ssl = NULL;
    int *handshakeCount = NULL;
    tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);

    if (c == NULL) {
        tcn_ThrowException(e, "ssl ctx is null");
        return 0;
    }
    if (c->ctx == NULL) {
        tcn_ThrowException(e, "ctx is null");
        return 0;
    }

    UNREFERENCED_STDARGS;

    ssl = SSL_new(c->ctx);
    if (ssl == NULL) {
        tcn_ThrowException(e, "cannot create new ssl");
        return 0;
    }

    // Store the handshakeCount in the SSL instance.
    handshakeCount = malloc(sizeof(int));
    *handshakeCount = 0;
    SSL_set_app_data3(ssl, handshakeCount);

    // Add callback to keep track of handshakes.
    SSL_CTX_set_info_callback(c->ctx, ssl_info_callback);

    if (server) {
        SSL_set_accept_state(ssl);
    } else {
        SSL_set_connect_state(ssl);
    }

    // Setup verify and seed
    SSL_set_verify_result(ssl, X509_V_OK);
    SSL_rand_seed(c->rand_file);

    // Store for later usage in SSL_callback_SSL_verify
    SSL_set_app_data2(ssl, c);
    return P2J(ssl);
}

TCN_IMPLEMENT_CALL(void, SSL, setBIO)(TCN_STDARGS,
                                      jlong ssl /* SSL * */,
                                      jlong rbio /* BIO * */,
                                      jlong wbio /* BIO * */) {
    SSL *ssl_ = J2P(ssl, SSL *);
    BIO *r = J2P(rbio, BIO *);
    BIO *w = J2P(wbio, BIO *);

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return;
    }

    UNREFERENCED_STDARGS;

    SSL_set_bio(ssl_, r, w);
}

TCN_IMPLEMENT_CALL(jint, SSL, getError)(TCN_STDARGS,
                                       jlong ssl /* SSL * */,
                                       jint ret) {
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return 0;
    }

    UNREFERENCED_STDARGS;

    return SSL_get_error(ssl_, ret);
}

// How much did SSL write into this BIO?
TCN_IMPLEMENT_CALL(jint /* nbytes */, SSL, pendingWrittenBytesInBIO)(TCN_STDARGS,
                                                                     jlong bio /* BIO * */) {
    BIO *b = J2P(bio, BIO *);

    if (b == NULL) {
        tcn_ThrowException(e, "bio is null");
        return 0;
    }

    UNREFERENCED_STDARGS;

    return BIO_ctrl_pending(b);
}

// How much is available for reading in the given SSL struct?
TCN_IMPLEMENT_CALL(jint, SSL, pendingReadableBytesInSSL)(TCN_STDARGS, jlong ssl /* SSL * */) {
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return 0;
    }

    UNREFERENCED_STDARGS;

    return SSL_pending(ssl_);
}

// Write wlen bytes from wbuf into bio
TCN_IMPLEMENT_CALL(jint /* status */, SSL, writeToBIO)(TCN_STDARGS,
                                                       jlong bio /* BIO * */,
                                                       jlong wbuf /* char* */,
                                                       jint wlen /* sizeof(wbuf) */) {
    BIO *b = J2P(bio, BIO *);
    void *w = J2P(wbuf, void *);

    if (b == NULL) {
        tcn_ThrowException(e, "bio is null");
        return 0;
    }
    if (w == NULL) {
        tcn_ThrowException(e, "wbuf is null");
        return 0;
    }

    UNREFERENCED_STDARGS;

    return BIO_write(b, w, wlen);

}

// Read up to rlen bytes from bio into rbuf
TCN_IMPLEMENT_CALL(jint /* status */, SSL, readFromBIO)(TCN_STDARGS,
                                                        jlong bio /* BIO * */,
                                                        jlong rbuf /* char * */,
                                                        jint rlen /* sizeof(rbuf) - 1 */) {
    BIO *b = J2P(bio, BIO *);
    void *r = J2P(rbuf, void *);

    if (b == NULL) {
        tcn_ThrowException(e, "bio is null");
        return 0;
    }
    if (r == NULL) {
        tcn_ThrowException(e, "rbuf is null");
        return 0;
    }

    UNREFERENCED_STDARGS;

    return BIO_read(b, r, rlen);
}

// Write up to wlen bytes of application data to the ssl BIO (encrypt)
TCN_IMPLEMENT_CALL(jint /* status */, SSL, writeToSSL)(TCN_STDARGS,
                                                       jlong ssl /* SSL * */,
                                                       jlong wbuf /* char * */,
                                                       jint wlen /* sizeof(wbuf) */) {
    SSL *ssl_ = J2P(ssl, SSL *);
    void *w = J2P(wbuf, void *);

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return 0;
    }
    if (w == NULL) {
        tcn_ThrowException(e, "wbuf is null");
        return 0;
    }

    UNREFERENCED_STDARGS;

    return SSL_write(ssl_, w, wlen);
}

// Read up to rlen bytes of application data from the given SSL BIO (decrypt)
TCN_IMPLEMENT_CALL(jint /* status */, SSL, readFromSSL)(TCN_STDARGS,
                                                        jlong ssl /* SSL * */,
                                                        jlong rbuf /* char * */,
                                                        jint rlen /* sizeof(rbuf) - 1 */) {
    SSL *ssl_ = J2P(ssl, SSL *);
    void *r = J2P(rbuf, void *);

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return 0;
    }
    if (r == NULL) {
        tcn_ThrowException(e, "rbuf is null");
        return 0;
    }

    UNREFERENCED_STDARGS;

    return SSL_read(ssl_, r, rlen);
}

// Get the shutdown status of the engine
TCN_IMPLEMENT_CALL(jint /* status */, SSL, getShutdown)(TCN_STDARGS,
                                                        jlong ssl /* SSL * */) {
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return 0;
    }

    UNREFERENCED_STDARGS;

    return SSL_get_shutdown(ssl_);
}

// Called when the peer closes the connection
TCN_IMPLEMENT_CALL(void, SSL, setShutdown)(TCN_STDARGS,
                                           jlong ssl /* SSL * */,
                                           jint mode) {
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return;
    }

    UNREFERENCED_STDARGS;

    SSL_set_shutdown(ssl_, mode);
}

// Free the SSL * and its associated internal BIO
TCN_IMPLEMENT_CALL(void, SSL, freeSSL)(TCN_STDARGS,
                                       jlong ssl /* SSL * */) {
    int *handshakeCount = NULL;
    SSL *ssl_ = J2P(ssl, SSL *);
    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return;
    }
    handshakeCount = SSL_get_app_data3(ssl_);

    UNREFERENCED_STDARGS;

    if (handshakeCount != NULL) {
        free(handshakeCount);
    }
    SSL_free(ssl_);
}

// Make a BIO pair (network and internal) for the provided SSL * and return the network BIO
TCN_IMPLEMENT_CALL(jlong, SSL, makeNetworkBIO)(TCN_STDARGS,
                                               jlong ssl /* SSL * */) {
    SSL *ssl_ = J2P(ssl, SSL *);
    BIO *internal_bio;
    BIO *network_bio;

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return 0;
    }

    if (BIO_new_bio_pair(&internal_bio, 0, &network_bio, 0) != 1) {
        tcn_ThrowException(e, "BIO_new_bio_pair failed");
        return 0;
    }

    UNREFERENCED(o);

    SSL_set_bio(ssl_, internal_bio, internal_bio);

    return P2J(network_bio);
}

// Free a BIO * (typically, the network BIO)
TCN_IMPLEMENT_CALL(void, SSL, freeBIO)(TCN_STDARGS,
                                       jlong bio /* BIO * */) {
    BIO *bio_ = J2P(bio, BIO *);

    UNREFERENCED_STDARGS;

    if (bio_ != NULL) {
        BIO_free(bio_);
    }
}

// Send CLOSE_NOTIFY to peer
TCN_IMPLEMENT_CALL(jint /* status */, SSL, shutdownSSL)(TCN_STDARGS,
                                                        jlong ssl /* SSL * */) {
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return 0;
    }

    UNREFERENCED_STDARGS;

    return SSL_shutdown(ssl_);
}

// Read which cipher was negotiated for the given SSL *.
TCN_IMPLEMENT_CALL(jstring, SSL, getCipherForSSL)(TCN_STDARGS,
                                                  jlong ssl /* SSL * */)
{
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return NULL;
    }

    UNREFERENCED_STDARGS;

    return AJP_TO_JSTRING(SSL_get_cipher(ssl_));
}

// Read which protocol was negotiated for the given SSL *.
TCN_IMPLEMENT_CALL(jstring, SSL, getVersion)(TCN_STDARGS,
                                                  jlong ssl /* SSL * */)
{
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return NULL;
    }

    UNREFERENCED_STDARGS;

    return AJP_TO_JSTRING(SSL_get_version(ssl_));
}

// Is the handshake over yet?
TCN_IMPLEMENT_CALL(jint, SSL, isInInit)(TCN_STDARGS,
                                        jlong ssl /* SSL * */) {
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return 0;
    }

    UNREFERENCED(o);

    return SSL_in_init(ssl_);
}

TCN_IMPLEMENT_CALL(jint, SSL, doHandshake)(TCN_STDARGS,
                                           jlong ssl /* SSL * */) {
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return 0;
    }

    UNREFERENCED(o);

    return SSL_do_handshake(ssl_);
}

// Read which protocol was negotiated for the given SSL *.
TCN_IMPLEMENT_CALL(jstring, SSL, getNextProtoNegotiated)(TCN_STDARGS,
                                                         jlong ssl /* SSL * */) {
    SSL *ssl_ = J2P(ssl, SSL *);
    const unsigned char *proto;
    unsigned int proto_len;

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return NULL;
    }

    UNREFERENCED(o);

    SSL_get0_next_proto_negotiated(ssl_, &proto, &proto_len);
    return tcn_new_stringn(e, (char*) proto, proto_len);
}

/*** End Twitter API Additions ***/

/*** Apple API Additions ***/

TCN_IMPLEMENT_CALL(jstring, SSL, getAlpnSelected)(TCN_STDARGS,
                                                         jlong ssl /* SSL * */) {
    // Use weak linking with GCC as this will alow us to run the same packaged version with multiple
    // version of openssl.
    #if defined(__GNUC__) || defined(__GNUG__)
        if (!SSL_get0_alpn_selected) {
            UNREFERENCED(o);
            UNREFERENCED(ssl);
            return NULL;
        }
    #endif

    // We can only support it when either use openssl version >= 1.0.2 or GCC as this way we can use weak linking
    #if OPENSSL_VERSION_NUMBER >= 0x10002000L || defined(__GNUC__) || defined(__GNUG__)
        SSL *ssl_ = J2P(ssl, SSL *);
        const unsigned char *proto;
        unsigned int proto_len;

        if (ssl_ == NULL) {
            tcn_ThrowException(e, "ssl is null");
            return NULL;
        }

        UNREFERENCED(o);

        SSL_get0_alpn_selected(ssl_, &proto, &proto_len);
        return tcn_new_stringn(e, (char*) proto, proto_len);
    #else
        UNREFERENCED(o);
        UNREFERENCED(ssl);
        return NULL;
    #endif
}

TCN_IMPLEMENT_CALL(jobjectArray, SSL, getPeerCertChain)(TCN_STDARGS,
                                                  jlong ssl /* SSL * */)
{
    STACK_OF(X509) *sk;
    int len;
    int i;
    X509 *cert;
    int length;
    unsigned char *buf;
    jobjectArray array;
    jbyteArray bArray;
    jclass byteArrayClass = tcn_get_byte_array_class();

    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return NULL;
    }

    UNREFERENCED(o);

    // Get a stack of all certs in the chain.
    sk = SSL_get_peer_cert_chain(ssl_);

    len = sk_X509_num(sk);
    if (len <= 0) {
        // No peer certificate chain as no auth took place yet, or the auth was not successful.
        return NULL;
    }
    // Create the byte[][] array that holds all the certs
    array = (*e)->NewObjectArray(e, len, byteArrayClass, NULL);

    for(i = 0; i < len; i++) {
        cert = sk_X509_value(sk, i);

        buf = NULL;
        length = i2d_X509(cert, &buf);
        if (length < 0) {
            if (buf != NULL) {
                OPENSSL_free(buf);
            }
            // In case of error just return an empty byte[][]
            return (*e)->NewObjectArray(e, 0, byteArrayClass, NULL);
        }
        bArray = (*e)->NewByteArray(e, length);
        (*e)->SetByteArrayRegion(e, bArray, 0, length, (jbyte*) buf);
        (*e)->SetObjectArrayElement(e, array, i, bArray);

        // Delete the local reference as we not know how long the chain is and local references are otherwise
        // only freed once jni method returns.
        (*e)->DeleteLocalRef(e, bArray);

        OPENSSL_free(buf);
    }
    return array;
}

TCN_IMPLEMENT_CALL(jbyteArray, SSL, getPeerCertificate)(TCN_STDARGS,
                                                  jlong ssl /* SSL * */)
{
    X509 *cert;
    int length;
    unsigned char *buf = NULL;
    jbyteArray bArray;

    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return NULL;
    }

    UNREFERENCED(o);

    // Get a stack of all certs in the chain
    cert = SSL_get_peer_certificate(ssl_);
    if (cert == NULL) {
        return NULL;
    }

    length = i2d_X509(cert, &buf);

    bArray = (*e)->NewByteArray(e, length);
    (*e)->SetByteArrayRegion(e, bArray, 0, length, (jbyte*) buf);

    // We need to free the cert as the reference count is incremented by one and it is not destroyed when the
    // session is freed.
    // See https://www.openssl.org/docs/ssl/SSL_get_peer_certificate.html
    X509_free(cert);

    OPENSSL_free(buf);

    return bArray;
}

TCN_IMPLEMENT_CALL(jstring, SSL, getErrorString)(TCN_STDARGS, jlong number)
{
    char buf[ERR_LEN];
    UNREFERENCED(o);
    ERR_error_string(number, buf);
    return tcn_new_string(e, buf);
}

TCN_IMPLEMENT_CALL(jlong, SSL, getTime)(TCN_STDARGS, jlong ssl)
{
    SSL *ssl_ = J2P(ssl, SSL *);
    SSL_SESSION *session = NULL;

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return 0;
    }

    session = SSL_get_session(ssl_);
    if (session == NULL) {
        // BoringSSL does not protect against a NULL session. OpenSSL
        // returns 0 if the session is NULL, so do that here.
        return 0;
    }

    UNREFERENCED(o);

    return SSL_get_time(session);
}


TCN_IMPLEMENT_CALL(jlong, SSL, getTimeout)(TCN_STDARGS, jlong ssl)
{
    SSL *ssl_ = J2P(ssl, SSL *);
    SSL_SESSION *session = NULL;

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return 0;
    }

    session = SSL_get_session(ssl_);
    if (session == NULL) {
        // BoringSSL does not protect against a NULL session. OpenSSL
        // returns 0 if the session is NULL, so do that here.
        return 0;
    }

    UNREFERENCED(o);

    return SSL_get_timeout(session);
}


TCN_IMPLEMENT_CALL(jlong, SSL, setTimeout)(TCN_STDARGS, jlong ssl, jlong seconds)
{
    SSL *ssl_ = J2P(ssl, SSL *);
    SSL_SESSION *session = NULL;

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return 0;
    }

    session = SSL_get_session(ssl_);
    if (session == NULL) {
        // BoringSSL does not protect against a NULL session. OpenSSL
        // returns 0 if the session is NULL, so do that here.
        return 0;
    }

    UNREFERENCED(o);

    return SSL_set_timeout(session, seconds);
}


TCN_IMPLEMENT_CALL(void, SSL, setVerify)(TCN_STDARGS, jlong ssl,
                                                jint level, jint depth)
{
    tcn_ssl_ctxt_t *c;
    int verify;
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return;
    }

    c = SSL_get_app_data2(ssl_);

    verify = SSL_VERIFY_NONE;

    UNREFERENCED(o);
    TCN_ASSERT(ctx != 0);
    c->verify_mode = level;

    if (c->verify_mode == SSL_CVERIFY_UNSET)
        c->verify_mode = SSL_CVERIFY_NONE;
    if (depth > 0)
        c->verify_depth = depth;
    /*
     *  Configure callbacks for SSL context
     */
    if (c->verify_mode == SSL_CVERIFY_REQUIRE)
        verify |= SSL_VERIFY_PEER_STRICT;
    if ((c->verify_mode == SSL_CVERIFY_OPTIONAL) ||
        (c->verify_mode == SSL_CVERIFY_OPTIONAL_NO_CA))
        verify |= SSL_VERIFY_PEER;
    if (!c->store) {
        if (SSL_CTX_set_default_verify_paths(c->ctx)) {
            c->store = SSL_CTX_get_cert_store(c->ctx);
            X509_STORE_set_flags(c->store, 0);
        }
        else {
            /* XXX: See if this is fatal */
        }
    }

    SSL_set_verify(ssl_, verify, SSL_callback_SSL_verify);
}

TCN_IMPLEMENT_CALL(void, SSL, setOptions)(TCN_STDARGS, jlong ssl,
                                                 jint opt)
{
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return;
    }

    UNREFERENCED_STDARGS;

#ifndef SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
    /* Clear the flag if not supported */
    if (opt & 0x00040000) {
        opt &= ~0x00040000;
    }
#endif
    SSL_set_options(ssl_, opt);
}

TCN_IMPLEMENT_CALL(void, SSL, clearOptions)(TCN_STDARGS, jlong ssl,
                                                 jint opt)
{
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return;
    }

    UNREFERENCED_STDARGS;

    SSL_clear_options(ssl_, opt);
}

TCN_IMPLEMENT_CALL(jint, SSL, getOptions)(TCN_STDARGS, jlong ssl)
{
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return 0;
    }

    UNREFERENCED_STDARGS;

    return SSL_get_options(ssl_);
}

TCN_IMPLEMENT_CALL(jobjectArray, SSL, getCiphers)(TCN_STDARGS, jlong ssl)
{
    STACK_OF(SSL_CIPHER) *sk;
    int len;
    jobjectArray array;
    const SSL_CIPHER *cipher;
    const char *name;
    int i;
    jstring c_name;
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return NULL;
    }

    UNREFERENCED_STDARGS;

    sk = SSL_get_ciphers(ssl_);
    len = sk_SSL_CIPHER_num(sk);

    if (len <= 0) {
        // No peer certificate chain as no auth took place yet, or the auth was not successful.
        return NULL;
    }

    // Create the byte[][] array that holds all the certs
    array = (*e)->NewObjectArray(e, len, tcn_get_string_class(), NULL);

    for (i = 0; i < len; i++) {
        cipher = sk_SSL_CIPHER_value(sk, i);
        name = SSL_CIPHER_get_name(cipher);

        c_name = (*e)->NewStringUTF(e, name);
        (*e)->SetObjectArrayElement(e, array, i, c_name);
    }
    return array;
}

TCN_IMPLEMENT_CALL(jboolean, SSL, setCipherSuites)(TCN_STDARGS, jlong ssl,
                                                         jstring ciphers)
{
    jboolean rv = JNI_TRUE;
    TCN_ALLOC_CSTRING(ciphers);
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return JNI_FALSE;
    }

    UNREFERENCED(o);

    if (!J2S(ciphers)) {
        return JNI_FALSE;
    }

    if (!SSL_set_cipher_list(ssl_, J2S(ciphers))) {
        char err[ERR_LEN];
        ERR_error_string(ERR_get_error(), err);
        tcn_Throw(e, "Unable to configure permitted SSL ciphers (%s)", err);
        rv = JNI_FALSE;
    }

    TCN_FREE_CSTRING(ciphers);
    return rv;
}

TCN_IMPLEMENT_CALL(jbyteArray, SSL, getSessionId)(TCN_STDARGS, jlong ssl)
{

    unsigned int len;
    const unsigned char *session_id;
    SSL_SESSION *session;
    jbyteArray bArray;
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return NULL;
    }

    UNREFERENCED(o);

    session = SSL_get_session(ssl_);
    if (session == NULL) {
        return NULL;
    }

    session_id = SSL_SESSION_get_id(session, &len);
    if (len == 0 || session_id == NULL) {
        return NULL;
    }

    bArray = (*e)->NewByteArray(e, len);
    (*e)->SetByteArrayRegion(e, bArray, 0, len, (jbyte*) session_id);
    return bArray;
}

TCN_IMPLEMENT_CALL(jint, SSL, getHandshakeCount)(TCN_STDARGS, jlong ssl)
{
    int *handshakeCount = NULL;
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return -1;
    }

    UNREFERENCED(o);

    handshakeCount = SSL_get_app_data3(ssl_);
    if (handshakeCount != NULL) {
        return *handshakeCount;
    }
    return 0;
}


TCN_IMPLEMENT_CALL(void, SSL, clearError)(TCN_STDARGS)
{
    UNREFERENCED(o);
    ERR_clear_error();
}

TCN_IMPLEMENT_CALL(jint, SSL, renegotiate)(TCN_STDARGS,
                                           jlong ssl /* SSL * */) {
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return 0;
    }

    UNREFERENCED(o);

    return SSL_renegotiate(ssl_);
}

TCN_IMPLEMENT_CALL(void, SSL, setState)(TCN_STDARGS,
                                           jlong ssl, /* SSL * */
                                           jint state) {
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
        return;
    }

    UNREFERENCED(o);

    SSL_set_state(ssl_, state);
}

TCN_IMPLEMENT_CALL(void, SSL, setTlsExtHostName)(TCN_STDARGS, jlong ssl, jstring hostname) {
    TCN_ALLOC_CSTRING(hostname);
    SSL *ssl_ = J2P(ssl, SSL *);

    if (ssl_ == NULL) {
        tcn_ThrowException(e, "ssl is null");
    } else {
        UNREFERENCED(o);

        if (SSL_set_tlsext_host_name(ssl_, J2S(hostname)) != 1) {
            char err[ERR_LEN];
            ERR_error_string(ERR_get_error(), err);
            tcn_Throw(e, "Unable to set TLS servername extension (%s)", err);
        }
    }

    TCN_FREE_CSTRING(hostname);
}

TCN_IMPLEMENT_CALL(jobjectArray, SSL, authenticationMethods)(TCN_STDARGS, jlong ssl) {
    SSL *ssl_ = J2P(ssl, SSL *);
    const STACK_OF(SSL_CIPHER) *ciphers = NULL;
    int len;
    int i;
    jobjectArray array;

    TCN_ASSERT(ssl_ != NULL);

    UNREFERENCED(o);

    ciphers = SSL_get_ciphers(ssl_);
    len = sk_SSL_CIPHER_num(ciphers);

    array = (*e)->NewObjectArray(e, len, tcn_get_string_class(), NULL);

    for (i = 0; i < len; i++) {
        (*e)->SetObjectArrayElement(e, array, i,
        (*e)->NewStringUTF(e, SSL_cipher_authentication_method((SSL_CIPHER*) sk_value((_STACK*) ciphers, i))));
    }
    return array;
}

TCN_IMPLEMENT_CALL(void, SSL, setCertificateBio)(TCN_STDARGS, jlong ssl,
                                                         jlong cert, jlong key,
                                                         jstring password)
{
    SSL *ssl_ = J2P(ssl, SSL *);
    BIO *cert_bio = J2P(cert, BIO *);
    BIO *key_bio = J2P(key, BIO *);
    EVP_PKEY* pkey = NULL;
    X509* xcert = NULL;
    tcn_pass_cb_t* cb_data = NULL;
    TCN_ALLOC_CSTRING(password);
    char err[ERR_LEN];

    UNREFERENCED(o);
    TCN_ASSERT(ssl != NULL);

    cb_data = &tcn_password_callback;
    cb_data->password[0] = '\0';
    if (J2S(password) != NULL) {
        strncat(cb_data->password, J2S(password), SSL_MAX_PASSWORD_LEN - 1);
    }

    if (key <= 0) {
        key = cert;
    }

    if (cert <= 0 || key <= 0) {
        tcn_Throw(e, "No Certificate file specified or invalid file format");
        goto cleanup;
    }

    if ((pkey = load_pem_key_bio(cb_data, key_bio)) == NULL) {
        ERR_error_string_n(ERR_get_error(), err, ERR_LEN);
        ERR_clear_error();
        tcn_Throw(e, "Unable to load certificate key (%s)",err);
        goto cleanup;
    }
    if ((xcert = load_pem_cert_bio(cb_data, cert_bio)) == NULL) {
        ERR_error_string_n(ERR_get_error(), err, ERR_LEN);
        ERR_clear_error();
        tcn_Throw(e, "Unable to load certificate (%s) ", err);
        goto cleanup;
    }

    if (SSL_use_certificate(ssl_, xcert) <= 0) {
        ERR_error_string_n(ERR_get_error(), err, ERR_LEN);
        ERR_clear_error();
        tcn_Throw(e, "Error setting certificate (%s)", err);
        goto cleanup;
    }
    if (SSL_use_PrivateKey(ssl_, pkey) <= 0) {
        ERR_error_string_n(ERR_get_error(), err, ERR_LEN);
        ERR_clear_error();
        tcn_Throw(e, "Error setting private key (%s)", err);
        goto cleanup;
    }
    if (SSL_check_private_key(ssl_) <= 0) {
        ERR_error_string_n(ERR_get_error(), err, ERR_LEN);
        ERR_clear_error();

        tcn_Throw(e, "Private key does not match the certificate public key (%s)",
                  err);
        goto cleanup;
    }
cleanup:
    TCN_FREE_CSTRING(password);
    EVP_PKEY_free(pkey); // this function is safe to call with NULL
    X509_free(xcert); // this function is safe to call with NULL
}

TCN_IMPLEMENT_CALL(void, SSL, setCertificateChainBio)(TCN_STDARGS, jlong ssl,
                                                                  jlong chain,
                                                                  jboolean skipfirst)
{
    SSL *ssl_ = J2P(ssl, SSL *);
    BIO *b = J2P(chain, BIO *);
    char err[ERR_LEN];

    UNREFERENCED(o);
    TCN_ASSERT(ssl_ != NULL);
    TCN_ASSERT(b != NULL);

    if (SSL_use_certificate_chain_bio(ssl_, b, skipfirst) < 0)  {
        ERR_error_string_n(ERR_get_error(), err, ERR_LEN);
        ERR_clear_error();
        tcn_Throw(e, "Error setting certificate chain (%s)", err);
    }
}

TCN_IMPLEMENT_CALL(long, SSL, parsePrivateKey)(TCN_STDARGS, jlong privateKeyBio, jstring password)
{
    EVP_PKEY* pkey = NULL;
    BIO *bio = J2P(privateKeyBio, BIO *);
    tcn_pass_cb_t* cb_data = &tcn_password_callback;
    TCN_ALLOC_CSTRING(password);
    char err[ERR_LEN];

    UNREFERENCED(o);

    if (bio == NULL) {
        tcn_Throw(e, "Unable to load certificate key");
        goto cleanup;
    }

    cb_data->password[0] = '\0';
    if (J2S(password) != NULL) {
        strncat(cb_data->password, J2S(password), SSL_MAX_PASSWORD_LEN - 1);
    }

    if ((pkey = load_pem_key_bio(cb_data, bio)) == NULL) {
        ERR_error_string_n(ERR_get_error(), err, ERR_LEN);
        ERR_clear_error();
        tcn_Throw(e, "Unable to load certificate key (%s)",err);
        goto cleanup;
    }

cleanup:
    TCN_FREE_CSTRING(password);
    return P2J(pkey);
}

TCN_IMPLEMENT_CALL(void, SSL, freePrivateKey)(TCN_STDARGS, jlong privateKey)
{
    EVP_PKEY *key = J2P(privateKey, EVP_PKEY *);
    UNREFERENCED(o);
    EVP_PKEY_free(key); // Safe to call with NULL as well.
}

TCN_IMPLEMENT_CALL(long, SSL, parseX509Chain)(TCN_STDARGS, jlong x509ChainBio)
{
    BIO *cert_bio = J2P(x509ChainBio, BIO *);
    X509* cert = NULL;
    STACK_OF(X509) *chain = NULL;
    char err[ERR_LEN];
    unsigned long error;
    int n = 0;

    UNREFERENCED(o);

    if (cert_bio == NULL) {
        tcn_Throw(e, "No Certificate specified or invalid format");
        goto cleanup;
    }

    chain = sk_X509_new_null();
    while ((cert = PEM_read_bio_X509(cert_bio, NULL, NULL, NULL)) != NULL) {
        if (sk_X509_push(chain, cert) != 1) {
            tcn_Throw(e, "No Certificate specified or invalid format");
            goto cleanup;
        }
        cert = NULL;
        n++;
    }

    // ensure that if we have an error its just for EOL.
    if ((error = ERR_peek_error()) > 0) {
        if (!(ERR_GET_LIB(error) == ERR_LIB_PEM
              && ERR_GET_REASON(error) == PEM_R_NO_START_LINE)) {

            ERR_error_string_n(ERR_get_error(), err, ERR_LEN);
            tcn_Throw(e, "Invalid format (%s)", err);
            goto cleanup;
        }
        ERR_clear_error();
    }

    return P2J(chain);

cleanup:
    ERR_clear_error();
    sk_X509_pop_free(chain, X509_free);
    X509_free(cert);
    return 0;
}

TCN_IMPLEMENT_CALL(void, SSL, freeX509Chain)(TCN_STDARGS, jlong x509Chain)
{
    STACK_OF(X509) *chain = J2P(x509Chain, STACK_OF(X509) *);
    UNREFERENCED(o);
    sk_X509_pop_free(chain, X509_free);
}

/*** End Apple API Additions ***/

#else
#error OpenSSL is required!

/* OpenSSL is not supported.
 * Create empty stubs.
 */

TCN_IMPLEMENT_CALL(jint, SSL, version)(TCN_STDARGS)
{
    UNREFERENCED_STDARGS;
    return 0;
}

TCN_IMPLEMENT_CALL(jstring, SSL, versionString)(TCN_STDARGS)
{
    UNREFERENCED_STDARGS;
    return NULL;
}

TCN_IMPLEMENT_CALL(jint, SSL, initialize)(TCN_STDARGS, jstring engine)
{
    UNREFERENCED(o);
    UNREFERENCED(engine);
    tcn_ThrowAPRException(e, APR_ENOTIMPL);
    return (jint)APR_ENOTIMPL;
}

TCN_IMPLEMENT_CALL(jboolean, SSL, randLoad)(TCN_STDARGS, jstring file)
{
    UNREFERENCED_STDARGS;
    UNREFERENCED(file);
    return JNI_FALSE;
}

TCN_IMPLEMENT_CALL(jboolean, SSL, randSave)(TCN_STDARGS, jstring file)
{
    UNREFERENCED_STDARGS;
    return JNI_FALSE;
}

TCN_IMPLEMENT_CALL(jboolean, SSL, randMake)(TCN_STDARGS, jstring file,
                                            jint length, jboolean base64)
{
    UNREFERENCED_STDARGS;
    UNREFERENCED(file);
    UNREFERENCED(length);
    UNREFERENCED(base64);
    return JNI_FALSE;
}

TCN_IMPLEMENT_CALL(void, SSL, randSet)(TCN_STDARGS, jstring file)
{
    UNREFERENCED_STDARGS;
    UNREFERENCED(file);
}

TCN_IMPLEMENT_CALL(jint, SSL, fipsModeGet)(TCN_STDARGS)
{
    UNREFERENCED(o);
    tcn_ThrowException(e, "FIPS was not available to tcnative at build time. You will need to re-build tcnative against an OpenSSL with FIPS.");
    return 0;
}

TCN_IMPLEMENT_CALL(jint, SSL, fipsModeSet)(TCN_STDARGS, jint mode)
{
    UNREFERENCED(o);
    UNREFERENCED(mode);
    tcn_ThrowException(e, "FIPS was not available to tcnative at build time. You will need to re-build tcnative against an OpenSSL with FIPS.");
    return 0;
}

TCN_IMPLEMENT_CALL(jlong, SSL, newBIO)(TCN_STDARGS, jlong pool,
                                       jobject callback)
{
    UNREFERENCED_STDARGS;
    UNREFERENCED(pool);
    UNREFERENCED(callback);
    return 0;
}

TCN_IMPLEMENT_CALL(jlong, SSL, newMemBIO)(TCN_STDARGS)
{
    UNREFERENCED_STDARGS;
    return 0;
}

TCN_IMPLEMENT_CALL(jint, SSL, closeBIO)(TCN_STDARGS, jlong bio)
{
    UNREFERENCED_STDARGS;
    UNREFERENCED(bio);
    return (jint)APR_ENOTIMPL;
}

TCN_IMPLEMENT_CALL(void, SSL, setPasswordCallback)(TCN_STDARGS,
                                                   jobject callback)
{
    UNREFERENCED_STDARGS;
    UNREFERENCED(callback);
}

TCN_IMPLEMENT_CALL(void, SSL, setPassword)(TCN_STDARGS, jstring password)
{
    UNREFERENCED_STDARGS;
    UNREFERENCED(password);
}

TCN_IMPLEMENT_CALL(jboolean, SSL, generateRSATempKey)(TCN_STDARGS, jint idx)
{
    UNREFERENCED_STDARGS;
    UNREFERENCED(idx);
    return JNI_FALSE;
}

TCN_IMPLEMENT_CALL(jboolean, SSL, loadDSATempKey)(TCN_STDARGS, jint idx,
                                                  jstring file)
{
    UNREFERENCED_STDARGS;
    UNREFERENCED(idx);
    UNREFERENCED(file);
    return JNI_FALSE;
}

TCN_IMPLEMENT_CALL(jstring, SSL, getLastError)(TCN_STDARGS)
{
    UNREFERENCED_STDARGS;
    return NULL;
}

TCN_IMPLEMENT_CALL(jboolean, SSL, hasOp)(TCN_STDARGS, jint op)
{
    UNREFERENCED_STDARGS;
    UNREFERENCED(op);
    return JNI_FALSE;
}

/*** Begin Twitter 1:1 API addition ***/
TCN_IMPLEMENT_CALL(jint, SSL, getLastErrorNumber)(TCN_STDARGS) {
  UNREFERENCED(o);
  tcn_ThrowException(e, "Not implemented");
  return 0;
}

TCN_IMPLEMENT_CALL(jlong, SSL, newSSL)(TCN_STDARGS, jlong ssl_ctx) {
  UNREFERENCED(o);
  UNREFERENCED(ssl_ctx);
  tcn_ThrowException(e, "Not implemented");
  return 0;
}

TCN_IMPLEMENT_CALL(void, SSL, setBIO)(TCN_STDARGS, jlong ssl, jlong rbio, jlong wbio) {
  UNREFERENCED(o);
  UNREFERENCED(ssl);
  UNREFERENCED(rbio);
  UNREFERENCED(wbio);
  tcn_ThrowException(e, "Not implemented");
}

TCN_IMPLEMENT_CALL(jint, SSL, pendingWrittenBytesInBIO)(TCN_STDARGS, jlong bio) {
  UNREFERENCED(o);
  UNREFERENCED(bio);
  tcn_ThrowException(e, "Not implemented");
  return 0;
}

TCN_IMPLEMENT_CALL(jint, SSL, pendingReadableBytesInSSL)(TCN_STDARGS, jlong ssl) {
  UNREFERENCED(o);
  UNREFERENCED(ssl);
  tcn_ThrowException(e, "Not implemented");
  return 0;
}

TCN_IMPLEMENT_CALL(jint, SSL, writeToBIO)(TCN_STDARGS, jlong bio, jlong wbuf, jint wlen) {
  UNREFERENCED(o);
  UNREFERENCED(bio);
  UNREFERENCED(wbuf);
  UNREFERENCED(wlen);
  tcn_ThrowException(e, "Not implemented");
  return 0;
}

TCN_IMPLEMENT_CALL(jint, SSL, readFromBIO)(TCN_STDARGS, jlong bio, jlong rbuf, jint rlen) {
  UNREFERENCED(o);
  UNREFERENCED(bio);
  UNREFERENCED(rbuf);
  UNREFERENCED(rlen);
  tcn_ThrowException(e, "Not implemented");
  return 0;
}

TCN_IMPLEMENT_CALL(jint, SSL, writeToSSL)(TCN_STDARGS, jlong ssl, jlong wbuf, jint wlen) {
  UNREFERENCED(o);
  UNREFERENCED(ssl);
  UNREFERENCED(wbuf);
  UNREFERENCED(wlen);
  tcn_ThrowException(e, "Not implemented");
  return 0;
}

TCN_IMPLEMENT_CALL(jint, SSL, readFromSSL)(TCN_STDARGS, jlong ssl, jlong rbuf, jint rlen) {
  UNREFERENCED(o);
  UNREFERENCED(ssl);
  UNREFERENCED(rbuf);
  UNREFERENCED(rlen);
  tcn_ThrowException(e, "Not implemented");
  return 0;
}

TCN_IMPLEMENT_CALL(jint, SSL, getShutdown)(TCN_STDARGS, jlong ssl) {
  UNREFERENCED(o);
  UNREFERENCED(ssl);
  tcn_ThrowException(e, "Not implemented");
  return 0;
}

TCN_IMPLEMENT_CALL(void, SSL, setShutdown)(TCN_STDARGS, jlong ssl, jint mode) {
  UNREFERENCED(o);
  UNREFERENCED(ssl);
  UNREFERENCED(mode);
  tcn_ThrowException(e, "Not implemented");
}

TCN_IMPLEMENT_CALL(void, SSL, freeSSL)(TCN_STDARGS, jlong ssl) {
  UNREFERENCED(o);
  UNREFERENCED(ssl);
  tcn_ThrowException(e, "Not implemented");
}

TCN_IMPLEMENT_CALL(jlong, SSL, makeNetworkBIO)(TCN_STDARGS, jlong ssl) {
  UNREFERENCED(o);
  UNREFERENCED(ssl);
  tcn_ThrowException(e, "Not implemented");
  return 0;
}

TCN_IMPLEMENT_CALL(void, SSL, freeBIO)(TCN_STDARGS, jlong bio) {
  UNREFERENCED(o);
  UNREFERENCED(bio);
  tcn_ThrowException(e, "Not implemented");
}

TCN_IMPLEMENT_CALL(jint, SSL, shutdownSSL)(TCN_STDARGS, jlong ssl) {
  UNREFERENCED(o);
  UNREFERENCED(ssl);
  tcn_ThrowException(e, "Not implemented");
  return 0;
}

TCN_IMPLEMENT_CALL(jstring, SSL, getCipherForSSL)(TCN_STDARGS, jlong ssl) {
  UNREFERENCED(o);
  UNREFERENCED(ssl);
  tcn_ThrowException(e, "Not implemented");
  return NULL;
}

TCN_IMPLEMENT_CALL(jint, SSL, isInInit)(TCN_STDARGS, jlong ssl) {
  UNREFERENCED(o);
  UNREFERENCED(ssl);
  tcn_ThrowException(e, "Not implemented");
  return 0;
}

TCN_IMPLEMENT_CALL(jint, SSL, doHandshake)(TCN_STDARGS, jlong ssl) {
  UNREFERENCED(o);
  UNREFERENCED(ssl);
  tcn_ThrowException(e, "Not implemented");
}

TCN_IMPLEMENT_CALL(jstring, SSL, getNextProtoNegotiated)(TCN_STDARGS, jlong ssl) {
  UNREFERENCED(o);
  UNREFERENCED(ssl);
  tcn_ThrowException(e, "Not implemented");
  return NULL;
}

/*** End Twitter 1:1 API addition ***/

/*** Begin Apple 1:1 API addition ***/

TCN_IMPLEMENT_CALL(jstring, SSL, getAlpnSelected)(TCN_STDARGS, jlong ssl) {
    UNREFERENCED(o);
    UNREFERENCED(ssl);
    tcn_ThrowException(e, "Not implemented");
    return NULL;
}

TCN_IMPLEMENT_CALL(jobjectArray, SSL, getPeerCertChain)(TCN_STDARGS, jlong ssl)
{
  UNREFERENCED(o);
  UNREFERENCED(ssl);
  tcn_ThrowException(e, "Not implemented");
  return NULL;
}

TCN_IMPLEMENT_CALL(jbyteArray, SSL, getPeerCertificate)(TCN_STDARGS, jlong ssl)
{
  UNREFERENCED(o);
  UNREFERENCED(ssl);
  tcn_ThrowException(e, "Not implemented");
  return NULL;
}

TCN_IMPLEMENT_CALL(jstring, SSL, getErrorString)(TCN_STDARGS, jlong number)
{
  UNREFERENCED(o);
  tcn_ThrowException(e, "Not implemented");
  return NULL;
}

TCN_IMPLEMENT_CALL(jstring, SSL, getVersion)(TCN_STDARGS, jlong ssl)
{
  UNREFERENCED(o);
  UNREFERENCED(ssl);
  tcn_ThrowException(e, "Not implemented");
  return NULL;
}

TCN_IMPLEMENT_CALL(jlong, SSL, getTime)(TCN_STDARGS, jlong ssl)
{
  UNREFERENCED(o);
  UNREFERENCED(ssl);
  tcn_ThrowException(e, "Not implemented");
  return 0;
}

TCN_IMPLEMENT_CALL(jlong, SSL, getTimeout)(TCN_STDARGS, jlong ssl)
{
  UNREFERENCED(o);
  UNREFERENCED(ssl);
  tcn_ThrowException(e, "Not implemented");
  return 0;
}

TCN_IMPLEMENT_CALL(jlong, SSL, setTimeout)(TCN_STDARGS, jlong ssl, jlong seconds)
{
  UNREFERENCED(o);
  UNREFERENCED(ssl);
  UNREFERENCED(seconds);
  tcn_ThrowException(e, "Not implemented");
  return 0;
}

TCN_IMPLEMENT_CALL(void, SSL, setVerify)(TCN_STDARGS, jlong ssl,
                                                jint level, jint depth)
{
    UNREFERENCED(o);
    UNREFERENCED(ssl);
    tcn_ThrowException(e, "Not implemented");
}

TCN_IMPLEMENT_CALL(void, SSL, setOptions)(TCN_STDARGS, jlong ssl,
                                                 jint opt)
{
    UNREFERENCED_STDARGS;
    UNREFERENCED(ssl);
    UNREFERENCED(opt);
    tcn_ThrowException(e, "Not implemented");
}

TCN_IMPLEMENT_CALL(void, SSL, clearOptions)(TCN_STDARGS, jlong ssl,
                                                 jint opt)
{
    UNREFERENCED_STDARGS;
    UNREFERENCED(ssl);
    UNREFERENCED(opt);
    tcn_ThrowException(e, "Not implemented");
}

TCN_IMPLEMENT_CALL(jint, SSL, getOptions)(TCN_STDARGS, jlong ssl)
{
    UNREFERENCED_STDARGS;
    UNREFERENCED(ssl);
    tcn_ThrowException(e, "Not implemented");
    return 0;
}
TCN_IMPLEMENT_CALL(jobjectArray, SSL, getCiphers)(TCN_STDARGS, jlong ssl)
{
    UNREFERENCED_STDARGS;
    UNREFERENCED(ssl);
    tcn_ThrowException(e, "Not implemented");
    return 0;
}
TCN_IMPLEMENT_CALL(jboolean, SSL, setCipherSuites)(TCN_STDARGS, jlong ssl,
                                                         jstring ciphers)
{
    UNREFERENCED_STDARGS;
    UNREFERENCED(ssl);
    UNREFERENCED(ciphers);
    tcn_ThrowException(e, "Not implemented");
    return JNI_FALSE;
}
TCN_IMPLEMENT_CALL(jbyteArray, SSL, getSessionId)(TCN_STDARGS, jlong ssl)
{
    UNREFERENCED(o);
    UNREFERENCED(ssl);
    tcn_ThrowException(e, "Not implemented");
}
TCN_IMPLEMENT_CALL(jint, SSL, getHandshakeCount)(TCN_STDARGS, jlong ssl)
{
    UNREFERENCED(o);
    UNREFERENCED(ssl);
    tcn_ThrowException(e, "Not implemented");
}

TCN_IMPLEMENT_CALL(void, SSL, clearError)(TCN_STDARGS)
{
    UNREFERENCED(o);
    tcn_ThrowException(e, "Not implemented");
}

TCN_IMPLEMENT_CALL(jint, SSL, renegotiate)(TCN_STDARGS, jlong ssl) {
  UNREFERENCED(o);
  UNREFERENCED(ssl);
  tcn_ThrowException(e, "Not implemented");
}

TCN_IMPLEMENT_CALL(void, SSL, setState)(TCN_STDARGS, jlong ssl, jint state) {
  UNREFERENCED(o);
  UNREFERENCED(ssl);
  UNREFERENCED(state);
  tcn_ThrowException(e, "Not implemented");
}

TCN_IMPLEMENT_CALL(void, SSL, setTlsExtHostName)(TCN_STDARGS, jlong ssl, jstring hostname) {
  UNREFERENCED(o);
  UNREFERENCED(ssl);
  UNREFERENCED(hostname);
  tcn_ThrowException(e, "Not implemented");
}

TCN_IMPLEMENT_CALL(jobjectArray, SSL, authenticationMethods)(TCN_STDARGS, jlong ssl) {
  UNREFERENCED(o);
  UNREFERENCED(ssl);
  tcn_ThrowException(e, "Not implemented");
}


TCN_IMPLEMENT_CALL(long, SSL, parsePrivateKey)(TCN_STDARGS, jlong privateKeyBio, jstring password)
{
     UNREFERENCED(o);
     UNREFERENCED(privateKeyBio);
     UNREFERENCED(password);
     tcn_ThrowException(e, "Not implemented");
     return 0;
}

TCN_IMPLEMENT_CALL(void, SSL, freePrivateKey)(TCN_STDARGS, jlong privateKey)
{
     UNREFERENCED(o);
     UNREFERENCED(privateKey);
     tcn_ThrowException(e, "Not implemented");
}

TCN_IMPLEMENT_CALL(long, SSL, parseX509Chain)(TCN_STDARGS, jlong x509ChainBio)
{
     UNREFERENCED(o);
     UNREFERENCED(x509ChainBio);
     tcn_ThrowException(e, "Not implemented");
     return 0;
}

TCN_IMPLEMENT_CALL(void, SSL, freeX509Chain)(TCN_STDARGS, jlong x509Chain)
{
    UNREFERENCED(o);
    UNREFERENCED(x509Chain);
    tcn_ThrowException(e, "Not implemented");
}
/*** End Apple API Additions ***/
#endif
