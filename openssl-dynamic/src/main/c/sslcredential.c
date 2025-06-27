/*
 * Copyright 2025 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include <jni.h>
#include <stdint.h>
#include <string.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/err.h>

// SSL_CREDENTIAL is a BoringSSL-specific feature
#ifdef OPENSSL_IS_BORINGSSL
#include <openssl/ssl_credential.h>
#endif

#include "tcn.h"
#include "ssl_private.h"
#include "sslcredential.h"

#define SSLCREDENTIAL_CLASSNAME "io/netty/internal/tcnative/SSLCredential"

// Helper functions
#ifdef OPENSSL_IS_BORINGSSL
static void throw_openssl_error(JNIEnv* env, const char* msg) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    tcn_Throw(env, "%s: %s", msg, err_buf);
}
#endif

static void throw_unsupported_operation(JNIEnv* env, const char* operation) {
    jclass exceptionClass = (*env)->FindClass(env, "java/lang/UnsupportedOperationException");
    if (exceptionClass != NULL) {
        char message[256];
        snprintf(message, sizeof(message), 
                "%s is not supported. SSL_CREDENTIAL API is a BoringSSL-specific feature.", 
                operation);
        (*env)->ThrowNew(env, exceptionClass, message);
    }
}

// Core SSL_CREDENTIAL functions
JNIEXPORT jlong JNICALL Java_io_netty_internal_tcnative_SSLCredential_newX509(
    JNIEnv* env, jclass clazz) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* cred = SSL_CREDENTIAL_new_x509();
    TCN_CHECK_NULL(cred, credential, 0);
    return (jlong)(intptr_t)cred;
#else
    throw_unsupported_operation(env, "SSL_CREDENTIAL_new_x509");
    return 0;
#endif
}

JNIEXPORT void JNICALL Java_io_netty_internal_tcnative_SSLCredential_upRef(
    JNIEnv* env, jclass clazz, jlong cred) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, /* void */);
    SSL_CREDENTIAL_up_ref(c);
#else
    throw_unsupported_operation(env, "SSL_CREDENTIAL_up_ref");
#endif
}

JNIEXPORT void JNICALL Java_io_netty_internal_tcnative_SSLCredential_free(
    JNIEnv* env, jclass clazz, jlong cred) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    if (c != NULL) {
        SSL_CREDENTIAL_free(c);
    }
#else
    throw_unsupported_operation(env, "SSL_CREDENTIAL_free");
#endif
}

// SSL_CREDENTIAL configuration methods
JNIEXPORT jboolean JNICALL Java_io_netty_internal_tcnative_SSLCredential_setPrivateKey(
    JNIEnv* env, jclass clazz, jlong cred, jlong key) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    EVP_PKEY* pkey = (EVP_PKEY*)(intptr_t)key;
    
    TCN_CHECK_NULL(c, credential, JNI_FALSE);
    TCN_CHECK_NULL(pkey, privateKey, JNI_FALSE);

    if (SSL_CREDENTIAL_set1_private_key(c, pkey) == 0) {
        throw_openssl_error(env, "Failed to set private key");
        return JNI_FALSE;
    }
    return JNI_TRUE;
#else
    throw_unsupported_operation(env, "SSL_CREDENTIAL_set1_private_key");
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_io_netty_internal_tcnative_SSLCredential_setCertChain(
    JNIEnv* env, jclass clazz, jlong cred, jlongArray certs) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, JNI_FALSE);
    TCN_CHECK_NULL(certs, certificateArray, JNI_FALSE);

    jsize len = (*env)->GetArrayLength(env, certs);
    if (len == 0) {
        tcn_Throw(env, "Certificate array is empty");
        return JNI_FALSE;
    }

    CRYPTO_BUFFER** cert_buffers = OPENSSL_malloc(sizeof(CRYPTO_BUFFER*) * len);
    TCN_CHECK_NULL(cert_buffers, certificateBuffers, JNI_FALSE);

    jlong* certs_elems = (*env)->GetLongArrayElements(env, certs, NULL);
    if (certs_elems == NULL) {
        OPENSSL_free(cert_buffers);
        return JNI_FALSE;
    }

    for (jsize i = 0; i < len; i++) {
        cert_buffers[i] = (CRYPTO_BUFFER*)(intptr_t)certs_elems[i];
    }

    int result = SSL_CREDENTIAL_set1_cert_chain(c, cert_buffers, len);
    
    // Clean up
    (*env)->ReleaseLongArrayElements(env, certs, certs_elems, JNI_ABORT);
    OPENSSL_free(cert_buffers);

    if (result == 0) {
        throw_openssl_error(env, "Failed to set certificate chain");
        return JNI_FALSE;
    }
    return JNI_TRUE;
#else
    throw_unsupported_operation(env, "SSL_CREDENTIAL_set1_cert_chain");
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_io_netty_internal_tcnative_SSLCredential_setOcspResponse(
    JNIEnv* env, jclass clazz, jlong cred, jbyteArray ocsp) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, JNI_FALSE);
    TCN_CHECK_NULL(ocsp, ocspData, JNI_FALSE);

    jsize len = (*env)->GetArrayLength(env, ocsp);
    jbyte* ocsp_data = (*env)->GetByteArrayElements(env, ocsp, NULL);
    if (ocsp_data == NULL) {
        return JNI_FALSE;
    }

    CRYPTO_BUFFER* ocsp_buffer = CRYPTO_BUFFER_new((const uint8_t*)ocsp_data, len, NULL);
    (*env)->ReleaseByteArrayElements(env, ocsp, ocsp_data, JNI_ABORT);

    TCN_CHECK_NULL(ocsp_buffer, ocspBuffer, JNI_FALSE);

    int result = SSL_CREDENTIAL_set1_ocsp_response(c, ocsp_buffer);
    CRYPTO_BUFFER_free(ocsp_buffer);

    if (result == 0) {
        throw_openssl_error(env, "Failed to set OCSP response");
        return JNI_FALSE;
    }
    return JNI_TRUE;
#else
    throw_unsupported_operation(env, "SSL_CREDENTIAL_set1_ocsp_response");
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_io_netty_internal_tcnative_SSLCredential_setSigningAlgorithmPrefs(
    JNIEnv* env, jclass clazz, jlong cred, jintArray prefs) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, JNI_FALSE);
    TCN_CHECK_NULL(prefs, preferencesArray, JNI_FALSE);

    jsize len = (*env)->GetArrayLength(env, prefs);
    if (len == 0) {
        tcn_Throw(env, "Preferences array is empty");
        return JNI_FALSE;
    }

    uint16_t* native_prefs = OPENSSL_malloc(sizeof(uint16_t) * len);
    TCN_CHECK_NULL(native_prefs, signingAlgorithmPrefs, JNI_FALSE);

    jint* prefs_data = (*env)->GetIntArrayElements(env, prefs, NULL);
    if (prefs_data == NULL) {
        OPENSSL_free(native_prefs);
        return JNI_FALSE;
    }

    for (jsize i = 0; i < len; i++) {
        native_prefs[i] = (uint16_t)prefs_data[i];
    }

    int result = SSL_CREDENTIAL_set1_signing_algorithm_prefs(c, native_prefs, len);
    
    // Clean up
    (*env)->ReleaseIntArrayElements(env, prefs, prefs_data, JNI_ABORT);
    OPENSSL_free(native_prefs);

    if (result == 0) {
        throw_openssl_error(env, "Failed to set signing algorithm preferences");
        return JNI_FALSE;
    }
    return JNI_TRUE;
#else
    throw_unsupported_operation(env, "SSL_CREDENTIAL_set1_signing_algorithm_prefs");
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_io_netty_internal_tcnative_SSLCredential_setCertificateProperties(
    JNIEnv* env, jclass clazz, jlong cred, jbyteArray cert_props) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, JNI_FALSE);
    TCN_CHECK_NULL(cert_props, certificateProperties, JNI_FALSE);

    jsize len = (*env)->GetArrayLength(env, cert_props);
    jbyte* props_data = (*env)->GetByteArrayElements(env, cert_props, NULL);
    if (props_data == NULL) {
        return JNI_FALSE;
    }

    CRYPTO_BUFFER* props_buffer = CRYPTO_BUFFER_new((const uint8_t*)props_data, len, NULL);
    (*env)->ReleaseByteArrayElements(env, cert_props, props_data, JNI_ABORT);

    TCN_CHECK_NULL(props_buffer, certificatePropertiesBuffer, JNI_FALSE);

    int result = SSL_CREDENTIAL_set1_certificate_properties(c, props_buffer);
    CRYPTO_BUFFER_free(props_buffer);

    if (result == 0) {
        throw_openssl_error(env, "Failed to set certificate properties");
        return JNI_FALSE;
    }
    return JNI_TRUE;
#else
    throw_unsupported_operation(env, "SSL_CREDENTIAL_set1_certificate_properties");
    return JNI_FALSE;
#endif
}

JNIEXPORT jboolean JNICALL Java_io_netty_internal_tcnative_SSLCredential_setSignedCertTimestampList(
    JNIEnv* env, jclass clazz, jlong cred, jbyteArray sct_list) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, JNI_FALSE);
    TCN_CHECK_NULL(sct_list, sctList, JNI_FALSE);

    jsize len = (*env)->GetArrayLength(env, sct_list);
    jbyte* sct_data = (*env)->GetByteArrayElements(env, sct_list, NULL);
    if (sct_data == NULL) {
        return JNI_FALSE;
    }

    CRYPTO_BUFFER* sct_buffer = CRYPTO_BUFFER_new((const uint8_t*)sct_data, len, NULL);
    (*env)->ReleaseByteArrayElements(env, sct_list, sct_data, JNI_ABORT);

    TCN_CHECK_NULL(sct_buffer, sctBuffer, JNI_FALSE);

    int result = SSL_CREDENTIAL_set1_signed_cert_timestamp_list(c, sct_buffer);
    CRYPTO_BUFFER_free(sct_buffer);

    if (result == 0) {
        throw_openssl_error(env, "Failed to set signed certificate timestamp list");
        return JNI_FALSE;
    }
    return JNI_TRUE;
#else
    throw_unsupported_operation(env, "SSL_CREDENTIAL_set1_signed_cert_timestamp_list");
    return JNI_FALSE;
#endif
}

JNIEXPORT void JNICALL Java_io_netty_internal_tcnative_SSLCredential_setMustMatchIssuer(
    JNIEnv* env, jclass clazz, jlong cred, jboolean match) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, /* void */);
    SSL_CREDENTIAL_set_must_match_issuer(c, match == JNI_TRUE ? 1 : 0);
#else
    throw_unsupported_operation(env, "SSL_CREDENTIAL_set_must_match_issuer");
#endif
}

// Private key methods
JNIEXPORT jint JNICALL Java_io_netty_internal_tcnative_SSLCredential_setPrivateKeyMethod(
    JNIEnv* env, jclass clazz, jlong cred, jlong method) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    const SSL_PRIVATE_KEY_METHOD* m = (const SSL_PRIVATE_KEY_METHOD*)(intptr_t)method;
    
    TCN_CHECK_NULL(c, credential, 0);
    TCN_CHECK_NULL(m, privateKeyMethod, 0);

    return SSL_CREDENTIAL_set_private_key_method(c, m);
#else
    throw_unsupported_operation(env, "SSL_CREDENTIAL_set_private_key_method");
    return 0;
#endif
}

// Trust anchor configuration
JNIEXPORT jint JNICALL Java_io_netty_internal_tcnative_SSLCredential_setTrustAnchorId(
    JNIEnv* env, jclass clazz, jlong cred, jbyteArray id) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, 0);
    TCN_CHECK_NULL(id, trustAnchorId, 0);

    jsize len = (*env)->GetArrayLength(env, id);
    jbyte* id_data = (*env)->GetByteArrayElements(env, id, NULL);
    if (id_data == NULL) {
        return 0;
    }

    int result = SSL_CREDENTIAL_set1_trust_anchor_id(c, (const uint8_t*)id_data, len);
    (*env)->ReleaseByteArrayElements(env, id, id_data, JNI_ABORT);

    if (result == 0) {
        throw_openssl_error(env, "Failed to set trust anchor ID");
        return 0;
    }
    return 1;
#else
    throw_unsupported_operation(env, "SSL_CREDENTIAL_set1_trust_anchor_id");
    return 0;
#endif
}

// Ex data support
JNIEXPORT jint JNICALL Java_io_netty_internal_tcnative_SSLCredential_setExData(
    JNIEnv* env, jclass clazz, jlong cred, jint idx, jlong arg) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, 0);
    return SSL_CREDENTIAL_set_ex_data(c, idx, (void*)(intptr_t)arg);
#else
    throw_unsupported_operation(env, "SSL_CREDENTIAL_set_ex_data");
    return 0;
#endif
}

JNIEXPORT jlong JNICALL Java_io_netty_internal_tcnative_SSLCredential_getExData(
    JNIEnv* env, jclass clazz, jlong cred, jint idx) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, 0);
    return (jlong)(intptr_t)SSL_CREDENTIAL_get_ex_data(c, idx);
#else
    throw_unsupported_operation(env, "SSL_CREDENTIAL_get_ex_data");
    return 0;
#endif
}

JNIEXPORT jint JNICALL Java_io_netty_internal_tcnative_SSLCredential_getExNewIndex(
    JNIEnv* env, jclass clazz, jlong argl, jlong argp, jlong free_func) {
    throw_unsupported_operation(env, "SSL_CREDENTIAL_get_ex_new_index");
    return 0;
}

// Delegated credentials
JNIEXPORT jlong JNICALL Java_io_netty_internal_tcnative_SSLCredential_newDelegated(
    JNIEnv* env, jclass clazz) {
    throw_unsupported_operation(env, "SSL_CREDENTIAL_new_delegated");
    return 0;
}

JNIEXPORT jint JNICALL Java_io_netty_internal_tcnative_SSLCredential_setDelegatedCredential(
    JNIEnv* env, jclass clazz, jlong cred, jbyteArray dc) {
    throw_unsupported_operation(env, "SSL_CREDENTIAL_set1_delegated_credential");
    return 0;
}

// SPAKE2+ support
JNIEXPORT jlong JNICALL Java_io_netty_internal_tcnative_SSLCredential_newSpake2PlusV1Client(
    JNIEnv* env, jclass clazz, jbyteArray identity, jbyteArray password) {
    throw_unsupported_operation(env, "SSL_CREDENTIAL_new_spake2plusv1_client");
    return 0;
}

JNIEXPORT jlong JNICALL Java_io_netty_internal_tcnative_SSLCredential_newSpake2PlusV1Server(
    JNIEnv* env, jclass clazz, jbyteArray identity, jbyteArray password) {
    throw_unsupported_operation(env, "SSL_CREDENTIAL_new_spake2plusv1_server");
    return 0;
}

// JNI Method Registration Table
static const JNINativeMethod methods[] = {
    // Core functions
    { "newX509", "()J", (void*)Java_io_netty_internal_tcnative_SSLCredential_newX509 },
    { "upRef", "(J)V", (void*)Java_io_netty_internal_tcnative_SSLCredential_upRef },
    { "free", "(J)V", (void*)Java_io_netty_internal_tcnative_SSLCredential_free },
    
    // Configuration
    { "setPrivateKey", "(JJ)Z", (void*)Java_io_netty_internal_tcnative_SSLCredential_setPrivateKey },
    { "setCertChain", "(J[J)Z", (void*)Java_io_netty_internal_tcnative_SSLCredential_setCertChain },
    { "setOcspResponse", "(J[B)Z", (void*)Java_io_netty_internal_tcnative_SSLCredential_setOcspResponse },
    { "setSigningAlgorithmPrefs", "(J[I)Z", (void*)Java_io_netty_internal_tcnative_SSLCredential_setSigningAlgorithmPrefs },
    { "setCertificateProperties", "(J[B)Z", (void*)Java_io_netty_internal_tcnative_SSLCredential_setCertificateProperties },
    { "setSignedCertTimestampList", "(J[B)Z", (void*)Java_io_netty_internal_tcnative_SSLCredential_setSignedCertTimestampList },
    { "setMustMatchIssuer", "(JZ)V", (void*)Java_io_netty_internal_tcnative_SSLCredential_setMustMatchIssuer },
    
    // Private key methods
    { "setPrivateKeyMethod", "(JJ)I", (void*)Java_io_netty_internal_tcnative_SSLCredential_setPrivateKeyMethod },
    
    // Trust anchor configuration
    { "setTrustAnchorId", "(J[B)I", (void*)Java_io_netty_internal_tcnative_SSLCredential_setTrustAnchorId },
    
    // Ex data support
    { "setExData", "(JIJ)I", (void*)Java_io_netty_internal_tcnative_SSLCredential_setExData },
    { "getExData", "(JI)J", (void*)Java_io_netty_internal_tcnative_SSLCredential_getExData },
    { "getExNewIndex", "(JJJ)I", (void*)Java_io_netty_internal_tcnative_SSLCredential_getExNewIndex },
    
    // Delegated credentials
    { "newDelegated", "()J", (void*)Java_io_netty_internal_tcnative_SSLCredential_newDelegated },
    { "setDelegatedCredential", "(J[B)I", (void*)Java_io_netty_internal_tcnative_SSLCredential_setDelegatedCredential },

    // SPAKE2+ support
    { "newSpake2PlusV1Client", "([B[B)J", (void*)Java_io_netty_internal_tcnative_SSLCredential_newSpake2PlusV1Client },
    { "newSpake2PlusV1Server", "([B[B)J", (void*)Java_io_netty_internal_tcnative_SSLCredential_newSpake2PlusV1Server },
};

// JNI registration functions
JNIEXPORT jint JNICALL netty_internal_tcnative_SSLCREDENTIAL_JNI_OnLoad(
    JNIEnv* env, const char* packagePrefix) {
    return netty_jni_util_register_natives(env, packagePrefix, SSLCREDENTIAL_CLASSNAME, methods, sizeof(methods) / sizeof(methods[0]));
}

JNIEXPORT void JNICALL netty_internal_tcnative_SSLCREDENTIAL_JNI_OnUnLoad(
    JNIEnv* env, const char* packagePrefix) {
    netty_jni_util_unregister_natives(env, packagePrefix, SSLCREDENTIAL_CLASSNAME);
}
