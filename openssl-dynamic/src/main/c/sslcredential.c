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

// SSL_CREDENTIAL is a BoringSSL-specific feature
#ifdef OPENSSL_IS_BORINGSSL

// Helper function to throw OpenSSL errors with context
static void throw_openssl_error(JNIEnv* env, const char* msg) {
    unsigned long err = ERR_get_error();
    char err_buf[256];
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    tcn_Throw(env, "%s: %s", msg, err_buf);
}

// Core SSL_CREDENTIAL functions
JNIEXPORT jlong JNICALL Java_io_netty_internal_tcnative_SSLCredential_newX509(
    JNIEnv* env, jclass clazz) {
    SSL_CREDENTIAL* cred = SSL_CREDENTIAL_new_x509();
    if (cred == NULL) {
        throw_openssl_error(env, "Failed to create SSL_CREDENTIAL");
        return 0;
    }
    return (jlong)(intptr_t)cred;
}

JNIEXPORT void JNICALL Java_io_netty_internal_tcnative_SSLCredential_upRef(
    JNIEnv* env, jclass clazz, jlong cred) {
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    if (c == NULL) {
        tcn_Throw(env, "SSL_CREDENTIAL pointer is null");
        return;
    }
    SSL_CREDENTIAL_up_ref(c);
}

JNIEXPORT void JNICALL Java_io_netty_internal_tcnative_SSLCredential_free(
    JNIEnv* env, jclass clazz, jlong cred) {
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    if (c != NULL) {
        SSL_CREDENTIAL_free(c);
    }
}

// SSL_CREDENTIAL configuration methods
JNIEXPORT jboolean JNICALL Java_io_netty_internal_tcnative_SSLCredential_setPrivateKey(
    JNIEnv* env, jclass clazz, jlong cred, jlong key) {
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    EVP_PKEY* pkey = (EVP_PKEY*)(intptr_t)key;
    
    if (c == NULL || pkey == NULL) {
        tcn_Throw(env, "SSL_CREDENTIAL or EVP_PKEY pointer is null");
        return JNI_FALSE;
    }

    if (SSL_CREDENTIAL_set1_private_key(c, pkey) == 0) {
        throw_openssl_error(env, "Failed to set private key");
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

JNIEXPORT jboolean JNICALL Java_io_netty_internal_tcnative_SSLCredential_setCertChain(
    JNIEnv* env, jclass clazz, jlong cred, jlongArray certs) {
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    if (c == NULL) {
        tcn_Throw(env, "SSL_CREDENTIAL pointer is null");
        return JNI_FALSE;
    }

    if (certs == NULL) {
        tcn_Throw(env, "Certificate array is null");
        return JNI_FALSE;
    }

    jsize len = (*env)->GetArrayLength(env, certs);
    if (len == 0) {
        tcn_Throw(env, "Certificate array is empty");
        return JNI_FALSE;
    }

    CRYPTO_BUFFER** cert_buffers = OPENSSL_malloc(sizeof(CRYPTO_BUFFER*) * len);
    if (cert_buffers == NULL) {
        tcn_Throw(env, "Failed to allocate memory for certificate chain");
        return JNI_FALSE;
    }

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
}

JNIEXPORT jboolean JNICALL Java_io_netty_internal_tcnative_SSLCredential_setOcspResponse(
    JNIEnv* env, jclass clazz, jlong cred, jbyteArray ocsp) {
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    if (c == NULL) {
        tcn_Throw(env, "SSL_CREDENTIAL pointer is null");
        return JNI_FALSE;
    }

    if (ocsp == NULL) {
        tcn_Throw(env, "OCSP data is null");
        return JNI_FALSE;
    }

    jsize len = (*env)->GetArrayLength(env, ocsp);
    jbyte* ocsp_data = (*env)->GetByteArrayElements(env, ocsp, NULL);
    if (ocsp_data == NULL) {
        return JNI_FALSE;
    }

    CRYPTO_BUFFER* ocsp_buffer = CRYPTO_BUFFER_new((const uint8_t*)ocsp_data, len, NULL);
    (*env)->ReleaseByteArrayElements(env, ocsp, ocsp_data, JNI_ABORT);

    if (ocsp_buffer == NULL) {
        tcn_Throw(env, "Failed to create OCSP buffer");
        return JNI_FALSE;
    }

    int result = SSL_CREDENTIAL_set1_ocsp_response(c, ocsp_buffer);
    CRYPTO_BUFFER_free(ocsp_buffer);

    if (result == 0) {
        throw_openssl_error(env, "Failed to set OCSP response");
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

JNIEXPORT jboolean JNICALL Java_io_netty_internal_tcnative_SSLCredential_setSigningAlgorithmPrefs(
    JNIEnv* env, jclass clazz, jlong cred, jintArray prefs) {
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    if (c == NULL) {
        tcn_Throw(env, "SSL_CREDENTIAL pointer is null");
        return JNI_FALSE;
    }

    if (prefs == NULL) {
        tcn_Throw(env, "Preferences array is null");
        return JNI_FALSE;
    }

    jsize len = (*env)->GetArrayLength(env, prefs);
    if (len == 0) {
        tcn_Throw(env, "Preferences array is empty");
        return JNI_FALSE;
    }

    uint16_t* native_prefs = OPENSSL_malloc(sizeof(uint16_t) * len);
    if (native_prefs == NULL) {
        tcn_Throw(env, "Failed to allocate memory for signing algorithm preferences");
        return JNI_FALSE;
    }

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
}

JNIEXPORT jboolean JNICALL Java_io_netty_internal_tcnative_SSLCredential_setCertificateProperties(
    JNIEnv* env, jclass clazz, jlong cred, jbyteArray cert_props) {
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    if (c == NULL) {
        tcn_Throw(env, "SSL_CREDENTIAL pointer is null");
        return JNI_FALSE;
    }

    if (cert_props == NULL) {
        tcn_Throw(env, "Certificate properties is null");
        return JNI_FALSE;
    }

    jsize len = (*env)->GetArrayLength(env, cert_props);
    jbyte* props_data = (*env)->GetByteArrayElements(env, cert_props, NULL);
    if (props_data == NULL) {
        return JNI_FALSE;
    }

    CRYPTO_BUFFER* props_buffer = CRYPTO_BUFFER_new((const uint8_t*)props_data, len, NULL);
    (*env)->ReleaseByteArrayElements(env, cert_props, props_data, JNI_ABORT);

    if (props_buffer == NULL) {
        tcn_Throw(env, "Failed to create certificate properties buffer");
        return JNI_FALSE;
    }

    int result = SSL_CREDENTIAL_set1_certificate_properties(c, props_buffer);
    CRYPTO_BUFFER_free(props_buffer);

    if (result == 0) {
        throw_openssl_error(env, "Failed to set certificate properties");
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

JNIEXPORT jboolean JNICALL Java_io_netty_internal_tcnative_SSLCredential_setSignedCertTimestampList(
    JNIEnv* env, jclass clazz, jlong cred, jbyteArray sct_list) {
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    if (c == NULL) {
        tcn_Throw(env, "SSL_CREDENTIAL pointer is null");
        return JNI_FALSE;
    }

    if (sct_list == NULL) {
        tcn_Throw(env, "SCT list is null");
        return JNI_FALSE;
    }

    jsize len = (*env)->GetArrayLength(env, sct_list);
    jbyte* sct_data = (*env)->GetByteArrayElements(env, sct_list, NULL);
    if (sct_data == NULL) {
        return JNI_FALSE;
    }

    CRYPTO_BUFFER* sct_buffer = CRYPTO_BUFFER_new((const uint8_t*)sct_data, len, NULL);
    (*env)->ReleaseByteArrayElements(env, sct_list, sct_data, JNI_ABORT);

    if (sct_buffer == NULL) {
        tcn_Throw(env, "Failed to create SCT buffer");
        return JNI_FALSE;
    }

    int result = SSL_CREDENTIAL_set1_signed_cert_timestamp_list(c, sct_buffer);
    CRYPTO_BUFFER_free(sct_buffer);

    if (result == 0) {
        throw_openssl_error(env, "Failed to set signed certificate timestamp list");
        return JNI_FALSE;
    }
    return JNI_TRUE;
}

JNIEXPORT void JNICALL Java_io_netty_internal_tcnative_SSLCredential_setMustMatchIssuer(
    JNIEnv* env, jclass clazz, jlong cred, jboolean match) {
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    if (c == NULL) {
        tcn_Throw(env, "SSL_CREDENTIAL pointer is null");
        return;
    }
    SSL_CREDENTIAL_set_must_match_issuer(c, match == JNI_TRUE ? 1 : 0);
}

// Private key methods
JNIEXPORT jint JNICALL Java_io_netty_internal_tcnative_SSLCredential_setPrivateKeyMethod(
    JNIEnv* env, jclass clazz, jlong cred, jlong method) {
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    const SSL_PRIVATE_KEY_METHOD* m = (const SSL_PRIVATE_KEY_METHOD*)(intptr_t)method;
    
    if (c == NULL || m == NULL) {
        tcn_Throw(env, "SSL_CREDENTIAL or SSL_PRIVATE_KEY_METHOD pointer is null");
        return 0;
    }

    return SSL_CREDENTIAL_set_private_key_method(c, m);
}

// Trust anchor configuration
JNIEXPORT jint JNICALL Java_io_netty_internal_tcnative_SSLCredential_setTrustAnchorId(
    JNIEnv* env, jclass clazz, jlong cred, jbyteArray id) {
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    if (c == NULL) {
        tcn_Throw(env, "SSL_CREDENTIAL pointer is null");
        return 0;
    }

    if (id == NULL) {
        tcn_Throw(env, "Trust anchor ID is null");
        return 0;
    }

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
}

// Ex data support
JNIEXPORT jint JNICALL Java_io_netty_internal_tcnative_SSLCredential_setExData(
    JNIEnv* env, jclass clazz, jlong cred, jint idx, jlong arg) {
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    if (c == NULL) {
        tcn_Throw(env, "SSL_CREDENTIAL pointer is null");
        return 0;
    }
    return SSL_CREDENTIAL_set_ex_data(c, idx, (void*)(intptr_t)arg);
}

JNIEXPORT jlong JNICALL Java_io_netty_internal_tcnative_SSLCredential_getExData(
    JNIEnv* env, jclass clazz, jlong cred, jint idx) {
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    if (c == NULL) {
        tcn_Throw(env, "SSL_CREDENTIAL pointer is null");
        return 0;
    }
    return (jlong)(intptr_t)SSL_CREDENTIAL_get_ex_data(c, idx);
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

// JNI initialization
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

JNIEXPORT jint JNICALL netty_internal_tcnative_SSLCREDENTIAL_JNI_OnLoad(
    JNIEnv* env, const char* packagePrefix) {
    return netty_jni_util_register_natives(env, packagePrefix, SSLCREDENTIAL_CLASSNAME, methods, sizeof(methods) / sizeof(methods[0]));
}

JNIEXPORT void JNICALL netty_internal_tcnative_SSLCREDENTIAL_JNI_OnUnLoad(
    JNIEnv* env, const char* packagePrefix) {
    netty_jni_util_unregister_natives(env, packagePrefix, SSLCREDENTIAL_CLASSNAME);
}

#else // !OPENSSL_IS_BORINGSSL

// Stub implementations for non-BoringSSL builds
// These functions will throw UnsupportedOperationException when called

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

JNIEXPORT jlong JNICALL Java_io_netty_internal_tcnative_SSLCredential_newX509(
    JNIEnv* env, jclass clazz) {
    throw_unsupported_operation(env, "SSL_CREDENTIAL_new_x509");
    return 0;
}

JNIEXPORT void JNICALL Java_io_netty_internal_tcnative_SSLCredential_upRef(
    JNIEnv* env, jclass clazz, jlong cred) {
    throw_unsupported_operation(env, "SSL_CREDENTIAL_up_ref");
}

JNIEXPORT void JNICALL Java_io_netty_internal_tcnative_SSLCredential_free(
    JNIEnv* env, jclass clazz, jlong cred) {
    throw_unsupported_operation(env, "SSL_CREDENTIAL_free");
}

JNIEXPORT jboolean JNICALL Java_io_netty_internal_tcnative_SSLCredential_setPrivateKey(
    JNIEnv* env, jclass clazz, jlong cred, jlong key) {
    throw_unsupported_operation(env, "SSL_CREDENTIAL_set1_private_key");
    return JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_io_netty_internal_tcnative_SSLCredential_setCertChain(
    JNIEnv* env, jclass clazz, jlong cred, jlongArray certs) {
    throw_unsupported_operation(env, "SSL_CREDENTIAL_set1_cert_chain");
    return JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_io_netty_internal_tcnative_SSLCredential_setOcspResponse(
    JNIEnv* env, jclass clazz, jlong cred, jbyteArray ocsp) {
    throw_unsupported_operation(env, "SSL_CREDENTIAL_set1_ocsp_response");
    return JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_io_netty_internal_tcnative_SSLCredential_setSigningAlgorithmPrefs(
    JNIEnv* env, jclass clazz, jlong cred, jintArray prefs) {
    throw_unsupported_operation(env, "SSL_CREDENTIAL_set1_signing_algorithm_prefs");
    return JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_io_netty_internal_tcnative_SSLCredential_setCertificateProperties(
    JNIEnv* env, jclass clazz, jlong cred, jbyteArray cert_props) {
    throw_unsupported_operation(env, "SSL_CREDENTIAL_set1_certificate_properties");
    return JNI_FALSE;
}

JNIEXPORT jboolean JNICALL Java_io_netty_internal_tcnative_SSLCredential_setSignedCertTimestampList(
    JNIEnv* env, jclass clazz, jlong cred, jbyteArray sct_list) {
    throw_unsupported_operation(env, "SSL_CREDENTIAL_set1_signed_cert_timestamp_list");
    return JNI_FALSE;
}

JNIEXPORT void JNICALL Java_io_netty_internal_tcnative_SSLCredential_setMustMatchIssuer(
    JNIEnv* env, jclass clazz, jlong cred, jboolean match) {
    throw_unsupported_operation(env, "SSL_CREDENTIAL_set_must_match_issuer");
}

JNIEXPORT jint JNICALL Java_io_netty_internal_tcnative_SSLCredential_setPrivateKeyMethod(
    JNIEnv* env, jclass clazz, jlong cred, jlong method) {
    throw_unsupported_operation(env, "SSL_CREDENTIAL_set_private_key_method");
    return 0;
}

JNIEXPORT jint JNICALL Java_io_netty_internal_tcnative_SSLCredential_setTrustAnchorId(
    JNIEnv* env, jclass clazz, jlong cred, jbyteArray id) {
    throw_unsupported_operation(env, "SSL_CREDENTIAL_set1_trust_anchor_id");
    return 0;
}

JNIEXPORT jint JNICALL Java_io_netty_internal_tcnative_SSLCredential_setExData(
    JNIEnv* env, jclass clazz, jlong cred, jint idx, jlong arg) {
    throw_unsupported_operation(env, "SSL_CREDENTIAL_set_ex_data");
    return 0;
}

JNIEXPORT jlong JNICALL Java_io_netty_internal_tcnative_SSLCredential_getExData(
    JNIEnv* env, jclass clazz, jlong cred, jint idx) {
    throw_unsupported_operation(env, "SSL_CREDENTIAL_get_ex_data");
    return 0;
}

JNIEXPORT jint JNICALL Java_io_netty_internal_tcnative_SSLCredential_getExNewIndex(
    JNIEnv* env, jclass clazz, jlong argl, jlong argp, jlong free_func) {
    throw_unsupported_operation(env, "SSL_CREDENTIAL_get_ex_new_index");
    return 0;
}

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

// JNI registration for non-BoringSSL builds
static const JNINativeMethod methods[] = {
    { "newX509", "()J", (void*)Java_io_netty_internal_tcnative_SSLCredential_newX509 },
    { "upRef", "(J)V", (void*)Java_io_netty_internal_tcnative_SSLCredential_upRef },
    { "free", "(J)V", (void*)Java_io_netty_internal_tcnative_SSLCredential_free },
    { "setPrivateKey", "(JJ)Z", (void*)Java_io_netty_internal_tcnative_SSLCredential_setPrivateKey },
    { "setCertChain", "(J[J)Z", (void*)Java_io_netty_internal_tcnative_SSLCredential_setCertChain },
    { "setOcspResponse", "(J[B)Z", (void*)Java_io_netty_internal_tcnative_SSLCredential_setOcspResponse },
    { "setSigningAlgorithmPrefs", "(J[I)Z", (void*)Java_io_netty_internal_tcnative_SSLCredential_setSigningAlgorithmPrefs },
    { "setCertificateProperties", "(J[B)Z", (void*)Java_io_netty_internal_tcnative_SSLCredential_setCertificateProperties },
    { "setSignedCertTimestampList", "(J[B)Z", (void*)Java_io_netty_internal_tcnative_SSLCredential_setSignedCertTimestampList },
    { "setMustMatchIssuer", "(JZ)V", (void*)Java_io_netty_internal_tcnative_SSLCredential_setMustMatchIssuer },
    { "setPrivateKeyMethod", "(JJ)I", (void*)Java_io_netty_internal_tcnative_SSLCredential_setPrivateKeyMethod },
    { "setTrustAnchorId", "(J[B)I", (void*)Java_io_netty_internal_tcnative_SSLCredential_setTrustAnchorId },
    { "setExData", "(JIJ)I", (void*)Java_io_netty_internal_tcnative_SSLCredential_setExData },
    { "getExData", "(JI)J", (void*)Java_io_netty_internal_tcnative_SSLCredential_getExData },
    { "getExNewIndex", "(JJJ)I", (void*)Java_io_netty_internal_tcnative_SSLCredential_getExNewIndex },
    { "newDelegated", "()J", (void*)Java_io_netty_internal_tcnative_SSLCredential_newDelegated },
    { "setDelegatedCredential", "(J[B)I", (void*)Java_io_netty_internal_tcnative_SSLCredential_setDelegatedCredential },
    { "newSpake2PlusV1Client", "([B[B)J", (void*)Java_io_netty_internal_tcnative_SSLCredential_newSpake2PlusV1Client },
    { "newSpake2PlusV1Server", "([B[B)J", (void*)Java_io_netty_internal_tcnative_SSLCredential_newSpake2PlusV1Server },
};

JNIEXPORT jint JNICALL netty_internal_tcnative_SSLCREDENTIAL_JNI_OnLoad(
    JNIEnv* env, const char* packagePrefix) {
    return netty_jni_util_register_natives(env, packagePrefix, SSLCREDENTIAL_CLASSNAME, methods, sizeof(methods) / sizeof(methods[0]));
}

JNIEXPORT void JNICALL netty_internal_tcnative_SSLCREDENTIAL_JNI_OnUnLoad(
    JNIEnv* env, const char* packagePrefix) {
    netty_jni_util_unregister_natives(env, packagePrefix, SSLCREDENTIAL_CLASSNAME);
}

#endif // OPENSSL_IS_BORINGSSL
