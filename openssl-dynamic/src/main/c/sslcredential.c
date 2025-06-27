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
TCN_IMPLEMENT_CALL(jlong, SSLCredential, newX509)(TCN_STDARGS) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* cred = SSL_CREDENTIAL_new_x509();
    TCN_CHECK_NULL(cred, credential, 0);
    return (jlong)(intptr_t)cred;
#else
    throw_unsupported_operation(e, "SSL_CREDENTIAL_new_x509");
    return 0;
#endif
}

TCN_IMPLEMENT_CALL(void, SSLCredential, upRef)(TCN_STDARGS, jlong cred) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, /* void */);
    SSL_CREDENTIAL_up_ref(c);
#else
    throw_unsupported_operation(e, "SSL_CREDENTIAL_up_ref");
#endif
}

TCN_IMPLEMENT_CALL(void, SSLCredential, free)(TCN_STDARGS, jlong cred) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    if (c != NULL) {
        SSL_CREDENTIAL_free(c);
    }
#else
    throw_unsupported_operation(e, "SSL_CREDENTIAL_free");
#endif
}

// SSL_CREDENTIAL configuration methods
TCN_IMPLEMENT_CALL(jboolean, SSLCredential, setPrivateKey)(TCN_STDARGS, jlong cred, jlong key) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    EVP_PKEY* pkey = (EVP_PKEY*)(intptr_t)key;
    
    TCN_CHECK_NULL(c, credential, JNI_FALSE);
    TCN_CHECK_NULL(pkey, privateKey, JNI_FALSE);

    if (SSL_CREDENTIAL_set1_private_key(c, pkey) == 0) {
        throw_openssl_error(e, "Failed to set private key");
        return JNI_FALSE;
    }
    return JNI_TRUE;
#else
    throw_unsupported_operation(e, "SSL_CREDENTIAL_set1_private_key");
    return JNI_FALSE;
#endif
}

TCN_IMPLEMENT_CALL(jboolean, SSLCredential, setCertChain)(TCN_STDARGS, jlong cred, jlongArray certs) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, JNI_FALSE);
    TCN_CHECK_NULL(certs, certificateArray, JNI_FALSE);

    jsize len = (*e)->GetArrayLength(e, certs);
    if (len == 0) {
        tcn_Throw(e, "Certificate array is empty");
        return JNI_FALSE;
    }

    CRYPTO_BUFFER** cert_buffers = OPENSSL_malloc(sizeof(CRYPTO_BUFFER*) * len);
    TCN_CHECK_NULL(cert_buffers, certificateBuffers, JNI_FALSE);

    jlong* certs_elems = (*e)->GetLongArrayElements(e, certs, NULL);
    if (certs_elems == NULL) {
        OPENSSL_free(cert_buffers);
        return JNI_FALSE;
    }

    for (jsize i = 0; i < len; i++) {
        cert_buffers[i] = (CRYPTO_BUFFER*)(intptr_t)certs_elems[i];
    }

    int result = SSL_CREDENTIAL_set1_cert_chain(c, cert_buffers, len);
    
    // Clean up
    (*e)->ReleaseLongArrayElements(e, certs, certs_elems, JNI_ABORT);
    OPENSSL_free(cert_buffers);

    if (result == 0) {
        throw_openssl_error(e, "Failed to set certificate chain");
        return JNI_FALSE;
    }
    return JNI_TRUE;
#else
    throw_unsupported_operation(e, "SSL_CREDENTIAL_set1_cert_chain");
    return JNI_FALSE;
#endif
}

TCN_IMPLEMENT_CALL(jboolean, SSLCredential, setOcspResponse)(TCN_STDARGS, jlong cred, jbyteArray ocsp) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, JNI_FALSE);
    TCN_CHECK_NULL(ocsp, ocspData, JNI_FALSE);

    jsize len = (*e)->GetArrayLength(e, ocsp);
    jbyte* ocsp_data = (*e)->GetByteArrayElements(e, ocsp, NULL);
    if (ocsp_data == NULL) {
        return JNI_FALSE;
    }

    CRYPTO_BUFFER* ocsp_buffer = CRYPTO_BUFFER_new((const uint8_t*)ocsp_data, len, NULL);
    (*e)->ReleaseByteArrayElements(e, ocsp, ocsp_data, JNI_ABORT);

    TCN_CHECK_NULL(ocsp_buffer, ocspBuffer, JNI_FALSE);

    int result = SSL_CREDENTIAL_set1_ocsp_response(c, ocsp_buffer);
    CRYPTO_BUFFER_free(ocsp_buffer);

    if (result == 0) {
        throw_openssl_error(e, "Failed to set OCSP response");
        return JNI_FALSE;
    }
    return JNI_TRUE;
#else
    throw_unsupported_operation(e, "SSL_CREDENTIAL_set1_ocsp_response");
    return JNI_FALSE;
#endif
}

TCN_IMPLEMENT_CALL(jboolean, SSLCredential, setSigningAlgorithmPrefs)(TCN_STDARGS, jlong cred, jintArray prefs) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, JNI_FALSE);
    TCN_CHECK_NULL(prefs, preferencesArray, JNI_FALSE);

    jsize len = (*e)->GetArrayLength(e, prefs);
    if (len == 0) {
        tcn_Throw(e, "Preferences array is empty");
        return JNI_FALSE;
    }

    uint16_t* native_prefs = OPENSSL_malloc(sizeof(uint16_t) * len);
    TCN_CHECK_NULL(native_prefs, signingAlgorithmPrefs, JNI_FALSE);

    jint* prefs_data = (*e)->GetIntArrayElements(e, prefs, NULL);
    if (prefs_data == NULL) {
        OPENSSL_free(native_prefs);
        return JNI_FALSE;
    }

    for (jsize i = 0; i < len; i++) {
        native_prefs[i] = (uint16_t)prefs_data[i];
    }

    int result = SSL_CREDENTIAL_set1_signing_algorithm_prefs(c, native_prefs, len);
    
    // Clean up
    (*e)->ReleaseIntArrayElements(e, prefs, prefs_data, JNI_ABORT);
    OPENSSL_free(native_prefs);

    if (result == 0) {
        throw_openssl_error(e, "Failed to set signing algorithm preferences");
        return JNI_FALSE;
    }
    return JNI_TRUE;
#else
    throw_unsupported_operation(e, "SSL_CREDENTIAL_set1_signing_algorithm_prefs");
    return JNI_FALSE;
#endif
}

TCN_IMPLEMENT_CALL(jboolean, SSLCredential, setCertificateProperties)(TCN_STDARGS, jlong cred, jbyteArray cert_props) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, JNI_FALSE);
    TCN_CHECK_NULL(cert_props, certificateProperties, JNI_FALSE);

    jsize len = (*e)->GetArrayLength(e, cert_props);
    jbyte* props_data = (*e)->GetByteArrayElements(e, cert_props, NULL);
    if (props_data == NULL) {
        return JNI_FALSE;
    }

    CRYPTO_BUFFER* props_buffer = CRYPTO_BUFFER_new((const uint8_t*)props_data, len, NULL);
    (*e)->ReleaseByteArrayElements(e, cert_props, props_data, JNI_ABORT);

    TCN_CHECK_NULL(props_buffer, certificatePropertiesBuffer, JNI_FALSE);

    int result = SSL_CREDENTIAL_set1_certificate_properties(c, props_buffer);
    CRYPTO_BUFFER_free(props_buffer);

    if (result == 0) {
        throw_openssl_error(e, "Failed to set certificate properties");
        return JNI_FALSE;
    }
    return JNI_TRUE;
#else
    throw_unsupported_operation(e, "SSL_CREDENTIAL_set1_certificate_properties");
    return JNI_FALSE;
#endif
}

TCN_IMPLEMENT_CALL(jboolean, SSLCredential, setSignedCertTimestampList)(TCN_STDARGS, jlong cred, jbyteArray sct_list) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, JNI_FALSE);
    TCN_CHECK_NULL(sct_list, sctList, JNI_FALSE);

    jsize len = (*e)->GetArrayLength(e, sct_list);
    jbyte* sct_data = (*e)->GetByteArrayElements(e, sct_list, NULL);
    if (sct_data == NULL) {
        return JNI_FALSE;
    }

    CRYPTO_BUFFER* sct_buffer = CRYPTO_BUFFER_new((const uint8_t*)sct_data, len, NULL);
    (*e)->ReleaseByteArrayElements(e, sct_list, sct_data, JNI_ABORT);

    TCN_CHECK_NULL(sct_buffer, sctBuffer, JNI_FALSE);

    int result = SSL_CREDENTIAL_set1_signed_cert_timestamp_list(c, sct_buffer);
    CRYPTO_BUFFER_free(sct_buffer);

    if (result == 0) {
        throw_openssl_error(e, "Failed to set signed certificate timestamp list");
        return JNI_FALSE;
    }
    return JNI_TRUE;
#else
    throw_unsupported_operation(e, "SSL_CREDENTIAL_set1_signed_cert_timestamp_list");
    return JNI_FALSE;
#endif
}

TCN_IMPLEMENT_CALL(void, SSLCredential, setMustMatchIssuer)(TCN_STDARGS, jlong cred, jboolean match) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, /* void */);
    SSL_CREDENTIAL_set_must_match_issuer(c, match == JNI_TRUE ? 1 : 0);
#else
    throw_unsupported_operation(e, "SSL_CREDENTIAL_set_must_match_issuer");
#endif
}

// Private key methods
TCN_IMPLEMENT_CALL(jint, SSLCredential, setPrivateKeyMethod)(TCN_STDARGS, jlong cred, jlong method) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    const SSL_PRIVATE_KEY_METHOD* m = (const SSL_PRIVATE_KEY_METHOD*)(intptr_t)method;
    
    TCN_CHECK_NULL(c, credential, 0);
    TCN_CHECK_NULL(m, privateKeyMethod, 0);

    return SSL_CREDENTIAL_set_private_key_method(c, m);
#else
    throw_unsupported_operation(e, "SSL_CREDENTIAL_set_private_key_method");
    return 0;
#endif
}

// Trust anchor configuration
TCN_IMPLEMENT_CALL(jint, SSLCredential, setTrustAnchorId)(TCN_STDARGS, jlong cred, jbyteArray id) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, 0);
    TCN_CHECK_NULL(id, trustAnchorId, 0);

    jsize len = (*e)->GetArrayLength(e, id);
    jbyte* id_data = (*e)->GetByteArrayElements(e, id, NULL);
    if (id_data == NULL) {
        return 0;
    }

    int result = SSL_CREDENTIAL_set1_trust_anchor_id(c, (const uint8_t*)id_data, len);
    (*e)->ReleaseByteArrayElements(e, id, id_data, JNI_ABORT);

    if (result == 0) {
        throw_openssl_error(e, "Failed to set trust anchor ID");
        return 0;
    }
    return 1;
#else
    throw_unsupported_operation(e, "SSL_CREDENTIAL_set1_trust_anchor_id");
    return 0;
#endif
}

// Ex data support
TCN_IMPLEMENT_CALL(jint, SSLCredential, setExData)(TCN_STDARGS, jlong cred, jint idx, jlong arg) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, 0);
    return SSL_CREDENTIAL_set_ex_data(c, idx, (void*)(intptr_t)arg);
#else
    throw_unsupported_operation(e, "SSL_CREDENTIAL_set_ex_data");
    return 0;
#endif
}

TCN_IMPLEMENT_CALL(jlong, SSLCredential, getExData)(TCN_STDARGS, jlong cred, jint idx) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, 0);
    return (jlong)(intptr_t)SSL_CREDENTIAL_get_ex_data(c, idx);
#else
    throw_unsupported_operation(e, "SSL_CREDENTIAL_get_ex_data");
    return 0;
#endif
}

TCN_IMPLEMENT_CALL(jint, SSLCredential, getExNewIndex)(TCN_STDARGS, jlong argl, jlong argp, jlong free_func) {
    throw_unsupported_operation(e, "SSL_CREDENTIAL_get_ex_new_index");
    return 0;
}

// Delegated credentials
TCN_IMPLEMENT_CALL(jlong, SSLCredential, newDelegated)(TCN_STDARGS) {
    throw_unsupported_operation(e, "SSL_CREDENTIAL_new_delegated");
    return 0;
}

TCN_IMPLEMENT_CALL(jint, SSLCredential, setDelegatedCredential)(TCN_STDARGS, jlong cred, jbyteArray dc) {
    throw_unsupported_operation(e, "SSL_CREDENTIAL_set1_delegated_credential");
    return 0;
}

// SPAKE2+ support
TCN_IMPLEMENT_CALL(jlong, SSLCredential, newSpake2PlusV1Client)(TCN_STDARGS, jbyteArray identity, jbyteArray password) {
    throw_unsupported_operation(e, "SSL_CREDENTIAL_new_spake2plusv1_client");
    return 0;
}

TCN_IMPLEMENT_CALL(jlong, SSLCredential, newSpake2PlusV1Server)(TCN_STDARGS, jbyteArray identity, jbyteArray password) {
    throw_unsupported_operation(e, "SSL_CREDENTIAL_new_spake2plusv1_server");
    return 0;
}

// JNI Method Registration Table Begin
static const JNINativeMethod method_table[] = {
    // Core functions
    { TCN_METHOD_TABLE_ENTRY(newX509, ()J, SSLCredential) },
    { TCN_METHOD_TABLE_ENTRY(upRef, (J)V, SSLCredential) },
    { TCN_METHOD_TABLE_ENTRY(free, (J)V, SSLCredential) },
    
    // Configuration
    { TCN_METHOD_TABLE_ENTRY(setPrivateKey, (JJ)Z, SSLCredential) },
    { TCN_METHOD_TABLE_ENTRY(setCertChain, (J[J)Z, SSLCredential) },
    { TCN_METHOD_TABLE_ENTRY(setOcspResponse, (J[B)Z, SSLCredential) },
    { TCN_METHOD_TABLE_ENTRY(setSigningAlgorithmPrefs, (J[I)Z, SSLCredential) },
    { TCN_METHOD_TABLE_ENTRY(setCertificateProperties, (J[B)Z, SSLCredential) },
    { TCN_METHOD_TABLE_ENTRY(setSignedCertTimestampList, (J[B)Z, SSLCredential) },
    { TCN_METHOD_TABLE_ENTRY(setMustMatchIssuer, (JZ)V, SSLCredential) },
    
    // Private key methods
    { TCN_METHOD_TABLE_ENTRY(setPrivateKeyMethod, (JJ)I, SSLCredential) },
    
    // Trust anchor configuration
    { TCN_METHOD_TABLE_ENTRY(setTrustAnchorId, (J[B)I, SSLCredential) },
    
    // Ex data support
    { TCN_METHOD_TABLE_ENTRY(setExData, (JIJ)I, SSLCredential) },
    { TCN_METHOD_TABLE_ENTRY(getExData, (JI)J, SSLCredential) },
    { TCN_METHOD_TABLE_ENTRY(getExNewIndex, (JJJ)I, SSLCredential) },
    
    // Delegated credentials
    { TCN_METHOD_TABLE_ENTRY(newDelegated, ()J, SSLCredential) },
    { TCN_METHOD_TABLE_ENTRY(setDelegatedCredential, (J[B)I, SSLCredential) },

    // SPAKE2+ support
    { TCN_METHOD_TABLE_ENTRY(newSpake2PlusV1Client, ([B[B)J, SSLCredential) },
    { TCN_METHOD_TABLE_ENTRY(newSpake2PlusV1Server, ([B[B)J, SSLCredential) },
};

static const jint method_table_size = sizeof(method_table) / sizeof(method_table[0]);

// JNI Method Registration Table End

// IMPORTANT: If you add any NETTY_JNI_UTIL_LOAD_CLASS or NETTY_JNI_UTIL_FIND_CLASS calls you also need to update
//            Library to reflect that.
jint netty_internal_tcnative_SSLCredential_JNI_OnLoad(JNIEnv* env, const char* packagePrefix) {
    if (netty_jni_util_register_natives(env,
             packagePrefix,
             SSLCREDENTIAL_CLASSNAME,
             method_table, method_table_size) != 0) {
        return JNI_ERR;
    }
    return NETTY_JNI_UTIL_JNI_VERSION;
}

void netty_internal_tcnative_SSLCredential_JNI_OnUnLoad(JNIEnv* env, const char* packagePrefix) {
    netty_jni_util_unregister_natives(env, packagePrefix, SSLCREDENTIAL_CLASSNAME);
}
