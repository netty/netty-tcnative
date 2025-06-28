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


#include "tcn.h"
#include "ssl_private.h"
#include "sslcredential.h"

#define SSLCREDENTIAL_CLASSNAME "io/netty/internal/tcnative/SSLCredential"

// Helper functions
#ifdef OPENSSL_IS_BORINGSSL
static void throw_openssl_error(JNIEnv* env, const char* msg) {
    unsigned long err = ERR_get_error();
    char err_buf[ERR_LEN] = {0};
    ERR_error_string_n(err, err_buf, sizeof(err_buf));
    tcn_Throw(env, "%s: %s", msg, err_buf);
}
#endif

static void throw_unsupported_operation(JNIEnv* env, const char* operation) {
    jclass exceptionClass = (*env)->FindClass(env, "java/lang/UnsupportedOperationException");
    if (exceptionClass != NULL) {
        char message[ERR_LEN] = {0};
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
TCN_IMPLEMENT_CALL(void, SSLCredential, setPrivateKey)(TCN_STDARGS, jlong cred, jlong key) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    EVP_PKEY* pkey = (EVP_PKEY*)(intptr_t)key;
    
    TCN_CHECK_NULL(c, credential, /* void */);
    TCN_CHECK_NULL(pkey, privateKey, /* void */);

    if (SSL_CREDENTIAL_set1_private_key(c, pkey) == 0) {
        throw_openssl_error(e, "Failed to set private key");
    }
#else
    throw_unsupported_operation(e, "SSL_CREDENTIAL_set1_private_key");
#endif
}

TCN_IMPLEMENT_CALL(void, SSLCredential, setCertChain)(TCN_STDARGS, jlong cred, jlongArray certs) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, /* void */);
    TCN_CHECK_NULL(certs, certificateArray, /* void */);

    jsize len = (*e)->GetArrayLength(e, certs);
    if (len == 0) {
        tcn_Throw(e, "Certificate array is empty");
        return;
    }

    CRYPTO_BUFFER** cert_buffers = OPENSSL_malloc(sizeof(CRYPTO_BUFFER*) * len);
    TCN_CHECK_NULL(cert_buffers, certificateBuffers, /* void */);

    jlong* certs_elems = (*e)->GetLongArrayElements(e, certs, NULL);
    if (certs_elems == NULL) {
        OPENSSL_free(cert_buffers);
        return;
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
    }
#else
    throw_unsupported_operation(e, "SSL_CREDENTIAL_set1_cert_chain");
#endif
}

TCN_IMPLEMENT_CALL(void, SSLCredential, setOcspResponse)(TCN_STDARGS, jlong cred, jbyteArray ocsp) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, /* void */);
    TCN_CHECK_NULL(ocsp, ocspData, /* void */);

    jsize len = (*e)->GetArrayLength(e, ocsp);
    jbyte* ocsp_data = (*e)->GetByteArrayElements(e, ocsp, NULL);
    if (ocsp_data == NULL) {
        return;
    }

    CRYPTO_BUFFER* ocsp_buffer = CRYPTO_BUFFER_new((const uint8_t*)ocsp_data, len, NULL);
    (*e)->ReleaseByteArrayElements(e, ocsp, ocsp_data, JNI_ABORT);

    TCN_CHECK_NULL(ocsp_buffer, ocspBuffer, /* void */);

    int result = SSL_CREDENTIAL_set1_ocsp_response(c, ocsp_buffer);
    CRYPTO_BUFFER_free(ocsp_buffer);

    if (result == 0) {
        throw_openssl_error(e, "Failed to set OCSP response");
        return;
    }
#else
    throw_unsupported_operation(e, "SSL_CREDENTIAL_set1_ocsp_response");
#endif
}

TCN_IMPLEMENT_CALL(void, SSLCredential, setSigningAlgorithmPrefs)(TCN_STDARGS, jlong cred, jintArray prefs) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, /* void */);
    TCN_CHECK_NULL(prefs, preferencesArray, /* void */);

    jsize len = (*e)->GetArrayLength(e, prefs);
    if (len == 0) {
        tcn_Throw(e, "Preferences array is empty");
        return;
    }

    uint16_t* native_prefs = OPENSSL_malloc(sizeof(uint16_t) * len);
    TCN_CHECK_NULL(native_prefs, signingAlgorithmPrefs, /* void */);

    jint* prefs_data = (*e)->GetIntArrayElements(e, prefs, NULL);
    if (prefs_data == NULL) {
        OPENSSL_free(native_prefs);
        return;
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
        return;
    }
#else
    throw_unsupported_operation(e, "SSL_CREDENTIAL_set1_signing_algorithm_prefs");
#endif
}

TCN_IMPLEMENT_CALL(void, SSLCredential, setCertificateProperties)(TCN_STDARGS, jlong cred, jbyteArray cert_props) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, /* void */);
    TCN_CHECK_NULL(cert_props, certificateProperties, /* void */);

    jsize len = (*e)->GetArrayLength(e, cert_props);
    jbyte* props_data = (*e)->GetByteArrayElements(e, cert_props, NULL);
    if (props_data == NULL) {
        return;
    }

    CRYPTO_BUFFER* props_buffer = CRYPTO_BUFFER_new((const uint8_t*)props_data, len, NULL);
    (*e)->ReleaseByteArrayElements(e, cert_props, props_data, JNI_ABORT);

    TCN_CHECK_NULL(props_buffer, certificatePropertiesBuffer, /* void */);

    int result = SSL_CREDENTIAL_set1_certificate_properties(c, props_buffer);
    CRYPTO_BUFFER_free(props_buffer);

    if (result == 0) {
        throw_openssl_error(e, "Failed to set certificate properties");
        return;
    }
#else
    throw_unsupported_operation(e, "SSL_CREDENTIAL_set1_certificate_properties");
#endif
}

TCN_IMPLEMENT_CALL(void, SSLCredential, setSignedCertTimestampList)(TCN_STDARGS, jlong cred, jbyteArray sct_list) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, /* void */);
    TCN_CHECK_NULL(sct_list, sctList, /* void */);

    jsize len = (*e)->GetArrayLength(e, sct_list);
    jbyte* sct_data = (*e)->GetByteArrayElements(e, sct_list, NULL);
    if (sct_data == NULL) {
        return;
    }

    CRYPTO_BUFFER* sct_buffer = CRYPTO_BUFFER_new((const uint8_t*)sct_data, len, NULL);
    (*e)->ReleaseByteArrayElements(e, sct_list, sct_data, JNI_ABORT);

    TCN_CHECK_NULL(sct_buffer, sctBuffer, /* void */);

    int result = SSL_CREDENTIAL_set1_signed_cert_timestamp_list(c, sct_buffer);
    CRYPTO_BUFFER_free(sct_buffer);

    if (result == 0) {
        throw_openssl_error(e, "Failed to set signed certificate timestamp list");
        return;
    }
#else
    throw_unsupported_operation(e, "SSL_CREDENTIAL_set1_signed_cert_timestamp_list");
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

// Trust anchor configuration
TCN_IMPLEMENT_CALL(void, SSLCredential, setTrustAnchorId)(TCN_STDARGS, jlong cred, jbyteArray id) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, /* void */);
    TCN_CHECK_NULL(id, trustAnchorId, /* void */);

    jsize len = (*e)->GetArrayLength(e, id);
    jbyte* id_data = (*e)->GetByteArrayElements(e, id, NULL);
    if (id_data == NULL) {
        return;
    }

    int result = SSL_CREDENTIAL_set1_trust_anchor_id(c, (const uint8_t*)id_data, len);
    (*e)->ReleaseByteArrayElements(e, id, id_data, JNI_ABORT);

    if (result == 0) {
        throw_openssl_error(e, "Failed to set trust anchor ID");
        return;
    }
#else
    throw_unsupported_operation(e, "SSL_CREDENTIAL_set1_trust_anchor_id");
#endif
}

// Delegated credentials
TCN_IMPLEMENT_CALL(jlong, SSLCredential, newDelegated)(TCN_STDARGS) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* credential = SSL_CREDENTIAL_new_delegated();
    if (credential == NULL) {
        throw_openssl_error(e, "Failed to create delegated SSL_CREDENTIAL");
        return 0;
    }
    return (jlong)(intptr_t)credential;
#else
    throw_unsupported_operation(e, "SSL_CREDENTIAL_new_delegated");
    return 0;
#endif
}

TCN_IMPLEMENT_CALL(void, SSLCredential, setDelegatedCredential)(TCN_STDARGS, jlong cred, jbyteArray dc) {
#ifdef OPENSSL_IS_BORINGSSL
    SSL_CREDENTIAL* c = (SSL_CREDENTIAL*)(intptr_t)cred;
    TCN_CHECK_NULL(c, credential, /* void */);
    TCN_CHECK_NULL(dc, delegatedCredential, /* void */);

    jsize len = (*e)->GetArrayLength(e, dc);
    jbyte* dc_data = (*e)->GetByteArrayElements(e, dc, NULL);
    if (dc_data == NULL) {
        return;
    }

    CRYPTO_BUFFER* dc_buffer = CRYPTO_BUFFER_new((const uint8_t*)dc_data, len, NULL);
    (*e)->ReleaseByteArrayElements(e, dc, dc_data, JNI_ABORT);

    TCN_CHECK_NULL(dc_buffer, delegatedCredentialBuffer, /* void */);

    int result = SSL_CREDENTIAL_set1_delegated_credential(c, dc_buffer);
    CRYPTO_BUFFER_free(dc_buffer);

    if (result == 0) {
        throw_openssl_error(e, "Failed to set delegated credential");
        return;
    }
#else
    throw_unsupported_operation(e, "SSL_CREDENTIAL_set1_delegated_credential");
#endif
}

// JNI Method Registration Table Begin
static const JNINativeMethod method_table[] = {
    // Core functions
    { TCN_METHOD_TABLE_ENTRY(newX509, ()J, SSLCredential) },
    { TCN_METHOD_TABLE_ENTRY(upRef, (J)V, SSLCredential) },
    { TCN_METHOD_TABLE_ENTRY(free, (J)V, SSLCredential) },
    
    // Configuration
    { TCN_METHOD_TABLE_ENTRY(setPrivateKey, (JJ)V, SSLCredential) },
    { TCN_METHOD_TABLE_ENTRY(setCertChain, (J[J)V, SSLCredential) },
    { TCN_METHOD_TABLE_ENTRY(setOcspResponse, (J[B)V, SSLCredential) },
    { TCN_METHOD_TABLE_ENTRY(setSigningAlgorithmPrefs, (J[I)V, SSLCredential) },
    { TCN_METHOD_TABLE_ENTRY(setCertificateProperties, (J[B)V, SSLCredential) },
    { TCN_METHOD_TABLE_ENTRY(setSignedCertTimestampList, (J[B)V, SSLCredential) },
    { TCN_METHOD_TABLE_ENTRY(setMustMatchIssuer, (JZ)V, SSLCredential) },
    
    // Trust anchor configuration
    { TCN_METHOD_TABLE_ENTRY(setTrustAnchorId, (J[B)V, SSLCredential) },
    
    // Delegated credentials
    { TCN_METHOD_TABLE_ENTRY(newDelegated, ()J, SSLCredential) },
    { TCN_METHOD_TABLE_ENTRY(setDelegatedCredential, (J[B)V, SSLCredential) }
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
