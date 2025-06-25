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
#ifndef NETTY_TCNATIVE_SSLCREDENTIAL_H_
#define NETTY_TCNATIVE_SSLCREDENTIAL_H_

#include <jni.h>
#include <openssl/ssl.h>

#ifdef __cplusplus
extern "C" {
#endif

// JNI initialization hooks
jint netty_internal_tcnative_SSLCredential_JNI_OnLoad(JNIEnv* env, const char* packagePrefix);
void netty_internal_tcnative_SSLCredential_JNI_OnUnLoad(JNIEnv* env, const char* packagePrefix);

// Core SSL_CREDENTIAL functions
JNIEXPORT jlong JNICALL Java_io_netty_internal_tcnative_SSLCredential_newX509(JNIEnv*, jclass);
JNIEXPORT void JNICALL Java_io_netty_internal_tcnative_SSLCredential_upRef(JNIEnv*, jclass, jlong);
JNIEXPORT void JNICALL Java_io_netty_internal_tcnative_SSLCredential_free(JNIEnv*, jclass, jlong);

// SSL_CREDENTIAL configuration methods
JNIEXPORT jboolean JNICALL Java_io_netty_internal_tcnative_SSLCredential_setPrivateKey(JNIEnv*, jclass, jlong, jlong);
JNIEXPORT jboolean JNICALL Java_io_netty_internal_tcnative_SSLCredential_setCertChain(JNIEnv*, jclass, jlong, jlongArray);
JNIEXPORT jboolean JNICALL Java_io_netty_internal_tcnative_SSLCredential_setOcspResponse(JNIEnv*, jclass, jlong, jbyteArray);
JNIEXPORT jboolean JNICALL Java_io_netty_internal_tcnative_SSLCredential_setSigningAlgorithmPrefs(JNIEnv*, jclass, jlong, jintArray);
JNIEXPORT jboolean JNICALL Java_io_netty_internal_tcnative_SSLCredential_setCertificateProperties(JNIEnv*, jclass, jlong, jbyteArray);
JNIEXPORT jboolean JNICALL Java_io_netty_internal_tcnative_SSLCredential_setSignedCertTimestampList(JNIEnv*, jclass, jlong, jbyteArray);
JNIEXPORT void JNICALL Java_io_netty_internal_tcnative_SSLCredential_setMustMatchIssuer(JNIEnv*, jclass, jlong, jboolean);

// Private key methods
JNIEXPORT jint JNICALL Java_io_netty_internal_tcnative_SSLCredential_setPrivateKeyMethod(JNIEnv*, jclass, jlong, jlong);

// Trust anchor configuration
JNIEXPORT jint JNICALL Java_io_netty_internal_tcnative_SSLCredential_setTrustAnchorId(JNIEnv*, jclass, jlong, jbyteArray);

// Ex data support
JNIEXPORT jint JNICALL Java_io_netty_internal_tcnative_SSLCredential_setExData(JNIEnv*, jclass, jlong, jint, jlong);
JNIEXPORT jlong JNICALL Java_io_netty_internal_tcnative_SSLCredential_getExData(JNIEnv*, jclass, jlong, jint);
JNIEXPORT jint JNICALL Java_io_netty_internal_tcnative_SSLCredential_getExNewIndex(JNIEnv*, jclass, jlong, jlong, jlong);

// Delegated credentials
JNIEXPORT jlong JNICALL Java_io_netty_internal_tcnative_SSLCredential_newDelegated(JNIEnv*, jclass);
JNIEXPORT jint JNICALL Java_io_netty_internal_tcnative_SSLCredential_setDelegatedCredential(JNIEnv*, jclass, jlong, jbyteArray);

// SPAKE2+ support
JNIEXPORT jlong JNICALL Java_io_netty_internal_tcnative_SSLCredential_newSpake2PlusV1Client(JNIEnv*, jclass, jbyteArray, jbyteArray);
JNIEXPORT jlong JNICALL Java_io_netty_internal_tcnative_SSLCredential_newSpake2PlusV1Server(JNIEnv*, jclass, jbyteArray, jbyteArray);

#ifdef __cplusplus
}
#endif

#endif /* NETTY_TCNATIVE_SSLCREDENTIAL_H_ */
