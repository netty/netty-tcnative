/*
 * Copyright 2016 The Netty Project
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
#include <openssl/ssl.h>
#include <openssl/tls1.h>
#include <stdio.h>

#include <tcn.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-variable"
#include <ssl_private.h>
#pragma GCC diagnostic pop

#include <io_netty_tcnative_jni_ocsp_Native_init.h>
#include <io_netty_tcnative_jni_ocsp_Native.h>

/**
 * https://www.openssl.org/docs/man1.0.2/ssl/SSL_set_tlsext_status_type.html
 */

/**
 * Some globally cached values.
 */
static jclass CALLBACK_CLAZZ = NULL;
static jmethodID CALLBACK_METHOD = NULL;

static void logException(JNIEnv *env) {
  (*env)->ExceptionDescribe(env);
  (*env)->ExceptionClear(env);
}

/**
 * Frees the callback
 */
static void freeCallback(JNIEnv *env, tcn_ssl_ctxt_t *c, jweak callbackRef) {
  
  if (c != NULL) {
    SSL_CTX_set_tlsext_status_arg(c->ctx, NULL);
    SSL_CTX_set_tlsext_status_cb(c->ctx, NULL);
  }

  (*env)->DeleteWeakGlobalRef(env, callbackRef);
}

/**
 * See:
 *   io_netty_tcnative_jni_ocsp_client_callback
 *   io_netty_tcnative_jni_ocsp_server_callback
 */
static int io_netty_tcnative_jni_ocsp_callback(int errorCode, SSL *ssl, void *arg) {

  // This is conceptually not possible.
  if (CALLBACK_CLAZZ == NULL) {
    fprintf(stderr, "io_netty_tcnative_jni_ocsp_callback: no callback class, %i\n", errorCode);
    return errorCode;
  }

  // This is conceptually not possible.
  if (CALLBACK_METHOD == NULL) {
    fprintf(stderr, "io_netty_tcnative_jni_ocsp_callback: no callback method, %i\n", errorCode);
    return errorCode;
  }

  if (arg == NULL) {
    fprintf(stderr, "io_netty_tcnative_jni_ocsp_callback: no callback object, %i\n", errorCode);
    return errorCode;
  }

  JavaVM *jvm = tcn_get_java_vm();
  if (jvm == NULL) {
    fprintf(stderr, "io_netty_tcnative_jni_ocsp_callback: no JVM, %i\n", errorCode);
    return errorCode;
  }

  JNIEnv *env;
  if (tcn_get_java_env(&env) != JNI_OK) {
    fprintf(stderr, "io_netty_tcnative_jni_ocsp_callback: no JNIEnv, %i\n", errorCode);
    return errorCode;
  }

  if ((*jvm)->AttachCurrentThread(jvm, (void **)&env, NULL) != JNI_OK) {
    fprintf(stderr, "AttachCurrentThread: %i\n", errorCode);
    logException(env);
    return errorCode;
  }

  jint value = 0;
  jobject callback = (*env)->NewLocalRef(env, (jweak)arg);

  if ((*env)->IsSameObject(env, callback, NULL) == JNI_FALSE) {

    value = (*env)->CallIntMethod(env, callback, CALLBACK_METHOD, (jlong)ssl);

    if ((*env)->ExceptionCheck(env)) {
      fprintf(stderr, "CallIntMethod: %i\n", errorCode);
      logException(env);

      // Use the errorCode in the event of an JVM exception
      value = errorCode;
    }
  }

  (*env)->DeleteLocalRef(env, callback);
  (*jvm)->DetachCurrentThread(jvm);

  return (int)value;
}

/**
 * The client uses -1 for errors
 */
static int io_netty_tcnative_jni_ocsp_client_callback(SSL *ssl, void *arg) {
  return io_netty_tcnative_jni_ocsp_callback(-1, ssl, arg);
}

/**
 * The server uses SSL_TLSEXT_ERR_ALERT_FATAL for errors (it's a non-negative number).
 */
static int io_netty_tcnative_jni_ocsp_server_callback(SSL *ssl, void *arg) {
  return io_netty_tcnative_jni_ocsp_callback(SSL_TLSEXT_ERR_ALERT_FATAL, ssl, arg);
}

jint io_netty_tcnative_jni_ocsp_Native_OnLoad(JNIEnv *env) {
  jclass clazz = (*env)->FindClass(env, "io/netty/tcnative/jni/ocsp/StatusCallback");
  if ((*env)->ExceptionCheck(env)) {
    logException(env);
    return JNI_ERR;
  }

  CALLBACK_CLAZZ = (*env)->NewGlobalRef(env, clazz);
  if ((*env)->ExceptionCheck(env)) {
    logException(env);
    return JNI_ERR;
  }

  CALLBACK_METHOD = (*env)->GetMethodID(env, CALLBACK_CLAZZ, "callback", "(J)I");
  if ((*env)->ExceptionCheck(env)) {
    logException(env);
    return JNI_ERR;
  }

  return JNI_OK;
}

void io_netty_tcnative_jni_ocsp_Native_OnUnLoad(JNIEnv *env) {
  if (CALLBACK_CLAZZ != NULL) {
    (*env)->DeleteGlobalRef(env, CALLBACK_CLAZZ);

    CALLBACK_CLAZZ = NULL;
    CALLBACK_METHOD = NULL;
  }
}

/**
 * Installs the OCSP stapling callback.
 */
JNIEXPORT jobject JNICALL Java_io_netty_tcnative_jni_ocsp_Native_newCallback
    (JNIEnv *env, jclass clazz, jlong ctx, jboolean client, jobject callback) {

  long error = -1L;
  
  if (ctx == 0L) {
    fprintf(stderr, "ctx ptr is 0L");
    return NULL;
  }

  //
  // ATTENTION: We need to create a global reference of the callback.
  //
  jweak callbackRef = (*env)->NewWeakGlobalRef(env, callback);

  tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
  
  error = SSL_CTX_set_tlsext_status_arg(c->ctx, callbackRef);
  if (error <= 0L) {
    fprintf(stderr, "newCallback/SSL_CTX_set_tlsext_status_arg: %li\n", error);
    freeCallback(env, NULL, callbackRef);
    return NULL;
  }
  
  //
  // The client and server use slightly different return values.
  // In particular in the event of an error. We need therefore
  // two slightly different callback functions.
  //
  
  if (client == JNI_TRUE) {
    error = SSL_CTX_set_tlsext_status_cb(c->ctx, io_netty_tcnative_jni_ocsp_client_callback);
    if (error <= 0L) {
      fprintf(stderr, "newCallback/SSL_CTX_set_tlsext_status_cb (client): %li\n", error);
      freeCallback(env, NULL, callbackRef);
      return NULL;
    }
  
  } else {
    error = SSL_CTX_set_tlsext_status_cb(c->ctx, io_netty_tcnative_jni_ocsp_server_callback);
    if (error <= 0L) {
      fprintf(stderr, "newCallback/SSL_CTX_set_tlsext_status_cb (server): %li\n", error);
      freeCallback(env, NULL, callbackRef);
      return NULL;
    }
  }

  return callbackRef;
}

/**
 * Releases the OCSP callback.
 */
JNIEXPORT void JNICALL Java_io_netty_tcnative_jni_ocsp_Native_freeCallback
    (JNIEnv *env, jclass clazz, jlong ctx, jobject callback) {

  tcn_ssl_ctxt_t *c = J2P(ctx, tcn_ssl_ctxt_t *);
  freeCallback(env, c, callback);
}

/**
 * Enables or disables OCSP stapling for the given SSLEngine.
 */
JNIEXPORT jboolean JNICALL Java_io_netty_tcnative_jni_ocsp_Native_setType
    (JNIEnv *env, jclass clazz, jlong ssl, jint type) {

  if (ssl == 0L) {
    fprintf(stderr, "SSL ptr is 0L");
    return JNI_FALSE;
  }

  long error = SSL_set_tlsext_status_type((SSL*)ssl, type);
  if (error <= 0L) {
    fprintf(stderr, "setType/SSL_set_tlsext_status_type: %li\n", error);
  }
  
  return (error == 1L) ? JNI_TRUE : JNI_FALSE;
}

/**
 * Server: Sets the stapled OCSP record bytes for the given SSLEngine.
 */
JNIEXPORT jboolean JNICALL Java_io_netty_tcnative_jni_ocsp_Native_setResponse
    (JNIEnv *env, jclass clazz, jlong ssl, jbyteArray response) {
  
  if (ssl == 0L) {
    fprintf(stderr, "SSL ptr is 0L");
    return JNI_FALSE;
  }

  jsize length = (*env)->GetArrayLength(env, response);
  if ((*env)->ExceptionCheck(env)) {
    logException(env);
    return JNI_FALSE;
  }

  //
  // ATTENTION: This took a while to figure out but OpenSSL wants to free()
  // this pointer on its own. Give it something it can free or it will crash.
  //

  jbyte *value = OPENSSL_malloc(sizeof(jbyte) * length);
  if (value == NULL) {
    fprintf(stderr, "OPENSSL_malloc() failed: %i\n", length);
    return JNI_FALSE;
  }

  (*env)->GetByteArrayRegion(env, response, 0, length, value);
  
  long error = SSL_set_tlsext_status_ocsp_resp((SSL*)ssl, value, length);
  if (error <= 0L) {
    fprintf(stderr, "setResponse/SSL_set_tlsext_status_ocsp_resp: %li\n", error);
  }
  
  return (error == 1L) ? JNI_TRUE : JNI_FALSE;
}

/**
 * Client: Returns the stapled OCSP record bytes as sent by the server.
 */
JNIEXPORT jbyteArray JNICALL Java_io_netty_tcnative_jni_ocsp_Native_getResponse
  (JNIEnv *env, jclass clazz, jlong ssl) {

  if (ssl == 0L) {
    fprintf(stderr, "SSL ptr is 0L");
    return NULL;
  }

  jbyte *value;
  long length = SSL_get_tlsext_status_ocsp_resp((SSL*)ssl, &value);
  if (length == -1L) {
    fprintf(stderr, "getResponse/SSL_get_tlsext_status_ocsp_resp: %li\n", length);
    return NULL;
  }

  if (length < 0L) {
    fprintf(stderr, "getResponse/SSL_get_tlsext_status_ocsp_resp: %li\n", length);
    return NULL;
  }

  jbyteArray response = (*env)->NewByteArray(env, (jint)length);
  (*env)->SetByteArrayRegion(env, response, 0, (jint)length, value);
  return response;
}
