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

#include "tcn.h"
#include "apr_version.h"
#include "apr_atomic.h"
#include "apr_strings.h"

#ifndef TCN_JNI_VERSION
#define TCN_JNI_VERSION JNI_VERSION_1_4
#endif

apr_pool_t *tcn_global_pool = NULL;
static JavaVM     *tcn_global_vm = NULL;

static jclass    jString_class;
static jmethodID jString_init;
static jmethodID jString_getBytes;
static jclass    byteArrayClass;
static jclass    keyMaterialClass;
static jfieldID  keyMaterialCertificateChainFieldId;
static jfieldID  keyMaterialPrivateKeyFieldId;

/* Called by the JVM when APR_JAVA is loaded */
JNIEXPORT jint JNICALL JNI_OnLoad_netty_tcnative(JavaVM *vm, void *reserved) 
{
    JNIEnv *env;
    apr_version_t apv;
    int apvn;

    UNREFERENCED(reserved);
    if ((*vm)->GetEnv(vm, (void **)&env, TCN_JNI_VERSION)) {
        return JNI_ERR;
    }
    tcn_global_vm = vm;

    /* Before doing anything else check if we have a valid
     * APR version.
     */
    apr_version(&apv);
    apvn = apv.major * 1000 + apv.minor * 100 + apv.patch;
    if (apvn < 1201) {
        tcn_Throw(env, "Unsupported APR version (%s)",
                  apr_version_string());
        return JNI_ERR;
    }


    /* Initialize global java.lang.String class */
    TCN_LOAD_CLASS(env, jString_class, "java/lang/String", JNI_ERR);

    TCN_GET_METHOD(env, jString_class, jString_init,
                   "<init>", "([B)V", JNI_ERR);
    TCN_GET_METHOD(env, jString_class, jString_getBytes,
                   "getBytes", "()[B", JNI_ERR);

    // Load the class which makes JNI references available in a static scope before loading any other classes.
    if ((*env)->FindClass(env, "io/netty/internal/tcnative/NativeStaticallyReferencedJniMethods") == NULL) {
        return JNI_ERR;
    }

    TCN_LOAD_CLASS(env, byteArrayClass, "[B", JNI_ERR);
    TCN_LOAD_CLASS(env, keyMaterialClass, "io/netty/internal/tcnative/CertificateRequestedCallback$KeyMaterial", JNI_ERR);

    TCN_GET_FIELD(env, keyMaterialClass, keyMaterialCertificateChainFieldId,
                   "certificateChain", "J", JNI_ERR);
    TCN_GET_FIELD(env, keyMaterialClass, keyMaterialPrivateKeyFieldId,
                   "privateKey", "J", JNI_ERR);

    return TCN_JNI_VERSION;
}

/* Called by the JVM when APR_JAVA is loaded */
JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    return JNI_OnLoad_netty_tcnative(vm, reserved);
}

/* Called by the JVM before the APR_JAVA is unloaded */
JNIEXPORT void JNICALL JNI_OnUnload_netty_tcnative(JavaVM *vm, void *reserved)
{
    JNIEnv *env;

    UNREFERENCED(reserved);

    if ((*vm)->GetEnv(vm, (void **)&env, TCN_JNI_VERSION)) {
        return;
    }

    if (tcn_global_pool) {
        TCN_UNLOAD_CLASS(env, jString_class);
        apr_terminate();
    }

    TCN_UNLOAD_CLASS(env, byteArrayClass);
    TCN_UNLOAD_CLASS(env, keyMaterialClass);
}

/* Called by the JVM before the APR_JAVA is unloaded */
JNIEXPORT void JNICALL JNI_OnUnload(JavaVM *vm, void *reserved)
{
    JNI_OnUnload_netty_tcnative(vm, reserved);
}

jstring tcn_new_stringn(JNIEnv *env, const char *str, size_t l)
{
    jstring result;
    jbyteArray bytes = 0;

    if (!str)
        return NULL;
    if ((*env)->EnsureLocalCapacity(env, 2) < 0) {
        return NULL; /* out of memory error */
    }
    bytes = (*env)->NewByteArray(env, l);
    if (bytes != NULL) {
        (*env)->SetByteArrayRegion(env, bytes, 0, l, (jbyte *)str);
        result = (*env)->NewObject(env, jString_class, jString_init, bytes);
        (*env)->DeleteLocalRef(env, bytes);
        return result;
    } /* else fall through */
    return NULL;
}

jstring tcn_new_string(JNIEnv *env, const char *str)
{
    if (!str)
        return NULL;
    else
        return (*env)->NewStringUTF(env, str);
}

TCN_IMPLEMENT_CALL(jboolean, Library, initialize0)(TCN_STDARGS)
{

    UNREFERENCED_STDARGS;
    if (!tcn_global_pool) {
        apr_initialize();
        if (apr_pool_create(&tcn_global_pool, NULL) != APR_SUCCESS) {
            return JNI_FALSE;
        }
        apr_atomic_init(tcn_global_pool);
    }
    return JNI_TRUE;
}

TCN_IMPLEMENT_CALL(jint, Library, aprMajorVersion)(TCN_STDARGS)
{
    apr_version_t apv;

    UNREFERENCED_STDARGS;
    apr_version(&apv);
    return apv.major;
}

TCN_IMPLEMENT_CALL(jstring, Library, aprVersionString)(TCN_STDARGS)
{
    UNREFERENCED(o);
    return AJP_TO_JSTRING(apr_version_string());
}

TCN_IMPLEMENT_CALL(jboolean, Library, aprHasThreads)(TCN_STDARGS)
{
    UNREFERENCED_STDARGS;
#if APR_HAS_THREADS
    return JNI_TRUE;
#else
    return JNI_FALSE;
#endif
}

jclass tcn_get_string_class()
{
    return jString_class;
}

jclass tcn_get_byte_array_class()
{
    return byteArrayClass;
}

jfieldID tcn_get_key_material_certificate_chain_field()
{
    return keyMaterialCertificateChainFieldId;
}

jfieldID tcn_get_key_material_private_key_field()
{
    return keyMaterialPrivateKeyFieldId;
}

jint tcn_get_java_env(JNIEnv **env)
{
    if ((*tcn_global_vm)->GetEnv(tcn_global_vm, (void **)env,
                                 TCN_JNI_VERSION)) {
        return JNI_ERR;
    }
    return JNI_OK;
}
