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
#ifndef _WIN32
// It's important to have #define _GNU_SOURCE before any other include as otherwise it will not work.
// See http://stackoverflow.com/questions/7296963/gnu-source-and-use-gnu
#define _GNU_SOURCE
#include <dlfcn.h>
#else
#define MAX_DLL_PATH_LEN 2048
#endif

#include "tcn.h"
#include "bb.h"
#include "native_constants.h"
#include "ssl.h"
#include "sslcontext.h"
#include "error.h"
#include <string.h>

#ifndef TCN_JNI_VERSION
#define TCN_JNI_VERSION JNI_VERSION_1_6
#endif

static JavaVM     *tcn_global_vm = NULL;

static jclass    jString_class;
static jmethodID jString_init;
static jmethodID jString_getBytes;
static jclass    byteArrayClass;
static jclass    keyMaterialClass;
static jfieldID  keyMaterialCertificateChainFieldId;
static jfieldID  keyMaterialPrivateKeyFieldId;

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

// TODO: Share code with netty natives utilities.
char* netty_internal_tcnative_util_prepend(const char* prefix, const char* str) {
    if (prefix == NULL) {
        char* result = (char*) malloc(sizeof(char) * (strlen(str) + 1));
        strcpy(result, str);
        return result;
    }
    char* result = (char*) malloc(sizeof(char) * (strlen(prefix) + strlen(str) + 1));
    strcpy(result, prefix);
    strcat(result, str);
    return result;
}

jint netty_internal_tcnative_util_register_natives(JNIEnv* env, const char* packagePrefix, const char* className, const JNINativeMethod* methods, jint numMethods) {
    char* nettyClassName = netty_internal_tcnative_util_prepend(packagePrefix, className);
    jclass nativeCls = (*env)->FindClass(env, nettyClassName);
    free(nettyClassName);
    nettyClassName = NULL;
    if (nativeCls == NULL) {
        return JNI_ERR;
    }

    return (*env)->RegisterNatives(env, nativeCls, methods, numMethods);
}

#ifndef TCN_NOT_DYNAMIC

static char* netty_internal_tcnative_util_strndup(const char *s, size_t n) {
// windows does not have strndup
#ifdef _WIN32
    char* copy = _strdup(s);
    if (copy != NULL && n < strlen(copy)) {
        // mark the end
        copy[n + 1] = '\0';
    }
    return copy;
#else
    return strndup(s, n);
#endif
}

static char* netty_internal_tcnative_util_rstrstr(char* s1rbegin, const char* s1rend, const char* s2) {
    size_t s2len = strlen(s2);
    char *s = s1rbegin - s2len;

    for (; s >= s1rend; --s) {
        if (strncmp(s, s2, s2len) == 0) {
            return s;
        }
    }
    return NULL;
}

static char* netty_internal_tcnative_util_rstrchar(char* s1rbegin, const char* s1rend, const char c2) {
    for (; s1rbegin >= s1rend; --s1rbegin) {
        if (*s1rbegin == c2) {
            return s1rbegin;
        }
    }
    return NULL;
}

static char* netty_internal_tcnative_util_strstr_last(const char* haystack, const char* needle) {
    char* prevptr = NULL;
    char* ptr = (char*) haystack;

    while ((ptr = strstr(ptr, needle)) != NULL) {
        // Just store the ptr and continue searching.
        prevptr = ptr;
        ++ptr;
    }
    return prevptr;
}

/**
 * The expected format of the library name is "lib<>netty-tcnative" on non windows platforms and "<>netty-tcnative" on windows,
 *  where the <> portion is what we will return.
 */
static char* parsePackagePrefix(const char* libraryPathName, jint* status) {
    char* packageNameEnd = netty_internal_tcnative_util_strstr_last(libraryPathName, "netty-tcnative");
    if (packageNameEnd == NULL) {
        *status = JNI_ERR;
        return NULL;
    }
#ifdef _WIN32
    // on windows there is no lib prefix so we instead look for the previous path separator or the beginning of the string.
    char* packagePrefix = netty_internal_tcnative_util_rstrchar(packageNameEnd, libraryPathName, '\\');
    if (packagePrefix == NULL) {
        // The string does not have to specify a path [1].
        // [1] https://msdn.microsoft.com/en-us/library/windows/desktop/ms683200(v=vs.85).aspx
        packagePrefix = libraryPathName;
    } else {
        packagePrefix += 1;
    }
#else
    char* packagePrefix = netty_internal_tcnative_util_rstrstr(packageNameEnd, libraryPathName, "lib");
    if (packagePrefix == NULL) {
        *status = JNI_ERR;
        return NULL;
    }
    packagePrefix += 3;
#endif

    if (packagePrefix == packageNameEnd) {
        return NULL;
    }
    // packagePrefix length is > 0
    // Make a copy so we can modify the value without impacting libraryPathName.
    size_t packagePrefixLen = packageNameEnd - packagePrefix;
    packagePrefix = netty_internal_tcnative_util_strndup(packagePrefix, packagePrefixLen);
    // Make sure the packagePrefix is in the correct format for the JNI functions it will be used with.
    char* temp = packagePrefix;
    packageNameEnd = packagePrefix + packagePrefixLen;
    // Package names must be sanitized, in JNI packages names are separated by '/' characters.
    for (; temp != packageNameEnd; ++temp) {
        if (*temp == '-') {
            *temp = '/';
        }
    }
    // Make sure packagePrefix is terminated with the '/' JNI package separator.
    if(*(--temp) != '/') {
        temp = packagePrefix;
        packagePrefix = netty_internal_tcnative_util_prepend(packagePrefix, "/");
        free(temp);
    }
    return packagePrefix;
}

#endif /* TCN_NOT_DYNAMIC */

jint netty_internal_tcnative_Library_JNI_OnLoad(JNIEnv* env, const char* packagePrefix) {
    // Load all c modules that we depend upon
    if (netty_internal_tcnative_Error_JNI_OnLoad(env, packagePrefix) == JNI_ERR) {
        return JNI_ERR;
    }
    if (netty_internal_tcnative_Buffer_JNI_OnLoad(env, packagePrefix) == JNI_ERR) {
        return JNI_ERR;
    }
    if (netty_internal_tcnative_NativeStaticallyReferencedJniMethods_JNI_OnLoad(env, packagePrefix) == JNI_ERR) {
        return JNI_ERR;
    }

    if (netty_internal_tcnative_SSL_JNI_OnLoad(env, packagePrefix) == JNI_ERR) {
        return JNI_ERR;
    }
    if (netty_internal_tcnative_SSLContext_JNI_OnLoad(env, packagePrefix) == JNI_ERR) {
        return JNI_ERR;
    }

    /* Initialize global java.lang.String class */
    TCN_LOAD_CLASS(env, jString_class, "java/lang/String", JNI_ERR);

    TCN_GET_METHOD(env, jString_class, jString_init,
                   "<init>", "([B)V", JNI_ERR);
    TCN_GET_METHOD(env, jString_class, jString_getBytes,
                   "getBytes", "()[B", JNI_ERR);

    TCN_LOAD_CLASS(env, byteArrayClass, "[B", JNI_ERR);

    char* keyMaterialClassName = netty_internal_tcnative_util_prepend(packagePrefix, "io/netty/internal/tcnative/CertificateRequestedCallback$KeyMaterial");
    jclass keyMaterialClassLocal = (*env)->FindClass(env, keyMaterialClassName);
    free(keyMaterialClassName);
    keyMaterialClassName = NULL;
    if (keyMaterialClassLocal == NULL) {
        return JNI_ERR;
    }
    keyMaterialClass = (*env)->NewGlobalRef(env, keyMaterialClassLocal);

    TCN_GET_FIELD(env, keyMaterialClass, keyMaterialCertificateChainFieldId,
                   "certificateChain", "J", JNI_ERR);
    TCN_GET_FIELD(env, keyMaterialClass, keyMaterialPrivateKeyFieldId,
                   "privateKey", "J", JNI_ERR);

    return TCN_JNI_VERSION;
}

void netty_internal_tcnative_Library_JNI_OnUnLoad(JNIEnv* env) {
    TCN_UNLOAD_CLASS(env, jString_class);
    TCN_UNLOAD_CLASS(env, byteArrayClass);
    TCN_UNLOAD_CLASS(env, keyMaterialClass);

    netty_internal_tcnative_Error_JNI_OnUnLoad(env);
    netty_internal_tcnative_Buffer_JNI_OnUnLoad(env);
    netty_internal_tcnative_NativeStaticallyReferencedJniMethods_JNI_OnUnLoad(env);
    netty_internal_tcnative_SSL_JNI_OnUnLoad(env);
    netty_internal_tcnative_SSLContext_JNI_OnUnLoad(env);
}

// JNI Wrapper for statically built Java 8 deps
jint JNI_OnLoad_netty_tcnative(JavaVM* vm, void* reserved) {
    JNIEnv* env;
    if ((*vm)->GetEnv(vm, (void**) &env, TCN_JNI_VERSION) != JNI_OK) {
        return JNI_ERR;
    }

#ifndef TCN_NOT_DYNAMIC
    jint status = 0;
    const char* name = NULL;
#ifndef _WIN32
    Dl_info dlinfo;
    // We need to use an address of a function that is uniquely part of this library, so choose a static
    // function. See https://github.com/netty/netty/issues/4840.
    if (!dladdr((void*) parsePackagePrefix, &dlinfo)) {
        fprintf(stderr, "FATAL: netty-tcnative JNI call to dladdr failed!\n");
        return JNI_ERR;
    }
    name = dlinfo.dli_fname;
#else
    HMODULE module = NULL;
    if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (void*) parsePackagePrefix, &module) == 0){
        fprintf(stderr, "FATAL: netty-tcnative JNI call to GetModuleHandleExA failed!\n");
        return JNI_ERR;
    }

    // add space for \0 termination as this is not automatically included for windows XP
    // See https://msdn.microsoft.com/en-us/library/windows/desktop/ms683197(v=vs.85).aspx
    char dllPath[MAX_DLL_PATH_LEN + 1];
    int dllPathLen = GetModuleFileNameA(module, dllPath, MAX_DLL_PATH_LEN);
    if (dllPathLen == 0) {
        fprintf(stderr, "FATAL: netty-tcnative JNI call to GetModuleFileNameA failed!\n");
        return JNI_ERR;
    } else {
        // ensure we null terminate as this is not automatically done on windows xp
        dllPath[dllPathLen] = '\0';
    }

    name = dllPath;
#endif
    char* packagePrefix = parsePackagePrefix(name, &status);

    if (status == JNI_ERR) {
        fprintf(stderr, "FATAL: netty-tcnative encountered unexpected library path: %s\n", name);
        return JNI_ERR;
    }
#else
    char* packagePrefix = NULL;
#endif /* TCN_NOT_DYNAMIC */

    tcn_global_vm = vm;
    jint ret = netty_internal_tcnative_Library_JNI_OnLoad(env, packagePrefix);

    if (packagePrefix != NULL) {
      free(packagePrefix);
      packagePrefix = NULL;
    }

    return ret;
}

jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    return JNI_OnLoad_netty_tcnative(vm, reserved);
}

void JNI_OnUnload_netty_tcnative(JavaVM* vm, void* reserved) {
    JNIEnv* env;
    if ((*vm)->GetEnv(vm, (void**) &env, TCN_JNI_VERSION) != JNI_OK) {
        // Something is wrong but nothing we can do about this :(
        return;
    }
    netty_internal_tcnative_Library_JNI_OnUnLoad(env);
}

void JNI_OnUnload(JavaVM* vm, void* reserved) {
  JNI_OnUnload_netty_tcnative(vm, reserved);
}
