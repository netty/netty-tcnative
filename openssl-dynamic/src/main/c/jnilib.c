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
#include "apr_version.h"
#include "apr_atomic.h"
#include "apr_strings.h"
#include "bb.h"
#include "native_constants.h"
#include "ssl.h"
#include "sslcontext.h"
#include "error.h"

#ifndef TCN_JNI_VERSION
#define TCN_JNI_VERSION JNI_VERSION_1_6
#endif

apr_pool_t *tcn_global_pool = NULL;
static JavaVM     *tcn_global_vm = NULL;

static jclass    jString_class;
static jmethodID jString_init;
static jmethodID jString_getBytes;
static jclass    byteArrayClass;

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

#ifndef TCN_BUILD_STATIC

static char* netty_internal_tcnative_util_strndup(const char *s, size_t n) {
// windows / solaris does not have strndup
#if defined(_WIN32) || defined(__sun)
#ifdef _WIN32
    char* copy = _strdup(s);
#else
    char* copy = strdup(s);
#endif
    if (copy != NULL && n < strlen(copy)) {
        // mark the end
        copy[n] = '\0';
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
 * The expected format of the library name is "lib<>netty_tcnative" on non windows platforms and "<>netty_tcnative" on windows,
 *  where the <> portion is what we will return.
 */
static char* parsePackagePrefix(const char* libraryPathName, jint* status) {
    char* packageNameEnd = netty_internal_tcnative_util_strstr_last(libraryPathName, "netty_tcnative");
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

    int packageNameLen = 0;
    char* temp = packagePrefix;
    for (; temp != packageNameEnd; ++temp) {
        ++packageNameLen;
        if (*temp == '_') {
	    // TODO: support _0xxxx as a unicode char
	    // Escape sequences _2 and _3 apply only to signatures, not package name
	    if ((temp+1 != packageNameEnd) && (*(temp+1) == '1')) {
              ++temp; // escapes _1, _2, _3 are 1 char in output
            }
        }
    }

    char* result = (char*) malloc(sizeof(char) * packageNameLen+1);

    // Copy while unescaping
    char *dst, *src;
    for (src = packagePrefix, dst = result; src != packageNameEnd; ++src) {
        if (*src != '_') {
	    *dst = *src;
	    ++dst;
	} else {
	    // TODO: support _0xxxx as unicode char
	    if ((src+1 != packageNameEnd) && (*(src+1) == '1')) {
	        *dst = '_';
		++src;
            } else {
	        *dst = '/';
	    }
	    ++dst;
	}
    }
    dst = '\0';

    // Make sure packagePrefix is terminated with the '/' JNI package separator.
    if(*(--dst) != '/') {
        temp = result;
        result = netty_internal_tcnative_util_prepend(result, "/");
        free(temp);
    }
    return result;
}

#endif /* TCN_BUILD_STATIC */

// JNI Method Registration Table Begin
static const JNINativeMethod method_table[] = {
  { TCN_METHOD_TABLE_ENTRY(initialize0, ()Z, Library) },
  { TCN_METHOD_TABLE_ENTRY(aprMajorVersion, ()I, Library) },
  { TCN_METHOD_TABLE_ENTRY(aprVersionString, ()Ljava/lang/String;, Library) },
  { TCN_METHOD_TABLE_ENTRY(aprHasThreads, ()Z, Library) },
};

static const jint method_table_size = sizeof(method_table) / sizeof(method_table[0]);
// JNI Method Registration Table End

static jint netty_internal_tcnative_Library_JNI_OnLoad(JNIEnv* env, const char* packagePrefix) {
    int errorOnLoadCalled = 0;
    int bufferOnLoadCalled = 0;
    int jniMethodsOnLoadCalled = 0;
    int sslOnLoadCalled = 0;
    int contextOnLoadCalled = 0;

    if (netty_internal_tcnative_util_register_natives(env, packagePrefix, "io/netty/internal/tcnative/Library", method_table, method_table_size) != 0) {
        goto error;
    }

    // Load all c modules that we depend upon
    if (netty_internal_tcnative_Error_JNI_OnLoad(env, packagePrefix) == JNI_ERR) {
        goto error;
    }
    errorOnLoadCalled = 1;

    if (netty_internal_tcnative_Buffer_JNI_OnLoad(env, packagePrefix) == JNI_ERR) {
        goto error;
    }
    bufferOnLoadCalled = 1;

    if (netty_internal_tcnative_NativeStaticallyReferencedJniMethods_JNI_OnLoad(env, packagePrefix) == JNI_ERR) {
        goto error;
    }
    jniMethodsOnLoadCalled = 1;

    if (netty_internal_tcnative_SSL_JNI_OnLoad(env, packagePrefix) == JNI_ERR) {
        goto error;
    }
    sslOnLoadCalled = 1;

    if (netty_internal_tcnative_SSLContext_JNI_OnLoad(env, packagePrefix) == JNI_ERR) {
        goto error;
    }
    contextOnLoadCalled = 1;

    apr_version_t apv;
    int apvn;

    /* Before doing anything else check if we have a valid
     * APR version.
     */
    apr_version(&apv);
    apvn = apv.major * 1000 + apv.minor * 100 + apv.patch;
    if (apvn < 1201) {
        tcn_Throw(env, "Unsupported APR version (%s)",
                  apr_version_string());
        goto error;
    }


    /* Initialize global java.lang.String class */
    TCN_LOAD_CLASS(env, jString_class, "java/lang/String", JNI_ERR);

    TCN_GET_METHOD(env, jString_class, jString_init,
                   "<init>", "([B)V", JNI_ERR);
    TCN_GET_METHOD(env, jString_class, jString_getBytes,
                   "getBytes", "()[B", JNI_ERR);

    TCN_LOAD_CLASS(env, byteArrayClass, "[B", JNI_ERR);

    return TCN_JNI_VERSION;
error:
    // Call unload methods if needed to ensure we correctly release any resources.
    if (errorOnLoadCalled == 1) {
        netty_internal_tcnative_Error_JNI_OnUnLoad(env);
    }
    if (bufferOnLoadCalled == 1) {
        netty_internal_tcnative_Buffer_JNI_OnUnLoad(env);
    }
    if (jniMethodsOnLoadCalled == 1) {
        netty_internal_tcnative_NativeStaticallyReferencedJniMethods_JNI_OnUnLoad(env);
    }
    if (sslOnLoadCalled == 1) {
        netty_internal_tcnative_SSL_JNI_OnUnLoad(env);
    }
    if (contextOnLoadCalled == 1) {
        netty_internal_tcnative_SSLContext_JNI_OnUnLoad(env);
    }
    return JNI_ERR;
}

static void netty_internal_tcnative_Library_JNI_OnUnLoad(JNIEnv* env) {
    if (tcn_global_pool != NULL) {
        TCN_UNLOAD_CLASS(env, jString_class);
        apr_terminate();
    }

    TCN_UNLOAD_CLASS(env, byteArrayClass);

    netty_internal_tcnative_Error_JNI_OnUnLoad(env);
    netty_internal_tcnative_Buffer_JNI_OnUnLoad(env);
    netty_internal_tcnative_NativeStaticallyReferencedJniMethods_JNI_OnUnLoad(env);
    netty_internal_tcnative_SSL_JNI_OnUnLoad(env);
    netty_internal_tcnative_SSLContext_JNI_OnUnLoad(env);
}

static jint JNI_OnLoad_netty_tcnative0(JavaVM* vm, void* reserved) {
    JNIEnv* env;
    if ((*vm)->GetEnv(vm, (void**) &env, TCN_JNI_VERSION) != JNI_OK) {
        return JNI_ERR;
    }

#ifndef TCN_BUILD_STATIC
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
#endif /* TCN_BUILD_STATIC */

    tcn_global_vm = vm;
    jint ret = netty_internal_tcnative_Library_JNI_OnLoad(env, packagePrefix);

    if (packagePrefix != NULL) {
      free(packagePrefix);
      packagePrefix = NULL;
    }

    return ret;
}

static void JNI_OnUnload_netty_tcnative0(JavaVM* vm, void* reserved) {
    JNIEnv* env;
    if ((*vm)->GetEnv(vm, (void**) &env, TCN_JNI_VERSION) != JNI_OK) {
        // Something is wrong but nothing we can do about this :(
        return;
    }
    netty_internal_tcnative_Library_JNI_OnUnLoad(env);
}

// As we build with -fvisibility=hidden we need to ensure we mark the entry load and unload functions used by the
// JVM as visible.
//
// It's important to note that we will only export functions that are prefixed with JNI_ so if we ever need to export
// more we need to ensure we add the prefix. This is enforced by the TCN_CHECK_STATIC function in tcnative.m4.

// Invoked by the JVM when statically linked
JNIEXPORT jint JNI_OnLoad_netty_tcnative(JavaVM* vm, void* reserved) {
    return JNI_OnLoad_netty_tcnative0(vm, reserved);
}

// Invoked by the JVM when statically linked
JNIEXPORT void JNI_OnUnload_netty_tcnative(JavaVM* vm, void* reserved) {
    JNI_OnUnload_netty_tcnative0(vm, reserved);
}

#ifndef TCN_BUILD_STATIC
JNIEXPORT jint JNI_OnLoad(JavaVM* vm, void* reserved) {
    return JNI_OnLoad_netty_tcnative0(vm, reserved);
}

JNIEXPORT void JNI_OnUnload(JavaVM* vm, void* reserved) {
    JNI_OnUnload_netty_tcnative0(vm, reserved);
}
#endif /* TCN_BUILD_STATIC */
