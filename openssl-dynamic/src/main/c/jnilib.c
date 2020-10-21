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
#include "sslsession.h"
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
    jstring result = NULL;
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

    apr_version(&apv);
    return apv.major;
}

TCN_IMPLEMENT_CALL(jstring, Library, aprVersionString)(TCN_STDARGS)
{
    return AJP_TO_JSTRING(apr_version_string());
}

TCN_IMPLEMENT_CALL(jboolean, Library, aprHasThreads)(TCN_STDARGS)
{
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
    return (*tcn_global_vm)->GetEnv(tcn_global_vm, (void **)env, TCN_JNI_VERSION);
}

// TODO: Share code with netty natives utilities.
char* netty_internal_tcnative_util_prepend(const char* prefix, const char* str) {
    if (str == NULL) {
        // If str is NULL we should just return NULL as passing NULL to strlen is undefined behavior.
        return NULL;
    }
    if (prefix == NULL) {
        char* result = (char*) malloc(sizeof(char) * (strlen(str) + 1));
        if (result == NULL) {
            return NULL;
        }
        strcpy(result, str);
        return result;
    }
    char* result = (char*) malloc(sizeof(char) * (strlen(prefix) + strlen(str) + 1));
    if (result == NULL) {
        return NULL;
    }
    strcpy(result, prefix);
    strcat(result, str);
    return result;
}

jint netty_internal_tcnative_util_register_natives(JNIEnv* env, const char* packagePrefix, const char* className, const JNINativeMethod* methods, jint numMethods) {
    char* nettyClassName = NULL;
    int retValue = JNI_ERR;
    
    TCN_PREPEND(packagePrefix, className, nettyClassName, done);
   
    jclass nativeCls = (*env)->FindClass(env, nettyClassName);
    if (nativeCls != NULL) {
        retValue = (*env)->RegisterNatives(env, nativeCls, methods, numMethods);
    }
done:
    free(nettyClassName);
    return retValue;
}

#ifndef TCN_BUILD_STATIC

static char* netty_internal_tcnative_util_strndup(const char *s, size_t n) {
    if (s == NULL) {
        // passing NULL to strndup is undefined behavior and may core dump.
        return NULL;
    }

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
    if (s1rbegin == NULL || s1rend == NULL || s2 == NULL) {
        // Return NULL if any of the parameters is NULL to not risk a segfault
        return NULL;
    }
    size_t s2len = strlen(s2);
    char *s = s1rbegin - s2len;

    for (; s >= s1rend; --s) {
        if (strncmp(s, s2, s2len) == 0) {
            return s;
        }
    }
    return NULL;
}

#ifdef _WIN32
static char* netty_internal_tcnative_util_rstrchar(char* s1rbegin, const char* s1rend, const char c2) {
    if (s1rbegin == NULL || s1rend == NULL || s2 == NULL) {
        // Return NULL if any of the parameters is NULL to not risk a segfault
        return NULL;
    }
    for (; s1rbegin >= s1rend; --s1rbegin) {
        if (*s1rbegin == c2) {
            return s1rbegin;
        }
    }
    return NULL;
}
#endif // _WIN32

static char* netty_internal_tcnative_util_strstr_last(const char* haystack, const char* needle) {
    if (haystack == NULL || needle == NULL) {
        // calling strstr with NULL is undefined behavior. Better just return NULL and not risk a crash.
        return NULL;
    }

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
#endif // _WIN32

    if (packagePrefix == packageNameEnd) {
        return NULL;
    }
    // packagePrefix length is > 0
    // Make a copy so we can modify the value without impacting libraryPathName.
    size_t packagePrefixLen = packageNameEnd - packagePrefix;
    if ((packagePrefix = netty_internal_tcnative_util_strndup(packagePrefix, packagePrefixLen)) == NULL) {
        *status = JNI_ERR;
        return NULL;
    }
    // Make sure the packagePrefix is in the correct format for the JNI functions it will be used with.
    char* temp = packagePrefix;
    packageNameEnd = packagePrefix + packagePrefixLen;
    // Package names must be sanitized, in JNI packages names are separated by '/' characters.
    for (; temp != packageNameEnd; ++temp) {
        if (*temp == '_') {
            *temp = '/';
        }
    }
    // Make sure packagePrefix is terminated with the '/' JNI package separator.
    if(*(--temp) != '/') {
        temp = packagePrefix;
        if ((packagePrefix = netty_internal_tcnative_util_prepend(packagePrefix, "/")) == NULL) {
            *status = JNI_ERR;
        } 
        free(temp);
    }
    return packagePrefix;
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
    int sessionOnLoadCalled = 0;
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

    if (netty_internal_tcnative_SSLSession_JNI_OnLoad(env, packagePrefix) == JNI_ERR) {
        goto error;
    }
    sessionOnLoadCalled = 1;

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
    TCN_LOAD_CLASS(env, jString_class, "java/lang/String", error);

    TCN_GET_METHOD(env, jString_class, jString_init,
                   "<init>", "([B)V", error);
    TCN_GET_METHOD(env, jString_class, jString_getBytes,
                   "getBytes", "()[B", error);

    TCN_LOAD_CLASS(env, byteArrayClass, "[B", error);

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
    if (sessionOnLoadCalled == 1) {
        netty_internal_tcnative_SSLSession_JNI_OnUnLoad(env);
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
    netty_internal_tcnative_SSLSession_JNI_OnUnLoad(env);
}

/* Fix missing Dl_info & dladdr in AIX
 * The code is taken from netbsd.org (src/crypto/external/bsd/openssl/dist/crypto/dso/dso_dlfcn.c)
 * except strlcpy & strlcat (those are taken from openbsd.org (src/lib/libc/string))
 */
#ifdef _AIX
/*-
 * See IBM's AIX Version 7.2, Technical Reference:
 *  Base Operating System and Extensions, Volume 1 and 2
 *  https://www.ibm.com/support/knowledgecenter/ssw_aix_72/com.ibm.aix.base/technicalreferences.htm
 */
#include <sys/ldr.h>
#include <errno.h>
#include <openssl/crypto.h>

/* strlcpy:
 * Copy string src to buffer dst of size dsize.  At most dsize-1
 * chars will be copied.  Always NUL terminates (unless dsize == 0).
 * Returns strlen(src); if retval >= dsize, truncation occurred.
 */
size_t strlcpy(char *dst, const char *src, size_t dsize)
{
    const char *osrc = src;
    size_t nleft = dsize;

    /* Copy as many bytes as will fit. */
    if (nleft != 0) {
        while (--nleft != 0) {
            if ((*dst++ = *src++) == '\0') {
                break;
            }
        }
    }

    /* Not enough room in dst, add NUL and traverse rest of src. */
    if (nleft == 0) {
        if (dsize != 0) {
            *dst = '\0';		/* NUL-terminate dst */
        }
        while (*src++) {
            ;
        }
    }

    return src - osrc - 1;	/* count does not include NUL */
}

/* strlcat:
 * Appends src to string dst of size dsize (unlike strncat, dsize is the
 * full size of dst, not space left).  At most dsize-1 characters
 * will be copied.  Always NUL terminates (unless dsize <= strlen(dst)).
 * Returns strlen(src) + MIN(dsize, strlen(initial dst)).
 * If retval >= dsize, truncation occurred.
 */
size_t strlcat(char *dst, const char *src, size_t dsize)
{
    const char *odst = dst;
    const char *osrc = src;
    size_t n = dsize;
    size_t dlen;

    /* Find the end of dst and adjust bytes left but don't go past end. */
    while (n-- != 0 && *dst != '\0') {
        dst++;
    }
    dlen = dst - odst;
    n = dsize - dlen;

    if (n-- == 0) {
        return dlen + strlen(src);
    }
    while (*src != '\0') {
        if (n != 0) {
            *dst++ = *src;
            n--;
        }
        src++;
    }
    *dst = '\0';

    return dlen + src - osrc;	/* count does not include NUL */
}

/* ~ 64 * (sizeof(struct ld_info) + _XOPEN_PATH_MAX + _XOPEN_NAME_MAX) */
#  define DLFCN_LDINFO_SIZE 86976
typedef struct Dl_info {
    const char *dli_fname;
} Dl_info;
/*
 * This dladdr()-implementation will also find the ptrgl (Pointer Glue) virtual
 * address of a function, which is just located in the DATA segment instead of
 * the TEXT segment.
 */
static int dladdr(void *ptr, Dl_info *dl)
{
    uintptr_t addr = (uintptr_t)ptr;
    struct ld_info *ldinfos;
    struct ld_info *next_ldi;
    struct ld_info *this_ldi;

    if ((ldinfos = OPENSSL_malloc(DLFCN_LDINFO_SIZE)) == NULL) {
        dl->dli_fname = NULL;
        return 0;
    }

    if ((loadquery(L_GETINFO, (void *)ldinfos, DLFCN_LDINFO_SIZE)) < 0) {
        /*-
         * Error handling is done through errno and dlerror() reading errno:
         *  ENOMEM (ldinfos buffer is too small),
         *  EINVAL (invalid flags),
         *  EFAULT (invalid ldinfos ptr)
         */
        OPENSSL_free((void *)ldinfos);
        dl->dli_fname = NULL;
        return 0;
    }
    next_ldi = ldinfos;

    do {
        this_ldi = next_ldi;
        if (((addr >= (uintptr_t)this_ldi->ldinfo_textorg)
             && (addr < ((uintptr_t)this_ldi->ldinfo_textorg +
                         this_ldi->ldinfo_textsize)))
            || ((addr >= (uintptr_t)this_ldi->ldinfo_dataorg)
                && (addr < ((uintptr_t)this_ldi->ldinfo_dataorg +
                            this_ldi->ldinfo_datasize)))) {
            char *buffer = NULL;
            char *member = NULL;
            size_t buffer_sz;
            size_t member_len;

            buffer_sz = strlen(this_ldi->ldinfo_filename) + 1;
            member = this_ldi->ldinfo_filename + buffer_sz;
            if ((member_len = strlen(member)) > 0) {
                buffer_sz += 1 + member_len + 1;
            }
            if ((buffer = OPENSSL_malloc(buffer_sz)) != NULL) {
                strlcpy(buffer, this_ldi->ldinfo_filename, buffer_sz);
                if (member_len > 0) {
                    /*
                     * Need to respect a possible member name and not just
                     * returning the path name in this case. See docs:
                     * sys/ldr.h, loadquery() and dlopen()/RTLD_MEMBER.
                     */
                    strlcat(buffer, "(", buffer_sz);
                    strlcat(buffer, member, buffer_sz);
                    strlcat(buffer, ")", buffer_sz);
                }
                dl->dli_fname = buffer;
            }
            break;
        } else {
            next_ldi = (struct ld_info *)((uintptr_t)this_ldi +
                                          this_ldi->ldinfo_next);
        }
    } while (this_ldi->ldinfo_next);
    OPENSSL_free((void *)ldinfos);
    return dl->dli_fname != NULL;
}
# endif                         /* _AIX */

static jint JNI_OnLoad_netty_tcnative0(JavaVM* vm, void* reserved) {
    JNIEnv* env = NULL;
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
    JNIEnv* env = NULL;
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
