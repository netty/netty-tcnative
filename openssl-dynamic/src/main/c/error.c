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

/*
 *
 * @author Mladen Turk
 * @version $Id: error.c 1442587 2013-02-05 13:49:48Z rjung $
 */

#include "tcn.h"

static const char *tcn_errors[] = {
                            "Unknown user error",
    /* TCN_TIMEUP      */   "Operation timed out",
    /* TCN_EAGAIN      */   "There is no data ready",
    /* TCN_EINTR       */   "Interrupted system call",
    /* TCN_EINPROGRESS */   "Operation in progress",
    /* TCN_ETIMEDOUT   */   "Connection timed out",
    NULL
};

/* Merge IS_ETIMEDOUT with APR_TIMEUP
 */
#define TCN_STATUS_IS_ETIMEDOUT(x) (APR_STATUS_IS_ETIMEDOUT((x)) || ((x) == APR_TIMEUP))
/*
 * Convenience function to help throw an java.lang.Exception.
 */
void tcn_ThrowException(JNIEnv *env, const char *msg)
{
    jclass javaExceptionClass;

    javaExceptionClass = (*env)->FindClass(env, "java/lang/Exception");
    if (javaExceptionClass == NULL) {
        fprintf(stderr, "Cannot find java/lang/Exception class\n");
        return;
    }
    (*env)->ThrowNew(env, javaExceptionClass, msg);
    (*env)->DeleteLocalRef(env, javaExceptionClass);

}

void tcn_ThrowMemoryException(JNIEnv *env, const char *file, int line, const char *msg)
{
    jclass javaExceptionClass;
    javaExceptionClass = (*env)->FindClass(env, "java/lang/OutOfMemoryError");
    if (javaExceptionClass == NULL) {
        fprintf(stderr, "Cannot find java/lang/OutOfMemoryError\n");
        return;
    }

    if (file) {
        char fmt[TCN_BUFFER_SZ];
        char *f = (char *)(file + strlen(file) - 1);
        while (f != file && '\\' != *f && '/' != *f) {
            f--;
        }
        if (f != file) {
            f++;
        }
        sprintf(fmt, "%s for [%04d@%s]", msg, line, f);
        (*env)->ThrowNew(env, javaExceptionClass, &fmt[0]);
    }
    else
        (*env)->ThrowNew(env, javaExceptionClass, msg);
    (*env)->DeleteLocalRef(env, javaExceptionClass);

}


void tcn_Throw(JNIEnv *env, const char *fmt, ...)
{
    char msg[TCN_BUFFER_SZ] = {'\0'};
    va_list ap;

    va_start(ap, fmt);
    apr_vsnprintf(msg, TCN_BUFFER_SZ, fmt, ap);
    tcn_ThrowException(env, msg);
    va_end(ap);
}

/*
 * Convenience function to help throw an APR Exception
 * from native error code.
 */
void tcn_ThrowAPRException(JNIEnv *e, apr_status_t err)
{
    jclass aprErrorClass;
    jmethodID constructorID = 0;
    jobject throwObj;
    jstring jdescription;
    char serr[512] = {0};

    aprErrorClass = (*e)->FindClass(e, TCN_ERROR_CLASS);
    if (aprErrorClass == NULL) {
        fprintf(stderr, "Cannot find " TCN_ERROR_CLASS " class\n");
        return;
    }

    /* Find the constructor ID */
    constructorID = (*e)->GetMethodID(e, aprErrorClass,
                                      "<init>",
                                      "(ILjava/lang/String;)V");
    if (constructorID == NULL) {
        fprintf(stderr,
                "Cannot find constructor for " TCN_ERROR_CLASS " class\n");
        goto cleanup;
    }

    apr_strerror(err, serr, 512);
    /* Obtain the string objects */
    jdescription = AJP_TO_JSTRING(serr);
    if (jdescription == NULL) {
        fprintf(stderr,
                "Cannot allocate description for " TCN_ERROR_CLASS " class\n");
        goto cleanup;
    }
    /* Create the APR Error object */
    throwObj = (*e)->NewObject(e, aprErrorClass, constructorID,
                               (jint)err, jdescription);
    if (throwObj == NULL) {
        fprintf(stderr,
                "Cannot allocate new " TCN_ERROR_CLASS " object\n");
        goto cleanup;
    }

    (*e)->Throw(e, throwObj);
cleanup:
    (*e)->DeleteLocalRef(e, aprErrorClass);
}


TCN_IMPLEMENT_CALL(jint, Error, osError)(TCN_STDARGS)
{
    UNREFERENCED_STDARGS;
    return (jint)apr_get_os_error();
}

TCN_IMPLEMENT_CALL(jstring, Error, strerror)(TCN_STDARGS, jint err)
{
    char serr[512] = {0};
    jstring jerr;

    UNREFERENCED(o);
    if (err >= TCN_TIMEUP && err <= TCN_ETIMEDOUT) {
        err -= TCN_TIMEUP;
        jerr = AJP_TO_JSTRING(tcn_errors[err + 1]);
    }
    else {
        apr_strerror(err, serr, 512);
        jerr = AJP_TO_JSTRING(serr);
    }
    return jerr;
}
