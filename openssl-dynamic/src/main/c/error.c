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
