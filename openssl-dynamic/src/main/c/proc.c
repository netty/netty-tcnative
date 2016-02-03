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
 * @version $Id: proc.c 1442587 2013-02-05 13:49:48Z rjung $
 */
 
#include "tcn.h"
#include "apr_thread_proc.h"
#include "apr_version.h"

#define ERRFN_USERDATA_KEY    "TCNATIVECHILDERRFN"

static void generic_child_errfn(apr_pool_t *pool, apr_status_t err,
                                const char *description)
{
    void *data;
    tcn_callback_t *cb;

    apr_pool_userdata_get(&data, ERRFN_USERDATA_KEY, pool);
    cb = (tcn_callback_t *)data;
    if (cb) {
        JNIEnv *env;
        tcn_get_java_env(&env);
        if (!TCN_IS_NULL(env, cb->obj)) {
            (*(env))->CallVoidMethod(env, cb->obj, cb->mid[0],
                                P2J(pool), (jint)err,
                                (*(env))->NewStringUTF(env, description),
                                NULL);
        }
    }
}

static apr_status_t child_errfn_pool_cleanup(void *data)
{
    tcn_callback_t *cb = (tcn_callback_t *)data;

    if (data) {
        JNIEnv *env;
        tcn_get_java_env(&env);
        if (!TCN_IS_NULL(env, cb->obj)) {
            TCN_UNLOAD_CLASS(env, cb->obj);
        }
        free(cb);
    }
    return APR_SUCCESS;
}

TCN_IMPLEMENT_CALL(jlong, Procattr, create)(TCN_STDARGS,
                                            jlong pool)
{
    apr_pool_t *p = J2P(pool, apr_pool_t *);
    apr_procattr_t *attr;


    UNREFERENCED(o);
    TCN_THROW_IF_ERR(apr_procattr_create(&attr, p), attr);

cleanup:
    return P2J(attr);
}

TCN_IMPLEMENT_CALL(jint, Procattr, ioSet)(TCN_STDARGS,
                                          jlong attr, jint in,
                                          jint out, jint err)
{
    apr_procattr_t *a = J2P(attr, apr_procattr_t *);

    UNREFERENCED_STDARGS;
    return (jint)apr_procattr_io_set(a, (apr_int32_t)in,
                     (apr_int32_t)out, (apr_int32_t)err);
}

TCN_IMPLEMENT_CALL(jint, Procattr, childInSet)(TCN_STDARGS,
                                          jlong attr, jlong in,
                                          jlong parent)
{
    apr_procattr_t *a = J2P(attr, apr_procattr_t *);
    apr_file_t *f = J2P(in, apr_file_t *);
    apr_file_t *p = J2P(parent, apr_file_t *);

    UNREFERENCED_STDARGS;
    return (jint)apr_procattr_child_in_set(a, f, p);
}

TCN_IMPLEMENT_CALL(jint, Procattr, childOutSet)(TCN_STDARGS,
                                          jlong attr, jlong out,
                                          jlong parent)
{
    apr_procattr_t *a = J2P(attr, apr_procattr_t *);
    apr_file_t *f = J2P(out, apr_file_t *);
    apr_file_t *p = J2P(parent, apr_file_t *);

    UNREFERENCED_STDARGS;
    return (jint)apr_procattr_child_out_set(a, f, p);
}

TCN_IMPLEMENT_CALL(jint, Procattr, childErrSet)(TCN_STDARGS,
                                          jlong attr, jlong err,
                                          jlong parent)
{
    apr_procattr_t *a = J2P(attr, apr_procattr_t *);
    apr_file_t *f = J2P(err, apr_file_t *);
    apr_file_t *p = J2P(parent, apr_file_t *);

    UNREFERENCED_STDARGS;
    return (jint)apr_procattr_child_in_set(a, f, p);
}

TCN_IMPLEMENT_CALL(jint, Procattr, dirSet)(TCN_STDARGS,
                                           jlong attr,
                                           jstring dir)
{
    apr_status_t rv;
    apr_procattr_t *a = J2P(attr, apr_procattr_t *);
    TCN_ALLOC_CSTRING(dir);

    UNREFERENCED(o);

    rv = apr_procattr_dir_set(a, J2S(dir));
    TCN_FREE_CSTRING(dir);
    return (jint) rv;
}

TCN_IMPLEMENT_CALL(jint, Procattr, cmdtypeSet)(TCN_STDARGS,
                                          jlong attr, jint cmd)
{
    apr_procattr_t *a = J2P(attr, apr_procattr_t *);

    UNREFERENCED_STDARGS;
    return (jint)apr_procattr_cmdtype_set(a, (apr_int32_t)cmd);
}

TCN_IMPLEMENT_CALL(jint, Procattr, detachSet)(TCN_STDARGS,
                                          jlong attr, jint detach)
{
    apr_procattr_t *a = J2P(attr, apr_procattr_t *);

    UNREFERENCED_STDARGS;
    return (jint)apr_procattr_detach_set(a, (apr_int32_t)detach);
}

TCN_IMPLEMENT_CALL(jint, Procattr, errorCheckSet)(TCN_STDARGS,
                                          jlong attr, jint chk)
{
    apr_procattr_t *a = J2P(attr, apr_procattr_t *);

    UNREFERENCED_STDARGS;
    return (jint)apr_procattr_error_check_set(a, (apr_int32_t)chk);
}

TCN_IMPLEMENT_CALL(jint, Procattr, addrspaceSet)(TCN_STDARGS,
                                          jlong attr, jint addr)
{
    apr_procattr_t *a = J2P(attr, apr_procattr_t *);

    UNREFERENCED_STDARGS;
    return (jint)apr_procattr_addrspace_set(a, (apr_int32_t)addr);
}

TCN_IMPLEMENT_CALL(jlong, Proc, alloc)(TCN_STDARGS,
                                       jlong pool)
{
    apr_pool_t *p = J2P(pool, apr_pool_t *);
    apr_proc_t *proc;

    UNREFERENCED_STDARGS;
    proc = (apr_proc_t *)apr_pcalloc(p, sizeof(apr_proc_t));

    return P2J(proc);
}

#define MAX_ARGS_SIZE 1024
#define MAX_ENV_SIZE  1024

TCN_IMPLEMENT_CALL(jint, Proc, create)(TCN_STDARGS, jlong proc,
                                       jstring progname,
                                       jobjectArray args,
                                       jobjectArray env,
                                       jlong attr, jlong pool)
{
    apr_status_t rv;
    apr_pool_t *p = J2P(pool, apr_pool_t *);
    apr_procattr_t *a = J2P(attr, apr_procattr_t *);
    apr_proc_t *np = J2P(proc, apr_proc_t *);
    TCN_ALLOC_CSTRING(progname);
    char *s_args[MAX_ARGS_SIZE];
    char *s_env[MAX_ENV_SIZE];
    const char * const *pargs = NULL;
    const char * const *penv  = NULL;
    jsize as = 0;
    jsize es = 0;
    jsize i;

    UNREFERENCED(o);
    if (args)
        as = (*e)->GetArrayLength(e, args);
    if (env)
        es = (*e)->GetArrayLength(e, env);
    if (as > (MAX_ARGS_SIZE - 1) || es > (MAX_ENV_SIZE - 2)) {
        TCN_FREE_CSTRING(progname);
        return APR_EINVAL;
    }
    if (as) {
        for (i = 0; i < as; i++) {
            jstring str = (*e)->GetObjectArrayElement(e, args, i);
            s_args[i] = tcn_get_string(e, str);
            (*e)->DeleteLocalRef(e, str);
        }
        s_args[i] = NULL;
        pargs = (const char * const *)&s_args[0];
    }
    if (es) {
        for (i = 0; i < es; i++) {
            jstring str = (*e)->GetObjectArrayElement(e, env, i);
            s_env[i] = tcn_get_string(e, str);
            (*e)->DeleteLocalRef(e, str);
        }
#ifdef WIN32
        s_env[i++] = apr_psprintf(p, TCN_PARENT_IDE "=%d", getpid());
#endif
        s_env[i] = NULL;
        penv = (const char * const *)&s_env[0];
    }
#ifdef WIN32
    else {
        char pps[32];
        itoa(getpid(), pps, 10);
        SetEnvironmentVariable(TCN_PARENT_IDE, pps);
    }
#endif
    rv = apr_proc_create(np, J2S(progname), pargs,
                         penv, a, p);
#ifdef WIN32
    if (!es)
        SetEnvironmentVariable(TCN_PARENT_IDE, NULL);
#endif

    /* Free local resources */
    TCN_FREE_CSTRING(progname);
    for (i = 0; i < as; i++) {
        if (s_args[i])
            free(s_args[i]);
    }
    for (i = 0; i < es; i++) {
        if (s_env[i])
            free(s_env[i]);
    }
    return rv;
}

TCN_IMPLEMENT_CALL(jint, Proc, wait)(TCN_STDARGS, jlong proc,
                                     jintArray rvals, jint waithow)
{
    apr_status_t rv;
    apr_proc_t *p = J2P(proc, apr_proc_t *);
    int exitcode;
    apr_exit_why_e exitwhy;

    UNREFERENCED(o);

    rv = apr_proc_wait(p, &exitcode, &exitwhy, (apr_wait_how_e)waithow);
    if (rv == APR_SUCCESS && rvals) {
        jsize n = (*e)->GetArrayLength(e, rvals);
        if (n > 1) {
            jint *ints = (*e)->GetIntArrayElements(e, rvals, NULL);
            ints[0] = exitcode;
            ints[1] = exitwhy;
            (*e)->ReleaseIntArrayElements(e, rvals, ints, 0);
        }
    }
    return rv;
}

TCN_IMPLEMENT_CALL(jint, Proc, waitAllProcs)(TCN_STDARGS,
                                             jlong proc, jintArray rvals,
                                             jint waithow, jlong pool)
{
    apr_status_t rv;
    apr_proc_t *p = J2P(proc, apr_proc_t *);
    apr_pool_t *c = J2P(pool, apr_pool_t *);
    int exitcode;
    apr_exit_why_e exitwhy;

    UNREFERENCED(o);

    rv = apr_proc_wait_all_procs(p, &exitcode, &exitwhy,
                                 (apr_wait_how_e)waithow, c);
    if (rv == APR_SUCCESS && rvals) {
        jsize n = (*e)->GetArrayLength(e, rvals);
        if (n > 1) {
            jint *ints = (*e)->GetIntArrayElements(e, rvals, NULL);
            ints[0] = exitcode;
            ints[1] = exitwhy;
            (*e)->ReleaseIntArrayElements(e, rvals, ints, 0);
        }
    }
    return rv;
}

TCN_IMPLEMENT_CALL(jint, Proc, detach)(TCN_STDARGS, jint daemonize)
{

    UNREFERENCED_STDARGS;
#if defined(WIN32) || defined (NETWARE)
    UNREFERENCED(daemonize);
    return APR_ENOTIMPL;
#else
    return (jint)apr_proc_detach(daemonize);
#endif
}

TCN_IMPLEMENT_CALL(jint, Proc, kill)(TCN_STDARGS, jlong proc, jint sig)
{
    apr_proc_t *p = J2P(proc, apr_proc_t *);

    UNREFERENCED_STDARGS;
    return (jint)apr_proc_kill(p, (int)sig);
}

TCN_IMPLEMENT_CALL(void, Pool, noteSubprocess)(TCN_STDARGS, jlong pool,
                                               jlong proc, jint how)
{
    apr_proc_t *p = J2P(proc, apr_proc_t *);
    apr_pool_t *a = J2P(pool, apr_pool_t *);

    UNREFERENCED_STDARGS;
    apr_pool_note_subprocess(a, p, (apr_kill_conditions_e)how);
}

TCN_IMPLEMENT_CALL(jint, Proc, fork)(TCN_STDARGS,
                                     jlongArray proc,
                                     jlong pool)
{
    apr_status_t rv = APR_EINVAL;

#if APR_HAS_FORK
    apr_pool_t *p = J2P(pool, apr_pool_t *);
    apr_proc_t *f = apr_pcalloc(p, sizeof(apr_proc_t));

    UNREFERENCED(o);

    rv = apr_proc_fork(f, p);
    if (rv == APR_SUCCESS && proc) {
        jsize n = (*e)->GetArrayLength(e, proc);
        if (n > 0) {
            jlong *rp = (*e)->GetLongArrayElements(e, proc, NULL);
            rp[0] = P2J(f);
            (*e)->ReleaseLongArrayElements(e, proc, rp, 0);
        }
    }
#else
    UNREFERENCED_STDARGS;
    UNREFERENCED(proc);
    UNREFERENCED(pool);

#endif
    return rv;
}

TCN_IMPLEMENT_CALL(void, Procattr, errfnSet)(TCN_STDARGS, jlong attr,
                                             jlong pool, jobject obj)
{
    apr_procattr_t *a = J2P(attr, apr_procattr_t *);
    apr_pool_t *p = J2P(pool, apr_pool_t *);
    tcn_callback_t *cb = (tcn_callback_t *)malloc(sizeof(tcn_callback_t));
    jclass cls;

    UNREFERENCED(o);

    if (cb == NULL) {
       return;
    }
    cls = (*e)->GetObjectClass(e, obj);
    cb->obj    = (*e)->NewGlobalRef(e, obj);
    cb->mid[0] = (*e)->GetMethodID(e, cls, "callback", "(JILjava/lang/String;)V");

    apr_pool_userdata_setn(cb, ERRFN_USERDATA_KEY, child_errfn_pool_cleanup, p);
    apr_procattr_child_errfn_set(a, generic_child_errfn);

}

TCN_IMPLEMENT_CALL(jint, Procattr, userSet)(TCN_STDARGS,
                                            jlong attr,
                                            jstring username,
                                            jstring password)
{

#if ((APR_MAJOR_VERSION >= 1) && (APR_MINOR_VERSION >= 1))
    apr_status_t rv;
    apr_procattr_t *a = J2P(attr, apr_procattr_t *);
    TCN_ALLOC_CSTRING(username);
#if APR_PROCATTR_USER_SET_REQUIRES_PASSWORD
    TCN_ALLOC_CSTRING(password);
#else
    const char *cpassword = NULL;
#endif
    UNREFERENCED(o);

    rv = apr_procattr_user_set(a, J2S(username), J2S(password));
    TCN_FREE_CSTRING(username);
#if APR_PROCATTR_USER_SET_REQUIRES_PASSWORD
    TCN_FREE_CSTRING(password);
#endif
    return (jint) rv;
#else
    UNREFERENCED_STDARGS;
    UNREFERENCED(attr);
    UNREFERENCED(username);
    UNREFERENCED(password);

    return APR_ENOTIMPL;
#endif
}

TCN_IMPLEMENT_CALL(jint, Procattr, groupSet)(TCN_STDARGS,
                                             jlong attr,
                                             jstring group)
{

#if ((APR_MAJOR_VERSION >= 1) && (APR_MINOR_VERSION >= 1))
    apr_status_t rv;
    apr_procattr_t *a = J2P(attr, apr_procattr_t *);
    TCN_ALLOC_CSTRING(group);

    UNREFERENCED(o);

    rv = apr_procattr_group_set(a, J2S(group));
    TCN_FREE_CSTRING(group);
    return (jint) rv;
#else
    UNREFERENCED_STDARGS;
    UNREFERENCED(attr);
    UNREFERENCED(group);

    return APR_ENOTIMPL;
#endif
}
