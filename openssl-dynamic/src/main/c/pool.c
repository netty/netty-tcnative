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
 * @version $Id: pool.c 1442587 2013-02-05 13:49:48Z rjung $
 */

#include "tcn.h"

extern apr_pool_t *tcn_global_pool;


TCN_IMPLEMENT_CALL(jlong, Pool, create)(TCN_STDARGS, jlong parent)
{
    apr_pool_t *p = J2P(parent, apr_pool_t *);
    apr_pool_t *n;

    UNREFERENCED(o);
    /* Make sure our global pool is accessor for all pools */
    if (p == NULL)
        p = tcn_global_pool;
    TCN_THROW_IF_ERR(apr_pool_create(&n, p), n);
cleanup:
    return P2J(n);
}

TCN_IMPLEMENT_CALL(void, Pool, destroy)(TCN_STDARGS, jlong pool)
{
    apr_pool_t *p = J2P(pool, apr_pool_t *);
    UNREFERENCED_STDARGS;
    TCN_ASSERT(pool != 0);
    apr_pool_destroy(p);
}
