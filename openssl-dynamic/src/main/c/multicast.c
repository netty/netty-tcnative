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
 * @version $Id: multicast.c 1650120 2015-01-07 17:17:37Z schultz $
 */

#include "tcn.h"

TCN_IMPLEMENT_CALL(jint, Multicast, join)(TCN_STDARGS,
                                          jlong sock, jlong join,
                                          jlong iface, jlong source)
{
    tcn_socket_t *s = J2P(sock, tcn_socket_t *);
    apr_sockaddr_t *ja = J2P(join, apr_sockaddr_t *);
    apr_sockaddr_t *ia = J2P(iface, apr_sockaddr_t *);
    apr_sockaddr_t *sa = J2P(source, apr_sockaddr_t *);
    UNREFERENCED_STDARGS;
    return (jint)apr_mcast_join(s->sock, ja, ia, sa);
}

TCN_IMPLEMENT_CALL(jint, Multicast, leave)(TCN_STDARGS,
                                           jlong sock, jlong addr,
                                           jlong iface, jlong source)
{
    tcn_socket_t *s = J2P(sock, tcn_socket_t *);
    apr_sockaddr_t *aa = J2P(addr, apr_sockaddr_t *);
    apr_sockaddr_t *ia = J2P(iface, apr_sockaddr_t *);
    apr_sockaddr_t *sa = J2P(source, apr_sockaddr_t *);
    UNREFERENCED_STDARGS;
    return (jint)apr_mcast_leave(s->sock, aa, ia, sa);
}

TCN_IMPLEMENT_CALL(jint, Multicast, hops)(TCN_STDARGS,
                                          jlong sock, jint ttl)
{
    tcn_socket_t *s = J2P(sock, tcn_socket_t *);
    UNREFERENCED_STDARGS;
    return (jint)apr_mcast_hops(s->sock, (apr_byte_t)ttl);
}

TCN_IMPLEMENT_CALL(jint, Multicast, loopback)(TCN_STDARGS,
                                              jlong sock, jboolean opt)
{
    tcn_socket_t *s = J2P(sock, tcn_socket_t *);
    apr_byte_t on = 0;
    UNREFERENCED_STDARGS;
    if (opt)
        on = 1;
    return (jint)apr_mcast_loopback(s->sock, on);
}

TCN_IMPLEMENT_CALL(jint, Multicast, ointerface)(TCN_STDARGS,
                                                jlong sock, jlong iface)
{
    tcn_socket_t *s = J2P(sock, tcn_socket_t *);
    apr_sockaddr_t *ia = J2P(iface, apr_sockaddr_t *);
    UNREFERENCED_STDARGS;
    return (jint)apr_mcast_interface(s->sock, ia);
}
