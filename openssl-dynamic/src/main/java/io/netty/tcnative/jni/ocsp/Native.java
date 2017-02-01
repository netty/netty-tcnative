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
package io.netty.tcnative.jni.ocsp;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;

/**
 * https://www.openssl.org/docs/man1.0.2/ssl/SSL_set_tlsext_status_type.html
 */
public class Native {

    private Native() {}

    /**
     * Registers a OCSP {@link StatusCallback} for the given {@link SSLContext}
     */
    public static native StatusCallback newCallback(long ctx, boolean client, StatusCallback callback);

    /**
     * Removes and frees the {@link StatusCallback}
     */
    public static native void freeCallback(long ctx, StatusCallback callback);

    /**
     * Enables or disables OCSP stapling on the given {@link SSLEngine}.
     *
     * @see StatusType
     */
    public static native boolean setType(long ssl, int type);

    /**
     * Sets the OCSP staple for the given {@link SSLEngine}. The {@code byte[]} is assumed
     * to be a valid OCSP staple as provided to you by the CA's OCSP responder. No further
     * validation will be applied and incorrect data will likely result in a drop of the
     * underlying connection.
     *
     * NOTE: This is only meant to be called for server {@link SSLEngine}s.
     */
    public static native boolean setResponse(long ssl, byte[] response);

    /**
     * Returns the OCSP staple for the given {@link SSLEngine} or {@code null} if the server
     * didn't provide a staple.
     *
     * NOTE: This is only meant to be called for client {@link SSLEngine}s.
     */
    public static native byte[] getResponse(long ssl);
}
