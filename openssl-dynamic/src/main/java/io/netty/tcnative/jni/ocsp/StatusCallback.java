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

/**
 * Implementations of this interface are being called from JNI. Please notice that there
 * is a slight difference in the return values depending on if this is being used for
 * client or server side SSL. In particular the server side is a bit "poorly" documented
 * in the sense that {@link ServerStatusCode#SSL_TLSEXT_ERR_NOACK} will likely end the
 * handshake while it's not mentioned at all how to opt-out from the OCSP status request.
 * 
 * https://www.openssl.org/docs/man1.0.2/ssl/SSL_set_tlsext_status_type.html
 * 
 * @see ClientStatusCode
 * @see ServerStatusCode
 */
public interface StatusCallback {
    public int callback(long ssl);
}
