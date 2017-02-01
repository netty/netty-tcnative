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
 * These are the return values for {@link StatusCallback#callback(long)} if it's being called in server mode.
 * Please notice that {@link #SSL_TLSEXT_ERR_ALERT_WARNING} is undocumented.
 * 
 * https://www.openssl.org/docs/man1.0.2/ssl/SSL_set_tlsext_status_type.html
 * https://github.com/openssl/openssl/blob/master/include/openssl/tls1.h
 * 
 * @see StatusCallback
 */
public enum ServerStatusCode implements StatusCode {
    SSL_TLSEXT_ERR_OK(0),
    SSL_TLSEXT_ERR_ALERT_WARNING(1),
    SSL_TLSEXT_ERR_NOACK(2),
    SSL_TLSEXT_ERR_ALERT_FATAL(3);

    private final int value;

    private ServerStatusCode(int value) {
        this.value = value;
    }

    @Override
    public int value() {
        return value;
    }
}
