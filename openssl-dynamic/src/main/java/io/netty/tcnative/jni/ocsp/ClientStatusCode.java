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
 * These are the return values for {@link StatusCallback#callback(long)} if it's being called in client mode.
 * 
 * https://www.openssl.org/docs/man1.0.2/ssl/SSL_set_tlsext_status_type.html
 * 
 * @see StatusCallback
 */
public enum ClientStatusCode implements StatusCode {
    ERROR(-1),
    NACK(0),
    ACK(1);

    private final int value;

    private ClientStatusCode(int value) {
        this.value = value;
    }

    @Override
    public int value() {
        return value;
    }
}
