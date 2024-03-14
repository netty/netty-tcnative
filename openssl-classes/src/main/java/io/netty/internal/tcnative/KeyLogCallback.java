/*
 * Copyright 2024 The Netty Project
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
package io.netty.internal.tcnative;

/**
 * Callback hooked into <a href="https://github.com/google/boringssl/blob/master/include/openssl/ssl.h#L4379">SSL_CTX_set_keylog_callback</a>
 * This is intended for TLS debugging with tools like <a href="https://wiki.wireshark.org/TLS">Wireshark</a>.
 * For instance, a valid {@code SSLKEYLOGFILE} implementation could look like this:
 * <pre>{@code
 *         final PrintStream out = new PrintStream("~/tls.sslkeylog_file");
 *         SSLContext.setKeyLogCallback(ctxPtr, new KeyLogCallback() {
 *             @Override
 *             public void handle(long ssl, byte[] line) {
 *                 out.println(new String(line));
 *             }
 *         });
 * }</pre>
 * <p>
 * <strong>Warning:</strong> The log output will contain secret key material, and can be used to decrypt
 * TLS sessions! The log output should be handled with the same care given to the private keys.
 */
public interface KeyLogCallback {
    /**
     * Called when a new key log line is emitted.
     * <p>
     * <strong>Warning:</strong> The log output will contain secret key material, and can be used to decrypt
     * TLS sessions! The log output should be handled with the same care given to the private keys.
     *
     * @param ssl  the SSL instance
     * @param line an array of the key types on client-mode or {@code null} on server-mode.
     *
     */
    void handle(long ssl, byte[] line);
}
