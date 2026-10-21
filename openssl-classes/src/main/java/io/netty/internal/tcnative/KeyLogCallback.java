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
 * Callback hooked into {@code SSL_CTX_set_keylog_callback}.
 * <p>
 * It is supported by BoringSSL, AWS-LC and OpenSSL 1.1.1 or later, but not by LibreSSL.
 * <p>
 * Each line uses the NSS Key Log Format (the format of {@code SSLKEYLOGFILE}). This is intended for TLS debugging
 * with tools like <a href="https://wiki.wireshark.org/TLS">Wireshark</a>.
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
 *
 * @see SSLContext#setKeyLogCallback(long, KeyLogCallback)
 * @see <a href="https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_CTX_set_keylog_callback">BoringSSL</a>
 * @see <a href="https://docs.openssl.org/master/man3/SSL_CTX_set_keylog_callback/">OpenSSL</a>
 */
public interface KeyLogCallback {
    /**
     * Called when a new key log line is emitted.
     * <p>
     * <strong>Warning:</strong> The log output will contain secret key material, and can be used to decrypt
     * TLS sessions! The log output should be handled with the same care given to the private keys.
     * <p>
     * This method is expected to never throw any {@link Throwable}: anything it throws is cleared and ignored.
     *
     * @param ssl the native {@code SSL*} pointer of the connection the line belongs to.
     * @param line a single line in the NSS Key Log Format, without a trailing newline.
     */
    void handle(long ssl, byte[] line);
}
