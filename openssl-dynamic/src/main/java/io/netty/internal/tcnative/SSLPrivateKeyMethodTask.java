/*
 * Copyright 2019 The Netty Project
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

abstract class SSLPrivateKeyMethodTask extends SSLTask {
    private static final byte[] EMPTY = new byte[0];
    private final SSLPrivateKeyMethod method;

    // Will be accessed via JNI.
    private byte[] resultBytes;

    SSLPrivateKeyMethodTask(long ssl, SSLPrivateKeyMethod method) {
        super(ssl);
        this.method = method;
    }

    @Override
    protected final int runTask(long ssl) {
        try {
            resultBytes = runTask(ssl, method);
            return 1;
        } catch (Exception e) {
            // Return 0 as this signals back that the operation failed.
            resultBytes = EMPTY;
            return 0;
        }
    }

    protected abstract byte[] runTask(long ssl, SSLPrivateKeyMethod method) throws Exception;
}
