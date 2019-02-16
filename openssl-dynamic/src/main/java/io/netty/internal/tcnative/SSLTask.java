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

/**
 * A SSL related task that will be returned by {@link SSL#getTask(int)}
 */
abstract class SSLTask implements Runnable {

    private final long ssl;

    // These fields are accessed via JNI.
    private int returnValue;
    private boolean complete;

    protected SSLTask(long ssl) {
        // It is important that this constructor never throws. Be sure to not change this!
        this.ssl = ssl;
    }

    @Override
    public final void run() {
        if (!complete) {
            complete = true;
            returnValue = runTask(ssl);
        }
    }

    /**
     * Run the task and return the return value that should be passed back to OpenSSL.
     */
    protected abstract int runTask(long ssl);
}
