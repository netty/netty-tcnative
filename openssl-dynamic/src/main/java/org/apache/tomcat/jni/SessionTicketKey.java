/*
 *  Licensed to the Apache Software Foundation (ASF) under one or more
 *  contributor license agreements.  See the NOTICE file distributed with
 *  this work for additional information regarding copyright ownership.
 *  The ASF licenses this file to You under the Apache License, Version 2.0
 *  (the "License"); you may not use this file except in compliance with
 *  the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.apache.tomcat.jni;

/**
 * Session Ticket Key
 */
public final class SessionTicketKey {
    /**
     * Size of session ticket key name
     */
    public static final int NAME_SIZE = 16;
    /**
     * Size of session ticket key HMAC key
     */
    public static final int HMAC_KEY_SIZE = 16;
    /**
     * Size of session ticket key AES key
     */
    public static final int AES_KEY_SIZE = 16;
    /**
     * Size of session ticker key
     */
    public static final int TICKET_KEY_SIZE = NAME_SIZE + HMAC_KEY_SIZE + AES_KEY_SIZE;

    private final byte[] name;
    private final byte[] hmacKey;
    private final byte[] aesKey;

    /**
     * Construct SesionTicketKey.
     * @param name the name of the session ticket key
     * @param hmacKey the HMAC key of the session ticket key
     * @param aesKey the AES key of the session ticket key
     */
    public SessionTicketKey(byte[] name, byte[] hmacKey, byte[] aesKey) {
        if (name == null || name.length != NAME_SIZE) {
            throw new IllegalArgumentException("Length of name should be 16");
        }
        if (hmacKey == null || hmacKey.length != HMAC_KEY_SIZE) {
            throw new IllegalArgumentException("Length of hmacKey should be 16");
        }
        if (aesKey == null || aesKey.length != AES_KEY_SIZE) {
            throw new IllegalArgumentException("Length of aesKey should be 16");
        }
        this.name = name;
        this.hmacKey = hmacKey;
        this.aesKey = aesKey;
    }

    /**
     * Get name.
     * @return the name of the session ticket key
     */
    public byte[] getName() {
        return name;
    }

    /**
     * Get HMAC key.
     * @return the HMAC key of the session ticket key
     */
    public byte[] getHmacKey() {
        return hmacKey;
    }

    /**
     * Get AES Key.
     * @return the AES key of the session ticket key
     */
    public byte[] getAesKey() {
        return aesKey;
    }
}
