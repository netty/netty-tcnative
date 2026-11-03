/*
 * Copyright 2026 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.netty.internal.tcnative;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import java.io.File;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class SSLCredentialIdTest {

    @BeforeAll
    public static void loadNativeLib() throws Exception {
        String testClassesRoot = SSLCredentialIdTest.class.getProtectionDomain().getCodeSource().getLocation().getFile();
        File[] directories = new File(testClassesRoot + File.separator + "META-INF" + File.separator + "native")
                .listFiles();
        if (directories == null || directories.length != 1) {
            throw new IllegalStateException("Could not find platform specific native directory");
        }
        String libName = System.mapLibraryName("netty_tcnative")
                // Fix the filename (this is needed for macOS).
                .replace(".dylib", ".jnilib");
        System.load(directories[0].getAbsoluteFile() + File.separator + libName);
        Library.initialize();
    }

    @Test
    public void newCredentialsHavePositiveDistinctIds() throws Exception {
        long x509 = SSLCredential.newX509();
        long delegated = SSLCredential.newDelegated();
        try {
            long x509Id = SSLCredential.getId(x509);
            long delegatedId = SSLCredential.getId(delegated);
            assertTrue(x509Id > 0);
            assertTrue(delegatedId > 0);
            assertNotEquals(x509Id, delegatedId);
        } finally {
            SSLCredential.free(x509);
            SSLCredential.free(delegated);
        }
    }

    @Test
    public void freshSslHasNoSelectedCredentialId() throws Exception {
        long ctx = SSLContext.make(SSL.SSL_PROTOCOL_TLSV1_2, SSL.SSL_MODE_SERVER);
        try {
            SSLContext.setRecordSelectedCredential(ctx, true);
            long ssl = SSL.newSSL(ctx, true);
            try {
                assertEquals(0, SSL.getSelectedCredentialId(ssl));
            } finally {
                SSL.freeSSL(ssl);
            }
        } finally {
            SSLContext.free(ctx);
        }
    }
}
