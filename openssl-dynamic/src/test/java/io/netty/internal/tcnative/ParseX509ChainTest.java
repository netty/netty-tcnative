/*
 * Copyright 2026 The Netty Project
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

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class ParseX509ChainTest extends AbstractNativeTest {

    // Self-signed certificate for CN=localhost, valid until 2126.
    private static final String CERT = "-----BEGIN CERTIFICATE-----\n"
            + "MIIDCzCCAfOgAwIBAgIUJWpRnT7xrBRXt5NcmJZTXVwC6YQwDQYJKoZIhvcNAQEL\n"
            + "BQAwFDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MTAyMTE5MTgxMloYDzIxMjYw\n"
            + "OTI3MTkxODEyWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEB\n"
            + "AQUAA4IBDwAwggEKAoIBAQC7KJ5dHrVOaK1Cb7Joo5O6pECdh7uRoeQmZ5TFMfMZ\n"
            + "bAxzrul3LFFlrRS88zYDkqaUdPWulR3bUmMhnsjzbtbHNqXAE3uTGrG40SADLLWs\n"
            + "mbziOXmg6FeEHngL8yGVmX+lTIfT6EGhtIQHy+1DsXZdAGeYwsGDodP0gp/E8SoT\n"
            + "j4b2rY7TXHe5EVf365EE6dOdfitg4fKCvX6AffQui6060QxKcCY3X1OUKWQT5d4m\n"
            + "ImnyTWZVceBTMS50PFFj0vCG/MBXrM1zfRzMexfdeDjBL2vUSSKm6fcGIQOnw8rH\n"
            + "uYNAbiYeV83t0ouxlyyHOrUK+T/XnTzULECy3kkh+o9fAgMBAAGjUzBRMB0GA1Ud\n"
            + "DgQWBBSqOyhNqmRoIsCoAow9NHXTV8WNXzAfBgNVHSMEGDAWgBSqOyhNqmRoIsCo\n"
            + "Aow9NHXTV8WNXzAPBgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQAk\n"
            + "WG2yi4qNLHFoFvqwVX0a/w7t4HN/YXToaYsENIClqh5cCYH0RNH63lhyKTIAgc9d\n"
            + "v8j0HhMjnq0dXNlaHsW2NsxBG8ymza1mQ1iy0JXp2FwsmR5/4TYLQyoNizOvTcWG\n"
            + "Fa4yQdqZzOHTewdk9KIcJ/xQIF+dAEXN9/73gZmCjZlTKX63mi98RMQG5iGhyfaj\n"
            + "pu3r3Zwvcij4aEP+68OjK2QEMzi9Xqu3JQlEPdn7G6TgJYr2E2lxNFUV7HLLb2z/\n"
            + "PQThc+oA7pY3pU20ulnc2lGRDmOpzTte5CpeqnyXj84eCMQpSIU81s7ORMabNWGE\n"
            + "4plNfw7rB7n3hyYkXo3K\n"
            + "-----END CERTIFICATE-----\n";

    private static final String KEY = "-----BEGIN PRIVATE KEY-----\n"
            + "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7KJ5dHrVOaK1C\n"
            + "b7Joo5O6pECdh7uRoeQmZ5TFMfMZbAxzrul3LFFlrRS88zYDkqaUdPWulR3bUmMh\n"
            + "nsjzbtbHNqXAE3uTGrG40SADLLWsmbziOXmg6FeEHngL8yGVmX+lTIfT6EGhtIQH\n"
            + "y+1DsXZdAGeYwsGDodP0gp/E8SoTj4b2rY7TXHe5EVf365EE6dOdfitg4fKCvX6A\n"
            + "ffQui6060QxKcCY3X1OUKWQT5d4mImnyTWZVceBTMS50PFFj0vCG/MBXrM1zfRzM\n"
            + "exfdeDjBL2vUSSKm6fcGIQOnw8rHuYNAbiYeV83t0ouxlyyHOrUK+T/XnTzULECy\n"
            + "3kkh+o9fAgMBAAECggEAGBx8gmyhWO+dWpC/QEHKl2HvvRuua22a0ePIQ7tSoTTN\n"
            + "Sd3/z82S0vGAWXNPwxgSg8+pkws85HNxt/QX2VyvKMz+f4dDBUmMGc4/PIl3Ajxw\n"
            + "HAjhhXxJQgkW2BtDeV1kF2yLlx41zlpOJB7+exkSsZqKviBhA89GWhq18I5NKGW9\n"
            + "qeyVGAzwqXNeLvV6xVdqF01zFdZgp6EqTVVMoaDFrI4hM2CPiAjaUhp/oqYARMrN\n"
            + "Zb5DLhs1PmwsQMG8rU5XtgzXMCd2z0zDMzWnNMxz9QCYunDqm+yJQbZDvtttfy9t\n"
            + "ZwZKLsj1YgrA8XheIsKISJRi+CHdja5hqyavwLe98QKBgQDqhA4S17Z58arkJwLZ\n"
            + "0tuDdG9l/7CXV2Ojx+cXqTPeGgUdVj0Lnx7pBFPN0hROxhEHE4M1rNZNOMhx6Dl+\n"
            + "tXZvL+WyJkCYrZ8bYDTHzYMnEvCgYJ2OLk5+GMz/uchwbKvhmP3fAykWg1yOYH/M\n"
            + "RslixVZSQ35kVc7aGOi55bpqVwKBgQDMTe1ZGD10DJd+Fb90+t25zqeL8WpnwJim\n"
            + "tJlZSzxcBQ8SSvSGL5JseTCmFIezX15OBfHKpc5xTnUlywxzryYrZg1I7MlacFB7\n"
            + "fvy2DGPHQliyb5Zx2XK3KyMIeVyz74HNuiAp2BuzO0b+EWhn0/6dpYV4QEH3hpV0\n"
            + "I4PEjsTuOQKBgDaWjIwYSDJ0bXn0FrbLXStpM/EDJoDj556dDo60ZQ1i8yPUChul\n"
            + "a1WEG1nCd9WqRxZllVouJCgPeqEBFDkJVkslVAs22jxv1aRSrZaAoPG8d+Rs+N+6\n"
            + "qayyay1velepBA1cRmPd4XeLFkVR8w2CwKfMFX7KlSYXzzF3MNzsu4q7AoGBAJJu\n"
            + "5EiwjBNqlwaDFfgFevibexFd1pNIwuDxntwWhcu6wIOu/7ZR0JQ5BLp1CpJxL4mi\n"
            + "zxwdXWtu/Z45+9HK3wPKIIl9VhChYb4yVXUySi3eiu5R9rXhUkyg+XowalZ5u0K2\n"
            + "PilfwPLk8MxXs8p/cwaRRanb/KwqZWKZte8jGVlZAoGBAJ771RDYjiqW8xnRbFTz\n"
            + "rxCibirm6nkOYDCjxOXrdIMyAnGyfG3Z/q3btUQY4f13bldh01uEDO3MtRuGuqd2\n"
            + "LGeSAlLG6D9M/zHI+Rz/aQYC0quTZt4IkcWSPyuumwZrtv5stK4/soScqSIROoXR\n"
            + "xc21WTP7JcKLERB6iFiL9upH\n"
            + "-----END PRIVATE KEY-----\n";

    private static final int BUFFER_SIZE = 64 * 1024;

    @Test
    public void testNonCertificateBlocksAreNotAddedToTheChain() throws Exception {
        // PEM data that contains the certificate followed by its private key. Only the certificate must end up in
        // the chain, otherwise the private key is sent to the remote peer as part of the handshake.
        byte[][] peerChain = handshakeAndGetPeerCertChain(CERT + KEY);
        assertNotNull(peerChain);
        assertEquals(1, peerChain.length);
        assertArrayEquals(decodeCertificate(CERT), peerChain[0]);
    }

    /**
     * Runs a handshake in memory, using the given PEM data as certificate chain of the server, and returns the
     * certificate chain that the client received.
     */
    private static byte[][] handshakeAndGetPeerCertChain(String serverChainPem) throws Exception {
        long serverCtx = SSLContext.make(SSL.SSL_PROTOCOL_ALL, SSL.SSL_MODE_SERVER);
        long clientCtx = SSLContext.make(SSL.SSL_PROTOCOL_ALL, SSL.SSL_MODE_CLIENT);
        long client = 0;
        long server = 0;
        try {
            SSLContext.setVerify(clientCtx, SSL.SSL_CVERIFY_NONE, 10);
            // Trust the self-signed certificate (required by BoringSSL, which always uses the verifier).
            SSLContext.setCertVerifyCallback(clientCtx, new CertificateVerifier() {
                @Override
                public int verify(long ssl, byte[][] x509, String authAlgorithm) {
                    return X509_V_OK;
                }
            });

            client = SSL.newSSL(clientCtx, false);
            server = SSL.newSSL(serverCtx, true);
            long clientBio = SSL.bioNewByteBuffer(client, BUFFER_SIZE);
            long serverBio = SSL.bioNewByteBuffer(server, BUFFER_SIZE);
            setKeyMaterial(server, serverChainPem);

            ByteBuffer clientToServer = emptyBuffer();
            ByteBuffer serverToClient = emptyBuffer();
            boolean clientDone = false;
            boolean serverDone = false;
            for (int i = 0; i < 10 && !(clientDone && serverDone); i++) {
                clientDone = doHandshake(client, clientBio, serverToClient);
                clientToServer = append(clientToServer, flush(clientBio));
                serverDone = doHandshake(server, serverBio, clientToServer);
                serverToClient = append(serverToClient, flush(serverBio));
            }
            assertTrue(clientDone, "Client handshake did not complete");
            assertTrue(serverDone, "Server handshake did not complete");
            return SSL.getPeerCertChain(client);
        } finally {
            if (client != 0) {
                SSL.freeSSL(client);
            }
            if (server != 0) {
                SSL.freeSSL(server);
            }
            SSLContext.free(clientCtx);
            SSLContext.free(serverCtx);
        }
    }

    private static void setKeyMaterial(long ssl, String chainPem) throws Exception {
        long certBio = toBio(chainPem);
        long keyBio = toBio(KEY);
        long chain = 0;
        long key = 0;
        try {
            chain = SSL.parseX509Chain(certBio);
            key = SSL.parsePrivateKey(keyBio, null);
            SSL.setKeyMaterial(ssl, chain, key);
        } finally {
            SSL.freeX509Chain(chain);
            SSL.freePrivateKey(key);
            SSL.freeBIO(certBio);
            SSL.freeBIO(keyBio);
        }
    }

    private static byte[] decodeCertificate(String pem) {
        return Base64.getMimeDecoder().decode(pem
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", ""));
    }

    private static long toBio(String pem) throws Exception {
        byte[] bytes = pem.getBytes(StandardCharsets.US_ASCII);
        ByteBuffer buffer = ByteBuffer.allocateDirect(bytes.length);
        buffer.put(bytes);
        long bio = SSL.newMemBIO();
        assertEquals(bytes.length, SSL.bioWrite(bio, Buffer.address(buffer), bytes.length));
        return bio;
    }

    /**
     * Feeds all readable bytes of {@code in} to the {@code SSL} and advances the handshake.
     *
     * @return {@code true} if the handshake completed.
     */
    private static boolean doHandshake(long ssl, long bio, ByteBuffer in) {
        int length = in.remaining();
        SSL.bioSetByteBuffer(bio, Buffer.address(in) + in.position(), length, false);
        int result = SSL.doHandshake(ssl);
        in.position(in.position() + length - SSL.bioLengthByteBuffer(bio));
        SSL.bioClearByteBuffer(bio);
        if (result == 1) {
            return true;
        }
        int error = SSL.getError(ssl, result);
        if (error != SSL.SSL_ERROR_WANT_READ && error != SSL.SSL_ERROR_WANT_WRITE) {
            fail("Handshake failed: " + SSL.getLastError());
        }
        return false;
    }

    /**
     * Returns the bytes the {@code SSL} wrote during the handshake.
     */
    private static ByteBuffer flush(long bio) {
        ByteBuffer out = ByteBuffer.allocateDirect(BUFFER_SIZE);
        SSL.bioSetByteBuffer(bio, Buffer.address(out), out.capacity(), true);
        int written = SSL.bioFlushByteBuffer(bio);
        SSL.bioClearByteBuffer(bio);
        out.limit(written);
        return out;
    }

    private static ByteBuffer append(ByteBuffer remaining, ByteBuffer data) {
        // Never allocate an empty buffer, its address may be 0 which is rejected by bioSetByteBuffer.
        ByteBuffer buffer = ByteBuffer.allocateDirect(Math.max(1, remaining.remaining() + data.remaining()));
        buffer.put(remaining).put(data).flip();
        return buffer;
    }

    private static ByteBuffer emptyBuffer() {
        ByteBuffer buffer = ByteBuffer.allocateDirect(1);
        buffer.limit(0);
        return buffer;
    }
}
