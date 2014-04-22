package org.apache.tomcat.jni.ssl;

import org.apache.tomcat.jni.Pool;
import org.apache.tomcat.jni.SSL;
import org.apache.tomcat.jni.SSLContext;

/**
 * Encapsulates an OpenSSL SSL_CTX object.
 */
public class SSLContextHolder {
    private long sslContext = 0L;

    /**
     * Create an SSLContext from the given SSLConfiguration
     * @param sslConfiguration the SSLConfiguration
     */
    public SSLContextHolder(long pool, SSLConfiguration sslConfiguration) throws Exception {
        synchronized (SSLContextHolder.class) {
            sslContext = SSLContext.make(pool,
                                         SSL.SSL_PROTOCOL_ALL,
                                         SSL.SSL_MODE_SERVER);

            SSLContext.setOptions(sslContext, SSL.SSL_OP_ALL);
            SSLContext.setOptions(sslContext, SSL.SSL_OP_NO_SSLv2);
            SSLContext.setOptions(sslContext, SSL.SSL_OP_CIPHER_SERVER_PREFERENCE);
            SSLContext.setOptions(sslContext, SSL.SSL_OP_SINGLE_ECDH_USE);
            SSLContext.setOptions(sslContext, SSL.SSL_OP_SINGLE_DH_USE);
            SSLContext.setOptions(sslContext, SSL.SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

            /* List the ciphers that the client is permitted to negotiate. */
            SSLContext.setCipherSuite(sslContext, sslConfiguration.getCipherSpec());

            /* Set certificate verification policy. */
            SSLContext.setVerify(sslContext, SSL.SSL_CVERIFY_NONE, 10);

            final String certFilename = sslConfiguration.getCertPath();
            final String certChainFilename = sslConfiguration.getCaPath();

            /* Load the certificate file and private key. */
            if (!SSLContext.setCertificate(sslContext,
                                           certFilename,
                                           sslConfiguration.getKeyPath(),
                                           sslConfiguration.getKeyPassword(),
                                           SSL.SSL_AIDX_RSA)) {
                throw new Exception("Failed to set certificate file '" + certFilename + "': " +
                                    SSL.getLastError());
            }

            /* Load certificate chain file, if specified */
            if (certChainFilename != null && certChainFilename.length() > 0) {
                /* If named same as cert file, we must skip the first cert since it was loaded above. */
                boolean skipFirstCert = certFilename.equals(certChainFilename);

                if (!SSLContext.setCertificateChainFile(sslContext, certChainFilename, skipFirstCert)) {
                  throw new Exception("Failed to set certificate chain file '" + certChainFilename + "': " +
                                      SSL.getLastError());
                }
            }

            /* Set next protocols for next protocol negotiation extension, if specified */
            String nextProtos = sslConfiguration.getNextProtos();
            if (nextProtos != null && nextProtos.length() > 0) {
                SSLContext.setNextProtos(sslContext, nextProtos);
            }
        }
    }

    protected long getSslContext() {
        return sslContext;
    }
}
