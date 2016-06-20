package org.apache.tomcat.jni;

/**
 * Is called during handshake and hooked into openssl via {@code SSL_CTX_set_client_cert_cb}.
 *
 * IMPORTANT: Implementations of this interface should be static as it is stored as a global reference via JNI. This
 *            means if you use an inner / anonymous class to implement this and also depend on the finalizer of the
 *            class to free up the SSLContext the finalizer will never run as the object is never GC, due the hard
 *            reference to the enclosing class. This will most likely result in a memory leak.
 */
public interface CertificateRequestedCallback {

    /**
     * The types contained in the {@code keyTypeBytes} array.
     */
    // Extracted from https://github.com/openssl/openssl/blob/master/include/openssl/tls1.h
    byte TLS_CT_RSA_SIGN = 1;
    byte TLS_CT_DSS_SIGN = 2;
    byte TLS_CT_RSA_FIXED_DH = 3;
    byte TLS_CT_DSS_FIXED_DH = 4;
    byte TLS_CT_ECDSA_SIGN = 64;
    byte TLS_CT_RSA_FIXED_ECDH = 65;
    byte TLS_CT_ECDSA_FIXED_ECDH = 66;

    /**
     * Called during cert selection.
     *
     * Implementation should use {@link SSL#setCertificateBio(long, long, long, String)} and
     * {@link SSL#setCertificateChainBio(long, long, boolean)} to set the certificate and private key to use.
     *
     * @param ssl                       the SSL instance
     * @param keyTypeBytes              an array of the key types.
     * @param asn1DerEncodedPrincipals  the principals
     */
    void requested(long ssl, byte[] keyTypeBytes, byte[][] asn1DerEncodedPrincipals);
}
