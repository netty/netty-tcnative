/*
 * Copyright 2025 The Netty Project
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
 * SSL_CREDENTIAL management for BoringSSL.
 * 
 * This class provides methods to create and manage SSL_CREDENTIAL objects,
 * which are used to configure credentials for SSL/TLS connections in BoringSSL.
 * 
 * <p>This API is only supported when using BoringSSL. For usage instructions and detailed
 * documentation, see the 
 * <a href="https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_CREDENTIAL_free">BoringSSL SSL_CREDENTIAL documentation</a>.
 * </p>
 * 
 * <p>SSL_CREDENTIAL objects allow fine-grained control over certificate and private key
 * configuration, including support for multiple credentials, delegated credentials,
 * and SPAKE2+ authentication.</p>
 */
public final class SSLCredential {

    private SSLCredential() { }

    /**
     * Create a new X509 SSL_CREDENTIAL.
     * 
     * <p>This is a BoringSSL-specific feature. See 
     * <a href="https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_CREDENTIAL_new_x509">SSL_CREDENTIAL_new_x509</a>
     * for detailed documentation.</p>
     * 
     * @return the SSL_CREDENTIAL instance (SSL_CREDENTIAL *)
     * @throws Exception if an error occurred
     */
    public static native long newX509() throws Exception;

    /**
     * Increment the reference count of an SSL_CREDENTIAL.
     * 
     * <p>This is a BoringSSL-specific feature. See 
     * <a href="https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_CREDENTIAL_up_ref">SSL_CREDENTIAL_up_ref</a>
     * for detailed documentation.</p>
     * 
     * @param cred the SSL_CREDENTIAL instance (SSL_CREDENTIAL *)
     * @throws Exception if an error occurred
     */
    public static native void upRef(long cred) throws Exception;

    /**
     * Free an SSL_CREDENTIAL and decrement its reference count.
     * 
     * <p>This is a BoringSSL-specific feature. See 
     * <a href="https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_CREDENTIAL_free">SSL_CREDENTIAL_free</a>
     * for detailed documentation.</p>
     * 
     * @param cred the SSL_CREDENTIAL instance (SSL_CREDENTIAL *)
     * @throws Exception if an error occurred
     */
    public static native void free(long cred) throws Exception;

    /**
     * Set the private key for an SSL_CREDENTIAL.
     * 
     * <p>This is a BoringSSL-specific feature. See 
     * <a href="https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_CREDENTIAL_set1_private_key">SSL_CREDENTIAL_set1_private_key</a>
     * for detailed documentation.</p>
     * 
     * @param cred the SSL_CREDENTIAL instance (SSL_CREDENTIAL *)
     * @param key the private key (EVP_PKEY *)
     * @throws Exception if an error occurred
     */
    public static native void setPrivateKey(long cred, long key) throws Exception;

    /**
     * Set the certificate chain for an SSL_CREDENTIAL.
     * 
     * <p>This is a BoringSSL-specific feature. See 
     * <a href="https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_CREDENTIAL_set1_cert_chain">SSL_CREDENTIAL_set1_cert_chain</a>
     * for detailed documentation.</p>
     * 
     * @param cred the SSL_CREDENTIAL instance (SSL_CREDENTIAL *)
     * @param chain the certificate chain (STACK_OF(X509) *)
     * @throws Exception if an error occurred
     */
    public static native void setCertChain(long cred, long[] chain) throws Exception;

    /**
     * Set the OCSP response for an SSL_CREDENTIAL.
     * 
     * <p>This is a BoringSSL-specific feature. See 
     * <a href="https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_CREDENTIAL_set1_ocsp_response">SSL_CREDENTIAL_set1_ocsp_response</a>
     * for detailed documentation.</p>
     * 
     * @param cred the SSL_CREDENTIAL instance (SSL_CREDENTIAL *)
     * @param response the OCSP response bytes
     * @throws Exception if an error occurred
     */
    public static native void setOcspResponse(long cred, byte[] response) throws Exception;

    /**
     * Set the signing algorithm preferences for an SSL_CREDENTIAL.
     * 
     * <p>This is a BoringSSL-specific feature. See 
     * <a href="https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_CREDENTIAL_set1_signing_algorithm_prefs">SSL_CREDENTIAL_set1_signing_algorithm_prefs</a>
     * for detailed documentation.</p>
     * 
     * @param cred the SSL_CREDENTIAL instance (SSL_CREDENTIAL *)
     * @param prefs the signing algorithm preferences
     * @throws Exception if an error occurred
     */
    public static native void setSigningAlgorithmPrefs(long cred, int[] prefs) throws Exception;

    /**
     * Set the certificate properties for an SSL_CREDENTIAL.
     * 
     * <p>This is a BoringSSL-specific feature. See 
     * <a href="https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_CREDENTIAL_set1_certificate_properties">SSL_CREDENTIAL_set1_certificate_properties</a>
     * for detailed documentation.</p>
     * 
     * @param cred the SSL_CREDENTIAL instance (SSL_CREDENTIAL *)
     * @param properties the certificate properties
     * @throws Exception if an error occurred
     */
    public static native void setCertificateProperties(long cred, byte[] properties) throws Exception;

    /**
     * Set the signed certificate timestamp list for an SSL_CREDENTIAL.
     * 
     * <p>This is a BoringSSL-specific feature. See 
     * <a href="https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_CREDENTIAL_set1_signed_cert_timestamp_list">SSL_CREDENTIAL_set1_signed_cert_timestamp_list</a>
     * for detailed documentation.</p>
     * 
     * @param cred the SSL_CREDENTIAL instance (SSL_CREDENTIAL *)
     * @param sctList the signed certificate timestamp list
     * @throws Exception if an error occurred
     */
    public static native void setSignedCertTimestampList(long cred, byte[] sctList) throws Exception;

    /**
     * Set whether the issuer must match for an SSL_CREDENTIAL.
     * 
     * <p>This is a BoringSSL-specific feature. See 
     * <a href="https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_CREDENTIAL_set_must_match_issuer">SSL_CREDENTIAL_set_must_match_issuer</a>
     * for detailed documentation.</p>
     * 
     * @param cred the SSL_CREDENTIAL instance (SSL_CREDENTIAL *)
     * @param mustMatch {@code true} if issuer must match, {@code false} otherwise
     * @throws Exception if an error occurred
     */
    public static native void setMustMatchIssuer(long cred, boolean mustMatch) throws Exception;

    /**
     * Set the trust anchor ID for an SSL_CREDENTIAL.
     * 
     * <p>This is a BoringSSL-specific feature for trust anchor configuration. See 
     * <a href="https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_CREDENTIAL_set1_trust_anchor_id">SSL_CREDENTIAL_set1_trust_anchor_id</a>
     * for detailed documentation.</p>
     * 
     * @param cred the SSL_CREDENTIAL instance (SSL_CREDENTIAL *)
     * @param id the trust anchor ID
     * @throws Exception if an error occurred
     */
    public static native void setTrustAnchorId(long cred, byte[] id) throws Exception;

    /**
     * Create a new delegated SSL_CREDENTIAL.
     * 
     * <p>This is a BoringSSL-specific feature for delegated credential support. See 
     * <a href="https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_CREDENTIAL_new_delegated">SSL_CREDENTIAL_new_delegated</a>
     * for detailed documentation.</p>
     * 
     * @return the delegated SSL_CREDENTIAL instance (SSL_CREDENTIAL *)
     * @throws Exception if an error occurred
     */
    public static native long newDelegated() throws Exception;

    /**
     * Set the delegated credential for an SSL_CREDENTIAL.
     * 
     * <p>This is a BoringSSL-specific feature for delegated credential configuration. See 
     * <a href="https://commondatastorage.googleapis.com/chromium-boringssl-docs/ssl.h.html#SSL_CREDENTIAL_set1_delegated_credential">SSL_CREDENTIAL_set1_delegated_credential</a>
     * for detailed documentation.</p>
     * 
     * @param cred the SSL_CREDENTIAL instance (SSL_CREDENTIAL *)
     * @param delegatedCred the delegated credential bytes
     * @throws Exception if an error occurred
     */
    public static native void setDelegatedCredential(long cred, byte[] delegatedCred) throws Exception;

} 
