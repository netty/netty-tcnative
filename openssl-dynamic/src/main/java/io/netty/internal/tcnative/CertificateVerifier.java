/*
 * Copyright 2014 The Netty Project
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
 * Is called during handshake and hooked into openssl via {@code SSL_CTX_set_cert_verify_callback}.
 *
 * IMPORTANT: Implementations of this interface should be static as it is stored as a global reference via JNI. This
 *            means if you use an inner / anonymous class to implement this and also depend on the finalizer of the
 *            class to free up the SSLContext the finalizer will never run as the object is never GC, due the hard
 *            reference to the enclosing class. This will most likely result in a memory leak.
 */
public interface CertificateVerifier {
    int X509_V_OK = SSL.x509vOK();
    int X509_V_ERR_UNSPECIFIED = SSL.x509vErrUnspecified();
    int X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT = SSL.x509vErrUnableToGetIssuerCert();
    int X509_V_ERR_UNABLE_TO_GET_CRL = SSL.x509vErrUnableToGetCrl();
    int X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE = SSL.x509vErrUnableToDecryptCertSignature();
    int X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE = SSL.x509vErrUnableToDecryptCrlSignature();
    int X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY = SSL.x509vErrUnableToDecodeIssuerPublicKey();
    int X509_V_ERR_CERT_SIGNATURE_FAILURE = SSL.x509vErrCertSignatureFailure();
    int X509_V_ERR_CRL_SIGNATURE_FAILURE = SSL.x509vErrCrlSignatureFailure();
    int X509_V_ERR_CERT_NOT_YET_VALID = SSL.x509vErrCertNotYetValid();
    int X509_V_ERR_CERT_HAS_EXPIRED = SSL.x509vErrCertHasExpired();
    int X509_V_ERR_CRL_NOT_YET_VALID = SSL.x509vErrCrlNotYetValid();
    int X509_V_ERR_CRL_HAS_EXPIRED = SSL.x509vErrCrlHasExpired();
    int X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD = SSL.x509vErrErrorInCertNotBeforeField();
    int X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD = SSL.x509vErrErrorInCertNotAfterField();
    int X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD = SSL.x509vErrErrorInCrlLastUpdateField();
    int X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD = SSL.x509vErrErrorInCrlNextUpdateField();
    int X509_V_ERR_OUT_OF_MEM = SSL.x509vErrOutOfMem();
    int X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT = SSL.x509vErrDepthZeroSelfSignedCert();
    int X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN = SSL.x509vErrSelfSignedCertInChain();
    int X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = SSL.x509vErrUnableToGetIssuerCertLocally();
    int X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE  = SSL.x509vErrUnableToVerifyLeafSignature();
    int X509_V_ERR_CERT_CHAIN_TOO_LONG = SSL.x509vErrCertChainTooLong();
    int X509_V_ERR_CERT_REVOKED = SSL.x509vErrCertRevoked();
    int X509_V_ERR_INVALID_CA = SSL.x509vErrInvalidCa();
    int X509_V_ERR_PATH_LENGTH_EXCEEDED = SSL.x509vErrPathLengthExceeded();
    int X509_V_ERR_INVALID_PURPOSE = SSL.x509vErrInvalidPurpose();
    int X509_V_ERR_CERT_UNTRUSTED = SSL.x509vErrCertUntrusted();
    int X509_V_ERR_CERT_REJECTED = SSL.x509vErrCertRejected();
    int X509_V_ERR_SUBJECT_ISSUER_MISMATCH = SSL.x509vErrSubjectIssuerMismatch();
    int X509_V_ERR_AKID_SKID_MISMATCH = SSL.x509vErrAkidSkidMismatch();
    int X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH = SSL.x509vErrAkidIssuerSerialMismatch();
    int X509_V_ERR_KEYUSAGE_NO_CERTSIGN = SSL.x509vErrKeyUsageNoCertSign();
    int X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER = SSL.x509vErrUnableToGetCrlIssuer();
    int X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION = SSL.x509vErrUnhandledCriticalExtension();
    int X509_V_ERR_KEYUSAGE_NO_CRL_SIGN = SSL.x509vErrKeyUsageNoCrlSign();
    int X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION = SSL.x509vErrUnhandledCriticalCrlExtension();
    int X509_V_ERR_INVALID_NON_CA = SSL.x509vErrInvalidNonCa();
    int X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED = SSL.x509vErrProxyPathLengthExceeded();
    int X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE = SSL.x509vErrKeyUsageNoDigitalSignature();
    int X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED = SSL.x509vErrProxyCertificatesNotAllowed();
    int X509_V_ERR_INVALID_EXTENSION = SSL.x509vErrInvalidExtension();
    int X509_V_ERR_INVALID_POLICY_EXTENSION = SSL.x509vErrInvalidPolicyExtension();
    int X509_V_ERR_NO_EXPLICIT_POLICY = SSL.x509vErrNoExplicitPolicy();
    int X509_V_ERR_DIFFERENT_CRL_SCOPE = SSL.x509vErrDifferntCrlScope();
    int X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE = SSL.x509vErrUnsupportedExtensionFeature();
    int X509_V_ERR_UNNESTED_RESOURCE = SSL.x509vErrUnnestedResource();
    int X509_V_ERR_PERMITTED_VIOLATION = SSL.x509vErrPermittedViolation();
    int X509_V_ERR_EXCLUDED_VIOLATION  = SSL.x509vErrExcludedViolation();
    int X509_V_ERR_SUBTREE_MINMAX = SSL.x509vErrSubtreeMinMax();
    int X509_V_ERR_APPLICATION_VERIFICATION = SSL.x509vErrApplicationVerification();
    int X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE = SSL.x509vErrUnsupportedConstraintType();
    int X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX = SSL.x509vErrUnsupportedConstraintSyntax();
    int X509_V_ERR_UNSUPPORTED_NAME_SYNTAX = SSL.x509vErrUnsupportedNameSyntax();
    int X509_V_ERR_CRL_PATH_VALIDATION_ERROR = SSL.x509vErrCrlPathValidationError();
    int X509_V_ERR_PATH_LOOP = SSL.x509vErrPathLoop();
    int X509_V_ERR_SUITE_B_INVALID_VERSION = SSL.x509vErrSuiteBInvalidVersion();
    int X509_V_ERR_SUITE_B_INVALID_ALGORITHM = SSL.x509vErrSuiteBInvalidAlgorithm();
    int X509_V_ERR_SUITE_B_INVALID_CURVE = SSL.x509vErrSuiteBInvalidCurve();
    int X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM = SSL.x509vErrSuiteBInvalidSignatureAlgorithm();
    int X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED = SSL.x509vErrSuiteBLosNotAllowed();
    int X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256 = SSL.x509vErrSuiteBCannotSignP384WithP256();
    int X509_V_ERR_HOSTNAME_MISMATCH = SSL.x509vErrHostnameMismatch();
    int X509_V_ERR_EMAIL_MISMATCH = SSL.x509vErrEmailMismatch();
    int X509_V_ERR_IP_ADDRESS_MISMATCH = SSL.x509vErrIpAddressMismatch();
    int X509_V_ERR_DANE_NO_MATCH = SSL.x509vErrDaneNoMatch();

    /**
     * Returns {@code true} if the passed in certificate chain could be verified and so the handshake
     * should be successful, {@code false} otherwise.
     *
     * @param ssl               the SSL instance
     * @param x509              the {@code X509} certificate chain
     * @param authAlgorithm     the auth algorithm
     * @return verified         {@code true} if verified successful, {@code false} otherwise
     */
    int verify(long ssl, byte[][] x509, String authAlgorithm);
}
