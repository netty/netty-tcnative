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
package org.apache.tomcat.jni;

/**
 * Is called during handshake and hooked into openssl via {@code SSL_CTX_set_cert_verify_callback}.
 *
 * IMPORTANT: Implementations of this interface should be static as it is stored as a global reference via JNI. This
 *            means if you use an inner / anonymous class to implement this and also depend on the finalizer of the
 *            class to free up the SSLContext the finalizer will never run as the object is never GC, due the hard
 *            reference to the enclosing class. This will most likely result in a memory leak.
 */
public interface CertificateVerifier {

    int X509_V_OK = 0;
    int X509_V_ERR_UNSPECIFIED = 1;
    int X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT = 2;
    int X509_V_ERR_UNABLE_TO_GET_CRL = 3;
    int X509_V_ERR_UNABLE_TO_DECRYPT_CERT_SIGNATURE = 4;
    int X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE = 5;
    int X509_V_ERR_UNABLE_TO_DECODE_ISSUER_PUBLIC_KEY = 6;
    int X509_V_ERR_CERT_SIGNATURE_FAILURE = 7;
    int X509_V_ERR_CRL_SIGNATURE_FAILURE = 8;
    int X509_V_ERR_CERT_NOT_YET_VALID = 9;
    int X509_V_ERR_CERT_HAS_EXPIRED = 10;
    int X509_V_ERR_CRL_NOT_YET_VALID = 11;
    int X509_V_ERR_CRL_HAS_EXPIRED = 12;
    int X509_V_ERR_ERROR_IN_CERT_NOT_BEFORE_FIELD = 13;
    int X509_V_ERR_ERROR_IN_CERT_NOT_AFTER_FIELD = 14;
    int X509_V_ERR_ERROR_IN_CRL_LAST_UPDATE_FIELD = 15;
    int X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD = 16;
    int X509_V_ERR_OUT_OF_MEM = 17;
    int X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT = 18;
    int X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN = 19;
    int X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 20;
    int X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE  = 21;
    int X509_V_ERR_CERT_CHAIN_TOO_LONG = 22;
    int X509_V_ERR_CERT_REVOKED = 23;
    int X509_V_ERR_INVALID_CA = 24;
    int X509_V_ERR_PATH_LENGTH_EXCEEDED = 25;
    int X509_V_ERR_INVALID_PURPOSE = 26;
    int X509_V_ERR_CERT_UNTRUSTED = 27;
    int X509_V_ERR_CERT_REJECTED = 28;
    int X509_V_ERR_SUBJECT_ISSUER_MISMATCH = 29;
    int X509_V_ERR_AKID_SKID_MISMATCH = 30;
    int X509_V_ERR_AKID_ISSUER_SERIAL_MISMATCH = 31;
    int X509_V_ERR_KEYUSAGE_NO_CERTSIGN = 32;
    int X509_V_ERR_UNABLE_TO_GET_CRL_ISSUER = 33;
    int X509_V_ERR_UNHANDLED_CRITICAL_EXTENSION = 34;
    int X509_V_ERR_KEYUSAGE_NO_CRL_SIGN = 35;
    int X509_V_ERR_UNHANDLED_CRITICAL_CRL_EXTENSION = 36;
    int X509_V_ERR_INVALID_NON_CA = 37;
    int X509_V_ERR_PROXY_PATH_LENGTH_EXCEEDED = 38;
    int X509_V_ERR_KEYUSAGE_NO_DIGITAL_SIGNATURE = 39;
    int X509_V_ERR_PROXY_CERTIFICATES_NOT_ALLOWED = 40;
    int X509_V_ERR_INVALID_EXTENSION = 41;
    int X509_V_ERR_INVALID_POLICY_EXTENSION = 42;
    int X509_V_ERR_NO_EXPLICIT_POLICY = 43;
    int X509_V_ERR_DIFFERENT_CRL_SCOPE = 44;
    int X509_V_ERR_UNSUPPORTED_EXTENSION_FEATURE = 45;
    int X509_V_ERR_UNNESTED_RESOURCE = 46;
    int X509_V_ERR_PERMITTED_VIOLATION = 47;
    int X509_V_ERR_EXCLUDED_VIOLATION  = 48;
    int X509_V_ERR_SUBTREE_MINMAX = 49;
    int X509_V_ERR_APPLICATION_VERIFICATION = 50;
    int X509_V_ERR_UNSUPPORTED_CONSTRAINT_TYPE = 51;
    int X509_V_ERR_UNSUPPORTED_CONSTRAINT_SYNTAX = 52;
    int X509_V_ERR_UNSUPPORTED_NAME_SYNTAX = 53;
    int X509_V_ERR_CRL_PATH_VALIDATION_ERROR = 54;
    int X509_V_ERR_PATH_LOOP = 55;
    int X509_V_ERR_SUITE_B_INVALID_VERSION = 56;
    int X509_V_ERR_SUITE_B_INVALID_ALGORITHM = 57;
    int X509_V_ERR_SUITE_B_INVALID_CURVE = 58;
    int X509_V_ERR_SUITE_B_INVALID_SIGNATURE_ALGORITHM = 59;
    int X509_V_ERR_SUITE_B_LOS_NOT_ALLOWED = 60;
    int X509_V_ERR_SUITE_B_CANNOT_SIGN_P_384_WITH_P_256 = 61;
    int X509_V_ERR_HOSTNAME_MISMATCH = 62;
    int X509_V_ERR_EMAIL_MISMATCH = 63;
    int X509_V_ERR_IP_ADDRESS_MISMATCH = 64;
    int X509_V_ERR_DANE_NO_MATCH = 65;

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
