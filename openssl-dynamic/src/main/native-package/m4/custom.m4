dnl ---------------------------------------------------------------------------
dnl  Copyright 2014 The Netty Project
dnl
dnl  Licensed under the Apache License, Version 2.0 (the "License");
dnl  you may not use this file except in compliance with the License.
dnl  You may obtain a copy of the License at
dnl
dnl     http://www.apache.org/licenses/LICENSE-2.0
dnl
dnl  Unless required by applicable law or agreed to in writing, software
dnl  distributed under the License is distributed on an "AS IS" BASIS,
dnl  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
dnl  See the License for the specific language governing permissions and
dnl  limitations under the License.
dnl ---------------------------------------------------------------------------

AC_DEFUN([CUSTOM_M4_SETUP],
[
  dnl These macros were copied from tomcat-native/jni/native/build/

  dnl This macro was copied from tomcat-native/jni/native/build with slight modifications
  dnl - Fix autoconf warnings
  sinclude(m4/tcnative.m4)

  dnl Enable OpenSSL OCSP verification support.
  AC_ARG_ENABLE(ocsp,
  [AS_HELP_STRING([--enable-ocsp],[Turn on OpenSSL OCSP verification support])],
  [
    case "${enableval}" in
      yes)
         TCN_ADDTO(CFLAGS, [-DHAVE_OPENSSL_OCSP])
         AC_MSG_RESULT([Enabling OCSP verification support...])
         ;;
    esac
  ])

  dnl Check if the libs we link against are static
  TCN_CHECK_STATIC

  dnl Make sure OpenSSL is available in the system and set extra flags if we compile against a static version.
  if $use_openssl ; then
    TCN_CHECK_SSL_TOOLKIT
  fi

  dnl Update the compiler/linker flags to add OpenSSL to the build path.
  CFLAGS="$CFLAGS $TCN_OPENSSL_INC -D_LARGEFILE64_SOURCE"
  CXXFLAGS="$CXXFLAGS $TCN_OPENSSL_INC"
  LDFLAGS="$LDFLAGS $TCN_OPENSSL_LIBS"
  AC_SUBST(CFLAGS)
  AC_SUBST(CXXFLAGS)
  AC_SUBST(LDFLAGS)
])

