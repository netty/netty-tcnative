# ---------------------------------------------------------------------------
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
# ---------------------------------------------------------------------------

## --------------------------------
## Initialization macros.
## --------------------------------
AC_PREREQ([2.61])
AC_INIT([@PROJECT_NAME@], [@VERSION@])
AC_CONFIG_AUX_DIR([autotools])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/error.c])
#AC_CONFIG_SRCDIR([@FIRST_SOURCE_FILE@])
AC_CONFIG_HEADERS([src/config.h])
AC_CANONICAL_HOST
AC_CANONICAL_SYSTEM

${CFLAGS="-O3 -Werror -fno-omit-frame-pointer"}

## -----------------------------------------------
## Application Checks
## -----------------------------------------------
AC_PROG_CC
AC_PROG_INSTALL
# Make AM_PROG_AR work before automake 1.12
m4_ifdef([AM_PROG_AR], [AM_PROG_AR])
AC_PROG_LIBTOOL([disable-static])

## -----------------------------------------------
## API Checks
## -----------------------------------------------
WITH_JNI_JDK

CUSTOM_M4_SETUP

WITH_OSX_UNIVERSAL

CFLAGS="$CFLAGS $JNI_EXTRA_CFLAGS"
AC_SUBST(CFLAGS)
CXXFLAGS="$CXXFLAGS $JNI_EXTRA_CFLAGS"
AC_SUBST(CXXFLAGS)
LDFLAGS="$LDFLAGS $JNI_EXTRA_LDFLAGS -release @VERSION@"
AC_SUBST(LDFLAGS)

## -----------------------------------------------------
## Generate the files
## -----------------------------------------------------
AM_INIT_AUTOMAKE([subdir-objects no-dependencies -Wall foreign])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

echo "
  ($PACKAGE_NAME) version $PACKAGE_VERSION
  Prefix.........: $prefix
  C Compiler.....: $CC $CFLAGS
  Linker.........: $LD $LDFLAGS $LIBS
"
