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

/*
 * Fallbacks for glibc-internal symbols that musl (Alpine Linux) does not export, so that
 * the single glibc-built shared library also loads under musl.
 *
 * These are deliberately compiled in on a GLIBC host -- the release images are CentOS
 * 6/7 -- so there must be no `#ifndef __GLIBC__` guard here or the definitions would be
 * compiled out of exactly the artifacts that need them. `weak` is what keeps them from
 * colliding with glibc's own definitions at link time; the linker satisfies references
 * from libgcc.a / APR with these definitions instead of leaving them undefined, which is
 * what removes the runtime failure.
 *
 * `visibility("default")` is required because the build uses -fvisibility=hidden
 * (see native-package/configure.ac). Hidden would be enough for the fully static
 * boringssl-static build, but openssl-dynamic links libapr/libcrypto dynamically and
 * those resolve at runtime.
 *
 * The one that is genuinely load-fatal is __getauxval: libgcc's AArch64 outline-atomics
 * probe (init_have_lse_atomics) calls it from an ELF init constructor, so an unresolved
 * __getauxval crashes the JVM with SIGSEGV inside dlopen rather than raising
 * UnsatisfiedLinkError. The rest are currently latent -- they sit in lazy PLT slots that
 * nothing calls -- and are provided so they cannot become fatal later.
 *
 * See https://github.com/netty/netty-tcnative/issues/907
 */

#ifdef __linux__

/* Guarded: the build already passes -D_LARGEFILE64_SOURCE (native-package/m4/custom.m4),
 * and redefining it is an error under -Werror. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif

#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/*
 * <sys/auxv.h> and getauxval() only exist from glibc 2.16. The x86_64 release image is
 * CentOS 6 (glibc 2.12), where including it is a fatal error, so this must stay conditional.
 */
#if defined(__has_include)
#  if __has_include(<sys/auxv.h>)
#    define TCN_HAVE_SYS_AUXV 1
#  endif
#endif
#ifdef TCN_HAVE_SYS_AUXV
#  include <sys/auxv.h>
#endif

#define TCN_MUSL_COMPAT __attribute__((weak, visibility("default")))

/*
 * Some glibc versions define these internal names as function-like MACROS rather than only
 * declaring them -- glibc 2.17's <string.h> does this for __strdup under _GNU_SOURCE, so a
 * definition here expands into the macro body and fails to compile ("expected identifier or
 * '(' before '__extension__'"). Undefine them first. Newer glibc (2.28, 2.35) only declares
 * them, so this is invisible there: it must not be removed just because one toolchain is
 * happy without it.
 */
#undef __getauxval
#undef __isinf
#undef __isnan
#undef __strdup
#undef fopen64

/*
 * glibc exports getauxval and the __-prefixed alias; musl exports only getauxval.
 * (gcompat supplies __getauxval, which is why tcnative 2.0.65 happened to work on Alpine:
 * it carried a DT_NEEDED on libcrypt.so.1, which Alpine symlinks to libgcompat.so.0.)
 *
 * Where getauxval() is unavailable -- glibc < 2.16, i.e. the CentOS 6 release image -- read
 * /proc/self/auxv directly rather than dropping the fallback. The alternative would leave the
 * artifact without it the moment a toolchain starts emitting __getauxval on x86_64, which is
 * how the aarch64 breakage happened in the first place.
 */
#ifndef TCN_HAVE_SYS_AUXV
static unsigned long tcn_auxv_lookup(unsigned long type) {
    unsigned long entry[2];
    unsigned long value = 0;
    int fd = open("/proc/self/auxv", O_RDONLY);
    if (fd < 0) {
        return 0;
    }
    while (read(fd, entry, sizeof(entry)) == (ssize_t) sizeof(entry)) {
        if (entry[0] == type) {
            value = entry[1];
            break;
        }
        if (entry[0] == 0) { /* AT_NULL terminates the vector */
            break;
        }
    }
    close(fd);
    return value;
}
#endif

TCN_MUSL_COMPAT unsigned long __getauxval(unsigned long type) {
#ifdef TCN_HAVE_SYS_AUXV
    return getauxval(type);
#else
    return tcn_auxv_lookup(type);
#endif
}

/*
 * musl 1.2.4 (Alpine 3.19+) removed the LFS64 aliases; off_t is unconditionally 64-bit
 * there, so forwarding to fopen is exact rather than a narrowing.
 */
TCN_MUSL_COMPAT FILE *fopen64(const char *path, const char *mode) {
    return fopen(path, mode);
}

/* glibc-internal math aliases emitted via APR's configure-era headers. */
TCN_MUSL_COMPAT int __isinf(double value) {
    return isinf(value);
}

TCN_MUSL_COMPAT int __isnan(double value) {
    return isnan(value);
}

/* glibc-internal alias APR links against directly. */
TCN_MUSL_COMPAT char *__strdup(const char *str) {
    return strdup(str);
}

#endif /* __linux__ */
