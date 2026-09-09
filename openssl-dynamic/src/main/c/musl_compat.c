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
#include <inttypes.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
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

/*
 * _FORTIFY_SOURCE entry points. Everything this project compiles passes -U_FORTIFY_SOURCE, so
 * none of our own objects reference these. Two archives we link but do not build can: on a
 * Debian-derived toolchain the packaged libstdc++.a (cp-demangle.o, floating_to_chars.o,
 * debug.o) and libgcc.a (_eprintf.o) are themselves fortified, and cp-demangle.o is pulled in
 * through the verbose terminate handler. The result is an undefined __sprintf_chk that makes
 * `ldd` fail on Alpine even though nothing on the load path calls it. Same shape as the rest
 * of this file: weak so glibc's own definition wins on glibc, defined here so musl has one.
 *
 * Semantics follow glibc: slen is the destination size, or (size_t) -1 when unknown.
 */
TCN_MUSL_COMPAT int __sprintf_chk(char *s, int flag, size_t slen, const char *format, ...) {
    va_list ap;
    int written;
    (void) flag;
    va_start(ap, format);
    if (slen == (size_t) -1) {
        written = vsprintf(s, format, ap);
    } else {
        written = vsnprintf(s, slen, format, ap);
    }
    va_end(ap);
    return written;
}

TCN_MUSL_COMPAT int __fprintf_chk(FILE *stream, int flag, const char *format, ...) {
    va_list ap;
    int written;
    (void) flag;
    va_start(ap, format);
    written = vfprintf(stream, format, ap);
    va_end(ap);
    return written;
}

/*
 * glibc 2.32+ exports this byte, and libstdc++ 11+ headers read it (ext/atomicity.h,
 * __gnu_cxx::__is_single_threaded) to skip atomic reference counting while a process is still
 * single-threaded. Any C++ compiled against such headers -- BoringSSL's libssl on a current
 * toolchain -- imports it as a plain data symbol, and musl has no such thing. Zero is the
 * conservative value: "not single-threaded", so the atomic path is always taken. On glibc the
 * libc definition wins as usual. The JVM is multi-threaded long before this library loads, so
 * the value could never legitimately be nonzero here anyway.
 */
TCN_MUSL_COMPAT char __libc_single_threaded = 0;

/*
 * glibc 2.38 made the integer parsers and the scanf family C23-conformant (binary "0b"
 * prefixes) under a new symbol version, and redirects every call to an __isoc23_* name
 * whenever _GNU_SOURCE is defined, whatever -std says. Anything built on glibc >= 2.38
 * (Ubuntu 24.04, Debian 13) imports them: APR (sockaddr.o, apr_strings.o), the packaged libstdc++.a
 * (eh_alloc.o, debug.o), and on x86_64 something else again brings in strtoull. musl exports
 * only the plain names. The whole family is covered here so the next builder does not find
 * the next member.
 *
 * The bodies must call the PLAIN symbols. A literal strtol() here is subject to the same
 * redirect, so on musl it would resolve to this very function and recurse. The asm labels
 * bind each reference to the unversioned name, which both libcs export.
 *
 * __restrict, not restrict: the Debian 7 image compiles with GCC 4.9, whose default is gnu90,
 * where `restrict` is not a keyword.
 */
extern long tcn_plain_strtol(const char *, char **, int) __asm__("strtol");
extern unsigned long tcn_plain_strtoul(const char *, char **, int) __asm__("strtoul");
extern long long tcn_plain_strtoll(const char *, char **, int) __asm__("strtoll");
extern unsigned long long tcn_plain_strtoull(const char *, char **, int) __asm__("strtoull");
extern intmax_t tcn_plain_strtoimax(const char *, char **, int) __asm__("strtoimax");
extern uintmax_t tcn_plain_strtoumax(const char *, char **, int) __asm__("strtoumax");
extern int tcn_plain_vsscanf(const char *, const char *, va_list) __asm__("vsscanf");

TCN_MUSL_COMPAT long __isoc23_strtol(const char *__restrict nptr, char **__restrict endptr, int base) {
    return tcn_plain_strtol(nptr, endptr, base);
}

TCN_MUSL_COMPAT unsigned long __isoc23_strtoul(const char *__restrict nptr, char **__restrict endptr, int base) {
    return tcn_plain_strtoul(nptr, endptr, base);
}

TCN_MUSL_COMPAT long long __isoc23_strtoll(const char *__restrict nptr, char **__restrict endptr, int base) {
    return tcn_plain_strtoll(nptr, endptr, base);
}

TCN_MUSL_COMPAT unsigned long long __isoc23_strtoull(const char *__restrict nptr, char **__restrict endptr, int base) {
    return tcn_plain_strtoull(nptr, endptr, base);
}

TCN_MUSL_COMPAT intmax_t __isoc23_strtoimax(const char *__restrict nptr, char **__restrict endptr, int base) {
    return tcn_plain_strtoimax(nptr, endptr, base);
}

TCN_MUSL_COMPAT uintmax_t __isoc23_strtoumax(const char *__restrict nptr, char **__restrict endptr, int base) {
    return tcn_plain_strtoumax(nptr, endptr, base);
}

TCN_MUSL_COMPAT int __isoc23_vsscanf(const char *__restrict str, const char *__restrict format, va_list ap) {
    return tcn_plain_vsscanf(str, format, ap);
}

TCN_MUSL_COMPAT int __isoc23_sscanf(const char *__restrict str, const char *__restrict format, ...) {
    va_list ap;
    int matched;
    va_start(ap, format);
    matched = tcn_plain_vsscanf(str, format, ap);
    va_end(ap);
    return matched;
}

/*
 * glibc 2.35 added _dl_find_object, and libgcc_eh.a from gcc 12 on (unwind-dw2-fde-dip.o)
 * calls it to locate a frame's .eh_frame when unwinding. musl has no equivalent. Returning
 * -1 means "no object found": the unwinder then reports no FDE and a C++ exception would
 * terminate instead of propagating. Nothing here throws - BoringSSL compiles its C++ with
 * -fno-exceptions, APR and this module are C - so the only observable effect is that the
 * symbol resolves. Declared with a void * result on purpose: the real struct only exists in
 * glibc >= 2.35 headers and the release image is glibc 2.12.
 */
TCN_MUSL_COMPAT int _dl_find_object(void *address, void *result) {
    (void) address;
    (void) result;
    return -1;
}

#endif /* __linux__ */
