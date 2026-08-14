#!/bin/sh
# Fail the build if a Linux native library would not load under musl (Alpine).
#
# The released Linux artifacts are glibc-built, but the same jar is expected to work on musl --
# there is no -musl classifier and no plan for one. That silently stopped being true after
# 2.0.65 and went unnoticed for eight releases (netty-tcnative#907, #152, netty#15112). Two
# distinct things break it, and neither is visible on a glibc builder:
#
#  1. A DT_NEEDED entry musl cannot resolve. musl's loader satisfies a fixed set of libc alias
#     names from musl itself, without ever touching the filesystem -- ldso/dynlink.c:
#         static const char reserved[] = "c.pthread.rt.m.dl.util.xnet.";
#     Everything else is a real file lookup. "ld-linux-<arch>.so.*" does not begin with "lib",
#     so it is looked up as a file and is simply absent on Alpine.
#
#  2. An undefined GLOBAL symbol musl does not export -- e.g. __getauxval, where musl has only
#     getauxval. That one is referenced from libgcc's init_have_lse_atomics, an .init_array
#     constructor that runs during dlopen, so on aarch64 the JVM dies with SIGSEGV inside
#     JVM_LoadLibrary instead of raising a catchable UnsatisfiedLinkError -- the application
#     cannot fall back to the JDK provider. Undefined WEAK symbols are fine; they resolve to 0.
#
# Only (1) and a regression of the musl_compat.c fallbacks are treated as errors. A general
# undefined-GLOBAL scan is reported but does not fail the build, because it cannot decide
# reachability: with lazy PLT binding an unresolved symbol that nothing calls never aborts.
# netty-transport-native-epoll is the proof -- it imports __xpg_strerror_r as an undefined
# GLOBAL and nevertheless loads and runs on bare Alpine on both architectures, because the
# symbol sits on an error path. Failing on that shape would make this check cry wolf. What it
# cannot rule out is the constructor case above, which is why the runtime check on real Alpine
# is a separate and non-optional part of the verification.
#
# Runs on the build host with binutils only, so it also covers the cross-compiled aarch64
# artifact, which is built with -DskipTests and is otherwise never verified at all. Bound to the
# package phase (not verify) because every build, deploy and staging command is "clean package
# <plugin>:goal" and stops before verify; unlike surefire, antrun is unaffected by -DskipTests.
#
# usage: check_musl_compat.sh <path-to-.so> [static|dynamic]
# env:   TOOL_PREFIX  binutils prefix for cross-built objects, e.g. aarch64-none-linux-gnu-
# exit:  0 ok / 1 would fail on musl / 2 usage error
#
# See docs/musl-compatibility.md for the full rules, the verification ladder and the dead ends.

set -u

SO="${1:-}"
PROFILE="${2:-static}"
if [ -z "$SO" ] || [ ! -f "$SO" ]; then
  echo "usage: $0 <path-to-.so> [static|dynamic]" >&2
  exit 2
fi

READELF="${TOOL_PREFIX:-}readelf"
NM="${TOOL_PREFIX:-}nm"

# DT_NEEDED names musl resolves internally (the reserved[] stems above). Nothing else is allowed
# for boringssl-static -- notably not libgcc_s.so.1: `gcc_s.` is not a reserved stem, so it is a
# real file lookup, and Alpine JDK images disagree about shipping the `libgcc` package that would
# satisfy it (eclipse-temurin does, amazoncorretto and many vendor images do not). The build links
# libgcc.a/libgcc_eh.a statically instead; see boringssl-static/pom.xml and check 4 below.
RESERVED='^lib(c|pthread|rt|m|dl|util|xnet)\.so'
case "$PROFILE" in
  static)
    # boringssl-static links everything else statically, so nothing beyond RESERVED is allowed.
    # Must be a pattern that cannot match rather than '': `grep -Eq ""` matches every input and
    # would silently disable check 1 altogether.
    EXTRA='^$' ;;
  dynamic)
    # openssl-dynamic deliberately links against the system OpenSSL and APR. Those are not
    # musl-reserved, so this artifact needs `apk add openssl apr` on Alpine -- that is by design
    # and is not what this check is about. ld-linux is still never acceptable.
    # NOTE: this branch currently has no caller anywhere in the tree (openssl-dynamic is not
    # gated), so its libgcc_s.so.1 allowance is untested and deliberately left as-is.
    EXTRA='^(libgcc_s\.so\.1|libssl\.so|libcrypto\.so|libapr-1\.so)' ;;
  *)
    echo "$0: unknown profile '$PROFILE' (expected static or dynamic)" >&2
    exit 2 ;;
esac

# The __-prefixed symbols musl really does export. Regenerate on any Alpine machine with:
#   nm -D --defined-only /lib/ld-musl-$(uname -m).so.1 | awk '$3 ~ /^__/ { print $3 }' | sort -u
MUSL_UNDERSCORE_SYMS='
__assert_fail __cxa_atexit __cxa_finalize __cxa_thread_atexit_impl
__ctype_b_loc __ctype_get_mb_cur_max __ctype_tolower_loc __ctype_toupper_loc
__errno_location __fpclassify __fpclassifyf __fpclassifyl
__h_errno_location __libc_start_main __signbit __signbitf __signbitl
__stack_chk_fail __stack_chk_guard __tls_get_addr
'

# The fallbacks openssl-dynamic/src/main/c/musl_compat.c defines. Asserting these are *defined*
# rather than undefined catches the compatibility file being dropped or excluded from the link.
MUSL_COMPAT_SYMS='__getauxval fopen64 __isinf __isnan __strdup'

rc=0
MACHINE=$("$READELF" -h "$SO" 2>/dev/null | sed -n 's/.*Machine:[[:space:]]*//p')
echo "== musl compatibility check: $SO"
echo "   machine=$MACHINE profile=$PROFILE"

NEEDED=$("$READELF" -d "$SO" 2>/dev/null | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p')

# ---------------------------------------------------------------- 1. DT_NEEDED allowlist
BAD_NEEDED=""
for lib in $NEEDED; do
  if printf '%s' "$lib" | grep -Eq "$RESERVED" || printf '%s' "$lib" | grep -Eq "$EXTRA"; then
    continue
  fi
  BAD_NEEDED="$BAD_NEEDED $lib"
done
if [ -n "$BAD_NEEDED" ]; then
  rc=1
  echo "   FAIL: DT_NEEDED entries musl cannot resolve:"
  for lib in $BAD_NEEDED; do echo "         $lib"; done
  echo "         musl resolves only the libc/libpthread/librt/libm/libdl/libutil/libxnet"
  echo "         aliases internally; anything else must exist as a file on bare Alpine."
  echo "         Drop it with 'patchelf --remove-needed', or stop linking against it."
else
  echo "   ok: DT_NEEDED is satisfiable by musl"
fi

# ---------------------------------------------------------------- 2. still statically linked
if [ "$PROFILE" = static ]; then
  if printf '%s\n' "$NEEDED" | grep -Eq '^lib(ssl|crypto)\.so'; then
    rc=1
    echo "   FAIL: libssl.so/libcrypto.so in DT_NEEDED -- this is NOT a static BoringSSL build."
    echo "         The APR and BoringSSL steps skip themselves when their target directory"
    echo "         already exists, so a tree left over from another architecture or a failed"
    echo "         run yields a green build linked against the host's shared OpenSSL."
    echo "         Remove the module target directories and build again."
  fi
fi

# ---------------------------------------------------------------- 3. undefined GLOBAL symbols
# `nm -D` prints "U" for undefined GLOBAL and "w"/"v" for undefined WEAK, which is exactly the
# distinction that matters: an undefined WEAK resolves to 0 and is harmless (APR imports
# __pthread_key_create that way). This is also why nm is used rather than
# `readelf --dyn-syms`: that spelling postdates the binutils in the CentOS 6 release image, and
# readelf silently truncates long names unless -W is passed.
#
# Two shapes are flagged rather than a fixed list of known-bad names: __-prefixed (the
# glibc-private namespace -- __getauxval, __isinf, __strdup, the _FORTIFY_SOURCE *_chk family,
# __isoc99_* redirects) and the LFS64 aliases (fopen64 and friends), which musl 1.2.4 removed
# outright. A denylist would only guard against a repeat, and the history here is that each
# release broke on a *different* symbol.
UND=$("$NM" -D --undefined-only "$SO" 2>/dev/null \
  | awk '$1 == "U" { print $2 }' | sed 's/@.*//' | sort -u)

ALLOW=$(printf '%s\n' $MUSL_UNDERSCORE_SYMS)
BAD_SYMS=$(printf '%s\n' "$UND" \
  | grep -E '^__|^[a-z][a-z0-9_]*64$' \
  | grep -vxF "$ALLOW")
if [ -n "$BAD_SYMS" ]; then
  echo "   WARN: undefined GLOBAL symbols musl does not export:"
  printf '%s\n' "$BAD_SYMS" | sed 's/^/         /'
  echo "         Not fatal by itself -- with lazy binding an uncalled symbol never aborts, and"
  echo "         netty-transport-native-epoll ships __xpg_strerror_r this way and works fine."
  echo "         But triage each one: if it is reachable from an ELF .init_array constructor it"
  echo "         runs during dlopen and crashes the JVM instead of raising UnsatisfiedLinkError."
  echo "         The fix is a weak, default-visibility fallback in"
  echo "         openssl-dynamic/src/main/c/musl_compat.c, implemented via the portable name."
  echo "         If musl does export one, add it to MUSL_UNDERSCORE_SYMS in this script"
  echo "         (arbiter: nm -D --defined-only /lib/ld-musl-\$(uname -m).so.1)."
else
  echo "   ok: no undefined GLOBAL symbol outside musl's exports"
fi

# The musl_compat.c fallbacks must be present, not merely absent from the undefined set: an
# artifact that never referenced them at all is fine, but one that references them and does not
# define them is exactly the aarch64 crash.
MISSING_COMPAT=""
for sym in $MUSL_COMPAT_SYMS; do
  if printf '%s\n' "$UND" | grep -qxF "$sym"; then
    MISSING_COMPAT="$MISSING_COMPAT $sym"
  fi
done
if [ -n "$MISSING_COMPAT" ]; then
  rc=1
  echo "   FAIL: musl_compat.c fallbacks are referenced but undefined:$MISSING_COMPAT"
  echo "         musl_compat.c is not being compiled into this artifact, or its definitions"
  echo "         were dropped by -fvisibility=hidden / --exclude-libs."
fi

# The unwinder must be linked in statically. libstdc++.a pulls in _Unwind_*, and the only two
# providers are libgcc_eh.a (static) and libgcc_s.so.1 (shared) -- so leaving these undefined is
# the exact shape that puts libgcc_s.so.1 back into DT_NEEDED and makes the artifact unloadable on
# an Alpine image without the `libgcc` package. Check 1 already rejects the DT_NEEDED entry; this
# one exists so that a build whose -l:libgcc*.a flags stopped reaching the link (libtool silently
# drops anything outside its pass-through allowlist) fails loudly here rather than producing a
# library that is quietly missing its unwinder. Not caught by the scan above: _Unwind_ has a
# single leading underscore.
UND_UNWIND=$(printf '%s\n' "$UND" | grep '^_Unwind_' | tr '\n' ' ')
if [ -n "$UND_UNWIND" ]; then
  rc=1
  echo "   FAIL: the unwinder is not linked in; undefined _Unwind_* symbols:"
  echo "         $UND_UNWIND"
  echo "         Ensure LDFLAGS keeps '-l:libgcc.a -l:libgcc_eh.a' *after* '-l:libstdc++.a'."
  echo "         Do not spell it -static-libgcc: libtool drops that before gcc sees it."
else
  echo "   ok: unwinder linked statically (no undefined _Unwind_*)"
fi

# ---------------------------------------------------------------- 4. glibc floor (informational)
# Not a gate, but a regression here would quietly cut the supported platform range, and the
# x86_64 artifact is released from CentOS 6 precisely to keep this at 2.12.
FLOOR=$("$READELF" -V "$SO" 2>/dev/null | grep -oE 'GLIBC_[0-9.]+' | sort -uV | tail -1)
echo "   info: glibc symbol floor: ${FLOOR:-none}"

if [ "$rc" -ne 0 ]; then
  echo "== FAIL: this artifact would not load on bare Alpine."
  echo "   See docs/musl-compatibility.md. Set -DmuslCheck.skip=true to bypass locally."
  exit 1
fi
echo "== PASS (loadability invariants hold; see WARN lines above, if any)"
