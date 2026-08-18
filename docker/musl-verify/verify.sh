#!/bin/sh
# ----------------------------------------------------------------------------
# Copyright 2026 The Netty Project
#
# The Netty Project licenses this file to you under the Apache License,
# version 2.0 (the "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at:
#
#   https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
# ----------------------------------------------------------------------------
# Verify a built Linux boringssl-static artifact under the libc of THIS container.
#
# Run it on Alpine to prove the glibc-built jar really loads on musl, and on a glibc image as
# the control -- anything that fails on Alpine but also fails here means the harness is broken,
# not the library. Complements scripts/check_musl_compat.sh, which runs inside the build and can
# only inspect the ELF: this one has the real libc present, so it can resolve DT_NEEDED for
# real, diff undefined symbols against what is actually exported, and above all execute the
# thing. See docs/musl-compatibility.md.
#
# usage: verify.sh <dir-containing-the-built-jars>
# env:   MUSL_VARIANT  label for the log, e.g. bare / gcompat / glibc-control
# exit:  0 all checks passed / 1 at least one failed / 2 usage or setup error
set -u

IN="${1:-}"
if [ -z "$IN" ] || [ ! -d "$IN" ]; then
  echo "usage: $0 <dir-containing-the-built-jars>" >&2
  exit 2
fi
VARIANT="${MUSL_VARIANT:-unknown}"
HERE=$(dirname "$0")

case "$(uname -m)" in
  aarch64) CLS=linux-aarch_64 ;;
  x86_64)  CLS=linux-x86_64 ;;
  *) echo "$0: unsupported architecture $(uname -m)" >&2; exit 2 ;;
esac

# Discover rather than hardcode a path: upload-artifact computes a least-common-ancestor, so the
# directory layout inside a downloaded artifact depends on how many modules produced jars.
# -sources and -javadoc jars are both published, hence the exclusions.
NATIVE_JAR=$(find "$IN" -name "netty-tcnative-boringssl-static-*-$CLS.jar" \
                        ! -name '*-sources.jar' ! -name '*-javadoc.jar' | head -1)
CLASSES_JAR=$(find "$IN" -name 'netty-tcnative-classes-*.jar' \
                        ! -name '*-sources.jar' ! -name '*-javadoc.jar' | head -1)
if [ -z "$NATIVE_JAR" ]; then
  echo "$0: no netty-tcnative-boringssl-static $CLS jar under $IN" >&2
  exit 2
fi
if [ -z "$CLASSES_JAR" ]; then
  echo "$0: no netty-tcnative-classes jar under $IN" >&2
  exit 2
fi

# find returns paths relative to $IN, and both the unpack step and javac run from elsewhere.
abspath() {
  case "$1" in
    /*) printf '%s\n' "$1" ;;
    *)  printf '%s\n' "$PWD/${1#./}" ;;
  esac
}
NATIVE_JAR=$(abspath "$NATIVE_JAR")
CLASSES_JAR=$(abspath "$CLASSES_JAR")
HERE=$(abspath "$HERE")

echo "=================================================================="
echo " arch     : $(uname -m)  ($CLS)"
echo " variant  : $VARIANT"
echo " libc     : $(apk info -v musl 2>/dev/null | head -1 || ldd --version 2>&1 | head -1)"
echo " compat   : $(apk info 2>/dev/null | grep -Ex 'gcompat|libc6-compat|libgcc|libstdc\+\+' | sort | tr '\n' ' ')"
echo " java     : $(java -version 2>&1 | head -1)"
echo " jar      : $(basename "$NATIVE_JAR")"
echo "=================================================================="

FAILURES=0
fail() { FAILURES=$((FAILURES + 1)); echo "   FAIL: $1"; }

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
(cd "$WORK" && jar xf "$NATIVE_JAR" META-INF/native) || { echo "$0: cannot unpack $NATIVE_JAR" >&2; exit 2; }
SO=$(find "$WORK/META-INF/native" -name '*.so' | head -1)
[ -n "$SO" ] || { echo "$0: no .so inside $NATIVE_JAR" >&2; exit 2; }

# ---------------------------------------------------------------- ldd: the loader's own verdict
# On Alpine `ldd` IS the musl loader, so this reports the real relocation errors with no JVM in
# the way. Authoritative for dynamic linking, and worth printing even when it succeeds.
echo "-- ldd"
LDD_OUT=$(ldd "$SO" 2>&1)
echo "$LDD_OUT" | sed 's/^/   /' | head -30
if echo "$LDD_OUT" | grep -qE 'Error loading shared library|Error relocating|not found'; then
  fail "ldd reports unresolved libraries or relocations"
fi

# ---------------------------------------------------------------- DT_NEEDED, resolved for real
# On the build host this can only be judged against a hardcoded allowlist. Here the loader is
# present, so ask it: resolution is read back out of the ldd output above rather than guessing at
# library paths, which differ between musl (/lib) and glibc multiarch (/lib/<triplet>).
echo "-- DT_NEEDED"
MUSL_LDSO="/lib/ld-musl-$(uname -m).so.1"
for lib in $(readelf -d "$SO" 2>/dev/null | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p'); do
  case "$lib" in
    # ldso/dynlink.c: static const char reserved[] = "c.pthread.rt.m.dl.util.xnet.";
    # musl satisfies these from itself and never looks at the filesystem, which is also why
    # installing gcompat does not help: it ships /lib/libc.so.6 -> libgcompat.so.0, but
    # libc.so.6 is reserved so that symlink is never read.
    libc.so*|libpthread.so*|librt.so*|libm.so*|libdl.so*|libutil.so*|libxnet.so*)
      if [ -e "$MUSL_LDSO" ]; then
        echo "   ok        $lib (musl-reserved)"
      else
        echo "   ok        $lib"
      fi ;;
    *)
      resolved=$(echo "$LDD_OUT" | awk -v l="$lib" '$1 == l && $2 == "=>" { print $3; exit }')
      if [ -n "$resolved" ] && [ "$resolved" != "not" ]; then
        echo "   ok        $lib -> $resolved"
      else
        fail "$lib in DT_NEEDED is neither musl-reserved nor resolvable on this system"
      fi ;;
  esac
done

# ---------------------------------------------------------------- undefined vs really exported
# Reported, not fatal: with lazy binding an undefined GLOBAL that nothing calls never aborts.
# netty-transport-native-epoll ships __xpg_strerror_r this way and runs fine on bare Alpine.
# The execution checks below are what actually decide the outcome.
echo "-- undefined GLOBAL symbols not exported by anything installed"
UND=$(mktemp); AVAIL=$(mktemp)
nm -D --undefined-only "$SO" 2>/dev/null | awk '$1 == "U" { print $2 }' | sed 's/@.*//' | sort -u > "$UND"
for provider in "$MUSL_LDSO" /usr/lib/libgcc_s.so.1 /usr/lib/libstdc++.so.6 /lib/libgcompat.so.0 /usr/lib/libc.so.6; do
  [ -e "$provider" ] && nm -D --defined-only "$provider" 2>/dev/null | awk '{ print $NF }' | sed 's/@.*//'
done | sort -u > "$AVAIL"
MISSING=$(comm -23 "$UND" "$AVAIL")
if [ -z "$MISSING" ]; then
  echo "   none"
else
  echo "$MISSING" | sed 's/^/   WARN /'
fi
rm -f "$UND" "$AVAIL"

# ------------------------------------------------------- drop the ELF tools (and libgcc with them)
# Everything above needs binutils; nothing below does. binutils depends on libgcc, so on an image
# whose JDK does not itself require libgcc, installing it silently satisfies a libgcc_s.so.1
# DT_NEEDED and the bare leg stops testing what it claims to. Removing it here means the execution
# checks -- the ones that actually decide the outcome -- run against the package set a stock Alpine
# JDK image really has. Guarded on apk so the Debian glibc-control image skips this untouched.
if [ "${MUSL_DROP_ELFTOOLS:-0}" = "1" ] && command -v apk >/dev/null 2>&1; then
  echo "-- dropping ELF tools so the runtime checks see no libgcc"
  apk del .elftools >/dev/null 2>&1 || echo "   WARN: could not remove the .elftools virtual package"
  echo "   compat now: $(apk info 2>/dev/null | grep -Ex 'gcompat|libc6-compat|libgcc|libstdc\+\+' | sort | tr '\n' ' ')"
  for lib in /usr/lib/libgcc_s.so.1 /usr/lib/libstdc++.so.6; do
    if [ -e "$lib" ]; then
      echo "   note: $lib is still present (the JDK itself depends on it)"
    else
      echo "   ok: $lib is absent"
    fi
  done
fi

# ---------------------------------------------------------------- execute
echo "-- load and initialize"
CLASSES="$WORK/classes"
mkdir -p "$CLASSES"
javac -nowarn -d "$CLASSES" -cp "$CLASSES_JAR" "$HERE/MuslLoadCheck.java" \
  || { echo "$0: cannot compile MuslLoadCheck" >&2; exit 2; }

# Keep core dumps and hs_err files out of the mounted work tree: a SIGSEGV here writes hundreds
# of megabytes, and on aarch64 that was the normal outcome before the fix.
ulimit -c 0 2>/dev/null || true
JVM_OPTS="-ea -Xcheck:jni -XX:-CreateCoredumpOnCrash -XX:ErrorFile=$WORK/hs_err_%p.log"

# A hard JVM crash prints no RESULT line. Synthesise a failure for it rather than letting a
# missing line read as success -- this is the single most important behaviour in this script.
run_level() {
    level="$1"
    out=$(java $JVM_OPTS -cp "$CLASSES:$CLASSES_JAR" MuslLoadCheck "$level" "$SO" 2>&1)
    rc=$?
    if echo "$out" | grep -q '^RESULT'; then
        echo "$out" | grep '^RESULT' | sed 's/^/   /'
    else
        printf '   RESULT\t%s\tFAIL\tJVM died without a result line (exit=%s)\n' "$level" "$rc"
        echo "$out" | grep -E '^#  (SIGSEGV|SIGBUS|SIGILL)|^# C  \[' | sed 's/^/     crash| /'
    fi
    if [ "$rc" -ne 0 ]; then
        fail "level '$level' exited $rc"
    fi
}

run_level load
run_level init
run_level context

echo "------------------------------------------------------------------"
if [ "$FAILURES" -ne 0 ]; then
  echo "musl-verify: FAIL ($FAILURES check(s)) on $(uname -m)/$VARIANT"
  exit 1
fi
echo "musl-verify: PASS on $(uname -m)/$VARIANT"
