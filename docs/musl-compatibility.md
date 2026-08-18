# Keeping netty-tcnative loadable on musl (Alpine Linux)

The released Linux artifacts are built against glibc. They are nevertheless expected to load
**on musl too**, from the same jar — there is no `-musl` classifier and adding one is not the
plan. This document records the rules that make that work, how to verify them, and the dead
ends, so the property is not lost again by accident.

Background: <https://github.com/netty/netty-tcnative/issues/907>,
<https://github.com/netty/netty-tcnative/issues/152>,
<https://github.com/netty/netty/issues/15112>. The approach mirrors
[async-profiler#952](https://github.com/async-profiler/async-profiler/issues/952), which ships
one binary for both libcs; its packaging step strips the same `ld-linux` entries with the same
tool ([Makefile#L156](https://github.com/async-profiler/async-profiler/blob/bb8f0476a1804ac77b48b84a3905fb26e9ca7428/Makefile#L156)).

---

## 1. The one rule that explains most failures

musl's dynamic linker satisfies a **fixed list of libc alias names from musl itself**, without
ever looking at the filesystem — `ldso/dynlink.c`:

```c
/* Catch and block attempts to reload the implementation itself */
if (name[0]=='l' && name[1]=='i' && name[2]=='b') {
    static const char reserved[] = "c.pthread.rt.m.dl.util.xnet.";
```

So a `DT_NEEDED` entry is safe **iff** it is `lib` + one of those stems + `.`:

| `DT_NEEDED` | on bare Alpine | why |
|---|---|---|
| `libc.so.6`, `libpthread.so.0`, `librt.so.1`, `libdl.so.2`, `libm.so.6` | **fine** | reserved, resolved internally by musl |
| `ld-linux-x86-64.so.2`, `ld-linux-aarch64.so.1` | **hard failure** | does not start with `lib` → real file lookup → absent |
| `libgcc_s.so.1` | **hard failure** unless the image happens to ship Alpine's `libgcc` package | `gcc_s.` is not in the reserved list |
| `libcrypt.so.1` | only with `gcompat` installed | not reserved; Alpine's gcompat symlinks it to `libgcompat.so.0` |

Three consequences that are easy to get wrong:

- **"the JDK image provides `libgcc`" is not a safe assumption.** Alpine JDK images disagree, and
  the difference is invisible until it is not:

  | image | ships `libgcc`? |
  |---|---|
  | `eclipse-temurin:21-jdk-alpine` | yes |
  | `amazoncorretto:21-alpine` | **no** |
  | many vendor/derived `*-jdk-alpine` images | **no** |

  So `libgcc_s.so.1` is *not* an acceptable `DT_NEEDED` — it is only an invisible one on the
  particular image the verification happens to run on. It is now linked statically instead
  (`-l:libgcc.a -l:libgcc_eh.a`, see §6) and rejected by `scripts/check_musl_compat.sh`. Note also
  that `apk add binutils` pulls `libgcc` in as a dependency, so an image that installs binutils to
  *inspect* the artifact thereby stops being able to *detect* this class of bug — see §4b.

- **`gcompat` being installed does not mean it is loaded.** gcompat ships
  `/lib/libc.so.6 -> libgcompat.so.0`, but `libc.so.6` is reserved, so musl short-circuits it
  and that symlink is never read. Only a *non-reserved* `DT_NEEDED` actually pulls
  `libgcompat.so.0` into the process. This is exactly why 2.0.65 worked on Alpine by accident
  (it carried `libcrypt.so.1`) and 2.0.73 did not.
- **A missing symbol is not always a catchable error.** See §2.

---

## 2. The three failure classes, and their signatures

### Class A — unreserved `DT_NEEDED`

```
Error loading shared library ld-linux-x86-64.so.2: No such file or directory
```
Surfaces as `UnsatisfiedLinkError`. Recoverable by the application.

`ld-linux-*` gets recorded because **`__tls_get_addr` lives in glibc's loader**, and dynamic
TLS is pulled in by `libstdc++.a`. Note musl *does* define `__tls_get_addr` itself — only the
filename lookup fails, never the symbol. That is why simply dropping the entry is correct and
sufficient.

Whether this entry appears depends on the **toolchain and link path**, not on the architecture
or the version alone. Observed:

| build | `ld-linux-*` in `DT_NEEDED`? |
|---|---|
| official x86_64 (CentOS 6), 2.0.73–2.0.81 | **yes** |
| official aarch64 cross (CentOS 7, ARM GCC 10.2), 2.0.82-SNAPSHOT | no |
| native aarch64 glibc 2.28 / GCC 8, 2.0.82-SNAPSHOT | **yes** |
| native aarch64 glibc 2.28 / GCC 8, 2.0.76-SNAPSHOT | no |

So the same source can gain or lose the entry from a compiler or dependency change on either
architecture. Do not treat "this arch does not have it" as a stable property: the removal runs
unconditionally in both release profiles, and is a harmless no-op where the entry is absent,
rather than being applied only where it was last observed.

### Class B — glibc-internal symbol musl does not export

```
Error relocating <lib>.so: __getauxval: symbol not found
```

| symbol | comes from | musl has it? |
|---|---|---|
| `__getauxval` | libgcc AArch64 outline-atomics probe | no (only `getauxval`) |
| `fopen64` | APR built with `-D_LARGEFILE64_SOURCE` | no — musl 1.2.4 (Alpine 3.19+) removed the LFS64 aliases |
| `__isinf`, `__isnan` | APR-era glibc math aliases | no |
| `__strdup` | APR | no |
| `__pthread_key_create` | APR | no — but it is imported **WEAK**, so it may stay unresolved harmlessly |

### Class C — Class B inside an ELF init constructor → **JVM crash, not an exception**

The dangerous one. `__getauxval` is called from libgcc's `init_have_lse_atomics`, which is an
`.init_array` constructor and therefore runs **during `dlopen`**:

```
C  [libnetty_tcnative_linux_aarch_64.so+0x2466c]  init_have_lse_atomics+0xc
C  [ld-musl-aarch64.so.1+0x6cedc]  dlopen+0xc4
V  [libjvm.so+0x8f5c8c]  JVM_LoadLibrary+0x88
```

The JVM dies with SIGSEGV and writes a core. The application cannot catch it and cannot fall
back to the JDK SSL provider. Any unresolved symbol reachable from a constructor is in this
class, so **do not assume "unresolved but never called" is safe** — check whether a
constructor touches it.

---

## 3. Invariants to preserve

For every released Linux `.so`, on a **bare** Alpine image (no `gcompat`, no `libc6-compat`):

1. No `DT_NEEDED` outside the musl-reserved set. No exceptions — in particular not
   `libgcc_s.so.1`, which is why the unwinder is linked statically.
2. No undefined **GLOBAL** symbol that musl does not export. (Undefined **WEAK** is fine.)
   No undefined `_Unwind_*` in particular: those come from `libstdc++.a`, and leaving them
   undefined is precisely what puts `libgcc_s.so.1` back into `DT_NEEDED`.
3. `System.load()` succeeds, `OpenSsl.isAvailable()` is true, and a real TLS handshake
   completes.
4. No behaviour change on glibc — identical negotiated cipher suite.

---

## 4. How to verify

### 4a. Static check on the built library (fast, catches most things)

Run inside a container with `binutils`. `$SO` is the built library, e.g.
`boringssl-static/target/native-lib-only/META-INF/native/linux64/libnetty_tcnative.so`.

```sh
# 1. DT_NEEDED — anything not in the reserved set is a problem, libgcc_s.so.1 included
readelf -d "$SO" | sed -n 's/.*(NEEDED).*\[\(.*\)\]/\1/p'

# 1b. the unwinder must be linked in statically; this must print 0
nm -D --undefined-only "$SO" | awk '$1 == "U" { print $2 }' | grep -c '^_Unwind_'

# 2. undefined GLOBAL symbols not provided by musl.
#    -W is essential: without it readelf truncates names and appends "[...]".
readelf -W --dyn-syms "$SO" | awk '$7=="UND" && $5=="GLOBAL" {print $8}' | sed 's/@.*//' | sort -u \
  > /tmp/und
nm -D --defined-only /lib/ld-musl-$(uname -m).so.1 | awk '{print $NF}' | sed 's/@.*//' | sort -u \
  > /tmp/have
comm -23 /tmp/und /tmp/have     # must be empty (modulo libstdc++/libgcc_s symbols)
```

Also confirm the build really is static-BoringSSL — a stale `target/` can silently produce a
library linked against the *host's shared* OpenSSL (see §7):

```sh
readelf -d "$SO" | grep -E 'libssl\.so|libcrypto\.so' && echo "NOT a static BoringSSL build"
objdump -f boringssl-static/target/boringssl-main/build/libssl.a | grep -m1 architecture
readelf -h "$SO" | grep Machine        # must match the intended target
```

In a **cross** build the `objdump -f` line reports `architecture: UNKNOWN!`, because the host
binutils is reading a foreign-architecture archive. That is not a failure — check
`readelf -h "$SO" | grep Machine` instead, and rely on the absence of `libssl.so`/`libcrypto.so`
from `DT_NEEDED` for the static-linking question.

### 4b. Ground truth: musl's own loader

On Alpine, `ldd` *is* the musl loader, so this reports the real errors with no JVM involved:

```sh
ldd "$SO"     # look for "Error loading shared library" / "Error relocating"
```

**Beware what your inspection tools drag in.** `apk add binutils` — needed for the `readelf`/`nm`
checks in §4a — depends on `libgcc`, so installing it satisfies a `libgcc_s.so.1` `DT_NEEDED` and
turns a bare image into a non-bare one. `docker/Dockerfile.alpine` therefore installs binutils as
the virtual package `.elftools`, and `verify.sh` removes it (with `libgcc`) before the execution
checks when `MUSL_DROP_ELFTOOLS=1`. If you inspect by hand, do the `readelf` work in one container
and the load test in a clean one.

**And beware what the JDK itself drags in.** On `eclipse-temurin:21-jdk-alpine` the JDK *depends*
on `libgcc`, so `apk del` cannot remove it there — the `bare` legs run with libgcc present no
matter what, and cannot police invariant 1's `libgcc_s.so.1` clause. That is what the separate
`nolibgcc` CI legs are for: same harness on `amazoncorretto:21-alpine`, whose JDK pulls no libgcc,
so the runtime checks really do run without it. Run it locally with:

```sh
MUSL_VARIANT=nolibgcc MUSL_JDK_IMAGE=amazoncorretto:21-alpine MUSL_DROP_ELFTOOLS=1 \
  docker compose -f docker/docker-compose.alpine.yaml build runtime-setup
MUSL_VARIANT=nolibgcc MUSL_DROP_ELFTOOLS=1 MUSL_JARS_DIR=<dir> \
  docker compose -f docker/docker-compose.alpine.yaml run --rm verify
```

### 4c. Runtime check on bare Alpine

```sh
docker run --rm -v "$PWD":/w -w /w eclipse-temurin:21-jdk-alpine sh -c '
  java -cp "netty-common.jar:netty-buffer.jar:netty-transport.jar:netty-resolver.jar:\
netty-codec.jar:netty-codec-base.jar:netty-handler.jar:netty-tcnative-classes.jar:\
netty-tcnative-boringssl-static-<ver>-linux-<arch>.jar:." YourCheck'
```

The check must go further than loading. Minimum bar, in order of strength:

1. `System.load()` on the extracted `.so`
2. `io.netty.handler.ssl.OpenSsl.isAvailable()`
3. **a full TLS handshake** — an in-memory `SSLEngine` pair (OpenSSL-backed server with a
   self-signed cert, OpenSSL-backed client) driven to completion, then application data
   round-tripped both ways

Only (3) would catch a library that loads but whose crypto is broken.

Two TLS 1.3 behaviours will make a naive handshake test report false failures:
- the client reaches `NOT_HANDSHAKING` while the server still sits in `NEED_UNWRAP` waiting
  for optional post-handshake traffic — treat an idle `NEED_UNWRAP` as settled;
- the first post-handshake record is a `NewSessionTicket`, so a single `unwrap` legitimately
  produces zero application bytes — loop until application data appears.

### 4d. Regression check on glibc

Run the same three checks on `eclipse-temurin:21-jdk-jammy` and compare the negotiated
protocol/cipher against a released version. It must be identical.

---

## 5. Where the compatibility code lives

| file | role |
|---|---|
| `openssl-dynamic/src/main/c/musl_compat.c` | weak fallbacks for the Class B symbols. Applies to **every** profile, since it is a source file. |
| `boringssl-static/pom.xml`, antrun `native-jar` target | post-link `patchelf --remove-needed ld-linux-*` (Class A). Present in **both** release profiles: `boringssl-static-default` (x86_64) and `linux-aarch64`. |
| `docker/Dockerfile.centos6` | installs `patchelf` from the upstream prebuilt **static** binary — CentOS 6 is EOL with no EPEL, and `objcopy` cannot remove a `DT_NEEDED`. Needs `--no-check-certificate`, same as the OpenSSL download: the CA bundle cannot verify modern GitHub TLS. |
| `docker/Dockerfile.cross_compile_aarch64` | installs `patchelf` from EPEL 7 (available there, unlike CentOS 6) |

Note the two release profiles duplicate the whole native build, so **a change to one does not
apply to the other**. `linux-aarch64` cross-compiles from an x86_64 host; patchelf is
arch-agnostic and edits the aarch64 object correctly from there (verified), whereas the
`strip` in that profile has to use the cross-prefixed `aarch64-none-linux-gnu-strip`.

### Rules for `musl_compat.c`

- **Do not guard with `#ifndef __GLIBC__`.** The release images *are* glibc; the definitions
  must be compiled into exactly the artifacts that need them. `__attribute__((weak))` is what
  prevents collision with glibc's own definitions at link time.
- Mark every definition `__attribute__((weak, visibility("default")))`. The build uses
  `-fvisibility=hidden` (`native-package/configure.ac`), and `openssl-dynamic` resolves
  against `libapr`/`libcrypto` at runtime, so hidden is not sufficient there.
  `-Wl,--exclude-libs,ALL` (`m4/tcnative.m4`) only hides symbols coming *out of static
  archives*, so our own stay exported.
- The build uses `-Werror -Wunused`. Guard feature macros with `#ifndef` — the build already
  passes `-D_LARGEFILE64_SOURCE` (`m4/custom.m4`) and redefining it is an error.
- Implement each fallback in terms of the portable name (`__getauxval` → `getauxval`,
  `fopen64` → `fopen`, `__strdup` → `strdup`, …), which exists on both libcs.

### Adding new C files

No autotools change is needed: hawtjni scans `src/main/c` and generates `Makefile.am` itself.
Only the Windows `vs2010.vcxproj.static.template` has an explicit source list.

---

## 6. Dead ends — do not re-try these

| attempt | why it fails |
|---|---|
| `-static-libgcc` **spelled that way** | libtool discards it, silently. See "Linking the unwinder statically" below — use `-l:libgcc.a -l:libgcc_eh.a` instead, which does work. |
| `-ftls-model=initial-exec` to avoid `__tls_get_addr` | unsafe in a `dlopen`'d library — can fail at load once the static TLS block is exhausted. Strip the `DT_NEEDED` instead. |
| a `linux-x86_64-musl` classifier | unnecessary; the goal is one binary. It would also need runtime libc detection, which netty tried (`#11722`) and reverted 3 days later (`#11738`) because `/proc/self/maps` false-positives when gcompat is present. |
| relying on `gcompat` | does not help at all on aarch64 for ≥2.0.73 (still SIGSEGV), because nothing pulls `libgcompat.so.0` in. See §1. |
| removing `-D_LARGEFILE64_SOURCE` (`m4/custom.m4`) to kill `fopen64` | this *is* the root cause and would be the cleaner fix, but it changes APR's build configuration — needs its own evaluation. Not done. |

### Linking the unwinder statically, and why the spelling matters

`libstdc++.a` pulls in the `_Unwind_*` family, and the only two providers are `libgcc_eh.a`
(static) and `libgcc_s.so.1` (shared). Leaving them undefined is what records the `libgcc_s.so.1`
`DT_NEEDED`. The obvious fix is `-static-libgcc` — and it does not work, for a reason worth
knowing because it generalises to every flag in this build.

**libtool does not pass the flag to the compiler.** GNU libtool 2.4.6 builds a shared library with
`archive_cmds`, which expands only `$libobjs $deplibs $compiler_flags`. In `func_mode_link`, `-l*`
is parsed into `deplibs`, but `-static-libgcc` / `-static-libstdc++` match neither the
pass-through allowlist nor any specific case and fall into the catch-all `-* | +*)` branch, which
appends them **only** to `compile_command`/`finalize_command` — the paths used to link *programs*.
So `gcc -shared` never sees them. To confirm it on any build tree, put both spellings on the same
`LDFLAGS` line and read what survived:

```sh
grep dependency_libs boringssl-static/target/native-build/libnetty_tcnative.la
# dependency_libs=' -L.../boringssl-main/build -lssl -lcrypto -l:libstdc++.a -lrt -lpthread -ldl'
```

`-l:libstdc++.a` is there; `-static-libstdc++`, passed alongside it, is not. Only the `-l:` form
ever does any work here.

**The fix** is therefore to name the archives directly, after `libstdc++.a` (which is what pulls
the `_Unwind_*` references in):

```
LDFLAGS=... -l:libstdc++.a -l:libgcc.a -l:libgcc_eh.a
```

`libgcc_eh.a` defines the `_Unwind_*` family; with them resolved, the driver's trailing
`--as-needed -lgcc_s` records no `DT_NEEDED`. Measured identical on GCC 4.9.4, 9.5.0 (x86_64) and
10.5.0 (aarch64) — the shipping toolchains are devtoolset-9 (9.3.1) and ARM GCC 10.2.1:

| link | `DT_NEEDED` | undefined `_Unwind_*` |
|---|---|---|
| `-l:libstdc++.a` alone | `libgcc_s.so.1 libc.so.6` | 11 |
| `+ -l:libgcc.a -l:libgcc_eh.a` | `libc.so.6` | 0 |

**One consequence on aarch64.** Static `libgcc.a` brings `init_have_lse_atomics` — the
outline-atomics probe — into the library as an `.init_array` constructor, and it references
`__getauxval`. That is a Class C symbol (§2): unresolved, it SIGSEGVs the JVM inside `dlopen`. It
is satisfied by the weak, default-visibility fallback in `musl_compat.c`, and
`check_musl_compat.sh` fails the build if that ever stops being true. Do not remove that fallback
on the grounds that "nothing references it" — with static libgcc, something does.

---

## 7. Build-system traps

The APR and BoringSSL steps guard on **directory existence**, not validity or architecture:

```
[echo] APR was already build, skipping the build step.
[echo] BoringSSL was already build, skipping the build step.
```

- A run that fails partway leaves an empty `target/apr`; every later run then skips building
  APR and fails far downstream with `configure: error: the --with-apr parameter is incorrect`.
- Worse, building a **second architecture in the same tree** silently produces a wrong
  artifact: reusing an aarch64 `target/boringssl-main` for an x86_64 build leaves
  `libssl.a`/`libcrypto.a` as aarch64 archives, the linker skips them as incompatible and
  falls back to the host's *shared* system OpenSSL. It builds and packages successfully.

**Always `rm -rf <module>/target` when switching architecture or after a failed run**, and run
the §4a `DT_NEEDED` check on the output.

### libtool silently drops link flags it does not recognise

The native library is linked by GNU libtool (`AC_PROG_LIBTOOL` in `native-package/configure.ac`),
not by a bare `gcc` command, and libtool filters `LDFLAGS`. Only flags it classifies survive into
the `gcc -shared` line: `-l*` and `-L*` become `deplibs`, `-Wl,*` becomes `compiler_flags`, and a
fixed allowlist (`-O*`, `-g*`, `-flto*`, `-fstack-protector*`, `-m*`, `-pthread`, …) passes
through. **Everything else is discarded without a warning.**

Practical rules:

- Prefer `-l:libfoo.a` over driver flags like `-static-libgcc` / `-static-libstdc++`. The `-l:`
  form is passed through; the `-static-lib*` ones are not (§6).
- Anything that must reach the *linker* can be forced with `-Wl,...`; anything that must reach the
  *compiler driver* has no reliable route through `LDFLAGS` at all — set `CC` instead.
- **Verify, do not assume.** `grep dependency_libs target/native-build/libnetty_tcnative.la` shows
  exactly what survived, without re-running the build.

A known casualty: the `boringssl-static-asan` profile's `-fsanitize=address` in `<ldflags>` never
reaches the link on Linux — partly because libtool would drop it, and partly because that profile
only overrides properties consumed by `boringssl-static-default`, whose Linux branch hardcodes
`hawtjniLdflags` and ignores `${ldflags}` entirely. Not fixed; noted so it is not mistaken for a
working ASan build.

### Building the official images needs the right host

`docker/Dockerfile.centos6` **cannot be built on a modern-kernel host**. CentOS 6.10 userspace
needs the legacy `vsyscall` page, which recent kernels disable by default, so most of its
binaries die with SIGSEGV (exit 139). It fails on upstream's very first `sed -i`, before any of
this project's own steps. Symptom worth recognising: trivial binaries such as `/bin/true` and
`sed --version` succeed while `sed -i`, plain `sed`, and `yum --version` all crash — which makes
it look like a broken image rather than a host problem. The host needs `vsyscall=emulate` on the
kernel command line (a reboot), or use a host/CI runner that already has it.

`docker/Dockerfile.cross_compile_aarch64` (CentOS 7) builds fine on a modern kernel. Note the
EPEL `ninja-build` GPG-key line in its output is a warning, not a failure.

If you ever need an x86_64 build on a host you cannot reboot, a CentOS 7 image on the same base
as the aarch64 cross one works, but note two things it needs that the cross image does not: an
SCL **devtoolset** — the CentOS 7 system gcc is 4.8.5, too old for BoringSSL, and the cross image
sidesteps that by compiling with the ARM toolchain — and **`no-asm`** for OpenSSL, because
CentOS 7's binutils 2.27 cannot assemble OpenSSL 3.6's AVX-512 sources (same workaround, same
reason, as the CentOS 6 image). Be aware it also raises the artifact's glibc floor; measure it
rather than assuming the host's version:

```sh
readelf -V <lib> | grep -oE 'GLIBC_[0-9.]+' | sort -uV | tail -1
```

A CentOS 7-built x86_64 artifact measured `GLIBC_2.16`, against `<= GLIBC_2.12` from CentOS 6 —
so that route drops RHEL/CentOS 6 and Ubuntu 12.04. `pom.xml` documents releasing x86_64 from
RHEL 6 precisely to keep that reach, so this is a deliberate trade, not a free fix.

### The release image is glibc 2.12 — mind what headers you use

`docker/Dockerfile.centos6` is **glibc 2.12**, which predates a lot. `<sys/auxv.h>` and
`getauxval()` only arrived in glibc 2.16, so including that header unconditionally is a *fatal*
error on the x86_64 release image:

```
musl_compat.c: fatal error: sys/auxv.h: No such file or directory
```

`musl_compat.c` therefore probes with `__has_include` and falls back to reading
`/proc/self/auxv` directly. Note the fallback is kept rather than compiling `__getauxval` out on
old glibc: dropping it would leave the artifact unprotected the moment an x86_64 toolchain starts
emitting `__getauxval`, which is exactly how the aarch64 breakage arose.

Every other toolchain tried — glibc 2.17, 2.28, 2.35 and musl — has the header, so this only
shows up on the real release image. Build there before trusting a portability claim.

### Old glibc headers macro-define the names we override

glibc 2.17's `<string.h>` defines `__strdup` as a function-like **macro** under `_GNU_SOURCE`, so
defining it expands into the macro body:

```
musl_compat.c:87:23: error: expected identifier or '(' before '__extension__'
```

Newer glibc (2.28, 2.35) only *declares* it, so gcc 8, gcc 11 and the ARM GCC 10.2 cross build
all accept the file without the `#undef` block in `musl_compat.c`. **Do not remove those
`#undef`s because the toolchain in front of you is happy without them** — build on the oldest
supported glibc before concluding the file compiles cleanly.

Other notes:
- `patchelf --remove-needed` exits 0 when the entry is absent, so one invocation listing both
  `ld-linux-x86-64.so.2` and `ld-linux-aarch64.so.1` is safe on either architecture.
- A post-link antrun step cannot be bound to the `compile` phase — plugin ordering puts antrun
  *before* hawtjni. Use the `native-jar` target (phase `package`) or `process-classes`.
- Ant's `<exec>` does not echo silent commands, so absence of `strip`/`patchelf` output in the
  log does **not** mean they did not run. Verify on the artifact instead.
- Link flags are set per profile and are duplicated: the x86_64 default profile sets
  `hawtjniLdflags` in the `ldflags-setup` antrun execution, while the `linux-aarch64` profile
  hardcodes `LDFLAGS` in its hawtjni `configureArgs`. Changing one does not change the other.

---

## 8. Checklist for a change that touches native linking

- [ ] §4a static check passes on **both** `linux-x86_64` and `linux-aarch_64`
- [ ] no `libssl.so`/`libcrypto.so` in `DT_NEEDED` (still a static BoringSSL build)
- [ ] §4c runtime check passes on **bare** Alpine, including a real handshake
- [ ] §4d glibc regression: identical negotiated cipher suite vs. the previous release
- [ ] built in a clean tree (`rm -rf target`), not an incremental one
- [ ] if a new symbol was added to `musl_compat.c`: it is `weak` + `visibility("default")`,
      compiles under `-Werror`, and is confirmed to go from `UND` to defined in the output
