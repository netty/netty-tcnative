# Using the docker images

```
cd /path/to/netty-tcnative/
```
# Using the docker images

```
cd /path/to/netty-tcnative/
```

## Arch Linux with java 8

```
docker compose -f docker/docker-compose.arch.yaml -f docker/docker-compose.arch-18.yaml run build
```

## centos 6 with java 8

```
docker compose -f docker/docker-compose.centos-6.yaml -f docker/docker-compose.centos-6.18.yaml run build
```

## debian 7 with java 8

```
docker compose -f docker/docker-compose.debian.yaml -f docker/docker-compose.debian-7.18.yaml run build
```

## openSUSE Leap 15.1 with java 8

```
docker compose -f docker/docker-compose.opensuse.yaml -f docker/docker-compose.opensuse-151.18.yaml run build
```

## centos7 with java8 for aarch64 cross compile

```
docker compose -f docker/docker-compose.centos-7.yaml run cross-compile-aarch64-build
```

etc, etc


## Alpine/musl verification of an already-built artifact

Unlike the images above, this one does not build netty-tcnative. It checks that a Linux artifact
built by one of the glibc images still loads under musl, which is the contract the released jars
have: there is no `-musl` classifier. Build first, then:

```
docker compose -f docker/docker-compose.alpine.yaml build runtime-setup
docker compose -f docker/docker-compose.alpine.yaml run --rm verify
```

`MUSL_JARS_DIR` selects where to search for the jars (default: the whole tree), so the same
command works against a directory of downloaded release jars.

To confirm a fix does not secretly depend on the compatibility shim, run the same check with
gcompat installed. It must give the same answer as the bare run — `libc.so.6` is one of the
names musl's loader satisfies internally, so gcompat's `/lib/libc.so.6 -> libgcompat.so.0`
symlink is never read:

```
MUSL_VARIANT=gcompat MUSL_EXTRA_PKGS=gcompat \
  docker compose -f docker/docker-compose.alpine.yaml build runtime-setup
MUSL_VARIANT=gcompat MUSL_EXTRA_PKGS=gcompat \
  docker compose -f docker/docker-compose.alpine.yaml run --rm verify
```

The glibc control. Anything that fails on Alpine must pass here, otherwise the check is at fault
rather than the artifact:

```
docker compose -f docker/docker-compose.alpine.yaml build control-runtime-setup
docker compose -f docker/docker-compose.alpine.yaml run --rm control-verify
```

See `docs/musl-compatibility.md`.
