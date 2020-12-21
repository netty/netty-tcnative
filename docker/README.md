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
docker-compose -f docker/docker-compose.arch.yaml -f docker/docker-compose.arch-18.yaml run build
```

## centos 6 with java 8

```
docker-compose -f docker/docker-compose.centos-6.yaml -f docker/docker-compose.centos-6.18.yaml run build
```

## debian 7 with java 8

```
docker-compose -f docker/docker-compose.debian.yaml -f docker/docker-compose.debian-7.18.yaml run build
```

## openSUSE Leap 15.1 with java 8

```
docker-compose -f docker/docker-compose.opensuse.yaml -f docker/docker-compose.opensuse-151.18.yaml run build
```

## centos7 with java8 for aarch64 cross compile

```
docker-compose -f docker/docker-compose.centos-7.yaml run cross-compile-aarch64-build
```

etc, etc

