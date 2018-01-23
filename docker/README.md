
** Create a docker image **
```
docker build -f Dockerfile-netty-tcnative-centos6 . -t netty-tcnative-centos6
```

** Using the image **

```
cd /path/to/netty-tcnative/
```

```
docker run -it -v ~/.m2:/root/.m2 -v ~/.ssh:/root/.ssh -v ~/.gnupg:/root/.gnupg -v `pwd`:/code -w /code netty-tcnative-centos6 bash
```
