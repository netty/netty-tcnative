ARG debian_version=7
FROM debian:$debian_version
# needed to do again after FROM due to docker limitation
ARG debian_version

ENV SOURCE_DIR /root/source
ENV CMAKE_VERSION_BASE 3.8
ENV CMAKE_VERSION $CMAKE_VERSION_BASE.2
ENV NINJA_VERSION 1.7.2
ENV GO_VERSION 1.9.3
ENV GCC_VERSION 4.9.4

# install dependencies
RUN apt-get -y update && apt-get -y install \
 autoconf \
 automake \
 bzip2 \
 cmake \
 curl \
 gcc \
 gcc-multilib \
 git \
 gnupg \
 g++ \
 libapr1-dev \
 libssl-dev \
 libtool \
 make \
 perl \
 tar \
 unzip \
 wget \
 xutils-dev \
 zip

RUN mkdir $SOURCE_DIR
WORKDIR $SOURCE_DIR

RUN wget -q https://cmake.org/files/v$CMAKE_VERSION_BASE/cmake-$CMAKE_VERSION-Linux-x86_64.tar.gz && tar zxf cmake-$CMAKE_VERSION-Linux-x86_64.tar.gz && mv cmake-$CMAKE_VERSION-Linux-x86_64 /opt/ && echo 'PATH=/opt/cmake-$CMAKE_VERSION-Linux-x86_64/bin:$PATH' >> ~/.bashrc

RUN wget -q https://github.com/ninja-build/ninja/releases/download/v$NINJA_VERSION/ninja-linux.zip && unzip ninja-linux.zip && mkdir -p /opt/ninja-$NINJA_VERSION/bin && mv ninja /opt/ninja-$NINJA_VERSION/bin && echo 'PATH=/opt/ninja-$NINJA_VERSION/bin:$PATH' >> ~/.bashrc

RUN wget -q http://storage.googleapis.com/golang/go$GO_VERSION.linux-amd64.tar.gz && tar zxf go$GO_VERSION.linux-amd64.tar.gz && mv go /opt/ && echo 'PATH=/opt/go/bin:$PATH' >> ~/.bashrc && echo 'export GOROOT=/opt/go/' >> ~/.bashrc

RUN wget -q ftp://ftp.gnu.org/gnu/gcc/gcc-$GCC_VERSION/gcc-$GCC_VERSION.tar.gz && tar zxf gcc-$GCC_VERSION.tar.gz
WORKDIR gcc-$GCC_VERSION

RUN ./contrib/download_prerequisites && ./configure --prefix=/opt/gcc-$GCC_VERSION/ --enable-languages=c,c++ && make && make install && echo 'PATH=/opt/gcc-$GCC_VERSION/bin:$PATH' >> ~/.bashrc && echo 'export CC=/opt/gcc-$GCC_VERSION/bin/gcc' >> ~/.bashrc && echo 'export CXX=/opt/gcc-$GCC_VERSION/bin/g++' >> ~/.bashrc

RUN rm -rf $SOURCE_DIR

ARG java_version=1.8
ENV JAVA_VERSION $java_version
# installing java with jabba
RUN curl -sL https://github.com/shyiko/jabba/raw/master/install.sh | JABBA_COMMAND="install $JAVA_VERSION -o /jdk" bash

RUN echo 'export JAVA_HOME="/jdk"' >> ~/.bashrc
RUN echo 'PATH=/jdk/bin:$PATH' >> ~/.bashrc
