ARG centos_version=6
FROM centos:$centos_version
# needed to do again after FROM due to docker limitation
ARG centos_version

ENV SOURCE_DIR /root/source
ENV CMAKE_VERSION_BASE 3.8
ENV CMAKE_VERSION $CMAKE_VERSION_BASE.2
ENV NINJA_VERSION 1.7.2
ENV GO_VERSION 1.9.3

# install dependencies
RUN yum install -y \
 apr-devel \
 autoconf \
 automake \
 bzip2 \
 git \
 glibc-devel \
 gnupg \
 libapr1-dev \
 libtool \
 lsb-core \
 make \
 openssl-devel \
 perl \
 tar \
 unzip \
 wget

RUN mkdir $SOURCE_DIR
WORKDIR $SOURCE_DIR

RUN wget -q https://cmake.org/files/v$CMAKE_VERSION_BASE/cmake-$CMAKE_VERSION-Linux-x86_64.tar.gz && tar zxf cmake-$CMAKE_VERSION-Linux-x86_64.tar.gz && mv cmake-$CMAKE_VERSION-Linux-x86_64 /opt/ && echo 'PATH=/opt/cmake-$CMAKE_VERSION-Linux-x86_64/bin:$PATH' >> ~/.bashrc

RUN wget -q https://github.com/ninja-build/ninja/releases/download/v$NINJA_VERSION/ninja-linux.zip && unzip ninja-linux.zip && mkdir -p /opt/ninja-$NINJA_VERSION/bin && mv ninja /opt/ninja-$NINJA_VERSION/bin && echo 'PATH=/opt/ninja-$NINJA_VERSION/bin:$PATH' >> ~/.bashrc

RUN wget -q http://storage.googleapis.com/golang/go$GO_VERSION.linux-amd64.tar.gz && tar zxf go$GO_VERSION.linux-amd64.tar.gz && mv go /opt/ && echo 'PATH=/opt/go/bin:$PATH' >> ~/.bashrc && echo 'export GOROOT=/opt/go/' >> ~/.bashrc

RUN wget -q http://linuxsoft.cern.ch/cern/scl/RPM-GPG-KEY-cern && mv RPM-GPG-KEY-cern /etc/pki/rpm-gpg/
RUN wget -q http://linuxsoft.cern.ch/cern/scl/slc6-scl.repo && mv slc6-scl.repo /etc/yum.repos.d
RUN yum install -y devtoolset-3-gcc-c++
RUN echo 'source /opt/rh/devtoolset-3/enable' >> ~/.bashrc

RUN rm -rf $SOURCE_DIR

ARG java_version=1.8
ENV JAVA_VERSION $java_version
# installing java with jabba
RUN curl -sL https://github.com/shyiko/jabba/raw/master/install.sh | JABBA_COMMAND="install $JAVA_VERSION -o /jdk" bash


RUN echo 'export JAVA_HOME="/jdk"' >> ~/.bashrc
RUN echo 'PATH=/jdk/bin:$PATH' >> ~/.bashrc
