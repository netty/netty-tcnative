#!/bin/bash
set -e

if [ "$#" -ne 2 ]; then
    echo "Expected staging profile id and tag, login into oss.sonatype.org to retrieve it"
    exit 1
fi

OS=$(uname)

if [ "$OS" != "Darwin" ]; then
    echo "Needs to be executed on macOS"
    exit 1
fi

BRANCH=$(git branch --show-current)

if git tag | grep -q "$2" ; then
    echo "Tag $2 already exists"
    exit 1
fi

git fetch
git checkout "$2"

export JAVA_HOME="$JAVA8_HOME"

./mvnw -Psonatype-oss-release -am -pl openssl-dynamic,boringssl-static clean package gpg:sign org.sonatype.plugins:nexus-staging-maven-plugin:deploy -DstagingRepositoryId="$1" -DnexusUrl=https://oss.sonatype.org -DserverId=sonatype-nexus-staging -DskipTests=true
./mvnw -Psonatype-oss-release,uber-staging -pl boringssl-static clean package gpg:sign org.sonatype.plugins:nexus-staging-maven-plugin:deploy -DstagingRepositoryId="$1" -DnexusUrl=https://oss.sonatype.org -DserverId=sonatype-nexus-staging -DskipTests=true
./mvnw org.sonatype.plugins:nexus-staging-maven-plugin:rc-close org.sonatype.plugins:nexus-staging-maven-plugin:rc-release -DstagingRepositoryId="$1" -DnexusUrl=https://oss.sonatype.org -DserverId=sonatype-nexus-staging -DskipTests=true -DstagingProgressTimeoutMinutes=10

git checkout "$BRANCH"
