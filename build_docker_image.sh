#!/bin/bash -x

if [ "$1" == "use-cache" ]
then
	echo "Building with cache usage allowed"
	cache_directive=""
else
	echo "Building with no cache usage. To enable usage pass value 'use-cache' as param one to this script"
	cache_directive="--no-cache"
fi

set -e

REPOTAG="anchore-engine:latest"

mkdir -p /tmp/anchore-engine-build
rm -rf /tmp/anchore-engine-build/anchore-engine
if [ ! -z "$ANCHOREDOCKERFILEOVERRIDE" ]; then
    cp -a ${ANCHOREDOCKERFILEOVERRIDE} /tmp/anchore-engine-build/Dockerfile
    TAG="anchore-engine:dev"
else
    cp -a Dockerfile /tmp/anchore-engine-build
fi

cd /tmp/anchore-engine-build
if [ ! -z "$ANCHORESRCHOME" ]; then
    rsync -azP /${ANCHORESRCHOME}/anchore-engine/ /tmp/anchore-engine-build/anchore-engine/
    rsync -azP /${ANCHORESRCHOME}/anchore-cli/ /tmp/anchore-engine-build/anchore-cli/
    rsync -azP /${ANCHORESRCHOME}/anchore/ /tmp/anchore-engine-build/anchore/
    TAG="anchore-engine:dev"
else
    git clone git@github.com:anchore/anchore-engine.git
fi

cd /tmp/anchore-engine-build && docker build -t ${TAG} ${cache_directive} . && docker tag ${TAG} anchore/${TAG}
