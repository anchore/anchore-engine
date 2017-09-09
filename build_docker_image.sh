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

mkdir -p /tmp/anchore-engine-build
rm -rf /tmp/anchore-engine-build/anchore-engine
cp -a Dockerfile /tmp/anchore-engine-build

cd /tmp/anchore-engine-build
rsync -azP /root/anchore-engine/ /tmp/anchore-engine-build/anchore-engine/
#git clone git@github.com:anchore/anchore-engine.git

cd /tmp/anchore-engine-build && docker build -t anchore-engine:latest ${cache_directive} . && docker tag anchore-engine:latest anchore/anchore-engine:latest
