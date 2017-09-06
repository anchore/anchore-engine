#!/bin/bash -x

if [ -z "$ANCHORESRCHOME" ]; then
    echo "set ANCHORESRCHOME to directory that contains anchore-engine, anchore, and anchore-cli"
    exit 1
fi

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
rm -rf /tmp/anchore-engine-build/anchore-cli
rm -rf /tmp/anchore-engine-build/anchore

cp -a Dockerfile /tmp/anchore-engine-build
cd /tmp/anchore-engine-build

#git clone git@github.com:anchore/anchore-engine.git
#git clone git@github.com:anchore/anchore-cli.git
#git clone git@github.com:anchore/anchore.git

rsync --delete -azP /${ANCHORESRCHOME}/anchore-engine/ /tmp/anchore-engine-build/anchore-engine/
rsync --delete -azP /${ANCHORESRCHOME}/anchore-cli/ /tmp/anchore-engine-build/anchore-cli/
rsync --delete -azP /${ANCHORESRCHOME}/anchore/ /tmp/anchore-engine-build/anchore/

cd /tmp/anchore-engine-build && docker build -t anchore-engine:latest ${cache_directive} . && docker tag anchore-engine:latest anchore/anchore-engine:latest
