#!/bin/bash -x

if [ "${1}" == "dev" ]; then
    BUILDMODE="dev"
    if [ -z "${ANCHORE_SRC_HOME}" ]; then
	ANCHORESRCHOME="/root/"
    else
	ANCHORESRCHOME="${ANCHORE_SRC_HOME}"
    fi
    if [ -d "${ANCHORESRCHOME}/wheelhouse" ]; then
	ANCHOREWHEELHOUSE="${ANCHORESRCHOME}/wheelhouse"
    fi
    if [ -z "${ANCHORE_ENGINE_DOCKERFILE}" ]; then
	DOCKERFILE="scripts/dockerfiles/Dockerfile.dev"
    else
	DOCKERFILE="${ANCHORE_ENGINE_DOCKERFILE}"
    fi
    if [ -z "${ANCHORE_ENGINE_TAG}" ]; then
	TAG="anchore-engine:dev"
    else
	TAG="${ANCHORE_ENGINE_TAG}"
    fi
else
    BUILDMODE="latest"
    DOCKERFILE="Dockerfile"
    TAG="anchore-engine:latest"
fi

#if [ "$1" == "use-cache" ]
#then
#	echo "Building with cache usage allowed"
#	cache_directive=""
#else
#	echo "Building with no cache usage. To enable usage pass value 'use-cache' as param one to this script"
#	cache_directive="--no-cache"
#fi

set -e

# CACHE_DIRECTIVE="--no-cache"
CACHE_DIRECTIVE=""

mkdir -p /tmp/anchore-engine-build
rm -rf /tmp/anchore-engine-build/anchore-engine/
cp -a ${DOCKERFILE} /tmp/anchore-engine-build/Dockerfile

cd /tmp/anchore-engine-build/

if [ "${BUILDMODE}" == "dev" ]; then
    rsync -azP /${ANCHORESRCHOME}/anchore-engine/ /tmp/anchore-engine-build/anchore-engine/
    rsync -azP /${ANCHORESRCHOME}/anchore-cli/ /tmp/anchore-engine-build/anchore-cli/
    #rsync -azP /${ANCHORESRCHOME}/anchore/ /tmp/anchore-engine-build/anchore/
else
    git clone git@github.com:anchore/anchore-engine.git
fi

#cd anchore-engine; export CURRHASH=`git log --pretty=format:'%H' -n 1`; cd ..

WHEELVOLUME=""
if [ ! -z "$ANCHOREWHEELHOUSE" ]; then
    if [ -d "$ANCHOREWHEELHOUSE" ]; then
	WHEELVOLUME="-v ${ANCHOREWHEELHOUSE}:/wheelhouse"
    fi
fi

cd /tmp/anchore-engine-build && docker build -t ${TAG} ${CACHE_DIRECTIVE} ${WHEELVOLUME} . && docker tag ${TAG} anchore/${TAG} 

