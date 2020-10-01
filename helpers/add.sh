#!/usr/bin/env sh
set -ue
IMAGE=$1

run_anchore_engine_dc() {
        pushd ~/code/dev-tools/dev-engine > /dev/null
        docker-compose $@
        popd > /dev/null
}

run_anchore_engine_dc exec api anchore-cli image add $IMAGE
echo "IMAGE $IMAGE ADDED"
run_anchore_engine_dc exec api anchore-cli image list
run_anchore_engine_dc exec api anchore-cli image wait $IMAGE