#!/usr/bin/env sh
set -ue
IMAGE=$1

run_anchore_engine_dc() {
        pushd ~/code/dev-tools/dev-engine > /dev/null
        docker-compose $@
        popd > /dev/null
}

run_anchore_engine_dc exec api anchore-cli subscription deactivate analysis_update $IMAGE
run_anchore_engine_dc exec api anchore-cli subscription deactivate policy_eval $IMAGE
run_anchore_engine_dc exec api anchore-cli subscription deactivate tag_update $IMAGE
run_anchore_engine_dc exec api anchore-cli subscription deactivate vuln_update $IMAGE
run_anchore_engine_dc exec api anchore-cli image del $IMAGE || true
echo "IMAGE $IMAGE DELETED"
run_anchore_engine_dc exec api anchore-cli image list