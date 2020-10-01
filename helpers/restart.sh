#!/usr/bin/env sh
set -ue

run_anchore_engine_dc() {
        pushd ~/code/dev-tools/dev-engine > /dev/null
        docker-compose $@
        popd > /dev/null
}

run_anchore_engine_dc kill analyzer
run_anchore_engine_dc start analyzer
echo "Restarted Analyzer"