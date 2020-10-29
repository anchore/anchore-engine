#!/usr/bin/env bash

# Usage: test_with_deps.sh <path to test(s) to run> <additional params to pass to tox>
# Unit test Example: ./scripts/testing/test_with_deps.sh test/unit
# Integration test Example: ./scripts/testing/test_with_deps.sh test/integration
# Specific test example: ./scripts/testing/test_with_deps.sh test/integration/subsys/test_simplequeue.py -- --log_cli_level DEBUG

# Run it from the top directory of the repo e.g. scripts/test_with_deps.sh unit
# It will detect dependencies by the existence of "setup_deps.sh" or "teardown_deps.sh", if none found it assumes there are no deps

# Runs a specific set of tests with the proper dependencies setup, uses tox
to_run=${1}
full_params=$@

test_dir=$(echo "${to_run}" | cut -f -2 -d '/')

if [[ -e ${test_dir}/setup_deps.sh ]]; then
	echo "Found deps, initializing"
	pushd "${test_dir}"
	source ./setup_deps.sh
	popd
else
	echo No setup_depts.sh script found to run, skipping
fi

echo "Running the tests"
echo "Full params: ${full_params}"
tox ${full_params}
test_return_code=$?

if [[ -e ${test_dir}/teardown_deps.sh ]]; then
	pushd "${test_dir}"
	echo "Tearing down deps"
	source ./teardown_deps.sh
	popd
else
	echo "No teardown_deps.sh found to run, skipping"
fi

exit ${test_return_code}

