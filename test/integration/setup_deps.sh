#!/usr/bin/env bash

echo "Setting up integration test dependencies"

docker-compose -f deps/docker-compose.yaml up -d

# These are from deps/minio/config/config.json, not real S3 creds. They should match the ones set in that config or tests will fail.
export ANCHORE_TEST_S3_ACCESS_KEY="9EB92C7W61YPFQ6QLDOU"
export ANCHORE_TEST_S3_SECRET_KEY="TuHo2UbBx+amD3YiCeidy+R3q82MPTPiyd+dlW+s"
export ANCHORE_TEST_S3_URL="http://localhost:9000"
export ANCHORE_TEST_S3_BUCKET="testarchivebucket"

export ANCHORE_TEST_SWIFT_AUTH_URL="http://localhost:8080/auth/v1.0"
export ANCHORE_TEST_SWIFT_KEY="testing"
export ANCHORE_TEST_SWIFT_USER="test:tester"
export ANCHORE_TEST_SWIFT_CONTAINER="testarchive"

export ANCHORE_TEST_DB_URL="postgresql://postgres:postgres@localhost:5432/postgres"
export ANCHORE_TEST_DB_USER="postgres"
export ANCHORE_TEST_DB_PASS="postgres"
export ANCHORE_TEST_DATA_ENV_DIR="${PWD}/../data/test_data_env"
