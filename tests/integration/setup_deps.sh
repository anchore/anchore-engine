#!/usr/bin/env bash

echo "Setting up integration test dependencies"

docker-compose -f deps/docker-compose.yaml up -d