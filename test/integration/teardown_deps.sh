#!/bin/bash

echo Tearing down integration test dependencies

docker-compose -f deps/docker-compose.yaml down -v


