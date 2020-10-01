#!/usr/bin/env sh
set -ue
IMAGE=$1

./delete.sh $IMAGE || true
./add.sh $IMAGE