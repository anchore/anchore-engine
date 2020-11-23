#!/usr/bin/env bash

set -e

source_dir=${1}
bucket=${2}
branch_name=${3}

latest_version_path="current/"

if [[ "${branch_name}" = "master" ]]
then
  publish_version="current"
else
  publish_version=${branch_name}
fi

echo "Publish version = ${publish_version}"

if [[ -z "${source_dir}" ]]
then
  echo "Source dir not set. Quitting deploy"
  exit 1
fi

if [[ -z "${bucket}" ]]
then
  echo "Bucket must be set. Quitting deploy"
  exit 1
fi

if [[ -z ${source_dir} ]]
then
  echo No content in source dir, aborting deploy
  exit 1
fi

echo "Deploying contents of ${source_dir} to ${bucket}/${publish_version}"
s3deploy -bucket ${bucket} -region us-west-2 -source ${source_dir} -path ${publish_version}
