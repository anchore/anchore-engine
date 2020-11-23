#!/usr/bin/env bash
set -e

# The url for the base, e.g. http://docs.anchore.com/
site_prefix=${1}

# The version to deploy, if available. If not, use the versions file
this_version=${2-master}


if [[ -z ${this_version} ]]
then
  echo "No version found"
  exit 1
fi

export HUGO_ENV="production"

rm -rf public/

if [[ -n "${site_prefix}" ]]
then
  if [[ ${this_version} = "master" ]]
  then
    echo Building "current" version
    pub_path="current/"
  else
    echo Building non-current version ${this_version}
    pub_path=${this_version}/
  fi

  echo Building with site prefix ${site_prefix}/${pub_path}
  hugo --gc -b ${site_prefix}/${pub_path}
else
  hugo --gc
fi
