#!/usr/bin/env bash

if [ "${SET_HOSTID_TO_HOSTNAME}" == "true" ];
then
echo Setting ANCHORE_DEFAULT_HOST_ID to ${HOSTNAME}
export ANCHORE_DEFAULT_HOST_ID=${HOSTNAME}
fi

export PATH=${PATH}:/usr/local/bin

exec $@
