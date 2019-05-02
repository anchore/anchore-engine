#!/usr/bin/env bash

if [ "${SET_HOSTID_TO_HOSTNAME}" == "true" ];
then
echo "Setting ANCHORE_HOST_ID to ${HOSTNAME}"
export ANCHORE_HOST_ID=${HOSTNAME}
fi

if [ -f "/opt/rh/rh-python36/enable" ]; then
    source /opt/rh/rh-python36/enable
fi

exec "$@"
