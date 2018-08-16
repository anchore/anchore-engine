#!/bin/bash

set -e
if [ -d "/wheelhouse" ]; then
    echo "doing source build with wheels"
    PRE_PCMD=""
    PCMD="pip3 install --no-index -f /wheelhouse ."
else
    echo "doing regular RPM-only source build"
    PRE_PCMD="yum -y install gcc python-devel openssl-devel"
    PRE_PCMD=""
    PCMD="pip3 install ."
fi

if [ ! -z "${PRE_PCMD}" ]; then
    ${PRE_PCMD}
fi

if [ ! -z "${PCMD}" ]; then
    ${PCMD}
fi

exit 0
