#!/bin/bash

if [ -d "/wheelhouse" ]; then
    echo "doing source build with wheels"
    PRE_PCMD=""
    PCMD="pip install --no-index -f /wheelhouse ."
else
    echo "doing regular RPM-only source build"
    PRE_PCMD="yum -y install gcc python-devel openssl-devel"
    PCMD="pip install ."
fi

if [ ! -z "${PRE_PCMD}" ]; then
    ${PRE_PCMD}
fi

if [ ! -z "${PCMD}" ]; then
    ${PCMD}
fi

exit 0
