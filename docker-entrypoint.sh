#!/usr/bin/env bash

if [[ "${SET_HOSTID_TO_HOSTNAME}" == "true" ]]; then
    echo "Setting ANCHORE_HOST_ID to ${HOSTNAME}"
    export ANCHORE_HOST_ID=${HOSTNAME}
fi

if [[ -f "/opt/rh/rh-python36/enable" ]]; then
    source /opt/rh/rh-python36/enable
fi

# check if /home/anchore/certs/ exists & has files in it
if [[ -d "/home/anchore/certs" ]] && [[ ! -z "$(ls -A /home/anchore/certs)" ]]; then
    mkdir -p /home/anchore/certs_override/python
    mkdir -p /home/anchore/certs_override/os
    ### for python
    cp /opt/rh/rh-python36/root/usr/lib/python3.6/site-packages/certifi/cacert.pem /home/anchore/certs_override/python/cacert.pem
    cat /home/anchore/certs/*.crt >> /home/anchore/certs_override/python/cacert.pem
    cat /home/anchore/certs/*.pem >> /home/anchore/certs_override/python/cacert.pem
    ### for OS (go, openssl)
    cp -a /etc/pki/tls/certs/* /home/anchore/certs_override/os/
    cat /home/anchore/certs/* >> /home/anchore/certs_override/os/anchore.bundle.crt
    ### setup ENV overrides to system CA bundle utilizing appended custom certs
    export REQUESTS_CA_BUNDLE=/home/anchore/certs_override/python/cacert.pem
    export SSL_CERT_DIR=/home/anchore/certs_override/os/
fi

exec "$@"
