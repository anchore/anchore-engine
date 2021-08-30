#!/usr/bin/env bash

if [[ "${SET_HOSTID_TO_HOSTNAME}" == "true" ]]; then
    echo "Setting ANCHORE_HOST_ID to ${HOSTNAME}"
    export ANCHORE_HOST_ID=${HOSTNAME}
fi

# check if /home/anchore/certs/ exists & has files in it
if [[ -d "/home/anchore/certs" ]] && [[ -n "$(ls -A /home/anchore/certs)" ]]; then
    mkdir -p /home/anchore/certs_override/python
    mkdir -p /home/anchore/certs_override/os
    ### for python
    cp "$(python3 -m certifi)" /home/anchore/certs_override/python/cacert.pem
    for file in /home/anchore/certs/*; do
        if grep -q 'BEGIN CERTIFICATE' "${file}"; then
            cat "${file}" >> /home/anchore/certs_override/python/cacert.pem
        fi
    done
    ### for OS (go, openssl)
    cp -a /etc/pki/tls/certs/* /home/anchore/certs_override/os/
    for file in /home/anchore/certs/*; do
        if grep -q 'BEGIN CERTIFICATE' "${file}"; then
            cat "${file}" >> /home/anchore/certs_override/os/anchore.bundle.crt
        fi
    done
    ### setup ENV overrides to system CA bundle utilizing appended custom certs
    export REQUESTS_CA_BUNDLE=/home/anchore/certs_override/python/cacert.pem
    export SSL_CERT_DIR=/home/anchore/certs_override/os/
fi

# Add the CLI virtual env bin path
export PATH=$PATH:/anchore-cli/bin

exec "$@"
