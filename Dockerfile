FROM ubuntu:18.04 as wheelbuilder
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8
ENV GOPATH=/go
RUN mkdir -p /go && \
    apt -y update && \
    apt -y install vim curl psmisc git rpm python3 python3-pip golang btrfs-tools git-core libdevmapper-dev libgpgme11-dev go-md2man libglib2.0-dev libostree-dev && \
    git clone https://github.com/containers/skopeo $GOPATH/src/github.com/containers/skopeo && \
    cd $GOPATH/src/github.com/containers/skopeo && \
    make binary-local && \
    make install
RUN pip3 install --upgrade pip
COPY ./requirements.txt /requirements.txt

# Build the wheels from the requirements
RUN pip3 wheel --wheel-dir=/wheels -r /requirements.txt

# Do the final build
FROM ubuntu:18.04
ARG CLI_COMMIT
ARG ANCHORE_COMMIT
LABEL anchore_cli_commit=$CLI_COMMIT
LABEL anchore_commit=$ANCHORE_COMMIT
ENV LANG=en_US.UTF-8 LC_ALL=C.UTF-8

VOLUME /analysis_scratch

# Default values overrideable at runtime of the container
ENV ANCHORE_CONFIG_DIR=/config \
    ANCHORE_SERVICE_DIR=/anchore_service \
    ANCHORE_LOG_LEVEL=INFO \
    ANCHORE_ENABLE_METRICS=false \
    ANCHORE_INTERNAL_SSL_VERIFY=false \
    ANCHORE_WEBHOOK_DESTINATION_URL=null \
    ANCHORE_FEEDS_ENABLED=true \
    ANCHORE_FEEDS_SELECTIVE_ENABLED=true \
    ANCHORE_ENDPOINT_HOSTNAME=localhost \
    ANCHORE_EVENTS_NOTIFICATIONS_ENABLED=false \
    ANCHORE_FEED_SYNC_INTERVAL_SEC=21600 \
    ANCHORE_EXTERNAL_PORT=null \
    ANCHORE_AUTHZ_HANDLER=native \
    ANCHORE_EXTERNAL_AUTHZ_ENDPOINT=null \
    ANCHORE_ADMIN_PASSWORD=foobar \
    ANCHORE_ADMIN_EMAIL=admin@myanchore \
    ANCHORE_HOST_ID="anchore-quickstart" \
    ANCHORE_DB_PORT=5432 \
    ANCHORE_DB_NAME=postgres \
    ANCHORE_DB_USER=postgres \
    SET_HOSTID_TO_HOSTNAME=false \
    ANCHORE_CLI_USER=admin \
    ANCHORE_CLI_PASS=foobar \
    ANCHORE_SERVICE_PORT=8228 \
    ANCHORE_CLI_URL="http://localhost:8228" \
    ANCHORE_FEEDS_URL="https://ancho.re/v1/service/feeds" \
    ANCHORE_FEEDS_CLIENT_URL="https://ancho.re/v1/account/users" \
    ANCHORE_FEEDS_TOKEN_URL="https://ancho.re/oauth/token"


EXPOSE ${ANCHORE_SERVICE_PORT}
RUN apt -y update && \
    apt -y install git curl psmisc rpm python3-minimal python3-pip libgpgme11 libdevmapper1.02.1 libostree-1-1 && \
    pip3 install -e git+git://github.com/anchore/anchore-cli.git@$CLI_COMMIT\#egg=anchorecli && \
    apt -y remove git && \
    apt -y autoremove

# Skopeo stuff
COPY --from=wheelbuilder /usr/bin/skopeo /usr/bin/skopeo
COPY --from=wheelbuilder /etc/containers/policy.json /etc/containers/policy.json

# Anchore Stuff
COPY --from=wheelbuilder /wheels /wheels
COPY . /anchore-engine

WORKDIR /anchore-engine
RUN mkdir ${ANCHORE_SERVICE_DIR} && \
    mkdir /config && \
    cp conf/default_config.yaml /config/config.yaml && \
    md5sum /config/config.yaml > /config/build_installed && \
    cp docker-compose.yaml /docker-compose.yaml && \
    cp docker-compose-dev.yaml /docker-compose-dev.yaml && \
    cp docker-entrypoint.sh /docker-entrypoint.sh && \
    chmod +x /docker-entrypoint.sh

RUN pip3 install --no-index --find-links=/wheels -r requirements.txt && \
    pip3 install . && \
    rm -rf /anchore-engine

HEALTHCHECK --start-period=20s \
    CMD curl -f http://localhost:8228/health || exit 1

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["anchore-manager", "service", "start", "--all"]
