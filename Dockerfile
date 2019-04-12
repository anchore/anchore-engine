FROM ubuntu:18.04 as wheelbuilder
ENV LANG=C.UTF-8 LC_ALL=C.UTF-8
ENV GOPATH=/go
ENV SKOPEO_VERSION=v0.1.32

RUN set -ex && \
    mkdir -p /go && \
    apt-get -y update && \
    apt-get -y upgrade && \
    apt-get -y install vim curl psmisc git rpm python3 python3-pip golang btrfs-tools git-core libdevmapper-dev libgpgme11-dev go-md2man libglib2.0-dev libostree-dev libssl-dev && \
    git clone --branch "$SKOPEO_VERSION" https://github.com/containers/skopeo ${GOPATH}/src/github.com/containers/skopeo && \
    cd ${GOPATH}/src/github.com/containers/skopeo && \
    make binary-local && \
    make install

COPY ./requirements.txt /requirements.txt

# Build the wheels from the requirements
RUN pip3 wheel --wheel-dir=/wheels -r /requirements.txt

# Do the final build
FROM ubuntu:18.04

ARG CLI_COMMIT
ARG ANCHORE_COMMIT
ARG ANCHORE_ENGINE_VERSION="0.4.0"
ARG ANCHORE_ENGINE_RELEASE="dev"

# Container metadata section

MAINTAINER dev@anchore.com

LABEL anchore_cli_commit=$CLI_COMMIT \
      anchore_commit=$ANCHORE_COMMIT \
      name="anchore-engine" \
      maintainer="dev@anchore.com" \
      vendor="Anchore Inc." \
      version=$ANCHORE_ENGINE_VERSION \
      release=$ANCHORE_ENGINE_RELEASE \
      summary="Anchore Engine - container image scanning service for policy-based security, best-practice and compliance enforcement." \
      description="Anchore is an open platform for container security and compliance that allows developers, operations, and security teams to discover, analyze, and certify container images on-premises or in the cloud. Anchore Engine is the on-prem, OSS, API accessible service that allows ops and developers to perform detailed analysis, run queries, produce reports and define policies on container images that can be used in CI/CD pipelines to ensure that only containers that meet your organization’s requirements are deployed into production."

# Environment variables to be present in running environment
ENV LANG=en_US.UTF-8 LC_ALL=C.UTF-8

# Default values overrideable at runtime of the container
ENV ANCHORE_CONFIG_DIR=/config \
    ANCHORE_SERVICE_DIR=/anchore_service \
    ANCHORE_LOG_LEVEL=INFO \
    ANCHORE_ENABLE_METRICS=false \
    ANCHORE_INTERNAL_SSL_VERIFY=false \
    ANCHORE_WEBHOOK_DESTINATION_URL=null \
    ANCHORE_FEEDS_ENABLED=true \
    ANCHORE_FEEDS_SELECTIVE_ENABLED=true \
    ANCHORE_FEEDS_SSL_VERIFY=true \
    ANCHORE_ENDPOINT_HOSTNAME=localhost \
    ANCHORE_EVENTS_NOTIFICATIONS_ENABLED=false \
    ANCHORE_FEED_SYNC_INTERVAL_SEC=21600 \
    ANCHORE_EXTERNAL_PORT=null \
    ANCHORE_EXTERNAL_TLS=false \
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

# Container run environment settings

#VOLUME /analysis_scratch
EXPOSE ${ANCHORE_SERVICE_PORT}

# Build dependencies

RUN set -ex && \
    apt-get -y update && \
    apt-get -y upgrade && \
    apt-get -y install git curl psmisc rpm python3-minimal python3-pip libgpgme11 libdevmapper1.02.1 libostree-1-1 && \
    pip3 install -e git+git://github.com/anchore/anchore-cli.git@$CLI_COMMIT\#egg=anchorecli && \
    apt-get -y remove git && \
    apt-get clean && \
    apt-get -y autoremove

# Copy skopeo artifacts from build step
COPY --from=wheelbuilder /usr/bin/skopeo /usr/bin/skopeo
COPY --from=wheelbuilder /etc/containers/policy.json /etc/containers/policy.json

# Copy python artifacts from build step
COPY --from=wheelbuilder /wheels /wheels
COPY . /anchore-engine

# Setup container default configs and directories

WORKDIR /anchore-engine

RUN set -ex && \
    mkdir ${ANCHORE_SERVICE_DIR} && \
    mkdir /config && \
    mkdir /licenses && \
    cp LICENSE /licenses/ && \
    cp conf/default_config.yaml /config/config.yaml && \
    md5sum /config/config.yaml > /config/build_installed && \
    cp docker-compose.yaml /docker-compose.yaml && \
    cp docker-compose-dev.yaml /docker-compose-dev.yaml && \
    cp docker-entrypoint.sh /docker-entrypoint.sh && \
    chmod +x /docker-entrypoint.sh

# Perform the anchore-engine build and install

RUN set -ex && \
    pip3 install --no-index --find-links=/wheels -r requirements.txt && \
    pip3 install . && \
    rm -rf /anchore-engine /root/.cache /wheels

# Setup anchore user and permissions

RUN set -ex && \
    groupadd --gid 1000 anchore && \
    useradd --uid 1000 --gid anchore --shell /bin/bash --create-home anchore && \
    mkdir -p /var/log/anchore && chown -R anchore:anchore /var/log/anchore && \
    mkdir -p /var/run/anchore && chown -R anchore:anchore /var/run/anchore && \
    mkdir -p /analysis_scratch && chown -R anchore:anchore /analysis_scratch && \
    mkdir -p /workspace && chown -R anchore:anchore /workspace && \
    mkdir -p ${ANCHORE_SERVICE_DIR} && chown -R anchore:anchore ${ANCHORE_SERVICE_DIR}

# Container runtime instructions

HEALTHCHECK --start-period=20s \
    CMD curl -f http://localhost:8228/health || exit 1

USER anchore:anchore

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["anchore-manager", "service", "start", "--all"]
