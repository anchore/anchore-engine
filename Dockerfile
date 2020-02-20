FROM registry.access.redhat.com/ubi8/ubi:8.1 as anchore-engine-builder

######## This is stage1 where anchore wheels, binary deps, and any items from the source tree get staged to /build_output ########

ARG CLI_COMMIT

ENV LANG=en_US.UTF-8 LC_ALL=C.UTF-8

ENV GOPATH=/go
ENV SKOPEO_VERSION=v0.1.41

COPY . /buildsource
WORKDIR /buildsource

RUN set -ex && \
    mkdir -p /build_output /build_output/deps /build_output/configs /build_output/wheels

RUN set -ex && \
    echo "installing OS dependencies" && \
    yum update -y && \
    yum install -y gcc make python36 git python3-wheel python36-devel go

# create anchore binaries
RUN set -ex && \
    echo "installing anchore" && \
    pip3 wheel --wheel-dir=/build_output/wheels . && \
    pip3 wheel --wheel-dir=/build_output/wheels/ git+git://github.com/anchore/anchore-cli.git@$CLI_COMMIT\#egg=anchorecli && \
    cp ./LICENSE /build_output/ && \
    cp ./conf/default_config.yaml /build_output/configs/default_config.yaml && \
    cp ./scripts/docker-compose/anchore-prometheus.yml /build_output/configs/anchore-prometheus.yml && \
    cp ./scripts/docker-compose/anchore-swaggerui-nginx.conf /build_output/configs/anchore-swaggerui-nginx.conf && \
    cp ./docker-compose.yaml /build_output/configs/docker-compose.yaml && \
    cp ./docker-compose-dev.yaml /build_output/configs/docker-compose-dev.yaml && \
    cp ./docker-entrypoint.sh /build_output/configs/docker-entrypoint.sh 

# stage anchore dependency binaries
RUN set -ex && \
    echo "installing GO" && \
    mkdir -p /go

RUN set -ex && \
    echo "installing Skopeo" && \
    git clone --branch "$SKOPEO_VERSION" https://github.com/containers/skopeo ${GOPATH}/src/github.com/containers/skopeo && \
    cd ${GOPATH}/src/github.com/containers/skopeo && \
    make binary-local DISABLE_CGO=1 && \
    make install-binary && \
    cp /usr/bin/skopeo /build_output/deps/ && \
    cp default-policy.json /build_output/configs/skopeo-policy.json

# stage RPM dependency binaries
RUN yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm && \
    yum install -y --downloadonly --downloaddir=/build_output/deps/ dpkg

RUN tar -z -c -v -C /build_output -f /anchore-buildblob.tgz .

# Build setup section

FROM registry.access.redhat.com/ubi8/ubi:8.1 as anchore-engine-final

######## This is stage2 which does setup and install entirely from items from stage1's /build_output ########

ARG CLI_COMMIT
ARG ANCHORE_COMMIT
ARG ANCHORE_ENGINE_VERSION="0.6.1"
ARG ANCHORE_ENGINE_RELEASE="r0"

# Copy skopeo artifacts from build step
COPY --from=anchore-engine-builder /build_output /build_output

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
    ANCHORE_DISABLE_METRICS_AUTH=false \
    ANCHORE_INTERNAL_SSL_VERIFY=false \
    ANCHORE_WEBHOOK_DESTINATION_URL=null \
    ANCHORE_FEEDS_ENABLED=true \
    ANCHORE_FEEDS_SELECTIVE_ENABLED=true \
    ANCHORE_FEEDS_SSL_VERIFY=true \
    ANCHORE_ENDPOINT_HOSTNAME=localhost \
    ANCHORE_EVENTS_NOTIFICATIONS_ENABLED=false \
    ANCHORE_CATALOG_NOTIFICATION_INTERVAL_SEC=30 \
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
    ANCHORE_FEEDS_TOKEN_URL="https://ancho.re/oauth/token" \
    ANCHORE_GLOBAL_CLIENT_READ_TIMEOUT=0 \
    ANCHORE_GLOBAL_CLIENT_CONNECT_TIMEOUT=0 \
    ANCHORE_AUTH_PUBKEY=null \
    ANCHORE_AUTH_PRIVKEY=null \
    ANCHORE_AUTH_SECRET=null \
    ANCHORE_OAUTH_ENABLED=false \
    ANCHORE_OAUTH_TOKEN_EXPIRATION=3600 \
    ANCHORE_AUTH_ENABLE_HASHED_PASSWORDS=false \
    AUTHLIB_INSECURE_TRANSPORT=true
# Insecure transport required in case for things like tls sidecars

# Container run environment settings

#VOLUME /analysis_scratch
EXPOSE ${ANCHORE_SERVICE_PORT}

# Build dependencies

RUN set -ex && \
    yum update -y && \
    yum install -y python36 python3-wheel procps psmisc

# Setup container default configs and directories

WORKDIR /anchore-engine

# Perform OS setup

RUN set -ex && \
    groupadd --gid 1000 anchore && \
    useradd --uid 1000 --gid anchore --shell /bin/bash --create-home anchore && \
    mkdir ${ANCHORE_SERVICE_DIR} && \
    mkdir /config && \
    mkdir /licenses && \
    mkdir -p /var/log/anchore && chown -R anchore:anchore /var/log/anchore && \
    mkdir -p /var/run/anchore && chown -R anchore:anchore /var/run/anchore && \
    mkdir -p /analysis_scratch && chown -R anchore:anchore /analysis_scratch && \
    mkdir -p /workspace && chown -R anchore:anchore /workspace && \
    mkdir -p ${ANCHORE_SERVICE_DIR} && chown -R anchore:anchore /anchore_service && \
    cp /build_output/LICENSE /licenses/ && \
    cp /build_output/configs/default_config.yaml /config/config.yaml && \
    cp /build_output/configs/anchore-prometheus.yml /config/anchore-prometheus.yml && \
    cp /build_output/configs/anchore-swaggerui-nginx.conf /config/anchore-swaggerui-nginx.conf && \
    cp /build_output/configs/docker-compose.yaml /docker-compose.yaml && \
    cp /build_output/configs/docker-compose-dev.yaml /docker-compose-dev.yaml && \
    cp /build_output/configs/docker-entrypoint.sh /docker-entrypoint.sh && \
    md5sum /config/config.yaml > /config/build_installed && \
    chmod +x /docker-entrypoint.sh

# Perform any base OS specific setup

# Perform the anchore-engine build and install

RUN set -ex && \
    pip3 install --no-index --find-links=./ /build_output/wheels/*.whl && \
    cp /build_output/deps/skopeo /usr/bin/skopeo && \
    mkdir -p /etc/containers && \
    cp /build_output/configs/skopeo-policy.json /etc/containers/policy.json && \
    yum install -y /build_output/deps/dpkg*.rpm && \
    rm -rf /build_output /root/.cache

# Container runtime instructions

HEALTHCHECK --start-period=20s \
    CMD curl -f http://localhost:8228/health || exit 1

USER anchore:anchore

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["anchore-manager", "service", "start", "--all"]
