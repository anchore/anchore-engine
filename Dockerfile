ARG BASE_REGISTRY=registry.access.redhat.com
ARG BASE_IMAGE=ubi8/ubi
ARG BASE_TAG=8.4

#### Start first stage
#### Anchore wheels, binary dependencies, etc. are staged to /build_output for second stage
FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG} as anchore-engine-builder

ARG CLI_COMMIT

ENV LANG=en_US.UTF-8 LC_ALL=C.UTF-8
ENV SYFT_VERSION=v0.26.0
ENV GRYPE_VERSION=v0.22.0
ENV PIP_VERSION=21.0.1

COPY . /buildsource
WORKDIR /buildsource

# setup build artifact directory
RUN set -ex && \
    mkdir -p \
        /build_output/configs \
        /build_output/cli_wheels \
        /build_output/deps \
        /build_output/wheels

# installing build dependencies
RUN set -ex && \
    echo "installing build dependencies" && \
    # keepcache is used so that subsequent invocations of yum do not remove the cached RPMs in --downloaddir
    echo "keepcache = 1" >> /etc/yum.conf && \
    yum update -y && \
    yum module disable -y python36 && \
    yum module enable -y python38 && \
    yum install -y \
        gcc \
        git \
        go \
        make \
        python38 \
        python38-devel \
        python38-psycopg2 \
        python38-wheel && \
    yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm && \
    pip3 install pip=="${PIP_VERSION}"

# stage dependent binaries into /build_output
RUN set -ex && \
    echo "downloading OS dependencies" && \
    pip3 download -d /build_output/wheels pip=="${PIP_VERSION}" && \
    yum install -y --downloadonly --downloaddir=/build_output/build_deps/ \
        clamav \
        clamav-update \
        dpkg && \
    echo "downloading Syft" && \
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /build_output/deps "${SYFT_VERSION}" && \
    echo "downloading Grype" && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /build_output/deps "${GRYPE_VERSION}"

# stage anchore-engine wheels and default application configs into /build_output
RUN set -ex && \
    echo "creating anchore-engine wheels" && \
    pip3 wheel --wheel-dir=/build_output/wheels . && \
    pip3 wheel --wheel-dir=/build_output/cli_wheels/ git+git://github.com/anchore/anchore-cli.git@"${CLI_COMMIT}"\#egg=anchorecli && \
    cp ./LICENSE /build_output/ && \
    cp ./conf/default_config.yaml /build_output/configs/default_config.yaml && \
    cp ./docker-entrypoint.sh /build_output/configs/docker-entrypoint.sh && \
    cp -R ./conf/clamav /build_output/configs/

RUN tar -z -c -v -C /build_output -f /anchore-buildblob.tgz .

#### Start second stage
#### Setup and install using first stage artifacts in /build_output
FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG} as anchore-engine-final

ARG CLI_COMMIT
ARG ANCHORE_COMMIT
ARG ANCHORE_ENGINE_VERSION="1.0.0"
ARG ANCHORE_ENGINE_RELEASE="r0"

# Container metadata section
LABEL anchore_cli_commit="${CLI_COMMIT}" \
      anchore_commit="${ANCHORE_COMMIT}" \
      name="anchore-engine" \
      maintainer="dev@anchore.com" \
      vendor="Anchore Inc." \
      version="${ANCHORE_ENGINE_VERSION}" \
      release="${ANCHORE_ENGINE_RELEASE}" \
      summary="Anchore Engine - container image scanning service for policy-based security, best-practice and compliance enforcement." \
      description="Anchore is an open platform for container security and compliance that allows developers, operations, and security teams to discover, analyze, and certify container images on-premises or in the cloud. Anchore Engine is the on-prem, OSS, API accessible service that allows ops and developers to perform detailed analysis, run queries, produce reports and define policies on container images that can be used in CI/CD pipelines to ensure that only containers that meet your organization’s requirements are deployed into production."

# Environment variables to be present in running environment
ENV LANG=en_US.UTF-8 LC_ALL=C.UTF-8
ENV PATH="${PATH}:/anchore-cli/bin"

# Default values overrideable at runtime of the container
ENV ANCHORE_CONFIG_DIR=/config \
    ANCHORE_SERVICE_DIR=/anchore_service \
    ANCHORE_LOG_LEVEL=INFO \
    ANCHORE_ENABLE_METRICS=false \
    ANCHORE_DISABLE_METRICS_AUTH=false \
    ANCHORE_INTERNAL_SSL_VERIFY=false \
    ANCHORE_WEBHOOK_DESTINATION_URL=null \
    ANCHORE_HINTS_ENABLED=false \
    ANCHORE_FEEDS_ENABLED=true \
    ANCHORE_FEEDS_SSL_VERIFY=true \
    ANCHORE_ENDPOINT_HOSTNAME=localhost \
    ANCHORE_EVENTS_NOTIFICATIONS_ENABLED=false \
    ANCHORE_CATALOG_NOTIFICATION_INTERVAL_SEC=30 \
    ANCHORE_FEED_SYNC_INTERVAL_SEC=21600 \
    ANCHORE_EXTERNAL_PORT=null \
    ANCHORE_EXTERNAL_TLS=false \
    ANCHORE_AUTHZ_HANDLER=native \
    ANCHORE_EXTERNAL_AUTHZ_ENDPOINT=null \
    ANCHORE_ADMIN_PASSWORD=null \
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
    AUTHLIB_INSECURE_TRANSPORT=true \
    ANCHORE_MAX_COMPRESSED_IMAGE_SIZE_MB=-1 \
    ANCHORE_GLOBAL_SERVER_REQUEST_TIMEOUT_SEC=180 \
    ANCHORE_VULNERABILITIES_PROVIDER=null \
    ANCHORE_GRYPE_DB_URL="https://toolbox-data.anchore.io/grype/databases/listing.json" \
    ANCHORE_ENABLE_PACKAGE_FILTERING="true"

#### Perform OS setup

# Setup container user/group and required application directories
RUN set -ex && \
    groupadd --gid 1000 anchore && \
    useradd --uid 1000 --gid anchore --shell /bin/bash --create-home anchore && \
    mkdir -p \
        /analysis_scratch \
        "${ANCHORE_SERVICE_DIR}"/bundles \
        /config \
        /home/anchore/clamav/db \
        /licenses \
        /var/log/anchore \
        /var/run/anchore \
        /workspace \
        /workspace_preload && \
    chown -R 1000:0 \
        /analysis_scratch \
        "${ANCHORE_SERVICE_DIR}" \
        /config \
        /home/anchore \
        /licenses \
        /var/log/anchore \
        /var/run/anchore \
        /workspace \
        /workspace_preload && \
    chmod -R g+rwX \
        /analysis_scratch \
        "${ANCHORE_SERVICE_DIR}" \
        /config \
        /home/anchore \
        /licenses \
        /var/log/anchore \
        /var/run/anchore \
        /workspace \
        /workspace_preload

# Install build dependencies
RUN set -ex && \
    yum update -y && \
    yum module disable -y python36 && \
    yum module enable -y python38 && \
    yum install -y \
        procps \
        psmisc \
        python38 \
        python38-psycopg2 \
        python38-wheel \
        skopeo

#### Install application & dependencies

# Copy the installed artifacts from the first stage
COPY --from=anchore-engine-builder /build_output /build_output

# Copy default application configuration files
RUN set -ex && \
    echo "copying default application config files" && \
    cp /build_output/LICENSE /licenses/ && \
    cp /build_output/configs/default_config.yaml /config/config.yaml && \
    md5sum /config/config.yaml > /config/build_installed && \
    cp /build_output/configs/docker-entrypoint.sh /docker-entrypoint.sh && \
    chmod +x /docker-entrypoint.sh && \
    cp /build_output/configs/clamav/freshclam.conf /home/anchore/clamav/ && \
    chmod -R ug+rw /home/anchore/clamav

# Upgrade pip from staged wheel
RUN set -ex && \
    echo "updating pip" && \
    pip3 install --upgrade --no-index --find-links=/build_output/wheels/ pip

# Install anchore-cli into a virtual environment
RUN set -ex && \
    echo "installing anchore-cli into virtual environment" && \
    python3 -m venv /anchore-cli && \
    source /anchore-cli/bin/activate && \
    pip3 install --no-index --find-links=/build_output/cli_wheels/ anchorecli && \
    deactivate

# Install anchore-engine & required dependencies
RUN set -ex && \
    echo "installing anchore-engine and required dependencies" && \
    pip3 install --no-index --find-links=/build_output/wheels/ anchore-engine && \
    cp /build_output/deps/syft /usr/bin/syft && \
    cp /build_output/deps/grype /usr/bin/grype && \
    yum install -y /build_output/build_deps/*.rpm && \
    echo "cleaning up unneccesary files used for testing/cache/build" && \
    rm -rf \
        /build_output \
        /root/.cache \
        /usr/local/lib64/python3.8/site-packages/twisted/test \
        /usr/local/lib64/python3.8/site-packages/Crypto/SelfTest \
        /usr/share/doc

# Container runtime instructions

HEALTHCHECK --start-period=20s \
    CMD curl -f http://localhost:8228/health || exit 1

USER 1000

EXPOSE "${ANCHORE_SERVICE_PORT}"

WORKDIR /anchore-engine

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["anchore-manager", "service", "start", "--all"]
