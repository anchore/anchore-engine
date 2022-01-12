ARG BASE_REGISTRY=registry.access.redhat.com
ARG BASE_IMAGE=ubi8/ubi
ARG BASE_TAG=8.5

#### Start first stage
#### Anchore wheels, binary dependencies, etc. are staged to /build_output for second stage
FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG} as anchore-engine-builder

ENV CLI_COMMIT=master

ENV LANG=en_US.UTF-8 
ENV LC_ALL=C.UTF-8

# environment variables for dependent binary versions
ENV SYFT_VERSION=v0.33.0
ENV GRYPE_VERSION=v0.27.3
ENV PIP_VERSION=21.0.1

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
    yum install -y --downloadonly --downloaddir=/build_output/deps/ \
        clamav \
        clamav-update \
        dpkg

RUN set -ex && \
    echo "downloading anchore-cli" && \
    pip3 wheel --wheel-dir=/build_output/cli_wheels/ git+git://github.com/anchore/anchore-cli.git@"${CLI_COMMIT}"\#egg=anchorecli

RUN set -exo pipefail && \
    echo "downloading Syft" && \
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /build_output/deps "${SYFT_VERSION}"

RUN set -exo pipefail && \
    echo "downloading Grype" && \
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /build_output/deps "${GRYPE_VERSION}"

COPY . /buildsource
WORKDIR /buildsource

# stage anchore-engine wheels and default application configs into /build_output
RUN set -ex && \
    echo "creating anchore-engine wheels" && \
    pip3 wheel --wheel-dir=/build_output/wheels . && \
    cp ./LICENSE /build_output/ && \
    cp ./conf/default_config.yaml /build_output/configs/default_config.yaml && \
    cp ./docker-entrypoint.sh /build_output/configs/docker-entrypoint.sh

# create p1 buildblob & checksum
RUN set -ex && \
    tar -z -c -v -C /build_output -f /anchore-buildblob.tgz . && \
    sha256sum /anchore-buildblob.tgz > /buildblob.tgz.sha256sum

#### Start second stage
#### Setup and install using first stage artifacts in /build_output
FROM ${BASE_REGISTRY}/${BASE_IMAGE}:${BASE_TAG} as anchore-engine-final

ARG CLI_COMMIT
ARG ANCHORE_COMMIT
ARG ANCHORE_ENGINE_VERSION="1.1.0"
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
ENV AUTHLIB_INSECURE_TRANSPORT=true
ENV LANG=en_US.UTF-8 
ENV LC_ALL=C.UTF-8
ENV PATH="${PATH}:/anchore-cli/bin"
ENV SET_HOSTID_TO_HOSTNAME=false

# Default values overrideable at runtime of the container
ENV ANCHORE_ADMIN_EMAIL=admin@myanchore \
    ANCHORE_ADMIN_PASSWORD=null \
    ANCHORE_AUTH_ENABLE_HASHED_PASSWORDS=false \
    ANCHORE_AUTH_PRIVKEY=null \
    ANCHORE_AUTH_PUBKEY=null \
    ANCHORE_AUTH_SECRET=null \
    ANCHORE_AUTHZ_HANDLER=native \
    ANCHORE_CATALOG_NOTIFICATION_INTERVAL_SEC=30 \
    ANCHORE_CLI_PASS=foobar \
    ANCHORE_CLI_USER=admin \
    ANCHORE_CLI_URL="http://localhost:8228" \
    ANCHORE_CONFIG_DIR=/config \
    ANCHORE_DB_NAME=postgres \
    ANCHORE_DB_PORT=5432 \
    ANCHORE_DB_USER=postgres \
    ANCHORE_DISABLE_METRICS_AUTH=false \
    ANCHORE_ENABLE_METRICS=false \
    ANCHORE_ENABLE_PACKAGE_FILTERING="true" \
    ANCHORE_ENDPOINT_HOSTNAME=localhost \
    ANCHORE_EVENTS_NOTIFICATIONS_ENABLED=false \
    ANCHORE_EXTERNAL_AUTHZ_ENDPOINT=null \
    ANCHORE_EXTERNAL_PORT=null \
    ANCHORE_EXTERNAL_TLS=false \
    ANCHORE_FEEDS_CLIENT_URL="https://ancho.re/v1/account/users" \
    ANCHORE_FEEDS_ENABLED=true \
    ANCHORE_FEEDS_SSL_VERIFY=true \
    ANCHORE_FEED_SYNC_INTERVAL_SEC=21600 \
    ANCHORE_FEEDS_TOKEN_URL="https://ancho.re/oauth/token" \
    ANCHORE_FEEDS_URL="http://mcs-psc.cb-psc.io/vulnerability_feed/v1/feeds" \
    ANCHORE_GLOBAL_CLIENT_CONNECT_TIMEOUT=0 \
    ANCHORE_GLOBAL_CLIENT_READ_TIMEOUT=0 \
    ANCHORE_GLOBAL_SERVER_REQUEST_TIMEOUT_SEC=180 \
    ANCHORE_GRYPE_DB_URL="https://toolbox-data.anchore.io/grype/databases/listing.json" \
    ANCHORE_HINTS_ENABLED=false \
    ANCHORE_HOST_ID="anchore-quickstart" \
    ANCHORE_INTERNAL_SSL_VERIFY=false \
    ANCHORE_LOG_LEVEL=INFO \
    ANCHORE_MAX_COMPRESSED_IMAGE_SIZE_MB=-1 \
    ANCHORE_OAUTH_ENABLED=false \
    ANCHORE_OAUTH_TOKEN_EXPIRATION=3600 \
    ANCHORE_SERVICE_DIR=/anchore_service \
    ANCHORE_SERVICE_PORT=8228 \
    ANCHORE_VULNERABILITIES_PROVIDER=null \
    ANCHORE_WEBHOOK_DESTINATION_URL=null

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
        skopeo && \
    yum clean all

# Copy the installed artifacts from the first stage
COPY --from=anchore-engine-builder /build_output /build_output

# Install anchore-cli into a virtual environment
RUN set -ex && \
    echo "updating pip" && \
    pip3 install --upgrade --no-index --find-links=/build_output/wheels/ pip && \
    echo "installing anchore-cli into virtual environment" && \
    python3 -m venv /anchore-cli && \
    source /anchore-cli/bin/activate && \
    pip3 install --no-index --find-links=/build_output/cli_wheels/ anchorecli && \
    deactivate

# Install required OS deps & application config files
RUN set -exo pipefail && \
    cp /build_output/deps/syft /usr/bin/syft && \
    cp /build_output/deps/grype /usr/bin/grype && \
    yum install -y /build_output/deps/*.rpm && \
    yum clean all

# Install anchore-engine & cleanup filesystem
RUN set -ex && \
    echo "installing anchore-engine and required dependencies" && \
    pip3 install --no-index --find-links=/build_output/wheels/ anchore-engine && \
    echo "copying default application config files" && \
    cp /build_output/LICENSE /licenses/ && \
    cp /build_output/configs/default_config.yaml /config/config.yaml && \
    md5sum /config/config.yaml > /config/build_installed && \
    cp /build_output/configs/docker-entrypoint.sh /docker-entrypoint.sh && \
    chmod +x /docker-entrypoint.sh && \
    cp -R $(pip3 show anchore-engine | grep Location: | cut -c 11-)/anchore_engine/conf/clamav/freshclam.conf /home/anchore/clamav/ && \
    chmod -R ug+rw /home/anchore/clamav
    # FIXME: This fails in our GitLab CI pipeline (possibly related to
    # https://gitlab.bit9.local/octarine/anchore/-/jobs/2549626, might require
    # the GitLab runner daemons to be updated)
    # echo "cleaning up unneccesary files used for testing/cache/build" && \
    # rm -rf \
    #    /build_output \
    #    /root/.cache \
    #    /usr/local/lib64/python3.8/site-packages/twisted/test \
    #    /usr/local/lib64/python3.8/site-packages/Crypto/SelfTest \
    #    /usr/share/doc

# Container runtime instructions

HEALTHCHECK --start-period=20s \
    CMD curl -f http://localhost:8228/health || exit 1

USER 1000

EXPOSE "${ANCHORE_SERVICE_PORT}"

WORKDIR /anchore-engine

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["anchore-manager", "service", "start", "--all"]
