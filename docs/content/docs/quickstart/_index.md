---
title: "Quickstart"
linkTitle: "Quickstart"
weight: 1
---

## Important note on project status

As of 2023, Anchore Engine is no longer maintained as an active project. Users are recommended to install Syft or Grype.

## Introduction

In this section, you'll learn how to get up and running with a stand-alone Anchore Engine installation for trial, demonstration and review with [Docker Compose](https://docs.docker.com/compose/install/).


## Configuration Files for this Quickstart:

* [Docker Compose File](./docker-compose.yaml)

* (Optional) [Prometheus Configuration for Monitoring](./anchore-prometheus.yml). See [Enabling Prometheus Monitoring]({{< ref "#optional-enabling-prometheus-monitoring" >}})

* (Optional) [Swagger UI Nginx Proxy](./anchore-swaggerui-nginx.conf) to browse the API with a Swagger UI. See [Enabling Swagger UI]({{< ref "#enabling-swagger-ui" >}})


## Requirements

The following instructions assume you are using a system running Docker v1.12 or higher, and a version of Docker Compose that supports at least v2 of the docker-compose configuration format.

* A stand-alone installation requires at least 4GB of RAM, and enough disk space available to support the largest container images you intend to analyze (we recommend 3x largest container image size).  For small images/testing (basic Linux distro images, database images, etc), between 5GB and 10GB of disk space should be sufficient.


### Step 1: Download the docker-compose.yaml file and start.

```
# curl -O https://engine.anchore.io/docs/quickstart/docker-compose.yaml
# docker-compose up -d
```

### Step 2: Verify service availability

After a few moments (depending on system speed), your Anchore Engine services should be up and running, ready to use.  You can verify the containers are running with docker-compose:

```
# docker-compose ps
                Name                               Command                        State           Ports
-------------------------------------------------------------------------------------------------------
anchorequickstart_anchore-db_1                   docker-entrypoint.sh postgres    Up      5432/tcp
anchorequickstart_analyzer_1              /docker-entrypoint.sh anch ...   Up      8228/tcp
anchorequickstart_api_1                   /docker-entrypoint.sh anch ...   Up      0.0.0.0:8228->8228/tcp
anchorequickstart_catalog_1               /docker-entrypoint.sh anch ...   Up      8228/tcp
anchorequickstart_policy-engine_1         /docker-entrypoint.sh anch ...   Up      8228/tcp
anchorequickstart_simpleq_1               /docker-entrypoint.sh anch ...   Up      8228/tcp
```

You can run a command to get the status of the Anchore Engine services:

```
# docker-compose exec api anchore-cli system status
Service policy_engine (anchore-quickstart, http://policy-engine:8228): up
Service simplequeue (anchore-quickstart, http://simpleq:8228): up
Service catalog (anchore-quickstart, http://catalog:8228): up
Service analyzer (anchore-quickstart, http://analyzer:8228): up
Service apiext (anchore-quickstart, http://api:8228): up

Engine DB Version: 0.0.13
Engine Code Version: 0.8.1
```

**Note:** The first time you run Anchore Engine, it will take some time (10+ minutes, depending on network speed) for the vulnerability data to get synced into the engine.  For the best experience, wait until the core vulnerability data feeds have completed before proceeding.  You can check the status of your feed sync using the CLI:

```
# docker-compose exec api anchore-cli system feeds list
Feed                   Group                  LastSync                    RecordCount
vulnerabilities        alpine:3.10            2021-11-29T20:53:28Z        2329
vulnerabilities        alpine:3.11            2021-11-29T20:53:28Z        2656
vulnerabilities        alpine:3.12            2021-11-29T20:53:28Z        3009
vulnerabilities        alpine:3.13            2021-11-29T20:53:28Z        3376
vulnerabilities        alpine:3.14            2021-11-29T20:53:28Z        3741
vulnerabilities        alpine:3.2             2021-11-29T20:53:28Z        306
vulnerabilities        alpine:3.3             2021-11-29T20:53:28Z        471
vulnerabilities        alpine:3.4             2021-11-29T20:53:28Z        683
vulnerabilities        alpine:3.5             2021-11-29T20:53:28Z        903
vulnerabilities        alpine:3.6             2021-11-29T20:53:28Z        1077
vulnerabilities        alpine:3.7             2021-11-29T20:53:28Z        1462
vulnerabilities        alpine:3.8             2021-11-29T20:53:28Z        1675
vulnerabilities        alpine:3.9             2021-11-29T20:53:28Z        1962
vulnerabilities        amzn:2                 2021-11-29T20:53:28Z        696
vulnerabilities        debian:10              2021-11-29T20:53:28Z        26464
vulnerabilities        debian:11              2021-11-29T20:53:28Z        23910
vulnerabilities        debian:12              2021-11-29T20:53:28Z        22963
vulnerabilities        debian:7               2021-11-29T20:53:28Z        20455
vulnerabilities        debian:8               2021-11-29T20:53:28Z        24058
vulnerabilities        debian:9               2021-11-29T20:53:28Z        26354
vulnerabilities        debian:unstable        2021-11-29T20:53:28Z        28816
vulnerabilities        github:composer        2021-11-29T20:53:28Z        449
vulnerabilities        github:gem             2021-11-29T20:53:28Z        423
vulnerabilities        github:go              2021-11-29T20:53:28Z        223
vulnerabilities        github:java            2021-11-29T20:53:28Z        864
vulnerabilities        github:npm             2021-11-29T20:53:28Z        2151
vulnerabilities        github:nuget           2021-11-29T20:53:28Z        153
vulnerabilities        github:python          2021-11-29T20:53:28Z        850
vulnerabilities        nvd                    2021-11-29T20:53:28Z        174005
vulnerabilities        ol:5                   2021-11-29T20:53:28Z        1255
vulnerabilities        ol:6                   2021-11-29T20:53:28Z        1642
vulnerabilities        ol:7                   2021-11-29T20:53:28Z        1641
vulnerabilities        ol:8                   2021-11-29T20:53:28Z        644
vulnerabilities        rhel:5                 2021-11-29T20:53:28Z        7764
vulnerabilities        rhel:6                 2021-11-29T20:53:28Z        7872
vulnerabilities        rhel:7                 2021-11-29T20:53:28Z        7218
vulnerabilities        rhel:8                 2021-11-29T20:53:28Z        3369
vulnerabilities        sles:11                2021-11-29T20:53:28Z        594
vulnerabilities        sles:11.1              2021-11-29T20:53:28Z        5987
vulnerabilities        sles:11.2              2021-11-29T20:53:28Z        3291
vulnerabilities        sles:11.3              2021-11-29T20:53:28Z        6874
vulnerabilities        sles:11.4              2021-11-29T20:53:28Z        6388
vulnerabilities        sles:12                2021-11-29T20:53:28Z        4244
vulnerabilities        sles:12.1              2021-11-29T20:53:28Z        5203
vulnerabilities        sles:12.2              2021-11-29T20:53:28Z        6896
vulnerabilities        sles:12.3              2021-11-29T20:53:28Z        7722
vulnerabilities        sles:12.4              2021-11-29T20:53:28Z        7703
vulnerabilities        sles:12.5              2021-11-29T20:53:28Z        7878
vulnerabilities        sles:15                2021-11-29T20:53:28Z        1136
vulnerabilities        sles:15.1              2021-11-29T20:53:28Z        609
vulnerabilities        ubuntu:12.04           2021-11-29T20:53:28Z        14962
vulnerabilities        ubuntu:12.10           2021-11-29T20:53:28Z        5652
vulnerabilities        ubuntu:13.04           2021-11-29T20:53:28Z        4127
vulnerabilities        ubuntu:14.04           2021-11-29T20:53:28Z        26740
vulnerabilities        ubuntu:14.10           2021-11-29T20:53:28Z        4456
vulnerabilities        ubuntu:15.04           2021-11-29T20:53:28Z        6159
vulnerabilities        ubuntu:15.10           2021-11-29T20:53:28Z        6513
vulnerabilities        ubuntu:16.04           2021-11-29T20:53:28Z        23858
vulnerabilities        ubuntu:16.10           2021-11-29T20:53:28Z        8647
vulnerabilities        ubuntu:17.04           2021-11-29T20:53:28Z        9157
vulnerabilities        ubuntu:17.10           2021-11-29T20:53:28Z        7943
vulnerabilities        ubuntu:18.04           2021-11-29T20:53:28Z        18111
vulnerabilities        ubuntu:18.10           2021-11-29T20:53:28Z        8399
vulnerabilities        ubuntu:19.04           2021-11-29T20:53:28Z        8668
vulnerabilities        ubuntu:19.10           2021-11-29T20:53:28Z        8430
vulnerabilities        ubuntu:20.04           2021-11-29T20:53:28Z        11964
vulnerabilities        ubuntu:20.10           2021-11-29T20:53:28Z        9992
vulnerabilities        ubuntu:21.04           2021-11-29T20:53:28Z        10475
vulnerabilities        ubuntu:21.10           2021-11-29T20:53:28Z        10159
```

As soon as you see RecordCount values > 0 for all vulnerability groups, the system is fully populated and ready to present vulnerability results.   Note that feed syncs are incremental, so the next time you start up Anchore Engine it will be ready immediately.  The CLI tool includes a useful utility that will block until the feeds have completed a successful sync:

```
# docker-compose exec api anchore-cli system wait
Starting checks to wait for anchore-engine to be available timeout=-1.0 interval=5.0
API availability: Checking anchore-engine URL (http://localhost:8228)...
API availability: Success.
Service availability: Checking for service set (catalog,apiext,policy_engine,simplequeue,analyzer)...
Service availability: Success.
Feed sync: Checking sync completion for feed set (vulnerabilities)...
Feed sync: Checking sync completion for feed set (vulnerabilities)...
...
...
Feed sync: Success.

```

### Step 3: Begin using Anchore

Start using the anchore-engine service to analyze images - a short example follows which demonstrates a basic workflow of adding a container image for analysis, waiting for the analysis to complete, then running content reports, vulnerability scans and policy evaluations against the analyzed image.

```
# docker-compose exec api anchore-cli image add docker.io/library/debian:7
...
...

# docker-compose exec api anchore-cli image wait docker.io/library/debian:7
Status: analyzing
Waiting 5.0 seconds for next retry.
Status: analyzing
Waiting 5.0 seconds for next retry.
...
...

# docker-compose exec api anchore-cli image content docker.io/library/debian:7 os
Package                       Version                      License
apt                           0.9.7.9+deb7u7               GPLv2+
base-files                    7.1wheezy11                  Unknown
debconf                       1.5.49                       BSD-2-clause
...
...

# docker-compose exec api anchore-cli image vuln docker.io/library/debian:7 all
Vulnerability ID        Package                                  Severity          Fix         Vulnerability URL
CVE-2005-2541           tar-1.26+dfsg-0.1+deb7u1                 Negligible        None        https://security-tracker.debian.org/tracker/CVE-2005-2541
CVE-2007-5686           login-1:4.1.5.1-1+deb7u1                 Negligible        None        https://security-tracker.debian.org/tracker/CVE-2007-5686
CVE-2007-5686           passwd-1:4.1.5.1-1+deb7u1                Negligible        None        https://security-tracker.debian.org/tracker/CVE-2007-5686
CVE-2007-6755           libssl1.0.0-1.0.1t-1+deb7u4              Negligible        None        https://security-tracker.debian.org/tracker/CVE-2007-6755
...
...
...

# docker-compose exec api anchore-cli evaluate check docker.io/library/debian:7
Image Digest: sha256:92d507d81bd3b0459b121215f6f9d8249bb154c8b65e041942745dcc6309a7b5
Full Tag: docker.io/library/debian:7
Status: pass
Last Eval: 2018-11-06T22:51:47Z
Policy ID: 2c53a13c-1765-11e8-82ef-23527761d060
```

**Note:** This document is intended to serve as a quickstart guide. Before moving further with Anchore to explore the scanning, policy evaluation, image content reporting, CI/CD integrations and other capabilities, it is highly recommended that you enhance your learning by reading the [Overview]({{< ref "/docs/general" >}}) sections to gain a deeper understanding of fundamentals, concepts, and proper usage.

### Next Steps

Now that you have Anchore Engine running, you can begin to learn more about Anchore architecture, Anchore concepts, and Anchore usage.

- For more information about Anchore Engine, see [Overview]({{< ref "/docs/general" >}}).
- For more information about Anchore Concepts, see [Concepts]({{< ref "/docs/general/concepts" >}}).
- For more information about Anchore Usage, see [Usage]({{< ref "/docs/usage" >}}).


### Optional: Enabling Prometheus Monitoring

1. Uncomment the following section at the bottom of the docker-compose.yaml file:

    ```
    #  # Uncomment this section to add a prometheus instance to gather metrics. This is mostly for quickstart to demonstrate prometheus metrics exported
    #  prometheus:
    #    image: docker.io/prom/prometheus:latest
    #    depends_on:
    #      - api
    #    volumes:
    #      - ./anchore-prometheus.yml:/etc/prometheus/prometheus.yml:z
    #    logging:
    #      driver: "json-file"
    #      options:
    #        max-size: 100m
    #    ports:
    #      - "9090:9090"
    #
    ```

1. For each service entry in the docker-compose.yaml, change the following to enable metrics in the API for each service

    ```
    ANCHORE_ENABLE_METRICS=false
    ```

    to

    ```
    ANCHORE_ENABLE_METRICS=true
    ```

1. Download the example prometheus configuration into the same directory as the docker-compose.yaml file, with name _anchore-prometheus.yml_

    ```
    curl -O https://engine.anchore.io/docs/quickstart/anchore-prometheus.yml
    docker-compose up -d
    ```

    You should see a new container started and can access prometheus via your browser on `http://localhost:9090`


### Optional: Enabling Swagger UI

1. Uncomment the following section at the bottom of the docker-compose.yaml file:

    ```
    #  # Uncomment this section to run a swagger UI service, for inspecting and interacting with the anchore engine API via a browser (http://localhost:8080 by default, change if needed in both sections below)
    #  swagger-ui-nginx:
    #    image: docker.io/nginx:latest
    #    depends_on:
    #      - api
    #      - swagger-ui
    #    ports:
    #      - "8080:8080"
    #    volumes:
    #      - ./anchore-swaggerui-nginx.conf:/etc/nginx/nginx.conf:z
    #    logging:
    #      driver: "json-file"
    #      options:
    #        max-size: 100m
    #  swagger-ui:
    #    image: docker.io/swaggerapi/swagger-ui
    #    environment:
    #      - URL=http://localhost:8080/v1/swagger.json
    #    logging:
    #      driver: "json-file"
    #      options:
    #        max-size: 100m
    ```

1. Download the nginx configuration into the same directory as the docker-compose.yaml file, with name _anchore-swaggerui-nginx.conf_

    ```
    curl -O https://engine.anchore.io/docs/quickstart/anchore-swaggerui-nginx.conf
    docker-compose up -d
    ```

    You should see a new container started and can access swagger via your browser on `http://localhost:8080`

