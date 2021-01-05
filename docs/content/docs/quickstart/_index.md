---
title: "Quickstart"
linkTitle: "Quickstart"
weight: 1
---

## Introduction

In this section, you'll learn how to get up and running with a stand-alone Anchore Engine installation for trial, demonstration and review with [Docker Compose](https://docs.docker.com/compose/install/).


## Configuration Files for this Quickstart:

* [Docker Compose File](./docker-compose.yaml)

* (Optional) [Prometheus Configuration for Monitoring](./anchore-prometheus.yml). See [Enabling Prometheus Monitoring]({{< ref "#optional-enabling-prometheus-monitoring" >}})

* (Optional) [Swagger UI Nginx Proxy](./anchore-swaggerui-nginx.conf) to browse the API with a Swagger UI. See [Enabling Swagger UI]({{< ref "#enabling-swagger-ui" >}})


## Requirements

The following instructions assume you are using a system running Docker v1.12 or higher, and a version of Docker Compose that supports at least v2 of the docker-compose configuration format.

* A stand-alone installation will requires at least 4GB of RAM, and enough disk space available to support the largest container images you intend to analyze (we recommend 3x largest container image size).  For small images/testing (basic Linux distro images, database images, etc), between 5GB and 10GB of disk space should be sufficient.


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
Feed                   Group                  LastSync                          RecordCount        
vulnerabilities        alpine:3.10            2020-04-27T19:49:45.186409        1725               
vulnerabilities        alpine:3.11            2020-04-27T19:49:59.993730        1904               
vulnerabilities        alpine:3.3             2020-04-27T19:50:16.213013        457                
vulnerabilities        alpine:3.4             2020-04-27T19:50:20.128136        681                
vulnerabilities        alpine:3.5             2020-04-27T19:50:25.876762        875                
vulnerabilities        alpine:3.6             2020-04-27T19:50:33.361682        1051               
vulnerabilities        alpine:3.7             2020-04-27T19:50:42.354798        1395               
vulnerabilities        alpine:3.8             2020-04-27T19:50:54.311199        1486               
vulnerabilities        alpine:3.9             2020-04-27T19:51:07.340326        1558               
vulnerabilities        amzn:2                 2020-04-27T19:51:20.726861        327                
vulnerabilities        centos:5               2020-04-27T19:51:31.586422        1347               
vulnerabilities        centos:6               2020-04-27T19:51:57.345700        1403               
vulnerabilities        centos:7               2020-04-27T19:52:26.350592        1063               
vulnerabilities        centos:8               2020-04-27T19:52:59.187517        215                
vulnerabilities        debian:10              2020-04-27T19:53:08.194067        22580              
vulnerabilities        debian:11              2020-04-27T19:56:03.833415        19681              
vulnerabilities        debian:7               2020-04-27T19:58:44.907852        20455              
vulnerabilities        debian:8               pending                           12500              
vulnerabilities        debian:9               pending                           None               
vulnerabilities        debian:unstable        pending                           None               
vulnerabilities        ol:5                   pending                           None               
vulnerabilities        ol:6                   pending                           None               
vulnerabilities        ol:7                   pending                           None               
vulnerabilities        ol:8                   pending                           None               
vulnerabilities        rhel:5                 pending                           None               
vulnerabilities        rhel:6                 pending                           None               
vulnerabilities        rhel:7                 pending                           None               
vulnerabilities        rhel:8                 pending                           None               
vulnerabilities        ubuntu:12.04           pending                           None               
vulnerabilities        ubuntu:12.10           pending                           None               
vulnerabilities        ubuntu:13.04           pending                           None               
vulnerabilities        ubuntu:14.04           pending                           None               
vulnerabilities        ubuntu:14.10           pending                           None               
vulnerabilities        ubuntu:15.04           pending                           None               
vulnerabilities        ubuntu:15.10           pending                           None               
vulnerabilities        ubuntu:16.04           pending                           None               
vulnerabilities        ubuntu:16.10           pending                           None               
vulnerabilities        ubuntu:17.04           pending                           None               
vulnerabilities        ubuntu:17.10           pending                           None               
vulnerabilities        ubuntu:18.04           pending                           None               
vulnerabilities        ubuntu:18.10           pending                           None               
vulnerabilities        ubuntu:19.04           pending                           None               
vulnerabilities        ubuntu:19.10           pending                           None               
vulnerabilities        ubuntu:20.04           pending                           None
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

Now that you have Anchore Engine running, you can begin to learning more about Anchore Architecture, Anchore Concepts and Anchore Usage.

- To learn more about Anchore Engine, go to [Overview]({{< ref "/docs/general" >}})
- To learn more about Anchore Concepts, go to [Concepts]({{< ref "/docs/general/concepts" >}})
- To learn more about using Anchore Usage, go to [Usage]({{< ref "/docs/usage" >}})


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

    You should see a new container started and can access prometheus via your browser on `http://localhost:8080/ui/`

