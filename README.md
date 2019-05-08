# Anchore Engine [![CircleCI](https://circleci.com/gh/anchore/anchore-engine/tree/master.svg?style=svg)](https://circleci.com/gh/anchore/anchore-engine/tree/master)

For the most up-to-date information on Anchore Engine, Anchore CLI, and other Anchore software, please refer to the [Anchore Documentation](https://docs.anchore.com)

The Anchore Engine is an open source project that provides a centralized service for inspection, analysis and certification of container images. The Anchore engine is provided as a Docker container image that can be run standalone, or within an orchestration platform such as Kubernetes, Docker Swarm, Rancher, Amazon ECS, and other container orchestration platforms.

The Anchore engine can be accessed directly through a RESTful API or via the Anchore [CLI](https://github.com/anchore/anchore-cli).

With a deployment of Anchore Engine running in your environment, container images are downloaded and analyzed from Docker V2 compatible container registries, and then evaluated against user customizable policies to perform security, compliance and best practices enforcement checks.  Anchore Engine is appropriate to use stand alone/interactively, as a service integrated with your CI/CD to bring security/compliance/best-practice enforcement to your build pipeline, or as a component integrated into existing container monitoring and control frameworks via integration with it's RESTful API.

Anchore Engine is also the OSS foundation for [Anchore Enterprise](https://anchore.com/enterprise), which adds a graphical UI (providing policy management, user management, a summary dashboard, security and policy evaluation reports, and many other graphical client controls), and other back-end features and modules.

## Installation

There are several ways to get started with Anchore Engine, for the latest information on quickstart and full production installation with docker-compose, Helm, and other methods, please visit:

- [Anchore Engine Installation](https://docs.anchore.com/current/docs/engine/engine_installation/)

The Anchore Engine is distributed as a [Docker Image](https://hub.docker.com/r/anchore/anchore-engine/) available from DockerHub.

## Quick Start (TLDR)

To quickly bring up an installation of Anchore Engine on a system with docker (and docker-compose) installed, follow these simple steps:

```
mkdir ~/aevolume
cd ~/aevolume

docker pull docker.io/anchore/anchore-engine:latest
docker create --name ae docker.io/anchore/anchore-engine:latest
docker cp ae:/docker-compose.yaml ~/aevolume/docker-compose.yaml
docker rm ae

docker-compose pull
docker-compose up -d
```

Once the Engine is up and running, you can begin to interact with the system using the CLI.

## Getting Started using the CLI

The [Anchore CLI](https://github.com/anchore/anchore-cli) is an easy way to control and interact with the Anchore Engine.

The Anchore CLI can be installed using the Python pip command, or by running the CLI from the [Anchore Engine CLI](https://cloud.docker.com/u/anchore/repository/docker/anchore/engine-cli) container image.  See the [Anchore CLI](https://github.com/anchore/anchore-cli) project on github for code and more installation options and usage.

## CLI Quick Start (TLDR)

By default the Anchore CLI will try to connect to the Anchore Engine at http://localhost:8228/v1 with no authentication.
The username, password and URL for the server can be passed to the Anchore CLI as command line arguments:

    --u   TEXT   Username     eg. admin
    --p   TEXT   Password     eg. foobar
    --url TEXT   Service URL  eg. http://localhost:8228/v1

Rather than passing these parameters for every call to the cli, they can also be set as environment variables:

    ANCHORE_CLI_URL=http://myserver.example.com:8228/v1
    ANCHORE_CLI_USER=admin
    ANCHORE_CLI_PASS=foobar

Add an image to the Anchore Engine:

    anchore-cli image add docker.io/library/debian:latest

Wait for the image to move to the 'analyzed' state:

    anchore-cli image wait docker.io/library/debian:latest

List images analyzed by the Anchore Engine:

    anchore-cli image list

Get image overview and summary information:

    anchore-cli image get docker.io/library/debian:latest

List feeds and wait for at least one vulnerability data feed sync to complete (first sync can take some time (20-30 minutes), thereafter syncs will only merge deltas)

    anchore-cli system feeds list
    anchore-cli system wait

Obtain the results of the vulnerability scan on an image:

    anchore-cli image vuln docker.io/library/debian:latest os

List operating system packages present in an image:

    anchore-cli image content docker.io/library/debian:latest os

Perform a policy evaluation against an image using the default policy:

    anchore-cli evaluate check docker.io/library/debian:latest

View other available policies from the [Anchore Policy Hub](https://www.github.com/anchore/hub)

    anchore-cli policy hub --help
    anchore-cli policy hub list

## API

For the external API definition (the user-facing service), see [External API Swagger Spec](https://github.com/anchore/anchore-engine/blob/master/anchore_engine/services/apiext/swagger/swagger.yaml).  If you have Anchore Engine running, you can also review the Swagger by directing your browser at http://<your-anchore-engine-api-host>:8228/v1/ui/ (NOTE: the trailing slash is required for the embedded swagger UI browser to be viewed properly).

Each service implements its own API, and all APIs are defined in Swagger/OpenAPI spec. You can find each in the _anchore_engine/services/\<servicename\>/api/swagger_ directory.

## More Information

For further details on use of the Anchore CLI with the Anchore Engine please refer to the [Anchore Engine Documentation](https://docs.anchore.com)

