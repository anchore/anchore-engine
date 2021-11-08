# Anchore Engine [![CircleCI](https://circleci.com/gh/anchore/anchore-engine/tree/master.svg?style=svg)](https://circleci.com/gh/anchore/anchore-engine/tree/master)

For the most up-to-date information on Anchore Engine, Anchore CLI, and other Anchore software, please refer to the
[Anchore Documentation](https://engine.anchore.io).

## We'll be at KubeCon 2021!

Attending KubeCon 2021 in person? Join us for a meetup on **Tuesday, October 12th**.

We’ll have free swag, giveaways, snacks, and sips. Space will be limited, so make sure to
[save your seat](https://get.anchore.com/2021-kubecon-na-opensource-happy-hour/)!

---

The Anchore Engine is an open-source project that provides a centralized service for inspection, analysis, and
certification of container images. The Anchore Engine is provided as a Docker container image that can be run standalone
or within an orchestration platform such as Kubernetes, Docker Swarm, Rancher, Amazon ECS, and other container
orchestration platforms.

In addition, we also have several modular container tools that can be run standalone or integrated into automated
workflows such as CI/CD pipelines.

- **[Syft](https://github.com/anchore/syft)**: a CLI tool and library for **generating a Software Bill of Materials**
  (SBOM) from container images and filesystems.

- **[Grype](https://github.com/anchore/grype)**: a **vulnerability scanner** for container images and filesystems.

The Anchore Engine can be accessed directly through a RESTful API or via the Anchore
[CLI](https://github.com/anchore/anchore-cli).

With a deployment of Anchore Engine running in your environment, container images are downloaded and analyzed from
Docker V2 compatible container registries and then evaluated against user-customizable policies to perform security,
compliance, and best practices enforcement checks.

Anchore Engine can be used in several ways:

- Standalone or interactively.
- As a service integrated with your CI/CD to bring security/compliance/best-practice enforcement to your build pipeline
- As a component integrated into existing container monitoring and control frameworks via integration with its RESTful
  API.

Anchore Engine is also the OSS foundation for [Anchore Enterprise](https://anchore.com/enterprise), which adds a
graphical UI (providing policy management, user management, a summary dashboard, security and policy evaluation reports,
and many other graphical client controls), and other back-end features and modules.

**Supported Operating Systems**

- Alpine
- Amazon Linux 2
- CentOS
- Debian
- Google Distroless
- Oracle Linux
- Red Hat Enterprise Linux
- Red Hat Universal Base Image (UBI)
- Ubuntu

**Supported Packages**

- GEM
- Java Archive (jar, war, ear)
- NPM
- Python (PIP)

## Installation

There are several ways to get started with Anchore Engine, for the latest information on quickstart and full production
installation with docker-compose, Helm, and other methods, please visit:

- [Anchore Engine Installation](https://engine.anchore.io/docs/install/)

The Anchore Engine is distributed as a [Docker Image](https://hub.docker.com/r/anchore/anchore-engine/) available from
DockerHub.

## Quick Start (TLDR)

See [documentation](https://engine.anchore.io/docs/quickstart/) for the full quickstart guide.

To quickly bring up an installation of Anchore Engine on a system with docker (and docker-compose) installed, follow
these simple steps:

```
curl https://engine.anchore.io/docs/quickstart/docker-compose.yaml > docker-compose.yaml
docker-compose up -d
```

Once the Engine is up and running, you can begin to interact with the system using the CLI.

## Getting Started using the CLI

The [Anchore CLI](https://github.com/anchore/anchore-cli) is an easy way to control and interact with the Anchore Engine.

The Anchore CLI can be installed using the Python pip command, or by running the CLI from the
[Anchore Engine CLI](https://hub.docker.com/r/anchore/engine-cli) container image. See the
[Anchore CLI](https://github.com/anchore/anchore-cli) project on Github for code and more installation options and
usage.

## CLI Quick Start (TLDR)

By default, the Anchore CLI tries to connect to the Anchore Engine at http://localhost:8228/v1 with no authentication.
The username, password, and URL for the server can be passed to the Anchore CLI as command-line arguments:

    --u   TEXT   Username     eg. admin
    --p   TEXT   Password     eg. foobar
    --url TEXT   Service URL  eg. http://localhost:8228/v1

Rather than passing these parameters for every call to the tool, they can also be set as environment variables:

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

List feeds and wait for at least one vulnerability data feed sync to complete. The first sync can take some time
(20-30 minutes) after that syncs will only merge deltas.

    anchore-cli system feeds list
    anchore-cli system wait

Obtain the results of the vulnerability scan on an image:

    anchore-cli image vuln docker.io/library/debian:latest os

List operating system packages present in an image:

    anchore-cli image content docker.io/library/debian:latest os

## API

For the external API definition (the user-facing service), see
[External API Swagger Spec](https://github.com/anchore/anchore-engine/blob/master/anchore_engine/services/apiext/swagger/swagger.yaml).
If you have Anchore Engine running, you can also review the Swagger by directing your browser at
`http://<your-anchore-engine-api-host>:8228/v1/ui/` (NOTE: the trailing slash is required for the embedded swagger UI
browser to be viewed properly).

Each service implements its own API, and all APIs are defined in Swagger/OpenAPI spec. You can find each in the
`anchore_engine/services/\<servicename\>/api/swagger` directory.

## More Information

For further details on the use of the Anchore CLI with the Anchore Engine, please refer to the
[Anchore Engine Documentation](https://engine.anchore.io/)

## Developing

This repo was reformatted using [Black](https://black.readthedocs.io/en/stable/) in Nov. 2020. This commit can
be ignored in your local environment when using `git blame` since it impacted so many files. To ignore the commit you
need to configure git-blame to use the provided file: `.git-blame-ignore-revs` as a list of commits to ignore for blame.

Set your local git configuration to use the provided file by running this from within the root of this source tree:
```shell
git config blame.ignoreRevsFile .git-blame-ignore-revs
````

### Setting up your Virtual Environment
Anchore Engine uses `pip-compile` from the [`pip-tools`](https://pip-tools.readthedocs.io/en/latest/) package to manage
the requirements for itself and for its tests. To set up your virtual environment using `pip-tools`, use the following
commands:

```shell
python -m venv .venv
source .venv/bin/activate
pip install pip-tools
pip-sync
pip-sync requirements-test.txt  # If you want the test packages installed too.
```

### Updating Requirements
With `pip-compile`, we do not need to (nor should we) change `requirements.txt` directly. We can instead add our new
packages or package versions to `requirements.in` or `requirements-test.in` and then we can run the following to
update our `requirements*.txt` files:

```shell
# If not already, make sure that you're in your virtual environment.
source .venv/bin/activate
pip-compile requirements.in
pip-compile requirements-test.in
pip-sync  # Update the virtual environment to the current state of requirements.txt
```
