# Anchore Engine [![CircleCI](https://circleci.com/gh/anchore/anchore-engine/tree/master.svg?style=svg)](https://circleci.com/gh/anchore/anchore-engine/tree/master)

For the most up-to-date information on Anchore Engine, Anchore CLI, and other Anchore software, please refer to the [Anchore Documentation](https://engine.anchore.io)

The Anchore Engine is an open-source project that provides a centralized service for inspection, analysis, and certification of container images. The Anchore Engine is provided as a Docker container image that can be run standalone or within an orchestration platform such as Kubernetes, Docker Swarm, Rancher, Amazon ECS, and other container orchestration platforms.

In addition, we also have several modular container tools that can be run standalone or integrated into automated workflows such as CI/CD pipelines.

- **[Syft](https://github.com/anchore/syft)**: a CLI tool and library for **generating a Software Bill of Materials** (SBOM) from container images and filesystems

- **[Grype](https://github.com/anchore/grype)**: a **vulnerability scanner** for container images and filesystems

The Anchore Engine can be accessed directly through a RESTful API or via the Anchore [CLI](https://github.com/anchore/anchore-cli).

With a deployment of Anchore Engine running in your environment, container images are downloaded and analyzed from Docker V2 compatible container registries and then evaluated against user-customizable policies to perform security, compliance, and best practices enforcement checks.

Anchore Engine can be used in several ways:

- Standalone or interactively.
- As a service integrated with your CI/CD to bring security/compliance/best-practice enforcement to your build pipeline
- As a component integrated into existing container monitoring and control frameworks via integration with its RESTful API.

Anchore Engine is also the OSS foundation for [Anchore Enterprise](https://anchore.com/enterprise), which adds a graphical UI (providing policy management, user management, a summary dashboard, security and policy evaluation reports, and many other graphical client controls), and other back-end features and modules.

## Installation / Getting Started

The Anchore Engine is distributed via [Docker](https://hub.docker.com/r/anchore/anchore-engine/).
Head over to the [Anchore Engine Documentation](https://engine.anchore.io) for:
- Quickstart
- Installation (docker-compose, helm)
- Usage (CLI, API)

#### Supported Operating Systems
- Alpine
- Amazon Linux 2
- CentOS
- Debian
- Google Distroless
- Oracle Linux
- Red Hat Enterprise Linux
- Red Hat Universal Base Image (UBI)
- Ubuntu

#### Supported Packages

- GEM
- Java Archive (jar, war, ear)
- NPM
- Python (PIP)
- [More!](https://docs.anchore.com/current/docs/engine/usage/cli_usage/images/inspecting_image_content/)

#### API

For the external API definition (the user-facing service), see [External API Swagger Spec](https://github.com/anchore/anchore-engine/blob/master/anchore_engine/services/apiext/swagger/swagger.yaml). If you have Anchore Engine running, you can also review the Swagger by directing your browser at http://<your-anchore-engine-api-host>:8228/v1/ui/ (NOTE: the trailing slash is required for the embedded swagger UI browser to be viewed properly).

Each service implements its own API, and all APIs are defined in Swagger/OpenAPI spec. You can find each in the _anchore_engine/services/\<servicename\>/api/swagger_ directory.

## Contributing
Check out our Contribution guidelines [here](./CONTRIBUTING.rst)

## Changelog
Our Changelog is available [here](./CHANGELOG.md)

## Developing

This repo was reformatted using [Black](https://black.readthedocs.io/en/stable/) in Nov. 2020. This commit can
be ignored in your local environment when using `git blame` since it impacted so many files. To ignore the commit you need
to configure git-blame to use the provided file:  .git-blame-ignore-revs as a list of commits to ignore for blame.

Set your local git configuration to use the provided file by running this from within the root of this source tree:
`git config blame.ignoreRevsFile .git-blame-ignore-revs`
