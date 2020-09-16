# Anchore Engine [![CircleCI](https://circleci.com/gh/anchore/anchore-engine/tree/master.svg?style=svg)](https://circleci.com/gh/anchore/anchore-engine/tree/master)

For the most up-to-date information on Anchore Engine, Anchore CLI, and other Anchore software, please refer to the [Anchore Documentation](https://docs.anchore.com)

The Anchore Engine is an open-source project that provides a centralized service for inspection, analysis, and certification of container images. The Anchore Engine is provided as a Docker container image that can be run standalone or within an orchestration platform such as Kubernetes, Docker Swarm, Rancher, Amazon ECS, and other container orchestration platforms.

With a deployment of Anchore Engine running in your environment, container images are downloaded and analyzed from Docker V2 compatible container registries and then evaluated against user-customizable policies to perform security, compliance, and best practices enforcement checks.

Anchore Engine can be used in several ways:

* Standalone or interactively.
* As a service integrated with your CI/CD to bring security/compliance/best-practice enforcement to your build pipeline
* As a component integrated into existing container monitoring and control frameworks via integration with its RESTful API.

Anchore Engine is also the OSS foundation for [Anchore Enterprise](https://anchore.com/enterprise), which adds a graphical UI (providing policy management, user management, a summary dashboard, security and policy evaluation reports, and many other graphical client controls), and other back-end features and modules.

## Installation / Getting Started

The Anchore Engine is distributed via [Docker](https://hub.docker.com/r/anchore/anchore-engine/).
Head over to the [Anchore Engine Documentation](https://docs.anchore.com/current/docs/engine/) for:
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

## Contributing
Check out our Contribution guidelines [here](./CONTRIBUTING.rst)

## Changelog
Our Changelog is available [here](./CHANGELOG.md)