---
title: "Anchore Engine Installation"
linkTitle: "Installing"
weight: 3
---

The Anchore Engine is distributed as a [Docker Image](https://hub.docker.com/r/anchore/anchore-engine) available from DockerHub that can be scaled horizontally to handle hundreds of thousands of images.

A PostgreSQL database is required to provide persistent storage for the Anchore Engine, this database can be run as a Docker Container or provided as an external service to be accessed by the Anchore Engine. For detailed requirements for the database, network and storage please refer to the System Requirements page.

The Engine is comprised of six smaller micro-services that can be deployed in a single container or scaled out to handle load.

- Core Service
    - API Service
    - Catalog Service
    - Queuing Service
    - Policy Engine Service
    - Kubernetes Webhook Service

- Workers
    - Image Analyzer Service

For most installations a single instance of the Anchore Engine container running all 6 services is sufficient however multiple Analyzer services can be spun up to handle heavy load and to reduce analysis time for large deployments.

### Deployment Models

The Anchore Engine container can be deployed manually, using Docker Compose, Kubernetes or any container orchestration platform.

The following guides outline deployment of the Anchore Engine using common deployment models.

- Docker Compose
    Install and run Anchore using Docker Compose including a PostgreSQL container.

- Kubernetes
    Install and run on Kubernetes using PostgreSQL within the POD or as an external service.