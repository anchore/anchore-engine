---
title: "Security"
weight: 1
---

The Anchore Engine is deployed as container images that can be run manually, using Docker Compose, Kubernetes or any container platform that supports Docker compatible images.

By default, the Anchore Engine does not require any special permissions and can be run as an unprivileged container with no access to the underlying Docker host. *Note:* The Engine can be configured to pull images through the Docker Socket however this is not a recommended configuration as it grants the Anchore container added privileges and may incur a performance impact on the Docker Host.
