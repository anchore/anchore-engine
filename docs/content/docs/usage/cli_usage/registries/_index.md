---
title: "Working with Registries"
linkTitle: "Registries"
weight: 3
---

Using the API or CLI the Anchore Engine can be instructed to download an image from a public or private container registry.

The Anchore Engine will attempt to download images from any registry without requiring further configuration. However if
your registry requires authentication then the registry and corresponding credentials will need to be defined.
Anchore Engine can analyze images from any Docker V2 compatible registry.

![alt text](RegistryAccess.png)

Jump to the registry configuring guide for your registry:

- [Amazon Web Services ECR]({{< ref "ecr_configuration" >}})
- [Azure Container Registry ACR]({{< ref "acr_configuration" >}})
- [Google Container Registry GCR]({{< ref "gcr_configuration" >}})
