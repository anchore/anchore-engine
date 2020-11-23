---
title: "Accessing the Anchore Engine API"
linkTitle: "Using the API"
weight: 3
---

## Introduction

The Anchore Engine API is documented using the OpenAPI Specification (Swagger) and the source for the latest development version can be found in GitHub in [swagger.yaml](https://github.com/anchore/anchore-engine/blob/master/anchore_engine/services/apiext/swagger/swagger.yaml) document within the external API service.  There are also a variety of ways in which the API specification can be accessed.

### Online

You can browse latest stable the Anchore API specification [here](./specs/swagger.yaml)

### Local Swagger JSON

The JSON definition for the API specification for your specific instance of Anchore can be downloaded from a running Anchore Engine service at the following URI:

http://{servername:port}/v1/swagger.json

e.g.

http://localhost:8228/v1/swagger.json

### Local Swagger UI

Finally, Anchore includes the ability to deploy a sidecar set of containers that provide a local Swagger UI, allowing for the API to be viewed and tested within a web browser. The Swagger UI is accessed by first enabling an nginx proxy service and swagger-ui service that run alongside your anchore engine deployment, and then directing your browser at the nginx proxy service.


For instructions on deploying the Swagger UI as a sidecar, please see [Swagger in our FAQs.]({{< ref "/docs/faq" >}})
