---
title: "Configuring Content Hints"
linkTitle: "Configuring Content Hints"
weight: 5
---

For an overview of the content hints and overrides features, see the [feature overview]({{<ref "/docs/general/concepts/images/analysis/content_hints" >}})

## Enabling Content Hints

This feature is disabled by default to ensure that images may not exercise this feature without the admin's explicit approval.

In the each analyzer's ```config.yaml``` file (by default at ```/config/config.yaml```):

Set the ```enable_hints: true``` setting in the ```analyzer``` service section of config.yaml.  

If using the default config.yaml included in the image, you may instead set an environment variable (e.g for use in our provided config for Docker Compose for [Quickstart]({{< ref "/docs/quickstart" >}})):

```ANCHORE_HINTS_ENABLED=true``` environment variable for the analyzer service.

For Helm: see the Helm installation instructions for enabling the hints file mechanism when deploying with Helm.
