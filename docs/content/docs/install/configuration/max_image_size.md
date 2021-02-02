---
title: "Max Image Size"
linkTitle: "Max Image Size"
weight: 5
---

## Setting Size Filter
As of v0.9.1, Anchore Engine can be configured to have a size limit for images being added for analysis. Images that exceed the configured maximum size will not be added to Anchore and the catalog service will log an error message providing details of the failure. This size limit is applied when adding images to anchore via the [api/cli]({{< ref "docs/usage/cli_usage/images/_index.md#adding-an-image" >}}), [tag subscriptions]({{< ref "docs/usage/cli_usage/subscriptions/_index.md#tag-updates" >}}), and [repository watchers]({{< ref "/docs/usage/cli_usage/repositories/_index.md#watching-repositories" >}}).

The max size feature is disabled by default but can be enabled via  `max_compressed_image_size_mb` in the configuration file, which represents the size limit in MB of the compressed image. Values less than 0 will disable the feature and allow images of any size to be added to Anchore. A value of 0 will be enforced and prevent any images from being added. Non-integer values will cause bootstrap of the service to fail. If using compose with the default config, this can be set through the `ANCHORE_MAX_COMPRESSED_IMAGE_SIZE_MB` env variable on the catalog service. If using helm, it can be defined in the values file via `anchoreGlobal.maxCompressedImageSizeMB`