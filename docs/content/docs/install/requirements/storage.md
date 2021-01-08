---
title: "Storage"
weight: 1
---

The Anchore Engine uses a PostgreSQL database to store persistent data for images, tags, policies, subscriptions and other artifacts. One persistent storage volume is required for configuration information and two optional storage volumes may be provided as described below.

- **Configuration volume**
    This volume is used to provide persistent storage to the container from which it will read its configuration files and optionally certificates. *Requirement*: Less than 1MB
- [Optional] **Temporary storage**
    The temporary storage volume is recommended but not required. During the analysis of images Anchore Engine downloads and extracts all of the layers required for an image. These layers are extracted and analyzed after which the layers and extracted data are deleted. If a temporary storage is not configured then the container's ephemeral storage will be used to store temporary files, however performance is likely be improved by using a dedicated volume. A temporary storage volume may also be used for image layer caching to speed up analysis. Requirement: 3 times the uncompressed image size to be analyzed. *Note*: For container hosts using OverlayFS or OverlayFS2 storage with a kernel older than 4.13 a temporary volume is required to work around a kernel driver bug.
- [Optional] **Object storage**
    The Anchore Engine stores documents containing archives of image analysis data and policies as JSON documents. By default these documents are be stored within the PostgreSQL database however the Anchore Engine can be configured to store archive documents in a filesystem (volume), S3 Object store, or Swift Object Store. *Requirement*: Number of images x 10MB (estimated).