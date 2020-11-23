---
title: "Layer Caching"
weight: 1
---

Once an image is submitted to the Anchore Engine for analysis the Engine will attempt to retrieve metadata about the image from the Docker registry and if successful will download the image and queue the image for analysis.

The Anchore Engine can run one or more analyzer services to scale out processing of images. The next available analyzer worker will process the image.

Docker Images are made up of one or more layers, which are described in the manifest. The manifest lists the layers which are typically stored as gzipped compressed TAR files.

As part of image analysis the Anchore Engine will:

- Download all layers that comprise an image
- Extract the layers to a temporary file system location 
- Perform analysis on the contents of the image including:
    - Digest of every file (SHA1, SHA256 and MD5)
    - File attributes (size, owner, permissions, etc)
    - Operating System package manifest
    - Software library package manifest  (NPM, GEM, Java, Python, NuGet)
    - Scan for secret materials (api keys, private keys, etc
    
Following the analysis the extracted layers and downloaded layer tar files are deleted.

In many cases the images will share a number of common layers, especially if images are built form a consistent set of base images. To speed up the Anchore Engine can be configure to cache image layers to eliminate the need to download the same layer for many different images. The layer cache is displayed in the default Anchore Engine configuration. To enable the cache the following changes should be made:

1. Define temporary directory for cache data

It is recommended that the cache data is stored in an external volume to ensure that the cache does not use up the ephemeral storage space allocated to the container host.

By default the Anchore Engine uses the /tmp directory within the container to download and extract images. Configure a volume to be mounted into the container at a specified path and configure this path in config.yaml

`tmp_dir: '/scratch'`

In this example a volume has been mounted as /scratch within the container and config.yaml updated to use /scratch as the temporary directory for image analysis.

With the cache disabled the temporary directory should be sized to at least 3 times the uncompressed image size to be analyzed.
To enable layer caching the layer_cache_enable parameter and layer_cache_max_gigabytes parameter should be added to the analyzer section of the Anchore Engine configuration file config.yaml.

```YAML
analyzer:
    enabled: True
    require_auth: True
    cycle_timer_seconds: 1
    max_threads: 1
    analyzer_driver: 'nodocker'
    endpoint_hostname: '${ANCHORE_HOST_ID}'
    listen: '0.0.0.0'
    port: 8084
    layer_cache_enable: True
    layer_cache_max_gigabytes: 4
```

In this example the cache is set to 4 gigabytes. The temporary volume should be sized to at least 3 times the uncompressed image size + 4 gigabytes.

- The minimum size for the cache is 1 gigabyte.
- The cache users a least recently used (LRU) policy.
- The cache files will be stored in the anchore_layercache directory of the /tmp_dir volume.
