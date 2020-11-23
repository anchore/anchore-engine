---
title: "Considerations for RHEL"
weight: 1
---

### Special Considerations for installing on Red Hat Enterprise Linux (and/or any docker host using OverlayFS* as storage drivers)

If the Anchore Engine container is run on a Red Hat Enterprise Linux (RHEL) system or derivative such as CentOS or Oracle Linux (or any docker host configured to use the OverlayFS* storage drivers) then special consideration should be taken with configuring storage.

Red Hat Enterprise Linux 7.5 defaults to using OverlayFS for storage of container images including ephemeral container storage. Previous versions of Red Hat Enterprise Linux used the devicemapper storage driver.

There is a bug in the OverlayFS driver in kernels older than 4.13 that may result in errors during image analysis. During the image extraction process the following error may be logged:

`Directory renamed before its status could be extracted`

This error is seen during the extraction of the image layer tar files.

To work around this error, until the appropriate fix can be backported into Red Hat Enterprise Linux's 3.1 kernel it is recommended that an external volume is used to during image extraction.

By default the Anchore Engine uses the /tmp directory within the container to download and extract images. Configure a volume to be mounted into the container at a specified path and configure this path in config.yaml

`tmp_dir: '/scratch'`

In this example a volume has been mounted as /scratch within the container and config.yaml updated to use /scratch as the temporary directory for image analysis. This volume should be sized to at least 3 times the uncompressed image size to be analyzed.
