---
title: "Anchore Engine Release Notes - Version 1.0.0"
linkTitle: "1.0.0"
weight: 48
---

## Anchore Engine 1.0.0

API version - 0.1.19

DB Schema version - 0.0.16

This release contains a database schema update.

### V2 vulnerability provider, based on Grype

Version 1.0.0 is a significant release for Engine as it now has Grype integration for vulnerability scanning enabled by default. This creates a unified vulnerability scanning core across local tools as well as stateful Engine services. 

The legacy provider (non-Grype) is no longer the default for new deployments. If you are a current engine user and want to keep the existing non-Grype scanner, you can upgrade to 1.0.0 and configure Engine to use the legacy scanner. You do not have to use Grype, although upgrading to Grype is recommended because the legacy scanner will be deprecated at some point in the future.

The new V2 vulnerability provider syncs vulnerability data from the same upstream sources as Engine, but uses the Grype DB update mechanism to achieve much faster feed updates, and no longer uses the (https://ancho.re) endpoint for retrieving data.

### SUSE Linux Enterprise Server support

There is now Grype support for generating lists of CVEs for SLES and OpenSUSE. This is based on published data at (https://www.suse.com/support/security/).

### Fixed

Dependency updates to resolve non-impacting vulnerability findings


### Upgrading

Upgrading to 1.0.0 involves a database upgrade that the system will handle itself. It may cause the upgrade to take several minutes.

* [Upgrading Anchore Engine]({{< ref "/docs/install/upgrade" >}})
