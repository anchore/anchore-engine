---
title: "Anchore Engine Release Notes - Version 0.7.0"
linkTitle: "0.7.0"
weight: 70
---

## Anchore Engine 0.7.0

NOTE: This version of Anchore Engine is not compatible with Anchore Enterprise 2.2.x. If you are an Enterprise user you should not upgrade to this version, but instead wait for the Enterprise 2.3 release.

Anchore Engine 0.7.0 new Features, bug fixes and improvements.  The latest summary can always be found in the Anchore Engine [CHANGELOG](https://github.com/anchore/anchore-engine/blob/master/CHANGELOG.md) on github.

### Features

+ New vulnerability data feed and package matching from the GitHub Advisory Database (https://github.com/advisories).

  This will result in GHSA matches for non-os packages such as java, python, ruby, and npm. The GHSA match includes the relevant CVEs that the GHSA addresses.

+ New vulnerability data feed from the Red Hat Security Data API, replaces RHSA as default RPM vulnerability matching data source. NOTE: RHSA information is still available, but the primary identifier is now CVE ids for RPM matches, using this new data source.

  This provides better matches for CVEs that are not yet fixed or will not be fixed since those do not yet have RHSAs. It also makes the CVE the match key rather than RHSA for more consistent whitelisting and policy handling compared to other distros.

+ New APIs for granular control of data feeds, including enable/disable toggles and data flush capabilities.

  This provides finer grained control over which feeds will sync and which are used for matching vulnerabilities against images. Includes new anchore-cli commands
  to use the API calls:

  `anchore-cli system feeds config --enable|--disable <feed> [ --group <group name> ]`  
  and  
  `anchore-cli system feeds delete <feed> [ --group <group name> ]`

  For more information see [CLI Usage - Feeds]({{< ref "/docs/usage/cli_usage/feeds/feed_configuration" >}})

+ Switched base OS for all services to Redhat UBI 8 from Redhat UBI 7.


### Bug Fixes

+ API change to use query args instead of JSON body when doing an HTTP DELETE. Fixes #366.
+ Update external api version to 0.1.14 due to new feed config operations. Fixes #375.
+ Correctly handle UnsupportedVersionError in policy validation. Fixes #151.
+ Switch logger from policy engine specific passthrough to system default logger, to address incompatible calls to debug_exception. Fixes #346.
+ Update to improve permissions check, simplify IAM requirements. Fixes #297. Fixes #94.
+ Policy evaluation errors out if retrieved_files gate w/content_regex trigger references file not saved. Fixes #379.

### Improvements

+ Updated third party dependencies and reduced dependency version locks. Addresses #344.
+ More efficient image squasher implementation to improve performance when image layers include many hardlinks.
+ Many new unit/functional tests and better test logging outputs.


### Removed
+ Deprecated kubernetes_webhook service that handles webhook no longer supported in k8s. Fixes #357.

Additional minor bug fixes, significant test framework improvements, and performance updates in image analysis.


### Upgrading

* [Upgrading Anchore Engine]({{< ref "/docs/install/upgrade" >}})

0.7.0 Upgrade Information

The upgrade from 0.6.1 to 0.7.0 involves some data migration to support the move from RHSA-based vulnerability reporting to CVE-based for RedHat-based image.
The ancho.re feed service has already been updated to serve the new data which shows up in 0.6.1 and 0.7.0 systems as:

* `rhel:5`
* `rhel:6`
* `rhel:7`
* `rhel:8`

During the upgrade process the system will automatically perform the following steps:
1. Disabled the _centos:*_ vulnerability feed groups. This means they will no longer be synced with updates. You'll see this reflected in the output of `anchore-cli system feeds list` if you upgrade to the 0.7.0 version of anchore-cli.a
1. Rescans all images in your db that are rhel-based (centos, redhat, etc) using the vulnerabiliy data from the _rhel:*_ groups to update all matches
1. Flushes the _centos:*_ matches and all vulnerability records

The logging during this process is verbose to give you plenty of insight into what the system is doing. Because it must re-scan all rpm packages, step #2 can take quite a while depending on your specific deployment and how many images you have
analyzed that are based on centos or rhel.


NOTE: Restoring RHSA-based matching is possible, but not recommended. See the [Reverting Back to RHSA Data]({{< ref "/docs/releasenotes/0.7.0/data_matching_rollback">}})

