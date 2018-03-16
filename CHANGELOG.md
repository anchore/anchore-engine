# Changelog

## 0.1.9 (2018-XX-YY)

+ Added ability to specify metadata attributes on image add, which are carried through to webhook payloads
+ Added capability to enable image layer caching on analyzers via options in config.yaml
+ Added version information in API /v1/system/status
+ Added new webhook/subscription type analysis_update that fires when image analysis has completed
+ Fixed issue for analysis failure resulting from layers that replace populated subdirectories with softlinks in a single layer
+ Adds ability to whitelist and blacklist images in the policy bundle using new sections: "whitelisted_images", and "blacklisted_images". Each are json arrays of {"registry": str, "repository": str, "image": {"type":str, "value": str} entries to select images and affect the final evaluation result irrespective of policy evaluation result
+ Removes some old gates that were ineffective. Will result in eval warning if found in an existing policy: base_check, pkgdiff, suiddiff. These gates required data not reliably available from registry-pushed images
+ Adds 'in' and 'not_in' checks for image metadata checks and dockerfile directive checks to allow membership tests in lists of strings
+ Fixes some rule mapping bugs in specifying mapping rules by digest or image id
## 0.1.8 (2018-02-16)

+ Added ability to add a repository for anchore-engine to automatically scan (adds all tags found at add time, and adds new tags on-going)
+ Added first custom route to /summaries API (/summaries/imagetags), which is a fast path to fetch a complete image listing summary
+ Added API and call to describe policy language to get full set of gates and triggers.
+ Added /v1/system/policy_spec route to apiext service that returns a list of gate json objects.
+ Added a /v1/valiate_bundle route to the policy engine service for bundle-validation only for use by the apiext service.
+ Added the ALWAYS:ALWAYS policy gate/trigger that always fires if present
+ Added credentialed GCR registry support
+ Added Adds 'registryIds' to AWS ECR get_authorization_token call. Fixes #12 (contributed by Curtis Mattoon <cmattoon@cmattoon.com>)
+ Fixed apk package version comparisons, which now use same comparison logic as the "apk" tool. Fixes #25

## 0.1.7 (2018-01-22)

+ Added ability to specify policy bundles on evaluation calls (both in k8s image policy webhook service and via direct CLI/API call)
+ Many improvements to system performance with many loaded and active images
+ Fixed that requires policies and mappings as required fields for policy bundle add via the anchore-engine API. Fixes #22

## 0.1.6 (2018-01-08)

+ Added 'localfs' archive storage driver
+ Improved analyzer performance with new image layer squashing implementation
+ Fixed that makes image deletion from the policy engine service idempotent. Fixes #16
+ Fixed improve performance of image squashing when there are many files and whiteouts in base layers. Fixes #17

## 0.1.5 (2017-12-19)

+ Added 'nodocker' analyzer driver
+ Added unauthenticated /health route to the API service for use with LBs
+ Added ability to automatically restart twistd services via configuration setting (contributed by Alexander Urcioli alexurc@gmail.com)
+ Improved image manifest/download routines, adding support for manifest schema v1
+ Fixed issue where analyzer workspace was being handled separately from tmp_dir setting in config.yaml

## 0.1.4 (2017-11-27)

+ Added --force option to image delete
+ Fixed issue where imageId may not be set for image_detail if multiple tags referencing the same image are added before the image is analyzed
+ Many UX improvements around logging, stdout/stderr handling in the bootstrap (anchore-engine), and service pre-flight checks

## 0.1.3 (2017-11-03)

+ Added per-service log_level option
+ Added storing of uid/gid in file content query results
+ Added python, gem, npm and java content types if available
+ Minor Bug fixes and UX improvements

## 0.1.2 (2017-10-12)

+ Added policy_engine service and many new gates and triggers, with better policy bundle validation
+ Added 'awsauto' username/password pair for ECR registries when anchore-engine has access to ECR registry via IAM
+ Improved catalog monitors logic to reduce registry access on failure conditions and at steady state

## 0.1.0 (2017-09-29)

+ Initial Release
