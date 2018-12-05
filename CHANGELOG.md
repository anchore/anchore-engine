# Changelog

## 0.3.1 (2018-12-05)

+ Added - added vulnerabilty scan support for Amazon Linux 2 images (ALAS-* vulnerability matches)
+ Added -  policy engine policy evaluation optimization and cache for results to avoid re-evaluation when inputs have not changed. Uses combination of bundle content digest, feed sync update timestamps, and image load times to detect when a policy evaluation cannot have changed and uses a cached result instead of an evaluation to reduce CPU and DB usage.
+ Added - CLI operation 'system wait' to be used for scripting processes that need to block on an anchore-engine deployment coming up and being fully ready for use
+ Improved - removed feed endpoint and credentials check from policy engine bootstrap, and initialize group metadata for enabled feed types before syncing feed data
+ Fix - adjust build of embedded skopeo command that was causing segmentation fault when registry hostnames included the domain suffix '.local'
+ Minor bug fixes
	
## 0.3.0 (2018-11-15)

NOTE: For users upgrading from 0.2.X to 0.3.X, please note that the upgrade process may take some time for deployments anchore-engine that have a large number of images stored (many thousands).  Please review the upgrade guide (https://anchore.freshdesk.com/support/solutions/articles/36000052927-upgrading-anchore-engine) to safely plan for an upgrade, and plan for a longer service maintainence window than usual for this upgrade if your engine has a large number of images analyzed.

+ Major Version Update - anchore-engine and anchore-cli ported to Python3!
+ New Feature - Multi-user API and Structure
  + Adds user management and detection API routes: /accounts/*, /account, /user
  + New option in config.yaml for the "apiext" service: "authorization_handler" key, with default value "native". Allows extension point for other models in the future.
  + Accounts have one of three types: service (internal), admin, and user. Only admin account users can create other accounts/users.
  + During upgrade, existing users are migrated to accounts of the same name with user records with the same credentials.
  + Adds 'x-anchore-account' header support to allow admin users to make requests in the namespace of other accounts, for example to view events or image status, without requiring api route changes.
  + The existing config.yaml user sections are respected during first system initialization but ignored afterwards, so user management is purely via the APIs.
+ New Feature - Security-first Queries and Reports
  + Query for a list of images affected by input Vulnerability ID
  + Query for a list of images with an input package installed
  + Query for record information about a specific Vulnerability by ID
  + All queries include filter parameters to further refine results
  + API routes /v1/queries/ and corresponding CLI operation (anchore-cli query ...) included
+ New - Build and Testing infrastructure
  + Single canonical ./Dockerfile for container builds
  + CircleCI automation and test config
  + Unit and functional testing framework under ./test
+ Added - ability to add an image by specifying a digest,tag,created_at tuple with a POST to the /v1/images API route
+ Added - ability to add, fetch, store and refer to images by manifestList digest (common to see these digests in docker/runtime side) - reported as 'parentDigest' field for image records
+ Added - unauthenticated API route /version to retrieve service version information
+ Added - optional skopeo_global_timeout setting (seconds) for config.yaml which will be passed through to skopeo calls as the command-timeout option
+ Added - ability to ask for interactive (DB side effect free) policy evaluation via interactive=<true|false> query parameter to /v1/image/<image>/check route
+ Improved - java artifact manifest file parsing support and implementation (contributions by Matt Sicker <boards@gmail.com>)
+ Improved - add bootstrap process retries to improve behavior of simultaneous startup of distributed anchore-engine services
+ Improved - normalize all package database record handling for OS and Non-OS (NPM, GEM, Java, Python, etc) packages
+ Improved - better error passthrough from internal services (catalog/policy engine) back through external API to user (400, 404 instead of 500)
+ Improved - more consistent logging during bootstrap, throughout
+ Changed - move from CentOS to Ubuntu base image for anchore-engine containers
+ Removed - deprecated 'prune' routes and operations
+ Fix - handle case where manifests have incomplete history information, causing analysis failures (contribution by jianqli <jianqli@ebay.com>)
+ Fix - handle case that caused image analysis failure when package managers output non-integer values for package size metadata
+ Fix - prevent logging of DB connect string/credentials (Fix #95 contributed by Brendan Shaklovitz <nyanshak@users.noreply.github.com>)
+ Fix - bug where a container with no files triggers an analysis failure, during load in policy engine.  Fixes #105
+ Many bug fixes and improvements

## 0.2.4 (2018-08-06)

+ New ability to disable feed syncs and skip feed client bootstrap checks in the policy engine (see latest scripts/docker-compose/config.yaml example for 'sync_enabled: <True|False>')
+ Add capability to force re-analyze an image if provided a digest and tag that matches an existing image in anchore-engine
+ Add pom.properties metadata to Java analyzer (contributed by Matt Sicker <boards@gmail.com>)
+ Improved registry verify check when adding new registry credentials, including a validation timeout for firewalled/blocked registry endpoints
+ Improved anchore API swagger document with a refresh to more accurately specify request and response objects and route category/tags, for better swagger codegen client support
+ Fix update to service terminate handling in anchore_manager to avoid possible condition where service could terminate a different anchore service than intended on restart. Fixes #74
+ Minor bug fixes and improvements

## 0.2.3 (2018-06-29)

+ New feature: add 'eventlog' API and notification subsystem, that allows users to query an engine (and/or be notified via a webhook notification) for important engine events, including:
  + Details on reasons for image analysis failures
  + Information about internal processes like vulnerability feed sync start and end events
  + Troubleshooting information on image and repository watcher failures
  + Troubleshooting information about distributed anchore-engine services orphaned due to network connectivity or other issues
  + Details about policy sync failures from anchore.io if the automatic policy sync is turned on in the config
  + Troubleshooting information that presents details when other asynchronous engine operations experience failures
+ Improved java artifact analysis - Add support for scanning Jenkins plugins. This adds the file extension ".hpi" and ".jpi" to the list of recognized Java library filenames. (contributed by Matt Sicker <boards@gmail.com>)
+ Improved 'metadata' content implementation for handling the addition of dockerfile contents after an image has already been added
+ Improved install/readme content. (contributed by Lorens Kockum <LorensK@users.noreply.github.com>)
+ Fix to allow registry credential validation for ECR registries, on registry add
+ Fix that adds better checking for condition where endpoint_hostname/listen/port are not set for a given service in its config.yaml.  Fixes #67.
+ Fix that adds missing prettytable requirement. Fixes #64
+ Minor bug fixes and improvements

## 0.2.2 (2018-06-08)

+ New feature: support for multiple policies in mapping rules of policy bundles
+ New feature: add image 'metadata' content, accessible using 'anchore-cli image metadata <image>' to review dockerfile, docker hisory, and manifest content
+ New feature: support for non-os package vulnerability scanning and access to new data feed (NVD)
+ Improved DB bootstrap process significantly, including DB compatability checks
+ Improved GET routes to remove the need for a body (equiv. key=values can now also be supplied as querystring parameters)
+ Improved vulnerability record format including separation of package and version for effected packaged into their own fields
+ Add registry validation when adding a registry credential (can be optionally skipped)
+ Add options for 'external URL' broadcast for each service, in LB cases where the TLS/port state of the actual service differs from how the services intercommunicate. Fixes #49
+ Add better tolerance of archive document migration (contributed by Armstrong Li <jianqli@ebay.com>)
+ Remove dependency on external 'anchore' installation, bringing all analyzer/sync code from deprecated original anchore project into engine natively
+ Fix tar hardlink error largely noticed on RHEL/Centos based images, causing some images to fail analysis
+ Fix to return RFC3339 ISO datetime strings (contributed by Patrik Cyvoct <patrik@ptrk.io>)
+ Fix that adds force kwarg parameter to by_id function defs.  Fixes #55.
+ Fix that updates the ping_docker_registry() routine to handle translating docker.io to the actual dockerhub registry url. Fixes #52.
+ Many more minor bug fixes and improvements

## 0.2.1 (2018-04-29)

+ Security fix for github issue #36: anchore-engine allows authenticated user to issue malformed input on image/repo adds, allowing command execution on the engine host.  Many thanks to Cameron Lonsdale (https://github.com/CameronLonsdale) for discovering and reporting the issue.
+ Fix issue where manifest v1 schema based images could not be fetched by imageId
+ Fix issue where NPM feed data fails to sync due to DB column size limitations

## 0.2.0 (2018-04-26)

+ Many new features and deployment options!
+ New feature: anchore-engine services now supply prometheus metrics on the /metrics route for each service
+ New feature: deployments of anchore-engine now support running multiple core service instances (catalog, policy_engine, simplequeue, api), in addition to multiple workers (analyzer)
+ New feature: archive document driver subsystem for storing the large image analysis documents of anchore-engine in a variety of different external locations (db, localfs, S3, Swift)
+ New feature: ability to migrate archive documents between external sources when changing archive document drivers
+ New feature: inclusion checks to filter vulnerabilities for debian images by whether there is a vendor advisory
+ New documentation available at: https://anchore.freshdesk.com/support/solutions/articles/36000052880-anchore-engine-0-2-0-
+ Improved service registration process - services now push registration on startup/during operation instead of being polled centrally
+ Improved service startup / upgrade / management processes by introducing the anchore-manager utility
+ Improved example docker-compose and config YAMLs to better illustrate configuration options and provide quick start
+ Improved error information from API/CLI calls, in particular when adding an image fails due to registry access or archive document store failures
+ Add new management API route for manually triggering a feed sync
+ Fix to handle image analysis failures for some manifest schema v1 formats
+ Fix to better handle images using manifest lists
+ Fix to handle case where image vulnerability scan could be skipped during a feed sync
+ Fix to analyzer process to handle images with layers that contain PAX headers that are incompatible with python tarfile library
+ Many small performance improvements to reduce DB pressure and perform catalog monitor processes more efficiently

## 0.1.10 (2018-04-09)

+ Fix timestamp inconsistencies when updating/adding policy bundles (PUT/POST)
+ Adds policy validation for the /v1/policies/<id> PUT route
+ Fix the final_action in the results section of bundle eval table to reflect the policy result without image whitelist/blacklist application
+ Adds full lifecycle state for gates, triggers, and params to specify 'active', 'deprecated', or 'eol'.
+ Re-adds eol'd gate defs for pkgdiff, base_check, and suiddiff gate to conform to the lifecycle state scheme.
+ Deprecated and EOL gates/triggers will raise warnings in policy evaluation and EOL gates will automatically become no-ops in evaluation.
+ Initial migration of gates to new naming and consolidation. Old gates moved to deprecated/ and marked as deprecated state

## 0.1.9 (2018-03-19)

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
