# Changelog

## 0.7.1 (2020-04-28)
+ Added - anchore-manager command now has --no-auto-upgrade option to support more deployment and upgrade control
+ Improved - Bumped twisted and requests dependencies
+ Improved - Removes the docker-compose.yaml, prometheus.yaml, and nginx swagger ui configs from within the image, moving those to documentation for easier update/iteration without builds. Fixes #435
+ Fix - Ensure only supported os overrides are used in skopeo download commands. Fixes #430 (CVE-2020-11075 / GHSA-w4rm-w22x-h7m5)
+ Fix - Errors during feed data download can cause mismatched timestamps and missed feed data on sync. Fixes #406
+ Fix - Removed variable reference before assignment in squasher. Fixes #401
+ Fix - Fixes mis-labeled GHSA matches on python packages in policy evaluation to be correctly non-os matches. Fixes #400
+ Additional minor bug fixes, enhancements, and test framework improvements.

## 0.7.0 (2020-03-26)
+ Added - New vulnerability data feed and package matching from the GitHub Advisory Database (https://github.com/advisories).
+ Added - New vulnerability data feed from the Red Hat Security Data API, replaces RHSA as default RPM vulnerability matching data source. NOTE: RHSA information is still available, but the primary identifier is now CVE ids for RPM matches, using this new data source.
+ Added - New APIs for granular control of data feeds, including enable/disable toggles and data flush capabilities.
+ Added - Switched base OS for all services to Redhat UBI 8 from Redhat UBI 7.
+ Improved - Updated third party dependencies and reduced dependency version locks. Addresses #344.
+ Improved - More efficient image squasher implementation to improve performance when image layers include many hardlinks.
+ Improved - Many new unit/functional tests and better test logging outputs.
+ Fix - API change to use query args instead of JSON body when doing an HTTP DELETE. Fixes #366.
+ Fix - Update external api version to 0.1.14 due to new feed config operations. Fixes #375.
+ Fix - Correctly handle UnsupportedVersionError in policy validation. Fixes #151.
+ Fix - Switch logger from policy engine specific passthrough to system default logger, to address incompatible calls to debug_exception. Fixes #346.
+ Fix - Update to improve permissions check, simplify IAM requirements.  Fixes #297. Fixes #94.
+ Fix - Policy evaluation errors out if retrieved_files gate w/content_regex trigger references file not saved.  Fixes #379.
+ Removed - Deprecated kubernetes_webhook service that handles webhook no longer supported in k8s. Fixes #357.
+ Additional minor bug fixes, significant test framework improvements, and performance updates in image analysis.

## 0.6.1 (2020-1-30)
+ Improved - Substantial updates to feed sync process in policy engine service to increate transparency in the process, show incremental updates, and use much less memory during the sync. Fixes #284
+ Improved - Adds commented out defaults in docker-compose.yaml embedded in image to easily support starting prometheus and a swagger ui sidecar for API browsing.
+ Improved - Adds backoff/retry in analyzer task flow for loads to policy engine to handle transient failures. Fixes #322.
+ Improved - Dependency updates
+ Fix - Adds the release component of package version for rpms in package listing of OS packages in API responses. Fixes #320.
+ Fix - Removes the embedded swagger ui to keep image smaller and less dependencies with reduced security surface. Uses a side-card model instead with another container for the UI if browsing the API is desired. Fixes #323.
+ Minor bug fixes and improvements

## 0.6.0 (2019-12-13)

+ Added - Substantial updates to event subsystem, adding new many new info and error level event types and implementation.
+ Added - Auth toggle for prometheus metrics routes (using disable_auth in metrics section of config.yaml).
+ Added - Group API metrics by function name instead of URI to handle the large number of routes when using Ids in the route.
+ Fix - Change the db column type for the image_packages.size column from int -> bigint for larger packages than 2GB. Fixes #239.
+ Improved - Improvements in vuln listing for an image and vuln query performance. Resolves #286.
+ Improved - Introduce retries for individual feed group syncs and introduce more granular feed sync events to better track sync progress.
+ Improved - Quickstart/initial install via docker-compose now uses pre-loaded vulnerability data (preload DB) to reduce initial feed sync.
+ Improved - Moves deprecated gates/triggers to the EOL lifecycle stage. Resolves #276.
+ Minor bug fixes and improvements in error/eventing subsytems, and performance for NVD related vulnerability syncs and scans

## 0.5.2 (2019-11-15)

+ Fix - Remove failing (deprecated) code block from periodic vulnerability scan - Fixes #294
+ Fix - Address issue where the gate is incorrectly triggering when params are meant to filter by filename or content regex name.  Fixes #290.

## 0.5.1 (2019-10-10)

+ Added - Array support for the id param in /query/vulnerabilities and a namespace parameter for same route. Fixes #278.
+ Added - Support for images based on google distroless OS, including detection of base OS/version and installed OS dpkg packages.  Fixes #277.
+ Added - Ability to import an image analysis archive where the resulting image is owned by the account used to initiate the import. Fixes #269.
+ Added - New parameter to secret_search gate, which allows the user to specify whether to trigger if a match is found (default) or is not found (new behavior).  Fixes #264.
+ Added - New trigger in the 'files' gate to allow for checks against various file attributes - checksum and mode.  Fixes #262. Fixes #204.
+ Fix - Better parsing of www-authentiate response header when performing registry credential validation on registry add. Fixes #275.
+ Fix - Add fall-thru on fix_available check for os packages in vulnerbility gate, addressing duplicate trigger matches that are disregarded by policy. Fixes #273.
+ Fix - Addresses analysis failure in cases where image config document metadata does not contain a history element.  Fixes #260.
+ Fix - Addresses external_id reference before assignment error on ecr iam role usage. Fixes #259
+ Fix - Improvements and fixes within the version comparison implementation for dpkg and rpm. Fixes #274 and #265.
+ Improved - Enforce stricter api checks for "source" object in POST /images. Fixes #261
+ Many minor bug fixes and improvements, in API input validation, CPE-based CVE matching performance, and others

## 0.5.0 (2019-09-05)

+ Added - Support for local image analysis tool and process, including local analyzer operation in anchore_manager and new image analysis archive import API operation
+ Added - Switch NVD feed driver to consume normalized vulnerability data from latest NVD JSON 1.0 Schema
+ Added - New parameter to vulnerabilities gate to only trigger if a fix has been available for over a specified number of days
+ Added - New parameters in vulnerabilities gate to allow for triggers based on CVSSv3 scoring information. Implements #164.
+ Added - Structured CVSS scoring information throughout external API responses, where vulnerability information is returned (vulnerability scans, vulnerability queries). Implements #163, #160, #223.
+ Added - Optional support using hashed passwords on anchore user credential storage, and adds support token-based user authentication
+ Improved - More complete CPE version strings now available from latest NVD data feed, improving scope of non-os package vulnerability matches
+ Improved - Spelling, grammar and broken link updates to top level README. Contributions by Neil Levine <levine@yoyo.org> and MichaelSimons <msimons@microsoft.com>
+ Improved - Updated validation and improved error detail for user and account management API operations
+ Improved - Updates to quickstart/example docker-compose.yaml, and bootstrap entrypoint for better custom root CA inclusion
+ Many minor bug fixes and improvements

## 0.4.2 (2019-08-01)

+ Fix - Update to CPE match DB query, to account for package names that are not reported as lowercase.  Fixes #227.
+ Fix - Update to fix incorrect arg passing for error message construction of "detail" property, on policy bundle add validation failures.
+ Improved - Update to image analysis speed for some images exhibiting long unpack times due to layer complications. Improves squashing speed by going through layer tarfiles sequentially.

## 0.4.1 (2019-07-01)

+ Added - Store a set of digests in a subscription record, allowing engine to run vuln_update/policy_eval checks over specified digests as well as latest. Contribution by Mattia Pagnozzi <mattia.pagnozzi@gmail.com>
+ Added - New debug_exception logger function to dump stack only at debug or higher log level, otherwise just print error.
+ Added - Adds global internal client timeouts configurable in the config.yaml file. Fixes #210 add annotations key to AnchoreImage response definition type in.
+ Fix - GET /images?history=true not returning full history list. Fixes #215
+ Fix - Allow distro discovery routine to handle case where system os metadata files are broken softlinks inside the container image. Fixes #213
+ Fix - Update to analyzer code, to keep a consistent map of files regardless of any file name slash and dot prefixes that may be present in the layer tars.  Fixes #209
+ Fix - Add input validation for registry add to prevent trailing slash and prefix schema in the registry input string. Fixes #208
+ Fix - Implement dockerfile update check to invoke on only the specific digest, not tag. Fixes #201
+ Fix - Incorrect 500 response on successful feed sync call. Fixes #198
+ Fix - On image add, ensure that subscriptions are (re)activated based on API input. Fixes #195
+ Fix - Use of body in GET /images to filter by tag and/or digest rather than only using query param
+ Fix - Don't require type and key on PUT /subscriptions, reconciling code behavior with swagger spec. Contribution by by Mattia Pagnozzi <mattia.pagnozzi@gmail.com>
+ Fix - Add missing 'annotations' key to AnchoreImage response definition type in swagger spec.
+ Fix - Add correct DB filter on userId to prevent images deleted from one user account from resulting in deletions of images in other accounts, when Image Digests align across accounts.  Fixes #224.
+ Improved - Update Dockerfile using multi-stage model

## 0.4.0 (2019-05-09)

+ Added - Image Analysis Archive Subsystem. See #165.
+ Added - All anchore-engine services now run (by default) as non-root, including the analyzer (with new analyzer implementation)
+ Added - optional policy parameter for vulnerabilities older than N days. Implements #156. Contribution by i845783 <dan.wilson01@sap.com>
+ Added - new facility to carry anchore error codes through to API error response envelope.  Addresses #150 and will extend in future for richer error information in API responses.
+ Added - /system/error_codes route to describe possible anchore error codes.
+ Added - Re-platformed anchore engine and CLI container image on Red Hat Universal Base Image (UBI)
+ Fix - improved handling of case where default_bundle_file key is unset internally for initializers that reference that configuration key. Fixes #113.
+ Fix - skip dpkg results that are not in the explicit installed (ii) state.  Fixes #169.
+ Fix - bug in passwd_file gate's context setup that was parsing entries incorrectly.
+ Fix - bytes decode issue in the object store manager interface that is masked in py3.6 but exposed in py3.5
+ Fix - update to handle redirect for quay.io when trailing slash is omitted, during initial registry ping in validation routine.  Fixes #175.
+ Improved - cleanup feed sync error path where another sync is in progress. use the new anchore error code mechanism
+ Improved - support for psycopg2 SQL Alchemy Driver
+ Improved - new docker-compose quickstart method
+ Improved - combined analyzer module functionality
+ Improved - error message from parse_dockerimage_string. Contributed by Nicolas Simonds <nisimond@cisco.com>
+ Improved - re-introduce many integration tests and integration testing framework
+ Improved - remove more verbose logging around lease ops in monitor function of catalog
+ Improved - update workspace analyzer directory deletion to handle nested permissions errors using onerror shutil.rmtree handler, to avoid permission denied possibilities from rootless analyzer
+ Many performance, log cleanup and improvements, and other minor bugfixes
	
## 0.3.4 (2019-04-04)

+ Added - support for specifying registry credentials for specific repositories or sets of repos using wildcards. Implements #142.
+ Added - new configuration option enable_access_logging to control whether twisted access log lines are included in anchore service logs. Implements #155.
+ Added - implement orphaned service record autocleanup in the catalog services handler. Implements #145.
+ Fix - make system service events owned by the system admin account. Existing system events can be flushed via the api with context-set for anchore-system, and all future events will be in the admin account. Fixes #152.
+ Fix - added timeout support for client calls to catalog from policy engine disabled by default but configurable. Adds configurable service thread pool sizes and bumps default count from 20 to 50 threads max size. Fixes #154.
+ Fix - remove duplicates from the query/vulnerabilities records for NVD, ensuring that each namespace only has a unique and latest record for a given vulnerability ID. Fixes #166.
+ Fix - updates to policy validation and eval error handling and adds size unit support for image size check. Fixes #124.
+ Fix - cleaned up docker-compose so that mounted volume doesn't have yml extension
+ Improved - more consistent logging/event handling in service health monitor
+ Minor bug fixes and improvements
	
## 0.3.3 (2019-02-22)

+ Added - new ssl_verify option in feeds section of default/example config yamls and related environment settings in Dockerfile, to handle cases where default feed endpoint (ancho.re) is behind proxy with site-specific cert. Fixes #141
+ Added - the parentDigest to AnchoreImageTagSummary definition in apiext swagger.yaml.  Fixes #140
+ Added - imageDigest and more elements (package name, version, type, feed, feed group) to the vuln_update webhook payload. Fixes #130
+ Added - regex support for mapping rules using value prefix 'regexp:'. Fixes #128
+ Fix - only emit events into the event log for orphaned or down services when they transition, mitigating condition where simplequeue service can getting highly loaded when many orphaned service records are in place. Fixes #147
+ Fix - update to image unpack hardlink handler implementation and docker config parsing implementation to handle missing created fields, observed for images created using kaniko and buildkit.  Fixes #143. Fixes #144.
+ Fix - make updates to RFC3339 format validation and parsing for the add image by digest request input to correctly handle strings that contain millis. Fixes #136. Fixes #135.
+ Fix - update to routine that generates a digest from a manifest, removing intermediate parse that computed the wrong digest in cases where manifest contained un-indented json.  Fixes #131
+ Fix - improve feed sync error handling. Fixes #125
+ Improved - update default config to allow external setting of ANCHORE_EXTERNAL_TLS and ANCHORE_LOG_LEVEL.  Contribution by Jeremy T. Bouse <Jeremy.Bouse@UnderGrid.net> (PR #137 and #139)
+ Improved - several updates to circleCI/build configs, unit tests
+ Minor bug fixes

## 0.3.2 (2019-01-11)

+ Added - retry on feed sync failures due to queue availability, preventing delayed sync on bootstrap
+ Fix - update to dockerfile/effective_user trigger description and example str. Fixes #120
+ Fix - make feed sync listing available to all authenticated users rather than only admins
+ Fix - errors in mixed case username/accountnames by adding full case sensitivity in username and accounts
  + New realm impl to ensure case-sensitive Permission types loaded
  + Updates to the API swagger doc's regexes to allow upper-case letters
  + Updates to tests
  + Now supports mixed case in both username and account
+ Fix - high memory usage for db upgrades with large numbers of ImageGem or ImageNpm records in DB upgrade from DB version 0.0.7 to 0.0.8
+ Fix - ecr url parsing for getting the account and region. Fixes #118
+ Fix - Downgrade pg8000 dep version to support DB reconnect when DB connection is interrupted. Fixes #116
+ Improved - better hardlink handler for image squash, handling hardlinks being re-targetted across spanning layers
+ Minor logging cleanup, bug fixes
	
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
