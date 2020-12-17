---
title: "Object Storage"
linkTitle: "Object Storage"
weight: 6
---

Anchore Engine uses a PostgreSQL database to store structured data for images, tags, policies, subscriptions and metdata
about images, but other types of data in the system are less structured and tend to be larger pieces of data. Because of
that, there are benefits to supporting key-value access patterns for things like image manifests, analysis reports, and 
policy evaluations. For such data, Anchore has an internal object storage interface that, while defaulted to use the
same postgres db for storage, can be configured to use external object storage providers to support simpler capacity
management and lower costs. The options are:

- PostgreSQL database (default)
- Filesystem 
- S3 Object Store
- Swift Object Store

The configuration for the object store is set in the catalog's service configuration in the config.yaml.

### Changed in 0.4.0 of Anchore Engine

In releases before 0.4.0 of Anchore Engine, the configuration key was `archive`. As of 0.4.0 that has been changed to 
`object_store` but will still support `archive` for backwards compatibility, though that key is now deprecated. The
reason for the change is the new in 0.4.0 analysis archive feature, which uses the configuration key `analysis_archive`.

The change helps differentiate the analysis archive, which is an object store with specific lifecycle semantics, from 
the more generic object store configuration.


 