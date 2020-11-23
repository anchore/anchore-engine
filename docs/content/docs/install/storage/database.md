---
title: "Database Storage"
linkTitle: "Database"
weight: 1
---

Anchore stores all metadata in a structured format in a PostgreSQL database to support API operations and searches.

Examples of data persisted in the database:

* Image metadata (distro, version, layer counts, ...)
* Image digests to tag mapping (docker.io/nginx:latest is hash sha256:abcd at time _t_)
* Image analysis content indexed for policy evaluation (files, packages, ..)
* Feed data
  * vulnerability info
  * package info from upstream (gem/npm)
* Accounts, users...
* ...

If the [object store](../object_store) is not explicitly set to an external provider, then that data is also persisted in 
the database but can be [migrated](../object_store/migration)