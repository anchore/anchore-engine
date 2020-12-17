---
title: "Analysis Archive Storage Configuration"
linkTitle: "Analysis Archive"
weight: 1
---

For information on what the analysis archive is and how it works, see [Concepts: Analysis Archive]({{< ref "/docs/general/concepts/analysis_archive" >}})

The Analysis Archive is an [object store](../object_store) with specific semantics and thus is configured as an object store using the same
configuration options, just with a different config key: `analysis_archive`

Example configuration snippet for using the db for working set object store and S3 for the analysis archive:

```
...
services:
  ...
  catalog:
  ...
  object_store:
    compression:
      enabled: false
      min_size_kbytes: 100
    storage_driver:
      name: db
      config: {}      
  analysis_archive:
      compression:
        enabled: False
        min_size_kbytes: 100
      storage_driver:
        name: 's3'
        config:
          access_key: 'MY_ACCESS_KEY'
          secret_key: 'MY_SECRET_KEY'
          #iamauto: True
          url: 'https://S3-end-point.example.com'
          region: False
          bucket: 'anchorearchive'
          create_bucket: True
```

## Default Configuration

By default, if no `analysis_archive` config is found or the property is not present in the config.yaml, the analysis archive
will use the `object_store` or `archive` (for backwards compatibility) config sections and those defaults (e.g. db if found).

Anchore stores all of the analysis archive objects in an internal logical bucket: _analysis_archive_ that is distinct in
the configured backends (e.g a key prefix in the s3 bucket or swift container)

## Changing Configuration

Unless there are image analyses actually in the archive, there is no data to move if you need to update the configuration
to use a different backend, but once an image analysis has been archived to update the configuration you must follow
the object storage data migration process found [here](../object_store/migration). As noted in that guide, if you need
to migrate to/from an `analysis_archive` config you'll need to use the --from-analysis-archive/--to-analysis-archive 
options as needed to tell the migration process which configuration to use in the source and destination config files 
used for the migration.


## Common Configurations

1. Single shared object store backend: omit the analysis_archive config, or set it to _null_ or _{}_

2. Different bucket/container: the object_store and analysis_archive configurations are both specified and identical
with the exception of the _bucket_ or _container_ values for the analysis_archive so that its data is split into a
different backend bucket to allow for lifecycle controls or cost optimization since its access is much less frequent (if ever).

3. Primary object store in DB, analysis_archive in external S3/Swift: this keeps latency low as no external service is 
needed for the object store and active data but lets you use more scalable external object storage for archive data. This
approach is most beneficial if you can keep the working set of images small and quickly transition old analysis to the
archive to ensure the db is kept small and the analysis archive handles the data scaling over time.

