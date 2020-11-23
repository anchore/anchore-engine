---
title: "Database Driver"
weight: 1
---

The default object store driver is the PostgreSQL database driver which stores all object store documents within the PostgreSQL database.

Compression is not supported for this driver since the underlying database will handle compression.

There are no configuration options required for the Database driver.

The embedded configuration for anchore engine includes the default configuration for the db driver.

```YAML
object_store:
  compression:
    enabled: False
    min_size_kbytes: 100
  storage_driver:
    name: db
    config: {}
```

