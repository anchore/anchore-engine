---
title: "Filesystem Driver"
weight: 1
---

Using the file system driver object store documents can be stored on a filesystem volume passed to the Anchore Engine container.

**The filesystem driver does not handle distribution or replication.** To replicate the file system across nodes for performance and redundancy a clustered / shared filesystem such as Gluster, CephFS or Amazon EFS should be used.



**WARNING:** This driver is not recommended for scale-out production deployments



For environments who do not want to utilize the default PostgresSQL storage and need scale or redundancy an object store such as S3 or Swift will provide a better solution than the filesystem driver.

### Compression

The localfs (filesystem) driver supports compression of object_store documents. The object_store documents are JSON formatted and will see significant reduction in size through compression there is an overhead incurred by running compression and decompression on every access of these documents. The Anchore Engine can be configured to only compress documents above a certain size to reduce unnecessary overhead. In the example below any document over 100kb in size will be compressed.

```YAML
object_store:
  compression:
    enabled: True
    min_size_kbytes: 100
  storage_driver:
    name: localfs
    config:
      archive_data_dir: '/object_store'
``` 