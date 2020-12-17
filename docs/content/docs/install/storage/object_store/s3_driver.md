---
title: "S3 Object Store Driver"
weight: 1
---

Using the S3 driver, data can be stored using Amazon's S3 storage or any Amazon S3 API compatible system.

```YAML
object_store:
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

### Compression

The S3 driver supports compression of documents. The documents are JSON formatted and will see significant reduction in 
size through compression there is an overhead incurred by running compression and decompression on every access of these 
documents. The Anchore Engine can be configured to only compress documents above a certain size to reduce unnecessary 
overhead. In the example below any document over 100kb in size will be compressed.

### Authentication

The Anchore Engine can authenticate against the S3 service using one of two methods:

- Amazon Access Keys 
  Using this method an Access Key and Secret Access key that have access to read and write to the bucket. Parameters: 
  access_key and secret_key

- Inherit IAM Role
  The Anchore Engine can be configured to inherit the IAM role from the EC2 or ECS instance that is running the Anchore 
  Engine. When launching the EC2 instance that will run the Anchore Engine you need to specify a role that includes the 
  ability to read and write from the archive bucket. To use IAM roles to authenticate the access_key and secret_access 
  configurations should be replaced by  iamauto: True
  Parameters: iamauto

### Bucket

- The url parameter points to the endpoint for the Amazon S3 bucket
- The region parameter should be set to the AWS region hosting the bucket or False for an AWS compatible service that 
does not support regions
- The bucket parameter should be set to the name of the bucket that will be used to store the archive documents.
- The create_bucket parameter is used to configure if the Anchore Engine attempts to create a bucket. If this option is 
set then ensure that the IAM role or Access Keys have sufficient access to create a new bucket.