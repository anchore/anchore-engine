---
title: "Swift Archive Driver"
weight: 1
---

Using the Swift driver archive documents can be stored in an OpenStack Swift Object storage service.

The Swift driver supports three authentication methods: 
- Keystone V3
- Keystone V2
- Legacy (username / password)

### Common Configuration Options

#### Compression

The Swift driver supports compression of archive documents. The archive documents are JSON formatted and will see significant reduction in size through compression there is an overhead incurred by running compression and decompression on every access of these documents. The Anchore Engine can be configured to only compress documents above a certain size to reduce unnecessary overhead. In the example below any document over 100kb in size will be compressed.

#### Container

- The container parameter specifies the name of the container to be used.
- The create_container parameter is used to configure if the Anchore Engine attempts to create a container. If this option is set then ensure that the user has the appropriate rights to create a container.

### Legacy Authentication

```YAML
object_store:
  compression:
    enabled: True
    min_size_kbytes: 100
  storage_driver:
    name: 'swift'
    config:
      user: 'user:password'
      auth: 'http://swift.example.com:8080/auth/v1.0'
      key:  'anchore'
      container: 'anchorearchive'
      create_container: True
```

- The user configuration option should include the colon delimited username and password. eg. 'admin:secret'
- The auth parameter specifies the authentication end point for the Swift Service
- The key parameter specifies the key for the Swift Service

### Keystone V3

```YAML
object_store:
  compression:
    enabled: True
    min_size_kbytes: 100
  storage_driver:
     name: 'swift'
     config:
        auth_version: '3'
        os_username: 'myusername'
        os_password: 'mypassword'
        os_project_name: myproject
        os_project_domain_name: example.com
        os_auth_url: 'foo.example.com:8000/auth/etc'
       container: 'anchorearchive'
       create_container: True
```

- The auth_version configuration option specified Keystone V3 authentication
- The os_username parameter specifies the username
- The os_password parameter specifies the password
- The os_project_name parameter specifies the OpenStack project name under which the Swift service is configured
- The os_project_domain_name parameter specifies the domain name for the OpenStack project
- The os_auth_url parameter specifies the URL to the OpenStack Keystone service

### Keystone V2

```YAML
object_store:
  compression:
    enabled: true
    min_size_kbyte: 100
  storage_driver:    
    name: 'swift'
    config:
      auth_version: '2'
      os_username: 'myusername'
      os_password: 'mypassword'
      os_tenant_name: 'mytenant'
      os_auth_url: 'foo.example.com:8000/auth/etc'
```

- The auth_version configuration option specified Keystone V3 authentication
- The os_username parameter specifies the username
- The os_password parameter specifies the password
- The os_tenant_name parameter specifies the name of the OpenStack tenant under which the Swift service is configured
- The os_auth_url parameter specifies the URL to the OpenStack Keystone service

#### Note

The Anchore Engine archive drivers users the OpenStack Python SwiftClient library. The config section is passed to the SwiftClient library allowing any advanced parameters supported by the Swift library to be configured.

