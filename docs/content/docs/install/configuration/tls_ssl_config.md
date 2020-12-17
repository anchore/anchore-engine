---
title: "Configuring TLS / SSL"
linkTitle: "TLS / SSL"
weight: 3
---

Communication with the Anchore Engine and between Anchore Engine service can be secured with TLS/SSL. This can be performed in two ways

- Externally through a load balancing, ingress controller or reverse proxy such as NGINX
- Natively within the Anchore Engine

For most use cases an external service such as a proxy or load balancer will provide the simplest approach, especially when keys need to be rotated, new instances added, etc.

The Anchore Engine is comprised of 6 services, typically only the external API service (apiext) and Kubernetes webhook service are published externally, all other services are used for internal communication.

Transport Level Security (TLS/SSL) is enabled on a per-service basis. In the sample configuration the SSL/TLS configuration options are commented out.

In the following example the external API service is configured to listen on port 443 and is configured with a certificate for its external hostname anchore.example.com

Each service published in the Anchore Engine configuration (apiext, catalog, simplequeue, analyzer, policy_engine and kubernetes_webhook) can be configured to use transport level security.

```YAML
services:
  apiext:
    enabled: True
    endpoint_hostname: 'anchore.example.com'
    listen: '0.0.0.0'
    port: 443
    ssl_enable: True
    ssl_cert: '/config/anchore-ex.crt'
    ssl_key: '/config/anchore-ex.key'
    ssl_chain: '/config/anchore-ex.crt'
```

| Setting | Notes |
| :------ | :---- |
| enabled | If the service is enabled |
| endpoint_hostname | DNS name of service |
| listen | IP address of interface on which the service should listen (use '0.0.0.0' for all - default) |
| port | Port on which service should listen. |
| ssl_enable | Enable transport level security |
| ssl_cert | name, including full path of private key file. |
| ssl_chain | [optional] name, including full path of certificate chain |

The certificate files should be placed on a path accessible to the Anchore Engine service, for example in the /config directory which is typically mapped as a volume into the container.  Note that the location outside the container will depend on your configuration - for example if you are volume mounting '/path/to/aevolume/config/' on the docker host to '/config' within the container, you'll need to place the ssl files in '/path/to/aevolume/config/' on the docker host, so that they are accessible in '/config/' inside the container, before starting the service.

The ssl_chain file is optional and may be required by some certificate authorities. If your certificate authority provides a chain certificate then include it within the configuration.

**Note:** While a certificate may be purchased from a well-known and trusted certificate authority in some cases the certificate is signed by an intermediate certificate which is not included within a TLS/SSL clients trust stores. In these cases the intermediate certificate is signed by the certificate authority however without the full 'chain' showing the provenance and integrity of the certificate the TLS/SSL client may not trust the certificate.

Any certificates used by the Anchore Engine services need to be trusted by all other Anchore Engine services.

If an internal certificate authority is used the root certificate for the internal CA can be added to the Anchore engine using the following procedure or SSL verification can be disabled by setting the following parameter:

`internal_ssl_verify: True`