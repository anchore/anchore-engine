---
title: "Adding Custom Certificate Authority"
linkTitle: "Custom Certificates"
weight: 2
---

If a custom CA certificate is required to access an external resource then the Trust Store in the Anchore Engine container needs to be updated in two places.

1. The operating system provided trust store.
2. The Certifi trust store.

The operating system trust store is read by the skopeo utility and python requests library that is used to access container registries to read manifests and pull image layers.

If your container registry users a custom CA then you can update the trust store to trust the certificate or use the --insecure option when configuring the registry.

To add a certificate to the operating system trust store the CA certificate should be placed in the /etc location that is appropriate for the container image being used.  

- For anchore 0.2.X and earlier, the base container is CentOS 7, which stores certs in `/etc/pki/ca-trust/source/anchors/` and requires user to run update-ca-trust command as root to update the system certs.
- For anchore 0.3.X, the base container is Ubuntu 18.04, which stores certs in `/usr/local/share/ca-certificates/<new_directory>/<new_cert_file>.crt` and requires the user to run update-ca-certificates command as root to update the system certs.
- For anchore 0.4.X and newer, the base container is Red Hat Universal Base Image 7, which stores certs in `/etc/pki/ca-trust/source/anchors/` and requires user to run update-ca-trust command as root to update the system certs.
- For anchore 0.7.X and newer, the base container is Red Hat Universal Base Image 8, which stores certs in `/etc/pki/ca-trust/source/anchors/` and requires user to run update-ca-trust command as root to update the system certs.

[Certifi](https://pypi.org/project/certifi/) is a curated list of trusted certificate authorities that is used by the Python requests HTTP client library. The Python requests library is used by Anchore Engine for all HTTP interactions, including when communicating with Anchore Feed service, when webhooks are sent to a TLS enabled endpoint and inbetween Anchore Engine services if TLS has been configured. To update the Certifi trust store the CA certificate should be appended onto the cacert.pem file provided by the Certifi library.

- For anchore 0.2.X and earlier, the base container is CentOS 7, certifi's cacert.pem is installed in `/usr/lib/python2.7/site-packages/certifi/cacert.pem`
- For anchore 0.3.X, the base container is Ubuntu 18.04, certifi's cacert.pem is installed in `/usr/local/lib/python3.6/dist-packages/certifi/cacert.pem`
- For anchore 0.4.X and newer, the base container is Red Hat Universal Base Image 7, certifi's cacert.pem is installed in `/opt/rh/rh-python36/root/usr/lib/python3.6/site-packages/certifi/cacert.pem`
- For anchore 0.7.X and newer, the base container is Red Hat Universal Base Image 8, certifi's cacert.pem is installed in `/usr/local/lib/python3.6/site-packages/certifi/cacert.pem`

The following Dockerfile illustrates an example of how this general process can be automated to produce your own anchore-engine container (based on version 0.2.4 of anchore-engine) with new custom CA cert installed.  A similiar process can be used for anchore-engine 0.4.X or newer, with the commands adjusted as appropriate with the differences described above.

**Dockerfile**

```
FROM docker.io/anchore/anchore-engine:v0.4.0

USER root:root
COPY ./custom-ca.pem /etc/pki/ca-trust/source/anchors/
RUN update-ca-trust
RUN /usr/bin/cat /etc/pki/ca-trust/source/anchors/custom-ca.pem >> /opt/rh/rh-python36/root/usr/lib/python3.6/site-packages/certifi/cacert.pem
USER anchore:anchore

```

**Build Custom Image**

```
$ sudo docker build -t anchore/anchore-engine:v0.4.0custom .
```