---
title: "Configuring Registries"
weight: 1
---

The Anchore Engine will attempt to download images from any registry without requiring further configuration.
However if your registry requires authentication then the registry and corresponding credentials will need to be defined.

### Listing Registries

Running the following command lists the defined registries.

```
$ anchore-cli registry list 

Registry                    User            
docker.io                   anchore
quay.io                     anchore
registry.example.com        johndoe 
192.168.1.200:5000          janedoe
```

Here we can see that 4 registries have been defined. If no registry was defined then the Anchore Engine would attempt to pull images without authentication but a registry is defined then all pulls for images from that registry will use the specified username and password.

### Adding a Registry

Registries can be added using the following syntax.

`anchore-cli registry add REGISTRY USERNAME PASSWORD`

The REGISTRY parameter should include the fully qualified hostname and port number of the registry. For example: registry.anchore.com:5000

Anchore Engine will only pull images from a TLS/SSL enabled registry. If the registry is protected with a self signed certificate or a certificated signed by an unknown certificate authority then the `--insecure` parameter can be passed which instructs the Anchore Engine not to validate the certificate.

Most Docker V2 compatible registries require username and password for authentication. Amazon ECR, Google GCR and Microsoft Azure include support 
for their own native credentialing. See Working with [AWS ECR Registry Credentials]({{< ref "ecr_configuration" >}}),
[Working with Google GCR Registry Credentials]({{< ref "gcr_configuration" >}}) and 
[Working with Azure Registry Credentials]({{< ref "acr_configuration" >}}) for more details.


### Getting Registry Details

The *registry get* command allows the user to retrieve details about a specific registry.

For example:

```
$ anchore-cli registry get registry.example.com 

Registry: registry.example.com
User: johndoe
Verify TLS: False
Created: 2017-09-02T18:25:34
Updated: 2017-09-02T18:25:34
```

In this example we can see that the registry.example.com registry was added to the Anchore Engine on the 2nd September at 18:25 UTC. This registry. The password for the registry cannot be retrieved through the API or CLI.

### Updating Registry Details

Once a registry had been defined the parameters can be updated using the *update* command. This allows a registry's username, password and insecure (validate TLS) parameters to be updated.

`anchore-cli registry update REGISTRY USERNAME PASSWORD [--insecure]`

### Deleting Registries

A Registry can be deleted from Anchore's configuration using the `del` command.

For example to delete the configuration for registry.example.com the following command should be issued:

`anchore-cli registry delete registry.example.com`

**Note:** Deleting a registry record does not delete the records of images/tags associated with that registry.

### Advanced

Anchore engine attempts to perform a credential validation upon registry addition, but there are cases where a credential can be valid but the validation routine can fail (in particular, credential validation methods are changing for public registries over time).  If you are unable to add a registry but believe that the credential you are providing is valid, or you wish to add a credential to anchore before it is in place in the registry, you can bypass the registry credential validation process using the `--skip-validation` option to the `registry add` command.










