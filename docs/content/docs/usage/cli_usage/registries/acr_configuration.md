---
title: "Working with Azure Registry Credentials"
weight: 1
---

To use an Azure Registry, you can configure Anchore to use either the admin credential(s) or a service principal. Refer to Azure documentation for differences and how to setup each.  When you've chosen a credential type, use the following to determine which registry command options correspond to each value for your credential type

- Admin Account

    - Registry: The login server (Ex. myregistry1.azurecr.io)
    - Type: Set to docker_v2
    - Username: The username in the 'az acr credentials show --name <registry name>' output
    - Password: The password or password2 value from the 'az acr credentials show' command result

- Service Principle

    - Registry: The login server (Ex. myregistry1.azurecr.io)
      Type: Set to docker_v2
      Username: The service principal app id
      Password: The service principal password

To add an azure registry credential, invoke anchore-cli as follows:

`anchore-cli registry add --registry-type <Type> <Registry> <Username> <Password>`

Once a registry has been added, any image that is added (e.g. `anchore-cli image add <Registry>/some/repo:sometag`) will use the provided credential to download/inspect and analyze the image.
