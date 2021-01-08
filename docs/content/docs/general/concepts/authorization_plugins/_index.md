---
title: "Authorization Plugins"
linkTitle: "Authorization Plugins"
weight: 7
---

New in Anchore Engine 0.3.0, an open interface for allowing authorization decisions to be made by external plugins has been implemented. The interface is an HTTP API and has a swagger specification that can be found [here](https://github.com/anchore/anchore-engine/blob/master/anchore_engine/plugins/authorization/swagger/swagger.yaml).

The interface is simple and relies on just a few operations:

1. Principal lifecycle notifications (initialize, delete)
    1. Principals are basically users. These are merely notifications and may be ignored by an implementation. They are intended to allow an external plugin to synchronize the lifecycle of its data with that of the account store in anchore engine. For example, flushing all authorization rules when a user is deleted, or initializing new defaults when a principal/user is created.
2. Domain lifecycle notifications (initialize, delete)
    1. Domains are basically accounts. As for principals, these notifications may be ignored by an implementation. They are intended to allow an external plugin to synchronize the lifecycle of its data with that of the account store in anchore engine. For example, flushing all permission mappings when an account is deleted, or initializing defaults on creation of a new account/domain.
3. Authorization Request
    1. Determine if the requested (domain, action, target) tuples are authorized. See Accounts, User, and Access Control for more information on how domains, actions, and targets.

Configuring which authorization plugin to use for a service is determined by the: *authorization_handler* setting in the service's config section of the config.yaml. The default value is *native*, but to use an external provider (e.g. the RBAC plugin provided by Anchore Enterprise), set the value to *external and provide a authorization_handler_config* map object with the url to which requests should be made. For example:

The default (which applies if it is omitted):

```YAML
services:
  apiext:
    authorization_handler: native
```

To use an external handler:

```YAML
services:
  apiext:
    authorization_handler: external
    authorization_handler_config:
      endpoint: "http://localhost:89"
```

**Note:** This interface is currently not authenticated or authorized, and should be properly secured via network controls, or ideally, only available on the local host and not externally connected. This is intended to follow a side-car pattern where an authorizer is deployed locally with each external Anchore API component.