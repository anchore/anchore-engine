---
title: "Beta - Grype Integration"
linkTitle: "Grype Vulnerability Scanner"
weight: 1
---

Anchore Engine 0.10 includes a limited-functionality beta release of an integration with [Grype](https://github.com/anchore/grype)
for vulnerability scanning. This integration will replace the legacy vulnerability scanner in a future version of Anchore Engine,
but is provided in this release in a preview capacity so users can try it out.

***Note:*** This tech preview is not intended for use in production environments. It should be installed in sandbox environments,
and is strictly provided here to give users an early, hands-on preview of the feature. It may not include all 
functionality of the legacy scanner. Please report any issues found with it on the
[anchore-engine Github repo](https://github.com/anchore/anchore-engine/issues).

### Installing
As of 0.10.0, Anchore Engine can be configured to use either the legacy or grype vulnerability scanner. It is not possible to run
both vulnerability scanners at the same time. This configuration is picked up at bootstrap, and cannot be changed on a running system.

The grype scanner is intended for use in sandbox or staging environments in the current release. Downgrading from the
grype scanner back to the legacy scanner is not supported and will cause data issues.

#### Running with docker-compose
1. Install or update to Anchore Engine 0.10.0.
2. Add the following environment variable to the policy engine container section of the docker compose file:

```
    policy-engine:
      ...
      environment:
      ...
      - ANCHORE_VULNERABILITIES_PROVIDER=grype
```        

3. Redeploy the services.

#### Running with helm
1. Install or update to Anchore Engine 0.10.0.
2. Update the following value in your `values.yaml` configuration file. See 
   [the chart README](https://github.com/anchore/anchore-charts/tree/master/stable/anchore-engine#installing-the-anchore-engine-helm-chart)
   for more details on configuring this file:

```
    anchorePolicyEngine
      ...
      vulnerabilityProvider: grype
```

3. Redeploy the services

```
    helm upgrade
```

After making the relevant change above and redeploying, the system will start up with the grype vulnerability scanner enabled and will
sync the latest version of grype db. Note that legacy feeds will no longer be synced while grype is configured. All vulnerability data
and scanning will now come from the grype feed.

### Vulnerability Feed Data and Syncs

The Grype scanner has its own feed sync mechanism using the Grype vulnerability DB rather than the legacy https://ancho.re service used by
the legacy scanner. This results in a much faster sync process since the DB is packaged as a single database file. It also reduces
load on the Engine DB since the scanner matching and syncs do not require large amounts of writes into the Engine DB.

The feed synced by the Grype provider is identified as feed name 'grypedb' when using the feed listing API or `anchore-cli system feeds list` CLI command.

The Grype vulnerability DB is built from the same sources as the legacy service, so there is no reduction in scan coverage or vulnerabilities
sources supported.
