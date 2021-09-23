---
title: "Grype Integration"
linkTitle: "Grype Vulnerability Scanner"
weight: 1
---
### New Installation

As of Anchore Engine 1.0.0, Anchore Engine is fully integrated with Grype by default for vulnerability scanning. The V2 vulnerability scanner, based on Grype, replaces the legacy vulnerability scanner in previous versions of Anchore Engine. 
You can choose to use the legacy vulnerability scanner when installing Anchore Engine 1.0.0, but you will have to explicitly configure 1.0.0 to use the legacy vulnerability scanner.

### Upgrading

See the following scenarios when upgrading to Anchore Engine to 1.0.0.

-- If you are upgrading to Engine 1.0.0 with the legacy scanner configured, then Engine 1.0.0 will continue to respect that configured (legacy) scanner.
-- If you are upgrading to Engine 1.0.0 without the scanner configured, then Engine 1.0.0 will notice that it is an upgrade and default to the V1 vulnerability scanner (legacy), just as the previous installation instance defaulted to.
-- If you have Engine 1.0.0 that is using the V1 vulnerability scanner (legacy), either configured or because of an upgrade, you can follow the directions to configure it to the new V2 vulnerability scanner (based on Grype) and switch to it. But if you switch to the V2 scanner, you cannot revert back to the V1 legacy scanner unless you do a fresh install with the V1 scanner configured.
-- If you choose not to upgrade, instead performing a new installation of Engine 1.0.0, you will have the V2 vulnerability scanner (based on Grype) configured by default. 

***Note:*** The legacy vulnerability scanner will be removed in a future release.

#### Running with docker-compose
1. Install or update to Anchore Engine 1.0.0.
2. Add the following environment variable to the policy engine container section of the docker compose file:

```
    policy-engine:
      ...
      environment:
      ...
      - ANCHORE_VULNERABILITIES_PROVIDER=legacy
```        

3. Redeploy the services.

#### Running with helm
1. Install or update to Anchore Engine 1.0.0.
2. Update the following value in your `values.yaml` configuration file. See 
   [the chart README](https://github.com/anchore/anchore-charts/tree/master/stable/anchore-engine#installing-the-anchore-engine-helm-chart)
   for more details on configuring this file:

```
    anchorePolicyEngine
      ...
      vulnerabilityProvider: legacy
```

3. Redeploy the services

```
    helm upgrade
```

After making the relevant change above and redeploying, the system will start up with the legacy vulnerability scanner enabled and will sync the latest version of legacy database. Note that Grype feeds will not sync while legacy is configured. All vulnerability data and scanning will now come from the legacy scanner and feed.

### Vulnerability Feed Data and Syncs

The V2 vulnerability scanner based on Grype has its own feed sync mechanism using the Grype vulnerability database rather than the legacy https://ancho.re service used by
the legacy scanner. This results in a much faster sync process since the database is packaged as a single database file. It also reduces
load on the Engine database, since the scanner matching and syncs do not require large amounts of writes into the Engine database.

The Grype vulnerability database is built from the same sources as the legacy service, so there is no reduction in scan coverage or vulnerabilities
sources supported.
