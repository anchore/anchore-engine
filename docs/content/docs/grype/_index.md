---
title: "Grype Integration"
linkTitle: "Grype Vulnerability Scanner"
weight: 1
---

As of Anchore Engine 1.0.0, Anchore Engine is fully integrated with Grype by default for vulnerability scanning. The V2 vulnerability scanner, based on Grype, replaces the legacy vulnerability scanner in previous versions of Anchore Engine. The legacy vulnerability scanner will still be used for anyone running older versions of Anchore engine.
You can keep the legacy vulnerability scanner when installing Anchore Engine 1.0.0, but you will have to explicitly configure 1.0.0 to use the legacy vulnerability scanner.

If you are upgrading to Anchore Engine 1.0.0 from an earlier version, you will retain your previous vulnerability scanner setting. You will need to follow the linked instructions for upgrading to the new vulnerability scanner. 

***Note:*** The legacy vulnerability scanner will be removed in a future release.

### Installing
As of Anchore Engine 1.0.0, the V2 vulnerability scanner, based on Grype, is included with Anchore Engine by default. 

### Installing and keeping the legacy feed and vulnerability scanner
Anchore Engine can be configured to use the legacy vulnerability scanner. It is not possible to run both legacy and V2 vulnerability scanners at the same time. This configuration is picked up at bootstrap, and cannot be changed on a running system.
Downgrading from the V2 vulnerability scanner back to the legacy scanner is not supported and will cause data issues.

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
