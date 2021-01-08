---
title: "Reverting Back to use RHSA Data"
linkTitle: "Revert back to RHSA post-0.7.0 upgrade"
weight: 70
---

*NOTE: This section is only for very specific situations where you absolutely must revert the matching system to use the RHSA data. This should not be done lightly. The newer CVE-based data is more accurate, specific, and provides a more consistent experience with other distros.*

If your processing of anchore output relies on RHSA keys as vulnerability matches, or you have large RHSA-based whitelists that cannot be converted to CVE-based,
then it is possible, though not recommended, to migrate your system back to using the RHSA-based feeds (centos:* groups).

Here is the process. It requires the Anchore CLI with access to the API as well as direct access to the internal policy engine API endpoint. That may require a `docker exec` or `kubectl exec` call
to achieve and will be deployment/environment specific.

1. Revert the distro mapping records that map centos, fedora, and rhel to use the RHEL vuln data.
    1. With API access to the policy engine directly (output omitted for brevity), remove the existing _distro mappings_ to RHEL data. These are the used by Anchore:

    ```
    curl -X DELETE -u admin:foobar http://localhost:8087/v1/distro_mappings?from_distro=centos
    curl -X DELETE -u admin:foobar http://localhost:8087/v1/distro_mappings?from_distro=rhel
    curl -X DELETE -u admin:foobar http://localhost:8087/v1/distro_mappings?from_distro=fedora
    
    ```

    1. Continuing with API access to the policy engine directly, replace the removed mappings with new mappings to the _centos_ feeds:

    ```
    curl -H "Content-Type: application/json" -X POST -u admin:foobar -d'{"from_distro":"centos", "to_distro":"centos", "flavor":"RHEL"}' http://localhost:8087/v1/distro_mappings
    curl -H "Content-Type: application/json" -X POST -u admin:foobar -d'{"from_distro":"fedora", "to_distro":"centos", "flavor":"RHEL"}' http://localhost:8087/v1/distro_mappings
    curl -H "Content-Type: application/json" -X POST -u admin:foobar -d'{"from_distro":"rhel", "to_distro":"centos", "flavor":"RHEL"}' http://localhost:8087/v1/distro_mappings
    ```
   
    Note: if something went wrong and you want to undo the progress you've made, just make the same set of calls as the last two steps in the same order but with the `to_distro` values set to 'rhel'.
       
    1. Now, ensure you are back where you have access to the main Anchore API and the Anchore CLI installed. Disable the existing rhel feed groups

    ```
    anchore-cli system feeds config vulnerabilities --disable --group rhel:5
    anchore-cli system feeds config vulnerabilities --disable --group rhel:6
    anchore-cli system feeds config vulnerabilities --disable --group rhel:7
    anchore-cli system feeds config vulnerabilities --disable --group rhel:8
    ```

    ```
    anchore-cli system feeds delete vulnerabilities --group rhel:8
    anchore-cli system feeds delete vulnerabilities --group rhel:7
    anchore-cli system feeds delete vulnerabilities --group rhel:6
    anchore-cli system feeds delete vulnerabilities --group rhel:5
    ```
   
   1. Enable the centos feed groups that have the RHSA vulnerability data
    ```
    anchore-cli system feeds config vulnerabilities --enable --group centos:8
    anchore-cli system feeds config vulnerabilities --enable --group centos:7
    anchore-cli system feeds config vulnerabilities --enable --group centos:6
    anchore-cli system feeds config vulnerabilities --enable --group centos:5
    ```
   
   NOTE: if you already have centos data in your feeds (verify with `anchore-cli system feeds list`) then you'll need to delete the centos data groups as well
   to ensure a clean re-syncin the next steps. This is accomplished with: 
   ```
   anchore-cli system feeds delete vulnerabilities --group centos:5
   anchore-cli system feeds delete vulnerabilities --group centos:6
   anchore-cli system feeds delete vulnerabilities --group centos:7
   anchore-cli system feeds delete vulnerabilities --group centos:8
   ```   
   
   1. Now do a sync to re-match any images using rhel/centos to the RHSA data
   
    ```
    [root@d64b49fe951c ~]# anchore-cli system feeds sync
    
    WARNING: This operation should not normally need to be performed except when the anchore-engine operator is certain that it is required - the operation will take a long time (hours) to complete, and there may be an impact on anchore-engine performance during the re-sync/flush.
    
    Really perform a manual feed data sync/flush? (y/N)y
    Feed                   Group                  Status         Records Updated        Sync Duration        
    github                 github:composer        success        0                      0.28s                
    github                 github:gem             success        0                      0.34s                
    github                 github:java            success        0                      0.33s                
    github                 github:npm             success        0                      0.23s                
    github                 github:nuget           success        0                      0.23s                
    github                 github:python          success        0                      0.29s                
    nvdv2                  nvdv2:cves             success        0                      60.59s               
    vulnerabilities        alpine:3.10            success        0                      0.27s                
    vulnerabilities        alpine:3.11            success        0                      0.31s                
    vulnerabilities        alpine:3.3             success        0                      0.31s                
    vulnerabilities        alpine:3.4             success        0                      0.25s                
    vulnerabilities        alpine:3.5             success        0                      0.26s                
    vulnerabilities        alpine:3.6             success        0                      0.25s                
    vulnerabilities        alpine:3.7             success        0                      0.26s                
    vulnerabilities        alpine:3.8             success        0                      0.35s                
    vulnerabilities        alpine:3.9             success        0                      0.28s                
    vulnerabilities        amzn:2                 success        0                      0.26s                
    vulnerabilities        centos:7               success        1003                   34.91s               
    vulnerabilities        centos:8               success        199                    9.15s                
    vulnerabilities        debian:10              success        2                      0.50s                
    vulnerabilities        debian:11              success        4                      60.53s               
    vulnerabilities        debian:7               success        0                      0.30s                
    vulnerabilities        debian:8               success        3                      0.34s                
    vulnerabilities        debian:9               success        2                      0.38s                
    vulnerabilities        debian:unstable        success        4                      0.39s                
    vulnerabilities        ol:5                   success        0                      0.31s                
    vulnerabilities        ol:6                   success        0                      0.29s                
    vulnerabilities        ol:7                   success        0                      0.41s                
    vulnerabilities        ol:8                   success        0                      0.28s                
    vulnerabilities        rhel:5                 success        0                      0.28s                
    vulnerabilities        rhel:6                 success        0                      0.43s                
    vulnerabilities        ubuntu:12.04           success        0                      0.45s                
    vulnerabilities        ubuntu:12.10           success        0                      0.25s                
    vulnerabilities        ubuntu:13.04           success        0                      0.24s                
    vulnerabilities        ubuntu:14.04           success        0                      0.37s                
    vulnerabilities        ubuntu:14.10           success        0                      0.25s                
    vulnerabilities        ubuntu:15.04           success        0                      0.42s                
    vulnerabilities        ubuntu:15.10           success        0                      0.23s                
    vulnerabilities        ubuntu:16.04           success        0                      0.35s                
    vulnerabilities        ubuntu:16.10           success        0                      0.33s                
    vulnerabilities        ubuntu:17.04           success        0                      0.33s                
    vulnerabilities        ubuntu:17.10           success        0                      0.31s                
    vulnerabilities        ubuntu:18.04           success        0                      0.42s                
    vulnerabilities        ubuntu:18.10           success        0                      0.37s                
    vulnerabilities        ubuntu:19.04           success        0                      0.45s                
    vulnerabilities        ubuntu:19.10           success        0                      0.32s                
    [root@d64b49fe951c ~]# anchore-cli image vuln centos os
    Vulnerability ID        Package                            Severity        Fix                     CVE Refs              Vulnerability URL                                      Type        Feed Group        Package Path        
    RHSA-2020:0271          libarchive-3.3.2-7.el8             High            0:3.3.2-8.el8_1         CVE-2019-18408        https://access.redhat.com/errata/RHSA-2020:0271        rpm         centos:8          pkgdb               
    RHSA-2020:0273          sqlite-libs-3.26.0-3.el8           High            0:3.26.0-4.el8_1        CVE-2019-13734        https://access.redhat.com/errata/RHSA-2020:0273        rpm         centos:8          pkgdb               
    RHSA-2020:0575          systemd-239-18.el8_1.1             High            0:239-18.el8_1.4                              https://access.redhat.com/errata/RHSA-2020:0575        rpm         centos:8          pkgdb               
    RHSA-2020:0575          systemd-libs-239-18.el8_1.1        High            0:239-18.el8_1.4                              https://access.redhat.com/errata/RHSA-2020:0575        rpm         centos:8          pkgdb               
    RHSA-2020:0575          systemd-pam-239-18.el8_1.1         High            0:239-18.el8_1.4                              https://access.redhat.com/errata/RHSA-2020:0575        rpm         centos:8          pkgdb               
    RHSA-2020:0575          systemd-udev-239-18.el8_1.1        High            0:239-18.el8_1.4                              https://access.redhat.com/errata/RHSA-2020:0575        rpm         centos:8          pkgdb               
    ```

Note in the last command output that the OS vulnerabilities are again showing 'RHSA' matches. The restoration to RHSA-based vuln data is complete.
