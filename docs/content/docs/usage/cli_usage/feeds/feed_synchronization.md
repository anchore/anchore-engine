---
title: "Feed Synchronization"
linkTitle: "Synchronization"
weight: 1
---

When the Anchore Engine runs it will begin to synchronize security feed data from the Anchore feed service.

CVE data for Linux distributions such as Alpine, CentOS, Debian, Oracle, Red Hat and Ubuntu will be downloaded. The initial sync may take anywhere from  10 to 60 minutes depending on the speed of your network connection.

### Checking Feed Status

Starting with Anchore Engine version 0.2.0 the status of the feed synchronization can be retrieved through the API and Anchore CLI.

```
anchore-cli system feeds list 

Feed                   Group                  LastSync                           RecordCount        
vulnerabilities        alpine:3.3             2018-04-25T11:51:33.567214Z        457                
vulnerabilities        alpine:3.4             2018-04-25T11:51:33.976689Z        594                
vulnerabilities        alpine:3.5             2018-04-25T11:51:24.447436Z        649                
vulnerabilities        alpine:3.6             2018-04-25T11:51:32.413834Z        632                
vulnerabilities        alpine:3.7             2018-04-25T11:51:36.313911Z        689                
vulnerabilities        centos:5               2018-04-25T11:51:22.453408Z        1270               
vulnerabilities        centos:6               2018-04-25T11:51:22.966213Z        1245               
vulnerabilities        centos:7               2018-04-25T11:51:35.102044Z        621                
vulnerabilities        debian:10              2018-04-25T11:51:37.509069Z        16858              
vulnerabilities        debian:7               2018-04-25T11:51:20.383254Z        20225              
vulnerabilities        debian:8               2018-04-25T11:51:21.275382Z        19027              
vulnerabilities        debian:9               2018-04-25T11:51:23.704236Z        17662              
vulnerabilities        debian:unstable        2018-04-25T11:51:25.831878Z        17859              
vulnerabilities        ol:5                   2018-04-25T11:51:24.931268Z        1213               
vulnerabilities        ol:6                   2018-04-25T11:51:28.358076Z        1276               
vulnerabilities        ol:7                   2018-04-25T11:51:28.733646Z        685                
vulnerabilities        ubuntu:12.04           2018-04-25T11:51:34.452081Z        14945              
vulnerabilities        ubuntu:12.10           2018-04-25T11:51:35.517364Z        5652               
vulnerabilities        ubuntu:13.04           2018-04-25T11:51:35.923466Z        4127               
vulnerabilities        ubuntu:14.04           2018-04-25T11:51:29.495143Z        15311              
vulnerabilities        ubuntu:14.10           2018-04-25T11:51:33.162533Z        4456               
vulnerabilities        ubuntu:15.04           2018-04-25T11:51:30.617371Z        5676               
vulnerabilities        ubuntu:15.10           2018-04-25T11:51:31.957883Z        6511               
vulnerabilities        ubuntu:16.04           2018-04-25T11:51:26.467438Z        12288              
vulnerabilities        ubuntu:16.10           2018-04-25T11:51:27.961046Z        8646               
vulnerabilities        ubuntu:17.04           2018-04-25T11:51:39.485986Z        9156               
vulnerabilities        ubuntu:17.10           2018-04-25T11:51:22.047635Z        7169               
```

This command will report list the feeds synchronized by the Anchore engine, last sync time and current record count.

Note: Time is reported as UTC, not local time.

### Manually initiating feed sync

After the initial sync has completed the engine will run an incremental sync at a user defined period, by default every 4 hours. At any time a feed sync can be initiated through the API or CLI.

A sync operation can be manually initiated by running the system feeds sync command however this should not be required under normal operation.

`anchore-cli system feeds sync`

### Performing full resync

The Anchore Engine can be instructed to flush the current feed data and perform a full synchronization.

Under normal circumstances this operation should not be required since the Anchore Engine performs regular incremental sync.

This process may take anywhere from  10 to 60 minutes depending on the speed of your network connection.

`anchore-cli system feeds sync --flush`

The CLI will issue a warning and prompt for confirmation before proceeding with a sync.