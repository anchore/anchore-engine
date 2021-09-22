---
title: "Feed Configuration"
linkTitle: "Configuration"
weight: 1
---

### Feed Synchronization Interval

The default configuration for the Anchore Engine will download vulnerability data from Anchore's feed service every 21,600 seconds (6hours).

For most users the only configuration option that is typically updated is the feed synchronization interval - the time interval (in seconds) at which the feed sync is run.

```policy_engine:
    .....
    
    cycle_timers:
      ...
      feed_sync: 14400
```

### Feed Settings

Feed sync configuration is set in the config.yaml file used by policy engine service. The `services.policy_engine.vulnerabilities.sync.data` section
of the configuration file in the policy engine's container controls the behavior of feed syncs done by that particular container. Ensure this config is synchronized between containers if you are running more than one policy engine. This is usually handled for you by Helm Charts on Kubernetes, for example.

The Anchore Engine will default to downloading feed data from Anchore's feed service hosted at https://ancho.re/v1/service/feeds and running in AWS in the
us-west-2 region.

By default, Anchore Engine will only sync the non-grype feeds enabled in the config section shown below. Setting additional feed types to true or false will
enable or disable, respectively, synchronization of the specified feed.

```
services:
  ...
  policy_engine:
    ...
    vulnerabilities:
      ...
      sync:
        ...
        data:
          grypedb:
            enabled: true
            url: ${ANCHORE_GRYPE_DB_URL}
          packages:
            enabled: true
            url: ${ANCHORE_FEEDS_URL}
```

***Note:*** As shown above, Anchore Engine's default is now Grype. The Grype feed is the default, and the only one that Anchore Engine syncs.

#### Read Timeout

Under rare circumstances you may see syncs failing with errors to fetch data due to timeouts. This is typically due to load on the feed service, network issues, or
some other temporary condition. However, if you want to increase the timeout to improve the likelihood of success, modify the _read_timeout_seconds_ of the feeds configuration:

```
feeds:
  ...
  read_timeout_seconds: 180
```

### Controlling Which Feeds and Groups are Synced

Note: The package and nvd data feeds are large, resulting in the initial sync taking some time.

During initial feed sync, you can always query the progress and status of the feed sync using the anchore-cli.

```
anchore@93d6977e2061 anchore-engine]$ anchore-cli system feeds list
Feed                   Group                  LastSync                          RecordCount        
github                 github:composer        2020-03-27T22:19:57.328440        78                 
github                 github:gem             2020-03-27T22:19:59.069349        333                
github                 github:java            2020-03-27T22:20:03.393652        432                
github                 github:npm             2020-03-27T22:20:09.422600        653                
github                 github:nuget           2020-03-27T22:20:16.628054        50                 
github                 github:python          2020-03-27T22:20:17.754270        250                
nvdv2                  nvdv2:cves             2020-03-27T20:42:13.104384        141090             
vulnerabilities        alpine:3.10            2020-03-27T19:47:27.188488        1725               
vulnerabilities        alpine:3.11            2020-03-27T19:47:42.467000        1904               
vulnerabilities        alpine:3.3             2020-03-27T19:47:59.309026        457                
vulnerabilities        alpine:3.4             2020-03-27T19:48:03.531092        681                
vulnerabilities        alpine:3.5             2020-03-27T19:48:09.396503        875                
vulnerabilities        alpine:3.6             2020-03-27T19:48:17.029289        1051               
vulnerabilities        alpine:3.7             2020-03-27T19:48:27.230411        1395               
vulnerabilities        alpine:3.8             2020-03-27T19:48:39.811189        1486               
vulnerabilities        alpine:3.9             2020-03-27T19:48:53.472895        1558               
vulnerabilities        amzn:2                 2020-03-27T19:49:08.039725        320                
vulnerabilities        centos:5               2020-03-27T19:49:19.232142        1347               
vulnerabilities        centos:6               2020-03-27T19:49:45.948061        1393               
vulnerabilities        centos:7               2020-03-27T19:50:16.913685        1004               
vulnerabilities        centos:8               2020-03-27T19:50:47.762328        199                
vulnerabilities        debian:10              2020-03-27T19:50:56.298579        22407              
vulnerabilities        debian:11              2020-03-27T19:55:05.935002        19443              
vulnerabilities        debian:7               2020-03-27T19:58:55.500030        20455              
vulnerabilities        debian:8               2020-03-27T20:01:58.427061        23481              
vulnerabilities        debian:9               2020-03-27T20:05:20.356754        22507              
vulnerabilities        debian:unstable        2020-03-27T20:09:37.909305        23701              
vulnerabilities        ol:5                   2020-03-27T20:12:55.707457        1245               
vulnerabilities        ol:6                   2020-03-27T20:13:25.500670        1504               
vulnerabilities        ol:7                   2020-03-27T20:14:03.279049        1121               
vulnerabilities        ol:8                   2020-03-27T20:14:37.144376        157                
vulnerabilities        rhel:5                 2020-03-27T20:14:43.707760        7237               
vulnerabilities        rhel:6                 2020-03-27T20:16:59.010218        6805               
vulnerabilities        rhel:7                 2020-03-27T20:18:09.917886        5846               
vulnerabilities        rhel:8                 2020-03-27T20:19:12.650326        1428               
vulnerabilities        ubuntu:12.04           2020-03-27T20:19:28.540257        14948              
vulnerabilities        ubuntu:12.10           2020-03-27T20:21:27.080478        5652               
vulnerabilities        ubuntu:13.04           2020-03-27T20:23:09.806360        4127               
vulnerabilities        ubuntu:14.04           2020-03-27T20:23:40.672987        21176              
vulnerabilities        ubuntu:14.10           2020-03-27T20:27:27.221192        4456               
vulnerabilities        ubuntu:15.04           2020-03-27T20:28:05.360075        5877               
vulnerabilities        ubuntu:15.10           2020-03-27T20:28:53.416816        6513               
vulnerabilities        ubuntu:16.04           2020-03-27T20:29:51.105326        18288              
vulnerabilities        ubuntu:16.10           2020-03-27T20:33:29.612544        8647               
vulnerabilities        ubuntu:17.04           2020-03-27T20:35:33.512059        9157               
vulnerabilities        ubuntu:17.10           2020-03-27T20:36:39.141950        7936               
vulnerabilities        ubuntu:18.04           2020-03-27T20:37:35.077867        12547              
vulnerabilities        ubuntu:18.10           2020-03-27T20:39:20.097963        8397               
vulnerabilities        ubuntu:19.04           2020-03-27T20:40:18.628869        8664               
vulnerabilities        ubuntu:19.10           2020-03-27T20:41:20.828796        7327      
```

***Note:*** The Grype feed is the only feed that will be synced. It will
contain the records from all the other groups. It is not possible to include or exclude groups from the Grype feed.

### Using the Config File to Include/Exclude Feeds at System Bootstrap

The most common way to set which feeds are synced is in the config.yaml for the policy engine. By default, 
the _grypedb_ and _packages_ feeds are synced to provide good vulnerability matching support for a variety of linux distros
and application package types. Normally it will not be necessary to modify that set.

To disable a feed or enable a disabled feed, modify the config.yaml's _feeds_ section to:

```
feeds:
  selective_sync: 
    enabled: true
    feeds:
      grypedb: true
      packages: true
```

Those boolean values can be used to enable/disable the feeds. Note that changes will require a restart of the policy engine to take effect and settnig
a feed to 'false' will not remove any data or show in the API/CLI, it will simply skip updates during sync operations.


### Using the CLI to Configure Feeds


#### Disabling an Entire Feed

An entire feed can be disabled. This means that all the feed's groups will no longer be updated and no new groups will be synced either on subsequent sync operations.
This does not, however, remove any existing data nor will it remove the feed or feed group metadata records.

Example:
```
[anchore@93d6977e2061 anchore-engine]$ anchore-cli system feeds config github --disable
Feed                    Group                  LastSync                          RecordCount        
github(disabled)        github:composer        2020-03-27T22:19:57.328440        78                 
github(disabled)        github:gem             2020-03-27T22:19:59.069349        333                
github(disabled)        github:java            2020-03-27T22:20:03.393652        432                
github(disabled)        github:npm             2020-03-27T22:20:09.422600        653                
github(disabled)        github:nuget           2020-03-27T22:20:16.628054        50                 
github(disabled)        github:python          2020-03-27T22:20:17.754270        250      
```

The feed can be enabled again using a similar command and on the next sync operation its data will be updated.
Example:
```
[anchore@93d6977e2061 anchore-engine]$ anchore-cli system feeds config github --enable
Feed          Group                  LastSync                          RecordCount        
github        github:composer        2020-03-27T22:19:57.328440        78                 
github        github:gem             2020-03-27T22:19:59.069349        333                
github        github:java            2020-03-27T22:20:03.393652        432                
github        github:npm             2020-03-27T22:20:09.422600        653                
github        github:nuget           2020-03-27T22:20:16.628054        50                 
github        github:python          2020-03-27T22:20:17.754270        250                

[anchore@93d6977e2061 anchore-engine]$ anchore-cli system feeds sync

WARNING: This operation should not normally need to be performed except when the anchore-engine operator is certain that it is required - the operation will take a long time (hours) to complete, and there may be an impact on anchore-engine performance during the re-sync/flush.

Really perform a manual feed data sync/flush? (y/N)y
Feed                   Group                  Status         Records Updated        Sync Duration        
github                 github:composer        success        0                      0.59s                
github                 github:gem             success        0                      0.47s                
github                 github:java            success        0                      0.60s                
github                 github:npm             success        0                      0.52s                
github                 github:nuget           success        0                      0.45s                
github                 github:python          success        0                      0.50s                
nvdv2                  nvdv2:cves             success        0                      0.68s                
vulnerabilities        alpine:3.10            success        0                      0.56s                
vulnerabilities        alpine:3.11            success        0                      0.50s                
...

```

#### Disabling Specific Feed Groups

For a more granular approach, you can disable a single group within a feed.


### Using the CLI to Delete Feed Data


#### Deleting and Entire Feed

Deleting feed data

```
[anchore@93d6977e2061 anchore-engine]$ anchore-cli system feeds delete github

[anchore@93d6977e2061 anchore-engine]$ anchore-cli system feeds list
Feed                   Group                  LastSync                          RecordCount        
nvdv2                  nvdv2:cves             2020-03-28T00:03:34.079006        141090             
vulnerabilities        alpine:3.10            2020-03-28T00:03:32.065414        1725               
vulnerabilities        alpine:3.11            2020-03-28T00:03:32.685733        1904               
vulnerabilities        alpine:3.3             2020-03-28T00:02:03.906147        457                
vulnerabilities        alpine:3.4             2020-03-28T00:02:03.160375        681                
vulnerabilities        alpine:3.5             2020-03-28T00:02:04.693883        875                
vulnerabilities        alpine:3.6             2020-03-28T00:02:06.155002        1051               
vulnerabilities        alpine:3.7             2020-03-28T00:02:06.717063        1395               
vulnerabilities        alpine:3.8             2020-03-28T00:02:07.329353        1486               
vulnerabilities        alpine:3.9             2020-03-28T00:02:05.434095        1558               
vulnerabilities        amzn:2                 2020-03-28T00:02:08.671245        320                
vulnerabilities        centos:5               2020-03-28T00:02:09.375775        1347               
vulnerabilities        centos:6               2020-03-28T00:02:10.061647        1393               
vulnerabilities        centos:7               2020-03-28T00:02:10.656073        1004               
vulnerabilities        centos:8               2020-03-28T00:02:11.268366        199                
vulnerabilities        debian:10              2020-03-28T00:03:33.244902        22414              
vulnerabilities        debian:11              2020-03-28T00:02:11.914975        19450              
vulnerabilities        debian:7               2020-03-28T00:02:12.732607        20455              
vulnerabilities        debian:8               2020-03-28T00:02:13.759757        23488              
vulnerabilities        debian:9               2020-03-28T00:02:07.960085        22514              
vulnerabilities        debian:unstable        2020-03-28T00:02:14.585239        23708              
vulnerabilities        ol:5                   2020-03-28T00:02:15.882825        1245               
vulnerabilities        ol:6                   2020-03-28T00:02:15.368850        1504               
vulnerabilities        ol:7                   2020-03-28T00:02:17.334177        1121               
vulnerabilities        ol:8                   2020-03-28T00:02:18.057855        157                
vulnerabilities        rhel:5                 2020-03-28T00:02:18.748398        7237               
vulnerabilities        rhel:6                 2020-03-28T00:02:16.548115        6805               
vulnerabilities        rhel:7                 2020-03-28T00:03:20.039569        5846               
vulnerabilities        rhel:8                 2020-03-28T00:03:21.424688        1428               
vulnerabilities        ubuntu:12.04           2020-03-28T00:03:30.795672        14948              
vulnerabilities        ubuntu:12.10           2020-03-28T00:03:20.686089        5652               
vulnerabilities        ubuntu:13.04           2020-03-28T00:03:22.630122        4127               
vulnerabilities        ubuntu:14.04           2020-03-28T00:03:23.376621        21176              
vulnerabilities        ubuntu:14.10           2020-03-28T00:03:24.059663        4456               
vulnerabilities        ubuntu:15.04           2020-03-28T00:03:22.070692        5877               
vulnerabilities        ubuntu:15.10           2020-03-28T00:03:24.656382        6513               
vulnerabilities        ubuntu:16.04           2020-03-28T00:03:26.013850        18288              
vulnerabilities        ubuntu:16.10           2020-03-28T00:03:25.370678        8647               
vulnerabilities        ubuntu:17.04           2020-03-28T00:03:27.278963        9157               
vulnerabilities        ubuntu:17.10           2020-03-28T00:03:26.605719        7936               
vulnerabilities        ubuntu:18.04           2020-03-28T00:03:27.845497        12547              
vulnerabilities        ubuntu:18.10           2020-03-28T00:03:28.482261        8397               
vulnerabilities        ubuntu:19.04           2020-03-28T00:03:31.400152        8664               
vulnerabilities        ubuntu:19.10           2020-03-28T00:03:29.122119        7327               

[anchore@93d6977e2061 anchore-engine]$ anchore-cli system feeds sync

WARNING: This operation should not normally need to be performed except when the anchore-engine operator is certain that it is required - the operation will take a long time (hours) to complete, and there may be an impact on anchore-engine performance during the re-sync/flush.

Really perform a manual feed data sync/flush? (y/N)y
Feed                   Group                  Status         Records Updated        Sync Duration        
nvdv2                  nvdv2:cves             success        0                      0.81s                
vulnerabilities        alpine:3.10            success        0                      0.54s                
vulnerabilities        alpine:3.11            success        0                      0.60s                
vulnerabilities        alpine:3.3             success        0                      0.59s                
vulnerabilities        alpine:3.4             success        0                      0.75s                
vulnerabilities        alpine:3.5             success        0                      0.95s                
vulnerabilities        alpine:3.6             success        0                      0.57s                
vulnerabilities        alpine:3.7             success        0                      0.59s                
vulnerabilities        alpine:3.8             success        0                      0.51s                
vulnerabilities        alpine:3.9             success        0                      1.34s                
vulnerabilities        amzn:2                 success        0                      0.52s                
vulnerabilities        centos:5               success        0                      0.64s                
vulnerabilities        centos:6               success        0                      0.80s                
vulnerabilities        centos:7               success        0                      0.82s                
vulnerabilities        centos:8               success        0                      0.58s                
vulnerabilities        debian:10              success        0                      0.47s                
vulnerabilities        debian:11              success        0                      0.58s                
vulnerabilities        debian:7               success        0                      0.64s                
vulnerabilities        debian:8               success        0                      0.71s                
vulnerabilities        debian:9               success        0                      0.76s                
vulnerabilities        debian:unstable        success        0                      0.78s                
vulnerabilities        ol:5                   success        0                      0.65s                
vulnerabilities        ol:6                   success        0                      0.68s                
vulnerabilities        ol:7                   success        0                      0.69s                
vulnerabilities        ol:8                   success        0                      0.68s                
vulnerabilities        rhel:5                 success        0                      0.76s                
vulnerabilities        rhel:6                 success        0                      0.49s                
vulnerabilities        rhel:7                 success        0                      0.61s                
vulnerabilities        rhel:8                 success        0                      0.89s                
vulnerabilities        ubuntu:12.04           success        0                      0.76s                
vulnerabilities        ubuntu:12.10           success        0                      0.60s                
vulnerabilities        ubuntu:13.04           success        0                      0.65s                
vulnerabilities        ubuntu:14.04           success        0                      0.59s                
vulnerabilities        ubuntu:14.10           success        0                      1.01s                
vulnerabilities        ubuntu:15.04           success        0                      0.70s                
vulnerabilities        ubuntu:15.10           success        0                      0.60s                
vulnerabilities        ubuntu:16.04           success        0                      0.82s                
vulnerabilities        ubuntu:16.10           success        0                      0.57s                
vulnerabilities        ubuntu:17.04           success        0                      0.61s                
vulnerabilities        ubuntu:17.10           success        0                      0.51s                
vulnerabilities        ubuntu:18.04           success        0                      0.60s                
vulnerabilities        ubuntu:18.10           success        0                      0.60s                
vulnerabilities        ubuntu:19.04           success        0                      0.61s                
vulnerabilities        ubuntu:19.10           success        0                      0.60s                         
```


#### Deleting Specific Feed Groups

```
[anchore@93d6977e2061 ~]$ anchore-cli system feeds config --disable vulnerabilities --group centos:5
Group                     LastSync                          RecordCount        
centos:5(disabled)        2020-03-28T00:22:57.113534        1347               

[anchore@93d6977e2061 ~]$ anchore-cli system feeds delete vulnerabilities --group centos:5
Group                     LastSync        RecordCount        
centos:5(disabled)        pending         0         
```


#### Restoring Deleted Data

If you want to get data back, simply enable the feed and/or group and run a feed sync manually or wait for the next scheduled sync.


For an entire feed, here is an example of removal and re-adding it:
```
[anchore@93d6977e2061 ~]$ anchore-cli system feeds config github --disable
Feed                    Group                  LastSync                          RecordCount        
github(disabled)        github:composer        2020-03-28T01:08:58.652868        78                 
github(disabled)        github:gem             2020-03-28T01:08:59.179493        333                
github(disabled)        github:java            2020-03-28T01:08:59.699348        432                
github(disabled)        github:npm             2020-03-28T00:34:48.167115        653                
github(disabled)        github:nuget           2020-03-28T01:12:01.116613        50                 
github(disabled)        github:python          2020-03-28T01:08:58.083361        250                

[anchore@93d6977e2061 ~]$ anchore-cli system feeds delete github


[anchore@93d6977e2061 ~]$ anchore-cli system feeds config github --enable


[anchore@93d6977e2061 ~]$ anchore-cli system feeds sync

WARNING: This operation should not normally need to be performed except when the anchore-engine operator is certain that it is required - the operation will take a long time (hours) to complete, and there may be an impact on anchore-engine performance during the re-sync/flush.

Really perform a manual feed data sync/flush? (y/N)y
Feed                   Group                  Status         Records Updated        Sync Duration        
github                 github:composer        success        78                     1.64s                
github                 github:gem             success        333                    4.48s                
github                 github:java            success        432                    6.07s                
github                 github:npm             success        653                    7.39s                
github                 github:nuget           success        50                     1.10s                
github                 github:python          success        250                    3.34s                
nvdv2                  nvdv2:cves             success        0                      60.90s               
vulnerabilities        alpine:3.10            success        0                      0.52s                
vulnerabilities        alpine:3.11            success        0                      0.47s                
vulnerabilities        alpine:3.3             success        0                      0.56s                
vulnerabilities        alpine:3.4             success        0                      0.46s                
vulnerabilities        alpine:3.5             success        0                      0.52s                
vulnerabilities        alpine:3.6             success        0                      0.54s                
vulnerabilities        alpine:3.7             success        0                      60.76s               
vulnerabilities        alpine:3.8             success        0                      0.54s                
vulnerabilities        alpine:3.9             success        0                      0.54s                
vulnerabilities        amzn:2                 success        0                      0.49s                
vulnerabilities        centos:5               success        0                      0.47s                
vulnerabilities        centos:6               success        0                      0.49s                
vulnerabilities        centos:7               success        0                      0.48s                
vulnerabilities        centos:8               success        0                      0.53s                
vulnerabilities        debian:10              success        0                      0.62s                
vulnerabilities        debian:11              success        0                      0.50s
...        

```

For a single feed group, here is an example of removal and re-adding it:

```
[anchore@93d6977e2061 ~]$ anchore-cli system feeds config --enable vulnerabilities --group centos:5
Group           LastSync        RecordCount        
centos:5        pending         0                  

[anchore@93d6977e2061 ~]$ anchore-cli system feeds sync

WARNING: This operation should not normally need to be performed except when the anchore-engine operator is certain that it is required - the operation will take a long time (hours) to complete, and there may be an impact on anchore-engine performance during the re-sync/flush.

Really perform a manual feed data sync/flush? (y/N)y
Feed                   Group                  Status         Records Updated        Sync Duration        
...                
vulnerabilities        centos:5               success        1347                   27.41s               
... 

```

With these controls you can better customize the data set that anchore stores in the database. However, note that this should not normally be necessary
and modifying feed groups & data has implications on the sets of distros and types of artifacts Anchore can match vulnerabilities against.
