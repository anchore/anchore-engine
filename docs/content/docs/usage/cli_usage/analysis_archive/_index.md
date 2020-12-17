---
title: "Using the Analysis Archive"
linkTitle: "Analysis Archive"
weight: 1
---

As mentioned in [concepts]({{< ref "/docs/general/concepts/analysis_archive" >}}), there are two locations for image analysis to be stored:
* The working set: the standard state after analysis completes. In this location, the image is fully loaded and available for policy evaluation, content, and vulnerability queries.
* The archive set: a location to keep image analysis data that cannot be used for policy evaluation or queries but can use cheaper storage and less db space and can be reloaded into the working set as needed.

## Working with the Analysis Archive

List archived images:

```
root@37a8b1e75d0a:~# anchore-cli analysis-archive images list
Digest                                                                         Tags                           Analyzed At                 Archived At                 Status          Archive Size Bytes        
sha256:5c40b3c27b9f13c873fefb2139765c56ce97fd50230f1f2d5c91e55dec171907        docker.io/alpine:latest        2019-04-16T22:56:14Z        2019-04-19T18:17:05Z        archived        84785                     
```

To add an image to the archive, use the digest. All analysis, policy evaluations, and tags will be added to the archive.
NOTE: this does *not* remove it from the working set. To fully move it you must first archive and then delete image in the working set using the cli/api.


### Archiving Images

Archiving an image analysis creates a snapshot of the image's analysis data, policy evaluation history, and tags and stores in a different storage location and
different record location than working set images.

```
root@37a8b1e75d0a:~# anchore-cli image list
Full Tag                       Image Digest                                                                   Analysis Status        
docker.io/alpine:3.4           sha256:0325f4ff0aa8c89a27d1dbe10b29a71a8d4c1a42719a4170e0552a312e22fe88        analyzed               
docker.io/alpine:3.5           sha256:f7d2b5725685826823bc6b154c0de02832e5e6daf7dc25a00ab00f1158fabfc8        analyzed               
docker.io/alpine:3.7           sha256:92251458088c638061cda8fd8b403b76d661a4dc6b7ee71b6affcf1872557b2b        analyzed               
docker.io/alpine:3.8           sha256:899a03e9816e5283edba63d71ea528cd83576b28a7586cf617ce78af5526f209        analyzed               
docker.io/alpine:latest        sha256:5c40b3c27b9f13c873fefb2139765c56ce97fd50230f1f2d5c91e55dec171907        analyzed               

root@37a8b1e75d0a:~# anchore-cli analysis-archive images add sha256:92251458088c638061cda8fd8b403b76d661a4dc6b7ee71b6affcf1872557b2b
Image Digest                                                                   Archive Status        Details                       
sha256:92251458088c638061cda8fd8b403b76d661a4dc6b7ee71b6affcf1872557b2b        archived              Completed successfully        

```

Then to delete it in the working set (optionally):

_NOTE: You may need to use --force if the image is the newest of its tags and has active subscriptions__

`root@37a8b1e75d0a:~# anchore-cli image del sha256:92251458088c638061cda8fd8b403b76d661a4dc6b7ee71b6affcf1872557b2b`

At this point the image in the archive only.


### Restoring images from the archive into the working set

This will not delete the archive entry, only add it back to the working set. Restore and image to working set from archive:

```
root@37a8b1e75d0a:~# anchore-cli analysis-archive images restore sha256:92251458088c638061cda8fd8b403b76d661a4dc6b7ee71b6affcf1872557b2b 
Image Digest: sha256:92251458088c638061cda8fd8b403b76d661a4dc6b7ee71b6affcf1872557b2b
Parent Digest: sha256:fea30b82fd63049b797ab37f13bf9772b59c15a36b1eec6b031b6e483fd7f252
Analysis Status: analyzed
Image Type: docker
Image ID: 6d1ef012b5674ad8a127ecfa9b5e6f5178d171b90ee462846974177fd9bdd39f
Dockerfile Mode: Guessed
Distro: alpine
Distro Version: 3.7.3
Size: 4464640
Architecture: amd64
Layer Count: 1

Full Tag: docker.io/alpine:3.7
```

To view the restored image:
```
root@37a8b1e75d0a:~# anchore-cli image get sha256:92251458088c638061cda8fd8b403b76d661a4dc6b7ee71b6affcf1872557b2b
Image Digest: sha256:92251458088c638061cda8fd8b403b76d661a4dc6b7ee71b6affcf1872557b2b
Parent Digest: sha256:fea30b82fd63049b797ab37f13bf9772b59c15a36b1eec6b031b6e483fd7f252
Analysis Status: analyzed
Image Type: docker
Image ID: 6d1ef012b5674ad8a127ecfa9b5e6f5178d171b90ee462846974177fd9bdd39f
Dockerfile Mode: Guessed
Distro: alpine
Distro Version: 3.7.3
Size: 4464640
Architecture: amd64
Layer Count: 1

Full Tag: docker.io/alpine:3.7
```


## Working with Archive rules
As with all CLI commands, the `--help` option will show the arguments, options and descriptions of valid values.

List existing rules:

```
anchore-cli analysis-archive rules list
Rule Id                                 Global        Analysis Age (Days)        Tag Versions Newer        Registry        Repository        Tag        Last Updated                
134d7f8b36e44c1893d98bc9ee50d9c6        False         1                          0                         *               *                 *          2019-04-30T22:40:30Z     
```

Add a rule:

```
root@37a8b1e75d0a:~# anchore-cli analysis-archive rules add 90 1 archive --registry-selector docker.io --repository-selector "library/*" --tag-selector latest
Rule Id                                 Global        Analysis Age (Days)        Tag Versions Newer        Registry         Repository        Tag           Last Updated                
4ce89022ceea48f697410cb651c090bd        False         90                         1                         docker.io        library/*         latest        2019-04-30T23:35:57Z
```


The required parameters are: minimum age of analysis in days, number of tag versions newer, and the transition to use.

There is also an optional `--is-global` flag available for admin account users that makes the rule apply to all accounts
in the system.

As a non-admin user you can see global rules but you cannot update/delete them (will get a 404):

```
:~# anchore-cli --u test1 --p password analysis-archive rules list
Rule Id                                 Global        Analysis Age (Days)        Tag Versions Newer        Registry         Repository        Tag           Last Updated                
01a97699ed4b40cdb256e58a03d9cef2        True          90                         1                         docker.io        library/*         latest        2019-04-30T23:39:33Z        

root@37a8b1e75d0a:~# anchore-cli --u test1 --p password analysis-archive rules del 01a97699ed4b40cdb256e58a03d9cef2
Error: Rule not found
HTTP Code: 404
Detail: {'error_codes': []}

root@37a8b1e75d0a:~# anchore-cli --u test1 --p password analysis-archive rules get 01a97699ed4b40cdb256e58a03d9cef2
Rule Id                                 Global        Analysis Age (Days)        Tag Versions Newer        Registry         Repository        Tag           Last Updated                
01a97699ed4b40cdb256e58a03d9cef2        True          90                         1                         docker.io        library/*         latest        2019-04-30T23:39:33Z        
```


Delete a rule:

```
root@37a8b1e75d0a:~# anchore-cli analysis-archive rules del 134d7f8b36e44c1893d98bc9ee50d9c6
Success
```

