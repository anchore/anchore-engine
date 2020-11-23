---
title: "Evaluating Images Against Policies"
weight: 1
---

The `evaluate` command can be used to evaluate a given image for policy compliance.

The image to be evaluated can be in the following format:

- Image Digest
- Image ID
- registry/repo:tag

```
$ anchore-cli evaluate check debian:latest

Image Digest: sha256:427752aa7da803378f765f5a8efba421df5925cbde8ab011717f3642f406fb15
Full Tag: docker.io/debian:latest
Status: fail
Last Eval: 2017-09-02T15:19:55
Policy ID: 715a6056-87ab-49fb-abef-f4b4198c67bf
```

By default only the summary of the evaluation is shown. Passing the `--detail` parameter will show the policy checks that raised warnings or errors.

```
$ anchore-cli evaluate check debian:latest

Image Digest: sha256:427752aa7da803378f765f5a8efba421df5925cbde8ab011717f3642f406fb15
Full Tag: docker.io/debian:latest
Status: fail
Last Eval: 2017-09-02T15:19:55
Policy ID: 715a6056-87ab-49fb-abef-f4b4198c67bf

Gate                   Trigger              Detail                                                                                                                                         Status        
DOCKERFILECHECK        NOHEALTHCHECK        Dockerfile does not contain any HEALTHCHECK instructions   
ANCHORESEC             VULNHIGH             HIGH Vulnerability found in package - mount (CVE-2016-2779 - https://security-tracker.debian.org/tracker/CVE-2016-2779)                        stop          
ANCHORESEC             VULNHIGH             HIGH Vulnerability found in package - libuuid1 (CVE-2016-2779 - https://security-tracker.debian.org/tracker/CVE-2016-2779)                     stop        
```

In this example we specified library/repo:tag which could be ambiguous. At the time of writing the image Digest for `library/debian:latest` was `sha:256:427752aa.....` however previously different images may have been tagged as `library/debian:latest`. The `--show-history` parameter can be passed to show historic evaluations based on previous images or previous policy bundles.

Anchore supports whitelisting and blacklisting images by their name, ID or digest. A blacklist or whitelist takes precedence over any policy checks. For example if an image is explicitly listed as *blacklisted* then even if all the individual policy checks pass the image will still fail evaluation.

```
$ anchore-cli evaluate check library/alpine:latest --detail
Image Digest: sha256:8c03bb07a531c53ad7d0f6e7041b64d81f99c6e493cb39abba56d956b40eacbc
Full Tag: docker.io/library/alpine:latest
Image ID: 3fd9065eaf02feaf94d68376da52541925650b81698c53c6824d92ff63f98353
Status: fail
Last Eval: 2018-04-29T13:50:32
Policy ID: 2c53a13c-1765-11e8-82ef-23527761d060
Final Action: stop
Final Action Reason: blacklisted

Gate              Trigger            Detail                                                                                     Status        
dockerfile        instruction        Dockerfile directive 'HEALTHCHECK' not found, matching condition 'not_exists' check        warn         
```

 In this example even though the image only had one policy check that raised a warning the image fails policy evaluation since it is present on a blacklist.

### Evaluating status based on Digest or ID

Performing an evaluation on an image specified by name is not recommended since an image name is ambiguous. For example the tag `docker.io/library/centos:latest` refers to whatever image has the tag `library/centos:latest` at the time of evaluation. At any point in time another image may be tagged as `library/centos:latest`.

It is recommended that images are referenced by their Digest. For example at the time of writing the digest of the 'current' library/centos:latest image is `sha256:191c883e479a7da2362b2d54c0840b2e8981e5ab62e11ab925abf8808d3d5d44`

If the image to be evaluated is specified by Image ID or Image Digest then the `--tag` parameter must be added. Policies are mapped to images based on registry/repo:tag so since an Image ID may may to multiple different names we must specify the name user in the evaluation.

For example - referencing by Image Digest: 

`$ anchore-cli evaluate check docker.io/library/centos@sha256:191c883e479a7da2362b2d54c0840b2e8981e5ab62e11ab925abf8808d3d5d44 --tag=latest`

For example - referencing by image ID:

`$ anchore-cli evaluate check e934aafc22064b7322c0250f1e32e5ce93b2d19b356f4537f5864bd102e8531f --tag=docker.io/library/centos:latest`



