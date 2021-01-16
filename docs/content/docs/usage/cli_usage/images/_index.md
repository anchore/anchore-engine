---
title: "Analyzing Images"
linkTitle: "Images"
weight: 1
---

### Adding An Image

The `image add` command instructs the Anchore Engine to pull (download) and analyze an image from a registry.

`anchore-cli image add docker.io/library/nginx:latest`

The Anchore Engine will attempt to retrieve metadata about the image from the Docker registry and if successful will initiate a pull of the image and queue the image for analysis. The command will output details about the image including the image digest, image ID, and full name of the image.

```
Image Digest: sha256:2b0e9b0e40202e2a6a0619f327c9acb9d0adc39d7dc292fefc1a886fc8cefee3
Parent Digest: sha256:811483efcd38de17d93193b4b4bc4ba290a931215c4c8512cbff624e5967a7dd
Analysis Status: not_analyzed
Image Type: docker
Image ID: 2dd01afbe8df1fe326f6609c56b08beefc6bf254d28993263da188b8fbf1254d
Dockerfile Mode: None
Distro: None
Distro Version: None
Size: None
Architecture: None
Layer Count: None

Full Tag: docker.io/mysql:latest
```

For an image that has not yet been analyzed, the status will appear as *not_analyzed*. Once the image has been downloaded it will be queued for analysis. When the analysis begins the status will be updated to *analyzing*, after which te status will update to *analyzed*.

The image type is shown as `docker`, future release will support the analysis of OCI formatted images.

As of v0.9.1, Anchore Engine can be configured to have a size limit for images being added for analysis. This is disabled by default, but can be configure through the configuration variable `max_compressed_image_size_mb`, which if using the default configuration file can be set through `ANCHORE_MAX_COMPRESSED_IMAGE_SIZE_MB` env variable. This defines a size limit (MB) of the compressed size of the image and will prevent the image from being added for analysis in anchore if the image exceeds the given size. A value less than 0 disables this functionality and allows an image of any size to be added. Note that this size limit is also applied to [tag subscriptions]({{< ref "/docs/usage/cli_usage/subscriptions/_index.md#tag-updates" >}}) and [repository watchers]({{< ref "/docs/usage/cli_usage/repositories/_index.md#watching-repositories" >}}).

### Adding Images That You Own

For images that you are building yourself, the Dockerfile used to build the image should always be passsed to the Anchore Engine at the time of image addition. This is achieved by adding the image as above, but with the additional option to pass the Dockerfile contents to be stored with the engine alongside the image analysis data.

`anchore-cli image add myrepo.example.com:5000/app/webapp:latest --dockerfile=/path/to/Dockerfile`

To update an image's Dockerfile, simply run the same command again with the path to the updated Dockerfile. Note that running `add` without `--force` (see below) will not re-add an image if it already exists.

### Additional Options

When adding an image, there are some additional (optional) parameters that can be used. We show some examples below.
`anchore-cli image add alpine:latest --force`

the `--force` option can be used to reset the image analysis status of any image to *not_analyzed*, which is the base analysis state for an image. This option should be be necessary to use in normal circumstancesm but can be useful if image re-analysis is needed for any reason desired.

`anchore-cli image add myrepo.example.com:5000/app/webapp:latest --dockerfile /path/to/dockerfile --annotation owner=someperson --annotation owneremail=someperson@somewhere.com`

the `--annotation` parameter can be used to specify 'key=value' pairs to associate with the image at the time of image addition. These annotations will then be carried along with the tag, and will appear in image records when fetched, and in webhook notification payloads that contain image information when they are sent from the engine. To change an annotation, simply run the add command again with the updated annotation and the old annotation will be overriden.

`anchore-cli image add alpine:latest --noautosubscribe`

the '--noautosubscribe' flag can be used if you do not wish for the engine to automatically subscribe the input tag to the 'tag_update' subscription, which controls whether or not the engine will automatically watch the added tag for image content updates and pull in the latest content for analysis.  See Subscriptions for more information about using subscriptions and notifications in Anchore.

### Image Tags

In the previous example we added `docker.io/mysql:latest`, if we attempted to add a tag that mapped to the same image, for example `docker.io/mysql:5` the Anchore Engine will detect the duplicate image identifiers and return a detail of all tags matching that image.

```
Image Digest: sha256:2b0e9b0e40202e2a6a0619f327c9acb9d0adc39d7dc292fefc1a886fc8cefee3
Parent Digest: sha256:811483efcd38de17d93193b4b4bc4ba290a931215c4c8512cbff624e5967a7dd
Analysis Status: analyzed
Image Type: docker
Image ID: 2dd01afbe8df1fe326f6609c56b08beefc6bf254d28993263da188b8fbf1254d
Dockerfile Mode: Guessed
Distro: debian
Distro Version: 9
Size: 138302512
Architecture: amd64
Layer Count: 12

Full Tag: docker.io/mysql:latest
Full Tag: docker.io/mysql:5
```

### Deleting An Image

The `image del` command instructs the Anchore Engine to delete the image from the repository.

#### Get The Image Digest

To delete the image, first get the image digest from `anchore-cli image list`.

```
anchore-cli image list                                                             
Full Tag                    Image Digest                                                                Analysis Status        
docker.io/alpine:latest     sha256:acd3ca9941a85e8ed16515bfc5328e4e2f8c128caa72959a58a127b7801ee01f     analyzed        
```

#### Deactivate Image Subscriptions

Check if the image has any active subscriptions.

```
anchore-cli subscription list                                                   
Tag                         Subscription Type        Active        
docker.io/alpine:latest     analysis_update          True          
docker.io/alpine:latest     policy_eval              False         
docker.io/alpine:latest     tag_update               True          
docker.io/alpine:latest     vuln_update              False
```
If it the image has an active subscription(s), deactivate the subscription(s).

```
anchore-cli subscription deactivate analysis_update docker.io/alpine:latest
Success

anchore-cli subscription deactivate tag_update docker.io/alpine:latest
Success
```

#### Delete The Image

Once no subscriptions are active and the image digest has been obtained, delete the image.

```
anchore-cli image del sha256:acd3ca9941a85e8ed16515bfc5328e4e2f8c128caa72959a58a127b7801ee01f
Success
```

### Advanced

Anchore engine also allows adding images directly by digest / tag / timestamp tuple, which can be useful to add images that are still available in a registry but not associated with a current tag any longer.  This functionality is available via the anchore engine API directly for advanced use cases, by constructing a message body that has 'digest', 'tag' and 'created_at' fields populated - see the API for more details.
