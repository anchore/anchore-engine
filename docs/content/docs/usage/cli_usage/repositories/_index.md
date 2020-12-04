---
title: "Scanning Repositories"
linkTitle: "Repositories"
weight: 6
---

Individual images can be added to the Anchore Engine engine using the `image add` command. This may be performed by a CI/CD plugin such as Jenkins or manually by a user with the CLI or API.


The Anchore Engine can also be configured to scan repositories and automatically add any tags found in the repository. Once added, the Anchore Engine will poll the registry to look for changes at a user configurable interval.
This interval is specified in the Anchore Engine configuration file: config.yaml within the services -> Catalog configuration stanza.

```
cycle_timers:
      image_watcher: 3600
      repo_watcher: 60
```

In this example the repo is polled for updates every minute (60 seconds).

## Adding Repositories

The `repo add` command instructs the Anchore Engine to add the specified repository watch list.

`$ anchore-cli repo add repo.example.com/apps`

By default the Anchore Engine will automatically add the discovered tags to the list of subscribed tags (see [Working with Subscriptions]({{< ref "/docs/usage/cli_usage/subscriptions" >}}) this behavior can be overridden by passing the `--noautosubscribe` option.

The Anchore Engine needs to find a single TAG in the repository before the repository can be added to the watch list. By default the Anchore Engine will look for a tag named latest this behavior can be overridden using the `--lookuptag` option.

In the following example the *apps* repo is known to contain a dev tag.

`$ anchore-cli repo add repo.example.com/apps --lookuptag dev`

## Listing Repositories

The `repo list` command will show the repositories monitored by the Anchore Engine.

```
$ anchore-cli repo list

Repository                   Watched        TagCount        
docker.io/anchore/test        True           15              
docker.io/anchore/prod        True           25    
```

## Deleting Repositories

The `del` option can be used to instruct the Anchore Engine to remove the repository from the watch list. Once the repository record has been deleted no further changes to the repository will be detected by the Anchore Engine.

**Note:** No existing image data will be removed from the Anchore Engine.

`$ anchore-cli repo del repo.example.com/myrepo`

## Unwatching Repositories

When a repository is added the Anchore Engine will monitor the repository for new and updated tags. This behavior can be disabled preventing the Anchore Engine from monitoring the repository for changes.

In this case the `repo list` command will show false in the Watched column for this registry.

`$ anchore-cli repo unwatch repo.example.com/myrepo`

## Watching Repositories

The repo watch command instructs the Anchore Engine to monitor a repository for new and updated tags. By default repositories added to the Anchore Engine are automatically watched. This option is only required if a repository has been manually unwatched.

`$ anchore-cli repo watch repo.example.com/myrepo`

## Removing a Repository and All Images

There may be a time when you wish to stop a repository analysis when the analysis is running (e.g., accidentally watching an image with a large number of tags).  There are several steps in the process which are outlined below.  We will use `docker.io/library/alpine` as an example.

**Note:** Be careful when deleting images. In this flow, Anchore deletes the image, not just the repository/tag combo.  Because of this, deletes may impact more than the expected repository since an image may have tags in multiple repositories or even registries.

### Check the State

Take a look at the repository list.

```
# anchore-cli repo list
Repository                      Watched        TagCount       
docker.io/library/alpine        True          29
```

Also look at the image list.

```
# anchore-cli image list | grep 'docker.io/library/alpine'
docker.io/library/alpine:20190228              sha256:1dd6a46eca0d7025920a8b3e3db7fdc33ad5c4e2e317c314e125d4141ce14a0f        not_analyzed         
docker.io/library/alpine:20190408              sha256:00c76f80fd9298c831c4c5e799df6d7164b2a2692b10318c00ab217b381ba659        not_analyzed         
docker.io/library/alpine:20190707              sha256:c04b643dedaccae53e036f2bf72b0e792870f51708aff6ceaa6895de60e46257        not_analyzed         
docker.io/library/alpine:3.1                    sha256:25fd8fc1aefcc8ae46aae23daefcd7dcb97f676fa0bc72bb0bf7cfb75df4f22e        not_analyzed         
docker.io/library/alpine:3.10.1                sha256:57334c50959f26ce1ee025d08f136c2292c128f84e7b229d1b0da5dac89e9866        not_analyzed         
docker.io/library/alpine:3.5                    sha256:f7d2b5725685826823bc6b154c0de02832e5e6daf7dc25a00ab00f1158fabfc8        not_analyzed         
docker.io/library/alpine:3.6.5                  sha256:36c3a913e62f77a82582eb7ce30d255f805c3d1e11d58e1f805e14d33c2bc5a5        not_analyzed         
...
...
```

### Removing the Repository from the Watched List

Unwatch `docker.io/library/alpine` to prevent future automatic updates.

```
# anchore-cli repo unwatch docker.io/library/alpine
Repository                      Watched        TagCount       
docker.io/library/alpine        False          29
```

### Delete the Repository

Delete the repository.  This may need to be done a couple times if the repository still shows in the repository list.

```
# anchore-cli repo del docker.io/library/alpine
Success
```

### Forcefully Delete the Images

Delete the analysis/images.  This may need to be done several times to remove all images depending on how many there are.

```
# for i in `anchore-cli image list | grep 'docker.io/library/alpine' | awk '{print $1}' | sort | uniq`
> do
> anchore-cli image del ${i} --force
> done
Success
Success
Success
...
...
```

### Verify the Repository and All Images are Deleted

Check the repository list.

```
# anchore-cli repo list
<no output>
```

Check the image list.

```
# anchore-cli image list | grep 'docker.io/library/alpine'
<no output>
```
