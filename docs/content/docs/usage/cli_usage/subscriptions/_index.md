---
title: "Working with Subscriptions"
linkTitle: "Subscriptions"
weight: 4
---

## Working with Subscriptions

The Anchore Engine supports 4 types of subscriptions: Image Updates, Policy Updates, CVE Updates and Analysis Updates.

Notifications will be sent over a webhook to an endpoint specified in the Anchore Engine configuration file.

**Note:** A fifth notification type, repo_update, is not used for notifications but is instead used as a mechanism for tracking repository updates. Please see the repository scanning documentation for details.

### Tag Updates

This class of notification is triggered if a new image is tagged with the tag to which you have subscribed.

For example, if you had a subscription to the docker.io/library/node:latest tag and a new image was built, tagged as library/note:latest and pushed to the registry.

This subscription is activated automatically when a new tag is added to the Anchore Engine.

**Note:** If this subscription is disabled the Anchore Engine will not monitor the registry for new images.

### Policy Updates

This class of notification is triggered if a Tag to which a user has subscribed has a change in its policy evaluation status. The policy evaluation status of an image can be one of two states: *Pass* or *Fail*. If an image that was previously marked as Pass changes status to Fail or vice-versa then the policy update notification will be triggered.

The policy status of a Tag may be changed by a number of methods.

- Change to policy If an policy was changed, for example adding, editing or removing a policy check, then the policy status of an image may be effected. For example adding policy rule that blacklists a specific package that is present in a given Tag may cause the Tag’s policy status to move to Fail.

- Changes to whitelist If a whitelist is changed to add or remove a CVE then this may cause a policy status change. For example if an image contains a package that is vulnerable to Crticial Severity CVE-2017-9999 then this image may fail in it’s policy evaluation. If CVE-2017-9999 is added to a CVE Whitelist that is mapped to the subscribed Tag then the policy status may change from Fail to Pass.

- Change in Policy / Whitelist Mapping If the policy mapping is changed then a new policy or whitelist may be applied to an image which may change the status of the image. For example changing the mapping to add a more restrictive policy may change an Tag’s status from Pass to Fail.

- Change in Package or Vulnerability Data Some policy checks make use of data from external feeds. For example vulnerability checks use CVE data feeds. Changes in data within these feed may change the policy status, such as adding a new CVE vulnerability.

### Vulnerability / CVE Update

This class of notification is triggered if the list of CVEs or other security vulnerabilities in the image changes.

For example, a user was subscribed to the library/nginx:latest tag. On the 12th of September 2017 a new vulnerability was added to the Debian 9 vulnerability feed which matched a package in the library/nginx:latest image, triggering the email notification.

Based on the changes made by the upstream providers of CVE data (operating system vendors and NIST) CVEs may be added, removed or modified – for example a CVE initially marked as severity level Unknown may be upgraded to a higher severity level.

**Note:** A change to the CVE list in a Tag may not trigger a policy status change based on the policy rules configured for an image. In the example below the CVE had a unknown severity level which may not be tested by the policy mapped to this image.

### Analysis Update

This class of notification is triggered when an image has been analyzed. Typically this is triggered when a new TAG has been added to the system.
A common use case for this trigger is to alert an external system that a new TAG was added and has been successfully analyzed.

### Managing Subscriptions

Subscriptions are managed through the REST API or through the anchore-cli. The current subscription types are:

- tag_update : Tag update
- policy_eval : Policy status update
- vuln_update : CVE / Vulnerability updated (added/removed/changed)
- analysis_update: New Tag analyzed


**Note:** A fifth notification type, repo_update, is not used for notifications but is instead used as a mechanism for tracking repository updates. Please see the repository scanning documentation for details.

### Listing Subscriptions

Running the `subscription list` command will output a table showing the status of each Tag's subscriptions.

```
anchore-cli subscription list

Tag                                                            Subscription Type        Active        
docker.io/library/alpine:latest                                analysis_update          True          
docker.io/library/alpine:latest                                policy_eval              False         
docker.io/library/alpine:latest                                tag_update               True          
docker.io/library/alpine:latest                                vuln_update              False         
docker.io/library/centos:latest                                analysis_update          True          
docker.io/library/centos:latest                                policy_eval              False         
docker.io/library/centos:latest                                tag_update               True          
docker.io/library/centos:latest                                vuln_update              False  
```

**Note:** Subscriptions are tied to *registry/repo:tag* and not to image IDs.

### Activating Subscriptions

The `subscription activate` command is used to enable a subscription type for a given image. The command takes the following form:

`anchore-cli subscription activate SUBSCRIPTION_TYPE SUBSCRIPTION_KEY`

SUBSCRIPTION_TYPE should be either: 

- tag_update
- vuln_update
- policy_eval
- analysis_update

SUBSCRIPTION_KEY should be the name of the subscribed tag. eg. `docker.io/ubuntu:latest`

### Webhook Configuration

Webhooks are configured in the Anchore Engine configuration file `config.yaml` In the sample configuration file webhooks are disabled (commented) out.

```
webhooks:
  webhook_user: 'user'
  webhook_pass: 'pass'
  ssl_verify: False
```

The webhooks can, optionally, pass basic credentials to the webhook endpoint, if these are not required the the `webhook_user` and `webhool_pass` entries can be commented out. By default TLS/SSL connections will validate the certificate provided. This can be suppressed by uncommenting the `ssl_verify` option.

``` general:
    url: 'http://localhost:9090/general/<notification_type>/<userId>'
```

If configured, the general webook will receive all notifications (policy_eval, tag_update, vuln_update) for each user.In this case *<notification_type>* will be replaced by the appropriate type. will be replaced by the configured user which is, by default, admin. eg. http://localhost:9090/general/vuln_update/admin'

```
policy_eval:
    url: 'http://localhost:9090/somepath/<userId>'
    webhook_user: 'mehuser'
    webhook_pass: 'mehpass'
```

Specific endpoints for each event type can be configured, for example an endpoint for policy_eval notifications. In these cases the url, username, password and SSL/TLS verification can be specified.

```
error_event:
    url: 'http://localhost:9090/error_event/'
```

This webook, if configured, will send a webhook if any FATAL system events are logged.




