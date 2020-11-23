---
title: "Event Log"
linkTitle: "Events"
weight: 7
---

The event log subsystem is a new feature made available in the release 0.2.3 of anchore-engine. It provides the users with a mechanism to inspect asynchronous events occurring across various anchore-engine services. Anchore events include periodically triggered activities such as vulnerability data feed syncs in the policy-engine service, image analysis failures originating from the analyzer service, and other informational or system fault events. The catalog service may also generate events for any repositories or image tags that are being watched, when the engine encounters connectivity, authentication, authorization or other errors in the process of checking for updates. The event log is aimed at troubleshooting most common failure scenarios (especially those that happen during asynchronous engine operations) and to pinpoint the reasons for failures, that can be used subsequently to help with corrective actions. Events can be cleared from anchore-engine in bulk or individually.

The Anchore events (drawn from the event log) can be accessed through the Anchore Engine API and anchore-cli, or can be emitted as webhooks if your engine is configured to send webhook notifications. For API usage refer to the document on using the Anchore Engine API.

### Accessing Events

The anchore-cli command can be used to list events and filter through the results, get the details for a specific event and delete events matching certain criteria. 

```
anchore-cli event --help

Usage: anchore-cli event [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.

Commands:
  delete  Delete one or more events
  get     Get an event
  list    List events
```

For a list of the most recent events:

```anchore-cli event list

Timestamp                          Level        Service        Host                          Event                 ID

2018-06-28T22:36:37.250529Z        INFO         policy_engine        dockerhostid-localhost        feed_sync_complete        9b0078d22cca4a2fa677cdc0d632435a

2018-06-28T22:36:26.512589Z        ERROR        catalog              dockerhostid-localhost        list_tags_fail            67946415c113488b8fff8b335272a45b

2018-06-28T22:36:08.740953Z        INFO         policy_engine        dockerhostid-localhost        feed_sync_start           3b75967268824f4ca12c57d76c97d32c

...
```

**Note:** Events are ordered by the timestamp of their occurrence, the most recent events are at the top of the list and the least recent events at the bottom. 

For troubleshooting events related to a specific tag:

```
anchore-cli event list "docker.io/wazowskis/sixwheeldrive"

Timestamp                          Level        Service        Host                          Event                 ID

2018-06-30T03:56:27.711071Z        ERROR        catalog        dockerhostid-localhost        list_tags_fail        d77736ac78a043a9b84b3a1b8171aa44
```

To filter events by level such as ERROR or INFO:

```
anchore-cli event list --level ERROR

Timestamp                          Level        Service        Host                          Event                 ID

2018-06-28T22:36:26.512589Z        ERROR        catalog        dockerhostid-localhost        list_tags_fail        67946415c113488b8fff8b335272a45b
```

**Note:** Event listing response is paginated, anchore-cli displays the first 100 events matching the filters. For all the results use the --all flag.

All available options for listing events:

```
anchore-cli event list --help

Usage: anchore-cli event list [OPTIONS] [RESOURCE]
  RESOURCE: Value can be a tag, image digest or repository name. Displays
  results related to the specific resource

Options:
  --since TEXT    ISO8601 formatted UTC timestamp to filter events that occurred after the timestamp
  --before TEXT   ISO8601 formatted UTC timestamp to filter events that occurred before the timestamp
  --level TEXT      Filter results based on the level, supported levels are info and error
  --service TEXT  Filter events based on the originating service
  --host TEXT      Filter events based on the originating host
  --all                   Display all results. If not specified only the first 100 events are displayed
  --help               Show this message and exit
```
Event listing displays a brief summary of the event, to get more detailed information about the event such as the host where the event has occurred or the underlying the error:

```
anchore-cli event get d77736ac78a043a9b84b3a1b8171aa44

details:
  SkopeoError:
    cmd: /bin/sh -c skopeo inspect --tls-verify=true --creds "${SKOPUSER}":"${SKOPPASS}"
      docker://index.docker.io/wazowskis/sixwheeldrive:latest
    exitcode: 1
    msg: Error encountered in skopeo operation
    stderr: 'time="2018-06-30T03:56:27Z" level=fatal msg="Error reading manifest latest
      in docker.io/wazowskis/sixwheeldrive: errors: denied: requested access to the
      resource is denied unauthorized: authentication required "'
    stdout: null
level: ERROR
message: Failed to list tags in repository
resource:
  id: docker.io/wazowskis/sixwheeldrive
  type: repository
  user_id: admin
source:
  base_url: http://localhost:8082
  hostid: dockerhostid-localhost
  servicename: catalog
timestamp: '2018-06-30T03:56:27.711071Z'
type: list_tags_fail
```

### Clearing Events

Events can be cleared/deleted from the system in bulk or individually. Bulk deletion allows for specifying filters to clear the events within a certain time window.  To delete all events from the system:

```
anchore-cli event delete 

Really delete (clear) all events? (y/N)
```

Delete events before a specified timestamp (can also use `--since` instead of `--before` to delete events that were generated after a specified timestamp):

```
anchore-cli event delete --before 2018-06-30T03:56:27.711071Z

Deleted 27 events
```

Delete a specific event:

`anchore-cli event delete d77736ac78a043a9b84b3a1b8171aa44`

### Sending Events as Webhook Notifications

In addition to access via API and anchore-cli, the anchore engine may be configured to send notifications for events as they are generated in the system via its webhook subsystem. Webhook notifications for event log records is turned off by default. To turn enable the 'event_update' webhook, uncomment the 'event_log' section under 'services->catalog' in config.yaml, as in the following example:

```
services:
  ...
  catalog:
    ...
    event_log:
      notification:    
        enabled: True
        # (optional) notify events that match these levels. If this section is commented, notifications for all events are sent
        level:
        - error
```

**Note:** In order for events to be sent via webhook notifications, you'll need to ensure that the webhook subsystem is configured in config.yaml (if it isn't already) - refer to the document on subscriptions and notifications for information on how to enable webhooks in anchore engine. Event notifications will be sent to 'event_update' webhook endpoint if it is defined, and the 'general' webhook endpoint otherwise.

