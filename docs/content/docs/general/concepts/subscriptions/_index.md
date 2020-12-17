---
title: "Subscriptions"
linkTitle: "Subscriptions"
weight: 4
---

The Anchore Engine can be configured to emit webhooks corresponding to changes in images and tags.

- New TAG analyzed
    - This class of notification is triggered when a new TAG had be analyzed.
A new tag can be explicitly added to the system, for example adding myrepo.example.com/prodapp/web:latest
In this case once the corresponding image has been downloaded and analyzed the notification will triggered.
If the Anchore Engine has been configured to watch a repository then it will implicitly add new tags that are found.

- Image updated
    - This class of notification is triggered if a new image is tagged with the tag to which you have subscribed. For example a new image is tagged as prod/myapp:latest 

Anchore will monitor repositories for changes to images and tags and if a user is subscribed to a Tag that has been updated then a notification is triggered.

- Vulnerability updates
    - This class of notification is triggered if the list of CVEs or other security vulnerabilities in the image changes. These updates are based on the changes in data from the upstream providers of CVE data (operating system vendors and NIST) CVEs may be added, removed or modified – for example a CVE initially marked as severity level Unknown may be upgraded to a higher severity level.

*Note:* A change to the CVE list in a Tag may not trigger a policy status change based on the policy rules configured for an image.
For example adding a new low severity level CVE to an image is unlikely to change the image policy evaluation to fail. 

- Change in policy status
    - This class of notification is triggered if a Tag to which a user has subscribed has a change in its policy evaluation status. The policy evaluation status of an image can be one of two states: Pass or Fail. If an image that was previously marked as Pass changes status to Fail or vice-versa then the policy update notification will be triggered. The policy status of a Tag may be changed by a number of methods.
        - **Change to policy**
            If an policy was changed, for example adding, editing or removing a policy check, then the policy status of an image may be effected. For example adding policy rule that blacklists a specific package that is present in a given Tag may cause the Tag’s policy status to move to Fail.
        - **Changes to whitelist**
            If a whitelist is changed to add or remove a CVE then this may cause a policy status change. For example if an image contains a package that is vulnerable to Crticial Severity CVE-2017-9999 then this image may fail in it’s policy evaluation. If CVE-2017-9999 is added to a CVE Whitelist that is mapped to the subscribed Tag then the policy status may change from Fail to Pass.
        - **Change in Policy/Whitelist Mapping**
            Within the Policy Editor mappings are maintained that define what Policy and Whitelist are applied to a given Tag. If the policy mapping is changed then a new policy or whitelist may be applied to an image which may change the status of the image. For example changing the mapping to add a more restrictive policy may change an Tag’s status from Pass to Fail.
        - **Change in Package or Vulnerability Data**
            Some policy checks make use of data from external feeds. For example vulnerability checks use CVE data feeds. Changes in data within these feed may change the policy status, such as adding a new CVE vulnerability.

