---
title: "Policy Bundles"
weight: 1
---

Policy bundles are the unit of policy definition and evaluation in Anchore Engine. A user may have multiple bundles, but for a policy evaluation, the user must specify a bundle to be evaluated or default to the bundle currently marked 'active'. See Working with Policies for more detail on manipulating and configuring policies using the Engine CLI.

### Components of a Policy Bundle

A policy bundle is a single JSON document, composed of several parts:

- [Policies]({{< ref "/docs/engine/general/concepts/policy/policies" >}}) -  The named sets of rules and actions
- [Whitelists]({{< ref "/docs/engine/general/concepts/policy/whitelists" >}}) - Named sets of rule exclusions to override a match in a policy rule
- [Mappings]({{< ref "/docs/engine/general/concepts/policy/policy_mappings" >}}) - Ordered rules that determine which policies and whitelists should be applied to a specific image at evaluation time.
- Whitelisted Images - Overrides for specific images to statically set the final result to a pass regardless of the policy evaluation result.
- Blacklisted Images - Overrides for specific images to statically set the final result to a fail regardless of the policy evaluation result.

Example JSON for an empty bundle, showing the sections and top-level elements:

```
{
  "id": "default0,
  "version": "1_0",
  "name": "My Default bundle",
  "comment": "My system's default bundle",
  "whitelisted_images": [],
  "blacklisted_images": [],
  "mappings": [],
  "whitelists": [],
  "policies": []
}
```

### Policies

A bundle contains zero or more policies. The policies of a bundle define the checks to make against an image and the actions to recommend if the checks find a match.

Example of a single policy JSON object, one entry in the policies array of the larger policy bundle document:

```JSON
{
  "name": "DefaultPolicy",
  "version": "1_0",
  "comment": "Policy for basic checks",
  "id": "ba6daa06-da3b-46d3-9e22-f01f07b0489a",
  "rules": [
    {
      "action": "STOP",
      "gate": "vulnerabilities",
      "id": "80569900-d6b3-4391-b2a0-bf34cf6d813d",
      "params": [
        { "name": "package_type", "value": "all" },
        { "name": "severity_comparison", "value": ">=" },
        { "name": "severity", "value": "medium" }
      ],
      "trigger": "package"
    }
  ]
}
```

The above example defines a stop action to be produced for all package vulnerabilities found in an image that are severity medium or higher.

For information on how policies work and are evaluated, see: [Policies]({{< ref "/docs/engine/general/concepts/policy/policies" >}})

### Whitelists

A whitelist is a set of exclusion rules for trigger matches found during policy evaluation. A whitelist defines a specific gate and trigger_id (part of the output of a policy rule evaluation) that should have it's action recommendation statically set to go. When a policy rule result is whitelisted, it is still present in the output of the policy evaluation, but it's action is set to go and it is indicated that there was a whitelist match.

Whitelists are useful for things like:

- Ignoring CVE matches that are known to be false-positives
- Ignoring CVE matches on specific packages (perhaps if they are known to be custom patched)

Example of a simple whitelist as a JSON object from a bundle:

```JSON
{
  "id": "whitelist1",
  "name": "Simple Whitelist",
  "version": "1_0",
  "items": [
    { "id": "item1", "gate": "vulnerabilities", "trigger": "package", "trigger_id": "CVE-10000+libssl" },
    { "id": "item2", "gate": "vulnerabilities", "trigger": "package", "trigger_id": "CVE-10001+*" }
  ]
}
```

For more information, see: [Whitelists]({{< ref "/docs/engine/general/concepts/policy/whitelists" >}})

### Mappings

Mappings are named rules that define which policies and whitelists to evaluate for a given image. The list of mappings is evaluated in order, so the ordering of the list matters because the first rule that matches an input image will be used and all others ignored.

Example of a simple mapping rule set:

```JSON
[
  {
    "name": "DockerHub",
    "registry": "docker.io",
    "repository": "library/postgres",
    "image": { "type": "tag", "value": "latest" },
    "policy_ids": [ "policy1", "policy2" ],
    "whitelist_ids": [ "whitelist1", "whitelist2" ]
  },
  {
    "name": "default", 
    "registry": "*",
    "repository": "*",
    "image": { "type": "tag", "value": "*" },
    "policy_ids": [ "policy1" ],
    "whitelist_ids": [ "whitelist1" ]
  }
]
```

For more information about mappings see: [Mappings]({{< ref "/docs/engine/general/concepts/policy/policy_mappings" >}})

### Whitelisted Images

Whitelisted images are images, defined by registry, repository, and tag/digest/imageId, that will always result in a pass status for bundle evaluation unless the image is also matched in the blacklisted images section.

Example image whitelist section:

```JSON
{
  "name": "WhitelistDebianStable",
  "registry": "docker.io",
  "repository": "library/debian",
  "image": { "type": "tag", "value": "stable" }
}
```

### Blacklisted Images

Blacklisted images are images, defined by registry, repository, and tag/digest/imageId, that will always result in a policy bundle evaluation status of fail. It is important to note that blacklisting an image does not short-circuit the mapping evaluation or policy evaluations, so the full set of trigger matches will still be visible in the bundle evaluation result.

Blacklisted image matches override any whitelisted image matches (e.g. a tag matches a rule in both lists will always be blacklisted/fail).

Example image blacklist section:

```JSON
{
  "name": "BlacklistDebianUnstable",
  "registry": "docker.io",
  "repository": "library/debian",
  "image": { "type": "tag", "value": "unstable" }
}
```

A complete bundle example with all sections containing data:

```
{
  "id": "default0",
  "version": "1_0",
  "name": "My Default bundle",
  "comment": "My system's default bundle",
  "whitelisted_images": [
    {
      "name": "WhitelistDebianStable",
      "registry": "docker.io",
      "repository": "library/debian",
      "image": { "type": "tag", "value": "stable" }
    }
  ],
  "blacklisted_images": [
    {
      "name": "BlacklistDebianUnstable",
      "registry": "docker.io",
      "repository": "library/debian",
      "image": { "type": "tag", "value": "unstable" }
    }
  ],
  "mappings": [
    {
      "name": "DockerHub", 
      "registry": "docker.io",
      "repository": "library/postgres",
      "image": { "type": "tag", "value": "latest" },
      "policy_ids": [ "policy1", "policy2" ],
      "whitelist_ids": [ "whitelist1", "whitelist2" ]
    },
    {
      "name": "default", 
      "registry": "*",
      "repository": "*",
      "image": { "type": "tag", "value": "*" },
      "policy_ids": [ "policy1" ],
      "whitelist_ids": [ "whitelist1" ]
    }
  ],
  "whitelists": [
    {
      "id": "whitelist1",
      "name": "Simple Whitelist",
      "version": "1_0",
      "items": [
        { "id": "item1", "gate": "vulnerabilities", "trigger": "package", "trigger_id": "CVE-10000+libssl" },
        { "id": "item2", "gate": "vulnerabilities", "trigger": "package", "trigger_id": "CVE-10001+*" }
      ]
    },
    {
      "id": "whitelist2",
      "name": "Simple Whitelist",
      "version": "1_0",
      "items": [
        { "id": "item1", "gate": "vulnerabilities", "trigger": "package", "trigger_id": "CVE-1111+*" }
      ]
    }
  ],
  "policies": [
    {
      "name": "DefaultPolicy",
      "version": "1_0",
      "comment": "Policy for basic checks",
      "id": "policy1",
      "rules": [
        {
          "action": "STOP",
          "gate": "vulnerabilities",
          "trigger": "package",
          "id": "rule1",
          "params": [
            { "name": "package_type", "value": "all" },
            { "name": "severity_comparison", "value": ">=" },
            { "name": "severity", "value": "medium" }
          ]
        }
      ]
    },
    {
      "name": "DBPolicy",
      "version": "1_0",
      "comment": "Policy for basic checks on a db",
      "id": "policy2",
      "rules": [
        {
          "action": "STOP",
          "gate": "vulnerabilities",
          "trigger": "package",
          "id": "rule1",
          "params": [
            { "name": "package_type", "value": "all" },
            { "name": "severity_comparison", "value": ">=" },
            { "name": "severity", "value": "low" }
          ]
        }
      ]
    }
  ]
}
```

### Bundle Evaluation

A bundle evaluation results in a status of: *pass* or *fail* and that result based on the evaluation:

1. The mapping section to determine with policies and whitelists to select for evaluation against the given image and tag
2. The output of the policies' triggers and applied whitelists.
3. Blacklisted images section
4. Whitelisted images section

A *pass* status means the image evaluated against the bundle and only *go* or *warn* actions resulted from the policy evaluation and whitelist evaluations, or the image was whitelisted. A fail status means the image evaluated against the bundle and at least one *stop* action resulted from the policy evaluation and whitelist evaluation, or the image was blacklisted.

The flow chart for policy bundle evaluation:

![alt text](AnchoreFlowchart.jpg)