---
title: "Policy Mappings"
weight: 1
---

Mappings in the policy bundle are a set of rules, evaluated in order, that describe matches on an image, id, digest, or tag and the corresponding sets of policies and whitelists to apply to any image that matches the rule's criteria.

A mapping has:

- Registry - The registry url to match, including wildcards (e.g. 'docker.io', 'quay.io', 'gcr.io', '*')
- Repository - The repository name to match, including wildcards (e.g. 'library/nginx', 'mydockerhubusername/myrepositoryname', 'library/*', '*')
- Image - The way to select an image that matches the registry and repository filters
    - type: how to reference the image and the expected format of the 'value' property
        - "tag" - just the tag name itself (the part after the ':' in a docker pull string: e.g. nginx:latest -> 'latest' is the tag name)
        - "id" - the image id
        - "digest" - the image digest (e.g. sha256@abc123)
    - value: the value to match against, including wildcards

**Note:** Unlike other parts of the policy bundle, Mappings are evaluated in order and will halt on the first matching rule. This is important to understand when combined with wildcard matches since it enables sophisticated matching behavior.

### Examples

Example 1, all images match a single catch-all rule:

```JSON
[
  {
    "registry": "*",
    "repository": "*",
    "image": { "type": "tag", "value": "*"},
    "policy_ids": ["defaultpolicy"],
    "whitelist_ids": ["defaultwhitelist"]
  }
]
```

Example 2, all "official" images from DockerHub are evaluated against *officialspolicy* and *officialswhitelist* (made up names for this example), while all others from DockerHub will be evaluated against *defaultpolicy* and *defaultwhitelist* , and private GCR images will be evaluated against *gcrpolicy* and *gcrwhitelist*:

```JSON
[
  {
    "registry": "docker.io",
    "repository": "library/*",
    "image": { "type": "tag", "value": "*"},
    "policy_ids": [ "officialspolicy"],
    "whitelist_ids": [ "officialswhitelist"]
  },
  {
    "registry": "gcr.io",
    "repository": "*",
    "image": { "type": "tag", "value": "*"},
    "policy_ids": [ "gcrpolicy"],
    "whitelist_ids": [ "gcrwhitelist"]
  },
  {
    "registry": "*",
    "repository": "*",
    "image": { "type": "tag", "value": "*"}
    "policy_ids": [ "defaultpolicy"],
    "whitelist_ids": [ "defaultwhitelist"]
  }
]
```

Example 3, all images from a non-known registry will be evaluated against *defaultpolicy* and *defaultwhitelist*, and an internal registry's images will be evaluated against a different set (*internalpolicy* and *internalwhitelist*):

```JSON
[
  {
    "registry": "myregistry.mydomain.com:5000",
    "repository": "*",
    "image": { "type": "tag", "value": "*"},
    "policy_ids": [ "internalpolicy"],
    "whitelist_ids": [ "internalwhitelist"]
  },
  {
    "registry": "*",
    "repository": "*",
    "image": { "type": "tag", "value": "*"}
    "policy_ids": [ "defaultpolicy"],
    "whitelist_ids": [ "defaultwhitelist"]
  }
]
```

### Using Multiple Policies and Whitelists

The result of the evaluation of the mapping section of a policy bundle is the list of policies and whitelists that will be used for actually evaluating the image. Because multiple policies and whitelists can be specified in each mapping rule, you can use granular policies and whitelists and the combined them in the mapping rules. 

Examples of schemes to use for how to split-up policies include:

- Different policies for different types of checks such that each policy only uses one or two gates (e.g. vulnerabilities, packages, dockerfile)
- Different policies for web servers, another for database servers, another for logging infrastructure, etc.
- Different policies for different parts of the stack: os-packages vs. application packages






