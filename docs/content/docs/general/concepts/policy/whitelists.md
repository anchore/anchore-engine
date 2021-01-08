---
title: "Whitelists"
weight: 1
---

Whitelists provide a mechanism within a policy bundle to explicitly override a policy-rule match. A whitelist is a named set of exclusion rules that match trigger outputs.

Example whitelist:

```JSON
{
  "id": "whitelist1",
  "name": "My First Whitelist",
  "comment": "A whitelist for my first try",
  "version": "1_0",
  "items": [
    {
      "gate": "vulnerabilities",
      "trigger_id": "CVE-2018-0737+*",
      "id": "rule1",
      "expires_on": "2019-12-30T12:00:00Z"
    }
  ]
}
```

The components:

- Gate: The gate to whitelist matches from (ensures trigger_ids are not matched in the wrong context)
- Trigger Id: The specific trigger result to match and whitelists. This id is gate/trigger specific as each trigger may have its own trigger_id format. We'll use the most common for this example: the CVE trigger ids produced by the vulnerability->package gate-trigger. The trigger_id specified may include wildcards for partial matches.
- id: an identifier for the rule, must only be unique within the whitelist object itself
- Expires On: (optional) specifies when a particular whitelist item expires. This is a UTC RFC3339 date-time string. If the rule matches, but is expired, the policy engine will NOT whitelist according to that match. 

The whitelist is processed if it is specified in the mapping rule that was matched during bundle evaluation and is applied to the results of the policy evaluation defined in that same mapping rule. If a whitelist item matches a specific policy trigger output, then the action for that output is set to go and the policy evaluation result notes that the trigger output was matched for a whitelist item by associating it with the whitelist id and item id of the match.

An example of a whitelisted match from a snippet of a policy evaluation result (See Policies for more information on the format of the policy evaluation result). This a single row entry from the result:

```JSON
[                                                
  "0e2811757f931e2259e09784938f0b0990e7889a37d15efbbe63912fa39ff8b0", 
  "docker.io/node:latest", 
  "CVE-2018-0737+openssl", 
  "vulnerabilities", 
  "package", 
  "MEDIUM Vulnerability found in os package type (dpkg) - openssl (fixed in: 1.0.1t-1+deb8u9) - (CVE-2018-0737 - https://security-tracker.debian.org/tracker/CVE-2018-0737)", 
  "go", 
  {
    "matched_rule_id": "rule1", 
    "whitelist_id": "whitelist1", 
    "whitelist_name": "My First Whitelist"
  }, 
  "myfirstpolicy"
]
```

The items in order are:

- Image ID
- Tag used for evaluation
- Trigger ID of the policy rule match
- Gate name
- Trigger name
- Trigger Check Output message
- **Whitelist result object** - This shows that the match was whitelisted by our example whitelist policy and its rule.
Policy Id

**Note:** Whitelists are evaluated only as far as necessary. Once a policy rule match has been whitelisted by one whitelist item, it will not be checked again for whitelist matches. But, whitelist items may be evaluated out-of-order for performance optimization, so if multiple whitelist items match the same policy rule match any one of them may be the item that is actually matched against a given trigger_id.