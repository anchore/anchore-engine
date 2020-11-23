---
title: "Policy"
linkTitle: "Policy"
weight: 1
---

Once an image has been analyzed and its content has been discovered, categorized, and processed, the results can be evaluated against a user-defined set of checks to give a final pass/fail recommendation for an image. Anchore Engine policies are how users describe which checks to perform on what images and how the results should be interpreted.

 A policy is expressed as a policy bundle, which is made up from a set of rules that are used to perform an evaluation of a container image. The rules can define checks against an image for things such as:

- security vulnerabilities
- package whitelists and blacklists
- configuration file contents
- presence of credentials in image
- image manifest changes
- exposed ports

These checks are defined as Gates that contain Triggers that perform specific checks and emit matching results and these define the things that the engine can automatically evaluate and return a decision about.

For a full listing of gates, triggers, and their parameters see: [Anchore Policy Checks]({{< ref "/docs/overview/concepts/policy/policy_checks" >}})

These policies can be applied globally or customized for specific images or categories of applications.

![alt text](AnchorePolicyEval.png)

A policy can return one of two results:

**PASSED** indicating that image complies with your policy

![alt text](https://anchore.com/wp-content/uploads/2017/07/pass.png)

**FAILED** indicating that the image is out of compliance with your policy.

![alt text](https://anchore.com/wp-content/uploads/2017/07/fail.png)

For more information on the concepts of policies and how policies are defined and evaluated, see: [Policy Bundles and Evaluation]({{< ref "/docs/engine/general/concepts/policy/bundles" >}})

### Next Steps

Read more on [Policies]({{< ref "/docs/engine/general/concepts/policy/policies" >}})