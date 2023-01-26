---
title: "Anchore Engine"
linkTitle: "Anchore Engine Documentation"
weight: 10
---

NOTE: As of 2023, Anchore Engine is no longer maintained as an active project. Users are recommended to install Syft or Grype.

Anchore Engine is a system to help automate the description and enforcement of requirements on the content of docker containers.

With a bit more detail? Anchore Engine is a Docker container static analysis and policy-based compliance tool that automates the inspection, analysis, and evaluation of images against user-defined checks to allow high confidence in container deployments by ensuring workload content meets the required criteria. Anchore Engine ultimately provides a policy evaluation result for each image: pass/fail against policies defined by the user. Additionally, the way that policies are defined and evaluated allows the policy evaluation itself to double as an audit mechanism that allows point-in-time evaluations of specific image properties and content attributes.