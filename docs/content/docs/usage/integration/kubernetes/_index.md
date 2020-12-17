---
title: "Kubernetes Integration"
linkTitle: "Kubernetes"
weight: 3
---

Anchore Engine can be integrated with Kubernetes to ensure that only certified images are started within a Kubernetes POD.

Kubernetes can be configured to use an Admission Controller to validate that the container image is compliant with the user's policy.

The admission controller can be configured to make a webhook call into the Anchore Engine. The Anchore Engine exports a Kubernetes-specific API endpoint and will return the pass of fail response in the form of an ImageReview response.

![alt text](k8s.png)

This approach allows the Kubernetes system to make the final decision on running an container image and does not require installation of any per-node plugins into Kubernetes.

Using native Kubernetes features allows this approach to be used in both on-prem and cloud hosted Kubernetes environments.