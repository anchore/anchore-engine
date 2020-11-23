---
title: "Anchore Engine Overview"
linkTitle: "Overview"
weight: 2
---

### What is Anchore Engine?

In short: a system to help automate the description and enforcement of requirements on the content of docker containers.

With a bit more detail? Anchore Engine is a docker container static analysis and policy-based compliance tool that automates the inspection, analysis, and evaluation of images against user-defined checks to allow high confidence in container deployments by ensuring workload content meets the required criteria. Anchore Engine ultimately provides a policy evaluation result for each image: pass/fail against policies defined by the user. Additionally, the way that policies are defined and evaluated allows the policy evaluation itself to double as an audit mechanism that allows point-in-time evaluations of specific image properties and content attributes.

### How does it work?


Anchore takes a data-driven approach to analysis and policy enforcement. The system essentially has discrete phases for each image analyzed:

1. **Fetch** the image content and extract it, but never execute it
2. **Analyze** the image by running a set of Anchore analyzers over the image content to extract and classify as much metadata as possible
3. **Save** the resulting analysis in the database for future use and audit
4. **Evaluate** policies against the analysis result, including vulnerability matches on the artifacts discovered in the image
5. **Update** to the latest external data used for policy evaluation and vulnerability matches (we call this external data sync a feed sync), and automatically update image analysis results against any new data found upstream.
6. **Notify** users of changes to policy evaluations and vulnerability matches
7. **Repeat** 5 & 6 on intervals to ensure latest external data and updated image evaluations

![alt text](HowItWorks.png)

The primary interface is a RESTful API that provides mechanisms to request analysis, policy evaluation, and monitoring of images in registries as well as query for image contents and analysis results. We also provide a CLI and its own container.

There are, generally speaking, two different ways to use Anchore Engine, within its single API:

1. Interactive Mode - Use the APIs to explicitly request an image analysis, get a policy evaluation and content reports, but the engine only performs operations when specifically requested by a user
2. Watch Mode - Use the APIs to configure Anchore Engine to poll specific registries and repositories/tags to watch for new images added and automatically pull and evaluate them, emitting notifications when a given tag's vulnerability or policy evaluation state changes

With these two modes of operation, integration into CI/CD with Interactive Mode or less intrusive watching of production image repositories with Watch Mode, Anchore Engine can be easily integrated into most environments and processes.

### How to get it?

Anchore Engine is [open source](https://github.com/anchore/anchore-engine), and we build and deliver it as a [Docker container](https://hub.docker.com/r/anchore/anchore-engine).

The system is a collection of services that can be deployed co-located or fully distributed or anything in-between, and as such it can scale out to increase analysis throughput. The only external system required is a PostgreSQL database (9.6+) that all services connect to, but is not used for communication beyond some very simple service registration/lookup processes. The database is centralized simply for ease of management and operation.

The six services that comprise the Engine can be deployed in a single container or scaled out to handle load:

![alt text](AnchoreEngineServices.png)

For most installations a single instance is sufficient however multiple Analyzer Worker services can be spun up to handle heavy load and to reduce analysis time.

### Next Steps

Now that you have an overview, check out the [Concepts]({{< ref "/docs/engine/general/concepts" >}}) section to gain a deeper understanding.
