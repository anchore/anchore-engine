---
title: "Database"
weight: 1
---

The Anchore Engine requires PostgreSQL version 9.6 or higher database to provide persistent storage for image, policy and analysis data.

This database can be run in a container, as configured in the example Docker Compose file or can be provided as an external service to the Anchore Engine.
PostgreSQL compatible databases such as Amazon RDS for PostgreSQL can be used for highly scalable cloud deployments.