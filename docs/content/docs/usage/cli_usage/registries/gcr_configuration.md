---
title: "Working with Google Container Registry (GCR) Credentials"
weight: 1
---

When working with Google Container Registry it is recommended that you use JSON keys rather than the short lived access tokens.

JSON key files are long-lived and are tightly scoped to individual projects and resources. You can read more about JSON credentials in Google's documentation at the following URL: [Google Container Registry advanced authentication](https://cloud.google.com/container-registry/docs/advanced-authentication#using_a_json_key_file)

Once a JSON key file has been created with permissions to read from the container registry then the registry should be added with the username **_json_key** and the password should be the contents of the key file.

In the following example a file named key.json in the current directory contains the JSON key with readonly access to the my-repo repository within the my-project Google Cloud project.

`anchore-cli registry add us.gcr.io _json_key "$(cat key.json)"`


