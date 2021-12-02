---
title: "Gitlab"
linkTitle: "Gitlab"
weight: 4
---

### Adding Anchore Scanning to Gitlab

The 'on premises' solution requires a functional installation of Anchore Engine running on a system that is accessible from your GitLab runners.

#### On Premises Solution:

This sample job can run a Gitlab Runner including shared runners on Gitlab.com.
The Docker executor is not required and no special privileges are required for scanning.

The runner will require network access to two end points:

Registry that contains the anchore/anchore-cli:latest
By default that is hosted on DockerHub however the image can be pushed to any registry

Network access to communicate to an Anchore Engine service. Typically on port 8228

A running Anchore Engine is required, this does not need to be run within the Gitlab infrastructure as long as the HTTP(s) endpoint of the Anchore Engine is accessible by the Github runner.

If the Anchore Engine will require credentials to pull the image to be analyzed from a Docker registry then the credentials should be added to Anchore Engine using the following procedures.

An example job is shown below and is attached at the bottom of this page named anchore-on-prem-gitlab.txt

```
anchore_scan:
  image: anchore/engine-cli:latest
  variables:
    ANCHORE_CLI_URL: "http://anchore.example.com:8228/v1"
    ANCHORE_CLI_USER: "admin"
    ANCHORE_CLI_PASS: "foobar"
    ANCHORE_CLI_SSL_VERIFY: "false"
    ANCHORE_SCAN_IMAGE: docker.io/library/debian
    ANCHORE_TIMEOUT: 300
    ANCHORE_FAIL_ON_POLICY: "false"
  script:
    - echo "Adding image to Anchore engine at ${ANCHORE_CLI_URL}"
    - anchore-cli image add ${ANCHORE_SCAN_IMAGE}
    - echo "Waiting for analysis to complete"
    - anchore-cli image wait ${ANCHORE_SCAN_IMAGE} --timeout ${ANCHORE_TIMEOUT}
    - echo "Analysis complete"
    - echo "Producing reports"
    - anchore-cli --json image content ${ANCHORE_SCAN_IMAGE} os > image-packages.json
    - anchore-cli --json image content ${ANCHORE_SCAN_IMAGE} npm > image-npm.json
    - anchore-cli --json image content ${ANCHORE_SCAN_IMAGE} gem > image-gem.json
    - anchore-cli --json image content ${ANCHORE_SCAN_IMAGE} python > image-python.json
    - anchore-cli --json image content ${ANCHORE_SCAN_IMAGE} java > image-java.json
    - anchore-cli --json image content ${ANCHORE_SCAN_IMAGE} nuget > image-nuget.json
    - anchore-cli --json image vuln ${ANCHORE_SCAN_IMAGE} all > image-vulnerabilities.json
    - anchore-cli --json image get ${ANCHORE_SCAN_IMAGE} > image-details.json
    - anchore-cli --json evaluate check ${ANCHORE_SCAN_IMAGE} --detail > image-policy.json || true
    - if [ "${ANCHORE_FAIL_ON_POLICY}" == "true" ] ; then anchore-cli evaluate check ${ANCHORE_SCAN_IMAGE}  ; fi 
  artifacts:
    name: "$CI_JOB_NAME"
    paths:
    - image-policy.json
    - image-details.json
    - image-vulnerabilities.json
    - image-java.json
    - image-nuget.json    
    - image-python.json
    - image-gem.json
    - image-npm.json
    - image-packages.json
```

The container to be scanned should have been pushed to a registry from which the Anchore Engine can pull the image.

The first step of the job uses the Anchore CLI to instruct the Anchore Engine to analyze the image. The analysis process may take anywhere from 20 second to a few minutes depending on the size of the image, storage performance and network connectivity. During this period the Anchore Engine will:

- Download all the layers of the image to the Anchore Engine
- Extract the layers to a temporary location
- Analyze the image including reading package data, scanning for secrets or other sensitive information,  recording file data such as a digests (checksum) of all files in the image including details such as file size and ownership
- Add analysis data to the Anchore database
- Delete temporary files

The job will poll the Anchore Engine every 10 seconds to check if the image has been analyzed and will repeat this until the maximum number of retries specified has been reached.

The job will output 8 JSON artifacts for storage within the Job's workspace.

If the ANCHORE_FAIL_ON_POLICY is set to true then if the policy evaluation result is fail the entire job will fail.
