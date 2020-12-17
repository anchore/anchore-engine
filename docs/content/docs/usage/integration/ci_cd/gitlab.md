---
title: "Gitlab"
linkTitle: "Gitlab"
weight: 4
---

### Adding Anchore Scanning to Gitlab

There are two different solutions for adding Anchore Engine image scanning to your GitLab CI/CD pipelines. The 'on premises' solution requires a functional installation of Anchore Engine running on a system that is accessible from your GitLab runners. The 'integrated' solution allows you to run Anchore Engine directly on your GitLab docker runner and utilizes a pre-populated vulnerability database image. This solution does not require any external systems. 

A container scanning job can be added to the CI/CD pipeline to allow any image to be scanned for vulnerabilities and policy compliance.

#### Integrated Solution:

This sample pipeline runs directly on a GitLab runner, including shared runners on gitlab.com

The Docker executor is required for this job, as it utilizes the official Anchore Engine container.

A fully functional pipeline can be viewed at [gitlab.com/anchore/gitlab-demo](https://gitlab.com/anchore/gitlab-demo/blob/master/.gitlab-ci.yml)

To be a thorough as possible, this document will provide an entire Docker build/scan/publish pipeline. This is just one example of a pipeline utilizing the integrated Anchore Engine solution, users are free to tweak it to their needs. The 'container_scan' job is responsible for the actual Anchore Engine image scanning, the only requirement of this job is that the image to be scanned is pushed to the GitLab registry. 

```
variables:
  IMAGE_NAME: ${CI_REGISTRY_IMAGE}/build:${CI_COMMIT_REF_SLUG}-${CI_COMMIT_SHA}

stages:
- build
- scan
- publish

container_build:
  stage: build
  image: docker:stable
  services:
  - docker:stable-dind

  variables:
    DOCKER_DRIVER: overlay2

  script:
  - echo "$CI_JOB_TOKEN" | docker login -u gitlab-ci-token --password-stdin "${CI_REGISTRY}"
  - docker build -t "$IMAGE_NAME" .

container_scan_service:
  stage: scan
  variables:
    ANCHORE_CLI_URL: "http://anchore-engine:8228/v1"
    GIT_STRATEGY: none
  image: docker.io/anchore/inline-scan:v0.6.0
  services:
  - name: docker.io/anchore/inline-scan:v0.6.0
    alias: anchore-engine
    command: ["start"]

  script:
  - source /opt/rh/rh-python36/enable
  - anchore-cli system wait
  - anchore-cli registry add "$CI_REGISTRY" gitlab-ci-token "$CI_JOB_TOKEN" --skip-validate 
  - anchore_ci_tools.py -a -r --timeout 500 --image $IMAGE_NAME

  artifacts:
    name: ${CI_JOB_NAME}-${CI_COMMIT_REF_NAME}
    paths:
    - anchore-reports/*

container_publish:
  stage: publish
  image: docker:stable
  services:
  - docker:stable-dind

  variables:
    DOCKER_DRIVER: overlay2
    GIT_STRATEGY: none

  script:
  - echo "$CI_JOB_TOKEN" | docker login -u gitlab-ci-token --password-stdin "${CI_REGISTRY}"
  - docker pull "$IMAGE_NAME"
  - docker tag "$IMAGE_NAME" "${CI_REGISTRY_IMAGE}:latest"
  - docker push "${CI_REGISTRY_IMAGE}:latest"
```

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
