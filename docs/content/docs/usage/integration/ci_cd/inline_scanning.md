---
title: "Anchore Engine Inline Scanning"
linkTitle: "Inline Scanning"
weight: 3
---

## Introduction

`curl -s https://ci-tools.anchore.io/inline_scan-latest | bash -s -- -p alpine:latest`

To make using our inline-scan container as easy as possible, we have provided a simple wrapper script called inline_scan. The only requirements to run the inline_scan script is the ability to execute Docker commands & bash. We host a versioned copy of this script that can be downloaded directly with curl and executed in a bash pipeline.

To run the script on your workstation, use the following command syntax.

`curl -s https://ci-tools.anchore.io/inline_scan-latest | bash -s -- [options] IMAGE_NAME(s)`

### Inline Scan Options

```
-b <PATH>  [optional] Path to local Anchore policy bundle (ex: -b ./policy_bundle.json)
-d <PATH>  [optional] Path to local Dockerfile (ex: -d ./dockerfile)
-v <PATH>  [optional] Path to directory, all image archives in directory will be scanned (ex: -v /tmp/scan_images/)
-t <TEXT>  [optional] Specify timeout for image scanning in seconds. Defaults to 300s. (ex: -t 500)
-f  [optional] Exit script upon failed Anchore policy evaluation
-p  [optional] Pull remote docker images
-r  [optional] Generate analysis reports in your current working directory
-V  [optional] Increase verbosity
```

### Usage

Pull multiple images from DockerHub, scan them all and generate individual reports in ./anchore-reports.

`curl -s https://ci-tools.anchore.io/inline_scan-latest | bash -s -- -p -r alpine:latest ubuntu:latest centos:latest`

Perform a local docker build, then pass the Dockerfile to anchore inline scan. Use a custom policy bundle to ensure Dockerfile compliance, failing the script if anchore policy evaluation does not pass.

```
docker build -t example-image:latest -f Dockerfile .
curl -s https://ci-tools.anchore.io/inline_scan-latest | bash -s -- -f -d Dockerfile -b .anchore-policy.json example-image:latest
```

Save multiple docker image archives to a directory, then mount the entire directory for analysis using a timeout of 500s.

```
cd example1/
docker build -t example1:latest .
cd ../example2
docker build -t example2:latest .
cd ..
mkdir images/
docker save example1:latest -o images/example1+latest.tar
docker save example2:latest -o images/example2+latest.tar
curl -s https://ci-tools.anchore.io/inline_scan-latest | bash -s -- -v ./images -t 500
```

### CI Implementations

All of the following examples can be found in this Github repository - https://github.com/Btodhunter/ci-demos

#### CircleCI

This workflow requires the $DOCKER_USER & $DOCKER_PASS environment variables to be set in a context called dockerhub in your CircleCI account settings at settings -> context -> create

config.yml - https://github.com/Btodhunter/ci-demos/blob/master/.circleci/config.yml

```
version: 2.1
jobs:
  build_scan_image:
    docker:
    - image: docker:stable
    environment:
      IMAGE_NAME: btodhunter/anchore-ci-demo
      IMAGE_TAG: circleci
    steps:
    - checkout
    - setup_remote_docker
    - run:
        name: Build image
        command: docker build -t "${IMAGE_NAME}:ci" .
    - run:
        name: Scan image
        command: |
          apk add curl bash
          curl -s https://ci-tools.anchore.io/inline_scan-latest | bash -s -- -r "${IMAGE_NAME}:ci"
    - run:
        name: Push to DockerHub
        command: |
          echo "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin
          docker tag "${IMAGE_NAME}:ci" "${IMAGE_NAME}:${IMAGE_TAG}"
          docker push "${IMAGE_NAME}:${IMAGE_TAG}"
    - store_artifacts:
        path: anchore-reports/

workflows:
  scan_image:
    jobs:
    - build_scan_image:
        context: dockerhub
```

#### GitLab

GitLab allows docker command execution through a docker:dind service container. This job pushes the image to the GitLab registry, using built-in environment variables for specifying the image name and registry login credentials.

.gitlab-ci.yml - https://github.com/Btodhunter/ci-demos/blob/master/.gitlab-ci.yml

```
variables:
  IMAGE_NAME: ${CI_REGISTRY_IMAGE}/build:${CI_COMMIT_REF_SLUG}-${CI_COMMIT_SHA}

stages:
- build

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
  - apk add bash curl
  - curl -s https://ci-tools.anchore.io/inline_scan-latest | bash -s -- -r -t 500 "$IMAGE_NAME"
  - docker push "$IMAGE_NAME"

  artifacts:
    name: ${CI_JOB_NAME}-${CI_COMMIT_REF_NAME}
    paths:
    - anchore-reports/*
```

#### CodeShip

This job requires creating an encrypted environment variable file for loading the $DOCKER_USER & $DOCKER_PASS variables into your job. See - https://documentation.codeship.com/pro/builds-and-configuration/environment-variables/#encrypted-environment-variables

codeship-services.yml - https://github.com/Btodhunter/ci-demos/blob/master/codeship-services.yml

```
anchore:
  add_docker: true
  image: docker:stable-git
  environment:
    IMAGE_NAME: btodhunter/anchore-ci-demo
    IMAGE_TAG: codeship
  encrypted_env_file: env.encrypted
```

codeship-steps.yml - https://github.com/Btodhunter/ci-demos/blob/master/codeship-steps.yml

```
- name: build-scan
  service: anchore
  command: sh -c 'apk add bash curl &&
    mkdir -p /build &&
    cd /build &&
    git clone https://github.com/Btodhunter/ci-demos.git . &&
    docker build -t "${IMAGE_NAME}:ci" . &&
    curl -s https://ci-tools.anchore.io/inline_scan-latest | bash -s -- -f -b .anchore_policy.json "${IMAGE_NAME}:ci" &&
    echo "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin &&
    docker tag "${IMAGE_NAME}:ci" "${IMAGE_NAME}:${IMAGE_TAG}" &&
    docker push "${IMAGE_NAME}:${IMAGE_TAG}"'
```

#### Jenkins pipeline

To allow pushing to a private registry, the dockerhub-creds credentials must be created in the Jenkins server settings at - Jenkins -> Credentials -> System -> Global credentials -> Add Credentials

This example was tested against the Jenkins installation detailed here, using the declarative pipeline syntax - https://jenkins.io/doc/tutorials/build-a-multibranch-pipeline-project/#run-jenkins-in-docker

Jenkinsfile - https://github.com/Btodhunter/ci-demos/blob/master/Jenkinsfile

```
pipeline{
    agent {
        docker {
            image 'docker:stable'
        }
    }
    environment {
        IMAGE_NAME = 'btodhunter/anchore-ci-demo'
        IMAGE_TAG = 'jenkins'
    }
    stages {
        stage('Build Image') {
            steps {
                sh 'docker build -t ${IMAGE_NAME}:ci .'
            }
        }
        stage('Scan') {
            steps {
                sh 'apk add bash curl'
                sh 'curl -s https://ci-tools.anchore.io/inline_scan-latest | bash -s -- -d Dockerfile -b .anchore_policy.json ${IMAGE_NAME}:ci'
            }
        }
        stage('Push Image') {
            steps {
                withDockerRegistry([credentialsId: "dockerhub-creds", url: ""]){
                    sh 'docker tag ${IMAGE_NAME}:ci ${IMAGE_NAME}:${IMAGE_TAG}'
                    sh 'docker push ${IMAGE_NAME}:${IMAGE_TAG}'
                }
            }
        }
    }
}
```

#### TravisCI

The $DOCKER_USER & $DOCKER_PASS environment variables must be setup in the TravisCI console at repository -> settings -> environment variables

.travis.yml - https://github.com/Btodhunter/ci-demos/blob/master/.travis.yml

```
language: node_js

services:
  - docker

env:
  - IMAGE_NAME="btodhunter/anchore-ci-demo" IMAGE_TAG="travisci"

script:
  - docker build -t "${IMAGE_NAME}:ci" .
  - curl -s https://ci-tools.anchore.io/inline_scan-latest | bash -s -- "${IMAGE_NAME}:ci"
  - echo "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin
  - docker tag "${IMAGE_NAME}:ci" "${IMAGE_NAME}:${IMAGE_TAG}"
  - docker push "${IMAGE_NAME}:${IMAGE_TAG}"
```

#### AWS CodeBuild

The $DOCKER_USER, $DOCKER_PASS, $IMAGE_NAME, & $IMAGE_TAG environment variables must be set in the CodeBuild console at Build Projects -> <PROJECT_NAME> -> Edit Environment -> Additional Config -> Environment Variables

buildspec.yml - https://github.com/Btodhunter/ci-demos/blob/master/buildspec.yml

```
version: 0.2

phases:
  build:
    commands:
      - docker build -t ${IMAGE_NAME}:${IMAGE_TAG} .

  post_build:
    commands:
      - curl -s https://ci-tools.anchore.io/inline_scan-latest | bash -s -- ${IMAGE_NAME}:${IMAGE_TAG}
      - echo $DOCKER_PASS | docker login -u $DOCKER_USER --password-stdin
      - docker push ${IMAGE_NAME}:${IMAGE_TAG}
```
