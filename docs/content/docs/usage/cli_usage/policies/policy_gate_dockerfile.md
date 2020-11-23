---
title: "Policy Gate: dockerfile"
weight: 1
---

This article reviews the "dockerfile" gate and its triggers. The dockerfile gate allows users to perform checks on the content of the dockerfile or docker history for an image and make policy actions based on the construction of an image, not just its content. This is particularly useful for enforcing best practices or metadata inclusion (e.g. labels) on images.

Anchore is either given a dockerfile or infers one from the docker image layer history. There are implications to what data is available and what it means depending on these differing sources, so first, we'll cover the input data for the gate and how it impacts the triggers and parameters used.

### The "dockerfile"

The data that this gate operates on can come from two different sources: 

1. The actual dockerfile used to build an image, as provided by the user at the time of running `anchore-cli image add <img ref> --dockerfile <filename>` or the corresponding API call to: POST /images?dockerfile=<base64content> 
2. The history from layers as encoded in the image itself (see `docker history <img>` for this output)

All images have data from history available, but data from the actual dockerfile is only available when a user provides it. This also means that any images analyzed by the tag watcher functionality will not have an actual dockerfile.

#### The FROM line
In the actual dockerfile, the FROM instruction is preserved and available as used to build the image, however in the history data, the FROM line will always be the very first FROM instruction used to build the image and all of its dependent based image. Thus, for most images, the value in the history will be omitted and Anchore will automatically infer a FROM scratch line, which is logically inserted for this gate if the dockerfile/history does not contain an explicit FROM entry.

For example, using the docker.io/jenkins/jenkins image:

```
IMAGE                                                                     CREATED             CREATED BY                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       SIZE                COMMENT
sha256:3b9c9666a66e53473c05a3c69eb2cb888a8268f76935eecc7530653cddc28981   11 hours ago        /bin/sh -c #(nop) COPY file:3a15c25533fd87983edc33758f62af7b543ccc3ce9dd570e473eb0702f5f298e in /usr/local/bin/install-plugins.sh                                                                                                                                                                                                                                                                                                                                                                                                                                8.79kB              
<missing>                                                                 11 hours ago        /bin/sh -c #(nop) COPY file:f97999fac8a63cf8b635a54ea84a2bc95ae3da4d81ab55267c92b28b502d8812 in /usr/local/bin/plugins.sh                                                                                                                                                                                                                                                                                                                                                                                                                                        3.96kB              
<missing>                                                                 11 hours ago        /bin/sh -c #(nop)  ENTRYPOINT ["/sbin/tini" "--" "/usr/local/bin/jenkins.sh"]                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    0B                  
<missing>                                                                 11 hours ago        /bin/sh -c #(nop) COPY file:dc942ca949bb159f81bbc954773b3491e433d2d3e3ef90bac80ecf48a313c9c9 in /bin/tini                                                                                                                                                                                                                                                                                                                                                                                                                                                        529B                
<missing>                                                                 11 hours ago        /bin/sh -c #(nop) COPY file:a8f986413b77bf4d88562b9d3a0dce98ab6e75403192aa4d4153fb41f450843d in /usr/local/bin/jenkins.sh                                                                                                                                                                                                                                                                                                                                                                                                                                        1.45kB              
<missing>                                                                 11 hours ago        /bin/sh -c #(nop) COPY file:55594d9d2aed007553a6743a43039b1a48b30527f8fb991ad93e1fd5b1298f60 in /usr/local/bin/jenkins-support                                                                                                                                                                                                                                                                                                                                                                                                                                   6.12kB              
<missing>                                                                 11 hours ago        /bin/sh -c #(nop)  USER jenkins                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  0B                  
<missing>                                                                 11 hours ago        /bin/sh -c #(nop)  ENV COPY_REFERENCE_FILE_LOG=/var/jenkins_home/copy_reference_file.log                                                                                                                                                                                                                                                                                                                                                                                                                                                                         0B                  
<missing>                                                                 11 hours ago        /bin/sh -c #(nop)  EXPOSE 50000                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  0B                  
<missing>                                                                 11 hours ago        /bin/sh -c #(nop)  EXPOSE 8080                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   0B                  
<missing>                                                                 11 hours ago        |9 JENKINS_SHA=e026221efcec9528498019b6c1581cca70fe9c3f6b10303777d85c6699bca0e4 JENKINS_URL=https://repo.jenkins-ci.org/public/org/jenkins-ci/main/jenkins-war/2.161/jenkins-war-2.161.war TINI_VERSION=v0.16.1 agent_port=50000 gid=1000 group=jenkins http_port=8080 uid=1000 user=jenkins /bin/sh -c chown -R ${user} "$JENKINS_HOME" /usr/share/jenkins/ref                                                                                                                                                                                                  328B                
<missing>                                                                 11 hours ago        /bin/sh -c #(nop)  ENV JENKINS_INCREMENTALS_REPO_MIRROR=https://repo.jenkins-ci.org/incrementals                                                                                                                                                                                                                                                                                                                                                                                                                                                                 0B                  
<missing>                                                                 11 hours ago        /bin/sh -c #(nop)  ENV JENKINS_UC_EXPERIMENTAL=https://updates.jenkins.io/experimental                                                                                                                                                                                                                                                                                                                                                                                                                                                                           0B                  
<missing>                                                                 11 hours ago        /bin/sh -c #(nop)  ENV JENKINS_UC=https://updates.jenkins.io                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     0B                  
<missing>                                                                 11 hours ago        |9 JENKINS_SHA=e026221efcec9528498019b6c1581cca70fe9c3f6b10303777d85c6699bca0e4 JENKINS_URL=https://repo.jenkins-ci.org/public/org/jenkins-ci/main/jenkins-war/2.161/jenkins-war-2.161.war TINI_VERSION=v0.16.1 agent_port=50000 gid=1000 group=jenkins http_port=8080 uid=1000 user=jenkins /bin/sh -c curl -fsSL ${JENKINS_URL} -o /usr/share/jenkins/jenkins.war   && echo "${JENKINS_SHA}  /usr/share/jenkins/jenkins.war" | sha256sum -c -                                                                                                                  76MB                
<missing>                                                                 11 hours ago        /bin/sh -c #(nop)  ARG JENKINS_URL=https://repo.jenkins-ci.org/public/org/jenkins-ci/main/jenkins-war/2.161/jenkins-war-2.161.war                                                                                                                                                                                                                                                                                                                                                                                                                                0B                  
<missing>                                                                 11 hours ago        /bin/sh -c #(nop)  ARG JENKINS_SHA=5bb075b81a3929ceada4e960049e37df5f15a1e3cfc9dc24d749858e70b48919                                                                                                                                                                                                                                                                                                                                                                                                                                                              0B                  
<missing>                                                                 11 hours ago        /bin/sh -c #(nop)  ENV JENKINS_VERSION=2.161                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     0B                  
<missing>                                                                 11 hours ago        /bin/sh -c #(nop)  ARG JENKINS_VERSION                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           0B                  
<missing>                                                                 11 hours ago        /bin/sh -c #(nop) COPY file:c84b91c835048a52bb864c1f4662607c56befe3c4b1520b0ea94633103a4554f in /usr/share/jenkins/ref/init.groovy.d/tcp-slave-agent-port.groovy                                                                                                                                                                                                                                                                                                                                                                                                 328B                
<missing>                                                                 11 hours ago        |7 TINI_VERSION=v0.16.1 agent_port=50000 gid=1000 group=jenkins http_port=8080 uid=1000 user=jenkins /bin/sh -c curl -fsSL https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static-$(dpkg --print-architecture) -o /sbin/tini   && curl -fsSL https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static-$(dpkg --print-architecture).asc -o /sbin/tini.asc   && gpg --no-tty --import ${JENKINS_HOME}/tini_pub.gpg   && gpg --verify /sbin/tini.asc   && rm -rf /sbin/tini.asc /root/.gnupg   && chmod +x /sbin/tini   866kB               
<missing>                                                                 11 hours ago        /bin/sh -c #(nop) COPY file:653491cb486e752a4c2b4b407a46ec75646a54eabb597634b25c7c2b82a31424 in /var/jenkins_home/tini_pub.gpg                                                                                                                                                                                                                                                                                                                                                                                                                                   7.15kB              
<missing>                                                                 11 hours ago        /bin/sh -c #(nop)  ARG TINI_VERSION=v0.16.1                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      0B                  
<missing>                                                                 11 hours ago        |6 agent_port=50000 gid=1000 group=jenkins http_port=8080 uid=1000 user=jenkins /bin/sh -c mkdir -p /usr/share/jenkins/ref/init.groovy.d                                                                                                                                                                                                                                                                                                                                                                                                                         0B                  
<missing>                                                                 11 hours ago        /bin/sh -c #(nop)  VOLUME [/var/jenkins_home]                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    0B                  
<missing>                                                                 11 hours ago        |6 agent_port=50000 gid=1000 group=jenkins http_port=8080 uid=1000 user=jenkins /bin/sh -c mkdir -p $JENKINS_HOME   && chown ${uid}:${gid} $JENKINS_HOME   && groupadd -g ${gid} ${group}   && useradd -d "$JENKINS_HOME" -u ${uid} -g ${gid} -m -s /bin/bash ${user}                                                                                                                                                                                                                                                                                            328kB               
<missing>                                                                 11 hours ago        /bin/sh -c #(nop)  ENV JENKINS_SLAVE_AGENT_PORT=50000                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0B                  
<missing>                                                                 11 hours ago        /bin/sh -c #(nop)  ENV JENKINS_HOME=/var/jenkins_home                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0B                  
<missing>                                                                 11 hours ago        /bin/sh -c #(nop)  ARG JENKINS_HOME=/var/jenkins_home                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0B                  
<missing>                                                                 11 hours ago        /bin/sh -c #(nop)  ARG agent_port=50000                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          0B                  
<missing>                                                                 11 hours ago        /bin/sh -c #(nop)  ARG http_port=8080                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            0B                  
<missing>                                                                 11 hours ago        /bin/sh -c #(nop)  ARG gid=1000                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  0B                  
<missing>                                                                 11 hours ago        /bin/sh -c #(nop)  ARG uid=1000                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  0B                  
<missing>                                                                 11 hours ago        /bin/sh -c #(nop)  ARG group=jenkins                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             0B                  
<missing>                                                                 11 hours ago        /bin/sh -c #(nop)  ARG user=jenkins                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              0B                  
<missing>                                                                 11 hours ago        /bin/sh -c apt-get update && apt-get install -y git curl && rm -rf /var/lib/apt/lists/*                                                                                                                                                                                                                                                                                                                                                                                                                                                                          0B                  
<missing>                                                                 3 weeks ago         /bin/sh -c set -ex;   if [ ! -d /usr/share/man/man1 ]; then   mkdir -p /usr/share/man/man1;  fi;   apt-get update;  apt-get install -y --no-install-recommends   openjdk-8-jdk="$JAVA_DEBIAN_VERSION"  ;  rm -rf /var/lib/apt/lists/*;   [ "$(readlink -f "$JAVA_HOME")" = "$(docker-java-home)" ];   update-alternatives --get-selections | awk -v home="$(readlink -f "$JAVA_HOME")" 'index($3, home) == 1 { $2 = "manual"; print | "update-alternatives --set-selections" }';  update-alternatives --query java | grep -q 'Status: manual'                    348MB               
<missing>                                                                 3 weeks ago         /bin/sh -c #(nop)  ENV JAVA_DEBIAN_VERSION=8u181-b13-2~deb9u1                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    0B                  
<missing>                                                                 3 weeks ago         /bin/sh -c #(nop)  ENV JAVA_VERSION=8u181                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        0B                  
<missing>                                                                 3 weeks ago         /bin/sh -c #(nop)  ENV JAVA_HOME=/docker-java-home                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               0B                  
<missing>                                                                 3 weeks ago         /bin/sh -c ln -svT "/usr/lib/jvm/java-8-openjdk-$(dpkg --print-architecture)" /docker-java-home                                                                                                                                                                                                                                                                                                                                                                                                                                                                  33B                 
<missing>                                                                 3 weeks ago         /bin/sh -c {   echo '#!/bin/sh';   echo 'set -e';   echo;   echo 'dirname "$(dirname "$(readlink -f "$(which javac || which java)")")"';  } > /usr/local/bin/docker-java-home  && chmod +x /usr/local/bin/docker-java-home                                                                                                                                                                                                                                                                                                                                       87B                 
<missing>                                                                 3 weeks ago         /bin/sh -c #(nop)  ENV LANG=C.UTF-8                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              0B                  
<missing>                                                                 3 weeks ago         /bin/sh -c apt-get update && apt-get install -y --no-install-recommends   bzip2   unzip   xz-utils  && rm -rf /var/lib/apt/lists/*                                                                                                                                                                                                                                                                                                                                                                                                                               2.21MB              
<missing>                                                                 3 weeks ago         /bin/sh -c apt-get update && apt-get install -y --no-install-recommends   bzr   git   mercurial   openssh-client   subversion     procps  && rm -rf /var/lib/apt/lists/*                                                                                                                                                                                                                                                                                                                                                                                         142MB               
<missing>                                                                 3 weeks ago         /bin/sh -c set -ex;  if ! command -v gpg > /dev/null; then   apt-get update;   apt-get install -y --no-install-recommends    gnupg    dirmngr   ;   rm -rf /var/lib/apt/lists/*;  fi                                                                                                                                                                                                                                                                                                                                                                             7.81MB              
<missing>                                                                 3 weeks ago         /bin/sh -c apt-get update && apt-get install -y --no-install-recommends   ca-certificates   curl   netbase   wget  && rm -rf /var/lib/apt/lists/*                                                                                                                                                                                                                                                                                                                                                                                                                23.2MB              
<missing>                                                                 3 weeks ago         /bin/sh -c #(nop)  CMD ["bash"]                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  0B                  
<missing>                                                                 3 weeks ago         /bin/sh -c #(nop) ADD file:da71baf0d22cb2ede91c5e3ff959607e47459a9d7bda220a62a3da362b0e59ea in /                                                                                                                                                                                                                                                                                                                                                                                                                                                                 101MB
```

Where the actual dockerfile for that image is:

```
FROM openjdk:8-jdk-stretch

RUN apt-get update && apt-get install -y git curl && rm -rf /var/lib/apt/lists/*

ARG user=jenkins
ARG group=jenkins
ARG uid=1000
ARG gid=1000
ARG http_port=8080
ARG agent_port=50000
ARG JENKINS_HOME=/var/jenkins_home

ENV JENKINS_HOME $JENKINS_HOME
ENV JENKINS_SLAVE_AGENT_PORT ${agent_port}

# Jenkins is run with user `jenkins`, uid = 1000
# If you bind mount a volume from the host or a data container,
# ensure you use the same uid
RUN mkdir -p $JENKINS_HOME \
  && chown ${uid}:${gid} $JENKINS_HOME \
  && groupadd -g ${gid} ${group} \
  && useradd -d "$JENKINS_HOME" -u ${uid} -g ${gid} -m -s /bin/bash ${user}

# Jenkins home directory is a volume, so configuration and build history
# can be persisted and survive image upgrades
VOLUME $JENKINS_HOME

# `/usr/share/jenkins/ref/` contains all reference configuration we want
# to set on a fresh new installation. Use it to bundle additional plugins
# or config file with your custom jenkins Docker image.
RUN mkdir -p /usr/share/jenkins/ref/init.groovy.d

# Use tini as subreaper in Docker container to adopt zombie processes
ARG TINI_VERSION=v0.16.1
COPY tini_pub.gpg ${JENKINS_HOME}/tini_pub.gpg
RUN curl -fsSL https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static-$(dpkg --print-architecture) -o /sbin/tini \
  && curl -fsSL https://github.com/krallin/tini/releases/download/${TINI_VERSION}/tini-static-$(dpkg --print-architecture).asc -o /sbin/tini.asc \
  && gpg --no-tty --import ${JENKINS_HOME}/tini_pub.gpg \
  && gpg --verify /sbin/tini.asc \
  && rm -rf /sbin/tini.asc /root/.gnupg \
  && chmod +x /sbin/tini

COPY init.groovy /usr/share/jenkins/ref/init.groovy.d/tcp-slave-agent-port.groovy

# jenkins version being bundled in this docker image
ARG JENKINS_VERSION
ENV JENKINS_VERSION ${JENKINS_VERSION:-2.121.1}

# jenkins.war checksum, download will be validated using it
ARG JENKINS_SHA=5bb075b81a3929ceada4e960049e37df5f15a1e3cfc9dc24d749858e70b48919

# Can be used to customize where jenkins.war get downloaded from
ARG JENKINS_URL=https://repo.jenkins-ci.org/public/org/jenkins-ci/main/jenkins-war/${JENKINS_VERSION}/jenkins-war-${JENKINS_VERSION}.war

# could use ADD but this one does not check Last-Modified header neither does it allow to control checksum
# see https://github.com/docker/docker/issues/8331
RUN curl -fsSL ${JENKINS_URL} -o /usr/share/jenkins/jenkins.war \
  && echo "${JENKINS_SHA}  /usr/share/jenkins/jenkins.war" | sha256sum -c -

ENV JENKINS_UC https://updates.jenkins.io
ENV JENKINS_UC_EXPERIMENTAL=https://updates.jenkins.io/experimental
ENV JENKINS_INCREMENTALS_REPO_MIRROR=https://repo.jenkins-ci.org/incrementals
RUN chown -R ${user} "$JENKINS_HOME" /usr/share/jenkins/ref

# for main web interface:
EXPOSE ${http_port}

# will be used by attached slave agents:
EXPOSE ${agent_port}

ENV COPY_REFERENCE_FILE_LOG $JENKINS_HOME/copy_reference_file.log

USER ${user}

COPY jenkins-support /usr/local/bin/jenkins-support
COPY jenkins.sh /usr/local/bin/jenkins.sh
COPY tini-shim.sh /bin/tini
ENTRYPOINT ["/sbin/tini", "--", "/usr/local/bin/jenkins.sh"]

# from a derived Dockerfile, can use `RUN plugins.sh active.txt` to setup /usr/share/jenkins/ref/plugins from a support bundle
COPY plugins.sh /usr/local/bin/plugins.sh
COPY install-plugins.sh /usr/local/bin/install-plugins.sh
```

Anchore will detect the history/dockerfile as this, if not explicitly provided (note order is reversed from docker history output, so it reads in same order as actual dockerfile):

```
[
   {
      "Size" : 45323792,
      "Tags" : [],
      "Comment" : "",
      "Id" : "sha256:cd8eada9c7bb496eb685fc6d2198c33db7cb05daf0fde42e4cf5bf0127cbdf38",
      "Created" : "2018-12-28T23:29:37.981962131Z",
      "CreatedBy" : "/bin/sh -c #(nop) ADD file:da71baf0d22cb2ede91c5e3ff959607e47459a9d7bda220a62a3da362b0e59ea in / "
   },
   {
      "Size" : 0,
      "Tags" : [],
      "Comment" : "",
      "Id" : "<missing>",
      "Created" : "2018-12-28T23:29:38.226681736Z",
      "CreatedBy" : "/bin/sh -c #(nop)  CMD [\"bash\"]"
   },
   {
      "Size" : 10780911,
      "Comment" : "",
      "Tags" : [],
      "CreatedBy" : "/bin/sh -c apt-get update && apt-get install -y --no-install-recommends \t\tca-certificates \t\tcurl \t\tnetbase \t\twget \t&& rm -rf /var/lib/apt/lists/*",
      "Created" : "2018-12-29T00:04:28.920875483Z",
      "Id" : "sha256:c2677faec825930a8844845f55454ee0495ceb5bea9fc904d5b3125de863dc1d"
   },
   {
      "Comment" : "",
      "Tags" : [],
      "Size" : 4340024,
      "CreatedBy" : "/bin/sh -c set -ex; \tif ! command -v gpg > /dev/null; then \t\tapt-get update; \t\tapt-get install -y --no-install-recommends \t\t\tgnupg \t\t\tdirmngr \t\t; \t\trm -rf /var/lib/apt/lists/*; \tfi",
      "Created" : "2018-12-29T00:04:34.642152001Z",
      "Id" : "sha256:fcce419a96b1219a265bf7a933d66b585a6f8d73448533f3833c73ad49fb5e88"
   },
   {
      "Size" : 50062697,
      "Tags" : [],
      "Comment" : "",
      "Id" : "sha256:045b51e26e750443c84216071a1367a7aae0b76245800629dc04934628b4b1ea",
      "CreatedBy" : "/bin/sh -c apt-get update && apt-get install -y --no-install-recommends \t\tbzr \t\tgit \t\tmercurial \t\topenssh-client \t\tsubversion \t\t\t\tprocps \t&& rm -rf /var/lib/apt/lists/*",
      "Created" : "2018-12-29T00:04:59.676112605Z"
   },
 ... <truncated for brevity> ...
   {
      "Tags" : [],
      "Comment" : "",
      "Size" : 0,
      "Id" : "<missing>",
      "CreatedBy" : "/bin/sh -c #(nop)  ENTRYPOINT [\"/sbin/tini\" \"--\" \"/usr/local/bin/jenkins.sh\"]",
      "Created" : "2019-01-21T08:56:30.737221895Z"
   },
   {
      "Size" : 1549,
      "Tags" : [],
      "Comment" : "",
      "Id" : "sha256:283cd3aba8691a3b9d22d923de66243b105758e74de7d9469fe55a6a58aeee30",
      "Created" : "2019-01-21T08:56:32.015667468Z",
      "CreatedBy" : "/bin/sh -c #(nop) COPY file:f97999fac8a63cf8b635a54ea84a2bc95ae3da4d81ab55267c92b28b502d8812 in /usr/local/bin/plugins.sh "
   },
   {
      "Comment" : "",
      "Tags" : [],
      "Size" : 3079,
      "Created" : "2019-01-21T08:56:33.158854485Z",
      "CreatedBy" : "/bin/sh -c #(nop) COPY file:3a15c25533fd87983edc33758f62af7b543ccc3ce9dd570e473eb0702f5f298e in /usr/local/bin/install-plugins.sh ",
      "Id" : "sha256:b0ce8ab5a5a7da5d762f25af970f4423b98437a8318cb9852c3f21354cbf914f"
   }
]
```

NOTE: Anchore processes the leading /bin/sh commands, so you do not have to include those in any trigger param config if using the docker history output.

#### The actual_dockerfile_only Parameter

The actual vs history impacts the semantics of the dockerfile gate's triggers. To allow explicit control of the differences, most triggers in this gate includes a parameter: actual_dockerfile_only that if set to true or false will ensure the trigger check is only done on the source of data specified. If actual_dockerfile_only = true, then the trigger will evaluate only if an actual dockerfile is available for the image and will skip evaluation if not. If actual_dockerfile_only is false or omitted, then the trigger will run on the actual dockerfile if available, or the history data if the dockerfile was not provided.

#### Differences in data between Docker History and actual Dockerfile

With Actual Dockerfile:

1. FROM line is preserved, so the parent tag of the image is easily available
2. Instruction checks are all against instructions created during the build for that exact image, not any parent images
    1. When the actual_dockerfile_only parameter is set to true, all instructions from the parent image are ignored in policy processing. This may have some unexpected consequences depending on how your images are structured and layered (e.g. golden base images that establish common patterns of volumes, labels, healthchecks)
3. COPY/ADD instructions will maintain the actual values used
4. Multistage-builds in that specific dockerfile will be visible with multiple FROM lines in the output


With Docker History data, when no dockerfile is provided:

1. FROM line is not accurate, and will nearly always default to 'FROM scratch'
2. Instructions are processed from all layers in the image
3. COPY and ADD instructions are transformed into SHAs rather than the actual file path/name used at build-time
4. Multi-stage builds are not tracked with multiple FROM lines, only the copy operations between the phases

### Trigger: instruction

This trigger evaluates instructions found in the "dockerfile"

Supported Directives/Instructions (as of Anchore Engine v.0.3.2):

#### Parameters

actual_dockerfile_only (optional): See above

instruction: The dockerfile instruction to check against. One of: 

- ADD
- ARG
- COPY
- CMD
- ENTRYPOINT
- ENV
- EXPOSE
- FROM
- HEALTHCHECK
- LABEL
- MAINTAINER
- ONBUILD
- USER
- RUN
- SHELL
- STOPSIGNAL
- VOLUME
- WORKDIR

*check:* The comparison/evaluation to perform. One of: =, != , exists, not_exists, like, not_like, in, not_in.

*value* (optional): A string value to compare against, if applicable

#### Examples

1. Ensure an image has a HEALTHCHECK defined in the image (warn if not found): 

```
{
  "gate": "dockerfile",
  "trigger": "instruction", 
  "action": "warn", 
  "parameters": [ 
    {
      "name": "instruction",
      "value": "HEALTHCHECK"
    }, 
    {
      "name": "check",
      "value": "not_exists"
    }
  ]
}
```


2. Check for AWS environment variables set: 

```
{
  "gate": "dockerfile",
  "trigger": "instruction", 
  "action": "stop", 
  "parameters": [ 
    {
      "name": "instruction",
      "value": "ENV"
    }, 
    {
      "name": "check",
      "value": "like"
    },
    {
      "name": "value",
      "value": "AWS_.*KEY"
    }
  ]
}
```

### Trigger: effective_user

This trigger processes all `USER` directives in the dockerfile or history to determine which user will be used to run the container by default (assuming no user is set explicitly at runtime). The detected value is then subject to a whitelist or blacklist filter depending on the configured parameters. Typically, this is used for blacklisting the root user.

#### Parameters

*actual_dockerfile_only* (optional): See above

*users:* A string with a comma delimited list of username to check for

*type:* The type of check to perform. One of: 'blacklist' or 'whitelist'. This determines how the value of the 'users' parameter is interpreted.

#### Examples

1. Blacklist root user

```
{
  "gate": "dockerfile",
  "trigger": "effective_user", 
  "action": "stop", 
  "parameters": [ 
    {
      "name": "users",
      "value": "root"
    }, 
    {
      "name": "type",
      "value": "blacklist"
    }
  ]
}
```

2. Blacklist root user but only if set in actual dockerfile, not inherited from parent image 

```
{
  "gate": "dockerfile",
  "trigger": "effective_user", 
  "action": "stop", 
  "parameters": [ 
    {
      "name": "users",
      "value": "root"
    }, 
    {
      "name": "type",
      "value": "blacklist"
    },
    {
      "name": "actual_dockerfile_only",
      "value": "true"
    }
  ]
}
```

3. Warn if the user is not either "nginx" or "jenkins"

```
{
  "gate": "dockerfile",
  "trigger": "effective_user", 
  "action": "warn", 
  "parameters": [ 
    {
      "name": "users",
      "value": "nginx,jenkins"
    }, 
    {
      "name": "type",
      "value": "whitelist"
    }
  ]
}
```

### Trigger: exposed_ports

This trigger processes the set of `EXPOSE` directives in the dockerfile/history to determine the set of ports that are defined to be exposed (since it can span multiple directives). It performs checks on that set to blacklist/whitelist them based on parameter settings.

#### Parameters

*actual_dockerfile_only* (optional): See above

*ports:* String of comma delimited port numbers to be checked

*type:* The type of check to perform. One of: 'blacklist' or 'whitelist'. This determines how the value of the 'users' parameter is interpreted

#### Examples

1. Allow only ports 80 and 443. Trigger will fire on any port defined to be exposed that is not 80 or 443

```
{
  "gate": "dockerfile",
  "trigger": "exposed_ports", 
  "action": "warn", 
  "parameters": [ 
    {
      "name": "ports",
      "value": "80,443"
    }, 
    {
      "name": "type",
      "value": "whitelist"
    }
  ]
}
```

2. Blacklist ports 21 (ftp), 22 (ssh), and 53 (dns) . Trigger will fire a match on ports 21, 22, 53 if found in EXPOSE directives

```
{
  "gate": "dockerfile",
  "trigger": "exposed_ports", 
  "action": "warn", 
  "parameters": [ 
    {
      "name": "ports",
      "value": "21,22,53"
    }, 
    {
      "name": "type",
      "value": "blacklist"
    }
  ]
}
```

### Trigger: no_dockerfile_provided

This trigger allows checks on the way the image was added, firing if the dockerfile was not explicitly provided at analysis time. This is useful in identifying and qualifying other trigger matches.

#### Parameters
None

#### Examples

1. Raise a warning if no dockerfile was provided at analysis time 

```
{
  "gate": "dockerfile",
  "trigger": "no_dockerfile_provided", 
  "action": "warn", 
  "parameters": [] 
}
```