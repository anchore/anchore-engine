# Anchore Engine

The Anchore Engine is an open source project that provides a centralized service for inspection, analysis and certification of container images. The Anchore engine is provide as a Docker container image that can be run standalone or on an orchestration platform such as Kubernetes, Docker Swarm, Rancher or Amazon ECS.

The Anchore engine can be accessed directly through a RESTful API or via the Anchore [CLI](https://github.com/anchore/anchore-cli).  

Using the Anchore Engine, container images can be downloaded from Docker V2 compatible container registries, analyzed and evaluated against user defined policies. The Anchore Engine can integrate with Anchore's [Navigator](https://anchore.io) service allowing you to define policies and whitelists using a graphical editor that are automatically synchronized to the Anchore Engine. 

## Installation

The Anchore Engine is distributed as a [Docker Image](https://hub.docker.com/r/anchore/anchore-engine/) available from DockerHub. 

A PostgreSQL database is required to provide persistent storage for the Anchore Engine.

The Anchore Engine requires a single volume used to store configuration information and optionally certificates for TLS.

Anchore Engine can be run manually, using Docker Compose, Kubernetes or any container orchestration platform.

## Configuration 

1. Create a directory to expose as a volume containing Anchore Engine configuration files

`mkdir -p /root/aevolume/config`

2. Download the sample configuration file [config.yaml](https://github.com/anchore/anchore-engine/blob/master/scripts/docker-compose/config.yaml) from the scripts/docker-compose directory of the github project and save into the directory created in step #1

3. Edit the config.yaml file to specify your email and password for the admin user.
If you have a login for the [Anchore Navigator](https://anchore.io) uncomment the configuration options in the external_service_auths section and add your username and password to the auth parameter. This will configure the Anchore Engine to automatically synchronize policy bundles containing policies, whitelists and mappings from the Anchore Navigator.

`
    
    credentials:
      default_user: 'admin'
      users:
         admin:
           password: 'foobar'
           email: 'admin@myemail.com'
           external_service_auths:
           #  anchoreio:
           #    anchorecli:
           #      auth: 'myanchoreiouser:myanchoreiopass'
           #auto_policy_sync: True
 `  

4. Create a directory to expose as a volume for PostgreSQL data

`mkdir -p /root/aevolume/db/`


## Running Anchore Engine using Docker Compose  
To run Anchore Engine using Docker Compose the following additional steps must be performed:

1. Download the [docker-compose.yaml](https://github.com/anchore/anchore-engine/blob/master/scripts/docker-compose/docker-compose.yaml) file from the scripts/docker-compose directory of the github project.

2. [Optional] If running on Red Hat Enterprise Linux or CentOS with SELinux enabled:
The anchore-engine container needs to be run in in privileged mode to allow access to the Docker Socket.
Edit docker-compose.yaml to remove the comment (#) from the `privileged: true` configuration parameter.

3. Run 'docker-compose pull' to instruct Docker to download the required container images from DockerHub.

4. To start Anchore Engine run 'docker-compose up -d' 

5. To stop the Anchore Engine run `docker-compose down`


## Getting Started


Anchore Engine is using the [Anchore CLI](https://github.com/anchore/anchore-cli).

The Anchore CLI can be installed using the Python pip command. See [Anchore CLI installation ](https://github.com/anchore/anchore-engine/wiki/Installing-Anchore-CLI) instructions.


By default the Anchore CLI will try to connect to the Anchore Engine at http://localhost/v1 with no authentication.
The username, password and URL for the server can be passed to the Anchore CLI as command line arguments.

    --u   TEXT   Username     eg. admin
    --p   TEXT   Password     eg. foobar
    --url TEXT   Service URL  eg. http://localhost:8228/v1
   
Rather than passing these parameters for every call to the cli they can be stores as environment variables.

    ANCHORE_CLI_URL=http://myserver.example.com:8228/v1
    ANCHORE_CLI_USER=admin
    ANCHORE_CLI_PASS=foobar


Add an image to the Anchore Engine

    anchore-cli image add docker.io/library/debian:latest
List images analyzed by the Anchore Engine

    anchore-cli image list
Get a specific image and see when its status goes to analyzed

    anchore-cli image get docker.io/library/debian:latest
Perform a vulnerability scan on an image

    anchore-cli image vuln docker.io/library/debian:latest os

List operating system packages present in an image

    anchore-cli image content docker.io/library/debian:latest os
Subscribe to receive webhook notifications when new CVEs are added to an update

    anchore-cli subscription activate vuln_update docker.io/library/debian:latest


## More Information

For further details on use of the Anchore CLI with the Anchore Engine please refer to the Anchore Engine Wiki



