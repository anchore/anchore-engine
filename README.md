# Anchore Engine

For the most up-to-date information on Anchore Engine, Anchore CLI, and other Anchore software, please refer to the [Anchore Documentation](https://anchore.freshdesk.com/support/home)

The Anchore Engine is an open source project that provides a centralized service for inspection, analysis and certification of container images. The Anchore engine is provided as a Docker container image that can be run standalone (a docker-compose file is provided), or on an orchestration platform such as Kubernetes, Docker Swarm, Rancher or Amazon ECS.

The Anchore engine can be accessed directly through a RESTful API or via the Anchore [CLI](https://github.com/anchore/anchore-cli).

Using the Anchore Engine, container images can be downloaded from Docker V2 compatible container registries, and then evaluated against user defined policies. The Anchore Engine can integrate with Anchore's [Navigator](https://anchore.io) service, allowing you to define policies and whitelists using a graphical editor that are automatically synchronized to the Anchore Engine.

## Installation

The Anchore Engine is distributed as a [Docker Image](https://hub.docker.com/r/anchore/anchore-engine/) available from DockerHub.

A PostgreSQL database is required to provide persistent storage for the Anchore Engine.

The Anchore Engine requires a single volume used to store configuration information and optionally certificates for TLS.

## Configuration

1. Create a directory to expose as a volume containing Anchore Engine configuration files (we use /root/aevolume here but you can use non-root paths and adjust the samepl config/docker-compose configuration files accordingly)

`mkdir -p ~/aevolume/config`

2. Download the sample configuration file [config.yaml](https://raw.githubusercontent.com/anchore/anchore-engine/master/scripts/docker-compose/config.yaml) from the scripts/docker-compose directory of the github project and save into the directory created in step #1

`cd ~/aevolume/config && curl -O https://raw.githubusercontent.com/anchore/anchore-engine/master/scripts/docker-compose/config.yaml && cd -`

3. Edit the config.yaml file to specify your email and password for the admin user.

```
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
```

4. Make other changes to config.yaml to enable additional features or tune to your environment (not required for basic usage)

5. Create a directory to expose as a volume for PostgreSQL data

`mkdir -p ~/aevolume/db/`

## Running Anchore Engine using Docker Compose
To run Anchore Engine using Docker Compose the following additional steps must be performed:

1. Change to the directory in which you have created the config and db subdirectories.

`cd ~/aevolume`

2. Download the [docker-compose.yaml](https://raw.githubusercontent.com/anchore/anchore-engine/master/scripts/docker-compose/docker-compose.yaml) file from the scripts/docker-compose directory of the github project.

`curl -O https://raw.githubusercontent.com/anchore/anchore-engine/master/scripts/docker-compose/docker-compose.yaml`

3. Run `docker-compose pull` to instruct Docker to download the required container images from DockerHub.

4. To start Anchore Engine run `docker-compose up -d`

5. To stop the Anchore Engine run `docker-compose down`

## Getting Started using the CLI

The [Anchore CLI](https://github.com/anchore/anchore-cli) is an easy way to control the Anchore Engine.

The Anchore CLI can be installed using the Python pip command. See [Anchore CLI](https://github.com/anchore/anchore-cli) for instructions.


By default the Anchore CLI will try to connect to the Anchore Engine at http://localhost/v1 with no authentication.
The username, password and URL for the server can be passed to the Anchore CLI as command line arguments.
These values are the ones defined in your `~/aevolume/config/config.yaml`.

    --u   TEXT   Username     eg. admin
    --p   TEXT   Password     eg. foobar
    --url TEXT   Service URL  eg. http://localhost:8228/v1

Rather than passing these parameters for every call to the cli they can be set as environment variables.

    ANCHORE_CLI_URL=http://myserver.example.com:8228/v1
    ANCHORE_CLI_USER=admin
    ANCHORE_CLI_PASS=foobar


Add an image to the Anchore Engine:

    anchore-cli image add docker.io/library/debian:latest

List images analyzed by the Anchore Engine:

    anchore-cli image list

Get a specific image and see when its status goes to analyzed:

    anchore-cli image get docker.io/library/debian:latest

Obtain the results of the vulnerability scan on an image:

    anchore-cli image vuln docker.io/library/debian:latest os

List operating system packages present in an image:

    anchore-cli image content docker.io/library/debian:latest os

Subscribe to receive webhook notifications when new CVEs are added to an update:

    anchore-cli subscription activate vuln_update docker.io/library/debian:latest

## API
Each service implements its own API, and all APIs are defined in Swagger/OpenAPI spec. You can find each in the _anchore_engine/services/\<servicename\>/api/swagger_ directory.

For the external API definition (the user-facing service), see [External API Spec](https://github.com/anchore/anchore-engine/blob/master/anchore_engine/services/apiext/swagger/swagger.yaml).

## More Information

For further details on use of the Anchore CLI with the Anchore Engine please refer to the [Anchore Engine Documentation](https://anchore.freshdesk.com/support/home)

