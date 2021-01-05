---
title: "Accessing the Anchore Engine API"
linkTitle: "Using the API"
weight: 3
---

## Introduction

The Anchore Engine API is documented using the OpenAPI Specification (Swagger) and the source for the latest development version can be found in GitHub in [swagger.yaml](https://github.com/anchore/anchore-engine/blob/master/anchore_engine/services/apiext/swagger/swagger.yaml) document within the external API service.  There are also a variety of ways in which the API specification can be accessed.

### Online

You can browse latest stable the Anchore API specification [here](./specs/swagger.yaml)

### Local Swagger JSON

The JSON definition for the API specification for your specific instance of Anchore can be downloaded from a running Anchore Engine service at the following URI:

http://{servername:port}/v1/swagger.json

e.g.

http://localhost:8228/v1/swagger.json

### Local Swagger UI

1. When using docker-compose: Uncomment the following section at the bottom of the docker-compose.yaml file:

    ```
    #  # Uncomment this section to run a swagger UI service, for inspecting and interacting with the anchore engine API via a browser (http://localhost:8080 by default, change if needed in both sections below)
    #  swagger-ui-nginx:
    #    image: docker.io/nginx:latest
    #    depends_on:
    #      - api
    #      - swagger-ui
    #    ports:
    #      - "8080:8080"
    #    volumes:
    #      - ./anchore-swaggerui-nginx.conf:/etc/nginx/nginx.conf:z
    #    logging:
    #      driver: "json-file"
    #      options:
    #        max-size: 100m
    #  swagger-ui:
    #    image: docker.io/swaggerapi/swagger-ui
    #    environment:
    #      - URL=http://localhost:8080/v1/swagger.json
    #    logging:
    #      driver: "json-file"
    #      options:
    #        max-size: 100m
    ```

1. Download the nginx configuration into the same directory as the docker-compose.yaml file, with name _anchore-swaggerui-nginx.conf_

    ```
    curl -O https://engine.anchore.io/docs/quickstart/anchore-swaggerui-nginx.conf
    docker-compose up -d
    ```

    You should see a new container started and can access prometheus via your browser on `http://localhost:8080/ui/`

~
~
~
~
~
~
