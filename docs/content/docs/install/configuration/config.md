---
title: "Configuration"
linkTitle: "General"
weight: 1
---

## Initial Configuration

A single configuration file config.yaml is required to run the Anchore Engine - by default, this file is embedded in the anchore-engine container image, located in /config/config.yaml.  The default configuration file is provided as a way to get started, which is functional out of the box, without modification, when combined with either the Helm method or docker-compose method of installing anchore-engine.  The default configuration is set up to use environment variable substitutions so that configuration values can be controlled by setting the corresponding environment variables at deployment time (see [Using Environment Variables in Anchore]({{< ref "using_env_vars" >}}).  To review the embedded configuration file settings, see the [default config.yaml on github](https://github.com/anchore/anchore-engine/blob/master/conf/default_config.yaml) which is populated with several environment variables (all starting with ANCHORE_), the [example docker-compose.yaml on github](https://github.com/anchore/anchore-engine/blob/master/docker-compose.yaml) which includes several site-specific environment variable default settings, and the [anchore engine Dockerfile on github](https://github.com/anchore/anchore-engine/tree/master/Dockerfile) which sets baseline environment variable settings.

Each environment variable (starting with ANCHORE_) in the default config.yaml is set (either the baseline as set in the Dockerfile, or an override in docker-compose or Helm) to ensure that the system comes up with a fully populated configuration.

Some examples of useful initial settings follow.

* Default admin credentials: by default, the **admin** has a password of **foobar** and email **admin@myanchore**, set using the **ANCHORE_ADMIN_PASSWORD** and **ANCHORE_ADMIN_EMAIL** environment variables, respectively, in the Dockerfile.  To change these settings, simply add overrides for **ANCHORE_ADMIN_PASSWORD** and **ANCHORE_ADMIN_EMAIL** environment variables, set to your preferred values prior to deploying anchore engine.
```YAML
default_admin_password: '${ANCHORE_ADMIN_PASSWORD}'
default_admin_email: '${ANCHORE_ADMIN_EMAIL}'
```

* Log level: anchore engine is configured to run at the INFO log level by default.  The full set of options are FATAL, ERROR, WARN, INFO, and DEBUG (in ascending order of log output verbosity).  To set the log level of anchore engine services, add an override for **ANCHORE_LOG_LEVEL** prior to deploying anchore engine.
```YAML
log_level: '${ANCHORE_LOG_LEVEL}'
```

* Postgres Database: the anchore engine requires access to a PostgreSQL database to operate. The database can be run as a container with a persistent volume or outside of your container environment (which is set up automatically if the example docker-compose.yaml is used). If you wish to use an external Postgres Database, the elements of the connection string in the config.yaml can be specified as environment variable overrides. The default configuration is set up to connect to a postgres DB that is deployed alongside the engine services when using docker-compose or Helm, to the internal host **anchore-db** on port **5432** using username **postgres** with password **mysecretpassword** and db **postgres**. If an external database service is being used then you will need to provide the use, password, host, port and DB name environment variables, as shown below. 
```YAML
db_connect: 'postgresql://${ANCHORE_DB_USER}:${ANCHORE_DB_PASSWORD}@${ANCHORE_DB_HOST}:${ANCHORE_DB_PORT}/${ANCHORE_DB_NAME}'
```

## Manual Configuration File Override
While anchore engine is set up to run out of the box without modifications, and many useful values can be overriden using environment variables as described above, one can always opt to have full control over the configuration by providing a config.yaml file explicitly, typically by generating the file and making it available from an external mount/configmap/etc. at deployment time.  A good method to start if you wish to provide your own config.yaml is to extract the default config.yaml from the anchore engine container image, modify it, and then override the embedded /config/config.yaml at deployment time.  For example:

* Extract the default config file from the anchore-engine container image:

```
# docker pull docker.io/anchore/anchore-engine:latest
# docker create --name ae docker.io/anchore/anchore-engine:latest
# docker cp ae:/config/config.yaml ./my_config.yaml
# docker rm ae
```

* Modify the configuration file to your liking.

* Set up your deployment to override the embedded **/config/config.yaml** at run time (below example shows how to achieve this with docker-compose).  Edit the docker-compose.yaml to include a volume mount that mounts your **my_config.yaml** over the embedded **/config/config.yaml**, resulting in a volume section for each anchore engine service definition.

```YAML
...
  engine-api:
...
    volumes:
     - /path/to/my_config.yaml:/config/config.yaml:z
...
  engine-catalog:
...
    volumes:
     - /path/to/my_config.yaml:/config/config.yaml:z
...
  engine-simpleq:
...
    volumes:
     - /path/to/my_config.yaml:/config/config.yaml:z
...
  engine-policy-engine:
...
    volumes:
     - /path/to/my_config.yaml:/config/config.yaml:z
...
  engine-analyzer:
...
    volumes:
     - /path/to/my_config.yaml:/config/config.yaml:z
...
```
Now, each service will come up with your external **my_config.yaml** mounted over the embedded **/config/config.yaml**.





