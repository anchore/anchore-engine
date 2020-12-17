---
title: "Upgrading Anchore Engine"
linkTitle: "Upgrade"
weight: 6
---

The anchore-engine is distributed as a [Docker Image](https://hub.docker.com/r/anchore/anchore-engine), which is comprised of smaller micro-services that can be deployed in a single container or scaled out to handle load.

The latest version of the anchore-engine image will be tagged with both the latest tag and a version number. For example **latest** and **v0.7.1**.

To retrieve the version of a running anchore-engine the system status command can be run.

```
# anchore-cli system status
...
...
...

Engine DB Version: 0.0.13
Engine Code Version: 0.7.0
```

In this example the anchore-engine is version 0.7.0 and the database schema is version 0.0.13.  In cases where the database schema is changed between releases of the anchore-engine, the engine will upgrade the database schema at launch.

### Pre-upgrade Procedure

Prior to upgrading anchore-engine, we highly recommend performing a database backup/snapshot by stopping your anchore-engine installation, and backing up the anchore engine database in its entirely.  There is no automatic downgrade capability in anchore-engine, thus the only way to downgrade after an upgrade (whether it succeeds or fails) is to restore your database contents to a state from a prior version of anchore-engine, and explicitly run the compatible version of anchore-engine against the corresponding database contents. 

Whether or not you wish to have the ability to downgrade, we recommend backing up your anchore-engine database prior to upgrading the software as a best practice.

### Upgrade Procedure (for deployments using Helm)

For the latest upgrade instructions using the Helm chart, please refer to the official Anchore Helm Chart documentation

- [Anchore Helm Chart](https://github.com/anchore/anchore-charts/blob/master/stable/anchore-engine)


### Upgrade Procedure (example with docker-compose)

1. Stop all running instances of the Anchore Engine
```
# docker-compose down
```

2. Make a copy of your original docker-compose.yaml file as backup
```
# cp docker-compose.yaml docker.compose.yaml.backup
```

3. Pull the desired version of anchore-engine container image
```
# docker pull docker.io/anchore/anchore-engine:v0.7.1
```

4. Download the latest docker-compose.yaml
```
# curl https://docs.anchore.com/current/docs/quickstart/docker-compose.yaml
```

5. Review the latest docker-compose.yaml and merge any edits/changes from your original docker-compose.yaml.backup to the latest docker-compose.yaml

6. Restart the Anchore Engine containers
```
# docker-compose up -d
```

To monitor the progress of your upgrade, you can watch the docker logs from your anchore-engine container, where you should see some initial output indicating whether or not an upgrade is needed or being performed, followed by the regular anchore-engine log output.

```
# docker-compose logs -f anchore-engine
```

Once completed, you can review the new state of your engine to verify the new version is running using the regular system status command.

```
# anchore-cli system status
...
...
...

Engine DB Version: 0.0.13
Engine Code Version: 0.7.1
```

### Advanced / Manual Upgrade Procedure

If for any reason the automated upgrade fails, or you would like to perform the upgrade of the anchore database manually, you can use the following (general) procedure.  This should only be done by advanced operators after backing up the anchore database, ensuring that the anchore database is up and running, and that all running anchore-engine components are stopped.

- Install the desired anchore-engine container manually
- Run the anchore-engine container but override the entrypoint to run an interactive shell instead of the default 'anchore-manager service start' entrypoint command
- Manually execute the database upgrade command, using the appropriate db_connect string.  For example, if using Postgres, the db_connect string will look like `postgresql://$ANCHORE_DB_HOST/$ANCHORE_DB_NAME?user=$ANCHORE_DB_USER&password=$ANCHORE_DB_PASSWORD`

```
# anchore-manager db --db-connect "postgresql://$ANCHORE_DB_HOST/$ANCHORE_DB_NAME?user=$ANCHORE_DB_USER&password=$ANCHORE_DB_PASSWORD" upgrade
[MainThread] [anchore_manager.cli.utils/connect_database()] [INFO] DB params: {"db_connect_args": {"timeout": 86400, "ssl": false}, "db_pool_size": 30, "db_pool_max_overflow": 100}
[MainThread] [anchore_manager.cli.utils/connect_database()] [INFO] DB connection configured: True
[MainThread] [anchore_manager.cli.utils/connect_database()] [INFO] DB attempting to connect...
[MainThread] [anchore_manager.cli.utils/connect_database()] [INFO] DB connected: True
...
...
```
- The output will indicate whether or not a DB upgrade is needed, prompt for confirmation if it is, and will display upgrade progress output before completing.
