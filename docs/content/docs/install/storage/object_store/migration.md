---
title: "Migrating Data to New Drivers"
linkTitle: "Changing Drivers"
weight: 1
---

### Overview

To cleanly migrate data from one archive driver to another, Anchore Engine includes some tooling that automates the process in the 'anchore-manager' tool packaged with the system.

The migration process is an offline process; Anchore Engine is not designed to handle an online migration. 

For the migration process you will need:

1. The original config.yaml used by the services already, if services are split out or using different config.yaml for different services, you need the config.yaml used by the catalog services
2. An updated config.yaml (named dest-config.yaml in this example), with the archive driver section of the catalog service config set to the config you want to migrate *to*
3. The db connection string from config.yaml, this is needed by the anchore-manager script directly
4. Credentials and resources (bucket etc) for the destination of the migration

At a high-level the process is:

1. Shutdown all anchore engine services and components. The system should be fully offline, but the database must be online and available. For a docker-compose install, this is achieved by simply stopping the engine container, but not deleting it.
2. Prepare a new config.yaml that includes the new driver configuration for the destination of the migration (dest-config.yaml) in the same location as the existing config.yaml
3. Test the new dest-config.yaml to ensure correct configuration
4. Run the migration
5. Get coffee... this could take a while if you have a lot of analysis data
6. When complete, view the results
7. Ensure the dest-config.yaml is in place for all the components as config.yaml
8. Start anchore-engine

### Migration Example Using Docker Compose Deployed Anchore Engine

The following is an example migration for an anchore-engine deployed via docker-compose on a single host with a local postgresql container--basically the example used in 'Installing Anchore Engine' documents. At the end of this section, we'll cover the caveats and things to watch for a multi-node install of anchore engine.

This process requires that you run the command in a location that has access to both the source archive driver configuration and the new archive driver configuration.

#### Step 1: Shutdown all services

All services should be stopped, but the postgresql db must still be available and running.

`docker-compose stop anchore-engine`

#### Step 2: Prepare a new config.yaml

Both the original and new configurations are needed, so create a copy and update the archive driver section to the configuration you want to migrate to

```
cd config
cp config.yaml dest-config.yaml
<edit dest-config.yaml>
```

#### Step 3: Test the destination config

Assuming that config is `dest-config.yaml`:

```
[user@host aevolume]$ docker-compose run anchore-engine /bin/bash
[root@3209ad44d7bb ~]# anchore-manager objectstorage --db-connect ${db} check /config/dest-config.yaml 
[MainThread] [anchore_manager.cli.utils/connect_database()] [INFO] DB params: {"db_pool_size": 30, "db_connect": "postgresql+pg8000://postgres:postgres.dev@postgres-dev:5432/postgres", "db_connect_args": {"ssl": false, "connect_timeout": 120, "timeout": 30}, "db_pool_max_overflow": 100}
[MainThread] [anchore_manager.cli.utils/connect_database()] [INFO] DB connection configured: True
[MainThread] [anchore_manager.cli.utils/connect_database()] [INFO] DB attempting to connect...
[MainThread] [anchore_manager.cli.utils/connect_database()] [INFO] DB connected: True
[MainThread] [anchore_manager.cli.objectstorage/check()] [INFO] Using config file /config/dest-config.yaml
[MainThread] [anchore_engine.subsys.object_store.operations/initialize()] [INFO] Archive initialization complete
[MainThread] [anchore_manager.cli.objectstorage/check()] [INFO] Checking existence of test document with user_id = test, bucket = anchorecliconfigtest and archive_id = cliconfigtest
[MainThread] [anchore_manager.cli.objectstorage/check()] [INFO] Creating test document with user_id = test, bucket = anchorecliconfigtest and archive_id = cliconfigtest
[MainThread] [anchore_manager.cli.objectstorage/check()] [INFO] Checking document fetch
[MainThread] [anchore_manager.cli.objectstorage/check()] [INFO] Removing test object
[MainThread] [anchore_manager.cli.objectstorage/check()] [INFO] Archive config check completed successfully
```

#### Step 3a: Test the current config.yaml
 
If you are running the migration for a different location than one of the anchore engine containers

Same as above but using `/config/config.yaml` as the input to check (skipped in this instance since we're running the migration from the same container)

#### Step 4: Run the Migration

By default, the migration process will remove data from the source once it has confirmed it has been copied to the destination and the metadata has been updated in the anchore db. To skip the deletion on the source, use the '--nodelete' option. it is the safest option, but if you use it, you are responsible for removing the data later.

```
[root@3209ad44d7bb ~]# anchore-manager objectstorage --db-connect ${db} migrate /config/config.yaml /config/dest-config.yaml 
[MainThread] [anchore_manager.cli.utils/connect_database()] [INFO] DB params: {"db_pool_size": 30, "db_connect": "postgresql+pg8000://postgres:postgres.dev@postgres-dev:5432/postgres", "db_connect_args": {"ssl": false, "connect_timeout": 120, "timeout": 30}, "db_pool_max_overflow": 100}
[MainThread] [anchore_manager.cli.utils/connect_database()] [INFO] DB connection configured: True
[MainThread] [anchore_manager.cli.utils/connect_database()] [INFO] DB attempting to connect...
[MainThread] [anchore_manager.cli.utils/connect_database()] [INFO] DB connected: True
[MainThread] [anchore_manager.cli.objectstorage/migrate()] [INFO] Loading configs
[MainThread] [anchore_manager.cli.objectstorage/migrate()] [INFO] Migration from config: {
  "storage_driver": {
    "config": {}, 
    "name": "db"
  }, 
  "compression": {
    "enabled": false, 
    "min_size_kbytes": 100
  }
}
[MainThread] [anchore_manager.cli.objectstorage/migrate()] [INFO] Migration to config: {
  "storage_driver": {
    "config": {
      "access_key": "9EB92C7W61YPFQ6QLDOU", 
      "create_bucket": true, 
      "url": "http://minio-ephemeral-test:9000/", 
      "region": false, 
      "bucket": "anchore-engine-testing", 
      "prefix": "internaltest", 
      "secret_key": "TuHo2UbBx+amD3YiCeidy+R3q82MPTPiyd+dlW+s"
    }, 
    "name": "s3"
  }, 
  "compression": {
    "enabled": true, 
    "min_size_kbytes": 100
  }
}
Performing this operation requires *all* anchore-engine services to be stopped - proceed? (y/N)y
[MainThread] [anchore_engine.subsys.object_store.migration/initiate_migration()] [INFO] Initializing migration from {'storage_driver': {'config': {}, 'name': 'db'}, 'compression': {'enabled': False, 'min_size_kbytes': 100}} to {'storage_driver': {'config': {'access_key': '9EB92C7W61YPFQ6QLDOU', 'create_bucket': True, 'url': 'http://minio-ephemeral-test:9000/', 'region': False, 'bucket': 'anchore-engine-testing', 'prefix': 'internaltest', 'secret_key': 'TuHo2UbBx+amD3YiCeidy+R3q82MPTPiyd+dlW+s'}, 'name': 's3'}, 'compression': {'enabled': True, 'min_size_kbytes': 100}}
[MainThread] [anchore_engine.subsys.object_store.migration/migration_context()] [INFO] Initializing source object_store: {'storage_driver': {'config': {}, 'name': 'db'}, 'compression': {'enabled': False, 'min_size_kbytes': 100}}
[MainThread] [anchore_engine.subsys.object_store.migration/migration_context()] [INFO] Initializing dest object_store: {'storage_driver': {'config': {'access_key': '9EB92C7W61YPFQ6QLDOU', 'create_bucket': True, 'url': 'http://minio-ephemeral-test:9000/', 'region': False, 'bucket': 'anchore-engine-testing', 'prefix': 'internaltest', 'secret_key': 'TuHo2UbBx+amD3YiCeidy+R3q82MPTPiyd+dlW+s'}, 'name': 's3'}, 'compression': {'enabled': True, 'min_size_kbytes': 100}}
[MainThread] [anchore_engine.subsys.object_store.migration/initiate_migration()] [INFO] Migration Task Id: 1
[MainThread] [anchore_engine.subsys.object_store.migration/initiate_migration()] [INFO] Entering main migration loop
[MainThread] [anchore_engine.subsys.object_store.migration/initiate_migration()] [INFO] Migrating 7 documents
[MainThread] [anchore_engine.subsys.object_store.migration/initiate_migration()] [INFO] Deleting document on source after successful migration to destination. Src = db://admin/policy_bundles/2c53a13c-1765-11e8-82ef-23527761d060
[MainThread] [anchore_engine.subsys.object_store.migration/initiate_migration()] [INFO] Deleting document on source after successful migration to destination. Src = db://admin/manifest_data/sha256:0873c923e00e0fd2ba78041bfb64a105e1ecb7678916d1f7776311e45bf5634b
[MainThread] [anchore_engine.subsys.object_store.migration/initiate_migration()] [INFO] Deleting document on source after successful migration to destination. Src = db://admin/analysis_data/sha256:0873c923e00e0fd2ba78041bfb64a105e1ecb7678916d1f7776311e45bf5634b
[MainThread] [anchore_engine.subsys.object_store.migration/initiate_migration()] [INFO] Deleting document on source after successful migration to destination. Src = db://admin/image_content_data/sha256:0873c923e00e0fd2ba78041bfb64a105e1ecb7678916d1f7776311e45bf5634b
[MainThread] [anchore_engine.subsys.object_store.migration/initiate_migration()] [INFO] Deleting document on source after successful migration to destination. Src = db://admin/manifest_data/sha256:a0cd2c88c5cc65499e959ac33c8ebab45f24e6348b48d8c34fd2308fcb0cc138
[MainThread] [anchore_engine.subsys.object_store.migration/initiate_migration()] [INFO] Deleting document on source after successful migration to destination. Src = db://admin/analysis_data/sha256:a0cd2c88c5cc65499e959ac33c8ebab45f24e6348b48d8c34fd2308fcb0cc138
[MainThread] [anchore_engine.subsys.object_store.migration/initiate_migration()] [INFO] Deleting document on source after successful migration to destination. Src = db://admin/image_content_data/sha256:a0cd2c88c5cc65499e959ac33c8ebab45f24e6348b48d8c34fd2308fcb0cc138
[MainThread] [anchore_engine.subsys.object_store.migration/initiate_migration()] [INFO] Migration result summary: {"last_state": "running", "executor_id": "3209ad44d7bb:37:139731996518208:", "archive_documents_migrated": 7, "last_updated": "2018-08-15T18:03:52.951364", "online_migration": null, "created_at": "2018-08-15T18:03:52.951354", "migrate_from_driver": "db", "archive_documents_to_migrate": 7, "state": "complete", "migrate_to_driver": "s3", "ended_at": "2018-08-15T18:03:53.720554", "started_at": "2018-08-15T18:03:52.949956", "type": "archivemigrationtask", "id": 1}
[MainThread] [anchore_manager.cli.objectstorage/migrate()] [INFO] After this migration, your anchore-engine config.yaml MUST have the following configuration options added before starting up again:
compression:
  enabled: true
  min_size_kbytes: 100
storage_driver:
  config:
    access_key: 9EB92C7W61YPFQ6QLDOU
    bucket: anchore-engine-testing
    create_bucket: true
    prefix: internaltest
    region: false
    secret_key: TuHo2UbBx+amD3YiCeidy+R3q82MPTPiyd+dlW+s
    url: http://minio-ephemeral-test:9000/
  name: s3
```

**Note:** If something goes wrong you can reverse the parameters of the migrate command to migrate back to the original configuration (e.g. ... migrate /config/dest-config.yaml /config/config.yaml)

#### Step 5: Get coffee!

The migration time will depend on the amount of data and the source and destination systems performance.

#### Step 6: View results summary

```
[root@3209ad44d7bb ~]# anchore-manager objectstorage --db-connect ${db} list-migrations
[MainThread] [anchore_manager.cli.utils/connect_database()] [INFO] DB params: {"db_pool_size": 30, "db_connect": "postgresql+pg8000://postgres:postgres.dev@postgres-dev:5432/postgres", "db_connect_args": {"ssl": false, "connect_timeout": 120, "timeout": 30}, "db_pool_max_overflow": 100}
[MainThread] [anchore_manager.cli.utils/connect_database()] [INFO] DB connection configured: True
[MainThread] [anchore_manager.cli.utils/connect_database()] [INFO] DB attempting to connect...
[MainThread] [anchore_manager.cli.utils/connect_database()] [INFO] DB connected: True
id         state                  start time                         end time                 from        to        migrated count        total to migrate               last updated               
1         complete        2018-08-15T18:03:52.949956        2018-08-15T18:03:53.720554         db         s3              7                      7                2018-08-15T18:03:53.724628   
```

This lists all migrations for the service and the number of objects migrated. If you've run multiple migrations you'll see multiple rows in this response.

### Step 7: Replace old config.yaml with updated dest-config.yaml

```
[root@3209ad44d7bb ~]# cp /config/config.yaml /config/config.old.yaml
[root@3209ad44d7bb ~]# cp /config/dest-config.yaml /config/config.yaml
```

#### Step 8: Restart anchore-engine services

`[user@host aevolume]$ docker-compose start anchore-engine`

The system should now be up and running using the new configuration! You can verify with the anchore-cli by fetching a policy bundle, which will have been migrated:

```
[root@d8d3f49d9328 /]# anchore-cli policy list
Policy ID                                   Active        Created                     Updated                     
2c53a13c-1765-11e8-82ef-23527761d060        True          2018-08-15T17:16:33Z        2018-08-15T18:11:01Z        
[root@d8d3f49d9328 /]# anchore-cli policy get 2c53a13c-1765-11e8-82ef-23527761d060 --detail
{
    "blacklisted_images": [], 
    "comment": "Default bundle", 
    "id": "2c53a13c-1765-11e8-82ef-23527761d060", 
... <lots of json>
```

If that returns the content properly, then you're all done!

### Things to Watch for in a Multi-Node Anchore Engine Installation

- Before migration:
  Ensure all services are down before starting migration
- At migration:
  Ensure the place you're running the migration from has the same db access and network access to the archive locations
- After migration:
  Ensure that all components get the update config.yaml. Strictly speaking, only containers that run the catalog service need the update configuration, but its best to ensure that any config.yaml in the system which has a services.catalog definition also has the proper and up-to-date configuration to avoid confusion or accidental reverting of the config.

### Example Process with docker-compose

```
# ls docker-compose.yaml 
docker-compose.yaml

# docker-compose ps
              Name                            Command               State                       Ports                     
--------------------------------------------------------------------------------------------------------------------------
aevolumepy3_anchore-db_1           docker-entrypoint.sh postgres    Up      5432/tcp                                      
aevolumepy3_anchore-engine_1       /bin/sh -c anchore-engine        Up      0.0.0.0:8228->8228/tcp, 0.0.0.0:8338->8338/tcp
aevolumepy3_anchore-minio_1        /usr/bin/docker-entrypoint ...   Up      0.0.0.0:9000->9000/tcp                        
aevolumepy3_anchore-prometheus_1   /bin/prometheus --config.f ...   Up      0.0.0.0:9090->9090/tcp                        
aevolumepy3_anchore-redis_1        docker-entrypoint.sh redis ...   Up      6379/tcp                                      
aevolumepy3_anchore-ui_1           /bin/sh -c node /home/node ...   Up      0.0.0.0:3000->3000/tcp                        

# docker-compose stop anchore-engine
Stopping aevolume_anchore-engine_1 ... done

# docker-compose run anchore-engine anchore-manager objectstorage --db-connect postgresql+pg8000://postgres:mysecretpassword@anchore-db:5432/postgres check /config/config.yaml.new
[MainThread] [anchore_manager.cli.utils/connect_database()] [INFO] DB params: {"db_connect": "postgresql+pg8000://postgres:mysecretpassword@anchore-db:5432/postgres", "db_connect_args": {"timeout": 30, "ssl": false}, "db_pool_size": 30, "db_pool_max_overflow": 100}
[MainThread] [anchore_manager.cli.utils/connect_database()] [INFO] DB connection configured: True
[MainThread] [anchore_manager.cli.utils/connect_database()] [INFO] DB attempting to connect...
[MainThread] [anchore_manager.cli.utils/connect_database()] [INFO] DB connected: True
[MainThread] [anchore_manager.cli.objectstorage/check()] [INFO] Using config file /config/config.yaml.new
...
...

# docker-compose run anchore-engine anchore-manager objectstorage --db-connect postgresql+pg8000://postgres:mysecretpassword@anchore-db:5432/postgres migrate /config/config.yaml /config/config.yaml.new
[MainThread] [anchore_manager.cli.utils/connect_database()] [INFO] DB params: {"db_connect": "postgresql+pg8000://postgres:mysecretpassword@anchore-db:5432/postgres", "db_connect_args": {"timeout": 30, "ssl": false}, "db_pool_size": 30, "db_pool_max_overflow": 100}
[MainThread] [anchore_manager.cli.utils/connect_database()] [INFO] DB connection configured: True
[MainThread] [anchore_manager.cli.utils/connect_database()] [INFO] DB attempting to connect...
[MainThread] [anchore_manager.cli.utils/connect_database()] [INFO] DB connected: True
[MainThread] [anchore_manager.cli.objectstorage/migrate()] [INFO] Loading configs
[MainThread] [anchore_engine.configuration.localconfig/validate_config()] [WARN] no webhooks defined in configuration file - notifications will be disabled
[MainThread] [anchore_engine.configuration.localconfig/validate_config()] [WARN] no webhooks defined in configuration file - notifications will be disabled
[MainThread] [anchore_manager.cli.objectstorage/migrate()] [INFO] Migration from config: {
  "compression": {
    "enabled": false,
    "min_size_kbytes": 100
  },
  "storage_driver": {
    "name": "db",
    "config": {}
  }
}
[MainThread] [anchore_manager.cli.objectstorage/migrate()] [INFO] Migration to config: {
  "compression": {
    "enabled": true,
    "min_size_kbytes": 100
  },
  "storage_driver": {
    "name": "s3",
    "config": {
      "access_key": "Z54LPSMFKXSP2E2L4TGX",
      "secret_key": "EMaLAWLVhUmV/f6hnEqjJo5+/WeZ7ukyHaBKlscB",
      "url": "http://anchore-minio:9000",
      "region": false,
      "bucket": "anchorearchive",
      "create_bucket": true
    }
  }
}
Performing this operation requires *all* anchore-engine services to be stopped - proceed? (y/N) y
...
...
...
[MainThread] [anchore_engine.subsys.object_store.migration/initiate_migration()] [INFO] Migration result summary: {"last_updated": "2018-08-14T22:19:39.985250", "started_at": "2018-08-14T22:19:39.984603", "last_state": "running", "online_migration": null, "archive_documents_migrated": 500, "migrate_to_driver": "s3", "id": 9, "executor_id": "e9fc8f77714d:1:140375539468096:", "ended_at": "2018-08-14T22:20:03.957291", "created_at": "2018-08-14T22:19:39.985246", "state": "complete", "archive_documents_to_migrate": 500, "migrate_from_driver": "db", "type": "archivemigrationtask"}
[MainThread] [anchore_manager.cli.objectstorage/migrate()] [INFO] After this migration, your anchore-engine config.yaml MUST have the following configuration options added before starting up again:
...
...

# cp config/config.yaml config/config.yaml.original

# cp config/config.yaml.new config/config.yaml

# docker-compose start anchore-engine
Starting anchore-engine ... done
```

## Migrating Analysis Archive Data

The object storage migration process migrates any data stored in the source config to the destination configuration, if
the analysis archive is configured to use the same storage backend as the primary object store then that data is migrated
along with all other data, but if the source or destination configurations define different storage backends for the
analysis archive than that which is used by the primary object store, then additional paramters are necesary in the
migration commands to indicate which configurations to migrate to/from.


The most common migration patterns are:

1. Migrate from a single backend configuration to a split configuration to move analysis archive data to an external system (db -> db + s3)

2. Migrate from a dual-backend configuration to a single-backend configuration with a different config (e.g. db + s3 -> s3)


### Migrating a single backend to split backend

For example, moving from unified db backend (default config) to a db + s3 configuration with s3 for the analysis archive .

source-config.yaml snippet:
```
...
services:
...
  catalog:
    ...
    object_store:
      compression:
        enabled: false
        min_size_kbytes: 100
      storage_driver:
        name: db
        config: {}        
...

```

dest-config.yaml snippet:
```
...
services:
...
  catalog:
    ...
    object_store:
      compression:
        enabled: false
        min_size_kbytes: 100
      storage_driver:
        name: db
        config: {}
    analysis_archive:
      enabled: true
      compression:
        enabled: false
        min_size_kbytes: 100
      storage_driver:
        name: s3
        config: 
          access_key: 9EB92C7W61YPFQ6QLDOU
          secret_key: TuHo2UbBx+amD3YiCeidy+R3q82MPTPiyd+dlW+s
          url: 'http://minio-ephemeral-test:9000'
          region: null
          bucket: analysisarchive
      ...   

```

Anchore stores its internal data in logical 'buckets' that are overlayed onto the storage backed in a driver-specific 
way, so to migrate specific internal buckets (effectively these are classes of data), use the --bucket option in the 
manager cli. This should generally not be necessary, but for specific kinds of migrations it may be needed.

The following command will execute the migration. Note that the --bucket option is for an internal Anchore logical-bucket, not 
and actual bucket in S3:

```
anchore-manager objectstorage --db-connect migrate --to-analysis-archive --bucket analysis_archive source-config.yaml dest-config.yaml
```

### Migrating from dual object storage backends to a single backend

For example, migrating from a db + s3 backend to a single s3 backend in a different bucket:


Example source-config.yaml snippet:
```
...
services:
...
  catalog:
    ...
    object_store:
      compression:
        enabled: false
        min_size_kbytes: 100
      storage_driver:
        name: db
        config: {}
    analysis_archive:
      enabled: true
      compression:
        enabled: false
        min_size_kbytes: 100
      storage_driver:
        name: s3
        config: 
          access_key: 9EB92C7W61YPFQ6QLDOU
          secret_key: TuHo2UbBx+amD3YiCeidy+R3q82MPTPiyd+dlW+s
          url: 'http://minio-ephemeral-test:9000'
          region: null
          bucket: analysisarchive        
...

```

The dest config is a single backend. In this case, note the S3 bucket has changed so all data must be migrated.

Example dest-config.yaml snippet:
```
...
services:
...
  catalog:
    ...
    object_store:
      enabled: true
      compression:
        enabled: false
        min_size_kbytes: 100
      storage_driver:
        name: s3
        config: 
          access_key: 9EB92C7W61YPFQ6QLDOU
          secret_key: TuHo2UbBx+amD3YiCeidy+R3q82MPTPiyd+dlW+s
          url: 'http://minio-ephemeral-test:9000'
          region: null
          bucket: newanchorebucket
      ...

```

First, migrate the object data in the db on the source:
```
anchore-manager objectstorage --db-connect migrate source-config.yaml dest-config.yaml
``` 

Next, migrate the object data in the analysis archive from the old config (s3 bucket 'analysisarchive' to the new config 
(s3 bucket 'newanchorebucket'):
```
anchore-manager objectstorage --db-connect migrate --from-analysis-archive source-config.yaml dest-config.yaml  

```
