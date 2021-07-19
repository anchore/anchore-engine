import json
import time
from contextlib import contextmanager
from distutils.version import StrictVersion

from sqlalchemy import BigInteger, Column, DateTime, Enum, Integer, String, Text

import anchore_engine.common.helpers
import anchore_engine.db.entities.common
import anchore_engine.subsys.object_store.manager
from anchore_engine.db.entities.common import StringJSON
from anchore_engine.db.entities.exceptions import is_table_not_found

try:
    # Separate logger for use during bootstrap when logging may not be fully configured
    from twisted.python import log

    from anchore_engine.subsys import identities, logger  # pylint: disable=C0412
except:
    import logging

    logger = logging.getLogger(__name__)
    log = logger

upgrade_enabled = True

# Set at module level for any db module that needs db upgrade ability
my_module_upgrade_id = 1


def do_db_compatibility_check():
    required_pg_version = (9, 6)

    try:
        engine = anchore_engine.db.entities.common.get_engine()
        if engine.dialect.server_version_info >= required_pg_version:
            return True
        else:
            raise Exception(
                "discovered db version {} is not >= required db version {}".format(
                    engine.dialect.server_version_info, required_pg_version
                )
            )
    except Exception as err:
        raise err

    raise Exception("database compatibility could not be performed")


def do_db_post_actions(localconfig=None):
    return


def get_versions():
    code_versions = {}
    db_versions = {}

    from anchore_engine import version

    code_versions["service_version"] = version.version
    code_versions["db_version"] = version.db_version

    try:
        from anchore_engine.db import db_anchore, session_scope

        with session_scope() as dbsession:
            db_versions = db_anchore.get(session=dbsession)
    except Exception as err:
        if is_table_not_found(err):
            logger.info("anchore table not found")
            # raise TableNotFoundError('anchore table not found')
        else:
            raise Exception(
                "Cannot find existing/populated anchore DB tables in connected database - has anchore-engine initialized this DB?\n\nDB - exception: "
                + str(err)
            )

    return code_versions, db_versions


def do_version_update(db_versions, code_versions):
    from anchore_engine.db import db_anchore, session_scope

    with session_scope() as dbsession:
        db_anchore.add(
            code_versions["service_version"],
            code_versions["db_version"],
            code_versions,
            session=dbsession,
        )

    return True


@contextmanager
def upgrade_context(lock_id):
    """
    Provides a context for upgrades including a lock on the db to ensure only one upgrade process at a time doing checks.

    Use a postgresql application lock to block schema updates and serialize checks
    :param lock_id: the lock id (int) for the lock to acquire
    :return:
    """
    engine = anchore_engine.db.entities.common.get_engine()

    from anchore_engine.db.db_locks import application_lock_ids, db_application_lock

    with db_application_lock(
        engine, (application_lock_ids["upgrade"]["namespace"], lock_id)
    ):
        versions = get_versions()
        yield versions


def do_create_tables(specific_tables=None):
    print("Creating DB Tables")
    from anchore_engine.db.entities.common import Base, do_create

    try:
        with upgrade_context(my_module_upgrade_id) as ctx:
            do_create(specific_tables=specific_tables, base=Base)
    except Exception as err:
        raise err
    print("DB Tables created")
    return True


def do_db_bootstrap(localconfig=None, db_versions=None, code_versions=None):
    from anchore_engine.db import session_scope

    with upgrade_context(my_module_upgrade_id) as ctx:
        with session_scope() as session:
            try:
                initializer = identities.IdentityBootstrapper(
                    identities.IdentityManager, session
                )
                initializer.initialize_system_identities()
            except Exception as err:
                logger.exception(
                    "Error initializing system credentials on db bootstrap"
                )
                raise Exception(
                    "Initialization failed: could not initialize system credentials - exception: "
                    + str(err)
                )

        do_version_update(db_versions, code_versions)


def run_upgrade():
    """
    Entry point for upgrades (idempotent). If already upgraded, this is a no-op. If database is un-initialized.
    Will raise exception on failure and return bool. True = upgrade completed, False = no upgrade necessary.

    :return: True if upgrade executed, False if success, but no upgrade needed.
    """
    with upgrade_context(my_module_upgrade_id) as ctx:
        code_versions = ctx[0]
        db_versions = ctx[1]

        code_db_version = ctx[0].get("db_version", None)
        running_db_version = ctx[1].get("db_version", None)

        if not code_db_version:
            raise Exception(
                "cannot get code version (code_db_version={} running_db_version={})".format(
                    code_db_version, running_db_version
                )
            )
        elif code_db_version and running_db_version is None:
            print(
                "Detected no running db version, indicating db is not initialized but is connected. No upgrade necessary. Exiting normally."
            )
            ecode = 0
        elif code_db_version == running_db_version:
            print(
                "Detected anchore-engine version {} and running DB version {} match, nothing to do.".format(
                    code_db_version, running_db_version
                )
            )
        else:
            print(
                "Detected anchore-engine version {}, running DB version {}.".format(
                    code_db_version, running_db_version
                )
            )
            print("Performing upgrade.")
            try:
                rc = do_create_tables()
                if rc:
                    print("Table create success.")
                else:
                    raise Exception("Failure while creating tables.")

                # perform the upgrade logic here
                rc = do_upgrade(db_versions, code_versions)
                if rc:
                    # if successful upgrade, set the DB values to the incode values
                    rc = do_version_update(db_versions, code_versions)
                    print("Upgrade success.")
                    return rc
                else:
                    raise Exception(
                        "Upgrade routine from module returned false, please check your DB/environment and try again"
                    )
            except Exception as err:
                raise err


def do_upgrade(inplace, incode):
    global upgrade_enabled, upgrade_functions

    if StrictVersion(inplace["db_version"]) > StrictVersion(incode["db_version"]):
        raise Exception("DB downgrade not supported")

    if inplace["db_version"] != incode["db_version"]:
        print(
            (
                "Upgrading DB: from="
                + str(inplace["db_version"])
                + " to="
                + str(incode["db_version"])
            )
        )

        if upgrade_enabled:
            db_current = inplace["db_version"]
            db_target = incode["db_version"]

            for version_tuple, functions_to_run in upgrade_functions:
                db_from = version_tuple[0]
                db_to = version_tuple[1]

                # finish if we've reached the target version
                if StrictVersion(db_current) >= StrictVersion(db_target):
                    # done
                    break
                elif StrictVersion(db_to) <= StrictVersion(db_current):
                    # Upgrade code is for older version, skip it.
                    continue
                else:
                    print(
                        (
                            "Executing upgrade functions for version {} to {}".format(
                                db_from, db_to
                            )
                        )
                    )
                    for fn in functions_to_run:
                        try:
                            print(
                                ("Executing upgrade function: {}".format(fn.__name__))
                            )
                            fn()
                        except Exception as e:
                            log.err(
                                "Upgrade function {} raised an error. Failing upgrade.".format(
                                    fn.__name__
                                )
                            )
                            raise e

                    db_current = db_to

    if inplace["service_version"] != incode["service_version"]:
        print(
            (
                "upgrading service: from="
                + str(inplace["service_version"])
                + " to="
                + str(incode["service_version"])
            )
        )

    ret = True
    return ret


### Individual upgrade routines - be sure to add to the function map at the end of this module if adding a new routine here


def db_upgrade_001_002():
    engine = anchore_engine.db.entities.common.get_engine()

    from anchore_engine.db import db_policybundle, db_registries, session_scope

    try:
        table_name = "registries"
        column = Column("registry_type", String, primary_key=False)
        cn = column.compile(dialect=engine.dialect)
        ct = column.type.compile(engine.dialect)
        engine.execute(
            "ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s" % (table_name, cn, ct)
        )

        with session_scope() as dbsession:
            registry_records = db_registries.get_all(session=dbsession)
            for registry_record in registry_records:
                try:
                    if not registry_record["registry_type"]:
                        registry_record["registry_type"] = "docker_v2"
                        db_registries.update_record(registry_record, session=dbsession)
                except Exception as err:
                    pass
    except Exception as err:
        raise Exception(
            "failed to perform DB registry table upgrade - exception: " + str(err)
        )

    try:
        table_name = "policy_bundle"
        column = Column("policy_source", String, primary_key=False)
        cn = column.compile(dialect=engine.dialect)
        ct = column.type.compile(engine.dialect)
        engine.execute(
            "ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s" % (table_name, cn, ct)
        )

        with session_scope() as dbsession:
            policy_records = db_policybundle.get_all(session=dbsession)
            for policy_record in policy_records:
                try:
                    if not policy_record["policy_source"]:
                        policy_record["policy_source"] = "local"
                        db_policybundle.update_record(policy_record, session=dbsession)
                except Exception as err:
                    pass

    except Exception as err:
        raise Exception(
            "failed to perform DB policy_bundle table upgrade - exception: " + str(err)
        )

    return True


def db_upgrade_002_003():
    engine = anchore_engine.db.entities.common.get_engine()

    try:
        table_name = "images"
        column = Column("size", BigInteger)
        cn = column.compile(dialect=engine.dialect)
        ct = column.type.compile(engine.dialect)
        engine.execute("ALTER TABLE %s ALTER COLUMN %s TYPE %s" % (table_name, cn, ct))
    except Exception as e:
        raise Exception(
            "failed to perform DB upgrade on images.size field change from int to bigint - exception: {}".format(
                str(e)
            )
        )

    try:
        table_name = "feed_data_gem_packages"
        column = Column("id", BigInteger)
        cn = column.compile(dialect=engine.dialect)
        ct = column.type.compile(engine.dialect)
        engine.execute("ALTER TABLE %s ALTER COLUMN %s TYPE %s" % (table_name, cn, ct))
    except Exception as e:
        raise Exception(
            "failed to perform DB upgrade on feed_data_gem_packages.id field change from int to bigint - exception: {}".format(
                str(e)
            )
        )

    return True


def db_upgrade_003_004():
    engine = anchore_engine.db.entities.common.get_engine()

    import anchore_engine.common
    from anchore_engine.db import db_archivedocument, db_catalog_image, session_scope

    newcolumns = [
        Column("arch", String, primary_key=False),
        Column("distro", String, primary_key=False),
        Column("distro_version", String, primary_key=False),
        Column("dockerfile_mode", String, primary_key=False),
        Column("image_size", BigInteger, primary_key=False),
        Column("layer_count", Integer, primary_key=False),
    ]
    for column in newcolumns:
        try:
            table_name = "catalog_image"
            cn = column.compile(dialect=engine.dialect)
            ct = column.type.compile(engine.dialect)
            engine.execute(
                "ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s" % (table_name, cn, ct)
            )
        except Exception as e:
            log.err(
                "failed to perform DB upgrade on catalog_image adding column - exception: {}".format(
                    str(e)
                )
            )
            raise Exception(
                "failed to perform DB upgrade on catalog_image adding column - exception: {}".format(
                    str(e)
                )
            )

    with session_scope() as dbsession:
        image_records = db_catalog_image.get_all(session=dbsession)

    for image_record in image_records:
        userId = image_record["userId"]
        imageDigest = image_record["imageDigest"]

        log.err("upgrade: processing image " + str(imageDigest) + " : " + str(userId))
        try:

            # get the image analysis data from archive
            image_data = None
            with session_scope() as dbsession:
                result = db_archivedocument.get(
                    userId, "analysis_data", imageDigest, session=dbsession
                )
            if result and "jsondata" in result:
                image_data = json.loads(result["jsondata"])["document"]

            if image_data:
                # update the record and store
                anchore_engine.common.helpers.update_image_record_with_analysis_data(
                    image_record, image_data
                )
                with session_scope() as dbsession:
                    db_catalog_image.update_record(image_record, session=dbsession)
            else:
                raise Exception(
                    "upgrade: no analysis data found in archive for image: "
                    + str(imageDigest)
                )
        except Exception as err:
            log.err(
                "upgrade: failed to populate new columns with existing data for image ("
                + str(imageDigest)
                + "), record may be incomplete: "
                + str(err)
            )

    return True


def db_upgrade_004_005():
    engine = anchore_engine.db.entities.common.get_engine()
    from sqlalchemy import Column, String

    newcolumns = [
        Column("annotations", String, primary_key=False),
    ]
    for column in newcolumns:
        try:
            table_name = "catalog_image"
            cn = column.compile(dialect=engine.dialect)
            ct = column.type.compile(engine.dialect)
            engine.execute(
                "ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s" % (table_name, cn, ct)
            )
        except Exception as e:
            log.err(
                "failed to perform DB upgrade on catalog_image adding column - exception: {}".format(
                    str(e)
                )
            )
            raise Exception(
                "failed to perform DB upgrade on catalog_image adding column - exception: {}".format(
                    str(e)
                )
            )


def queue_data_upgrades_005_006():
    engine = anchore_engine.db.entities.common.get_engine()

    new_columns = [
        {
            "table_name": "queuemeta",
            "columns": [
                Column(
                    "max_outstanding_messages", Integer, primary_key=False, default=0
                ),
                Column("visibility_timeout", Integer, primary_key=False, default=0),
            ],
        },
        {
            "table_name": "queue",
            "columns": [
                Column("receipt_handle", String, primary_key=False),
                Column("visible_at", DateTime, primary_key=False),
            ],
        },
    ]

    for table in new_columns:
        for column in table["columns"]:
            try:
                cn = column.compile(dialect=engine.dialect)
                ct = column.type.compile(engine.dialect)
                engine.execute(
                    "ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s"
                    % (table["table_name"], cn, ct)
                )
            except Exception as e:
                log.err(
                    "failed to perform DB upgrade on catalog_image adding column - exception: {}".format(
                        str(e)
                    )
                )
                raise Exception(
                    "failed to perform DB upgrade on catalog_image adding column - exception: {}".format(
                        str(e)
                    )
                )


def archive_data_upgrade_005_006():
    """
    Upgrade the document archive data schema and move the data appropriately.
    Assumes both tables are in place (archive_document, archive_document_reference, object_storage)

    :return:
    """

    from anchore_engine.configuration import localconfig
    from anchore_engine.db import (
        LegacyArchiveDocument,
        ObjectStorageMetadata,
        session_scope,
    )
    from anchore_engine.subsys import object_store
    from anchore_engine.subsys.object_store.config import (
        ALT_OBJECT_STORE_CONFIG_KEY,
        DEFAULT_OBJECT_STORE_MANAGER_ID,
    )

    config = localconfig.get_config()
    object_store.initialize(
        config.get("services", {}).get("catalog", {}),
        manager_id=DEFAULT_OBJECT_STORE_MANAGER_ID,
        config_keys=(DEFAULT_OBJECT_STORE_MANAGER_ID, ALT_OBJECT_STORE_CONFIG_KEY),
        allow_legacy_fallback=True,
    )
    client = anchore_engine.subsys.object_store.manager.get_manager().primary_client

    session_counter = 0
    max_pending_session_size = 10000

    with session_scope() as db_session:
        for doc in db_session.query(
            LegacyArchiveDocument.userId,
            LegacyArchiveDocument.bucket,
            LegacyArchiveDocument.archiveId,
            LegacyArchiveDocument.documentName,
            LegacyArchiveDocument.created_at,
            LegacyArchiveDocument.last_updated,
            LegacyArchiveDocument.record_state_key,
            LegacyArchiveDocument.record_state_val,
        ):
            meta = ObjectStorageMetadata(
                userId=doc[0],
                bucket=doc[1],
                archiveId=doc[2],
                documentName=doc[3],
                is_compressed=False,
                document_metadata=None,
                content_url=client.uri_for(userId=doc[0], bucket=doc[1], key=doc[2]),
                created_at=doc[4],
                last_updated=doc[5],
                record_state_key=doc[6],
                record_state_val=doc[6],
            )

            db_session.add(meta)

            session_counter += 1

            if session_counter >= max_pending_session_size:
                db_session.flush()
                session_counter = 0


def fixed_artifact_upgrade_005_006():
    """
    Upgrade the feed_data_vulnerabilities_fixed_artifacts schema with new columns and fill in the defaults

    """
    from sqlalchemy import Boolean, Column, Text

    engine = anchore_engine.db.entities.common.get_engine()

    table_name = "feed_data_vulnerabilities_fixed_artifacts"
    vna = "vendor_no_advisory"
    newcolumns = [
        Column(vna, Boolean, primary_key=False),
        Column("fix_metadata", Text, primary_key=False),
    ]

    for column in newcolumns:
        try:
            cn = column.compile(dialect=engine.dialect)
            ct = column.type.compile(engine.dialect)
            engine.execute(
                "ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s" % (table_name, cn, ct)
            )
        except Exception as e:
            raise Exception(
                "failed to perform DB upgrade on {} adding column {} - exception: {}".format(
                    table_name, column.name, str(e)
                )
            )

    try:
        engine.execute(
            "UPDATE %s SET %s = FALSE WHERE %s IS NULL" % (table_name, vna, vna)
        )
    except Exception as e:
        raise Exception(
            "failed to perform DB upgrade on {} setting default value for column {} - exception: {}".format(
                table_name, vna, str(e)
            )
        )


def db_upgrade_005_006():
    queue_data_upgrades_005_006()
    archive_data_upgrade_005_006()
    fixed_artifact_upgrade_005_006()


def catalog_image_upgrades_006_007():
    engine = anchore_engine.db.entities.common.get_engine()

    new_columns = [
        {
            "table_name": "catalog_image",
            "columns": [Column("analyzed_at", Integer, primary_key=False)],
        },
        {
            "table_name": "catalog_image_docker",
            "columns": [Column("tag_detected_at", Integer, primary_key=False)],
        },
    ]

    for table in new_columns:
        for column in table["columns"]:
            try:
                cn = column.compile(dialect=engine.dialect)
                ct = column.type.compile(engine.dialect)
                engine.execute(
                    "ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s"
                    % (table["table_name"], cn, ct)
                )
            except Exception as e:
                log.err(
                    "failed to perform DB upgrade on {} adding column - exception: {}".format(
                        table, str(e)
                    )
                )
                raise Exception(
                    "failed to perform DB upgrade on {} adding column - exception: {}".format(
                        table, str(e)
                    )
                )

    try:
        engine.execute(
            "UPDATE catalog_image SET analyzed_at=last_updated WHERE analyzed_at IS NULL AND analysis_status='analyzed'"
        )
    except Exception as e:
        raise Exception(
            "failed to perform DB upgrade on catalog_image setting default value for column analyzed_at - exception: {}".format(
                str(e)
            )
        )

    try:
        engine.execute(
            "UPDATE catalog_image_docker SET tag_detected_at=created_at WHERE tag_detected_at IS NULL"
        )
    except Exception as e:
        raise Exception(
            "failed to perform DB upgrade on catalog_image_docker setting default value for column tag_detected_at - exception: {}".format(
                str(e)
            )
        )


def user_account_upgrades_007_008():
    logger.info("Upgrading user accounts for multi-user support")

    from anchore_engine.configuration.localconfig import (
        ADMIN_ACCOUNT_NAME,
        SYSTEM_ACCOUNT_NAME,
    )
    from anchore_engine.db import legacy_db_users, session_scope
    from anchore_engine.subsys.identities import AccountStates, manager_factory

    with session_scope() as session:
        mgr = manager_factory.for_session(session)
        for user in legacy_db_users.get_all():

            if user["userId"] == ADMIN_ACCOUNT_NAME:
                account_type = identities.AccountTypes.admin
            elif user["userId"] == SYSTEM_ACCOUNT_NAME:
                account_type = identities.AccountTypes.service
            else:
                account_type = identities.AccountTypes.user

            logger.info(
                "Migrating user: {} to new account with name {}, type {}, is_active {}".format(
                    user["userId"], user["userId"], account_type, user["active"]
                )
            )
            accnt = mgr.create_account(
                account_name=user["userId"],
                email=user["email"],
                account_type=account_type,
            )
            if not user["active"]:
                mgr.update_account_state(accnt["name"], AccountStates.disabled)

            logger.info(
                "Creating new user record in new account {} with username {}".format(
                    user["userId"], user["userId"]
                )
            )
            mgr.create_user(
                account_name=user["userId"],
                username=user["userId"],
                password=user["password"],
            )

            logger.info("Deleting old user record")
            legacy_db_users.delete(user["userId"], session)

    logger.info("User account upgrade complete")


def db_upgrade_006_007():
    catalog_image_upgrades_006_007()


def db_upgrade_007_008():
    catalog_upgrade_007_008()
    policy_engine_packages_upgrade_007_008()
    user_account_upgrades_007_008()


def catalog_upgrade_007_008():
    from anchore_engine.db import session_scope

    log.err("performing catalog table upgrades")
    engine = anchore_engine.db.entities.common.get_engine()
    new_columns = [
        {
            "table_name": "catalog_image",
            "columns": [
                Column("parentDigest", String()),
            ],
        },
    ]

    log.err("creating new table columns")
    for table in new_columns:
        for column in table["columns"]:
            log.err(
                "creating new column ({}) in table ({})".format(
                    column.name, table.get("table_name", "")
                )
            )
            try:
                cn = column.compile(dialect=engine.dialect)
                ct = column.type.compile(engine.dialect)
                engine.execute(
                    "ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s"
                    % (table["table_name"], cn, ct)
                )
            except Exception as e:
                log.err(
                    "failed to perform DB upgrade on {} adding column - exception: {}".format(
                        table, str(e)
                    )
                )
                raise Exception(
                    "failed to perform DB upgrade on {} adding column - exception: {}".format(
                        table, str(e)
                    )
                )


def policy_engine_packages_upgrade_007_008():
    from anchore_engine.db import Image, ImageGem, ImageNpm, ImagePackage, session_scope

    if True:
        engine = anchore_engine.db.entities.common.get_engine()

        file_path_length = 512
        hash_length = 80

        new_columns = [
            {
                "table_name": "image_packages",
                "columns": [
                    Column("pkg_path", String(file_path_length), primary_key=True),
                    Column("pkg_path_hash", String(hash_length)),
                    Column("metadata_json", StringJSON),
                ],
            },
            {
                "table_name": "image_package_vulnerabilities",
                "columns": [
                    Column("pkg_path", String(file_path_length), primary_key=True),
                ],
            },
            {
                "table_name": "image_package_db_entries",
                "columns": [
                    Column("pkg_path", String(file_path_length), primary_key=True),
                ],
            },
        ]

        log.err("creating new table columns")
        for table in new_columns:
            for column in table["columns"]:
                log.err(
                    "creating new column ({}) in table ({})".format(
                        column.name, table.get("table_name", "")
                    )
                )
                try:
                    cn = column.compile(dialect=engine.dialect)
                    ct = column.type.compile(engine.dialect)
                    engine.execute(
                        "ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s"
                        % (table["table_name"], cn, ct)
                    )
                except Exception as e:
                    log.err(
                        "failed to perform DB upgrade on {} adding column - exception: {}".format(
                            table, str(e)
                        )
                    )
                    raise Exception(
                        "failed to perform DB upgrade on {} adding column - exception: {}".format(
                            table, str(e)
                        )
                    )

        # populate the new columns
        log.err("updating new column (pkg_path) - this may take a while")
        for table in ["image_packages", "image_package_vulnerabilities"]:
            log.err("updating table ({}) column (pkg_path)".format(table))
            done = False
            while not done:
                startts = time.time()
                rc = engine.execute(
                    "UPDATE {} set pkg_path='pkgdb' where pkg_path is null".format(
                        table
                    )
                )
                log.err(
                    "updated {} records in {} (time={}), performing next range".format(
                        rc.rowcount, table, time.time() - startts
                    )
                )
                done = True

        with session_scope() as dbsession:
            db_image_ids = dbsession.query(Image.id).distinct().all()

        total_records = len(db_image_ids)
        record_count = 0
        for record in db_image_ids:
            db_image_id = record[0]
            startts = time.time()
            rc = engine.execute(
                "UPDATE image_package_db_entries set pkg_path='pkgdb' where image_id='{}' and pkg_path is null".format(
                    db_image_id
                )
            )
            record_count = record_count + 1
            log.err(
                "updated {} image ({} / {}) in {} (time={}), performing next image update".format(
                    db_image_id,
                    record_count,
                    total_records,
                    "image_package_db_entries",
                    time.time() - startts,
                )
            )

        exec_commands = [
            "ALTER TABLE image_package_vulnerabilities DROP CONSTRAINT IF EXISTS image_package_vulnerabilities_pkg_image_id_fkey",
            "ALTER TABLE image_package_db_entries DROP CONSTRAINT IF EXISTS image_package_db_entries_image_id_fkey",
            "ALTER TABLE image_packages DROP CONSTRAINT IF EXISTS image_packages_pkey",
            "ALTER TABLE image_package_db_entries DROP CONSTRAINT IF EXISTS image_package_db_entries_pkey",
            "ALTER TABLE image_package_vulnerabilities DROP CONSTRAINT IF EXISTS image_package_vulnerabilities_pkey",
        ]

        log.err("dropping primary key / foreign key relationships for new column")
        cmdcount = 1
        for command in exec_commands:
            log.err(
                "running update operation {} of {}: {}".format(
                    cmdcount, len(exec_commands), command
                )
            )
            engine.execute(command)
            cmdcount = cmdcount + 1

        exec_commands = [
            "ALTER TABLE image_packages ADD PRIMARY KEY (image_id,image_user_id,name,version,pkg_type,arch,pkg_path)",
            "ALTER TABLE image_package_vulnerabilities ADD PRIMARY KEY (pkg_user_id,pkg_image_id,pkg_name,pkg_version,pkg_type,pkg_arch,vulnerability_id,pkg_path)",
            "ALTER TABLE image_package_db_entries ADD PRIMARY KEY (image_id, image_user_id, pkg_name, pkg_version, pkg_type, pkg_arch, pkg_path,file_path)",
            "ALTER TABLE image_package_vulnerabilities ADD CONSTRAINT image_package_vulnerabilities_pkg_image_id_fkey FOREIGN KEY (pkg_image_id, pkg_user_id, pkg_name, pkg_version, pkg_type, pkg_arch, pkg_path) REFERENCES image_packages (image_id, image_user_id, name, version, pkg_type, arch, pkg_path) MATCH SIMPLE",
            "ALTER TABLE image_package_db_entries ADD CONSTRAINT image_package_db_entries_image_id_fkey FOREIGN KEY (image_id, image_user_id, pkg_name, pkg_version, pkg_type, pkg_arch, pkg_path) REFERENCES image_packages (image_id, image_user_id, name, version, pkg_type, arch, pkg_path) MATCH SIMPLE",
            # These are helpers for the upgrade itself, not needed by the functioning system. Needed for large npm/gem tables and pagination support
            "CREATE SEQUENCE IF NOT EXISTS image_npms_seq_id_seq",
            "ALTER TABLE image_npms add column IF NOT EXISTS seq_id int DEFAULT nextval('image_npms_seq_id_seq')",
            "CREATE INDEX IF NOT EXISTS idx_npm_seq ON image_npms using btree (seq_id)",
            "CREATE SEQUENCE IF NOT EXISTS image_gems_seq_id_seq",
            "ALTER TABLE image_gems add column IF NOT EXISTS seq_id int DEFAULT nextval('image_gems_seq_id_seq')",
            "CREATE INDEX IF NOT EXISTS idx_gem_seq ON image_gems using btree (seq_id)",
            "ALTER TABLE image_packages ALTER COLUMN origin TYPE varchar",
        ]

        log.err(
            "updating primary key / foreign key relationships for new column - this may take a while"
        )
        cmdcount = 1
        for command in exec_commands:
            log.err(
                "running update operation {} of {}: {}".format(
                    cmdcount, len(exec_commands), command
                )
            )
            engine.execute(command)
            cmdcount = cmdcount + 1

        log.err(
            "converting ImageNpm and ImageGem records into ImagePackage records - this may take a while"
        )
        # migrate ImageNpm and ImageGem records into ImagePackage records
        with session_scope() as dbsession:
            total_npms = dbsession.query(ImageNpm).count()
            total_gems = dbsession.query(ImageGem).count()

        log.err("will migrate {} image npm records".format(total_npms))

        npms = []
        chunk_size = 8192
        record_count = 0
        skipped_count = 0

        with session_scope() as dbsession:
            try:
                last_seq = -1
                while record_count < total_npms:
                    chunk_time = time.time()
                    log.err("Processing next chunk of records")
                    for n in (
                        dbsession.query(ImageNpm)
                        .filter(ImageNpm.seq_id > last_seq)
                        .limit(chunk_size)
                    ):
                        np = ImagePackage()

                        # primary keys
                        np.name = n.name
                        if len(n.versions_json):
                            version = n.versions_json[0]
                        else:
                            version = "N/A"
                        np.version = version
                        np.pkg_type = "npm"
                        np.arch = "N/A"
                        np.image_user_id = n.image_user_id
                        np.image_id = n.image_id
                        np.pkg_path = n.path

                        # other
                        np.pkg_path_hash = n.path_hash
                        np.distro_name = "npm"
                        np.distro_version = "N/A"
                        np.like_distro = "npm"
                        np.fullversion = np.version
                        np.license = " ".join(n.licenses_json)
                        np.origin = " ".join(n.origins_json)
                        fullname = np.name
                        np.normalized_src_pkg = fullname
                        np.src_pkg = fullname

                        npms.append(np)
                        last_seq = n.seq_id

                    if len(npms):
                        log.err("Inserting {} new records".format(len(npms)))

                        startts = time.time()
                        try:
                            with session_scope() as dbsession2:
                                dbsession2.bulk_save_objects(npms)
                        except Exception as err:
                            log.err("skipping duplicates: {}".format(err))
                            skipped_count += 1

                        record_count = record_count + len(npms)
                        log.err(
                            "merged {} / {} npm records (time={})".format(
                                record_count, total_npms, time.time() - startts
                            )
                        )

                    log.err(
                        "Chunk took: {} seconds to process {} records".format(
                            time.time() - chunk_time, len(npms)
                        )
                    )
                    npms = []

            except Exception as err:
                log.err("Error during npm migration: {}".format(err))
                raise err

        log.err("will migrate {} image gem records".format(total_gems))
        gems = []
        record_count = 0
        skipped_count = 0
        with session_scope() as dbsession:
            try:
                last_seq = -1
                while record_count < total_gems:
                    chunk_time = time.time()
                    log.err("Processing next chunk of records")
                    for n in (
                        dbsession.query(ImageGem)
                        .filter(ImageGem.seq_id > last_seq)
                        .limit(chunk_size)
                    ):

                        np = ImagePackage()

                        # primary keys
                        np.name = n.name
                        if len(n.versions_json):
                            version = n.versions_json[0]
                        else:
                            version = "N/A"
                        np.version = version
                        np.pkg_type = "gem"
                        np.arch = "N/A"
                        np.image_user_id = n.image_user_id
                        np.image_id = n.image_id
                        np.pkg_path = n.path

                        # other
                        np.pkg_path_hash = n.path_hash
                        np.distro_name = "gem"
                        np.distro_version = "N/A"
                        np.like_distro = "gem"
                        np.fullversion = np.version
                        np.license = " ".join(n.licenses_json)
                        np.origin = " ".join(n.origins_json)
                        fullname = np.name
                        np.normalized_src_pkg = fullname
                        np.src_pkg = fullname
                        gems.append(np)
                        last_seq = n.seq_id

                    if len(gems):
                        log.err("Inserting {} new records".format(len(gems)))

                        startts = time.time()
                        try:
                            with session_scope() as dbsession2:
                                dbsession2.bulk_save_objects(gems)
                        except Exception as err:
                            log.err("skipping duplicates: {}".format(err))
                            skipped_count += 1

                        record_count = record_count + len(gems)
                        log.err(
                            "merged {} / {} gem records (time={})".format(
                                record_count, total_gems, time.time() - startts
                            )
                        )

                    log.err(
                        "Chunk took: {} seconds to process {} records".format(
                            time.time() - chunk_time, len(npms)
                        )
                    )
                    gems = []

            except Exception as err:
                log.err("Error during gem migration: {}".format(err))
                raise err


def db_upgrade_008_009():
    """
    Runs upgrade on ImageGems and ImageNpms to add the column that was retrofitted for the 0.0.8 upgrade. This function ensures that
    users that already ran that upgrade end up with a 0.0.9 db that has the same schema.
    :return:
    """

    from anchore_engine.db import session_scope

    if True:
        engine = anchore_engine.db.entities.common.get_engine()

        exec_commands = [
            # These are helpers for the upgrade itself, not needed by the functioning system. Needed for large npm/gem tables and pagination support
            "CREATE SEQUENCE IF NOT EXISTS image_npms_seq_id_seq",
            "ALTER TABLE image_npms add column IF NOT EXISTS seq_id int DEFAULT nextval('image_npms_seq_id_seq')",
            "CREATE INDEX IF NOT EXISTS idx_npm_seq ON image_npms using btree (seq_id)",
            "CREATE SEQUENCE IF NOT EXISTS image_gems_seq_id_seq",
            "ALTER TABLE image_gems add column IF NOT EXISTS seq_id int DEFAULT nextval('image_gems_seq_id_seq')",
            "CREATE INDEX IF NOT EXISTS idx_gem_seq ON image_gems using btree (seq_id)",
            # This is a duplicate action from the updated 0.0.8 upgrade, effectively a no-op if that upgrade was already run
            "ALTER TABLE image_packages ALTER COLUMN origin TYPE varchar",
            # Indexes for vuln lookup performance
            "CREATE INDEX IF NOT EXISTS ix_image_cpe_user_img on image_cpes (image_id, image_user_id)",
            "CREATE INDEX IF NOT EXISTS ix_feed_data_cpe_vulnerabilities_name_version on feed_data_cpe_vulnerabilities (name, version)",
        ]

        cmdcount = 1
        for command in exec_commands:
            log.err(
                "running update operation {} of {}: {}".format(
                    cmdcount, len(exec_commands), command
                )
            )
            engine.execute(command)
            cmdcount = cmdcount + 1


def cpe_vulnerability_upgrade_009_010():
    """
    Runs upgrade on CpeVulnerability to create an index using foreign key columns vulnerability_id, namespace_name, severity in that order

    :return:
    """
    from anchore_engine.db import session_scope

    engine = anchore_engine.db.entities.common.get_engine()

    exec_commands = [
        "CREATE INDEX IF NOT EXISTS ix_feed_data_cpe_vulnerabilities_fk on feed_data_cpe_vulnerabilities (vulnerability_id, namespace_name, severity)"
    ]

    log.err(
        "Creating index ix_feed_data_cpe_vulnerabilities_fk on table feed_data_cpe_vulnerabilities"
    )

    cmdcount = 1
    for command in exec_commands:
        log.err(
            "running update operation {} of {}: {}".format(
                cmdcount, len(exec_commands), command
            )
        )
        engine.execute(command)
        cmdcount = cmdcount + 1


def archive_document_upgrade_009_010():
    """
    Runs upgrade on LegacyArchiveDocument to add b64_encoded column

    :return:
    """

    from anchore_engine.db import session_scope

    engine = anchore_engine.db.entities.common.get_engine()

    exec_commands = [
        "ALTER TABLE archive_document ADD COLUMN IF NOT EXISTS b64_encoded boolean"
    ]

    cmdcount = 1
    for command in exec_commands:
        log.err(
            "running update operation {} of {}: {}".format(
                cmdcount, len(exec_commands), command
            )
        )
        engine.execute(command)
        cmdcount = cmdcount + 1


def db_upgrade_009_010():
    archive_document_upgrade_009_010()
    cpe_vulnerability_upgrade_009_010()


def registry_name_upgrade_010_011():
    """
    Runs upgrade to add the 'registry_name' column to registry credential records

    :return:
    """

    from anchore_engine.db import session_scope

    engine = anchore_engine.db.entities.common.get_engine()

    new_columns = [
        {
            "table_name": "registries",
            "columns": [
                Column("registry_name", String()),
            ],
        }
    ]

    log.err("creating new table columns")
    for table in new_columns:
        for column in table["columns"]:
            log.err(
                "creating new column ({}) in table ({})".format(
                    column.name, table.get("table_name", "")
                )
            )
            try:
                cn = column.compile(dialect=engine.dialect)
                ct = column.type.compile(engine.dialect)
                engine.execute(
                    "ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s"
                    % (table["table_name"], cn, ct)
                )
            except Exception as e:
                log.err(
                    "failed to perform DB upgrade on {} adding column - exception: {}".format(
                        table, str(e)
                    )
                )
                raise Exception(
                    "failed to perform DB upgrade on {} adding column - exception: {}".format(
                        table, str(e)
                    )
                )

    # populate new column
    rc = engine.execute(
        "UPDATE registries set registry_name=registry where registry_name is null"
    )


def fixed_artifacts_upgrade_010_011():
    """
    Runs upgrade to add the 'fix_observed_at' column to fixed_artifacts records

    :return:
    """

    from anchore_engine.db import session_scope

    engine = anchore_engine.db.entities.common.get_engine()

    new_columns = [
        {
            "table_name": "feed_data_vulnerabilities_fixed_artifacts",
            "columns": [
                Column("fix_observed_at", DateTime()),
            ],
        }
    ]

    log.err("creating new table columns")
    for table in new_columns:
        for column in table["columns"]:
            log.err(
                "creating new column ({}) in table ({})".format(
                    column.name, table.get("table_name", "")
                )
            )
            try:
                cn = column.compile(dialect=engine.dialect)
                ct = column.type.compile(engine.dialect)
                engine.execute(
                    "ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s"
                    % (table["table_name"], cn, ct)
                )
            except Exception as e:
                log.err(
                    "failed to perform DB upgrade on {} adding column - exception: {}".format(
                        table, str(e)
                    )
                )
                raise Exception(
                    "failed to perform DB upgrade on {} adding column - exception: {}".format(
                        table, str(e)
                    )
                )

    # populate new column
    rc = engine.execute(
        "UPDATE feed_data_vulnerabilities_fixed_artifacts set fix_observed_at=updated_at where fix_observed_at is null and version!='None'"
    )


def update_users_010_011():
    """
    Upgrade to add column to users table
    :return:
    """
    from anchore_engine.configuration import localconfig
    from anchore_engine.db.entities.identity import UserTypes, anchore_uuid

    engine = anchore_engine.db.entities.common.get_engine()

    new_columns = [
        {
            "table_name": "account_users",
            "columns": [
                Column(
                    "type",
                    Enum(UserTypes, name="user_types"),
                    nullable=False,
                    default=UserTypes.native,
                ),
                Column(
                    "uuid",
                    String,
                    unique=True,
                    nullable=False,
                    default=anchore_uuid,
                    index=True,
                ),
                Column("source", String),
            ],
        }
    ]

    log.err("creating new table columns")
    for table in new_columns:
        for column in table["columns"]:
            log.err(
                "creating new column ({}) in table ({})".format(
                    column.name, table.get("table_name", "")
                )
            )
            try:
                cn = column.compile(dialect=engine.dialect)
                ct = column.type.compile(engine.dialect)
                engine.execute(
                    "ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s"
                    % (table["table_name"], cn, ct)
                )
            except Exception as e:
                log.err(
                    "failed to perform DB upgrade on {} adding column - exception: {}".format(
                        table, str(e)
                    )
                )
                raise Exception(
                    "failed to perform DB upgrade on {} adding column - exception: {}".format(
                        table, str(e)
                    )
                )

    # populate with default for system user
    rc = engine.execute(
        "UPDATE account_users set type='internal' where username = '%s'"
        % localconfig.SYSTEM_USERNAME
    )

    # populate with default for system user
    rc = engine.execute(
        "UPDATE account_users set type='native' where username <> '%s'"
        % localconfig.SYSTEM_USERNAME
    )

    users = engine.execute("SELECT username from account_users where uuid is null")
    for row in users:
        username = row["username"]
        rc = engine.execute(
            "UPDATE account_users set uuid='%s' where username='%s'"
            % (anchore_uuid(), username)
        )

    # Add constraints and index
    rc = engine.execute("ALTER TABLE account_users ALTER COLUMN uuid set not null")
    rc = engine.execute("ALTER TABLE account_users ALTER COLUMN type set not null")
    rc = engine.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS ix_account_users_uuid on account_users (uuid)"
    )


def db_upgrade_010_011():
    registry_name_upgrade_010_011()
    fixed_artifacts_upgrade_010_011()
    update_users_010_011()


def db_upgrade_package_size_011_012():
    """
    Update the column type for image package size from int to bigint
    :return:
    """
    from anchore_engine.db import session_scope

    engine = anchore_engine.db.entities.common.get_engine()

    # Add constraints and index
    log.err("Updating image package table size column from int to bigint")
    rc = engine.execute("ALTER TABLE image_packages ALTER COLUMN size type bigint")


def event_type_index_upgrade_011_012():
    """
    Runs upgrade to add the 'category' column to events records

    :return:
    """

    from anchore_engine.db import session_scope

    engine = anchore_engine.db.entities.common.get_engine()

    log.err("creating new column index")
    engine.execute("CREATE INDEX IF NOT EXISTS ix_type ON events using btree (type)")


def db_upgrade_011_012():
    event_type_index_upgrade_011_012()
    db_upgrade_package_size_011_012()


def upgrade_feed_groups_013():
    log.err("Upgrading feed and feed group schemas to add enabled flags")

    from anchore_engine.services.policy_engine.engine.feeds import sync

    engine = anchore_engine.db.entities.common.get_engine()

    log.err("Updating feeds table to have enabled flag")
    engine.execute("ALTER TABLE feeds ADD COLUMN IF NOT EXISTS enabled boolean")
    engine.execute("UPDATE feeds set enabled = TRUE")

    log.err("Updating feed_groups table to have enabled flag")
    engine.execute("ALTER TABLE feed_groups ADD COLUMN IF NOT EXISTS enabled boolean")
    engine.execute("UPDATE feed_groups set enabled = TRUE")

    log.err("Updating feed groups table to have count for each group")
    engine.execute("ALTER TABLE feed_groups ADD COLUMN IF NOT EXISTS count bigint")

    log.err("Updating feed groups table to have last_update for each group")
    engine.execute(
        "ALTER TABLE feed_groups ADD COLUMN IF NOT EXISTS last_update timestamp"
    )
    engine.execute(
        "UPDATE feed_groups set last_update = last_sync where last_update is NULL"
    )

    # Update the counts
    sync.DataFeeds.update_counts()


def upgrade_distro_mappings_rhel_013():
    """
    Updates distro map entries to use rhel feed instead of centos feed

    """
    engine = anchore_engine.db.entities.common.get_engine()

    log.err(
        'Updating distro mappings to map centos, fedora, and rhel to new feed distro "rhel"'
    )
    rc = engine.execute(
        "UPDATE distro_mappings set to_distro = 'rhel' where from_distro in ('centos', 'fedora', 'rhel') and to_distro = 'centos'"
    )
    log.err("Return = {}".format(rc.rowcount))
    log.err(
        "Mapping updated. All centos, fedora, and rhel images will now get vulnerability data from the vulnerabilities/rhel:* feed groups instead of vulnerabilities/centos:*"
    )


def upgrade_flush_centos_vulns_013():
    """
    Disable all centos feeds in the db
    Flush all vuln matches from centos
    Flush all vuln records from centos groups

    :return:
    """
    from anchore_engine.services.policy_engine.engine.feeds import sync
    from anchore_engine.services.policy_engine.engine.feeds.feeds import (
        have_vulnerabilities_for,
    )
    from anchore_engine.services.policy_engine.engine.vulnerabilities import (
        DistroNamespace,
    )

    engine = anchore_engine.db.entities.common.get_engine()

    log.err("Disabling all centos feed groups")
    rc = engine.execute(
        "UPDATE feed_groups set enabled = false where name like 'centos:%%'"
    )
    log.err("Return = {}".format(rc.rowcount))
    log.err("Centos feed groups disabled")

    log.err(
        "Updating centos and rhel-based image vulnerability matches to be use the new rhel feed for CVE matches instead of centos feed, which provides RHSA. This is reversible if desired. See documentation"
    )
    upgrade_centos_rhel_synced_013()

    for v in ["5", "6", "7", "8"]:
        centos_ns = "centos:{}".format(v)
        rhel_ns = "rhel:{}".format(v)
        t = time.time()
        if have_vulnerabilities_for(DistroNamespace("rhel", v, "rhel")):
            log.err(
                "Flushing centos:5 feed data since {} synced and update has migrated matches".format(
                    rhel_ns
                )
            )
            sync.DataFeeds.delete_feed_group("vulnerabilities", "{}".format(centos_ns))
            log.err(
                "Took {} seconds for flush of {} data".format(
                    time.time() - t, centos_ns
                )
            )

    log.err(
        "Migration of centos & rhel package matches from centos:* group data to rhel:* data and RHSA to CVE matches is complete"
    )


def upgrade_centos_rhel_synced_013():
    """
    Condition: rhel feeds synced, can move images over
    Action: Update matched packages against rhel data

    :return:
    """
    from anchore_engine.db import session_scope
    from anchore_engine.services.policy_engine.engine.vulnerabilities import (
        rescan_namespace,
    )

    log.err(
        "Scanning all images applicable for the rhel data feed to create matches based on new CVE data in rhel:* groups in addition to RHSA-based data from old centos:* groups. This may take a while"
    )

    t = time.time()
    # Add the RHEL feed matches
    with session_scope() as db:
        rescan_namespace(db, "rhel:5")
    log.err("Creating rhel:5 matches took {} seconds".format(time.time() - t))

    with session_scope() as db:
        rescan_namespace(db, "rhel:6")
    log.err("Creating rhel:6 matches took {} seconds".format(time.time() - t))

    with session_scope() as db:
        rescan_namespace(db, "rhel:7")
    log.err("Creating rhel:7 matches took {} seconds".format(time.time() - t))

    with session_scope() as db:
        rescan_namespace(db, "rhel:8")
    log.err("Creating rhel:8 matches took {} seconds".format(time.time() - t))


def db_upgrade_012_013():
    """
    Upgrade schema from 0.0.12 --> 0.0.13

    :return:
    """
    # Setup some policy engine stuff to support feed ops
    from anchore_engine.services.policy_engine import process_preflight

    process_preflight()

    upgrade_feed_groups_013()
    upgrade_distro_mappings_rhel_013()
    upgrade_flush_centos_vulns_013()


def upgrade_014_archive_rules():
    from anchore_engine.db import session_scope

    engine = anchore_engine.db.entities.common.get_engine()

    new_columns = [
        {
            "table_name": "catalog_archive_transition_rules",
            "columns": [
                Column(
                    "exclude_selector_registry",
                    String,
                ),
                Column(
                    "exclude_selector_repository",
                    String,
                ),
                Column(
                    "exclude_selector_tag",
                    String,
                ),
                Column(
                    "exclude_expiration_days",
                    Integer,
                ),
                Column("max_images_per_account", Integer),
            ],
        }
    ]

    log.err("creating new table columns")
    for table in new_columns:
        for column in table["columns"]:
            log.err(
                "creating new column ({}) in table ({})".format(
                    column.name, table.get("table_name", "")
                )
            )
            try:
                cn = column.compile(dialect=engine.dialect)
                ct = column.type.compile(engine.dialect)
                engine.execute(
                    "ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s"
                    % (table["table_name"], cn, ct)
                )
            except Exception as e:
                log.err(
                    "failed to perform DB upgrade on {} adding column - exception: {}".format(
                        table, str(e)
                    )
                )
                raise Exception(
                    "failed to perform DB upgrade on {} adding column - exception: {}".format(
                        table, str(e)
                    )
                )


def remove_policy_engine_sizes():
    """
    Removes all varchar size hints for policy engine tables

    :return:
    """
    engine = anchore_engine.db.entities.common.get_engine()

    to_update = [
        # Feeds
        ("feeds", "name"),
        ("feeds", "description"),
        # Feed Groups
        ("feed_groups", "description"),
        ("feed_groups", "name"),
        # GenericFeedDataRecord
        ("feed_group_data", "feed"),
        ("feed_group_data", "group"),
        ("feed_group_data", "id"),
        # GemMetadata
        ("feed_data_gem_packages", "name"),
        ("feed_data_gem_packages", "latest"),
        # NpmMetadata
        ("feed_data_npm_packages", "name"),
        ("feed_data_npm_packages", "sourcepkg"),
        ("feed_data_npm_packages", "latest"),
        # Vulnerability
        ("feed_data_vulnerabilities", "id"),
        ("feed_data_vulnerabilities", "namespace_name"),
        ("feed_data_vulnerabilities", "link"),
        # VulnerableArtifact
        ("feed_data_vulnerabilities_vulnerable_artifacts", "vulnerability_id"),
        ("feed_data_vulnerabilities_vulnerable_artifacts", "namespace_name"),
        ("feed_data_vulnerabilities_vulnerable_artifacts", "name"),
        ("feed_data_vulnerabilities_vulnerable_artifacts", "version"),
        ("feed_data_vulnerabilities_vulnerable_artifacts", "version_format"),
        ("feed_data_vulnerabilities_vulnerable_artifacts", "epochless_version"),
        # FixedArtifact
        ("feed_data_vulnerabilities_fixed_artifacts", "vulnerability_id"),
        ("feed_data_vulnerabilities_fixed_artifacts", "namespace_name"),
        ("feed_data_vulnerabilities_fixed_artifacts", "name"),
        ("feed_data_vulnerabilities_fixed_artifacts", "version"),
        ("feed_data_vulnerabilities_fixed_artifacts", "version_format"),
        ("feed_data_vulnerabilities_fixed_artifacts", "epochless_version"),
        # CpeVulnerability
        # ('feed_data_cpe_vulnerabilities', 'feed_name'),
        # ('feed_data_cpe_vulnerabilities', 'namespace_name'),
        # ('feed_data_cpe_vulnerabilities', 'vulnerability_id'),
        # ('feed_data_cpe_vulnerabilities', 'cpetype'),
        # ('feed_data_cpe_vulnerabilities', 'vendor'),
        # ('feed_data_cpe_vulnerabilities', 'name'),
        # ('feed_data_cpe_vulnerabilities', 'version'),
        # ('feed_data_cpe_vulnerabilities', 'update'),
        # ('feed_data_cpe_vulnerabilities', 'meta'),
        # ('feed_data_cpe_vulnerabilities', 'link'),
        #
        # # NvdMetadata (has cast error, but this is deprecated table, so skip
        # ('feed_data_nvd_vulnerabilities', 'name'),
        # ('feed_data_nvd_vulnerabilities', 'namespace_name'),
        # ('feed_data_nvd_vulnerabilities', 'summary'),
        # NvdV2Metadata
        ("feed_data_nvdv2_vulnerabilities", "name"),
        ("feed_data_nvdv2_vulnerabilities", "namespace_name"),
        ("feed_data_nvdv2_vulnerabilities", "description"),
        ("feed_data_nvdv2_vulnerabilities", "link"),
        # VulnDBMetadata
        ("feed_data_vulndb_vulnerabilities", "name"),
        ("feed_data_vulndb_vulnerabilities", "namespace_name"),
        ("feed_data_vulndb_vulnerabilities", "title"),
        ("feed_data_vulndb_vulnerabilities", "description"),
        ("feed_data_vulndb_vulnerabilities", "solution"),
        # CpeV2Vulnerability
        ("feed_data_cpev2_vulnerabilities", "feed_name"),
        ("feed_data_cpev2_vulnerabilities", "namespace_name"),
        ("feed_data_cpev2_vulnerabilities", "vulnerability_id"),
        ("feed_data_cpev2_vulnerabilities", "part"),
        ("feed_data_cpev2_vulnerabilities", "vendor"),
        ("feed_data_cpev2_vulnerabilities", "product"),
        ("feed_data_cpev2_vulnerabilities", "version"),
        ("feed_data_cpev2_vulnerabilities", "update"),
        ("feed_data_cpev2_vulnerabilities", "edition"),
        ("feed_data_cpev2_vulnerabilities", "language"),
        ("feed_data_cpev2_vulnerabilities", "sw_edition"),
        ("feed_data_cpev2_vulnerabilities", "target_sw"),
        ("feed_data_cpev2_vulnerabilities", "target_hw"),
        ("feed_data_cpev2_vulnerabilities", "other"),
        # VulnDBCpe
        ("feed_data_vulndb_cpes", "feed_name"),
        ("feed_data_vulndb_cpes", "namespace_name"),
        ("feed_data_vulndb_cpes", "vulnerability_id"),
        ("feed_data_vulndb_cpes", "part"),
        ("feed_data_vulndb_cpes", "vendor"),
        ("feed_data_vulndb_cpes", "product"),
        ("feed_data_vulndb_cpes", "version"),
        ("feed_data_vulndb_cpes", "update"),
        ("feed_data_vulndb_cpes", "edition"),
        ("feed_data_vulndb_cpes", "language"),
        ("feed_data_vulndb_cpes", "sw_edition"),
        ("feed_data_vulndb_cpes", "target_sw"),
        ("feed_data_vulndb_cpes", "target_hw"),
        ("feed_data_vulndb_cpes", "other"),
        # ImagePackage
        ("image_packages", "image_id"),
        ("image_packages", "image_user_id"),
        ("image_packages", "name"),
        ("image_packages", "version"),
        ("image_packages", "pkg_type"),
        ("image_packages", "arch"),
        ("image_packages", "pkg_path"),
        ("image_packages", "pkg_path_hash"),
        ("image_packages", "distro_name"),
        ("image_packages", "distro_version"),
        ("image_packages", "like_distro"),
        ("image_packages", "fullversion"),
        ("image_packages", "release"),
        ("image_packages", "origin"),
        ("image_packages", "src_pkg"),
        ("image_packages", "normalized_src_pkg"),
        ("image_packages", "license"),
        # ImagePackageManifest
        ("image_package_db_entries", "image_id"),
        ("image_package_db_entries", "image_user_id"),
        ("image_package_db_entries", "pkg_name"),
        ("image_package_db_entries", "pkg_version"),
        ("image_package_db_entries", "pkg_type"),
        ("image_package_db_entries", "pkg_arch"),
        ("image_package_db_entries", "pkg_path"),
        ("image_package_db_entries", "file_path"),
        ("image_package_db_entries", "digest"),
        ("image_package_db_entries", "digest_algorithm"),
        ("image_package_db_entries", "file_group_name"),
        ("image_package_db_entries", "file_user_name"),
        # ImageNpm
        ("image_npms", "image_user_id"),
        ("image_npms", "image_id"),
        ("image_npms", "path_hash"),
        ("image_npms", "path"),
        ("image_npms", "name"),
        ("image_npms", "source_pkg"),
        ("image_npms", "latest"),
        # ImageGem
        ("image_gems", "image_user_id"),
        ("image_gems", "image_id"),
        ("image_gems", "path_hash"),
        ("image_gems", "path"),
        ("image_gems", "name"),
        ("image_gems", "source_pkg"),
        ("image_gems", "latest"),
        # ImageCpe
        ("image_cpes", "image_user_id"),
        ("image_cpes", "image_id"),
        ("image_cpes", "pkg_type"),
        ("image_cpes", "pkg_path"),
        ("image_cpes", "cpetype"),
        ("image_cpes", "vendor"),
        ("image_cpes", "name"),
        ("image_cpes", "version"),
        ("image_cpes", "update"),
        ("image_cpes", "meta"),
        # FilesystemAnalysis
        ("image_fs_analysis_dump", "image_user_id"),
        ("image_fs_analysis_dump", "image_id"),
        ("image_fs_analysis_dump", "compressed_content_hash"),
        ("image_fs_analysis_dump", "compression_algorithm"),
        # AnalysisArtifact
        ("image_analysis_artifacts", "image_id"),
        ("image_analysis_artifacts", "image_user_id"),
        ("image_analysis_artifacts", "analyzer_id"),
        ("image_analysis_artifacts", "analyzer_artifact"),
        ("image_analysis_artifacts", "analyzer_type"),
        ("image_analysis_artifacts", "artifact_key"),
        # Image
        ("images", "id"),
        ("images", "user_id"),
        ("images", "digest"),
        ("images", "distro_name"),
        ("images", "distro_version"),
        ("images", "like_distro"),
        ("images", "dockerfile_mode"),
        # ImagePackageVulnerability
        ("image_package_vulnerabilities", "pkg_user_id"),
        ("image_package_vulnerabilities", "pkg_image_id"),
        ("image_package_vulnerabilities", "pkg_name"),
        ("image_package_vulnerabilities", "pkg_version"),
        ("image_package_vulnerabilities", "pkg_type"),
        ("image_package_vulnerabilities", "pkg_arch"),
        ("image_package_vulnerabilities", "pkg_path"),
        ("image_package_vulnerabilities", "vulnerability_id"),
        ("image_package_vulnerabilities", "vulnerability_namespace_name"),
        # DistroMapping
        ("distro_mappings", "from_distro"),
        ("distro_mappings", "to_distro"),
        ("distro_mappings", "flavor"),
        # PolicyEvaluationCache
        ("policy_engine_evaluation_cache", "user_id"),
        ("policy_engine_evaluation_cache", "image_id"),
        ("policy_engine_evaluation_cache", "eval_tag"),
        ("policy_engine_evaluation_cache", "bundle_id"),
        ("policy_engine_evaluation_cache", "bundle_digest"),
        ("policy_engine_evaluation_cache", "user_id"),
    ]

    log.err("Updating tables")
    for table_name, column_name in to_update:
        log.err(
            "Updating table {} column {} to varchar".format(table_name, column_name)
        )
        try:
            rc = engine.execute(
                'ALTER TABLE {} ALTER COLUMN "{}" type varchar'.format(
                    table_name, column_name
                )
            )
        except Exception as ex:
            log.err(
                "Failed updating {} column {} type to varchar. Err: {}".format(
                    table_name, column_name, str(ex)
                )
            )
            raise ex


def upgrade_oauth_client_014():
    """
    Changes required in db model for moving from authlib 0.12.3 -> 0.15.2
    New column in db as defined in the Authlib oauth2 client mixin type

    :return:
    """

    # TODO: should probably just drop and re-create this table for upgrade
    # Would only affect sessions/tokens that can be reset after a system upgrade anyway.

    engine = anchore_engine.db.entities.common.get_engine()

    new_columns = [
        {
            "table_name": "oauth2_clients",
            "columns": [
                Column(
                    "client_metadata",
                    Text,
                ),
                Column(
                    "client_id_issued_at",
                    Integer,
                ),
                Column(
                    "client_secret_expires_at",
                    Integer,
                ),
            ],
        }
    ]

    log.err("creating new table columns")
    for table in new_columns:
        for column in table["columns"]:
            log.err(
                "creating new column ({}) in table ({})".format(
                    column.name, table.get("table_name", "")
                )
            )
            try:
                cn = column.compile(dialect=engine.dialect)
                ct = column.type.compile(engine.dialect)
                engine.execute(
                    "ALTER TABLE %s ADD COLUMN IF NOT EXISTS %s %s"
                    % (table["table_name"], cn, ct)
                )
            except Exception as e:
                log.err(
                    "failed to perform DB upgrade on {} adding column - exception: {}".format(
                        table, str(e)
                    )
                )
                raise Exception(
                    "failed to perform DB upgrade on {} adding column - exception: {}".format(
                        table, str(e)
                    )
                )

    drop_columns = [
        {
            "table_name": "oauth2_clients",
            "columns": [
                "issued_at",
                "expires_at",
                "redirect_url",
                "token_endpoint_auth_method",
                "grant_type",
                "response_type",
                "scope",
                "logo_uri",
                "contact",
                "tos_uri",
                "policy_uri",
                "jwks_uri",
                "jwks_text",
                "i18n_metadata",
                "software_id",
                "software_version",
            ],
        }
    ]
    log.err("creating new table columns")
    for table in drop_columns:
        for column in table["columns"]:
            log.err(
                "creating dropping column ({}) in table ({})".format(
                    column, table.get("table_name", "")
                )
            )
            try:
                engine.execute(
                    "ALTER TABLE %s DROP COLUMN IF EXISTS %s"
                    % (table["table_name"], column)
                )
            except Exception as e:
                log.err(
                    "failed to perform DB upgrade on {} adding column - exception: {}".format(
                        table, str(e)
                    )
                )
                raise Exception(
                    "failed to perform DB upgrade on {} adding column - exception: {}".format(
                        table, str(e)
                    )
                )


def db_upgrade_013_014():
    remove_policy_engine_sizes()
    upgrade_014_archive_rules()
    upgrade_oauth_client_014()


# Global upgrade definitions. For a given version these will be executed in order of definition here
# If multiple functions are defined for a version pair, they will be executed in order.
# If any function raises and exception, the upgrade is failed and halted.
upgrade_functions = (
    (("0.0.1", "0.0.2"), [db_upgrade_001_002]),
    (("0.0.2", "0.0.3"), [db_upgrade_002_003]),
    (("0.0.3", "0.0.4"), [db_upgrade_003_004]),
    (("0.0.4", "0.0.5"), [db_upgrade_004_005]),
    (("0.0.5", "0.0.6"), [db_upgrade_005_006]),
    (("0.0.6", "0.0.7"), [db_upgrade_006_007]),
    (("0.0.7", "0.0.8"), [db_upgrade_007_008]),
    (("0.0.8", "0.0.9"), [db_upgrade_008_009]),
    (("0.0.9", "0.0.10"), [db_upgrade_009_010]),
    (("0.0.10", "0.0.11"), [db_upgrade_010_011]),
    (("0.0.11", "0.0.12"), [db_upgrade_011_012]),
    (("0.0.12", "0.0.13"), [db_upgrade_012_013]),
    (("0.0.13", "0.0.14"), [db_upgrade_013_014]),
)
