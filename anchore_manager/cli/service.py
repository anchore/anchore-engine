import os
import re
import sys
import json
import time
import click
import psutil
import importlib
import traceback
import threading
import subprocess
import watchdog
import anchore_engine.configuration.localconfig

from watchdog.observers import Observer
from watchdog.events import RegexMatchingEventHandler

from anchore_engine.subsys import logger
import anchore_engine.db.entities.common
from anchore_engine.db.entities.exceptions import TableNotFoundError
from anchore_engine.db.entities.exceptions import is_table_not_found

import anchore_manager.cli.utils

service_map = {
    'analyzer': 'anchore-worker',
    'simplequeue': 'anchore-simplequeue',
    'apiext': 'anchore-api',
    'catalog': 'anchore-catalog',
    'kubernetes_webhook': 'anchore-kubernetes-webhook',
    'policy_engine': 'anchore-policy-engine'
}


class AnchoreLogWatcher(RegexMatchingEventHandler):
    regexes = [re.compile(".*/anchore-.*\.log$")]
    files = {}

    def do_close(self, event):
        if event.src_path in self.files and self.files[event.src_path]['filehandle']:
            self.files[event.src_path]['filehandle'].close()
        self.files[event.src_path] = {'filehandle': None, 'filetell': 0}

    def on_deleted(self, event):
        if event.src_path not in self.files:
            self.files[event.src_path] = {'filehandle': None, 'filetell': 0}

        self.do_close(event)

    def on_modified(self, event):
        if event.src_path not in self.files:
            self.files[event.src_path] = {'filehandle': None, 'filetell': 0}

        if not self.files[event.src_path]['filehandle']:
            if os.path.exists(event.src_path):
                self.files[event.src_path]['filehandle'] = open(event.src_path)

        if self.files[event.src_path]['filehandle']:
            patt = re.match(".*anchore-(.*)\.log$", event.src_path)
            if patt:
                logname = patt.group(1)
            else:
                logname = event.src_path

            for line in self.files[event.src_path]['filehandle'].readlines():
                sys.stdout.write("[service:" + str(logname) + "] " + line)

            self.files[event.src_path]['filetell'] = self.files[event.src_path]['filehandle'].tell()

    def on_created(self, event):
        if event.src_path not in self.files:
            self.files[event.src_path] = {'filehandle': None, 'filetell': 0}

        if self.files[event.src_path]['filehandle']:
            self.do_close(event)

        if os.path.exists(event.src_path):
            self.files[event.src_path]['filehandle'] = open(event.src_path)
            self.files[event.src_path]['filetell'] = 0

    def on_moved(self, event):
        if event.src_path not in self.files:
            self.files[event.src_path] = {'filehandle': None, 'filetell': 0}
        self.on_created(event)

    def on_any_event(self, event):
        if event.src_path not in self.files:
            self.files[event.src_path] = {'filehandle': None, 'filetell': 0}


class ServiceThread():

    def __init__(self, thread_target, thread_args):
        self.thread_target = thread_target
        self.thread_args = thread_args
        self.start()

    def start(self):
        self.thread = threading.Thread(target=self.thread_target, args=self.thread_args)
        self.thread.name = self.thread_args[0]
        self.thread.start()


def terminate_service(service, flush_pidfile=False):
    pidfile = "/var/run/" + service + ".pid"
    try:
        logger.info("Looking for pre-existing service ({}) pid from pidfile ({})".format(service, pidfile))
        thepid = None
        if os.path.exists(pidfile):
            with open(pidfile, 'r') as FH:
                thepid = int(FH.read())

        if thepid:
            # get some additional information about the pid to determine whether or not to run the kill operations
            thepid_is_theservice = False
            try:
                running_pid = psutil.Process(thepid)
                cmdline = running_pid.cmdline()
                if pidfile in cmdline:
                    thepid_is_theservice = True
                    logger.info("Found existing service ({}) running with pid ({})".format(service, thepid))
                else:
                    logger.info("Found pid running but belongs to unrelated process - skipping terminate")
            except Exception as err:
                thepid_is_theservice = False
                
            if thepid_is_theservice:
                try:
                    logger.info("Terminating existing service ({}) with pid ({}) using signal 0".format(service, thepid))
                    os.kill(thepid, 0)
                except OSError:
                    pass
                else:
                    logger.info("Terminating existing service ({}) with pid ({}) using signal 9".format(service, thepid))
                    os.kill(thepid, 9)


            if flush_pidfile:
                logger.info("Removing stale pidfile ({}) for service ({})".format(pidfile, service))
                os.remove(pidfile)
    except Exception as err:
        logger.info("Could not detect/shut down running service ({}) - exception: {}".format(service, str(err)))


def startup_service(service, configdir):
    pidfile = "/var/run/" + service + ".pid"
    logfile = "/var/log/anchore/" + service + ".log"
    # os.environ['ANCHORE_LOGFILE'] = logfile

    logger.info("cleaning up service: {}".format(str(service)))
    terminate_service(service, flush_pidfile=True)

    twistd_cmd = '/bin/twistd'
    for f in ['/bin/twistd', '/usr/local/bin/twistd']:
        if os.path.exists(f):
            twistd_cmd = f

    cmd = [twistd_cmd, '--logger=anchore_engine.subsys.twistd_logger.logger', '--pidfile', pidfile, "-n", service, '--config', configdir]
    logger.info("starting service: {}".format(str(service)))
    logger.info("\t {}".format(' '.join(cmd)))

    try:
        newenv = os.environ.copy()
        newenv['ANCHORE_LOGFILE'] = logfile
        pipes = subprocess.Popen(cmd, env=newenv)
        sout, serr = pipes.communicate()
        rc = pipes.returncode
        raise Exception("process exited: " + str(rc))
    except Exception as err:
        logger.exception("service process exited at ({}): {}".format(str(time.ctime()), str(err)))
        logger.fatal('Could not start service due to: {}'.format(str(err)))

    logger.info("exiting service thread")

    return (False)

config = {}
module = None

@click.group(name='service', short_help='Service operations')
@click.pass_obj
def service(ctx_config):
    global config, module
    config = ctx_config

    try:
        # do some DB connection/pre-checks here
        try:

            log_level = 'INFO'
            if config['debug']:
                log_level = 'DEBUG'
            logger.set_log_level(log_level, log_to_stdout=True)

        except Exception as err:
            raise err

    except Exception as err:
        logger.error(anchore_manager.cli.utils.format_error_output(config, 'service', {}, err))
        sys.exit(2)

@service.command(name='list', short_help="List valid service names")
@click.option('--anchore-module', help='Module to list services for', default='anchore_engine')
def do_list(anchore_module):
    click.echo('Locally installed and available service types:')
    from anchore_engine.service import BaseService

    # Expects a services module within the base module
    importlib.import_module(anchore_module + '.services')
    for name in BaseService.registry.keys():
        click.echo(name)
    anchore_manager.cli.utils.doexit(0)
    return

@service.command(name='start', short_help="Start anchore-engine")
@click.argument('services', nargs=-1)
@click.option("--auto-upgrade", is_flag=True, help="Perform automatic upgrade on startup")
@click.option("--anchore-module", nargs=1, help="Name of anchore module to call DB routines from (default=anchore_engine)")
@click.option("--skip-config-validate", nargs=1, help="Comma-separated list of configuration file sections to skip specific validation processing (e.g. services,credentials,webhooks)")
@click.option("--skip-db-compat-check", is_flag=True, help="Skip the database compatibility check.")
@click.option("--all", is_flag=True, default=False)
def start(services, auto_upgrade, anchore_module, skip_config_validate, skip_db_compat_check, all):
    """
    Startup and monitor service processes. Specify a list of service names or empty for all.
    """

    global config
    ecode = 0

    auto_upgrade = True

    if not anchore_module:
        module_name = "anchore_engine"
    else:
        module_name = str(anchore_module)

    if os.environ.get('ANCHORE_ENGINE_SKIP_DB_COMPAT_CHECK', str(skip_db_compat_check)).lower() in ['true', 't', 'y', 'yes']:
        skip_db_compat_check = True
    else:
        skip_db_compat_check = False

    if services:
        input_services = list(services)
    else:
        input_services = os.getenv('ANCHORE_ENGINE_SERVICES', '').strip().split()

    if not input_services and not all:
        raise click.exceptions.BadArgumentUsage('No services defined to start. Must either provide service arguments, ANCHORE_ENGINE_SERVICES env var, or --all option')

    try:
        validate_params = {
            'services': True,
            'webhooks': True,
            'credentials': True
        }
        if skip_config_validate:
            try:
                items = skip_config_validate.split(',')
                for item in items:
                    validate_params[item] = False
            except Exception as err:
                raise Exception(err)

        # find/set up configuration        
        configdir = config['configdir']
        configfile = os.path.join(configdir, "config.yaml")

        localconfig = None
        if os.path.exists(configfile):
            try:
                localconfig = anchore_engine.configuration.localconfig.load_config(configdir=configdir, configfile=configfile, validate_params=validate_params)
            except Exception as err:
                raise Exception("cannot load local configuration: " + str(err))
        else:
            raise Exception("cannot locate configuration file ({})".format(configfile))

        # load the appropriate DB module
        try:
            logger.info("Loading DB routines from module ({})".format(module_name))
            module = importlib.import_module(module_name + ".db.entities.upgrade")
        except TableNotFoundError as ex:
            logger.info("Initialized DB not found.")
        except Exception as err:
            raise Exception("Input anchore-module (" + str(module_name) + ") cannot be found/imported - exception: " + str(err))

        # get the list of local services to start
        startFailed = False
        if not input_services:
            config_services = localconfig.get('services', {})
            if not config_services:
                logger.warn('could not find any services to execute in the config file')
                sys.exit(1)

            input_services = [ name for name, srv_conf in list(config_services.items()) if srv_conf.get('enabled')]

        services = []
        for service_conf_name in input_services:
            if service_conf_name in list(service_map.values()):
                svc = service_conf_name
            else:
                svc = service_map.get(service_conf_name)

            if svc:
                services.append(svc)
            else:
                logger.warn('specified service {} not found in list of available services {} - removing from list of services to start'.format(service_conf_name, list(service_map.keys())))

        if 'anchore-catalog' in services:
            services.remove('anchore-catalog')
            services.insert(0, 'anchore-catalog')

        if not services:
            logger.error("No services found in ANCHORE_ENGINE_SERVICES or as enabled in config.yaml to start - exiting")
            sys.exit(1)


        # preflight - db checks
        try:
            db_params = anchore_engine.db.entities.common.get_params(localconfig)
            #override db_timeout since upgrade might require longer db session timeout setting
            try:
                db_params['db_connect_args']['timeout'] = 86400
            except Exception as err:
                pass
            
            anchore_manager.cli.utils.connect_database(config, db_params, db_retries=300)
            code_versions, db_versions = anchore_manager.cli.utils.init_database(upgrade_module=module, localconfig=localconfig, do_db_compatibility_check=(not skip_db_compat_check))

            in_sync = False
            timed_out = False
            max_timeout = 3600

            timer = time.time()
            while not in_sync and not timed_out:
                code_versions, db_versions = module.get_versions()

                if code_versions and db_versions:
                    if code_versions['db_version'] != db_versions['db_version']:
                        if auto_upgrade and 'anchore-catalog' in services:
                            logger.info("Auto-upgrade is set - performing upgrade.")
                            try:
                                # perform the upgrade logic here
                                rc = module.run_upgrade()
                                if rc:
                                    logger.info("Upgrade completed")
                                else:
                                    logger.info("No upgrade necessary. Completed.")
                            except Exception as err:
                                raise err

                            in_sync = True
                        else:
                            logger.warn("this version of anchore-engine requires the anchore DB version ({}) but we discovered anchore DB version ({}) in the running DB - it is safe to run the upgrade while seeing this message - will retry for {} more seconds.".format(str(code_versions['db_version']), str(db_versions['db_version']), str(max_timeout - int(time.time() - timer))))
                            time.sleep(5)
                    else:
                        logger.info("DB version and code version in sync.")
                        in_sync = True
                else:
                    logger.warn('no existing anchore DB data can be discovered, assuming bootstrap')
                    in_sync = True

                if (max_timeout - int(time.time() - timer)) < 0:
                    timed_out = True

            if not in_sync:
                raise Exception("this version of anchore-engine requires the anchore DB version ("+str(code_versions['db_version'])+") but we discovered anchore DB version ("+str(db_versions['db_version'])+") in the running DB - please perform the DB upgrade process and retry")

        except Exception as err:
            raise err

        finally:
            rc = anchore_engine.db.entities.common.do_disconnect()

        # start up services
        logger.info('Starting services: {}'.format(services))
        try:
            if not os.path.exists("/var/log/anchore"):
                os.makedirs("/var/log/anchore/", 0o755)
        except Exception as err:
            logger.error("cannot create log directory /var/log/anchore - exception: {}".format(str(err)))
            raise err

        pids = []
        keepalive_threads = []
        for service in services:
            pidfile = "/var/run/" + service + ".pid"
            try:
                terminate_service(service, flush_pidfile=True)

                service_thread = ServiceThread(startup_service, (service, configdir))
                keepalive_threads.append(service_thread)
                max_tries = 30
                tries = 0
                alive = True
                while not os.path.exists(pidfile) and tries < max_tries:
                    logger.info("waiting for service pidfile {} to exist {}/{}".format(pidfile, tries, max_tries))

                    try:
                        alive = service_thread.thread.is_alive()
                    except:
                        pass
                    if not alive:
                        logger.info("service thread has stopped {}".format(service))
                        break

                    time.sleep(1)
                    tries = tries + 1

                logger.info("auto_restart_services setting: {}".format(localconfig.get('auto_restart_services', False)))
                if not localconfig.get('auto_restart_services', False):
                    logger.info("checking for startup failure pidfile={}, is_alive={}".format(os.path.exists(pidfile), alive))
                    if not os.path.exists(pidfile) or not alive:
                        raise Exception("service thread for ({}) failed to start".format(service))

                time.sleep(1)
            except Exception as err:
                startFailed = True
                logger.warn("service start failed - exception: {}".format(str(err)))
                break

        if startFailed:
            logger.fatal("one or more services failed to start. cleanly terminating the others")
            for service in services:
                terminate_service(service, flush_pidfile=True)
            sys.exit(1)
        else:
            # start up the log watchers
            try:
                observer = Observer()
                observer.schedule(AnchoreLogWatcher(), path="/var/log/anchore/")
                observer.start()

                try:
                    while True:
                        time.sleep(1)
                        if localconfig.get('auto_restart_services', False): #'auto_restart_services' in localconfig and localconfig['auto_restart_services']:
                            for service_thread in keepalive_threads:
                                if not service_thread.thread.is_alive():
                                    logger.info("restarting service: {}".format(service_thread.thread.name))
                                    service_thread.start()

                except KeyboardInterrupt:
                    observer.stop()
                observer.join()

            except Exception as err:
                logger.error("failed to startup log watchers - exception: {}".format(str(err)))
                raise err

    except Exception as err:
        logger.error(anchore_manager.cli.utils.format_error_output(config, 'servicestart', {}, err))
        if not ecode:
            ecode = 2
            
    anchore_manager.cli.utils.doexit(ecode)
