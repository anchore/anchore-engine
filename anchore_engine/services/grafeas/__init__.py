import copy
import re
import threading
import time
import traceback
import datetime
import json

import connexion
from twisted.application import internet
from twisted.internet import reactor
from twisted.internet.task import LoopingCall
from twisted.web.wsgi import WSGIResource

# anchore modules
from anchore_engine.clients import catalog, localanchore, simplequeue
import anchore_engine.configuration.localconfig
import anchore_engine.services.common
import anchore_engine.subsys.taskstate
from anchore_engine.subsys import logger

import anchore_engine.clients.policy_engine
from anchore_engine.services.policy_engine.api.models import ImageUpdateNotification, FeedUpdateNotification, ImageVulnerabilityListing, ImageIngressRequest, ImageIngressResponse, LegacyVulnerabilityReport
from anchore_engine.db import session_scope, DistroMapping
from anchore_engine.db import Vulnerability, FixedArtifact, VulnerableArtifact, ImagePackage, ImagePackageVulnerability

import anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client

try:
    application = connexion.FlaskApp(__name__, specification_dir='swagger/')
    application.app.url_map.strict_slashes = False
    application.add_api('swagger.yaml')
    app = application
except Exception as err:
    traceback.print_exc()
    raise err

grafeas_hostport = "localhost:8080"
cve_id_set = pkg_name_set = None

# service funcs (must be here)
def createService(sname, config):
    global app

    try:
        myconfig = config['services'][sname]
    except Exception as err:
        raise err

    try:
        kick_timer = int(myconfig['cycle_timer_seconds'])
    except:
        kick_timer = 1

    doapi = False
    try:
        if myconfig['listen'] and myconfig['port'] and myconfig['endpoint_hostname']:
            doapi = True
    except:
        doapi = False

    if doapi:
        # start up flask service

        flask_site = WSGIResource(reactor, reactor.getThreadPool(), app)
        root = anchore_engine.services.common.getAuthResource(flask_site, sname, config)
        ret_svc = anchore_engine.services.common.createServiceAPI(root, sname, config)

        # start up the monitor as a looping call
        kwargs = {'kick_timer': kick_timer}
        lc = LoopingCall(anchore_engine.services.grafeas.monitor, **kwargs)
        lc.start(1)
    else:
        # start up the monitor as a timer service
        kwargs = {'kick_timer': kick_timer}
        svc = internet.TimerService(1, anchore_engine.services.grafeas.monitor, **kwargs)
        svc.setName(sname)
        ret_svc = svc

    return (ret_svc)

def initializeService(sname, config):
    global grafeas_hostport, cve_id_set, pkg_name_set
    
    myconfig = config['services'][sname]
    if 'grafeas_hostport' in myconfig:
        grafeas_hostport = myconfig['grafeas_hostport']

    if 'cve_id_set' in myconfig:
        try:
            cve_id_set = myconfig['cve_id_set'].split(",")
        except Exception as err:
            logger.error("problem with format of cve_id_set in config (should by comma sep string) - exception: " + str(err))
            cve_id_set = None

    if 'pkg_name_set' in myconfig:
        try:
            pkg_name_set = myconfig['pkg_name_set'].split(",")
        except Exception as err:
            logger.error("problem with format of pkg_name_set in config (should by comma sep string) - exception: " + str(err))
            pkg_name_set = None

    return (anchore_engine.services.common.initializeService(sname, config))

def registerService(sname, config):
    return (anchore_engine.services.common.registerService(sname, config, enforce_unique=False))


############################################

def make_vulnerability_note(cveId, anch_vulns):
    nistInfo = "N/A"
    cvss_score = 0.0
    severity = "UNKNOWN"
    vulnerability_details = []
    external_urls = []
    links = []
    package_type = "N/A"
    long_description = "N/A"

    for anch_vuln in anch_vulns:
        try:
            cvss_score = anch_vuln.cvss2_score
            severity = anch_vuln.severity.upper()
            if severity == 'NEGLIGIBLE':
                severity = 'MINIMAL'

            retel = {
                'cpe_uri': None,
                'package': None,
                'severity_name': None,
                'description': None,
                'min_affected_version': None,
                'max_affected_version': None,
                'fixed_location': None
            }
            distro, distrovers = anch_vuln.namespace_name.split(":", 1)
            retel['cpe_uri'] = "cpe:/o:"+distro+":"+distro+"_linux:"+distrovers
            retel['min_affected_version'] = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Version(kind='MINIMUM')
            retel['severity_name'] = anch_vuln.severity.upper()
            if retel['severity_name'] == 'NEGLIGIBLE':
                retel['severity_name'] = 'MINIMAL'

            retel['description'] = anch_vuln.description
            long_description = anch_vuln.description
            if anch_vuln.link not in links:
                links.append(anch_vuln.link)

            for fixedIn in anch_vuln.fixed_in:
                retel['package'] = fixedIn.name
                package_type = fixedIn.version_format

                # TODO - for vulns that are present that have no fix version, unclear what to set ("MAXIMUM"?)
                if fixedIn.version and fixedIn.version != "None":
                    fix_version = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Version(kind="NORMAL", name=fixedIn.version)
                else:
                    fix_version = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Version(kind="MAXIMUM")

                retel['fixed_location'] = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.VulnerabilityLocation(cpe_uri=retel['cpe_uri'], package=retel['package'], version=fix_version)

                detail = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Detail(**retel)
                vulnerability_details.append(detail)
        except Exception as err:
            logger.warn("not enough info for detail creation - exception: " + str(err))
    
    vulnerability_type = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.VulnerabilityType(
        cvss_score=cvss_score,
        severity=severity,
        details=vulnerability_details,
        package_type=package_type
    )

    for link in links:
        external_urls.append(anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.RelatedUrl(url=link, label="More Info"))

    newnote = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Note(
        name="projects/security-scanner/notes/"+cveId, 
        short_description=cveId,
        long_description=long_description,
        related_url=external_urls,
        kind="PACKAGE_VULNERABILITY",
        create_time=str(datetime.datetime.utcnow()),
        update_time=str(datetime.datetime.utcnow()),
        vulnerability_type=vulnerability_type
    )

    return(newnote)
    
def update_vulnerability_notes(cve_id_set=[]):
    global grafeas_hostport

    anchore_vulns = {}
    db_vulns = []

    with session_scope() as dbsession:
        if cve_id_set:
            logger.debug("fetching limited vulnerability set from anchore DB: " + str(cve_id_set))
            for cveId in cve_id_set:
                try:
                    v = dbsession.query(Vulnerability).filter_by(id=cveId).all()
                    if v[0].id:
                        db_vulns = db_vulns + v
                except Exception as err:
                    logger.warn("configured cve id set ("+str(cveId)+") not found in DB, skipping: " + str(err))
        else:
            logger.debug("fetching full vulnerability set from anchore DB")
            db_vulns = dbsession.query(Vulnerability).all()

        for v in db_vulns:
            #logger.debug("HELLO: " + str(v.__dict__))
            #logger.debug("FIXEDIN: " + str(v.fixed_in))
            #logger.debug("VULNIN: " + str(v.vulnerable_in))
            cveId = v.id
            if v.id not in anchore_vulns:
                anchore_vulns[v.id] = []
            anchore_vulns[v.id].append(v)

        for cveId in anchore_vulns.keys():
            try:
                gnote = make_vulnerability_note(cveId, anchore_vulns[cveId])
                #logger.debug(json.dumps(gnote.to_dict(), indent=4))

                if True:
                    logger.debug("setting up grafeas api client for hostport: " + str(grafeas_hostport))
                    api_client = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.api_client.ApiClient(host=grafeas_hostport)
                    api_instance = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.GrafeasApi(api_client=api_client)
                    projects_id = "security-scanner"
                    note_id = cveId
                    note = gnote

                    try:
                        api_response = api_instance.get_note(projects_id, note_id)
                        logger.debug("note already exists in service, skipping add: " + note_id)
                        # TODO - need to actually diff the note for update case
                    except Exception as err:
                        #logger.debug("get err: " + str(err))
                        try:
                            api_response = api_instance.create_note(projects_id, note_id=note_id, note=note)
                            logger.debug("note added to grafeas service: " + note_id)
                        except Exception as err:
                            logger.warn("could not add note to grafeas service - exception: " + str(err))

            except Exception as err:
                logger.warn("unable to marshal cve id "+str(cveId)+" into vulnerability note - exception: " + str(err))

    return(True)

def make_package_note(pkgName, anch_pkgs):
    distributions = []
    long_description = "N/A"
    external_urls = []

    for anch_pkg in anch_pkgs:
        retel = {
            'cpe_uri': None,
            'architecture': None,
            'latest_version': None,
            'maintainer': None,
            'url': None,
            'description': None
        }

        retel['cpe_uri'] = "cpe:/a:"+pkgName+":"+pkgName+":"+anch_pkg.version

        retel['architecture'] = anch_pkg.arch
        if retel['architecture'] in ['amd64', 'x86_64']:
            retel['architecture'] = 'X86'
        else:
            retel['architecture'] = 'UNKNOWN'

        retel['maintainer'] = anch_pkg.origin
        retel['latest_version'] = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Version(kind="NORMAL", name=anch_pkg.version)
        retel['description'] = "distro="+anch_pkg.distro_name+" distro_version="+anch_pkg.distro_version+" pkg_type="+anch_pkg.pkg_type+" license="+anch_pkg.license+" src_package="+anch_pkg.src_pkg
        retel['url'] = "N/A"

        #logger.debug("MEH: " + str(anch_pkg))
        dist = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Distribution(**retel)
        distributions.append(dist)
    
    package = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Package(name=pkgName, distribution=distributions)

    newnote = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Note(
        name="projects/distro-packages/notes/"+pkgName, 
        short_description=pkgName,
        long_description=long_description,
        related_url=external_urls,
        kind="PACKAGE_MANAGER",
        create_time=str(datetime.datetime.utcnow()),
        update_time=str(datetime.datetime.utcnow()),
        package=package
    )    
    return(newnote)

def update_package_notes(pkg_name_set=[]):
    global grafeas_hostport

    anch_pkgs = {}
    db_pkgs = []
    with session_scope() as dbsession:
        if pkg_name_set:
            logger.debug("fetching limited package set from anchore DB: " + str(pkg_name_set))
            for pkgName in pkg_name_set:
                try:
                    p = dbsession.query(ImagePackage).filter_by(name=pkgName).all()
                    if p[0].name:
                        db_pkgs = db_pkgs + p
                except Exception as err:
                    logger.warn("configured pkg name set ("+str(pkgName)+") not found in DB, skipping: " + str(err))
        else:
            logger.debug("fetching full package set from anchore DB")
            db_pkgs = dbsession.query(ImagePackage).all()
    
        for p in db_pkgs:
            if p.name not in anch_pkgs:
                anch_pkgs[p.name] = []
            anch_pkgs[p.name].append(p)

        for pkgName in anch_pkgs.keys():
            try:
                gnote = make_package_note(pkgName, anch_pkgs[pkgName])
                #logger.debug(json.dumps(gnote.to_dict(), indent=4))
                if True:
                    logger.debug("setting up grafeas api client for hostport: " + str(grafeas_hostport))
                    api_client = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.api_client.ApiClient(host=grafeas_hostport)
                    api_instance = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.GrafeasApi(api_client=api_client)
                    projects_id = "distro-packages"
                    note_id = pkgName
                    note = gnote

                    try:
                        api_response = api_instance.get_note(projects_id, note_id)
                        logger.debug("note already exists in service, skipping add: " + note_id)
                        # TODO - need to actually diff the note for update case
                    except Exception as err:
                        logger.debug("get err: " + str(err))
                        try:
                            api_response = api_instance.create_note(projects_id, note_id=note_id, note=note)
                            logger.debug("note added to grafeas service: " + note_id)
                        except Exception as err:
                            logger.warn("could not add note to grafeas service - exception: " + str(err))


            except Exception as err:
                logger.warn("unable to marshal package "+str(pkgName)+" into package note - exception: " + str(err))


    return(True)

click = 0
running = False
last_run = 0
system_user_auth = ('anchore-system', '')
current_avg = 0.0
current_avg_count = 0.0

def monitor_func(**kwargs):
    global click, running, last_run, system_user_auth, grafeas_hostport, cve_id_set, pkg_name_set

    timer = int(time.time())
    if click < 5:
        click = click + 1
        logger.debug("Service starting in: " + str(5 - click))
        return (True)

    if round(time.time() - last_run) < kwargs['kick_timer']:
        logger.spew(
            "timer hasn't kicked yet: " + str(round(time.time() - last_run)) + " : " + str(kwargs['kick_timer']))
        return (True)

    try:
        running = True
        last_run = time.time()
        logger.debug("FIRING: grafeas")

        localconfig = anchore_engine.configuration.localconfig.get_config()
        system_user_auth = localconfig['system_user_auth']
        verify = localconfig['internal_ssl_verify']

        try:
            update_vulnerability_notes(cve_id_set=cve_id_set)
            pass
        except Exception as err:
            logger.error("unable to populate vulnerability notes - exception: " + str(err))

        try:
            update_package_notes(pkg_name_set=pkg_name_set)
            pass
        except Exception as err:
            logger.error("unable to populate package notes - exception: " + str(err))

    except Exception as err:
        logger.error(str(err))
    finally:
        running = False
        logger.debug("FIRING DONE: grafeas: " + str(int(time.time()) - timer))

    return (True)


monitor_thread = None


def monitor(**kwargs):
    global monitor_thread
    try:
        donew = False
        if monitor_thread:
            if monitor_thread.isAlive():
                logger.spew("MON: thread still running")
            else:
                logger.spew("MON: thread stopped running")
                donew = True
                monitor_thread.join()
                logger.spew("MON: thread joined: " + str(monitor_thread.isAlive()))
        else:
            logger.spew("MON: no thread")
            donew = True

        if donew:
            logger.spew("MON: starting")
            monitor_thread = threading.Thread(target=monitor_func, kwargs=kwargs)
            monitor_thread.start()
        else:
            logger.spew("MON: skipping")

    except Exception as err:
        logger.warn("MON thread start exception: " + str(err))
