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
cve_id_set = pkg_name_set = img_id_set = None
occurrence_name_map = {}
myconfig = {}

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
    global grafeas_hostport, cve_id_set, pkg_name_set, img_id_set, myconfig
    
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

    if 'img_id_set' in myconfig:
        try:
            img_id_set = myconfig['img_id_set'].split(",")
        except Exception as err:
            logger.error("problem with format of img_id_set in config (should by comma sep string) - exception: " + str(err))
            img_id_set = None

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
                    fix_version = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Version(kind="NORMAL", name=fixedIn.epochless_version)
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
        name="projects/anchore-vulnerabilities/notes/"+cveId, 
        short_description=cveId,
        long_description=long_description,
        related_url=external_urls,
        kind="PACKAGE_VULNERABILITY",
        create_time=str(datetime.datetime.utcnow()),
        update_time=str(datetime.datetime.utcnow()),
        vulnerability_type=vulnerability_type
    )

    return(newnote)
    
def update_vulnerability_notes(gapi, cve_id_set=[]):
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
            cveId = v.id
            if v.id not in anchore_vulns:
                anchore_vulns[v.id] = []
            anchore_vulns[v.id].append(v)

        for cveId in anchore_vulns.keys():
            try:
                gnote = make_vulnerability_note(cveId, anchore_vulns[cveId])
                #logger.debug(json.dumps(gnote.to_dict(), indent=4))

                if True:
                    #logger.debug("setting up grafeas api client for hostport: " + str(grafeas_hostport))
                    #api_client = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.api_client.ApiClient(host=grafeas_hostport)
                    #api_instance = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.GrafeasApi(api_client=api_client)

                    projects_id = "anchore-vulnerabilities"
                    note_id = cveId
                    note = gnote

                    always_update = False
                    if 'always_update' in myconfig and myconfig['always_update']:
                        always_update = True

                    try:
                        upsert_grafeas_note(gapi, projects_id, note_id, note, always_update=always_update)
                    except Exception as err:
                        logger.warn("note upsert failed - exception: " + str(err))

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
        retel['latest_version'] = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Version(kind="NORMAL", name=anch_pkg.fullversion)
        retel['description'] = "distro="+anch_pkg.distro_name+" distro_version="+anch_pkg.distro_version+" pkg_type="+anch_pkg.pkg_type.upper()+" license="+anch_pkg.license+" src_package="+anch_pkg.src_pkg
        retel['url'] = "N/A"

        dist = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Distribution(**retel)
        distributions.append(dist)
    
    package = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Package(name=pkgName, distribution=distributions)

    newnote = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Note(
        name="projects/anchore-distro-packages/notes/"+pkgName, 
        short_description=pkgName,
        long_description=long_description,
        related_url=external_urls,
        kind="PACKAGE_MANAGER",
        create_time=str(datetime.datetime.utcnow()),
        update_time=str(datetime.datetime.utcnow()),
        package=package
    )    
    return(newnote)

def update_package_notes(gapi, pkg_name_set=[]):
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
                    #logger.debug("setting up grafeas api client for hostport: " + str(grafeas_hostport))
                    #api_client = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.api_client.ApiClient(host=grafeas_hostport)
                    #api_instance = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.GrafeasApi(api_client=api_client)

                    projects_id = "anchore-distro-packages"
                    note_id = pkgName
                    note = gnote

                    always_update = False
                    if 'always_update' in myconfig and myconfig['always_update']:
                        always_update = True

                    try:
                        upsert_grafeas_note(gapi, projects_id, note_id, note, always_update=always_update)
                    except Exception as err:
                        logger.warn("note upsert failed - exception: " + str(err))

            except Exception as err:
                logger.warn("unable to marshal package "+str(pkgName)+" into package note - exception: " + str(err))


    return(True)

def upsert_grafeas_occurrence(gapi, projects_id, occ_id, occ, always_update=False):
    global occurrence_name_map

    existing_occ = None
    try:
        if occ_id in occurrence_name_map:
            existing_occ = gapi.get_occurrence(projects_id, occurrence_name_map[occ_id])
            logger.debug("got existing occurrence from grafeas: " + occ_id)
    except Exception as err:
        pass

    do_update = False
    if always_update:
        do_update = True
    #TODO actually diff existing and new to decide on update/create(skip)

    if not existing_occ:
        try:
            api_response = gapi.create_occurrence(projects_id, occurrence=occ)
            logger.debug("occurrence added to grafeas service: " + occ_id)
            g_occ_id = api_response.name.split("/")[-1]
            occurrence_name_map[occ_id] = g_occ_id
        except Exception as err:
            logger.warn("could not add occurrence to grafeas service - exception: " + str(err))
    elif existing_occ and do_update:
        try:
            occ.name = existing_occ.name
            api_response = gapi.update_occurrence(projects_id, occurrence_name_map[occ_id], occurrence=occ)
            logger.debug("occurrence updated in grafeas service: " + occ_id)
        except Exception as err:
            logger.warn("could not update occurrence in grafeas service - exception: " + str(err))
    else:
        logger.debug("skipping occurrence create/update - nothing to do: " + str(occ_id))

    if False:
        try:
            if 'always_update' in myconfig and myconfig['always_update']:
                raise Exception("always_update is set in config")

            if note_id in occurrence_name_map:
                api_response = gapi.get_occurrence(projects_id, occurrence_name_map[note_id])
                logger.debug("occurrence already exists in service, skipping add: " + note_id)
            else:
                raise Exception("new occurrence")
            # TODO - need to actually diff the note for update case

        except Exception as err:
            logger.debug("get err: " + str(err))
            try:
                api_response = gapi.create_occurrence(projects_id, occurrence=note)
                logger.debug("occurrence added to grafeas service: " + note_id)
                occ_id = api_response.name.split("/")[-1]
                occurrence_name_map[note_id] = occ_id
            except Exception as err:
                logger.warn("could not add occurrence to grafeas service - exception: " + str(err))


    return(True)

def upsert_grafeas_note(gapi, projects_id, note_id, note, always_update=False):
    try:
        existing_note = gapi.get_note(projects_id, note_id)
        logger.debug("got existing note from grafeas: " + note_id)
    except Exception as err:
        existing_note = None

    do_update = False
    if always_update:
        do_update = True
    #TODO actually diff existing and new to decide on update/create(skip)

    if not existing_note:
        try:
            api_response = gapi.create_note(projects_id, note_id=note_id, note=note)
            logger.debug("note added to grafeas service: " + note_id)
        except Exception as err:
            logger.warn("could not add note to grafeas service - exception: " + str(err))                        
    elif existing_note and do_update:
        try:
            api_response = gapi.update_note(projects_id, note_id, note=note)
            logger.debug("note updated in grafeas service: " + note_id)
        except Exception as err:
            logger.warn("could not update note in grafeas service - exception: " + str(err))
    else:
        logger.debug("skipping note create/update - nothing to do: " + str(note_id))

    return(True)

def make_image_vulnerability_occurrence(imageId, anch_img_pkgs, dbsession=None, gapi=None):
    import uuid

    newoccs = {}

    resource_url = None
    note_name = None

    vulnerability_details = {}

    localconfig = anchore_engine.configuration.localconfig.get_config()
    system_user_auth = localconfig['system_user_auth']
    verify = localconfig['internal_ssl_verify']

    userId = 'admin'
    user_record = catalog.get_user(system_user_auth, userId)
    user_auth = (user_record['userId'], user_record['password'])

    fulldigest = "unknown_registry/unknown_repo@"+imageId
    image_records = catalog.get_image(user_auth, imageId=imageId)
    if image_records:
        image_record = image_records[0]
        for image_detail in image_record['image_detail']:
            fulldigest = image_detail['registry'] + "/" + image_detail['repo'] + "@" + image_record['imageDigest']
    resource_url = "https://"+fulldigest

    #api_client = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.api_client.ApiClient(host=grafeas_hostport)
    #api_instance = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.GrafeasApi(api_client=api_client)
    projects_id = "anchore-vulnerabilities"

    for anch_img_pkg in anch_img_pkgs:
        try:
            p = dbsession.query(ImagePackage).filter_by(image_id=imageId, name=anch_img_pkg.pkg_name, version=anch_img_pkg.pkg_version).all()[0]
            pkgName = p.name
            pkgVersion = p.version
            pkgFullVersion = p.fullversion
            pkgRelease = p.release
        except:
            pkgName = anch_img_pkg.pkg_name
            pkgVersion = anch_img_pkg.pkg_version
            pkgFullVersion = anch_img.pkg.pkg_version
            pkgRelease = None

        distro,distro_version = anch_img_pkg.vulnerability_namespace_name.split(":",1)
        distro_cpe = "cpe:/o:"+distro+":"+distro+"_linux:"+distro_version

        note_name = "projects/anchore-vulnerabilities/notes/"+anch_img_pkg.vulnerability_id
        severity = "UNKNOWN"
        cvss_score = 0.0

        fixed_location = None
        try:
            api_response = gapi.get_note(projects_id, anch_img_pkg.vulnerability_id)
            vulnerability_note = api_response
            #logger.debug("WTF: " + str(json.dumps(vulnerability_note.to_dict(), indent=4)))
            severity = vulnerability_note.vulnerability_type.severity
            cvss_score = vulnerability_note.vulnerability_type.cvss_score
            fix_package = fix_version = "N/A"
            for detail in vulnerability_note.vulnerability_type.details:
                if detail.cpe_uri == distro_cpe:
                    fixed_location = detail.fixed_location
                    fixed_location.package = pkgName
                    break

        except Exception as err:
            logger.warn("could not get vulnability note from grafeas associated with found vulnerability ("+str(anch_img_pkg.vulnerability_id)+") - exception: " + str(err))

        affected_location = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.VulnerabilityLocation(
            package=pkgName,
            version=anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Version(kind="NORMAL", name=pkgFullVersion),
            cpe_uri="cpe:/a:"+anch_img_pkg.pkg_name+":"+anch_img_pkg.pkg_name+":"+anch_img_pkg.pkg_version
        )

        vulnerability_details = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.VulnerabilityDetails(
            type=anch_img_pkg.pkg_type.upper(),
            severity=severity,
            cvss_score=cvss_score,
            fixed_location=fixed_location,
            affected_location=affected_location
        )
            

        occ_id = str(uuid.uuid4())

        occ_id = str(imageId + anch_img_pkg.pkg_name + anch_img_pkg.vulnerability_id)
        newocc = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.Occurrence(
            name='projects/anchore-vulnerability-scan/occurrences/'+str(occ_id),
            resource_url=resource_url,
            note_name=note_name,
            kind="PACKAGE_VULNERABILITY",
            vulnerability_details=vulnerability_details,
            create_time=str(datetime.datetime.utcnow()),
            update_time=str(datetime.datetime.utcnow())
        )

        newoccs[occ_id] = newocc

    return(newoccs)


def update_image_vulnerability_occurrences(gapi, img_id_set=[]):
    global grafeas_hostport, myconfig

    anch_img_pkgs = {}
    db_imgs = []
    with session_scope() as dbsession:
        if img_id_set:
            logger.debug("fetching limited package set from anchore DB: " + str(img_id_set))
            for imageId in img_id_set:
                try:
                    p = dbsession.query(ImagePackageVulnerability).filter_by(pkg_image_id=imageId).all()
                    if p[0].pkg_image_id:
                        db_imgs = db_imgs + p
                except Exception as err:
                    logger.warn("configured image name set ("+str(imageId)+") not found in DB, skipping: " + str(err))
        else:
            logger.debug("fetching full package set from anchore DB")
            db_imgs = dbsession.query(ImagePackageVulnerability).all()
    
        for i in db_imgs:
            if i.pkg_image_id not in anch_img_pkgs:
                anch_img_pkgs[i.pkg_image_id] = []
            anch_img_pkgs[i.pkg_image_id].append(i)

        for imageId in anch_img_pkgs.keys():
            try:
                gnotes = make_image_vulnerability_occurrence(imageId, anch_img_pkgs[imageId], dbsession=dbsession, gapi=gapi)
                for note_id in gnotes.keys():
                    gnote = gnotes[note_id]

                    projects_id = "anchore-vulnerability-scan"
                    note = gnote

                    always_update = False
                    if 'always_update' in myconfig and myconfig['always_update']:
                        always_update = True

                    try:
                        upsert_grafeas_occurrence(gapi, projects_id, note_id, gnote, always_update=always_update)
                    except Exception as err:
                        logger.warn("occurrence upsert failed - exception: " + str(err))

            except Exception as err:
                logger.warn("unable to marshal occurrence "+str(imageId)+" into vulnerability occurrence - exception: " + str(err))            
        

    return(True)

click = 0
running = False
last_run = 0
system_user_auth = ('anchore-system', '')
current_avg = 0.0
current_avg_count = 0.0

def monitor_func(**kwargs):
    global click, running, last_run, system_user_auth, grafeas_hostport, cve_id_set, pkg_name_set, img_id_set

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

        logger.debug("setting up grafeas api client for hostport: " + str(grafeas_hostport))
        api_client = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.api_client.ApiClient(host=grafeas_hostport)
        api_instance = anchore_engine.vendored.grafeas_client.client_python.v1alpha1.swagger_client.GrafeasApi(api_client=api_client)

        logger.info("updating grafeas with latest vulnerability notes")
        try:
            update_vulnerability_notes(api_instance, cve_id_set=cve_id_set)
            pass
        except Exception as err:
            logger.error("unable to populate vulnerability notes - exception: " + str(err))

        logger.info("updating grafeas with latest package notes")
        try:
            update_package_notes(api_instance, pkg_name_set=pkg_name_set)
            pass
        except Exception as err:
            logger.error("unable to populate package notes - exception: " + str(err))

        logger.info("searching for vulnerability occurrences")
        try:
            update_image_vulnerability_occurrences(api_instance, img_id_set=img_id_set)
            pass
        except Exception as err:
            logger.error("unable to search/store for vulnerability occurrences - exception: " + str(err))

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
