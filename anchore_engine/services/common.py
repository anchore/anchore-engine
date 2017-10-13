import json
import os
import re
import time
import urllib
import attr
import traceback
import importlib

from twisted.application import service, internet
from twisted.cred.portal import IRealm, Portal
from twisted.internet.defer import succeed
from twisted.python import log
from twisted.web import server
from twisted.web.guard import HTTPAuthSessionWrapper, BasicCredentialFactory
from twisted.web.resource import IResource
from zope.interface import implementer

# anchore modules
import anchore_engine.auth.anchore_resources
import anchore_engine.auth.anchore_service
import anchore_engine.clients.localanchore
import anchore_engine.configuration.localconfig
from anchore_engine import db
from anchore_engine.auth.anchore_service import AnchorePasswordChecker
from anchore_engine.db import db_services, db_users, session_scope
from anchore_engine.subsys import logger
from anchore_engine.services.policy_engine.api.models import ImageUpdateNotification, FeedUpdateNotification, ImageVulnerabilityListing, ImageIngressRequest, ImageIngressResponse, LegacyVulnerabilityReport

apiext_status = {}
latest_service_records = {"service_records": []}
subscription_types = ['policy_eval', 'tag_update', 'vuln_update']
resource_types = ['registries', 'users', 'images', 'policies', 'evaluations', 'subscriptions', 'archive']
bucket_types = ["analysis_data", "policy_bundles", "policy_evaluations", "query_data", "vulnerability_scan", "image_content_data"]
super_users = ['admin', 'anchore-system']
image_content_types = ['os', 'files', 'npm', 'gem']

def registerService(sname, config, enforce_unique=True):
    ret = False
    myconfig = config['services'][sname]

    # TODO add version support/detection here

    service_template = {
        'type': 'anchore',
        'base_url': 'N/A',
        'version': 'v1'
    }

    if 'ssl_enable' in myconfig and myconfig['ssl_enable']:
        hstring = "https"
    else:
        hstring = "http"

    endpoint_hostname = endpoint_port = endpoint_hostport = None
    if 'endpoint_hostname' in myconfig:
        endpoint_hostname = myconfig['endpoint_hostname']
        service_template['base_url'] = hstring + "://"+myconfig['endpoint_hostname']
    if 'port' in myconfig:
        endpoint_port = int(myconfig['port'])
        service_template['base_url'] += ":"+ str(endpoint_port)

    if endpoint_hostname:
        endpoint_hostport = endpoint_hostname
        if endpoint_port:
            endpoint_hostport = endpoint_hostport + ":" + str(endpoint_port)

    try:
        service_template['status'] = True
        service_template['status_message'] = "registered"

        with session_scope() as dbsession:
            service_records = db_services.get_byname(sname, session=dbsession)

            # fail if trying to add a service that must be unique in the system, but one already is registered in DB
            if enforce_unique:
                if len(service_records) > 1:
                    raise Exception("more than one entry for service type ("+str(sname)+") exists in DB, but service must be unique - manual DB intervention required")

                for service_record in service_records:
                    if service_record and (service_record['hostid'] != config['host_id']):
                        raise Exception("service type ("+str(sname)+") already exists in system with different host_id - detail: my_host_id=" + str(config['host_id']) + " db_host_id=" + str(service_record['hostid']))

            # in any case, check if another host is registered that has the same endpoint
            for service_record in service_records:
                if service_record['base_url'] and service_record['base_url'] != 'N/A':
                    service_hostport = re.sub("^http.//", "", service_record['base_url'])
                    # if a different host_id has the same endpoint, fail
                    if (service_hostport == endpoint_hostport) and (config['host_id'] != service_record['hostid']):
                        raise Exception("trying to add new host but found conflicting endpoint from another host in DB - detail: my_host_id=" + str(config['host_id']) + " db_host_id="+str(service_record['hostid'])+" my_host_endpoint="+str(endpoint_hostport)+" db_host_endpoint="+str(service_hostport))
                7
            # if all checks out, then add/update the registration
            ret = db_services.add(config['host_id'], sname, service_template, session=dbsession)

    except Exception as err:
        raise err

    return(ret)

def check_services_ready(servicelist):
    global latest_service_records

    all_ready = False
    try:
        required_services_up = {}
        for s in servicelist:
            required_services_up[s] = False

        service_records = latest_service_records['service_records']
        for service_record in service_records:
            if service_record['servicename'] in required_services_up.keys():
                if service_record['status']:
                    required_services_up[service_record['servicename']] = True

        all_ready = True
        logger.debug("checking service readiness: " + str(required_services_up.keys()))
        for servicename in required_services_up.keys():
            if not required_services_up[servicename]:
                logger.warn("required service ("+str(servicename)+") is not (yet) available - will not queue analysis tasks this cycle")
                all_ready = False
                break

    except Exception as err:
        logger.error("could not check service status - exception: " + str(err))
        all_ready = False

    return(all_ready)


def createServiceAPI(resource, sname, config):
    myconfig = config['services'][sname]
    site = server.Site(resource)

    listen = myconfig['listen']

    if 'ssl_enable' in myconfig and myconfig['ssl_enable']:
        try:
            from OpenSSL import crypto
            from twisted.internet import ssl
            ssl_data = {}
            for s in ['ssl_cert', 'ssl_chain']:
                try:
                    with open (myconfig[s], 'rt') as FH:
                        sdata = FH.read()
                        ssl_data[s] = crypto.load_certificate(crypto.FILETYPE_PEM, sdata)
                except Exception as err:
                    ssl_data[s] = None
                    pass

            for s in ['ssl_key']:
                try:
                    with open (myconfig[s], 'rt') as FH:
                        sdata = FH.read()
                        ssl_data[s] = crypto.load_privatekey(crypto.FILETYPE_PEM, sdata)
                except Exception as err:
                    ssl_data[s] = None
                    pass

            if ssl_data['ssl_chain']:
                sfact = ssl.CertificateOptions(privateKey=ssl_data['ssl_key'], certificate=ssl_data['ssl_cert'], extraCertChain=[ssl_data['ssl_chain']])
            else:
                sfact = ssl.CertificateOptions(privateKey=ssl_data['ssl_key'], certificate=ssl_data['ssl_cert'])
                
            #skey = myconfig['ssl_key']
            #scert = myconfig['ssl_cert']
            #sfact = ssl.DefaultOpenSSLContextFactory(skey, scert)
            svc = internet.SSLServer(int(myconfig['port']), site, sfact, interface=listen)
        except Exception as err:
            raise err
    else:
        svc = internet.TCPServer(int(myconfig['port']), site, interface=listen)

    svc.setName(sname)

    return(svc)

def initializeService(sname, config):
    return(True)

# the anchore twistd plugins call this to initialize and make individual services
def makeService(snames, options, bootstrap_db=False, bootstrap_users=False):

    try:
        # config and init
        configfile = configdir = None
        if options['config']:
            configdir = options['config']
            configfile = os.path.join(options['config'], 'config.yaml')

        anchore_engine.configuration.localconfig.load_config(configdir=configdir, configfile=configfile)
        localconfig = anchore_engine.configuration.localconfig.get_config()
        localconfig['myservices'] = []
        logger.spew("localconfig="+json.dumps(localconfig, indent=4, sort_keys=True))
    except Exception as err:
        log.err("cannot load configuration: exception - " + str(err))
        raise err

    # get versions of things
    try:
        versions = anchore_engine.configuration.localconfig.get_versions()
    except Exception as err:
        log.err("cannot detect versions of service: exception - " + str(err))
        raise err

    logger.info("initializing database")

    # connect to DB
    try:
        db.initialize(versions=versions, bootstrap_db=bootstrap_db, bootstrap_users=bootstrap_users)
    except Exception as err:
        log.err("cannot connect to configured DB: exception - " + str(err))
        raise err

    #credential bootstrap
    with session_scope() as dbsession:
        system_user = db_users.get('anchore-system', session=dbsession)
        localconfig['system_user_auth'] = (system_user['userId'], system_user['password'])

    # application object
    application = service.Application("multi-service-"+'-'.join(snames))

    #from twisted.python.log import ILogObserver, FileLogObserver
    #from twisted.python.logfile import DailyLogFile
    #logfile = DailyLogFile("ghgh.log", "/tmp/")

    #multi-service
    retservice = service.MultiService()
    retservice.setServiceParent(application)
    
    success = False
    try:
        scount = 0
        for sname in snames:
            if sname in localconfig['services'] and localconfig['services'][sname]['enabled']:

                smodule = importlib.import_module("anchore_engine.services."+sname)

                s = smodule.createService(sname, localconfig)
                s.setServiceParent(retservice)

                rc = smodule.initializeService(sname, localconfig)
                if not rc:
                    raise Exception("failed to initialize service")

                rc = smodule.registerService(sname, localconfig)
                if not rc:
                    raise Exception("failed to register service")

                logger.debug("starting service: " + sname)
                success = True
                scount += 1
                localconfig['myservices'].append(sname)
            else:
                log.err("service not enabled in config, not starting service: " + sname)

        if scount == 0:
            log.err("no services/subservices were enabled/started on this host")
            success = False
    except Exception as err:
        log.err("cannot create/init/register service: " + sname + " - exception: " + str(err))
        success = False

    if not success:
        log.err("cannot start service (see above for information)")
        traceback.print_exc('Service init failure')
        raise Exception("cannot start service (see above for information)")

    return(retservice)

@implementer(IRealm)
@attr.s
class HTTPAuthRealm(object):
    resource = attr.ib()

    def requestAvatar(self, avatarId, mind, *interfaces):        
        #
        # to do route based auth, something like this (plus the anon portal setup in getResource())
        #
        #avatar = Resource()
        #avatar.putChild(b"health", Health())
        #if avatarId is not ANONYMOUS:
        #    avatar.putChild(b"this-stuff-requires-auth", SecretResource())
        #return succeed((IResource, avatar, lambda: None))

        return succeed((IResource, self.resource, lambda: None))

def getAuthResource(in_resource, sname, config):
    if sname in config['services']:
        localconfig = config['services'][sname]
    else:
        # no auth required
        return(in_resource)

    if localconfig and 'require_auth' in localconfig and localconfig['require_auth']:
        #if 'require_auth_file' not in localconfig or not os.path.exists(localconfig['require_auth_file']):
        #    raise Exception("require_auth is set for service, but require_auth_file is not set/invalid")
            
        realm = HTTPAuthRealm(resource=in_resource)
        portal = Portal(realm, [AnchorePasswordChecker()])

        #portal = Portal(realm, [FilePasswordDB(localconfig['require_auth_file'])])
        #portal = Portal(realm, [FilePasswordDB(localconfig['require_auth_file'], hash=hellothere)])

        #
        # for route-based auth, need anon and auth
        #
        #from twisted.cred.checkers import AllowAnonymousAccess
        #portal = Portal(
        #    realm, [
        #        FilePasswordDB('./configs/server-auth.db'),
        #        AllowAnonymousAccess(),
        #    ],
        #)
        
        credential_factory = BasicCredentialFactory('Authentication required')
        #credential_factory = DigestCredentialFactory('md5', 'anchore')
        resource = HTTPAuthSessionWrapper(portal, [credential_factory])
    else:
        resource = in_resource

    return (resource)

def getResource(app, sname, config):
    if sname in config['services']:
        localconfig = config['services'][sname]
    else:
        # no auth required
        return(app.resource())

    if localconfig and 'require_auth' in localconfig and localconfig['require_auth']:
        #if 'require_auth_file' not in localconfig or not os.path.exists(localconfig['require_auth_file']):
        #    raise Exception("require_auth is set for service, but require_auth_file is not set/invalid")
            
        realm = HTTPAuthRealm(resource=app.resource())
        portal = Portal(realm, [AnchorePasswordChecker()])

        #portal = Portal(realm, [FilePasswordDB(localconfig['require_auth_file'])])
        #portal = Portal(realm, [FilePasswordDB(localconfig['require_auth_file'], hash=hellothere)])

        #
        # for route-based auth, need anon and auth
        #
        #from twisted.cred.checkers import AllowAnonymousAccess
        #portal = Portal(
        #    realm, [
        #        FilePasswordDB('./configs/server-auth.db'),
        #        AllowAnonymousAccess(),
        #    ],
        #)
        
        credential_factory = BasicCredentialFactory('Authentication required')
        #credential_factory = DigestCredentialFactory('md5', 'anchore')
        resource = HTTPAuthSessionWrapper(portal, [credential_factory])
    else:
        resource = app.resource()

    return (resource)

def make_response_error(errmsg, in_httpcode=None, **kwargs):
    if not in_httpcode:
        httpcode = 500
    else:
        httpcode = in_httpcode
    detail = {}
    msg = str(errmsg)

    ret = {
        'message': str(msg),
        'httpcode': int(httpcode),
        'detail':detail
    }

    if type(errmsg) == Exception:
        if 'anchore_error_json' in errmsg.__dict__:
            if set(['message', 'httpcode', 'detail']).issubset(set(errmsg.__dict__['anchore_error_json'])):
                ret.update(errmsg.__dict__['anchore_error_json'])
                
    return(ret)

def make_response_routes(apiversion, inroutes):
    return_object = {}
    httpcode = 500

    routes = []
    try:
        for route in inroutes:
            routes.append('/'.join([apiversion, route]))
    except Exception as err:
        httpcode = 500
        return_object = make_response_error(err, in_httpcode=httpcode)
        httpcode = return_object['httpcode']

    else:
        httpcode = 200
        return_object = routes

    return(return_object, httpcode)

def lookup_registry_image(userId, image_info, registry_creds):
    digest = None
    manifest = None

    if not anchore_engine.auth.anchore_resources.registry_access(userId, image_info['registry']):
        raise Exception("access denied for user ("+str(userId)+") registry ("+str(image_info['registry'])+")")
    else:
        try:
            manifest,digest = anchore_engine.auth.docker_registry.get_image_manifest(userId, image_info, registry_creds)
        except Exception as err:
            raise Exception("cannot fetch image digest/manifest from registry - exception: " + str(err))

    return(digest, manifest)

def get_image_info(userId, image_type, input_string, registry_lookup=False, registry_creds=[]):
    ret = {}
    if image_type == 'docker':
        image_info = anchore_engine.clients.localanchore.parse_dockerimage_string(input_string)
        ret.update(image_info)

        if registry_lookup and image_info['registry'] != 'localbuild':
            digest, manifest = lookup_registry_image(userId, image_info, registry_creds)
            image_info['digest'] = digest
            image_info['fulldigest'] = image_info['registry']+"/"+image_info['repo']+"@"+digest
            image_info['manifest'] = manifest
            
            # if we got a manifest, and the image_info does not yet contain an imageId, try to get it from the manifest
            if manifest and not image_info['imageId']:
                try:
                    imageId = re.sub("^sha256:", "", manifest['config']['digest'])
                    image_info['imageId'] = imageId
                except Exception as err:
                    logger.debug("could not extract imageId from fetched manifest - exception: " + str(err))
                    #try:
                    #    logger.debug("manifest content: " + json.dumps(image_info['manifest'], indent=4))
                    #except:
                    #    pass

            ret.update(image_info)
        else:
            image_info['manifest'] = {}

    else:
        raise Exception ("image type ("+str(image_type)+") not supported")

    return(ret)

def policy_engine_image_load(client, imageUserId, imageId, imageDigest):

    resp = None

    try:
        request = ImageIngressRequest()
        request.user_id = imageUserId
        request.image_id = imageId
        request.fetch_url='catalog://'+str(imageUserId)+'/analysis_data/'+str(imageDigest)
        logger.debug("policy engine request (image add): " + str(request))
        resp = client.ingress_image(request)
        logger.spew("policy engine response (image add): " + str(resp))
    except Exception as err:
        logger.error("failed to add/check image: " + str(err))
        raise err

    return(resp)

def clean_docker_image_details_for_update(image_details):
    ret = []

    for image_detail in image_details:
        el = {}
        for k in image_detail.keys():
            if image_detail[k] != None:
                el[k] = image_detail[k]
        ret.append(el)
    return(ret)

def make_image_record(userId, image_type, input_string, image_metadata={}, registry_lookup=True, registry_creds=[]):
    if image_type == 'docker':
        try:
            dockerfile = image_metadata['dockerfile']
        except:
            dockerfile = None

        try:
            tag = image_metadata['tag']
        except:
            tag = None

        try:
            imageId = image_metadata['imageId']
        except:
            imageId = None

        try:
            digest = image_metadata['digest']
        except:
            digest = None

        return(make_docker_image(userId, input_string=input_string, tag=tag, digest=digest, imageId=imageId, dockerfile=dockerfile, registry_lookup=registry_lookup, registry_creds=registry_creds))

    else:
        raise Exception("image type ("+str(image_type)+") not supported")

    return(None)

def make_docker_image(userId, input_string=None, tag=None, digest=None, imageId=None, dockerfile=None, registry_lookup=True, registry_creds=[]):
    ret = {}

    if input_string:
        image_info = get_image_info(userId, "docker", input_string, registry_lookup=registry_lookup, registry_creds=registry_creds)
    else:
        if digest:
            image_info = get_image_info(userId, "docker", digest, registry_lookup=registry_lookup, registry_creds=registry_creds)
            digest = image_info['digest']
            
        if tag:
            image_info = get_image_info(userId, "docker", tag, registry_lookup=registry_lookup, registry_creds=registry_creds)
            if digest and not image_info['digest']:
                image_info['digest'] = digest
        
    if 'digest' in image_info:
        #imageDigest = urllib.base64.urlsafe_b64encode(str(image_info['digest']))
        imageDigest = str(image_info['digest'])
    else:
        raise Exception("input image_info needs to have a digest")
        
    if imageId:
        image_info['imageId'] = imageId

    new_input = db.CatalogImage().make()
    new_input['imageDigest'] = imageDigest
    new_input['userId'] = userId
    new_input['image_type'] = 'docker'

    new_image_obj = db.CatalogImage(**new_input)
    new_image = dict((key,value) for key, value in vars(new_image_obj).iteritems() if not key.startswith('_'))
    new_image['image_detail'] = []

    if image_info['tag']:
        new_input = db.CatalogImageDocker().make()
        new_input['imageDigest'] = imageDigest
        new_input['userId'] = userId
        new_input['dockerfile'] = dockerfile

        for t in ['registry', 'repo', 'tag', 'digest', 'imageId']:
            if t in image_info:
                new_input[t] = image_info[t]
        
        new_docker_image_obj = db.CatalogImageDocker(**new_input)
        new_docker_image = dict((key,value) for key, value in vars(new_docker_image_obj).iteritems() if not key.startswith('_'))
        new_image['image_detail'] = [new_docker_image]

    ret = new_image
    return(ret)

def make_policy_record(userId, bundle, policy_source="local"):
    payload = {}

    policyId = bundle['id']

    payload["policyId"] = policyId
    payload["active"] = True
    payload["userId"] = userId
    payload['policybundle'] = bundle
    payload['policy_source'] = policy_source

    return(payload)

def make_eval_record(userId, evalId, policyId, imageDigest, tag, final_action, eval_url):
    payload = {}

    payload["policyId"] = policyId
    payload["userId"] = userId
    payload["evalId"] = evalId
    payload["imageDigest"] = imageDigest
    payload["tag"] = tag
    payload["final_action"] = final_action
    payload["policyeval"] = eval_url
    payload["created_at"] = int(time.time())
    payload["last_updated"] = payload['created_at']

    return(payload)

def do_request_prep(request, default_params={}):
    ret = {}
    try:
        try:
            ret['auth'] = (request.authorization.username, request.authorization.password)
        except:
            try:
                ret['auth'] = (request.authorization.username, None)
            except:
                ret['auth'] = (None, None)

        try:
            ret['userId'] = request.authorization.username
        except:
            ret['userId'] = None

        ret['method'] = request.method
        ret['bodycontent'] = request.get_data()
        ret['params'] = default_params
        for param in request.args.keys():

            if type(request.args[param]) in [basestring, unicode]:
                if request.args[param].lower() == 'true':
                    val = True
                elif request.args[param].lower() == 'false':
                    val = False
                else:
                    val = request.args[param]
            else:
                val = request.args[param]

            ret['params'][param] = val

    except Exception as err:
        logger.error("error processing request parameters - exception: " + str(err))
        raise err

    return(ret)

def extract_analyzer_content(image_data, content_type):
    ret = {}
    try:
        idata = image_data[0]['image']
        imageId = idata['imageId']
        
        if content_type == 'files':
            try:
                fcsums = {}
                if 'files.sha256sums' in idata['imagedata']['analysis_report']['file_checksums']:
                    adata = idata['imagedata']['analysis_report']['file_checksums']['files.sha256sums']['base']
                    for k in adata.keys():
                        fcsums[k] = adata[k]

                if 'files.allinfo' in idata['imagedata']['analysis_report']['file_list']:
                    adata = idata['imagedata']['analysis_report']['file_list']['files.allinfo']['base']
                    for k in adata.keys():
                        avalue = json.loads(adata[k])
                        if k in fcsums:
                            avalue['sha256'] = fcsums[k]
                        ret[k] = avalue
                        
            except Exception as err:
                raise Exception("could not extract/parse content info - exception: " + str(err))
        elif content_type == 'os':
            try:
                if 'pkgs.allinfo' in idata['imagedata']['analysis_report']['package_list']:
                    adata = idata['imagedata']['analysis_report']['package_list']['pkgs.allinfo']['base']
                    for k in adata.keys():
                        avalue = json.loads(adata[k])
                        ret[k] = avalue
            except Exception as err:
                raise Exception("could not extract/parse content info - exception: " + str(err))
        elif content_type == 'npm':
            try:
                if 'pkgs.npms' in idata['imagedata']['analysis_report']['package_list']:
                    adata = idata['imagedata']['analysis_report']['package_list']['pkgs.npms']['base']
                    for k in adata.keys():
                        avalue = json.loads(adata[k])
                        ret[k] = avalue
            except Exception as err:
                raise Exception("could not extract/parse content info - exception: " + str(err))
        elif content_type == 'gem':
            try:
                if 'pkgs.gems' in idata['imagedata']['analysis_report']['package_list']:
                    adata = idata['imagedata']['analysis_report']['package_list']['pkgs.gems']['base']
                    for k in adata.keys():
                        avalue = json.loads(adata[k])
                        ret[k] = avalue
            except Exception as err:
                raise Exception("could not extract/parse content info - exception: " + str(err))
        elif content_type == 'metadata':
            try:
                if 'image_report' in idata['imagedata'] and 'analyzer_meta' in idata['imagedata']['analysis_report']:
                    ret = {'anchore_image_report': image_data[0]['image']['imagedata']['image_report'], 'anchore_distro_meta': image_data[0]['image']['imagedata']['analysis_report']['analyzer_meta']['analyzer_meta']['base']}
            except Exception as err:
                raise Exception("could not extract/parse content info - exception: " + str(err))
            
    except Exception as err:
        logger.error("exception: " + str(err))
        raise err

    return(ret)
