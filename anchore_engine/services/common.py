import json
import os
import re
import copy
import time
import urllib
import attr
import hashlib
import traceback
import importlib
import threading
import subprocess

#import simplejson as json
from collections import OrderedDict

from twisted.application import service, internet
from twisted.cred.portal import IRealm, Portal
from twisted.internet.defer import succeed
#from twisted.python import log
from twisted.web import server
from twisted.web.guard import HTTPAuthSessionWrapper, BasicCredentialFactory
from twisted.web.resource import IResource, Resource
from zope.interface import implementer

# anchore modules
import anchore_engine.auth.anchore_resources
import anchore_engine.auth.anchore_service
import anchore_engine.clients.localanchore
import anchore_engine.configuration.localconfig

from anchore_engine import db
from anchore_engine.auth.anchore_service import AnchorePasswordChecker
from anchore_engine.db import db_services, db_users, session_scope
from anchore_engine.subsys import logger, taskstate
from anchore_engine.services.policy_engine.api.models import ImageUpdateNotification, FeedUpdateNotification, ImageVulnerabilityListing, ImageIngressRequest, ImageIngressResponse, LegacyVulnerabilityReport

apiext_status = {}
subscription_types = ['policy_eval', 'tag_update', 'vuln_update', 'repo_update', 'analysis_update']
resource_types = ['registries', 'users', 'images', 'policies', 'evaluations', 'subscriptions', 'archive']
bucket_types = ["analysis_data", "policy_bundles", "policy_evaluations", "query_data", "vulnerability_scan", "image_content_data", "manifest_data"]
super_users = ['admin', 'anchore-system']
image_content_types = ['os', 'files', 'npm', 'gem', 'python', 'java']
image_vulnerability_types = ['os']

def update_image_record_with_analysis_data(image_record, image_data):

    image_summary_data = extract_analyzer_content(image_data, 'metadata')

    try:
        image_summary_metadata = copy.deepcopy(image_summary_data)
        if image_summary_metadata:
            logger.debug("getting image summary data")

            summary_record = {}

            adm = image_summary_metadata['anchore_distro_meta']

            summary_record['distro'] = adm.pop('DISTRO', 'N/A')
            summary_record['distro_version'] = adm.pop('DISTROVERS', 'N/A')

            air = image_summary_metadata['anchore_image_report']
            airm = air.pop('meta', {})
            al = air.pop('layers', [])
            ddata = air.pop('docker_data', {})

            summary_record['layer_count'] = str(len(al))
            summary_record['dockerfile_mode'] = air.pop('dockerfile_mode', 'N/A') 
            summary_record['arch'] = ddata.pop('Architecture', 'N/A')            
            summary_record['image_size'] = str(int(airm.pop('sizebytes', 0))) 

            formatted_image_summary_data = summary_record            
    except Exception as err:
        formatted_image_summary_data = {}

    if formatted_image_summary_data:
        image_record.update(formatted_image_summary_data)
        
    dockerfile_content, dockerfile_mode = extract_dockerfile_content(image_data)
    if dockerfile_content and dockerfile_mode:
        image_record['dockerfile_mode'] = dockerfile_mode
        for image_detail in image_record['image_detail']:
            image_detail['dockerfile'] = dockerfile_content.encode('base64')
            logger.debug("setting image_detail: ")

    return(True)

if False:
    def format_image_summary(image_summary_data):
        ret = {}

        # augment with image summary data, if available
        try:
            #if not input_image_summary_data:
            #    try:
            #        image_summary_data = catalog.get_document(user_auth, 'image_summary_data', image_record['imageDigest'])
            #    except:
            #        image_summary_data = {}
            #else:
            #    image_summary_data = input_image_summary_data

            #if not image_summary_data:
            #    # (re)generate image_content_data document
            #    logger.debug("generating image summary data from analysis data")
            #    image_data = catalog.get_document(user_auth, 'analysis_data', image_record['imageDigest'])

            #    image_content_data = {}
            #    for content_type in anchore_engine.services.common.image_content_types:
            #        try:
            #            image_content_data[content_type] = anchore_engine.services.common.extract_analyzer_content(image_data, content_type)
            #        except:
            #            image_content_data[content_type] = {}
            #    if image_content_data:
            #        logger.debug("adding image content data to archive")
            #        rc = catalog.put_document(user_auth, 'image_content_data', image_record['imageDigest'], image_content_data)

            #    image_summary_data = {}
            #    try:
            #        image_summary_data = anchore_engine.services.common.extract_analyzer_content(image_data, 'metadata')
            #    except:
            #        image_summary_data = {}

            #    #if image_summary_data:
            #    #    logger.debug("adding image summary data to archive")
            #    #    rc = catalog.put_document(user_auth, 'image_summary_data', image_record['imageDigest'], image_summary_data)

            image_summary_metadata = copy.deepcopy(image_summary_data)
            if image_summary_metadata:
                logger.debug("getting image summary data")

                summary_record = {}

                adm = image_summary_metadata['anchore_distro_meta']

                summary_record['distro'] = adm.pop('DISTRO', 'N/A')
                summary_record['distro_version'] = adm.pop('DISTROVERS', 'N/A')

                air = image_summary_metadata['anchore_image_report']
                airm = air.pop('meta', {})
                al = air.pop('layers', [])
                ddata = air.pop('docker_data', {})

                summary_record['layer_count'] = str(len(al))
                summary_record['dockerfile_mode'] = air.pop('dockerfile_mode', 'N/A') 
                summary_record['arch'] = ddata.pop('Architecture', 'N/A')            
                summary_record['image_size'] = str(int(airm.pop('sizebytes', 0))) 

                ret = summary_record

        except Exception as err:
            logger.warn("cannot format image summary data for image - exception: " + str(err))

        return(ret)

def registerService(sname, config, enforce_unique=True):
    ret = False
    myconfig = config['services'][sname]

    # TODO add version support/detection here

    service_template = {
        'type': 'anchore',
        'base_url': 'N/A',
        'status_base_url': 'N/A',
        'version': 'v1',
        'short_description': ''
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
        service_template['status'] = False
        service_template['status_message'] = taskstate.base_state('service_status')

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
            #for service_record in service_records:
            #    if service_record['base_url'] and service_record['base_url'] != 'N/A':
            #        service_hostport = re.sub("^http.//", "", service_record['base_url'])
            #        # if a different host_id has the same endpoint, fail
            #        if (service_hostport == endpoint_hostport) and (config['host_id'] != service_record['hostid']):
            #            raise Exception("trying to add new host but found conflicting endpoint from another host in DB - detail: my_host_id=" + str(config['host_id']) + " db_host_id="+str(service_record['hostid'])+" my_host_endpoint="+str(endpoint_hostport)+" db_host_endpoint="+str(service_hostport))

            # if all checks out, then add/update the registration
            ret = db_services.add(config['host_id'], sname, service_template, session=dbsession)

    except Exception as err:
        raise err

    return(ret)

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
def makeService(snames, options, db_connect=True, bootstrap_db=False, bootstrap_users=False, require_system_user_auth=True, module_name="anchore_engine.services", validate_params={}, specific_tables=None):
    try:
        logger.enable_bootstrap_logging(service_name=','.join(snames))

        try:
            # config and init
            configfile = configdir = None
            if options['config']:
                configdir = options['config']
                configfile = os.path.join(options['config'], 'config.yaml')

            anchore_engine.configuration.localconfig.load_config(configdir=configdir, configfile=configfile, validate_params=validate_params)
            localconfig = anchore_engine.configuration.localconfig.get_config()
            localconfig['myservices'] = []
            logger.spew("localconfig="+json.dumps(localconfig, indent=4, sort_keys=True))
        except Exception as err:
            logger.error("cannot load configuration: exception - " + str(err))
            raise err

        # get versions of things
        try:
            versions = anchore_engine.configuration.localconfig.get_versions()
        except Exception as err:
            logger.error("cannot detect versions of service: exception - " + str(err))
            raise err

        if db_connect:
            logger.info("initializing database")

            # connect to DB
            try:
                db.initialize(localconfig=localconfig, versions=versions, bootstrap_db=bootstrap_db, bootstrap_users=bootstrap_users, specific_tables=specific_tables)
            except Exception as err:
                logger.error("cannot connect to configured DB: exception - " + str(err))
                raise err

            #credential bootstrap
            localconfig['system_user_auth'] = (None, None)
            if require_system_user_auth:
                gotauth = False
                max_retries = 60
                for count in range(1,max_retries):
                    if gotauth:
                        continue
                    try:
                        with session_scope() as dbsession:
                            localconfig['system_user_auth'] = get_system_user_auth(session=dbsession)
                        if localconfig['system_user_auth'] != (None, None):
                            gotauth = True
                        else:
                            logger.error("cannot get system user auth credentials yet, retrying (" + str(count) + " / " + str(max_retries)+")")
                            time.sleep(5)
                    except Exception as err:
                        logger.error("cannot get system-user auth credentials - service may not have system level access")
                        localconfig['system_user_auth'] = (None, None)

                if not gotauth:
                    raise Exception("service requires system user auth to start")

        # application object
        application = service.Application("multi-service-"+'-'.join(snames))

        #multi-service
        retservice = service.MultiService()
        retservice.setServiceParent(application)

        success = False
        try:
            scount = 0
            for sname in snames:
                if sname in localconfig['services'] and localconfig['services'][sname]['enabled']:

                    smodule = importlib.import_module(module_name + "." + sname)

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
                    logger.error("service not enabled in config, not starting service: " + sname)

            if scount == 0:
                logger.error("no services/subservices were enabled/started on this host")
                success = False
        except Exception as err:
            logger.error("cannot create/init/register service: " + sname + " - exception: " + str(err))
            success = False

        if not success:
            logger.error("cannot start service (see above for information)")
            traceback.print_exc('Service init failure')
            raise Exception("cannot start service (see above for information)")

        return(retservice)
    finally:
        logger.disable_bootstrap_logging()

# simple twisted resource for health check route
class HealthResource(Resource):
    isLeaf = True
    def render_GET(self, request):
        return("")

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

def getAuthResource(in_resource, sname, config, password_checker=AnchorePasswordChecker()):

    if not password_checker:
        # explicitly passed in null password checker obj
        return(in_resource)

    if sname in config['services']:
        localconfig = config['services'][sname]
    else:
        # no auth required
        return(in_resource)
        
    do_auth = True
    if localconfig and 'require_auth' in localconfig and not localconfig['require_auth']:
        do_auth = False

    if do_auth:
    #if localconfig and 'require_auth' in localconfig and localconfig['require_auth']:
        #if 'require_auth_file' not in localconfig or not os.path.exists(localconfig['require_auth_file']):
        #    raise Exception("require_auth is set for service, but require_auth_file is not set/invalid")
            
        realm = HTTPAuthRealm(resource=in_resource)
        portal = Portal(realm, [password_checker])

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
        'message': msg,
        'httpcode': int(httpcode),
        'detail': kwargs.get('detail', {})
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

def manifest_to_digest(rawmanifest):

    d = json.loads(rawmanifest, object_pairs_hook=OrderedDict)
    d.pop('signatures', None)

    # this is using regular json
    dmanifest = re.sub(" +\n", "\n", json.dumps(d, indent=3))

    # this if using simplejson
    #dmanifest = json.dumps(d, indent=3)

    ret = "sha256:" + str(hashlib.sha256(dmanifest).hexdigest())

    return(ret)

def lookup_registry_image(userId, image_info, registry_creds):
    digest = None
    manifest = None

    if not anchore_engine.auth.anchore_resources.registry_access(userId, image_info['registry']):
        raise Exception("access denied for user ("+str(userId)+") registry ("+str(image_info['registry'])+")")
    else:
        try:
            manifest,digest = anchore_engine.auth.docker_registry.get_image_manifest(userId, image_info, registry_creds)
            #if 'schemaVersion' not in manifest or manifest['schemaVersion'] != 2:
            #    raise Exception("manifest schemaVersion != 2 not supported")
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
                    logger.debug("using digest hash as imageId due to incomplete manifest ("+str(image_info['fulldigest'])+")")
                    htype, image_info['imageId'] = image_info['digest'].split(":", 1)

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
            dockerfile_mode = image_metadata['dockerfile_mode']
        except:
            dockerfile_mode = None

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

        try:
            annotations = image_metadata['annotations']
        except:
            annotations = {}

        #try:
        #    manifest = image_metadata['manifest']
        #except:
        #    manifest = None

        return(make_docker_image(userId, input_string=input_string, tag=tag, digest=digest, imageId=imageId, dockerfile=dockerfile, dockerfile_mode=dockerfile_mode, registry_lookup=registry_lookup, registry_creds=registry_creds, annotations=annotations))

    else:
        raise Exception("image type ("+str(image_type)+") not supported")

    return(None)

def make_docker_image(userId, input_string=None, tag=None, digest=None, imageId=None, dockerfile=None, dockerfile_mode=None, registry_lookup=True, registry_creds=[], annotations={}):
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
    new_input['dockerfile_mode'] = dockerfile_mode

    final_annotation_data = {}
    for k,v in annotations.items():
        if v != 'null':
            final_annotation_data[k] = v
    new_input['annotations'] = json.dumps(final_annotation_data)
    
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

def make_policy_record(userId, bundle, policy_source="local", active=False):
    payload = {}

    policyId = bundle['id']

    payload["policyId"] = policyId
    payload["active"] = active
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

def extract_dockerfile_content(image_data):
    dockerfile_content = ""
    dockerfile_mode = "Guessed"

    try:
        dockerfile_content = image_data[0]['image']['imagedata']['image_report']['dockerfile_contents']
        dockerfile_mode = image_data[0]['image']['imagedata']['image_report']['dockerfile_mode']
    except Exception as err:
        dockerfile_content = ""
        dockerfile_mode = "Guessed"

    return(dockerfile_content, dockerfile_mode)

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
        elif content_type == 'python':
            try:
                if 'pkgs.python' in idata['imagedata']['analysis_report']['package_list']:
                    adata = idata['imagedata']['analysis_report']['package_list']['pkgs.python']['base']
                    for k in adata.keys():
                        avalue = json.loads(adata[k])
                        ret[k] = avalue
            except Exception as err:
                raise Exception("could not extract/parse content info - exception: " + str(err))
        elif content_type == 'java':
            try:
                if 'pkgs.java' in idata['imagedata']['analysis_report']['package_list']:
                    adata = idata['imagedata']['analysis_report']['package_list']['pkgs.java']['base']
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
        logger.warn("exception: " + str(err))
        raise err

    return(ret)


def run_command_list(cmd_list, env=None):
    """
    Run a command from a list with optional environemnt and return a tuple (rc, stdout_str, stderr_str)
    :param cmd_list: list of command e.g. ['ls', '/tmp']
    :param env: dict of env vars for the environment if desired. will replace normal env, not augment
    :return: tuple (rc_int, stdout_str, stderr_str)
    """

    rc = -1
    sout = serr = None

    try:
        if env:
            pipes = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        else:
            pipes = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        sout, serr = pipes.communicate()
        rc = pipes.returncode
    except Exception as err:
        raise err

    return(rc, sout, serr)


def run_command(cmdstr, env=None):
    return run_command_list(cmdstr.split(), env=env)


def get_system_user_auth(session=None):
    localconfig = anchore_engine.configuration.localconfig.get_config()
    if 'system_user_auth' in localconfig and localconfig['system_user_auth'] != (None, None):
        return(localconfig['system_user_auth'])

    if session:
        system_user = db_users.get('anchore-system', session=session)
        if system_user:
            return( (system_user['userId'], system_user['password']) )

    return ( (None, None) )

# generic monitor_func implementation

click = 0
running = False
last_run = 0
def monitor_func(**kwargs):
    global click, running, last_run

    monitors = kwargs['monitors']
    monitor_threads = kwargs['monitor_threads']
    servicename = kwargs['servicename']

    timer = int(time.time())
    if click < 5:
        click = click + 1
        logger.debug("service ("+str(servicename)+") starting in: " + str(5 - click))
        return (True)

    if round(time.time() - last_run) < kwargs['kick_timer']:
        logger.spew(
            "timer hasn't kicked yet: " + str(round(time.time() - last_run)) + " : " + str(kwargs['kick_timer']))
        return (True)

    try:
        running = True
        last_run = time.time()
        
        # handle setting the cycle timers based on configuration
        for monitor_name in monitors.keys():
            if not monitors[monitor_name]['initialized']:
                # first time
                if 'cycle_timers' in kwargs and monitor_name in kwargs['cycle_timers']:
                    try:
                        the_cycle_timer = monitors[monitor_name]['cycle_timer']
                        min_cycle_timer = monitors[monitor_name]['min_cycle_timer']
                        max_cycle_timer = monitors[monitor_name]['max_cycle_timer']

                        config_cycle_timer = int(kwargs['cycle_timers'][monitor_name])
                        if config_cycle_timer < 0:
                            the_cycle_timer = abs(int(config_cycle_timer))
                        elif config_cycle_timer < min_cycle_timer:
                            logger.warn("configured cycle timer for handler ("+str(monitor_name)+") is less than the allowed min ("+str(min_cycle_timer)+") - using allowed min")
                            the_cycle_timer = min_cycle_timer
                        elif config_cycle_timer > max_cycle_timer:
                            logger.warn("configured cycle timer for handler ("+str(monitor_name)+") is greater than the allowed max ("+str(max_cycle_timer)+") - using allowed max")
                            the_cycle_timer = max_cycle_timer
                        else:
                            the_cycle_timer = config_cycle_timer

                        monitors[monitor_name]['cycle_timer'] = the_cycle_timer
                    except Exception as err:
                        logger.warn("exception setting custom cycle timer for handler ("+str(monitor_name)+") - using default")

                monitors[monitor_name]['initialized'] = True
 
        # handle the thread (re)starters here
        for monitor_name in monitors.keys():
            start_thread = False
            if monitor_name not in monitor_threads:
                start_thread = True
            else:
                if not monitor_threads[monitor_name].isAlive():
                    logger.debug("thread stopped - restarting: " + str(monitor_name))
                    monitor_threads[monitor_name].join()
                    start_thread = True
            
            if start_thread:
                monitor_threads[monitor_name] = threading.Thread(target=monitors[monitor_name]['handler'], args=monitors[monitor_name]['args'], kwargs={'mythread': monitors[monitor_name]})
                logger.debug("starting up monitor_thread: " + str(monitor_name))
                monitor_threads[monitor_name].start()

    except Exception as err:
        logger.error(str(err))
    finally:
        running = False

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
            monitor_thread = threading.Thread(target=anchore_engine.services.common.monitor_func, kwargs=kwargs)
            monitor_thread.start()
        else:
            logger.spew("MON: skipping")

    except Exception as err:
        logger.warn("MON thread start exception: " + str(err))
        
