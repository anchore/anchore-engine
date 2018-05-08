import json
import yaml
import time

import os
import shutil
import sys
import re
import rpm
import subprocess
import docker
import io
import tarfile
import urllib
import hashlib
import random
import traceback

from stat import *
from prettytable import PrettyTable
from textwrap import fill
from rpmUtils.miscutils import splitFilename

import logging

import anchore_image, anchore_image_db
from configuration import AnchoreConfiguration
from anchore.util import contexts, scripting
import anchore_auth
import anchore_feeds
from .apk import compare_versions as apk_compare_versions_impl

_logger = logging.getLogger(__name__)

def init_analyzer_cmdline(argv, name):
    ret = {}

    if len(argv) < 4:
        print "ERROR: invalid input"
        raise Exception

    anchore_conf = AnchoreConfiguration()
    anchore_common_context_setup(anchore_conf)


    ret['analyzer_config'] = None
    anchore_analyzer_configfile = '/'.join([anchore_conf.config_dir, 'analyzer_config.yaml'])
    if os.path.exists(anchore_analyzer_configfile):
        try:
            with open(anchore_analyzer_configfile, 'r') as FH:
                anchore_analyzer_config = yaml.safe_load(FH.read())
        except Exception as err:
            print "ERROR: could not parse the analyzer_config.yaml - exception: " + str(err)
            raise err

        if anchore_analyzer_config and name in anchore_analyzer_config:
            ret['analyzer_config'] = anchore_analyzer_config[name]

    ret['anchore_config'] = anchore_conf.data

    ret['name'] = name

    FH=open(argv[0], 'r')
    ret['selfcsum'] = hashlib.md5(FH.read()).hexdigest()
    FH.close()
    ret['imgid'] = argv[1]

    try:
        fullid = discover_imageId(argv[1])
    except:
        fullid = None
    if fullid:
        ret['imgid_full'] = fullid
    else:
        ret['imgid_full'] = ret['imgid']

    ret['dirs'] = {}
    ret['dirs']['datadir'] = argv[2]
    ret['dirs']['outputdir'] = '/'.join([argv[3], "analyzer_output", name])
    ret['dirs']['unpackdir'] = argv[4]

    for d in ret['dirs'].keys():
        if not os.path.isdir(ret['dirs'][d]):
            try:
                os.makedirs(ret['dirs'][d])
            except Exception as err:
                print "ERROR: cannot find/create input dir '"+ret['dirs'][d]+"'"
                raise err

    return(ret)

def init_gate_cmdline(argv, gate_name, gate_help={}):
    if len(argv) > 2 and argv[2] == 'anchore_get_help':
        if gate_help:
            if argv[1] != 'stdout':
                gate_help_json = json.dumps(gate_help)
                thefile = os.path.join(argv[1], gate_name + ".help")
                update_file_jsonstr(gate_help_json, thefile)
            print json.dumps({gate_name:gate_help})
        sys.exit(0)
        
    ret = init_query_cmdline(argv, gate_name)
    return(ret)

def init_query_cmdline(argv, paramhelp):
    ret = {}

    logging.basicConfig(format='%(asctime)-15s %(levelname)s %(filename)s:%(funcName)s %(message)s', level='INFO')
    
    if len(argv) == 2 and re.match(".*help.*", argv[1]):
        print paramhelp
        return (False)

    if len(argv) < 5:
        print "ERROR: invalid input"
        raise Exception

    anchore_conf = AnchoreConfiguration()
    anchore_common_context_setup(anchore_conf)

    ret['anchore_config'] = anchore_conf.data

    ret['name'] = argv[0].split('/')[-1]
    ret['imgfile'] = argv[1]

    images = read_plainfile_tolist(ret['imgfile'])
    ret['imgid'] = images[0]
    if 'imgid' not in ret:
        print "ERROR: could not read imgid from input file"
        raise Exception("ERROR: could not read imgid from input file")

    if not is_image_analyzed(ret['imgid']):
        raise Exception("imageId ("+str(ret['imgid'])+") is not analyzed or analysis failed")

    ret['image_report'] = contexts['anchore_db'].load_image_report(ret['imgid'])

    ret['images'] = images

    ret['dirs'] = {}

    ret['dirs']['outputdir'] = argv[3]

    try:
        #ret['params'] = argv[4:]
        ret['params'] = ' '.join(argv[4:]).split()
    except:
        ret['params'] = list()

    for d in ret['dirs'].keys():
        thedir = ret['dirs'][d]
        if not os.path.exists(thedir):
            raise Exception(d + " directory '" + thedir + "' does not exist.")

    ret['meta'] = ret['image_report']['meta']
    ret['baseid'] = ret['image_report']['familytree'][0]

    ret['imgtags'] = ret['meta']['humanname']
    ret['output'] = '/'.join([ret['dirs']['outputdir'], ret['name']])
    ret['output_warns'] = '/'.join([ret['dirs']['outputdir'], ret['name']+".WARNS"])

    return (ret)

def get_docker_images(cli):
    ret = {}
    if not cli:
        return(ret)

    docker_images = cli.images(all=True)
    for i in docker_images:
        if 'Id' in i:
            Id = re.sub("sha256:", "", i['Id'])
            ret[Id] = i

    return(ret)

def anchore_common_context_setup(config):
    if 'docker_cli' not in contexts or not contexts['docker_cli']:

        dimages = {}
        try:
            contexts['docker_cli'] = docker.Client(base_url=config['docker_conn'], version='auto', timeout=int(config['docker_conn_timeout']))
            testconn = contexts['docker_cli'].version()
            dimages = get_docker_images(contexts['docker_cli']) 
        except Exception as err:
            contexts['docker_cli']=None

        contexts['docker_images'] = dimages

    if 'anchore_allimages' not in contexts or not contexts['anchore_allimages']:
        contexts['anchore_allimages'] = {}

    if 'anchore_db' not in contexts or not contexts['anchore_db']:
        contexts['anchore_db'] = anchore_image_db.load(driver=config['anchore_db_driver'], config=config)

    if 'anchore_auth' not in contexts or not contexts['anchore_auth']:
        aafile = os.path.join(config.config_dir, "anchore_auth.json")
        username = config.DEFAULT_ANON_ANCHORE_USERNAME
        password = config.DEFAULT_ANON_ANCHORE_PASSWORD
        if os.path.exists(aafile):
            try:
                with open(aafile, 'r') as FH:
                    aa = json.loads(FH.read())
                    username = aa['username']
                    password = aa['password']
            except:
                pass
                
        contexts['anchore_auth'] = anchore_auth.anchore_auth_init(username, password, aafile, config['anchore_client_url'], config['anchore_token_url'], config['anchore_auth_conn_timeout'], config['anchore_auth_max_retries'])

    if 'anchore_config' not in contexts or not contexts['anchore_config']:
        contexts['anchore_config'] = config

    return(True)

def load_analyzer_config(anchore_conf_dir):
    anchore_analyzer_config = {}
    csum = None

    anchore_analyzer_configfile = '/'.join([anchore_conf_dir, 'analyzer_config.yaml'])
    if os.path.exists(anchore_analyzer_configfile):
        try:
            with open(anchore_analyzer_configfile, 'r') as FH:
                adata = FH.read()
                csum = hashlib.md5(adata).hexdigest()
                anchore_analyzer_config = yaml.safe_load(adata)
        except Exception as err:
            raise err

    return(anchore_analyzer_config, csum)

# anchoreDB pass through functions

def is_image_analyzed(imageId):
    return(contexts['anchore_db'].is_image_analyzed(imageId))

def del_files_cache(imageId, namespace=None):
    return(contexts['anchore_db'].del_files_cache(imageId, namespace=None))

def load_files_tarfile(imageId, namespace):
    return(contexts['anchore_db'].load_files_tarfile(imageId, namespace))

def load_files_metadata(imageId, namespace):
    return(contexts['anchore_db'].load_files_metadata(imageId, namespace))

def load_files_namespaces(imageId):
    return(contexts['anchore_db'].load_files_namespaces(imageId))

def save_files(imageId, namespace, rootfsdir, files):
    return(contexts['anchore_db'].save_files(imageId, namespace, rootfsdir, files))

def save_gate_output(imageId, gate_name, data):
    return(contexts['anchore_db'].save_gate_output(imageId, gate_name, data))

def save_gate_help_output(gate_help):
    return(contexts['anchore_db'].save_gate_help_output(gate_help))

def save_analysis_output(imageId, module_name, module_value, data, module_type=None):
    return(contexts['anchore_db'].save_analysis_output(imageId, module_name, module_value, data, module_type=module_type))


def load_analysis_output(imageId, module_name, module_value):
    ret = {}
    ret = contexts['anchore_db'].load_analysis_output(imageId, module_name, module_value, module_type='user')
    if ret: return(ret)
    ret = contexts['anchore_db'].load_analysis_output(imageId, module_name, module_value, module_type='extra')
    if ret: return(ret)
    ret = contexts['anchore_db'].load_analysis_output(imageId, module_name, module_value)
    if ret: return(ret)

    return(ret)

def load_gate_output(imageId, gate_name):
    return(contexts['anchore_db'].load_gate_report(imageId, gate_name))

def load_image_report(imageId):
    return(contexts['anchore_db'].load_image_report(imageId))

def load_analysis_report(imageId):
    return(contexts['anchore_db'].load_analysis_report(imageId))

def load_gates_report(imageId):
    return(contexts['anchore_db'].load_gates_report(imageId))

def load_gates_eval_report(imageId):
    return(contexts['anchore_db'].load_gates_eval_report(imageId))


def list_analysis_outputs(imageId):
    return(contexts['anchore_db'].list_analysis_outputs(imageId))

def load_analyzer_manifest(imageId):
    return(contexts['anchore_db'].load_analyzer_manifest(imageId))


def load_image(imageId):
    return(contexts['anchore_db'].load_image(imageId))

def load_all_images():
    return(contexts['anchore_db'].load_all_images())


def is_image_analyzed(imageId):
    return(contexts['anchore_db'].is_image_analyzed(imageId))

def is_image_present(imageId, imagelist=None):
    return(contexts['anchore_db'].is_image_present(imageId, imagelist))


def get_image_list():
    return(contexts['anchore_db'].get_image_list())

def delete_image(imageId):
    return(contexts['anchore_db'].delete_image(imageId))


def is_intermediate_image(imageId, image_report=None):
    if not image_report:
        image_report = load_image_report(imageId)
    
    if image_report:
        try:
            if str(image_report['meta']['usertype']) in ['user', 'base', 'anchorebase', 'oldanchorebase']:
                return(False)
        except:
            pass

        try:
            if image_report['anchore_all_tags'] or image_report['anchore_current_tags']:
                return(False)
        except:
            pass

        try:
            if image_report['docker_data']['RepoTags']:
                return(False)
        except:
            pass
    else:
        raise Exception("could not load input image from anchoreDB: " + str(imageId))

    return(True)

def make_anchoretmpdir(tmproot):
    tmpdir = '/'.join([tmproot, str(random.randint(0, 9999999)) + ".anchoretmp"])
    try:
        os.makedirs(tmpdir)
        return(tmpdir)
    except:
        return(False)

def generate_gates_manifest():
    ret = {}
    failedgates = []

    config = contexts['anchore_config']
    gmanifest = contexts['anchore_db'].load_gates_manifest()

    # remove any modules that from manifest that are no longer present on FS
    for gcommand in gmanifest.keys():
        if not os.path.exists(gcommand):
            gmanifest.pop(gcommand, None)
#        else:
#            try:
#                if gmanifest[gcommand]['returncode'] != 0:
#                    failedgates.append(gmanifest[gcommand]['command'])
#            except:
#                pass

    # make list of all places gate modules can be
    gatesdir = '/'.join([config["scripts_dir"], "gates"])
    path_overrides = ['/'.join([config['user_scripts_dir'], 'gates'])]
    if config['extra_scripts_dir']:
        path_overrides = path_overrides + ['/'.join([config['extra_scripts_dir'], 'gates'])]
        
    # either generate a new element for the module record in the manifest (if new module or module csum is different from what is in manifest), or skip
    for gdir in path_overrides + [gatesdir]:
        for gcmd in os.listdir(gdir):
            script = os.path.join(gdir, gcmd)
            if re.match(".*~$|.*#$|.*\.pyc", gcmd) or not os.access(script, os.R_OK ^ os.X_OK):
                # skip tmp and pyc modules
                continue

            try:
                with open(script, 'r') as FH:
                    csum = hashlib.md5(FH.read()).hexdigest()
            except:
                csum = "N/A"

            if script not in gmanifest or gmanifest[script]['csum'] == 'N/A' or gmanifest[script]['csum'] != csum or gmanifest[script]['returncode'] != 0:
                el = {
                    'status':'FAIL',
                    'returncode':1,
                    'timestamp':time.time(),
                    'command':"",
                    'csum':csum,
                    'gatename':"",
                    'triggers':{},
                    'type':'gate'
                }

                cmd = [script, 'stdout', "anchore_get_help"]
                try:
                    el['command'] = ' '.join(cmd)

                    (rc, sout, cmdstring) = run_command(cmd)
                    el['returncode'] = rc
                    if rc == 0:
                        el['status'] = 'SUCCESS'
                        try:
                            data = json.loads(sout)
                        except:
                            data = {}

                        for gkey in data.keys():
                            el['gatename'] = gkey
                            el['triggers'] = data[gkey]
                    else:
                        raise Exception("could not exec/generate help/trigger output for gate module: " + str(' '.join(cmd)))
                except Exception as err:
                    _logger.warn("WARNING: " + str(err))

                    cmdstring = ' '.join(cmd)
                    if cmdstring not in failedgates:
                        failedgates.append(cmdstring)

                gmanifest[script] = el
            else:
                _logger.debug("no change in module, skipping trigger info get: " + str(script))

    # save the resulting manifest
    contexts['anchore_db'].save_gates_manifest(gmanifest)

    return(gmanifest, failedgates)

def discover_gates():
    gmanifest, failedgates = generate_gates_manifest()
    
    allhelp = {}
    for gkey in gmanifest:
        gatename = gmanifest[gkey]['gatename']
        allhelp[gatename] = gmanifest[gkey]['triggers']

    return(allhelp)

def discover_gates_orig():
    config = contexts['anchore_config']
    ret = {}

    gatesdir = '/'.join([config["scripts_dir"], "gates"])
    outputdir = make_anchoretmpdir(config['tmpdir'])

    path_overrides = ['/'.join([config['user_scripts_dir'], 'gates'])]
    if config['extra_scripts_dir']:
        path_overrides = path_overrides + ['/'.join([config['extra_scripts_dir'], 'gates'])]

    try:
        results = scripting.ScriptSetExecutor(path=gatesdir, path_overrides=path_overrides).execute(capture_output=True, fail_fast=True, cmdline=' '.join([outputdir, 'anchore_get_help']))
    except Exception as err:
        pass

    # walk through outputdir looking for dropped help output
    allhelp = {}
    for d in os.listdir(outputdir):
        gate_name = None
        match = re.match("(.*)\.help", d)
        if match:
            gate_name = match.group(1)
        if gate_name:
            helpfile = os.path.join(outputdir, d)
            with open(helpfile, 'r') as FH:
                helpdata = json.loads(FH.read())
            allhelp[gate_name] = helpdata

    shutil.rmtree(outputdir)

    save_gate_help_output(allhelp)

    return(allhelp)

def discover_from_info(dockerfile_contents):
    fromline = fromid = None

    #fromline = re.match(".*FROM\s+(\S+).*", dockerfile_contents).group(1)

    fromlines = re.findall("\s*FROM\s+(\S+)\s*[\n]", dockerfile_contents)
    if fromlines:
        fromline = fromlines[0]

    if fromline:
        fromline = fromline.lower()
        if re.match("scratch", fromline) or re.match(".*<unknown>.*", fromline):
            fromid = fromline
        else:
            try:
                fromid = discover_imageId(fromline)
            except:
                fromid = None
    return(fromline, fromid)

def get_imageIds_named(name):
    ret = list()
    for result in contexts['anchore_db'].load_all_images_iter():
        imageId = result[0]
        image = result[1]
        if name == imageId:
            ret.append(imageId)
        elif re.match("^"+name, imageId):
            ret.append(imageId)
        elif name in image['anchore_all_tags'] + image['anchore_current_tags'] or name+":latest" in image['anchore_all_tags'] + image['anchore_current_tags']:
            ret.append(imageId)

    return(ret)

def discover_imageIds(namelist):
    ret = list()
    
    for name in namelist:
        result = discover_imageId(name)
        ret.append(result)

    return(ret)

def discover_imageId(name):

    ret = None

    # method -
    # 1) check if 'name' is in docker images list (key == imageId)
    # 2) check if 'name' or 'name:latest' is in docker images list repo/tags
    # 3) check anchoreDB
    # 4) check docker_inspect

    imageId = None
    try:
        _logger.debug("looking for name ("+name+") in docker_images")

        name_variants = []
        name_variants.append(name)

        try:
            docker_images = contexts['docker_images']
        except:
            docker_images = {}

        if name in docker_images.keys():
            imageId = name

        if not imageId:
            _logger.debug("looking for alternative names ("+name+") in docker_images")
            iname = re.sub("sha256:", "", name)
            for dimageId in docker_images.keys():
                i = docker_images[dimageId]
                if iname == i['Id'] or iname == re.sub("sha256:", "", i['Id']):
                    imageId = re.sub("sha256:", "", i['Id'])
                    break
                elif 'RepoTags' in i and i['RepoTags']:
                    for r in i['RepoTags']:
                        if name == r or name+":latest" == r:
                            imageId = re.sub("sha256:", "", i['Id'])
                            break
                        elif "docker.io/"+name == r or "docker.io/"+name+":latest" == r:
                            imageId = re.sub("sha256:", "", i['Id'])
                            break

        if not imageId:
            _logger.debug("looking for name ("+name+") in anchoreDB")
            for iname in name_variants:
                if contexts['anchore_db'].is_image_present(iname):
                    imageId = name
                    break

        if not imageId:
            _logger.debug("trying to load name ("+name+") from anchoreDB")
            for iname in name_variants:
                aimage = contexts['anchore_db'].load_image(iname)
                if aimage:
                    imageId = name
                    break

        if not imageId:
            _logger.debug("searching for name ("+name+") in anchoreDB")
            for iname in name_variants:
                ilist = get_imageIds_named(iname)
                if len(ilist) == 1:
                    imageId = ilist[0]
                    #aimage = contexts['anchore_db'].load_image(imageId)
                elif len(ilist) > 1:
                    raise ValueError("Input image name '"+str(iname)+"' is ambiguous in anchore:\n\tmatching imageIds: " + str(ilist))

        if not imageId:
            _logger.debug("trying docker.inspect_image on name ("+name+")")
            docker_cli = contexts['docker_cli']
            if docker_cli:
                try:
                    docker_data = docker_cli.inspect_image(name)
                    imageId = re.sub("sha256:", "", docker_data['Id'])
                except Exception as err:
                    pass
                    
    except ValueError as err:
        raise err

    except Exception as err:
        raise err

    if not imageId:
        raise ValueError("Input image name '"+str(name)+"' not found in local dockerhost or anchore DB.")

    return(imageId)

def get_images_from_kubectl():
    images = {}
    try:
        cmd = "kubectl get --all-namespaces --output json pods".split()
        jsonbuf = subprocess.check_output(cmd)
        kubedata = json.loads(jsonbuf)
        if 'items' in kubedata:
            for item in kubedata['items']:
                if 'status' in item:
                    if 'containerStatuses' in item['status']:
                        imagename = imageId = None
                        for cs in item['status']['containerStatuses']:
                            if 'image' in cs:
                                imagename = cs['image']
                            if 'imageID' in cs:
                                imageId = re.sub("^docker://sha256:", "", cs['imageID'])
                            
                            if imagename and imageId:
                                images[imageId] = imagename
    except Exception as err:
        raise err
    return(images)

def print_result(config, result, outputmode=None):
    if not result:
        return (False)

    if not outputmode:
        if config.cliargs['json']:
            outputmode = 'json'
        elif config.cliargs['plain']:
            outputmode = 'plaintext'
        elif config.cliargs['html']:
            outputmode = 'table'
            tablemode = 'html'
        else:
            outputmode = 'table'
            tablemode = 'stdout'

    if outputmode == 'table' and tablemode == 'stdout':
        try:
            width = int(subprocess.check_output(['stty', 'size'], stderr=open(os.devnull, 'w')).split()[1]) - 10
        except:
            width = 70
    else:
        width = 9999999
    
    if outputmode == 'json':
        print json.dumps(result)
    else:
        output = list()
        if len(result.keys()) > 0:
            sortby = False

            # this is awkward - need better way to differentiate header from results
            for i in result.keys():
                json_dict = result[i]
                sortby = False

                header = json_dict['result']['header']
                if outputmode == 'table':
                    header = [ re.sub("_", " ", x.encode('utf8')) for x in header ]
                    t = PrettyTable(header)
                    t.align = 'l'

                for h in header:
                    if re.match(r"^\*.*", h):
                        sortby = h

                break

            emptyresult = False
            for i in result.keys():
                json_dict = result[i]

                for orow in json_dict['result']['rows']:
                    if outputmode == 'table':
                        row = [ fill(x, max(12, width / (len(orow))) ).encode('utf8') for x in orow ]
                        t.add_row(row)
                    elif outputmode == 'plaintext':
                        row = [ re.sub("\s", ",", x.encode('utf8')) for x in orow ]
                        output.append(row)
                    elif outputmode == 'raw':
                        output.append(orow)

#            if outputmode == 'table' and tablemode == 'html':
#                print "<HTML><BODY>"

            if outputmode == 'table':
                if sortby:
                    if tablemode == 'stdout':
                        print t.get_string(sortby=sortby, reversesort=True)
                    elif tablemode == 'html':
                        print t.get_html_string(sortby=sortby, reversesort=True).encode('utf8')
                else:
                    if tablemode == 'stdout':
                        print t
                    elif tablemode == 'html':
                        print t.get_html_string().encode('utf8')
                print ""
            elif outputmode == 'plaintext':
                print ' '.join(header)
                print ""
                for r in output:
                    print ' '.join(r)
            elif outputmode == 'raw':
                for i in range(len(output)):
                    row = output[i]
                    for j in range(len(row)):
                        print "--- " + header[j] + " ---"
                        print output[i][j]
                        print 

        for k in result.keys():
            if 'warns' in result[k]:
                if outputmode == 'table':
                    t = PrettyTable(['WarningOutput'])
                    t.align = 'l'
                    for warn in result[k]['warns']:
                        t.add_row([warn])
                    
                    if tablemode == 'stdout':
                        print t
                    elif tablemode == 'html':
                        print "<BR></BR>"
                        print t.get_html_string()
                if outputmode == 'plaintext':
                    print "\nWarning Output\n"
                    for warn in result[k]['warns']:
                        print str(warn)
                if outputmode == 'raw':
                    pass

#        if outputmode == 'table' and tablemode == 'html':
#            print "</BODY></HTML>"
    return (True)

def apkg_parse_apkdb(apkdb):
    if not os.path.exists(apkdb):
        raise ValueError("cannot locate APK installed DB '"+str(apkdb)+"'")
        
    apkgs = {}                
    apkg = {
        'version':"N/A",
        'sourcepkg':"N/A",
        'release':"N/A",
        'origin':"N/A",
        'arch':"N/A",
        'license':"N/A",
        'size':"N/A"
    }
    thename = ""
    thepath = ""
    thefiles = list()
    allfiles = list()

    FH=open(apkdb, 'r')
    for l in FH.readlines():
        l = l.strip().decode('utf8')

        if not l:
            apkgs[thename] = apkg
            if thepath:
                flist = list()
                for x in thefiles:
                    flist.append(os.path.join(thepath, x))
                flist.append(os.path.join(thepath))
                allfiles = allfiles + flist
            apkgs[thename]['files'] = allfiles
            apkg = {
                'version':"N/A",
                'sourcepkg':"N/A",
                'release':"N/A",
                'origin':"N/A",
                'arch':"N/A",
                'license':"N/A",
                'size':"N/A",
                'type':"APKG"
            }
            allfiles = list()
            thefiles = list()
            thepath = ""

        patt = re.match("(\S):(.*)", l)
        if patt:
            (k, v) = patt.group(1,2)
            apkg['type'] = "APKG"
            if k == 'P':
                thename = v
                apkg['name'] = v
            elif k == 'V':
                vpatt = re.match("(\S*)-(\S*)", v)
                if vpatt:
                    (vers, rel) = vpatt.group(1, 2)
                else:
                    vers = v
                    rel = "N/A"                    
                apkg['version'] = vers
                apkg['release'] = rel
            elif k == 'm':
                apkg['origin'] = v
            elif k == 'I':
                apkg['size'] = v
            elif k == 'L' and v:
                apkg['license'] = v
            elif k == 'o':
                apkg['sourcepkg'] = v
            elif k == 'A':
                apkg['arch'] = v
            elif k == 'F':
                if thepath:
                    flist = list()
                    for x in thefiles:
                        flist.append(os.path.join(thepath, x))
                    flist.append(os.path.join(thepath))
                    allfiles = allfiles + flist

                thepath = "/" + v
                thefiles = list()
            elif k == 'R':
                thefiles.append(v)

    FH.close()
    return(apkgs)

def apkg_get_all_pkgfiles(unpackdir):
    apkdb = '/'.join([unpackdir, 'rootfs/lib/apk/db/installed'])
    return(apkg_parse_apkdb(apkdb))

def dpkg_compare_versions(v1, op, v2):
    cmd = ['dpkg', '--compare-versions', v1, op, v2]
    return(subprocess.call(cmd))

def apkg_compare_versions(v1, op, v2):
    try:
        result = apk_compare_versions_impl(v1, op, v2)
        if result:
            return(0)
        else:
            return(1)
    except Exception as err:
        _logger.error("cannot compare version strings - exception: " + str(err))
        return(1)
        
    return(1)

def dpkg_get_all_packages(unpackdir):
    actual_packages = {}
    all_packages = {}
    other_packages = {}
    cmd = ["dpkg-query", "--admindir="+unpackdir+"/rootfs/var/lib/dpkg", "-W", "-f="+"${Package} ${Version} ${source:Package} ${source:Version} ${Architecture}\\n"]
    try:
        sout = subprocess.check_output(cmd)
        for l in sout.splitlines(True):
            l = l.strip()
            l = l.decode('utf8')
            (p, v, sp, sv, arch) = re.match('(\S*)\s*(\S*)\s*(\S*)\s*(\S*)\s*(.*)', l).group(1, 2, 3, 4, 5)
            if p and v:
                if p not in actual_packages:
                    actual_packages[p] = {'version':v, 'arch':arch}
                if p not in all_packages:
                    all_packages[p] = {'version':v, 'arch':arch}
            if sp and sv:
                if sp not in all_packages:
                    all_packages[sp] = {'version':sv, 'arch':arch}
            if p and v and sp and sv:
                if p == sp and v != sv:
                    other_packages[p] = [{'version':sv, 'arch':arch}]

    except Exception as err:
        print "Could not run command: " + str(cmd)
        print "Exception: " + str(err)
        print "Please ensure the command 'dpkg' is available and try again"
        raise err

    ret = (all_packages, actual_packages, other_packages)
    return(ret)

def dpkg_get_all_pkgfiles(unpackdir):
    allfiles = {}

    try:
        (allpkgs, actpkgs, othpkgs) = dpkg_get_all_packages(unpackdir)    
        cmd = ["dpkg-query", "--admindir="+unpackdir+"/rootfs/var/lib/dpkg", "-L"] + actpkgs.keys()
        sout = subprocess.check_output(cmd)
        for l in sout.splitlines():
            l = l.strip()
            l = l.decode('utf8')
            allfiles[l] = True
            
    except Exception as err:
        print "Could not run command: " + str(' '.join(cmd))
        print "Exception: " + str(err)
        print "Please ensure the command 'dpkg' is available and try again"
        raise err

    return(allfiles)

def verify_file_packages(unpackdir, flavor):
    if flavor == 'RHEL':
        return(rpm_verify_file_packages(unpackdir))
    else:
        return(generic_verify_file_packages(unpackdir))
            
def generic_verify_file_packages(unpackdir):
    return({}, None, "", "", 255)

def rpm_verify_file_packages(unpackdir):

    rootfs = os.path.join(unpackdir, 'rootfs')
    verify_output = verify_error = ""
    verify_exitcode = 255

    tmpdbpath = prepdbpath = None
    try:

        prepdbpath = rpm_prepdb(unpackdir)
        if not os.path.exists(prepdbpath):
            raise Exception("no prepdbpath created ("+str(prepdbpath)+")")

        tmpdbpath = os.path.join(rootfs, 'tmprpmdb')
        shutil.copytree(prepdbpath, tmpdbpath)
        if not os.path.exists(tmpdbpath):
            raise Exception("no tmpdbpath created ("+str(tmpdbpath)+")")

    except:
        if tmpdbpath and os.path.exists(tmpdbpath):
            shutil.rmtree(tmpdbpath)
        raise Exception("failed to prep environment for rpm verify - exception: " + str(err))

    try:
        verify_cmd = 'rpm --root=' + rootfs + ' --dbpath=/tmprpmdb/' + ' --verify -a'
        pipes = subprocess.Popen(verify_cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        o, e = pipes.communicate()
        verify_exitcode = pipes.returncode
        verify_output = o
        verify_error = e
    except Exception as err:
        raise ValueError("could not perform verify against RPM database: " + str(err))
    finally:
        if os.path.exists(tmpdbpath):
            shutil.rmtree(tmpdbpath)

    verify_hash = {}
    for line in verify_output.splitlines():
        el = line.split()
        file = el[-1]
        vresult = el[0]
        verify_hash[file] = vresult

    return(verify_hash, verify_cmd, verify_output, verify_error, verify_exitcode)

def rpm_prepdb(unpackdir):
    origrpmdir = os.path.join(unpackdir, 'rootfs', 'var', 'lib', 'rpm')
    ret = origrpmdir

    if os.path.exists(origrpmdir):
        newrpmdirbase = make_anchoretmpdir(unpackdir)
        newrpmdir = os.path.join(newrpmdirbase, 'var', 'lib', 'rpm')
        try:
            shutil.copytree(origrpmdir, newrpmdir)
            sout = subprocess.check_output(['rpmdb', '--root='+newrpmdirbase, '--dbpath=/var/lib/rpm', '--rebuilddb'])
            ret = newrpmdir
        except:
            pass

    return(ret)

def rpm_get_all_packages(unpackdir):
    rpms = {}
    rpmdbdir = rpm_prepdb(unpackdir)
    try:
        sout = subprocess.check_output(['rpm', '--dbpath='+rpmdbdir, '--queryformat', '%{NAME} %{VERSION} %{RELEASE} %{ARCH}\n', '-qa'], stderr=subprocess.STDOUT)
        for l in sout.splitlines():
            l = l.strip()
            l = l.decode('utf8')
            (name, vers, rel, arch) = re.match('(\S*)\s*(\S*)\s*(\S*)\s*(.*)', l).group(1, 2, 3, 4)
            rpms[name] = {'version':vers, 'release':rel, 'arch':arch}
    except Exception as err:
        print err.output
        raise ValueError("could not get package list from RPM database: " + str(err))

    return(rpms)

def rpm_get_all_pkgfiles(unpackdir):
    rpmfiles = {}
    rpmdbdir = rpm_prepdb(unpackdir)
    try:
        sout = subprocess.check_output(['rpm', '--dbpath='+rpmdbdir, '-qal'])
        for l in sout.splitlines():
            l = l.strip()
            l = l.decode('utf8')
            rpmfiles[l] = True
    except Exception as err:
        raise ValueError("could not get file list from RPM database: " + str(err))

    return(rpmfiles)

def gem_parse_meta(gem):
    ret = {}

    name = None
    versions = []
    lics = []
    latest = None
    origins = []
    sourcepkg = None
    rfiles = []

    try:
        for line in gem.splitlines():
            line = line.strip()
            line = re.sub("\.freeze", "", line)

            # look for the unicode \u{} format and try to convert to something python can use
            try:
                replline = line
                mat = "\\\u{.*?}"
                patt = re.match(r".*("+mat+").*", replline)
                while(patt):
                    replstr = ""
                    subpatt = re.match("\\\u{(.*)}", patt.group(1))
                    if subpatt:
                        chars = subpatt.group(1).split()
                        for char in chars:
                            replstr += unichr(int(char, 16))

                    if replstr:
                        replline = re.sub(re.escape(patt.group(1)), replstr, replline, 1)

                    patt = re.match(r".*("+mat+").*", replline)
                    line = replline
            except Exception as err:
                pass

            patt = re.match(".*\.name *= *(.*) *", line)
            if patt:
                name = json.loads(patt.group(1))

            patt = re.match(".*\.homepage *= *(.*) *", line)
            if patt:
                sourcepkg = json.loads(patt.group(1))

            patt = re.match(".*\.version *= *(.*) *", line)
            if patt:
                v = json.loads(patt.group(1))
                latest = v
                versions.append(latest)

            patt = re.match(".*\.licenses *= *(.*) *", line)
            if patt:
                lstr = re.sub("^\[|\]$", "", patt.group(1)).split(',')
                for thestr in lstr:
                    thestr = re.sub(' *" *', "", thestr)
                    lics.append(thestr)

            patt = re.match(".*\.authors *= *(.*) *", line)
            if patt:
                lstr = re.sub("^\[|\]$", "", patt.group(1)).split(',')
                for thestr in lstr:
                    thestr = re.sub(' *" *', "", thestr)
                    origins.append(thestr)

            patt = re.match(".*\.files *= *(.*) *", line)
            if patt:
                lstr = re.sub("^\[|\]$", "", patt.group(1)).split(',')
                for thestr in lstr:
                    thestr = re.sub(' *" *', "", thestr)
                    rfiles.append(thestr)

    except Exception as err:
        print "WARN could not fully parse gemspec file: " + str(name) + ": exception: " + str(err)
        return({})

    if name:
        ret[name] = {'name':name, 'lics':lics, 'versions':versions, 'latest':latest, 'origins':origins, 'sourcepkg':sourcepkg, 'files':rfiles}

    return(ret)

def npm_parse_meta(npm):

    record = {}

    name = npm.pop('name', None)
    if not name:
        return(record)

    lics = list()
    versions = list()
    latest = None
    origins = list()
    sourcepkg = None

    npmtime = npm.pop('time', None)
    npmdesc = npm.pop('description', None)
    npmdisttags = npm.pop('dist-tags', None)
    npmkeywords = npm.pop('keywords', None)


    npmlicense = npm.pop('license', None)
    npmversions = npm.pop('versions', None)
    npmversion = npm.pop('version', None)
    npmauthor = npm.pop('author', None)
    npmmaintainers = npm.pop('maintainers', None)
    npmrepository = npm.pop('repository', None)
    npmhomepage= npm.pop('homepage', None)

    if npmlicense:
        if isinstance(npmlicense, basestring):
            lics.append(npmlicense)
        elif isinstance(npmlicense, dict):
            for ktype in ['type', 'name', 'license', 'sourceType']:
                lic = npmlicense.pop(ktype, None)
                if lic:
                    lics.append(lic)
        elif isinstance(npmlicense, list):
            for lentry in npmlicense:
                if isinstance(lentry, basestring):
                    lics.append(lentry)
                elif isinstance(lentry, dict):
                    for ktype in ['type', 'name', 'license', 'sourceType']:
                        lic = lentry.pop(ktype, None)
                        if lic:
                            lics.append(lic)
        else:
            print "unknown type (" + str(name) + "): " + str(type(npmlicense))


    if npmversions:
        if isinstance(npmversions, dict):
            versions = npmversions.keys()
            for v in npmversions:
                if npmversions[v] == 'latest':
                    latest = v
        elif isinstance(npmversions, list):
            versions = npmversions
    elif npmversion:
        versions.append(npmversion)

    astring = None
    if npmauthor:
        if isinstance(npmauthor, basestring):
            astring = npmauthor
        elif isinstance(npmauthor, dict):
            aname = npmauthor.pop('name', None)
            aurl = npmauthor.pop('url', None)
            if aname:
                astring = aname
                if aurl:
                    astring += " ("+aurl+")"
        else:
            print "unknown type (" + str(name) + "): "+ str(type(npmauthor))

    elif npmmaintainers:
        for m in npmmaintainers:
            aname = m.pop('name', None)
            aemail = m.pop('email', None)
            if aname:
                astring = aname
                if aemail:
                    astring += " ("+aemail+")"

    if astring:
        origins.append(astring)

    if npmrepository:
        if isinstance(npmrepository, dict):
            sourcepkg = npmrepository.pop('url', None)
        elif isinstance(npmrepository, basestring):
            sourcepkg = npmrepository
        else:
            print "unknown type (" + str(name) + "): " + str(type(npmrepository))

    elif npmhomepage:
        if isinstance(npmhomepage, basestring):
            sourcepkg = npmhomepage

    if not lics:
        print "WARN: ("+name+") no lics: " + str(npm)
    if not versions:
        print "WARN: ("+name+") no versions: " + str(npm)
    if not origins:
        print "WARN: ("+name+") no origins: " + str(npm)
    if not sourcepkg:
        print "WARN: ("+name+") no sourcepkg: " + str(npm)

    if name:
        record[name] = {'name':name, 'lics':lics, 'versions':versions, 'latest':latest, 'origins':origins, 'sourcepkg':sourcepkg}

    return(record)

def get_distro_from_imageId(imageId):
    meta = {
        'DISTRO':None,
        'DISTROVERS':None,
        'LIKEDISTRO':None
    }

    anchore_analyzer_meta = load_analysis_output(imageId, 'analyzer_meta', 'analyzer_meta')
    meta['DISTRO'] = anchore_analyzer_meta.pop('DISTRO', 'UNKNOWN')
    meta['DISTROVERS'] = anchore_analyzer_meta.pop('DISTROVERS', 'UNKNOWN')
    meta['LIKEDISTRO'] = anchore_analyzer_meta.pop('LIKEDISTRO', 'UNKNOWN')
    return (meta)

def get_distro_from_path(inpath):

    meta = {
        'DISTRO':None,
        'DISTROVERS':None,
        'LIKEDISTRO':None
    }

    if os.path.exists('/'.join([inpath,"/etc/os-release"])):
        FH=open('/'.join([inpath,"/etc/os-release"]), 'r')
        for l in FH.readlines():
            l = l.strip()
            l = l.decode('utf8')
            try:
                (key, val) = l.split("=")
                val = re.sub(r'"', '', val)
                if key == "ID":
                    meta['DISTRO'] = val
                elif key == "VERSION_ID":
                    meta['DISTROVERS'] = val
                elif key == "ID_LIKE":
                    meta['LIKEDISTRO'] = ','.join(val.split())
            except:
                pass
        FH.close()
    elif os.path.exists('/'.join([inpath, "/etc/system-release-cpe"])):
        FH=open('/'.join([inpath, "/etc/system-release-cpe"]), 'r')
        for l in FH.readlines():
            l = l.strip()
            l = l.decode('utf8')
            try:
                distro = l.split(':')[2]
                vers = l.split(':')[4]
                meta['DISTRO'] = distro
                meta['DISTROVERS'] = vers
            except:
                pass
        FH.close()
    elif os.path.exists('/'.join([inpath, "/etc/redhat-release"])):
        FH=open('/'.join([inpath, "/etc/redhat-release"]), 'r')
        for l in FH.readlines():
            l = l.strip()
            l = l.decode('utf8')
            try:
                distro = vers = None
                patt = re.match(".*CentOS.*", l)
                if patt:
                    distro = 'centos'

                patt = re.match(".*(\d+\.\d+).*", l)
                if patt:
                    vers = patt.group(1)

                if distro:
                    meta['DISTRO'] = distro
                if vers:
                    meta['DISTROVERS'] = vers
            except:
                pass
        FH.close()
    elif os.path.exists('/'.join([inpath, "/bin/busybox"])):
        meta['DISTRO'] = "busybox"
        try:
            sout = subprocess.check_output(['/'.join([inpath, "/bin/busybox"])])
            fline = sout.splitlines(True)[0]
            slist = fline.split()
            meta['DISTROVERS'] = slist[1]
        except:
            meta['DISTROVERS'] = "0"

    if meta['DISTRO'] == 'debian' and not meta['DISTROVERS'] and os.path.exists('/'.join([inpath, "/etc/debian_version"])):
        with open('/'.join([inpath, "/etc/debian_version"]), 'r') as FH:
            meta['DISTRO'] = 'debian'
            for line in FH.readlines():
                line = line.strip()
                patt = re.match("(\d+)\..*", line)
                if patt:
                    meta['DISTROVERS'] = patt.group(1)
                elif re.match(".*sid.*", line):
                    meta['DISTROVERS'] = 'unstable'

    if not meta['DISTRO']:
        meta['DISTRO'] = "Unknown"
    if not meta['DISTROVERS']:
        meta['DISTROVERS'] = "0"
    if not meta['LIKEDISTRO']:
        meta['LIKEDISTRO'] = meta['DISTRO']

    #
    # some experimentation around alternative parsing of debian_version
    #
    #debmap = {
    #    'sid':'unstable',
    #    'buster':'10',
    #    'stretch':'9',
    #    'jessie':'8',
    #    'wheezy':'7',
    #    'squeeze':'6',
    #    'lenny':'5'
    #}
    #
    #if meta['DISTRO'] == 'debian' and os.path.exists(os.path.join(inpath, 'etc', 'debian_version')):
    #    with open(os.path.join(inpath, 'etc', 'debian_version'), 'r') as FH:
    #        for line in FH.readlines():
    #            line = line.strip()
    #            for regmatch in ["(.*)/(.*)", "(.*)"]:
    #                patt = re.match(regmatch, line)
    #                if patt:
    #                    for p in patt.groups():
    #                        if p in debmap:
    #                            meta['DISTROVERS'] = debmap[p]
    #

    return(meta)

def get_distro_flavor(distro, version, likedistro=None):
    ret = {
        'flavor':'Unknown',
        'version':'0',
        'fullversion':version,
        'distro':distro,
        'likedistro':distro,
        'likeversion':version
    }

    if distro in ['centos', 'rhel', 'redhat', 'fedora']:
        ret['flavor'] = "RHEL"
        ret['likedistro'] = 'centos'
    elif distro in ['debian', 'ubuntu']:
        ret['flavor'] = "DEB"
    elif distro in ['busybox']:
        ret['flavor'] = "BUSYB"
    elif distro in ['alpine']:
        ret['flavor'] = "ALPINE"
    elif distro in ['ol']:
        ret['flavor'] = "RHEL"
        ret['likedistro'] = 'centos'

    if ret['flavor'] == 'Unknown' and likedistro:
        likedistros = likedistro.split(',')
        for distro in likedistros:
            if distro in ['centos', 'rhel', 'fedora']:
                ret['flavor'] = "RHEL"
                ret['likedistro'] = 'centos'
            elif distro in ['debian', 'ubuntu']:
                ret['flavor'] = "DEB"
            elif distro in ['busybox']:
                ret['flavor'] = "BUSYB"
            elif distro in ['alpine']:
                ret['flavor'] = "ALPINE"
            elif distro in ['ol']:
                ret['flavor'] = "RHEL"
                ret['likedistro'] = 'centos'

            if ret['flavor'] != 'Unknown':
                break

    patt = re.match("(\d*)\.*(\d*)", version)
    if patt:
        (vmaj, vmin) = patt.group(1,2)
        if vmaj:
            ret['version'] = vmaj
            ret['likeversion'] = vmaj

    patt = re.match("(\d+)\.*(\d+)\.*(\d+)", version)
    if patt:
        (vmaj, vmin, submin) = patt.group(1,2,3)
        if vmaj and vmin:
            ret['version'] = vmaj + "." + vmin
            ret['likeversion'] = vmaj + "." + vmin

    return(ret)

def cve_load_data(imageId, cve_data_context=None):
    cve_data = None
    
    distrometa = get_distro_from_imageId(imageId)

    idistro = distrometa['DISTRO']
    idistrovers = distrometa['DISTROVERS']
    ilikedistro = distrometa['LIKEDISTRO']

    distrodict = get_distro_flavor(idistro, idistrovers, likedistro=ilikedistro)

    distro = distrodict['distro']
    distrovers = distrodict['version']
    likedistro = distrodict['likedistro']
    likeversion = distrodict['likeversion']
    fulldistro = distrodict['distro']
    fullversion = distrodict['fullversion']

    distrolist = [(distro,distrovers), (likedistro, likeversion), (fulldistro, fullversion), (likedistro, fullversion)]
    for f in distrolist:
        dstr = ':'.join([f[0], f[1]])
        if cve_data_context and dstr in cve_data_context:
            cve_data = cve_data_context[dstr]
            break
        else:
            feeddata = anchore_feeds.load_anchore_feed('vulnerabilities', ':'.join([f[0], f[1]]), ensure_unique=True)
            if feeddata['success']:
                cve_data = feeddata['data']
                if cve_data_context != None and dstr not in cve_data_context:
                    cve_data_context[dstr] = cve_data
                break

    if not cve_data:
        dstrs = []
        try:
            for dtup in distrolist:
                try:
                    dname = str(dtup[0])
                except:
                    dname = "unknown_distro"

                try:
                    dvers = str(dtup[1])
                    if dvers == '0':
                        dvers = "unknown_version"
                except:
                    dvers = "unknown_version"

                dstring = str(dname) + ":" + str(dvers)
                if dstring not in dstrs:
                    dstrs.append(dstring)
        except Exception as err:
            dstrs = ['unknown_distro:unknown_version']

        msg = "no CVE data is currently available for the detected base distro type ("+str(','.join(dstrs))+")"
        raise ValueError(str(msg))
        #raise ValueError("cannot find CVE data associated with the input container distro: ("+str(distrolist)+")")

    last_update = 0
    try:
        d = anchore_feeds.load_anchore_feed_group_datameta('vulnerabilities', dstr)
        last_update = d['last_update']
    except:
        pass

    return (last_update, dstr, cve_data)

def cve_scanimages(images, pkgmap, flavor, cve_data):
    results = {}
    for v in cve_data:
        outel = {}
        vuln = v['Vulnerability']

        #print "cve-scan: VULN NAME CVE: " + vuln['Name']
        for vtag in ['FixedIn', 'VulnerableIn']:
            if vtag in vuln:
                for fixes in vuln[vtag]:
                    isvuln = False
                    vpkg = fixes['Name']
                    #print "cve-scan: Vulnerable Package: " + vpkg
                    if vpkg in pkgmap:
                        for ivers in pkgmap[vpkg]['versions'].keys():
                            vvers = re.sub(r'^[0-9]*:', '', fixes['Version'])
                            #print "cve-scan: " + vpkg + "\n\tfixed vulnerability package version: " + vvers + "\n\timage package version: " + ivers

                            iversonly = ivers
                            isvuln = is_pkg_vuln(vtag, vpkg, flavor, ivers, iversonly, vvers)

                            if isvuln:
                                #print "cve-scan: Found vulnerable package: " + vpkg
                                severity = url = description = 'Not Available'
                                if 'Severity' in vuln:
                                    severity = vuln['Severity']
                                if 'Link' in vuln:
                                    url = vuln['Link']
                                if 'Description' in vuln:
                                    description = vuln['Description']

                                outel = {'images':pkgmap[vpkg]['versions'][ivers], 'pkgName': vpkg, 'imageVers': ivers, 'fixVers': vvers, 'severity': severity, 'url': url, 'description': description}

            if outel:
                results[vuln['Name']] = outel

    return(results)

def normalize_packages(imageId):
    
    distrometa = get_distro_from_imageId(imageId)
    idistro = distrometa['DISTRO']
    idistrovers = distrometa['DISTROVERS']
    ilikedistro = distrometa['LIKEDISTRO']
    distrodict = get_distro_flavor(idistro, idistrovers, likedistro=ilikedistro)
    flavor = distrodict['flavor']

    ret = {
        'bin_packages':{},
        'bin_to_src':{},
        'src_to_bin':{}
    }

    try:
        all_packages_detail = load_analysis_output(imageId, 'package_list', 'pkgs.allinfo')
        if not all_packages_detail:
            raise Exception("no package detail")

        for pkg in all_packages_detail.keys():

            try:
                # copy package details
                data = json.loads(all_packages_detail[pkg])
                ret['bin_packages'][pkg] = {}
                ret['bin_packages'][pkg].update(data)
                if data['release'] and data['release'] != "N/A":
                    ret['bin_packages'][pkg]['fullvers'] = data['version']+"-"+data['release']
                else:
                    ret['bin_packages'][pkg]['fullvers'] = data['version']

                # map binary to source pkg
                if pkg not in ret['bin_to_src']:
                    ret['bin_to_src'][pkg] = []

                # need to clean out/remove the "+b[0-9]+" from DEBs
                if flavor == 'DEB':
                    cleanvers = re.sub(re.escape("+b")+"\d+.*", "", data['version'])
                    spkg = re.sub(re.escape("-"+cleanvers), "", data['sourcepkg'])
                else:
                    spkg = re.sub(re.escape("-"+data['version'])+".*", "", data['sourcepkg'])

                ret['bin_to_src'][pkg].append(spkg)

                # map source pkg to binary
                if spkg not in ret['src_to_bin']:
                    ret['src_to_bin'][spkg] = []
                ret['src_to_bin'][spkg].append(pkg)
            except Exception as err:
                errmsg = "failed to normalize package: " + str(pkg) + " - exception: " + str(err)
                _logger.error(errmsg)
            
        return(ret)
    except Exception as err:
        _logger.debug("no package detail analyzer output found, falling back to base package analyzer output")

    try:
        all_packages = load_analysis_output(imageId, 'package_list', 'pkgs.all')
        all_packages_plus_source = load_analysis_output(imageId, 'package_list', 'pkgs_plus_source.all')
        
        all_packages.update(all_packages_plus_source)
        if not all_packages:
            raise Exception("no package data")

        for pkg in all_packages.keys():

            if flavor == 'RHEL':
                fname = pkg + '-' + all_packages[pkg] + '.tmparch.rpm'
                (n,v,r,e,a) = splitFilename(fname)
                el = {'version':v, 'release':r, 'fullvers':all_packages[pkg], 'type':'RPM', 'origin':"N/A", 'sourcepkg':"N/A", 'license':"N/A", 'arch':"N/A", 'size':"N/A"}
                ret['bin_packages'][pkg] = el
            elif flavor == 'DEB':
                try:
                    (v, r) = all_packages[pkg].split("-")
                except:
                    v = all_packages[pkg]
                    r = None
                    
                if r:
                    el = {'version':v, 'release':r, 'fullvers':all_packages[pkg], 'type':'DPKG', 'origin':"N/A", 'sourcepkg':"N/A", 'license':"N/A", 'arch':"N/A", 'size':"N/A"}
                else:
                    el = {'version':v, 'release':"", 'fullvers':all_packages[pkg], 'type':'DPKG', 'origin':"N/A", 'sourcepkg':"N/A", 'license':"N/A", 'arch':"N/A", 'size':"N/A"}

                ret['bin_packages'][pkg] = el
            elif flavor == 'ALPINE':
                try:
                    (v, r) = all_packages[pkg].split("-")
                except:
                    v = all_packages[pkg]
                    r = None
                    
                if r:
                    el = {'version':v, 'release':r, 'fullvers':all_packages[pkg], 'type':'APKG', 'origin':"N/A", 'sourcepkg':"N/A", 'license':"N/A", 'arch':"N/A", 'size':"N/A"}
                else:
                    el = {'version':v, 'release':"", 'fullvers':all_packages[pkg], 'type':'APKG', 'origin':"N/A", 'sourcepkg':"N/A", 'license':"N/A", 'arch':"N/A", 'size':"N/A"}

                ret['bin_packages'][pkg] = el

            else:
                pass

    except:
        _logger.debug("no package data found, skipping")

    try:
        all_packages_plus_source = load_analysis_output(imageId, 'package_list', 'pkgs_plus_source.all')
        for pkg in all_packages_plus_source.keys():
            if pkg not in ret['bin_packages']:
                svers = all_packages_plus_source[pkg]

                for rpkg in ret['bin_packages'].keys():
                    check_full = rpkg+"-"+all_packages_plus_source[pkg]
                    if ret['bin_packages'][rpkg]['fullname'] == check_full:

                        if rpkg not in ret['bin_to_src']:
                            ret['bin_to_src'][rpkg] = []
                        ret['bin_to_src'][rpkg].append(pkg)
                        
                        if pkg not in ret['src_to_bin']:
                            ret['src_to_bin'][pkg] = []
                        ret['src_to_bin'][pkg].append(rpkg)

    except Exception as err:
        _logger.debug("no source package data found, skipping")

    return(ret)

def cve_scan_packages(cve_data, norm_packages, flavor):
    import time
    #start = time.time()
    results = {}
    for v in cve_data:
        vuln = v['Vulnerability']
        #print "cve-scan: CVE: " + vuln['Name']

        fixedIn = {}
        if 'FixedIn' in vuln:
            for fixes in vuln['FixedIn']:
                vpkgname = fixes['Name']
                fixVers = re.sub(r'^[0-9]*:', '', fixes['Version'])
                fixedIn[vpkgname] = fixVers

        if 'VulnerableIn' in vuln:
            for vulns in vuln['VulnerableIn']:
                vpkgname = vulns['Name']
                vulnVers = re.sub(r'^[0-9]*:', '', vulns['Version'])
                if vpkgname not in fixedIn:
                    fixedIn[vpkgname] = "None"

        for vtag in ['FixedIn', 'VulnerableIn']:
            if vtag in vuln:
                for fixes in vuln[vtag]:
                    vpkgname = fixes['Name']
                    vvers = re.sub(r'^[0-9]*:', '', fixes['Version'])

                    fixVers = fixedIn[vpkgname]

                    vpkgs = []
                    ivers = iversonly = irelonly = None

                    #print "cve-scan: Vulnerable Package: " + vpkgname

                    if vpkgname in norm_packages['bin_packages']:
                        #ivers = norm_packages['bin_packages'][vpkgname]['fullvers']
                        #iversonly = norm_packages['bin_packages'][vpkgname]['version']
                        #irelonly = norm_packages['bin_packages'][vpkgname]['release']
                        vpkgs = [vpkgname]
                    
                    if vpkgname in norm_packages['src_to_bin']:
                        #bpkg = norm_packages['src_to_bin'][vpkgname][0]
                        #ivers = norm_packages['bin_packages'][bpkg]['fullvers']
                        #iversonly = norm_packages['bin_packages'][bpkg]['version']
                        #irelonly = norm_packages['bin_packages'][bpkg]['release']
                        vpkgs = vpkgs + norm_packages['src_to_bin'][vpkgname]


                    # go through all found packages that mapped to the CVE vul package to check versions for vulnerability
                    for vpkg in vpkgs:
                        isvuln = False

                        ivers = norm_packages['bin_packages'][vpkg]['fullvers']
                        iversonly = norm_packages['bin_packages'][vpkg]['version']

                        isvuln = is_pkg_vuln(vtag, vpkg, flavor, ivers, iversonly, vvers)

                        # finally - format and add result to return dict if vulnerability has been determined

                        if isvuln:
                            #print "cve-scan: Found vulnerable package: " + vpkg

                            severity = url = description = 'Not Available'
                            if 'Severity' in vuln:
                                severity = vuln['Severity']
                            if 'Link' in vuln:
                                url = vuln['Link']
                            if 'Description' in vuln:
                                description = vuln['Description']

                            try:
                                imagevers = norm_packages['bin_packages'][vpkg]['fullvers']
                            except:
                                imagevers = ivers
                            outel = {'pkgName': vpkg, 'imageVers': imagevers, 'fixVers': fixVers, 'severity': severity, 'url': url, 'description': description}

                            if vuln['Name'] not in results:
                                results[vuln['Name']] = []
                            if outel not in results[vuln['Name']]:
                                results[vuln['Name']].append(outel)

    return (results)

def cve_scanimage(cve_data, imageId):
    if not cve_data:
        return ({})

    try:
        distrometa = get_distro_from_imageId(imageId)
        idistro = distrometa['DISTRO']
        idistrovers = distrometa['DISTROVERS']
        ilikedistro = distrometa['LIKEDISTRO']
        distrodict = get_distro_flavor(idistro, idistrovers, likedistro=ilikedistro)
        flavor = distrodict['flavor']
    except Exception as err:
        print "cve-scan: could not determine image distro: returning empty value"
        return({})
    
    import time

    norm_packages = normalize_packages(imageId)

    if 'bin_packages' not in norm_packages or not norm_packages['bin_packages']:
        raise Exception("cannot perform CVE scan on image: no package data is available from analysis")

    results = cve_scan_packages(cve_data, norm_packages, flavor)

    return (results)

def is_pkg_vuln(vtag, vpkg, flavor, ivers, iversonly, vvers):
    isvuln = False
    #print "cve-scan: " + vpkg + "\n\tvulnerability package version: " + vvers + "\n\timage package version: " + ivers

    if vtag == 'VulnerableIn' and vvers == 'all':
        isvuln = True
    elif vvers != 'None':
        if flavor == 'RHEL':
            fixfile = vpkg + "-" + vvers + ".arch.rpm"
            imagefile = vpkg + "-" + ivers + ".arch.rpm"
            (n1, v1, r1, e1, a1) = splitFilename(imagefile)
            (n2, v2, r2, e2, a2) = splitFilename(fixfile)
            if vtag == 'FixedIn':
                if rpm.labelCompare(('1', v1, r1), ('1', v2, r2)) < 0:
                    isvuln = True
            elif vtag == 'VulnerableIn':
                if ivers == vvers or iversonly == vvers:
                    isvuln = True

        elif flavor == 'DEB':
            if vtag == 'FixedIn':
                if ivers != vvers:
                    comp_rc = dpkg_compare_versions(ivers, 'lt', vvers)
                    if comp_rc == 0:
                        isvuln = True
            elif vtag == 'VulnerableIn':
                if ivers == vvers or iversonly == vvers:
                    isvuln = True

        elif flavor == "ALPINE":
            if vtag == 'FixedIn':
                comp_rc = apkg_compare_versions(ivers, 'lt', vvers)
                if comp_rc == 0:
                    isvuln = True
            elif vtag == 'VulnerableIn':
                if ivers == vvers or iversonly == vvers:
                    isvuln = True
    else:
        isvuln = True

    return(isvuln)

def compare_package_versions(imageId, pkga, vera, pkgb, verb):
    # if ret == 0, versions are equal
    # if ret > 0, vers A is greater than version B
    # if ret < 0, vers A is less than version B

    fulla = '-'.join([str(pkga), str(vera)])
    fullb = '-'.join([str(pkgb), str(verb)])
    if fulla == fullb:
        return(0)

    distrometa = get_distro_from_imageId(imageId)
    idistro = distrometa['DISTRO']
    idistrovers = distrometa['DISTROVERS']
    ilikedistro = distrometa['LIKEDISTRO']
    distrodict = get_distro_flavor(idistro, idistrovers, likedistro=ilikedistro)
    flavor = distrodict['flavor']

    if flavor == "RHEL":
        fixfile = pkgb + "-" + verb + ".arch.rpm"
        imagefile = pkga + "-" + vera + ".arch.rpm"
        (n1, v1, r1, e1, a1) = splitFilename(imagefile)
        (n2, v2, r2, e2, a2) = splitFilename(fixfile)
        if rpm.labelCompare(('1', v1, r1), ('1', v2, r2)) < 0:
            return(-1)
        else:
            return(1)

    elif flavor == "DEB":
        comp_rc = dpkg_compare_versions(vera, 'lt', verb)
        if comp_rc == 0:
            return(-1)
        else:
            return(1)
    elif flavor == "ALPINE":
        comp_rc = apkg_compare_versions(vera, 'lt', verb)
        if comp_rc == 0:
            return(-1)
        else:
            return(1)
    else:
        raise ValueError("unsupported distro, cannot compare package versions")

    return(0)

def image_context_add(imagelist, allimages, docker_cli=None, dockerfile=None, tmproot='/tmp', anchore_db=None, docker_images=None, must_be_analyzed=False, usertype=None, must_load_all=False):
    retlist = list()
    for i in imagelist:
        if i in allimages:
            retlist.append(i)
        elif must_be_analyzed and not anchore_db.is_image_analyzed(i):
            errorstr = "Image(s) must be analyzed before operation can be performed.\n\tImage: " + str(i)
            raise Exception(errorstr)
        else:
            try:
                newimage = anchore_image.AnchoreImage(i, docker_cli=docker_cli, allimages=allimages, dockerfile=dockerfile, tmpdirroot=tmproot, usertype=usertype, anchore_db=anchore_db, docker_images=docker_images)
            except Exception as err:
                if must_load_all:
                    traceback.print_exc()
                    errorstr = "Could not load/initialize all input images.\n" + "\tImage: " + str(i) + "\n\tInfo: " + str(err.message)
                    raise Exception(errorstr)

            if not must_be_analyzed or newimage.is_analyzed():
                allimages[newimage.meta['imageId']] = newimage
                retlist.append(newimage.meta['imageId'])

            if must_be_analyzed and not newimage.is_analyzed():
                errorstr = "Image(s) must be analyzed before operation can be performed.\n\tImage: " + str(i)
                raise Exception(errorstr)

    return (retlist)


def diff_images(imageId, baseimageId):
    ret = {}

    areport = contexts['anchore_db'].load_analysis_report(imageId)
    breport = contexts['anchore_db'].load_analysis_report(baseimageId)
    
    for module_name in areport.keys():
        if module_name in breport:
            for module_value in areport[module_name].keys():
                if module_value in breport[module_name]:
                    for module_type in areport[module_name][module_value].keys():
                        output = {}

                        adata = areport[module_name][module_value][module_type]
                        try:
                            bdata = breport[module_name][module_value][module_type]
                        except:
                            for btype in breport[module_name][module_value].keys():
                                try:
                                    bdata = breport[module_name][module_value][btype]
                                    break
                                except:
                                    pass

                        if adata and bdata:
                            for akey in adata.keys():
                                if akey not in bdata:
                                    output[akey] = "INIMG_NOTINBASE"
                                elif adata[akey] != bdata[akey]:
                                    output[akey] = "VERSION_DIFF"
                            for bkey in bdata.keys():
                                if bkey not in adata:
                                    output[bkey] = "INBASE_NOTINIMG"
                            if module_name not in ret:
                                ret[module_name] = {}
                            if module_value not in ret[module_name]:
                                ret[module_name][module_value] = {}

                            ret[module_name][module_value][module_type] = output

    return(ret)

def update_file_list(listbuf, outfile, backup=False):
    src = listbuf
    if not os.path.exists(outfile):
        write_plainfile_fromlist(outfile, src)
    else:
        dst = read_plainfile_tolist(outfile)
        if src != dst:
            if backup:
                hfile = outfile + "." + str(int(time.time()))
                os.rename(outfile, hfile)

            write_plainfile_fromlist(outfile, src)

    return (True)


def update_file_jsonstr(jsonbuf, outfile, backup=False):
    src = json.loads(jsonbuf)
    if not os.path.exists(outfile):
        FH = open(outfile, 'w')
        FH.write(json.dumps(src))
        FH.close()
    else:
        FH = open(outfile, 'r')
        dst = json.loads(FH.read())
        FH.close()
        if src != dst:
            if backup:
                hfile = outfile + "." + str(int(time.time()))
                os.rename(outfile, hfile)
            FH = open(outfile, 'w')
            FH.write(json.dumps(src))
            FH.close()

    return (True)


def update_file_str(buf, outfile, backup=False):
    src = buf
    if not os.path.exists(outfile):
        write_plainfile_fromstr(outfile, src)
    else:
        dst = read_plainfile_tostr(outfile)
        if src != dst:
            if backup:
                hfile = outfile + "." + str(int(time.time()))
                os.rename(outfile, hfile)
            write_plainfile_fromstr(outfile, src)
    return (True)


def write_plainfile_fromstr(file, instr):
    FH=open(file, 'w')
    thestr = instr.encode('utf8')
    FH.write(thestr)
    FH.close()

def read_plainfile_tostr(file):
    if not os.path.isfile(file):
        return ("")
    FH = open(file, 'r')
    ret = FH.read().decode('utf8')
    FH.close()
    return (ret)


def read_kvfile_tolist(file):
    if not os.path.isfile(file):
        return([])

    ret = list()
    FH=open(file, 'r')
    for l in FH.readlines():
        l = l.strip().decode('utf8')
        if l:
            row = l.split()
            for i in range(0, len(row)):
                row[i] = re.sub("____", " ", row[i])
            ret.append(row)
    FH.close()

    return (ret)

def read_plainfile_tolist(file):
    if not os.path.isfile(file):
        return([])

    ret = list()
    FH=open(file, 'r')
    for l in FH.readlines():
        l = l.strip().decode('utf8')
        if l:
            ret.append(l)
    FH.close()

    return (ret)

def read_kvfile_todict(file):
    if not os.path.isfile(file):
        return ({})

    ret = {}
    FH = open(file, 'r')
    for l in FH.readlines():
        l = l.strip().decode('utf8')
        if l:
            (k, v) = re.match('(\S*)\s*(.*)', l).group(1, 2)
            k = re.sub("____", " ", k)
            ret[k] = v
    FH.close()

    return (ret)

def write_plainfile_fromlist(file, list):
    OFH = open(file, 'w')
    for l in list:
        thestr = l + "\n"
        thestr = thestr.encode('utf8')
        OFH.write(thestr)
    OFH.close()

def write_kvfile_fromlist(file, list, delim=' '):
    OFH = open(file, 'w')
    for l in list:
        for i in range(0,len(l)):
            l[i] = re.sub("\s", "____", l[i])
        thestr = delim.join(l) + "\n"
        thestr = thestr.encode('utf8')
        OFH.write(thestr)
    OFH.close()

def write_kvfile_fromdict(file, indict):
    dict = indict.copy()
    OFH = open(file, 'w')
    for k in dict.keys():
        if not dict[k]:
            dict[k] = "none"
        cleank = re.sub("\s+", "____", k)
        thestr = ' '.join([cleank, dict[k], '\n'])
        thestr = thestr.encode('utf8')
        OFH.write(thestr)
    OFH.close()

def touch_file(file):
    return(open(file, 'a').close())

def run_command_in_container(image=None, cmd="echo HELLO WORLD", fileget=None, fileput=None):
    if not image or not cmd:
        raise Exception("Invalid input: image="+str(image)+" cmd="+str(cmd))

    try:
        imageId = discover_imageId(image)
    except Exception as err:
        print str(err)
        return(list())

    olines = list()
    fbuf = ""

    try:
        docker_cli = contexts['docker_cli']
        
        container = docker_cli.create_container(image=image, command="/bin/bash -c '"+cmd+"'", tty=False)

        docker_cli.create_container(image=image, command="/bin/bash -c '"+cmd+"'", tty=False)
        if fileput:
            try:
                TFH=open(fileput, 'r')
                dat = TFH.read()
                TFH.close()
                docker_cli.put_archive(container.get('Id'), "/", dat)
            except Exception as err:
                traceback.print_exc()
                print str(err)
                pass
        response = docker_cli.start(container=container.get('Id'))
        output = docker_cli.logs(container=container.get('Id'), stdout=True, stderr=True, stream=True)
        for l in output:
            olines.append(l)

        if fileget:
            try:
                tstream,stat = docker_cli.get_archive(container, fileget)
                TFH = io.BytesIO(tstream.data)
                tar=tarfile.open(fileobj=TFH, mode='r', format=tarfile.PAX_FORMAT)
                for member in tar.getmembers():
                    fbuf = tar.extractfile(member).read()
                tar.close()
                TFH.close()
            except Exception as err:
                fbuf = ""
                pass

    except Exception as err:
        raise err
    finally:
        try:
            docker_cli.remove_container(container=container.get('Id'), force=True)
        except:
            pass

    return(olines, fbuf)

def get_files_from_tarfile(intarfile):
    allfiles = {}

    try:
        tar = tarfile.open(intarfile)
        for member in tar.getmembers():
            finfo = {}
            finfo['name'] = re.sub("^\./", "/", member.name.decode('utf8'))
            finfo['fullpath'] = os.path.normpath(finfo['name'])
            finfo['size'] = member.size
            finfo['mode'] = member.mode

            finfo['linkdst'] = None
            if member.isfile():
                finfo['type'] = 'file'
            elif member.isdir():
                finfo['type'] = 'dir'
            elif member.issym():
                finfo['type'] = 'slink'
                finfo['linkdst'] = re.sub("^\./", "/", member.linkname.decode('utf8'))
            elif member.islnk():
                finfo['type'] = 'hlink'
                finfo['linkdst'] = re.sub("^\./", "/", member.linkname.decode('utf8'))
            elif member.isdev():
                finfo['type'] = 'dev'
            else:
                finfo['type'] = 'UNKNOWN'

            if finfo['type'] == 'slink' or finfo['type'] == 'hlink':
                if re.match("^/", finfo['linkdst']):
                    fullpath = finfo['linkdst']
                else:
                    dstlist = finfo['linkdst'].split('/')
                    srclist = finfo['name'].split('/')
                    srcpath = srclist[0:-1]
                    fullpath = '/'.join(srcpath + dstlist)
                    fullpath = os.path.normpath('/'.join(srcpath + dstlist))
                finfo['fullpath'] = fullpath

            allfiles[finfo['name']] = finfo

        tar.close()
    except:
        pass

    return(allfiles)

def get_files_from_path(inpath):
    filemap = {}
    allfiles = {}
    real_root = os.open('/', os.O_RDONLY)

    try:
        os.chroot(inpath)
        #for root, dirs, files in os.walk('/', followlinks=True):
        for root, dirs, files in os.walk('/', followlinks=False):
            for name in dirs + files:
                filename = os.path.join(root, name).decode('utf8')
                osfilename = os.path.join(root, name)

                fstat = os.lstat(osfilename)

                finfo = {}
                finfo['name'] = filename
                finfo['fullpath'] = os.path.normpath(osfilename)
                finfo['size'] = fstat.st_size
                finfo['mode'] = fstat.st_mode
                finfo['uid'] = fstat.st_uid
                finfo['gid'] = fstat.st_gid
                
                mode = finfo['mode']
                finfo['linkdst'] = None
                finfo['linkdst_fullpath'] = None
                if S_ISREG(mode):
                    finfo['type'] = 'file'
                elif S_ISDIR(mode):
                    finfo['type'] = 'dir'
                elif S_ISLNK(mode):
                    finfo['type'] = 'slink'
                    finfo['linkdst'] = os.readlink(osfilename)
                elif S_ISCHR(mode) or S_ISBLK(mode):
                    finfo['type'] = 'dev'
                else:
                    finfo['type'] = 'UNKNOWN'

                if finfo['type'] == 'slink' or finfo['type'] == 'hlink':
                    if re.match("^/", finfo['linkdst']):
                        fullpath = finfo['linkdst']
                    else:
                        dstlist = finfo['linkdst'].split('/')
                        srclist = finfo['name'].split('/')
                        srcpath = srclist[0:-1]
                        fullpath = os.path.normpath(os.path.join(finfo['linkdst'], osfilename))
                    finfo['linkdst_fullpath'] = fullpath

                fullpath = os.path.realpath(osfilename)

                finfo['othernames'] = {}
                for f in [fullpath, finfo['linkdst_fullpath'], finfo['linkdst'], finfo['name']]:
                    if f:
                        finfo['othernames'][f] = True

                allfiles[finfo['name']] = finfo

        # first pass, set up the basic file map
        for name in allfiles.keys():
            finfo = allfiles[name]
            finfo['othernames'][name] = True

            filemap[name] = finfo['othernames']
            for oname in finfo['othernames']:
                filemap[oname] = finfo['othernames']

        # second pass, include second order
        newfmap = {}
        count = 0
        while newfmap != filemap or count > 5:
            count += 1
            filemap.update(newfmap)
            newfmap.update(filemap)
            for mname in newfmap.keys():
                for oname in newfmap[mname].keys():
                    newfmap[oname].update(newfmap[mname])

    except Exception as err:
        traceback.print_exc()
        print str(err)
        pass
    finally:
        os.fchdir(real_root)
        os.chroot('.')

    return(filemap, allfiles)

def grouper(inlist, chunksize):
    return (inlist[pos:pos + chunksize] for pos in xrange(0, len(inlist), chunksize))

def run_command(command):
    rc = 1
    sout = ""

    try:
        _logger.debug("running command: " + str(command))
        sout = subprocess.check_output(command, stderr=subprocess.STDOUT)
        sout = sout.decode('utf8')
        rc = 0
    except subprocess.CalledProcessError as err:
        sout = err.output.decode('utf8')
        rc = err.returncode
    except Exception as err:
        sout = str(err)
        rc = 1
    _logger.debug("command complete: " + str(command))

    return(rc, sout, ' '.join(command))

# this function attempts to get *ALL* known information about an image and normalize
def get_all_image_info(instr, do_verify=False, docker_cli=None):
    ret = {
        'imageId': None,
        'tags': [],
        'tag': None,
        'digests': [],
        'digest': None,
        'registry': None,
        'repo': None,
        'fulltag': None,
        'fulldigest': None,
        'pullstring': None,
        'local_docker_tags': [],
    }

    image_info = parse_dockerimage_string(instr)
    for k in image_info:
        if image_info[k] and k in ret:
            ret[k] = image_info[k]
    
    inspect_string = None
    ddata = {}
    for i in [instr, 'imageId', 'fulldigest', 'fulltag']:
        if i in ret and ret[i]:
            inspect_string = ret[i]
        else:
            inspect_string = i
            
        if not docker_cli:
            cli = contexts['docker_cli']
            try:
                ddata = cli.inspect_image(inspect_string)
            except:
                pass
        if ddata:
            break


    # find the best (latest) docker inspect data for the image
    if ddata:
        try:
            if 'RepoTags' in ddata:
                ret['local_docker_tags'] = ddata['RepoTags']

            if 'RepoDigests' in ddata and not ddata['RepoDigests']:
                # this is a local build case
                ret['registry'] = 'localbuild'
                ret['fulltag'] = ret['repo'] + ":" + ret['tag']
                ret['pullstring'] = None
        except Exception as err:
            pass

    if not ddata and ret['imageId']:
        image_report = load_image_report(ret['imageId'])
        ddata = image_report['docker_data']

    if 'Id' in ddata:
        if not ret['imageId']:
            ret['imageId'] = re.sub("^sha256:", "", ddata['Id'])        

    if 'RepoDigests' in ddata:
        ret['digests'] = ddata['RepoDigests']

    if 'RepoTags' in ddata:
        ret['tags'] = ddata['RepoTags']

    for d in ret['digests']:
        dinfo = parse_dockerimage_string(d)
        for t in ret['tags']:
            tinfo = parse_dockerimage_string(t)
            if dinfo['registry'] == tinfo['registry'] and dinfo['repo'] == tinfo['repo']:
                regmatch = dinfo['registry']
                repomatch = dinfo['repo']
                break
            else:
                regmatch = dinfo['registry']
                repomatch = dinfo['repo']

    if not ret['registry'] and not ret['repo'] and regmatch and repomatch:
        ret['registry'] = regmatch
        ret['repo'] = repomatch
        
    if not ret['tag']:
        for tag in ddata['RepoTags']:
            sub_image_info = parse_dockerimage_string(tag)
            sreg = sub_image_info['registry']
            srepo = sub_image_info['repo']
            stag = sub_image_info['tag']
            if ret['registry'] == sreg and ret['repo'] == srepo:
                ret['tag'] = stag
                ret['fulltag'] = tag

    if not ret['digest']:
        for digest in ret['digests']:
            patt = re.match("(.*)/(.*)@(.*)", digest)
            if patt:
                dreg = patt.group(1)
                drepo = patt.group(2)
                ddig = patt.group(3)
                if ret['registry'] == dreg and ret['repo'] == drepo:
                    ret['digest'] = ddig
                    ret['fulldigest'] = digest
                    break

    if not ret['pullstring'] and ret['registry'] != 'localbuild':
        if ret['fulldigest']:
            ret['pullstring'] = ret['fulldigest']
        elif ret['fulltag']:
            ret['pullstring'] = ret['fulltag']

    if do_verify:
        # verify the result:
        verified = True
        for k in ret.keys():
            if k != 'local_docker_tags' and not ret[k]:
                verified = False
                break

        if not verified:
            _logger.warn("image cannot be normalized: " + json.dumps(ret, indent=4))
            ret = {}

    return(ret)
    

def parse_dockerimage_string(instr):
    host = None
    port = None
    repo = None
    tag = None
    registry = None
    repotag = None
    fulltag = None
    fulldigest = None
    digest = None
    imageId = None

    if len(instr) == 64 and not re.findall("[^0-9a-fA-F]+",instr):
        imageId = instr
    else:

        # get the host/port
        patt = re.match("(.*?)/(.*)", instr)
        if patt:
            a = patt.group(1)
            remain = patt.group(2)
            patt = re.match("(.*?):(.*)", a)
            if patt:
                host = patt.group(1)
                port = patt.group(2)
            elif a == 'docker.io':
                host = 'docker.io'
                port = None
            elif a == '*':
                host = '*'
                port = None
            elif a in ['localhost', 'localhost.localdomain', 'localbuild']:
                host = a
                port = None
            else:
                patt = re.match(".*\..*", a)
                if patt:
                    host = a
                else:
                    host = 'docker.io'
                    remain = instr
                port = None

        else:
            host = 'docker.io'
            port = None
            remain = instr

        # get the repo/tag
        patt = re.match("(.*)@(.*)", remain)
        if patt:
            repo = patt.group(1)
            digest = patt.group(2)        
        else:
            patt = re.match("(.*):(.*)", remain)
            if patt:
                repo = patt.group(1)
                tag = patt.group(2)
            else:
                repo = remain
                tag = "latest"

        if not tag:
            tag = "latest"

        if port:
            registry = ':'.join([host, port])
        else:
            registry = host

        if digest:
            repotag = '@'.join([repo, digest])
        else:
            repotag = ':'.join([repo, tag])

        fulltag = '/'.join([registry, repotag])

        if not digest:
            digest = None
        else:
            fulldigest = registry + '/' + repo + '@' + digest
            tag = None
            fulltag = None
            repotag = None

    ret = {}
    ret['host'] = host
    ret['port'] = port
    ret['repo'] = repo
    ret['tag'] = tag
    ret['registry'] = registry
    ret['repotag'] = repotag
    ret['fulltag'] = fulltag
    ret['digest'] = digest
    ret['fulldigest'] = fulldigest
    ret['imageId'] = imageId

    if ret['fulldigest']:
        ret['pullstring'] = ret['fulldigest']
    elif ret['fulltag']:
        ret['pullstring'] = ret['fulltag']
    else:
        ret['pullstring'] = None


    return(ret)
