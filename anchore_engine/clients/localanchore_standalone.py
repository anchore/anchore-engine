import os
import re
import sys
import json
import uuid
import time
import shutil
import struct
import tarfile
import logging
from pkg_resources import resource_filename

import anchore_engine.services.common
import anchore_engine.auth.common
import anchore_engine.auth.skopeo_wrapper
from anchore.anchore_utils import read_kvfile_todict

try:
    from anchore_engine.subsys import logger
    # Separate logger for use during bootstrap when logging may not be fully configured
    from twisted.python import log
except:
    import logging
    logger = logging.getLogger(__name__)
    logger.setLevel("DEBUG")
    log = logger

def get_layertarfile(unpackdir, cachedir, layer):

    layer_candidates = [os.path.join(unpackdir, 'raw', layer+".tar"), os.path.join(unpackdir, 'raw', 'blobs', 'sha256', layer)]
    if cachedir:
        layer_candidates.append(os.path.join(cachedir, 'sha256', layer))
        
    layerfound = False
    for layer_candidate in layer_candidates:
        try:
            if os.path.exists(layer_candidate):
                try:
                    # try to update atime for the file
                    os.utime(layer_candidate, None)
                except:
                    pass
                return(layer_candidate)
        except:
            pass

    return(None)

def handle_tar_error(tarcmd, rc, sout, serr, unpackdir, rootfsdir, layer, layertar):
    handled = False

    try:
        slinkre = "tar: (.*): Cannot open: File exists"
        for errline in serr.splitlines():
            patt = re.match(slinkre, errline)
            if patt:
                matchfile = patt.group(1)
                logger.debug("found 'file exists' error on name: " + str(matchfile))
                if matchfile:
                    badfile = os.path.join(rootfsdir, patt.group(1))
                    if os.path.exists(badfile):
                        logger.debug("removing hierarchy: " + str(badfile))
                        shutil.rmtree(badfile)
                        handled = True

    except Exception as err:
        raise err

    return(handled)

def squash(unpackdir, cachedir, layers):
    rootfsdir = unpackdir + "/rootfs"

    if os.path.exists(unpackdir + "/squashed.tar"):
        return (True)

    if not os.path.exists(rootfsdir):
        os.makedirs(rootfsdir)

    revlayer = list(layers)
    revlayer.reverse()

    l_excludes = {}
    l_opqexcludes = {} # stores list of special files to exclude only for next layer (.wh..wh..opq handling)

    last_opqexcludes = {} # opq exlcudes for the last layer

    for l in revlayer:
        htype, layer = l.split(":",1)

        layertar = get_layertarfile(unpackdir, cachedir, layer)

        count = 0

        logger.debug("\tPass 1: " + str(layertar))
        layertarfile = tarfile.open(layertar, mode='r', format=tarfile.PAX_FORMAT)

        whpatt = re.compile(".*/\.wh\..*")
        whopqpatt = re.compile(".*/\.wh\.\.wh\.\.opq")

        l_opqexcludes[layer] = {}

        myexcludes = {}
        opqexcludes = {}

        for member in layertarfile.getmembers():
            # checks for whiteout conditions
            if whopqpatt.match(member.name):
                # found an opq entry, which means that this files in the next layer down (only) should not be included

                fsub = re.sub(r"\.wh\.\.wh\.\.opq", "", member.name, 1)

                # never include the whiteout file itself
                myexcludes[member.name] = True
                opqexcludes[fsub] = True

            elif whpatt.match(member.name):
                # found a normal whiteout, which means that this file in any lower layer should be excluded
                fsub = re.sub(r"\.wh\.", "", member.name, 1)

                # never include a whiteout file
                myexcludes[member.name] = True

                myexcludes[fsub] = True

            else:
                # if the last processed layer had an opq whiteout, check file to see if it lives in the opq directory
                if last_opqexcludes:
                    dtoks = member.name.split("/")
                    for i in range(0, len(dtoks)):
                        dtok = '/'.join(dtoks[0:i])
                        dtokwtrail = '/'.join(dtoks[0:i]) + "/"
                        if dtok in last_opqexcludes or dtokwtrail in last_opqexcludes:
                            l_opqexcludes[layer][member.name] = True
                            break

        # build up the list of excludes as we move down the layers
        for l in l_excludes.keys():
            myexcludes.update(l_excludes[l])

        l_excludes[layer] = myexcludes

        #last_opqexcludes = opqexcludes
        last_opqexcludes.update(opqexcludes)
        layertarfile.close()
        
    logger.debug("Pass 3: untarring layers with exclusions")

    imageSize = 0
    for l in layers:
        htype, layer = l.split(":",1)

        layertar = get_layertarfile(unpackdir, cachedir, layer)

        imageSize = imageSize + os.path.getsize(layertar) 
        
        # write out the exluded files, adding the per-layer excludes if present
        with open(unpackdir+"/efile", 'w') as OFH:
            for efile in l_excludes[layer]:
                OFH.write("%s\n" % efile)
            if layer in l_opqexcludes and l_opqexcludes[layer]:
                for efile in l_opqexcludes[layer]:
                    logger.debug("adding special for layer exclude: " + str(efile))
                    OFH.write("%s\n" % efile)

        retry = True
        success = False
        last_err = None
        max_retries = 10
        retries = 0
        while (not success) and (retry):
            tarcmd = "tar -C " + rootfsdir + " -x -X " + unpackdir+"/efile -f " + layertar
            logger.debug("untarring squashed tarball: " + str(tarcmd))
            try:
                rc, sout, serr = anchore_engine.services.common.run_command(tarcmd)
                if rc != 0:
                    logger.debug("tar error encountered, attempting to handle")
                    handled = handle_tar_error(tarcmd, rc, sout, serr, unpackdir=unpackdir, rootfsdir=rootfsdir, layer=layer, layertar=layertar)
                    if not handled:
                        raise Exception("command failed: cmd="+str(tarcmd)+" exitcode="+str(rc)+" stdout="+str(sout).strip()+" stderr="+str(serr).strip())
                    else:
                        logger.debug("tar error successfully handled, retrying")
                else:
                    logger.debug("command succeeded: stdout="+str(sout).strip()+" stderr="+str(serr).strip())
                    success = True
            except Exception as err:
                logger.error("command failed with exception - " + str(err))
                last_err = err
                success = False
                retry = False
                
            # safety net
            if retries > max_retries:
                retry = False
            retries = retries + 1

        if not success:
            if last_err:
                raise last_err
            else:
                raise Exception("unknown exception in untar")

    return ("done", imageSize)

def squash_backup(unpackdir, cachedir, layers):
    rootfsdir = unpackdir + "/rootfs"

    if os.path.exists(unpackdir + "/squashed.tar"):
        return (True)

    if not os.path.exists(rootfsdir):
        os.makedirs(rootfsdir)

    revlayer = list(layers)
    revlayer.reverse()

    l_excludes = {}
    l_opqexcludes = {} # stores list of special files to exclude only for next layer (.wh..wh..opq handling)

    last_opqexcludes = {} # opq exlcudes for the last layer

    for l in revlayer:
        htype, layer = l.split(":",1)

        layertar = get_layertarfile(unpackdir, cachedir, layer)

        count = 0

        logger.debug("\tPass 1: " + str(layertar))
        layertarfile = tarfile.open(layertar, mode='r', format=tarfile.PAX_FORMAT)

        whpatt = re.compile(".*/\.wh\..*")
        whopqpatt = re.compile(".*/\.wh\.\.wh\.\.opq")

        l_opqexcludes[layer] = {}

        myexcludes = {}
        opqexcludes = {}

        for member in layertarfile.getmembers():
            # checks for whiteout conditions
            if whopqpatt.match(member.name):
                # found an opq entry, which means that this files in the next layer down (only) should not be included

                fsub = re.sub(r"\.wh\.\.wh\.\.opq", "", member.name, 1)

                # never include the whiteout file itself
                myexcludes[member.name] = True
                opqexcludes[fsub] = True

            elif whpatt.match(member.name):
                # found a normal whiteout, which means that this file in any lower layer should be excluded
                fsub = re.sub(r"\.wh\.", "", member.name, 1)

                # never include a whiteout file
                myexcludes[member.name] = True

                myexcludes[fsub] = True

            else:
                # if the last processed layer had an opq whiteout, check file to see if it lives in the opq directory
                if last_opqexcludes:
                    dtoks = member.name.split("/")
                    for i in range(0, len(dtoks)):
                        dtok = '/'.join(dtoks[0:i])
                        dtokwtrail = '/'.join(dtoks[0:i]) + "/"
                        if dtok in last_opqexcludes or dtokwtrail in last_opqexcludes:
                            l_opqexcludes[layer][member.name] = True
                            break

        # build up the list of excludes as we move down the layers
        for l in l_excludes.keys():
            myexcludes.update(l_excludes[l])

        l_excludes[layer] = myexcludes

        #last_opqexcludes = opqexcludes
        last_opqexcludes.update(opqexcludes)
        layertarfile.close()
        
    logger.debug("Pass 3: untarring layers with exclusions")

    imageSize = 0
    for l in layers:
        htype, layer = l.split(":",1)

        layertar = get_layertarfile(unpackdir, cachedir, layer)

        imageSize = imageSize + os.path.getsize(layertar) 
        
        # write out the exluded files, adding the per-layer excludes if present
        with open(unpackdir+"/efile", 'w') as OFH:
            for efile in l_excludes[layer]:
                OFH.write("%s\n" % efile)
            if layer in l_opqexcludes and l_opqexcludes[layer]:
                for efile in l_opqexcludes[layer]:
                    logger.debug("adding special for layer exclude: " + str(efile))
                    OFH.write("%s\n" % efile)

        tarcmd = "tar -C " + rootfsdir + " -x -X " + unpackdir+"/efile -f " + layertar
        logger.debug("untarring squashed tarball: " + str(tarcmd))

        try:
            rc, sout, serr = anchore_engine.services.common.run_command(tarcmd)
            if rc != 0:
                raise Exception("command failed: cmd="+str(tarcmd)+" exitcode="+str(rc)+" stdout="+str(sout).strip()+" stderr="+str(serr).strip())
            else:
                logger.debug("command succeeded: stdout="+str(sout).strip()+" stderr="+str(serr).strip())
        except Exception as err:
            logger.error("command failed with exception - " + str(err))
            raise err

    return ("done", imageSize)

def make_staging_dirs(rootdir, use_cache_dir=None):
    if not os.path.exists(rootdir):
        raise Exception("passed in root directory must exist ("+str(rootdir)+")")

    rando = str(uuid.uuid4())
    ret = {
        'unpackdir': os.path.join(rootdir, rando),
        'copydir': os.path.join(rootdir, rando, "raw"),
        'rootfs': os.path.join(rootdir, rando, "rootfs"),
        'outputdir': os.path.join(rootdir, rando, "output"),
        'cachedir': use_cache_dir
    }

    for k in ret.keys():
        if not ret[k]:
            continue

        try:
            if not os.path.exists(ret[k]):
                logger.debug("making dir: " + k + " : " + str(ret[k]))
                os.makedirs(ret[k])
        except Exception as err:
            raise Exception("unable to prep staging directory - exception: " + str(err))

    return(ret)

def delete_staging_dirs(staging_dirs):
    for k in staging_dirs.keys():
        if k == 'cachedir':
            continue

        try:
            if os.path.exists(staging_dirs[k]):
                logger.debug("removing dir: " + k + " : " + str(staging_dirs[k]))
                shutil.rmtree(staging_dirs[k])
        except Exception as err:
            raise Exception("unable to delete staging directory - exception: " + str(err))

    return(True)

def pull_image(staging_dirs, pullstring, registry_creds=[], manifest=None, dest_type='oci'):
    outputdir = staging_dirs['outputdir']
    unpackdir = staging_dirs['unpackdir']
    copydir = staging_dirs['copydir']
    cachedir = staging_dirs['cachedir']

    user = pw = None
    registry_verify = False

    # extract user/pw/verify from registry_creds
    try:
        if registry_creds:
            image_info = anchore_engine.services.common.get_image_info(None, 'docker', pullstring, registry_lookup=False)
            user, pw, registry_verify = anchore_engine.auth.common.get_creds_by_registry(image_info['registry'], registry_creds=registry_creds)
    except Exception as err:
        raise err

    # download
    try:
        rc = anchore_engine.auth.skopeo_wrapper.download_image(pullstring, copydir, user=user, pw=pw, verify=registry_verify, manifest=manifest, use_cache_dir=cachedir, dest_type=dest_type)
    except Exception as err:
        raise err

    return(True)

def get_image_metadata_v1(staging_dirs, imageDigest, imageId, manifest_data, dockerfile_contents="", dockerfile_mode=""):
    outputdir = staging_dirs['outputdir']
    unpackdir = staging_dirs['unpackdir']
    copydir = staging_dirs['copydir']

    docker_history = []
    layers = []
    dockerfile_mode = "Guessed"
    dockerfile_contents = dockerfile_contents
    imageArch = ""

    try:
        imageArch = manifest_data['architecture']
    except:
        imageArch = ""

    try:
        for fslayer in manifest_data['fsLayers']:
            layers.append(fslayer['blobSum'])
    except Exception as err:
        logger.error("cannot get layers - exception: " + str(err))
        raise err
    
    try:
        hfinal = []
        count=0
        for rawhel in manifest_data['history']:
            hel = json.loads(rawhel['v1Compatibility'])
            try:
                lsize = hel['Size']
            except:
                lsize = 0
            
            if hel['container_config']['Cmd']:
                lcreatedby = ' '.join(hel['container_config']['Cmd'])
            else:
                lcreatedby = ""
            
            lcreated = hel['created']
            lid = layers[count]
            count = count + 1
            hfinal.append(
                {
                    'Created': lcreated,
                    'CreatedBy': lcreatedby,
                    'Comment': '',
                    'Id': lid,
                    'Size': lsize,
                    'Tags': []
                }
            )

        docker_history = hfinal
        if hfinal:
            with open(os.path.join(unpackdir, "docker_history.json"), 'w') as OFH:
                OFH.write(json.dumps(hfinal))
    except Exception as err:
        logger.error("cannot construct history - exception: " + str(err))
        raise err

    if not dockerfile_contents:
        # get dockerfile_contents (translate history to guessed DF)
        # TODO 'FROM' guess?
        dockerfile_contents = "FROM scratch\n"
        for hel in docker_history:
            patt = re.match("^/bin/sh -c #\(nop\) +(.*)", hel['CreatedBy'])
            if patt:
                cmd = patt.group(1)
            elif hel['CreatedBy']:
                cmd = "RUN " + hel['CreatedBy']
            else:
                cmd = None
            if cmd:
                dockerfile_contents = dockerfile_contents + cmd + "\n"        
        dockerfile_mode = "Guessed"
    elif not dockerfile_mode:
        dockerfile_mode = "Actual"

    layers.reverse()

    return(docker_history, layers, dockerfile_contents, dockerfile_mode, imageArch)

def get_image_metadata_v2_orig(staging_dirs, imageDigest, imageId, manifest_data, dockerfile_contents="", dockerfile_mode=""):
    outputdir = staging_dirs['outputdir']
    unpackdir = staging_dirs['unpackdir']
    copydir = staging_dirs['copydir']

    rawlayers = manifest_data['layers']

    hfinal = []
    layers = []
    docker_history = []
    imageArch = ""

    # get "history"    
    try:
        with open(os.path.join(copydir, imageId+".tar"), 'r') as FH:
            configdata = json.loads(FH.read())
            rawhistory = configdata['history']
            imageArch = configdata['architecture']
    except Exception as err:
        raise err

    try:
        done=False
        idx = 0
        while not done:
            if not rawhistory:
                done = True
            else:
                hel = rawhistory.pop(0)
                if 'empty_layer' in hel and hel['empty_layer']:
                    lid = "<missing>"
                    lsize = 0
                else:
                    lel = rawlayers.pop(0)
                    lid = lel['digest']
                    layers.append(lid)
                    lsize = lel['size']

                try:
                    lcreatedby = hel['created_by']
                except:
                    lcreatedby = ""

                lcreated = hel['created']

                hfinal.append(
                    {
                        'Created': lcreated,
                        'CreatedBy': lcreatedby,
                        'Comment': '',
                        'Id': lid,
                        'Size': lsize,
                        'Tags': []
                    }
                )

        docker_history = hfinal
        if hfinal:
            with open(os.path.join(unpackdir, "docker_history.json"), 'w') as OFH:
                OFH.write(json.dumps(hfinal))
    except Exception as err:
        raise err

    if not dockerfile_contents:
        # get dockerfile_contents (translate history to guessed DF)
        # TODO 'FROM' guess?
        dockerfile_contents = "FROM scratch\n"
        for hel in docker_history:
            patt = re.match("^/bin/sh -c #\(nop\) +(.*)", hel['CreatedBy'])
            if patt:
                cmd = patt.group(1)
            elif hel['CreatedBy']:
                cmd = "RUN " + hel['CreatedBy']
            else:
                cmd = None
            if cmd:
                dockerfile_contents = dockerfile_contents + cmd + "\n"        
        dockerfile_mode = "Guessed"
    elif not dockerfile_mode:
        dockerfile_mode = "Actual"

    return(docker_history, layers, dockerfile_contents, dockerfile_mode, imageArch)

def get_image_metadata_v2(staging_dirs, imageDigest, imageId, manifest_data, dockerfile_contents="", dockerfile_mode=""):
    outputdir = staging_dirs['outputdir']
    unpackdir = staging_dirs['unpackdir']
    copydir = staging_dirs['copydir']
    cachedir = staging_dirs['cachedir']

    rawlayers = manifest_data['layers']

    hfinal = []
    layers = []
    docker_history = []
    imageArch = ""

    # get "history"    
    if os.path.exists(os.path.join(copydir, imageId+".tar")):
        try:
            with open(os.path.join(copydir, imageId+".tar"), 'r') as FH:
                configdata = json.loads(FH.read())
                rawhistory = configdata['history']
                imageArch = configdata['architecture']
        except Exception as err:
            raise err
    elif os.path.exists(os.path.join(copydir, "index.json")):
        try:
            blobdir = os.path.join(copydir, 'blobs', 'sha256')
            if cachedir:
                blobdir = os.path.join(cachedir, 'sha256')

            dfile = nfile = None
            with open(os.path.join(copydir, "index.json"), 'r') as FH:
                idata = json.loads(FH.read())
                d_digest = idata['manifests'][0]['digest'].split(":", 1)[1]
                dfile = os.path.join(blobdir, d_digest)

            if dfile:
                with open(dfile, 'r') as FH:
                    n_data = json.loads(FH.read())
                    n_digest = n_data['config']['digest'].split(":", 1)[1]
                    nfile = os.path.join(blobdir, n_digest)
            else:
                raise Exception("could not find intermediate digest - exception: " + str(err))

            if nfile:
                with open(nfile, 'r') as FH:
                    configdata = json.loads(FH.read())
                    rawhistory = configdata['history']
                    imageArch = configdata['architecture']
            else:
                raise Exception("could not find final digest - exception: " + str(err))

        except Exception as err:
            raise err

    try:
        done=False
        idx = 0
        while not done:
            if not rawhistory:
                done = True
            else:
                hel = rawhistory.pop(0)
                if 'empty_layer' in hel and hel['empty_layer']:
                    lid = "<missing>"
                    lsize = 0
                else:
                    lel = rawlayers.pop(0)
                    lid = lel['digest']
                    layers.append(lid)
                    lsize = lel['size']

                try:
                    lcreatedby = hel['created_by']
                except:
                    lcreatedby = ""

                lcreated = hel['created']

                hfinal.append(
                    {
                        'Created': lcreated,
                        'CreatedBy': lcreatedby,
                        'Comment': '',
                        'Id': lid,
                        'Size': lsize,
                        'Tags': []
                    }
                )

        docker_history = hfinal
        if hfinal:
            with open(os.path.join(unpackdir, "docker_history.json"), 'w') as OFH:
                OFH.write(json.dumps(hfinal))
    except Exception as err:
        raise err

    if not dockerfile_contents:
        # get dockerfile_contents (translate history to guessed DF)
        # TODO 'FROM' guess?
        dockerfile_contents = "FROM scratch\n"
        for hel in docker_history:
            patt = re.match("^/bin/sh -c #\(nop\) +(.*)", hel['CreatedBy'])
            if patt:
                cmd = patt.group(1)
            elif hel['CreatedBy']:
                cmd = "RUN " + hel['CreatedBy']
            else:
                cmd = None
            if cmd:
                dockerfile_contents = dockerfile_contents + cmd + "\n"        
        dockerfile_mode = "Guessed"
    elif not dockerfile_mode:
        dockerfile_mode = "Actual"

    return(docker_history, layers, dockerfile_contents, dockerfile_mode, imageArch)

def unpack(staging_dirs, layers):
    outputdir = staging_dirs['outputdir']
    unpackdir = staging_dirs['unpackdir']
    copydir = staging_dirs['copydir']
    cachedir = staging_dirs['cachedir']

    try:
        squashtar, imageSize = squash(unpackdir, cachedir, layers)
    except Exception as err:
        raise err
    return(imageSize)


def run_anchore_analyzers(staging_dirs, imageDigest, imageId):
    outputdir = staging_dirs['outputdir']
    unpackdir = staging_dirs['unpackdir']
    copydir = staging_dirs['copydir']

    # run analyzers
    anchore_module_root = resource_filename("anchore", "anchore-modules")
    analyzer_root = os.path.join(anchore_module_root, "analyzers")
    for f in os.listdir(analyzer_root):
        thecmd = os.path.join(analyzer_root, f)
        if re.match(".*\.py$", thecmd):
            cmdstr = " ".join([thecmd, imageId, unpackdir, outputdir, unpackdir])
            if True:
                try:
                    rc, sout, serr = anchore_engine.services.common.run_command(cmdstr)
                    if rc != 0:
                        raise Exception("command failed: cmd="+str(cmdstr)+" exitcode="+str(rc)+" stdout="+str(sout).strip()+" stderr="+str(serr).strip())
                    else:
                        logger.debug("command succeeded: cmd="+str(cmdstr)+" stdout="+str(sout).strip()+" stderr="+str(serr).strip())
                except Exception as err:
                    logger.error("command failed with exception - " + str(err))
                    #raise err

    analyzer_manifest = {}
    #TODO populate analyzer_manifest?
    analyzer_report = {}
    for analyzer_output in os.listdir(os.path.join(outputdir, "analyzer_output")):
        if analyzer_output not in analyzer_report:
            analyzer_report[analyzer_output] = {}

        for analyzer_output_el in os.listdir(os.path.join(outputdir, "analyzer_output", analyzer_output)):
            if analyzer_output_el not in analyzer_report[analyzer_output]:
                analyzer_report[analyzer_output][analyzer_output_el] = {'base': {}}

            data = read_kvfile_todict(os.path.join(outputdir, "analyzer_output", analyzer_output, analyzer_output_el))
            if data:
                analyzer_report[analyzer_output][analyzer_output_el]['base'] = read_kvfile_todict(os.path.join(outputdir, "analyzer_output", analyzer_output, analyzer_output_el))
            else:
                analyzer_report[analyzer_output].pop(analyzer_output_el, None)

        if not analyzer_report[analyzer_output]:
            analyzer_report.pop(analyzer_output, None)

    return(analyzer_report)

def generate_image_export(staging_dirs, imageDigest, imageId, analyzer_report, imageSize, fulltag, docker_history, dockerfile_mode, dockerfile_contents, layers, familytree, imageArch, rdigest, analyzer_manifest):
    image_report = []
    image_report.append(
        {
            'image': 
            {
                'imageId': imageId,
                'imagedata':
                {
                    'analyzer_manifest': analyzer_manifest,
                    'analysis_report': analyzer_report,
                    'image_report': {
                        'meta': {
                            'shortparentId': '', 
                            'sizebytes': imageSize, 
                            'imageId': imageId,
                            'usertype': None, 
                            'shortId': imageId[0:12], 
                            'imagename': imageId, 
                            'parentId': '', 
                            'shortname': imageId[0:12], 
                            'humanname': fulltag
                        },
                        'docker_history': docker_history,
                        'dockerfile_mode': dockerfile_mode,
                        'dockerfile_contents': dockerfile_contents,
                        'layers': layers,
                        'familytree': familytree,
                        'docker_data': {
                            'Architecture': imageArch,
                            'RepoDigests': [rdigest],
                            'RepoTags': [fulltag]
                        }
                    }
                }
            }
        }
    )
    return(image_report)
    
def analyze_image(userId, manifest, image_record, tmprootdir, registry_creds=[], use_cache_dir=None):
    # need all this

    imageId = None
    imageDigest = None
    layers = []
    rawlayers = []
    familytree = []
    imageSize = 0
    analyzer_manifest = {}
    analyzer_report = {}
    imageArch = ""
    dockerfile_mode = ""
    docker_history = {}
    rdigest = ""
    staging_dirs = None
    manifest_schema_version = 0
    dest_type = 'oci'

    try:
        imageDigest = image_record['imageDigest']
        try:
            manifest_data = json.loads(manifest)
            manifest_schema_version = manifest_data['schemaVersion']
            if manifest_schema_version == 1:
                dest_type = 'dir'
            else:
                dest_type = 'oci'

        except Exception as err:
            raise Exception("cannot load manifest as JSON rawmanifest="+str(manifest)+") - exception: " + str(err))

        if image_record['dockerfile_mode']:
            dockerfile_mode = image_record['dockerfile_mode']

        image_detail = image_record['image_detail'][0]
        pullstring = image_detail['registry'] + "/" + image_detail['repo'] + "@" + image_detail['imageDigest']
        fulltag = image_detail['registry'] + "/" + image_detail['repo'] + ":" + image_detail['tag']
        imageId = image_detail['imageId']
        if image_detail['dockerfile']:
            dockerfile_contents = image_detail['dockerfile'].decode('base64')
        else:
            dockerfile_contents = None

        try:
            staging_dirs = make_staging_dirs(tmprootdir, use_cache_dir=use_cache_dir)
        except Exception as err:
            raise err

        try:
            rc = pull_image(staging_dirs, pullstring, registry_creds=registry_creds, manifest=manifest, dest_type=dest_type)
        except Exception as err:
            raise Exception("failed to pull image ("+str(pullstring)+") - exception: " + str(err))

        try:
            if manifest_data['schemaVersion'] == 1:
                docker_history, layers, dockerfile_contents, dockerfile_mode, imageArch = get_image_metadata_v1(staging_dirs, imageDigest, imageId, manifest_data, dockerfile_contents=dockerfile_contents, dockerfile_mode=dockerfile_mode)
            elif manifest_data['schemaVersion'] == 2:
                docker_history, layers, dockerfile_contents, dockerfile_mode, imageArch = get_image_metadata_v2(staging_dirs, imageDigest, imageId, manifest_data, dockerfile_contents=dockerfile_contents, dockerfile_mode=dockerfile_mode)
            else:
                raise Exception("unknown manifest schemaVersion")
            
        except Exception as err:
            raise Exception("failed to parse out manifest ("+str(pullstring)+") - exception: " + str(err))

        familytree = layers

        imageSize = unpack(staging_dirs, layers)

        familytree = layers
        analyzer_report = run_anchore_analyzers(staging_dirs, imageDigest, imageId)

        image_report = generate_image_export(staging_dirs, imageDigest, imageId, analyzer_report, imageSize, fulltag, docker_history, dockerfile_mode, dockerfile_contents, layers, familytree, imageArch, pullstring, analyzer_manifest)

    except Exception as err:
        raise Exception("failed to download, unpack, analyze, and generate image export - exception: " + str(err))
    finally:
        if staging_dirs:
            rc = delete_staging_dirs(staging_dirs)

    #if not imageDigest or not imageId or not manifest or not image_report:
    if not image_report:
        raise Exception("failed to analyze")

    return(image_report)
