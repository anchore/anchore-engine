import os
import re
import sys
import json
import uuid
import shutil
import struct
import tarfile
import logging
import subprocess
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

#def read_kvfile_todict(file):
#    if not os.path.isfile(file):
#        return ({})

#    ret = {}
#    FH = open(file, 'r')
#    for l in FH.readlines():
#        l = l.strip().decode('utf8')
#        if l:
#            (k, v) = re.match('(\S*)\s*(.*)', l).group(1, 2)
#            k = re.sub("____", " ", k)
#            ret[k] = v
#    FH.close()

#    return (ret)

def squash(unpackdir, layers):
    rootfsdir = unpackdir + "/rootfs"

    if os.path.exists(unpackdir + "/squashed.tar"):
        return (True)

    if not os.path.exists(rootfsdir):
        os.makedirs(rootfsdir)

    revlayer = list(layers)
    revlayer.reverse()

    squashtarfile = tarfile.open(unpackdir + '/squashed_tmp.tar', mode='w', format=tarfile.PAX_FORMAT)

    allfiles = list()
    lastexcludes = list()
    excludes = list()
    hlinks = {}
    hfiles = {}
    layerfiles = {}
    thetfile = {}

    for l in revlayer:
        #layertar = unpackdir + "/" + l + "/layer.tar"
        htype, lfile = l.split(":",1)
        #layertar = unpackdir + "/oci/blobs/" + htype+"/"+lfile
        layertar = unpackdir + "/raw/"+lfile+".tar"
        layerfiles[l] = {}

        logger.debug("\tPass 1: " + str(layertar))
        layertarfile = tarfile.open(layertar, mode='r', format=tarfile.PAX_FORMAT)
        for member in layertarfile.getmembers():
            #logger.debug("MEMBER: " + str(member))
            layerfiles[l][member.name] = True

            if re.match(".*\.wh\..*", member.name):
                fsub = re.sub(r"\.wh\.", "", member.name)
                if fsub not in allfiles:
                    if member.name not in excludes:
                        excludes.append(member.name)
                    if fsub not in excludes:
                        excludes.append(fsub)

            if member.islnk():
                if member.linkname not in hlinks:
                    hlinks[member.linkname] = list()
                hlinks[member.linkname].append(member.name)

            skip = False
            if member.name in allfiles:
                skip = True
            else:
                for p in excludes:
                    if re.match("^"+re.escape(p), member.name):
                        skip = True
                        break

            if not skip:
                allfiles.append(member.name)
                if member.isfile():
                    squashtarfile.addfile(member, layertarfile.extractfile(member))
                else:
                    try:
                        squashtarfile.addfile(member, layertarfile.extractfile(member))
                    except:
                        squashtarfile.addfile(member)

        layertarfile.close()

    squashtarfile.close()

    # should no longer need this pass
    if False:
        newhlinkmap = {}
        if True:
            squashtar = unpackdir + "/squashed.tar"
            squashtarfile = tarfile.open(unpackdir + '/squashed_tmp.tar', mode='r', format=tarfile.PAX_FORMAT)
            finalsquashtarfile = tarfile.open(squashtar, mode='w', format=tarfile.PAX_FORMAT)
            logger.debug("TEST HLINKS: " + str(hlinks))
            logger.debug("\tPass 2: " + str(squashtar))
            for member in squashtarfile.getmembers():
                if member.islnk():
                    try:
                        testfile = squashtarfile.getmember(member.linkname)
                        logger.debug("TEST CASE1")
                        finalsquashtarfile.addfile(member)
                    except:
                        if member.linkname in newhlinkmap:
                            member.linkname = newhlinkmap[member.linkname]
                            logger.debug("TEST CASE2")
                            finalsquashtarfile.addfile(member)
                        else:
                            for l in revlayer:
                                if member.linkname in layerfiles[l]:
                                    layertar = unpackdir + "/" + l + "/layer.tar"
                                    layertarfile = tarfile.open(layertar, mode='r', format=tarfile.PAX_FORMAT)
                                    try:
                                        testfile = layertarfile.getmember(member.linkname)
                                        testfile.name = hlinks[member.linkname][0]
                                        newhlinkmap[member.linkname] = testfile.name
                                        thefile = layertarfile.extractfile(testfile)
                                        logger.debug("TEST CASE3")
                                        finalsquashtarfile.addfile(testfile, thefile)
                                        break
                                    except:
                                        pass
                                    layertarfile.close()
                else:
                    try:
                        logger.debug("TEST CASE4")
                        finalsquashtarfile.addfile(member, squashtarfile.extractfile(member.name))
                    except:
                        logger.debug("TEST CASE5")
                        finalsquashtarfile.addfile(member)

            finalsquashtarfile.close()
            squashtarfile.close()
        squashtar = unpackdir + "/squashed.tar"
    else:
        squashtar = os.path.join(unpackdir, "squashed_tmp.tar")

    logger.debug("\tPass 3: " + str(squashtar))
    tarcmd = "tar -C " + rootfsdir + " -x -f " + squashtar
    logger.debug("untarring squashed tarball: " + str(tarcmd))
    subprocess.check_output(tarcmd.split())

    imageSize = os.path.getsize(squashtar)
    
    #try:
    #    # debug
    #    cmd = "cp "+ squashtar + " /config/"
    #    subprocess.check_output(cmd.split())
    #except:
    #    pass

    return (squashtar, imageSize)

def make_staging_dirs(rootdir):
    if not os.path.exists(rootdir):
        raise Exception("passed in root directory must exist ("+str(rootdir)+")")

    rando = str(uuid.uuid4())
    ret = {
        'unpackdir': os.path.join(rootdir, rando),
        'copydir': os.path.join(rootdir, rando, "raw"),
        'rootfs': os.path.join(rootdir, rando, "rootfs"),
        'outputdir': os.path.join(rootdir, rando, "output")
    }
    for k in ret.keys():
        try:
            if not os.path.exists(ret[k]):
                logger.debug("making dir: " + k + " : " + str(ret[k]))
                os.makedirs(ret[k])
        except Exception as err:
            raise Exception("unable to prep staging directory - exception: " + str(err))

    return(ret)

def delete_staging_dirs(staging_dirs):
    for k in staging_dirs.keys():
        try:
            if os.path.exists(staging_dirs[k]):
                logger.debug("removing dir: " + k + " : " + str(staging_dirs[k]))
                shutil.rmtree(staging_dirs[k])
        except Exception as err:
            raise Exception("unable to delete staging directory - exception: " + str(err))

    return(True)

def pull_image(staging_dirs, image_info, registry_creds=[]):
    outputdir = staging_dirs['outputdir']
    unpackdir = staging_dirs['unpackdir']
    copydir = staging_dirs['copydir']
    fulltag = image_info['fulltag']

    imageDigest = imageId = rawmanifest = None
    user = pw = None
    registry_verify = False

    # extract user/pw/verify from registry_creds
    try:
        if registry_creds:
            user, pw, registry_verify = anchore_engine.auth.common.get_creds_by_registry(image_info['registry'], registry_creds=registry_creds)
    except Exception as err:
        raise err

    # get the manifest/digest
    rawmanifest,imageDigest = anchore_engine.auth.skopeo_wrapper.get_image_manifest_skopeo(None, image_info['registry'], image_info['repo'], image_info['tag'], user=user, pw=pw, verify=registry_verify)
    #rawmanifest, imageDigest = anchore_engine.auth.docker_registry.get_image_manifest(None, image_info, registry_creds)
    try:
        d = rawmanifest
        logger.debug("MANIFEST: " + str(d))
        if d['schemaVersion'] != 2:
            raise Exception("manifest is not schema version 2 - unpack unsupported")

        rawimageId = d['config']['digest']
        htype, imageId = rawimageId.split(":",1)
        rawlayers = d['layers']
    except Exception as err:
        raise err

    # download
    try:
        rc = anchore_engine.auth.skopeo_wrapper.download_image(fulltag, copydir, user=user, pw=pw, verify=registry_verify)
    except Exception as err:
        raise err

    if not imageDigest or not imageId or not rawlayers:
        raise Exception("need imageDigest, imageId and layers to proceed: " + str(fulltag) + " : " + str(imageId) + " : " + str(imageDigest))
    
    return(imageDigest, imageId, rawmanifest, rawlayers)

def get_image_metadata(staging_dirs, imageDigest, imageId, rawlayers, dockerfile_contents=""):
    outputdir = staging_dirs['outputdir']
    unpackdir = staging_dirs['unpackdir']
    copydir = staging_dirs['copydir']

    hfinal = []
    layers = []
    docker_history = []

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

                hfinal.append(
                    {
                        'Created': hel['created'],
                        'CreatedBy': hel['created_by'],
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
            else:
                cmd = "RUN " + hel['CreatedBy']
            dockerfile_contents = dockerfile_contents + cmd + "\n"        
        dockerfile_mode = "Guessed"
    else:
        dockerfile_mode = "Actual"

    return(docker_history, layers, dockerfile_contents, dockerfile_mode)

def unpack(staging_dirs, layers):
    outputdir = staging_dirs['outputdir']
    unpackdir = staging_dirs['unpackdir']
    copydir = staging_dirs['copydir']

    try:
        squashtar, imageSize = squash(unpackdir, layers)
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
                    logger.debug("\t"+cmdstr)
                    sout = subprocess.check_output(cmdstr.split())
                except Exception as err:
                    logger.debug("ERROR - exception: " + str(err))

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


def analyze_image(userId, fulltag, tmprootdir, registry_creds=[], dockerfile_contents=""):
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
    manifest = ""
    staging_dirs = None

    try:
        try:
            image_info = anchore_engine.services.common.get_image_info(userId, "docker", fulltag, registry_lookup=False)
        except Exception as err:
            raise err

        try:
            staging_dirs = make_staging_dirs(tmprootdir)
        except Exception as err:
            raise err

        imageDigest, imageId, manifest, rawlayers = pull_image(staging_dirs, image_info, registry_creds=registry_creds)

        try:
            regrepo, tag = fulltag.split(":", 1)
        except:
            regrepo = fulltag
        rdigest = regrepo + "@" + imageDigest

        docker_history, layers, dockerfile_contents, dockerfile_mode = get_image_metadata(staging_dirs, imageDigest, imageId, rawlayers, dockerfile_contents=dockerfile_contents)
        familytree = layers

        imageSize = unpack(staging_dirs, layers)
        familytree = layers
        analyzer_report = run_anchore_analyzers(staging_dirs, imageDigest, imageId)

        image_report = generate_image_export(staging_dirs, imageDigest, imageId, analyzer_report, imageSize, fulltag, docker_history, dockerfile_mode, dockerfile_contents, layers, familytree, imageArch, rdigest, analyzer_manifest)

    except Exception as err:
        raise Exception("failed to download, unpack, analyze, and generate image export - exception: " + str(err))
    finally:
        if staging_dirs:
            rc = delete_staging_dirs(staging_dirs)

    if not imageDigest or not imageId or not manifest or not image_report:
        raise Exception("failed to analyze")

    return(imageDigest, imageId, manifest, image_report)

if __name__ == '__main__':
    fulltag = sys.argv[1]
    logger.debug( "DOING: " + str(fulltag))
    try:
        imageDigest, imageId, manifest, image_report = analyze_image(fulltag, "/tmp/unpacker")
        print "dig: " + imageDigest
        print "id: " + imageId
        print "manifest: " + str(len(manifest))
        print "image_report: " + str(image_report[0]['image']['imagedata'].keys())
    except Exception as err:
        logger.error("failed to analyze: " + str(err))
        raise err
    logger.debug( "DONE: " + str(fulltag))
