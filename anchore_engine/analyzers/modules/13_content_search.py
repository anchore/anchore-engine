#!/usr/bin/env python

import sys
import os
import shutil
import re
import json
import time
import rpm
import subprocess
import tarfile

import anchore.anchore_utils

analyzer_name = "content_search"

try:
    config = anchore.anchore_utils.init_analyzer_cmdline(sys.argv, analyzer_name)
except Exception as err:
    print str(err)
    sys.exit(1)

imgname = config['imgid']
imageId = config['imgid_full']
outputdir = config['dirs']['outputdir']
unpackdir = config['dirs']['unpackdir']
rootfsdir = '/'.join([unpackdir, 'rootfs'])

matchparams = list()
regexps = list()
if 'analyzer_config' in config and config['analyzer_config']:
    if 'regexp_match' in config['analyzer_config']  and type(config['analyzer_config']['regexp_match']) == list:
        regexps = config['analyzer_config']['regexp_match']
    if 'match_params' in config['analyzer_config']  and type(config['analyzer_config']['match_params']) == list:
        matchparams = config['analyzer_config']['match_params']

if len(regexps) <= 0:
    print "No regexp configuration found in analyzer_config.yaml for analyzer '"+analyzer_name+", skipping"
    sys.exit(0)

params = {'maxfilesize':False, 'storeonmatch':False, 'mimetypefilter': None}
if matchparams:
    for param in matchparams:
        try:
            (key, value) = param.split("=")
            if key == 'MAXFILESIZE':
                params['maxfilesize'] = int(value)
            elif key == 'STOREONMATCH':
                if str(value).lower() == 'y':
                    params['storeonmatch'] = True
            elif key == 'MIMETYPEFILTER':
                try:
                    mtypes = re.split(", *", str(value))
                except:
                    mtypes = None
                if mtypes:
                    params['mimetypefilter'] = mtypes

        except:
            print "WARN: could not parse parameter (should be 'key=value'), ignoring: " + str(param)

outputdata = {}
allfiles = {}
if os.path.exists(unpackdir + "/anchore_allfiles.json"):
    with open(unpackdir + "/anchore_allfiles.json", 'r') as FH:
        allfiles = json.loads(FH.read())
else:
    fmap, allfiles = anchore.anchore_utils.get_files_from_path(unpackdir + "/rootfs")
    with open(unpackdir + "/anchore_allfiles.json", 'w') as OFH:
        OFH.write(json.dumps(allfiles))

results = {}
pathmap = {}
# fileinfo                                                                                                                         
for name in allfiles.keys():
    thefile = '/'.join([rootfsdir, name])
    if os.path.isfile(thefile):

        dochecks = True
        if params['maxfilesize'] and os.path.getsize(thefile) > params['maxfilesize']:
            dochecks = False
        else:
            try:
                fmimetype = "unknown"
            except Exception as err:
                fmimetype = "unknown"

            if fmimetype != 'unknown' and (params['mimetypefilter'] and fmimetype not in params['mimetypefilter']):
                dochecks = False

        if dochecks:
            with open(thefile, 'r') as FH:
                lineno = 0
                for line in FH.readlines():
                    for regexp in regexps:
                        try:
                            regexpname, theregexp = regexp.split("=", 1)
                        except:
                            theregexp = regexp

                        try:
                            patt = re.match(theregexp, line)
                            if patt:
                                b64regexp = regexp.encode('base64')
                                if name not in results:
                                    results[name] = {}
                                if b64regexp not in results[name]:
                                    results[name][b64regexp] = list()
                                results[name][b64regexp].append(lineno)
                                pathmap[name] = thefile
                        except Exception as err:
                            import traceback
                            traceback.print_exc()
                            print "ERROR: configured regexp not valid or regexp cannot be applied - exception: " + str(err)
                            sys.exit(1)
                    lineno += 1
        else:
            # skipping this file because maxfilesize is set and file is larger
            pass

storefiles = list()
for name in results.keys():
    buf = json.dumps(results[name])
    outputdata[name] = buf
    if params['storeonmatch']:
        storefiles.append(pathmap[name])

if outputdata:
    ofile = os.path.join(outputdir, 'regexp_matches.all')
    anchore.anchore_utils.write_kvfile_fromdict(ofile, outputdata)

if params['storeonmatch'] and storefiles:
    anchore.anchore_utils.save_files(imageId, analyzer_name, rootfsdir, storefiles)

sys.exit(0)
