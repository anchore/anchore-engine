#!/usr/bin/env python

import sys
import os
import shutil
import re
import json
import time
import rpm
import subprocess
import stat

import anchore.anchore_utils

analyzer_name = "file_suids"

try:
    config = anchore.anchore_utils.init_analyzer_cmdline(sys.argv, analyzer_name)
except Exception as err:
    print str(err)
    sys.exit(1)

imgname = config['imgid']
imgid = config['imgid_full']
outputdir = config['dirs']['outputdir']
unpackdir = config['dirs']['unpackdir']

#if not os.path.exists(outputdir):
#    os.makedirs(outputdir)

outfiles = {}

try:
    allfiles = {}
    if os.path.exists(unpackdir + "/anchore_allfiles.json"):
        with open(unpackdir + "/anchore_allfiles.json", 'r') as FH:
            allfiles = json.loads(FH.read())
    else:
        fmap, allfiles = anchore.anchore_utils.get_files_from_path(unpackdir + "/rootfs")
        with open(unpackdir + "/anchore_allfiles.json", 'w') as OFH:
            OFH.write(json.dumps(allfiles))

    # fileinfo
    for name in allfiles.keys():
        if allfiles[name]['mode'] & stat.S_ISUID:
            outfiles[name] = oct(stat.S_IMODE(allfiles[name]['mode']))

except Exception as err:
    print "ERROR: " + str(err)

if outfiles:
    ofile = os.path.join(outputdir, 'files.suids')
    anchore.anchore_utils.write_kvfile_fromdict(ofile, outfiles)

sys.exit(0)
