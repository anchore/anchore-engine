#!/usr/bin/env python3

import sys
import os
import json
import stat

import anchore_engine.analyzers.utils

analyzer_name = "file_suids"

try:
    config = anchore_engine.analyzers.utils.init_analyzer_cmdline(sys.argv, analyzer_name)
except Exception as err:
    print(str(err))
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
        fmap, allfiles = anchore_engine.analyzers.utils.get_files_from_path(unpackdir + "/rootfs")
        with open(unpackdir + "/anchore_allfiles.json", 'w') as OFH:
            OFH.write(json.dumps(allfiles))

    # fileinfo
    for name in list(allfiles.keys()):
        if allfiles[name]['mode'] & stat.S_ISUID:
            outfiles[name] = oct(stat.S_IMODE(allfiles[name]['mode']))

except Exception as err:
    print("ERROR: " + str(err))

if outfiles:
    ofile = os.path.join(outputdir, 'files.suids')
    anchore_engine.analyzers.utils.write_kvfile_fromdict(ofile, outfiles)

sys.exit(0)
