#!/usr/bin/env python3

import sys
import os
import re
import json
import traceback

import anchore_engine.analyzers.utils

analyzer_name = "package_list"

try:
    config = anchore_engine.analyzers.utils.init_analyzer_cmdline(sys.argv, analyzer_name)
except Exception as err:
    print(str(err))
    sys.exit(1)

imgname = config['imgid']
imgid = config['imgid_full']
outputdir = config['dirs']['outputdir']
unpackdir = config['dirs']['unpackdir']
squashtar = os.path.join(unpackdir, "squashed.tar")

go_package_el = {
    'name': None,
    'version': None,
    'location': None,
    'type': 'go',
    'files': [],
    'license': 'N/A',
    'origin': 'N/A',
    'metadata': json.dumps({})
}

resultlist = {}
try:
    allfiles = {}
    if os.path.exists(unpackdir + "/anchore_allfiles.json"):
        with open(unpackdir + "/anchore_allfiles.json", 'r') as FH:
            allfiles = json.loads(FH.read())
    else:
        #fmap, allfiles = anchore_engine.analyzers.utils.get_files_from_path(unpackdir + "/rootfs")
        fmap, allfiles = anchore_engine.analyzers.utils.get_files_from_squashtar(os.path.join(unpackdir, "squashed.tar"))
        with open(unpackdir + "/anchore_allfiles.json", 'w') as OFH:
            OFH.write(json.dumps(allfiles))

    # leaving this as an example of the expected format for a go package - in the below example a package named 'text' is created and will match against CVE-2020-14040
    #el = {}
    #el.update(go_package_el)
    #el['name'] = 'text'
    #el['version'] = 'v0.3.3-1234-abcd'
    #el['location'] = '/fake/path/to/text'
    #resultlist[el['location']] = json.dumps(el)
    
except Exception as err:
    import traceback
    traceback.print_exc()
    print("WARN: analyzer unable to complete - exception: " + str(err))

if resultlist:
    ofile = os.path.join(outputdir, 'pkgs.go')
    anchore_engine.analyzers.utils.write_kvfile_fromdict(ofile, resultlist)

sys.exit(0)
