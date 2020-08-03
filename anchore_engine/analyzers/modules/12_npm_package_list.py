#!/usr/bin/env python3

import sys
import os
import re
import json
import tarfile

import anchore_engine.analyzers.utils

analyzer_name = "package_list"

try:
    config = anchore_engine.analyzers.utils.init_analyzer_cmdline(sys.argv, analyzer_name)
except Exception as err:
    print(str(err))
    sys.exit(1)

imgname = config['imgid']
imgid = imgname
outputdir = config['dirs']['outputdir']
unpackdir = config['dirs']['unpackdir']

pkglist = {}

try:
    allfiles = {}
    if os.path.exists(unpackdir + "/anchore_allfiles.json"):
        with open(unpackdir + "/anchore_allfiles.json", 'r') as FH:
            allfiles = json.loads(FH.read())
    else:
        fmap, allfiles = anchore_engine.analyzers.utils.get_files_from_squashtar(os.path.join(unpackdir, "squashed.tar"))
        with open(unpackdir + "/anchore_allfiles.json", 'w') as OFH:
            OFH.write(json.dumps(allfiles))

    with tarfile.open(os.path.join(unpackdir, "squashed.tar"), mode='r', format=tarfile.PAX_FORMAT) as tfl:
        memberhash = anchore_engine.analyzers.utils.get_memberhash(tfl)
        for tfile in list(allfiles.keys()):
            patt = re.match(".*package\.json$", tfile)
            if patt:
                thefile = re.sub("^/+", "", tfile)
                try:
                    basemember = memberhash.get(thefile)
                    member = anchore_engine.analyzers.utils._get_extractable_member(tfl, basemember, memberhash=memberhash)
                    with tfl.extractfile(member) as FH:
                        pbuf = str(FH.read(), 'utf-8')
                        pdata = json.loads(pbuf)
                        precord = anchore_engine.analyzers.utils.npm_parse_meta(pdata)
                        for k in list(precord.keys()):
                            record = precord[k]
                            pkglist[tfile] = json.dumps(record)
                except Exception as err:
                    import traceback
                    traceback.print_exc()
                    print("WARN: found package.json but cannot parse (" + str(tfile) +") - exception: " + str(err))

    try:
        squashtar = os.path.join(unpackdir, "squashed.tar")
        hints = anchore_engine.analyzers.utils.get_hintsfile(unpackdir, squashtar)
        for pkg in hints.get('packages', []):
            pkg_type = pkg.get('type', "").lower()

            if pkg_type == 'npm':
                try:
                    pkg_key, el = anchore_engine.analyzers.utils._hints_to_npm(pkg)
                    try:
                        pkglist[pkg_key] = json.dumps(el)
                    except Exception as err:
                        print ("WARN: unable to add npm package ({}) from hints - excpetion: {}".format(pkg_key, err))
                except Exception as err:
                    print ("WARN: bad hints record encountered - exception: {}".format(err))                        
    except Exception as err:
        print ("WARN: problem honoring hints file - exception: {}".format(err))
        
except Exception as err:
    import traceback
    traceback.print_exc()
    raise err

if pkglist:
    ofile = os.path.join(outputdir, 'pkgs.npms')
    anchore_engine.analyzers.utils.write_kvfile_fromdict(ofile, pkglist)

sys.exit(0)
