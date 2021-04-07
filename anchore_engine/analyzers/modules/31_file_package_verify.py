#!/usr/bin/env python3
import base64
import binascii
import sys
import os
import re
import json
import subprocess
import copy

import anchore_engine.analyzers.utils

analyzer_name = "file_package_verify"

try:
    config = anchore_engine.analyzers.utils.init_analyzer_cmdline(
        sys.argv, analyzer_name
    )
except Exception as err:
    print(str(err))
    sys.exit(1)

imgname = config["imgid"]
imgid = config["imgid_full"]
outputdir = config["dirs"]["outputdir"]
unpackdir = config["dirs"]["unpackdir"]
squashtar = os.path.join(unpackdir, "squashed.tar")

meta = anchore_engine.analyzers.utils.get_distro_from_squashtar(
    squashtar, unpackdir=unpackdir
)
distrodict = anchore_engine.analyzers.utils.get_distro_flavor(
    meta["DISTRO"], meta["DISTROVERS"], likedistro=meta["LIKEDISTRO"]
)
flavor = distrodict["flavor"]

# gather file metadata from installed packages

result = {}
resultlist = {}

try:
    if flavor == "RHEL":
        try:
            # result = rpm_get_file_package_metadata(unpackdir, record)
            result = anchore_engine.analyzers.utils.rpm_get_file_package_metadata_from_squashtar(
                unpackdir, squashtar
            )
        except Exception as err:
            raise Exception("ERROR: " + str(err))

    elif flavor == "DEB":
        try:
            # result = deb_get_file_package_metadata(unpackdir, record)
            result = anchore_engine.analyzers.utils.dpkg_get_file_package_metadata_from_squashtar(
                unpackdir, squashtar
            )
        except Exception as err:
            raise Exception("ERROR: " + str(err))

    elif flavor == "ALPINE":
        try:
            # result = apk_get_file_package_metadata(unpackdir, record)
            result = anchore_engine.analyzers.utils.apk_get_file_package_metadata_from_squashtar(
                unpackdir, squashtar
            )
        except Exception as err:
            raise Exception("ERROR: " + str(err))

    else:
        # do nothing, flavor not supported for getting metadata about files from pkg manager
        pass
except Exception as err:
    print("WARN: analyzer unable to complete - exception: " + str(err))
    result = {}
    resultline = {}

if result:
    for f in list(result.keys()):
        try:
            resultlist[f] = json.dumps(result[f], sort_keys=True)
        except Exception as err:
            print("WARN: " + str(err))
            resultlist[f] = ""

if resultlist:
    ofile = os.path.join(outputdir, "distro.pkgfilemeta")
    anchore_engine.analyzers.utils.write_kvfile_fromdict(ofile, resultlist)

sys.exit(0)
