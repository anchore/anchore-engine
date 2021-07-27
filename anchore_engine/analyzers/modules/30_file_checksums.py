#!/usr/bin/env python3

import os
import sys
import time

import anchore_engine.analyzers.utils

analyzer_name = "file_checksums"

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

domd5 = True
dosha1 = False

outfiles_sha1 = {}
outfiles_md5 = {}
outfiles_sha256 = {}

meta = anchore_engine.analyzers.utils.get_distro_from_squashtar(
    os.path.join(unpackdir, "squashed.tar"), unpackdir=unpackdir
)
distrodict = anchore_engine.analyzers.utils.get_distro_flavor(
    meta["DISTRO"], meta["DISTROVERS"], likedistro=meta["LIKEDISTRO"]
)
if distrodict["flavor"] == "ALPINE":
    dosha1 = True

try:
    timer = time.time()
    csums = ["sha256", "md5"]
    if dosha1:
        csums.append("sha1")

    allfiles = anchore_engine.analyzers.utils.get_checksums_from_squashtar(
        os.path.join(unpackdir, "squashed.tar"), csums=csums
    )

    for filename in allfiles.keys():
        file_sha256 = allfiles[filename].get("sha256", None)
        if file_sha256:
            outfiles_sha256[filename] = file_sha256

        file_sha1 = allfiles[filename].get("sha1", None)
        if file_sha1:
            outfiles_sha1[filename] = file_sha1

        file_md5 = allfiles[filename].get("md5", None)
        if file_md5:
            outfiles_md5[filename] = file_md5

except Exception as err:
    import traceback

    traceback.print_exc()
    print("ERROR: " + str(err))
    raise err

if outfiles_sha1:
    ofile = os.path.join(outputdir, "files.sha1sums")
    anchore_engine.analyzers.utils.write_kvfile_fromdict(ofile, outfiles_sha1)

if outfiles_md5:
    ofile = os.path.join(outputdir, "files.md5sums")
    anchore_engine.analyzers.utils.write_kvfile_fromdict(ofile, outfiles_md5)

if outfiles_sha256:
    ofile = os.path.join(outputdir, "files.sha256sums")
    anchore_engine.analyzers.utils.write_kvfile_fromdict(ofile, outfiles_sha256)


sys.exit(0)
