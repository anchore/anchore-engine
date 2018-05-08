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
import tarfile
import time
import hashlib

import anchore.anchore_utils

analyzer_name = "file_checksums"

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

domd5 = True
dosha1 = False

outfiles_sha1 = {}
outfiles_md5 = {}
outfiles_sha256 = {}

meta = anchore.anchore_utils.get_distro_from_path('/'.join([unpackdir, "rootfs"]))
distrodict = anchore.anchore_utils.get_distro_flavor(meta['DISTRO'], meta['DISTROVERS'], likedistro=meta['LIKEDISTRO'])
if distrodict['flavor'] == "ALPINE":
    dosha1 = True

try:
    timer = time.time()
    (tmp, allfiles) = anchore.anchore_utils.get_files_from_path(unpackdir + "/rootfs")
    for name in allfiles.keys():
        name = re.sub("^\.", "", name)
        thefile = '/'.join([unpackdir, "rootfs", name])

        csum = "DIRECTORY_OR_OTHER"
        if os.path.isfile(thefile) and not os.path.islink(thefile):
            if domd5:
                try:
                    with open(thefile, 'r') as FH:
                        csum = hashlib.md5(FH.read()).hexdigest()
                except:
                    csum = "DIRECTORY_OR_OTHER"
                outfiles_md5[name] = csum

            if dosha1:
                try:
                    with open(thefile, 'r') as FH:
                        csum = hashlib.sha1(FH.read()).hexdigest()
                except:
                    csum = "DIRECTORY_OR_OTHER"
                outfiles_sha1[name] = csum

            try:
                with open(thefile, 'r') as FH:
                    csum = hashlib.sha256(FH.read()).hexdigest()
            except:
                csum = "DIRECTORY_OR_OTHER"
            outfiles_sha256[name] = csum

        else:
            if domd5:
                outfiles_md5[name] = "DIRECTORY_OR_OTHER"
            if dosha1:
                outfiles_sha1[name] = "DIRECTORY_OR_OTHER"

            outfiles_sha256[name] = "DIRECTORY_OR_OTHER"

except Exception as err:
    import traceback
    traceback.print_exc()
    print "ERROR: " + str(err)
    raise err

if outfiles_sha1:
    ofile = os.path.join(outputdir, 'files.sha1sums')
    anchore.anchore_utils.write_kvfile_fromdict(ofile, outfiles_sha1)

if outfiles_md5:
    ofile = os.path.join(outputdir, 'files.md5sums')
    anchore.anchore_utils.write_kvfile_fromdict(ofile, outfiles_md5)

if outfiles_sha256:
    ofile = os.path.join(outputdir, 'files.sha256sums')
    anchore.anchore_utils.write_kvfile_fromdict(ofile, outfiles_sha256)


sys.exit(0)
