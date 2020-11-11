#!/usr/bin/env python3

import sys
import os
import anchore_engine.analyzers.utils
import json

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

meta = anchore_engine.analyzers.utils.get_distro_from_squashtar(
    os.path.join(unpackdir, "squashed.tar"), unpackdir=unpackdir)
distrodict = anchore_engine.analyzers.utils.get_distro_flavor(
    meta['DISTRO'], meta['DISTROVERS'], likedistro=meta['LIKEDISTRO'])

print("analyzer starting up: imageId="+str(imgid) + " meta="+str(meta) + " distrodict="+str(distrodict))

if distrodict['flavor'] not in ['DEB', 'BUSYB']:
    sys.exit(0)

pkgsall = {}
pkgfilesall = {}
pkgsplussource = {}
pkgsdetail = {}

if pkgsall:
    ofile = os.path.join(outputdir, 'pkgs.all')
    anchore_engine.analyzers.utils.write_kvfile_fromdict(ofile, pkgsall)
if pkgfilesall:
    ofile = os.path.join(outputdir, 'pkgfiles.all')
    anchore_engine.analyzers.utils.write_kvfile_fromdict(ofile, pkgfilesall)
if pkgsplussource:
    ofile = os.path.join(outputdir, 'pkgs_plus_source.all')
    anchore_engine.analyzers.utils.write_kvfile_fromdict(ofile, pkgsplussource)
if pkgsdetail:
    ofile = os.path.join(outputdir, 'pkgs.allinfo')
    anchore_engine.analyzers.utils.write_kvfile_fromdict(ofile, pkgsdetail)

sys.exit(0)
