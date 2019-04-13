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

meta = anchore_engine.analyzers.utils.get_distro_from_squashtar(os.path.join(unpackdir, "squashed.tar"))
distrodict = anchore_engine.analyzers.utils.get_distro_flavor(meta['DISTRO'], meta['DISTROVERS'], likedistro=meta['LIKEDISTRO'])

print("analyzer starting up: imageId="+str(imgid) + " meta="+str(meta) + " distrodict="+str(distrodict))

if distrodict['flavor'] not in ['RHEL', 'DEB', 'BUSYB', 'ALPINE']:
    sys.exit(0)

pkgsall = {}
pkgfilesall = {}
pkgsplussource = {}
pkgsdetail = {}

if distrodict['flavor'] == "RHEL":
    try:
        rpms, rpmdbdir = anchore_engine.analyzers.utils.rpm_get_all_packages_detail_from_squashtar(unpackdir, os.path.join(unpackdir, "squashed.tar"))
        for pkg in list(rpms.keys()):
            pkgsall[pkg] = rpms[pkg]['version'] + "-" + rpms[pkg]['release']
            pkgsdetail[pkg] = json.dumps(rpms[pkg])
    except Exception as err:
        import traceback
        traceback.print_exc()
        print("WARN: failed to generate RPM package list: " + str(err))

    try:
        rpmfiles = anchore_engine.analyzers.utils.rpm_get_all_pkgfiles(rpmdbdir)
        for pkgfile in list(rpmfiles.keys()):
            pkgfilesall[pkgfile] = "RPMFILE"
    except Exception as err:
        print("WARN: failed to get file list from RPMs: " + str(err))

elif distrodict['flavor'] == "DEB":
    try:
        (all_packages, all_packages_simple, actual_packages, other_packages, dpkgdbdir) = anchore_engine.analyzers.utils.dpkg_get_all_packages_detail_from_squashtar(unpackdir, os.path.join(unpackdir, "squashed.tar"))
    
        for p in list(actual_packages.keys()):
            pkgsall[p] = actual_packages[p]['version']

        for p in list(all_packages_simple.keys()):
            pkgsplussource[p] = all_packages_simple[p]['version']

        if len(other_packages) > 0:
            for p in list(other_packages.keys()):
                for v in other_packages[p]:
                    pkgsplussource[p] = v['version']

        for p in list(all_packages.keys()):
            pkgsdetail[p] = json.dumps(all_packages[p])

        
    except Exception as err:
        print("WARN: failed to get package list from DPKG: " + str(err))

    try:
        dpkgfiles = anchore_engine.analyzers.utils.dpkg_get_all_pkgfiles_from_squashtar(dpkgdbdir, os.path.join(unpackdir, "squashed.tar"))
        for pkgfile in list(dpkgfiles.keys()):
            pkgfilesall[pkgfile] = "DPKGFILE"

    except Exception as err:
        print("WARN: failed to get file list from DPKGs: " + str(err))

elif distrodict['flavor'] == 'ALPINE':
    try:
        apkgs = anchore_engine.analyzers.utils.apkg_get_all_pkgfiles_from_squashtar(unpackdir, os.path.join(unpackdir, "squashed.tar"))

        for pkg in list(apkgs.keys()):
            # all detail
            pkgsdetail[pkg] = json.dumps(apkgs[pkg])
            
            # base
            if apkgs[pkg]['release'] != "N/A":
                pvers = apkgs[pkg]['version']+"-"+apkgs[pkg]['release']
            else:
                pvers = apkgs[pkg]['version']
            pkgsall[pkg] = pvers
            pkgsplussource[pkg] = pvers

            # source package
            if 'sourcepkg' in apkgs[pkg] and apkgs[pkg]['sourcepkg']:
                spkg = apkgs[pkg]['sourcepkg']
                if spkg != pkg and spkg not in pkgsplussource:
                    pkgsplussource[spkg] = pvers

            # pkgfiles
            for pkgfile in apkgs[pkg]['files']:
                pkgfilesall[pkgfile] = 'APKFILE'

    except Exception as err:
        print("WARN: failed to generate APK package list: " + str(err))

elif distrodict['flavor'] == "BUSYB":
    pkgsall["BusyBox"] = distrodict['fullversion']
else:
    pkgsall["Unknown"] = "0"

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
