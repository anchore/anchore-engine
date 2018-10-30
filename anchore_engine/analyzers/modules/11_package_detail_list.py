#!/usr/bin/env python3

import sys
import os
import re
import json
import subprocess

import anchore_engine.analyzers.utils

def rpm_get_all_packages_detail(unpackdir):
    rpms = {}

    try:
        rpmdbdir = anchore_engine.analyzers.utils.rpm_prepdb(unpackdir)
    except:
        rpmdbdir = os.path.join(unpackdir, 'rootfs', 'var', 'lib', 'rpm')

    try:
        sout = subprocess.check_output(['rpm', '--dbpath='+rpmdbdir, '--queryformat', '%{NAME}|ANCHORETOK|%{VERSION}|ANCHORETOK|%{RELEASE}|ANCHORETOK|%{ARCH}|ANCHORETOK|%{SIZE}|ANCHORETOK|%{LICENSE}|ANCHORETOK|%{SOURCERPM}|ANCHORETOK|%{VENDOR}\n', '-qa'])
        for l in sout.splitlines():
            l = l.strip()
            l = str(l, 'utf-8')
            (name, vers, rel, arch, rawsize, lic, source, vendor) = l.split("|ANCHORETOK|")

            try:
                size = str(int(rawsize))
            except:
                size = str(0)

            vendor = vendor + " (vendor)"
            rpms[name] = {'version':vers, 'release':rel, 'arch':arch, 'size':size, 'license':lic, 'sourcepkg':source, 'origin':vendor, 'type':'rpm'}
    except:
        raise ValueError("could not get package list from RPM database: " + str(err))

    return(rpms)

def dpkg_get_all_packages_detail(unpackdir):
    all_packages = {}
    cmd = ["dpkg-query", "--admindir="+unpackdir+"/rootfs/var/lib/dpkg", "-W", "-f="+"${Package}|ANCHORETOK|${Version}|ANCHORETOK|${Architecture}|ANCHORETOK|${Installed-Size}|ANCHORETOK|${source:Package}-${source:Version}|ANCHORETOK|${Maintainer}\\n"]
    try:
        sout = subprocess.check_output(cmd)
        for l in sout.splitlines(True):
            l = l.strip()
            l = str(l, 'utf-8')
            (p, v, arch, rawsize, source, vendor) = l.split("|ANCHORETOK|")

            try:
                size = str(int(rawsize) * 1000)
            except:
                size = str(0)

            vendor = str(vendor) + " (maintainer)"
            arch = str(arch)
            source = str(source)

            try:
                licfile = '/'.join([unpackdir, 'rootfs/usr/share/doc/', p, 'copyright'])
                if not os.path.exists(licfile):
                    lic = "Unknown"
                else:
                    lics = deb_copyright_getlics(licfile)
                    if len(list(lics.keys())) > 0:
                        lic = ' '.join(lics)
                    else:
                        lic = "Unknown"
            except:
                lic = "Unknown"

            all_packages[p] = {'version':v, 'release':'N/A', 'arch':arch, 'size':size, 'origin':vendor, 'license':lic, 'sourcepkg':source, 'type':'dpkg'}
    except Exception as err:
        import traceback
        traceback.print_exc()
        print("Could not run command: " + str(cmd))
        print("Exception: " + str(err))
        raise ValueError("Please ensure the command 'dpkg' is available and try again: " + str(err))

    return(all_packages)

def deb_copyright_getlics(licfile):
    ret = {}

    if os.path.exists(licfile):
        found=False
        FH=open(licfile, 'r')
        lictext = FH.read()
        for l in lictext.splitlines():
            l = l.strip()
            m = re.match("License: (\S*)", l)
            if m:
                lic = m.group(1)
                if lic:
                    ret[lic] = True
                    found=True
        FH.close()
    return(ret)

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

#if not os.path.exists(outputdir):
#    os.makedirs(outputdir)

meta = anchore_engine.analyzers.utils.get_distro_from_path('/'.join([unpackdir, "rootfs"]))
distrodict = anchore_engine.analyzers.utils.get_distro_flavor(meta['DISTRO'], meta['DISTROVERS'], likedistro=meta['LIKEDISTRO'])

pkgs = None
pkglist = {}

if distrodict['flavor'] == "RHEL":
    try:
        pkgs = rpm_get_all_packages_detail(unpackdir)
    except Exception as err:
        print("WARN: failed to generate RPM package list: " + str(err))

elif distrodict['flavor'] == "DEB":
    try:
        pkgs = dpkg_get_all_packages_detail(unpackdir)
    except Exception as err:
        print("WARN: failed to generate DPKG package list: " + str(err))
elif distrodict['flavor'] == "ALPINE":
    try:
        pkgs = anchore_engine.analyzers.utils.apkg_get_all_pkgfiles(unpackdir)
    except Exception as err:
        print("WARN: failed to generate APKG package list: " + str(err))
else:
    pass

if pkgs:
    for p in list(pkgs.keys()):
        pkglist[p] = json.dumps(pkgs[p])

if pkglist:
    ofile = os.path.join(outputdir, 'pkgs.allinfo')
    anchore_engine.analyzers.utils.write_kvfile_fromdict(ofile, pkglist)

sys.exit(0)
