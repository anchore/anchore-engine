#!/usr/bin/env python

import sys
import os
import shutil
import re
import json
import rpm
import subprocess
import stat

import anchore.anchore_utils

def rpm_check_file_membership_from_path(unpackdir, allfiles=None):
    rpmfiles = {}
    matchfiles = list()
    nonmatchfiles = list()
    realnonmatchfiles = list()
    inpath = os.path.join(unpackdir, 'rootfs')
    rpmdbdir = anchore.anchore_utils.rpm_prepdb(unpackdir)

    if not allfiles:
        filemap, allfiles = anchore.anchore_utils.get_files_from_path(inpath)

    try:
        try:
            # get a list of all files from RPM
            try:
                sout = subprocess.check_output(['rpm', '--dbpath='+rpmdbdir, '-qal'])
                sout = sout.decode('utf8')
            except subprocess.CalledProcessError as err:
                sout = ""
                errmsg = err.output.decode('utf8')

            for l in sout.splitlines():
                l = l.strip()
                rpmfiles[l] = True
        except Exception as err:
            raise err

        # find any rpm files that are not in the filesystem (first past)
        for rfile in allfiles.keys():
            if rfile not in rpmfiles:
                nonmatchfiles.append(rfile)

        # second pass - hardlinks make this necessary
        done=False
        start = 0
        while not done:
            cmdlist = nonmatchfiles[start:start+256]
            if len(cmdlist) <= 0:
                done=True
            else:
                try:
                    sout = subprocess.check_output(['rpm', '--dbpath='+rpmdbdir, '-qf'] + cmdlist, stderr=subprocess.STDOUT)
                    sout = sout.decode('utf8')
                except subprocess.CalledProcessError as err:
                    sout = err.output.decode('utf8')

                for l in sout.splitlines():
                    l = l.strip()
                    try:
                        filename = re.match("file (.*) is not owned by any package", l).group(1)
                        realnonmatchfiles.append(filename)
                    except:
                        pass
            start = start + 256
    except Exception as err:
        raise err
    
    # for all files, if not unmatched, consider them matched to a package
    for rfile in allfiles.keys():
        if rfile not in realnonmatchfiles:
            matchfiles.append(rfile)

    #print "RESULT: " + str(len(matchfiles)) + " : " + str(len(realnonmatchfiles))
    return(matchfiles, realnonmatchfiles)

def dpkg_check_file_membership_from_path(unpackdir, allfiles=None):
    matchfiles = list()
    nonmatchfiles = list()
    inpath = os.path.join(unpackdir, 'rootfs')

    if not allfiles:
        filemap, allfiles = anchore.anchore_utils.get_files_from_path(inpath)

    try:
        try:

            for flist in anchore.anchore_utils.grouper(allfiles.keys(), 256):
                try:
                    sout = subprocess.check_output(['dpkg', "--admindir="+unpackdir+"/rootfs/var/lib/dpkg", '-S'] + flist, stderr=subprocess.STDOUT)
                    sout = sout.decode('utf8')
                except subprocess.CalledProcessError as err:
                    sout = err.output.decode('utf8')

                for l in sout.splitlines():
                    l = l.strip()
                    try:
                        filename = re.match("dpkg-query: no path found matching pattern (.*)", l).group(1)
                        nonmatchfiles.append(filename)
                    except:
                        pass

        except Exception as err:
            print str(err)

    except Exception as err:
        raise err

    matchfiles = list(set(allfiles.keys()) - set(nonmatchfiles))

    #print "RESULT: " + str(len(matchfiles)) + " : " + str(len(nonmatchfiles))

    return(matchfiles, nonmatchfiles)

analyzer_name = "file_list"

try:
    config = anchore.anchore_utils.init_analyzer_cmdline(sys.argv, analyzer_name)
except Exception as err:
    print str(err)
    sys.exit(1)

imgname = config['imgid']
imgid = config['imgid_full']
outputdir = config['dirs']['outputdir']
unpackdir = config['dirs']['unpackdir']

meta = anchore.anchore_utils.get_distro_from_path('/'.join([unpackdir, "rootfs"]))
distrodict = anchore.anchore_utils.get_distro_flavor(meta['DISTRO'], meta['DISTROVERS'], likedistro=meta['LIKEDISTRO'])

simplefiles = {}
outfiles = {}
nonpkgoutfiles = {}

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
        outfiles[name] = json.dumps(allfiles[name])
        simplefiles[name] = oct(stat.S_IMODE(allfiles[name]['mode']))

    if distrodict['flavor'] == "RHEL":
        # rpm file check
        match, nonmatch = rpm_check_file_membership_from_path(unpackdir, allfiles=allfiles)
        for f in nonmatch:
            nonpkgoutfiles[f] = 'NOTPKGED'
    elif distrodict['flavor'] == "DEB":
        # dpkg file check
        match, nonmatch = dpkg_check_file_membership_from_path(unpackdir, allfiles=allfiles)
        for f in nonmatch:
            nonpkgoutfiles[f] = 'NOTPKGED'

except Exception as err:
    import traceback
    traceback.print_exc()
    raise err

if simplefiles:
    ofile = os.path.join(outputdir, 'files.all')
    anchore.anchore_utils.write_kvfile_fromdict(ofile, simplefiles)

if outfiles:
    ofile = os.path.join(outputdir, 'files.allinfo')
    anchore.anchore_utils.write_kvfile_fromdict(ofile, outfiles)
if nonpkgoutfiles:
    ofile = os.path.join(outputdir, 'files.nonpkged')
    anchore.anchore_utils.write_kvfile_fromdict(ofile, nonpkgoutfiles)

sys.exit(0)
