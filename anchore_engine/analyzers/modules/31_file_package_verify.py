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
import copy

import anchore.anchore_utils

def apk_get_file_package_metadata(unpackdir, record_template):
    # derived from alpine apk checksum logic
    # 
    # a = "Q1XxRCAhhQ6eotekmwp6K9/4+DLwM="
    # sha1sum = a[2:].decode('base64').encode('hex')
    # 

    result = {}
    
    apkdbpath = os.path.join(unpackdir, 'rootfs', 'lib', 'apk', 'db', 'installed')
    try:
        if os.path.exists(apkdbpath):
            buf = None
            try:
                with open(apkdbpath, 'r') as FH:
                    buf = FH.read()

            except Exception as err:
                buf = None
                print "WARN: cannot read apk DB file - exception: " + str(err)

            if buf:
                fmode = raw_csum = uid = gid = sha1sum = fname = therealfile_apk = therealfile_fs = None
                for line in buf.splitlines():
                    line = line.strip().decode('utf8')
                    patt = re.match("(.):(.*)", line)
                    if patt:
                        atype = patt.group(1)
                        aval = patt.group(2)

                        if atype == 'P':
                            pkg = aval
                        elif atype == 'F':
                            fpath = aval
                        elif atype == 'R':
                            fname = aval
                        elif atype == 'a':
                            vvals = aval.split(":")
                            try:
                                uid = vvals[0]
                            except:
                                uid = None
                            try:
                                gid = vvals[1]
                            except:
                                gid = None
                            try:
                                fmode = vvals[2]
                            except:
                                fmode = None
                        elif atype == 'Z':
                            raw_csum = aval
                            fname = '/'.join(['/'+fpath, fname])
                            therealfile_apk = re.sub("\/+", "/", '/'.join([unpackdir, 'rootfs', fname]))
                            therealfile_fs = os.path.realpath(therealfile_apk)
                            if therealfile_apk == therealfile_fs:
                                try:
                                    sha1sum = raw_csum[2:].decode('base64').encode('hex')
                                except:
                                    sha1sum = None
                            else:
                                sha1sum = None

                            if fmode:
                                fmode = fmode.zfill(4)

                            if fname not in result:
                                result[fname] = []

                            el = copy.deepcopy(record_template)
                            el.update({"package": pkg or None, "digest": sha1sum or None, "digestalgo": "sha1", "mode": fmode or None, "group": gid or None, "user": uid or None})
                            result[fname].append(el)                                
                            fmode = raw_csum = uid = gid = sha1sum = fname = therealfile_apk = therealfile_fs = None

    except Exception as err:
        import traceback
        traceback.print_exc()
        raise Exception("WARN: could not parse apk DB file, looking for file checksums - exception: " + str(err))

    return(result)

def deb_get_file_package_metadata(unpackdir, record_template):

    result = {}
    conffile_csums = {}
    statuspath = os.path.join(unpackdir, "rootfs", "var", "lib", "dpkg", "status")

    try:
        if os.path.exists(statuspath):
            buf = None
            try:
                with open(statuspath, 'r') as FH:
                    buf = FH.read()
            except Exception as err:
                buf = None
                print "WARN: cannot read status file - exception: " + str(err)

            if buf:
                for line in buf.splitlines():
                    line = line.strip().decode('utf8')
                    if re.match("^Conffiles:.*", line):
                        fmode = True
                    elif re.match("^.*:.*", line):
                        fmode = False
                    else:
                        if fmode:
                            try:
                                (fname, csum) = line.split()
                                conffile_csums[fname] = csum
                            except Exception as err:
                                print "WARN: bad line in status for conffile line - exception: " + str(err)

    except Exception as err:
        raise Exception("WARN: could not parse dpkg status file, looking for conffiles checksums - exception: " + str(err))

    metafiles = {}
    conffiles = {}
    metapath = os.path.join(unpackdir, "rootfs", "var", "lib", "dpkg", "info")
    try:
        if os.path.exists(metapath):
            for f in os.listdir(metapath):
                patt = re.match("(.*)\.md5sums", f)
                if patt:
                    pkgraw = patt.group(1)
                    patt = re.match("(.*):.*", pkgraw)
                    if patt:
                        pkg = patt.group(1)
                    else:
                        pkg = pkgraw

                    metafiles[pkg] = os.path.join(metapath, f)

                patt = re.match("(.*)\.conffiles", f)
                if patt:
                    pkgraw = patt.group(1)
                    patt = re.match("(.*):.*", pkgraw)
                    if patt:
                        pkg = patt.group(1)
                    else:
                        pkg = pkgraw
                        
                    conffiles[pkg] = os.path.join(metapath, f)
        else:
            raise Exception("no dpkg info path found in image: " + str(metapath))

        for pkg in metafiles.keys():
            dinfo = None
            try:
                with open(metafiles[pkg], 'r') as FH:
                    dinfo = FH.read()
            except Exception as err:
                print "WARN: could not open/read metafile - exception: " + str(err)

            if dinfo:
                for line in dinfo.splitlines():
                    line = line.strip().decode('utf8')
                    try:
                        (csum, fname) = line.split()
                        fname = '/' + fname
                        fname = re.sub("\/\/", "\/", fname)

                        if fname not in result:
                            result[fname] = []

                        el = copy.deepcopy(record_template)
                        el.update({"package": pkg or None, "digest": csum or None, "digestalgo": "md5", "conffile": False})
                        result[fname].append(el)
                    except Exception as err:
                        print "WARN: problem parsing line from dpkg info file - exception: " + str(err)

        for pkg in conffiles.keys():
            cinfo = None
            try:
                with open(conffiles[pkg], 'r') as FH:
                    cinfo = FH.read()
            except Exception as err:
                cinfo = None
                print "WARN: could not open/read conffile - exception: " + str(err)

            if cinfo:
                for line in cinfo.splitlines():
                    line = line.strip().decode('utf8')
                    try:
                        fname = line
                        if fname in conffile_csums:
                            csum = conffile_csums[fname]
                            if fname not in result:
                                result[fname] = []
                            el = copy.deepcopy(record_template)
                            el.update({"package": pkg or None, "digest": csum or None, "digestalgo": "md5", "conffile": True})
                            result[fname].append(el)
                    except Exception as err:
                        print "WARN: problem parsing line from dpkg conffile file - exception: " + str(err)

    except Exception as err:
        raise Exception("WARN: could not find/parse dpkg info metadata files - exception: " + str(err))

    return(result)

def rpm_get_file_package_metadata(unpackdir, record_template):
    # derived from rpm source code rpmpgp.h
    rpm_digest_algo_map = {
        1: 'md5',
        2: 'sha1',
        3: 'ripemd160',
        5: 'md2',
        6: 'tiger192',
        7: 'haval5160',
        8: 'sha256',
        9: 'sha384',
        10: 'sha512',
        11: 'sha224'
    }

    result = {}

    try:
        rpmdbdir = anchore.anchore_utils.rpm_prepdb(unpackdir)
    except:
        rpmdbdir = os.path.join(unpackdir, 'rootfs', 'var', 'lib', 'rpm')

    cmdstr = 'rpm --dbpath='+rpmdbdir+' -qa --queryformat "[%{FILENAMES}|ANCHORETOK|%{FILEDIGESTS}|ANCHORETOK|%{FILEMODES:octal}|ANCHORETOK|%{FILEGROUPNAME}|ANCHORETOK|%{FILEUSERNAME}|ANCHORETOK|%{FILESIZES}|ANCHORETOK|%{=NAME}|ANCHORETOK|%{FILEFLAGS:fflags}|ANCHORETOK|%{=FILEDIGESTALGO}\\n]"'
    cmd = cmdstr.split()
    print cmdstr
    try:
        pipes = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        o, e = pipes.communicate()
        exitcode = pipes.returncode
        soutput = o
        serror = e

        if exitcode == 0:
            for l in soutput.splitlines():
                l = l.strip().decode('utf8')
                if l:
                    try:
                        (fname, fdigest, fmode, fgroup, fuser, fsize, fpackage, fflags, fdigestalgonum)= l.split("|ANCHORETOK|")
                        fname = re.sub('""', '', fname)
                        cfile = False
                        if 'c' in str(fflags):
                            cfile = True

                        try:
                            fdigestalgo = rpm_digest_algo_map[int(fdigestalgonum)]
                        except:
                            fdigestalgo = 'unknown'

                        if fname not in result:
                            result[fname] = []
                            
                        el = copy.deepcopy(record_template)
                        el.update({'digest': fdigest or None, 'digestalgo': fdigestalgo or None, 'mode': fmode or None, 'group': fgroup or None, 'user': fuser or None, 'size': fsize or None, 'package': fpackage or None, 'conffile': cfile})
                        result[fname].append(el)
                    except Exception as err:
                        print "WARN: unparsable output line - exception: " + str(err)
        else:
            raise Exception("rpm file metadata command failed with exitcode ("+str(exitcode)+") - stdoutput: " + str(soutput) + " : stderr: " + str(serror))

    except Exception as err:
        raise Exception("WARN: distro package metadata gathering failed - exception: " + str(err))

    return(result)

analyzer_name = "file_package_verify"

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
flavor = distrodict['flavor']

# gather file metadata from installed packages

record = {'digest': None, 'digestalgo': None, 'mode': None, 'group': None, 'user': None, 'size': None, 'package': None, 'conffile': False}
result = {}
resultlist = {}

try:
    if flavor == "RHEL":
        try:
            result = rpm_get_file_package_metadata(unpackdir, record)
        except Exception as err:
            raise Exception("ERROR: " + str(err))

    elif flavor == 'DEB':
        try:
            result = deb_get_file_package_metadata(unpackdir, record)
        except Exception as err:
            raise Exception("ERROR: " + str(err))

    elif flavor == 'ALPINE':
        try:
            result = apk_get_file_package_metadata(unpackdir, record)
        except Exception as err:
            raise Exception("ERROR: " + str(err))

    else:
        # do nothing, flavor not supported for getting metadata about files from pkg manager
        pass
except Exception as err:
    print "WARN: analyzer unable to complete - exception: " + str(err)
    result = {}
    resultline = {}

if result:
    for f in result.keys():
        try:
            resultlist[f] = json.dumps(result[f], sort_keys=True)
        except Exception as err:
            print "WARN: " + str(err)
            resultlist[f] = ""

if resultlist:
    ofile = os.path.join(outputdir, 'distro.pkgfilemeta')
    anchore.anchore_utils.write_kvfile_fromdict(ofile, resultlist)

# now run the distro package verifier, if present

verify_result = {}
try:
    vhash, vcmd, voutput, verror, vexitcode = anchore.anchore_utils.verify_file_packages(unpackdir, flavor)
    if vcmd:
        verify_result = {
            'cmd': vcmd,
            'exitcode': vexitcode,
            'cmd_output': voutput,
            'cmd_error': verror
        }
    
except Exception as err:
    print "WARN: could not run distro package verifier - exception: " + str(err)
    verify_result = {}

if verify_result:
    verify_output = {'distroverify': json.dumps(verify_result)}
    ofile = os.path.join(outputdir, 'distro.verifyresult')
    anchore.anchore_utils.write_kvfile_fromdict(ofile, verify_output)
    
sys.exit(0)
