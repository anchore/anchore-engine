import os
import shutil
import re
import subprocess
import hashlib
import yaml
import traceback
import random
import json
import tarfile
import copy

import anchore_engine.utils

from stat import *

def init_analyzer_cmdline(argv, name):
    ret = {}

    if len(argv) < 5:
        print("ERROR: invalid input")
        raise Exception

    configdir = argv[1]

    anchore_conf = {
        'config_dir': configdir,
    }

    ret['analyzer_config'] = None
    anchore_analyzer_configfile = '/'.join([anchore_conf.get('config_dir', '/config'), 'analyzer_config.yaml'])
    if os.path.exists(anchore_analyzer_configfile):
        try:
            with open(anchore_analyzer_configfile, 'r') as FH:
                anchore_analyzer_config = yaml.safe_load(FH.read())
        except Exception as err:
            print("ERROR: could not parse the analyzer_config.yaml - exception: " + str(err))
            raise err

        if anchore_analyzer_config and name in anchore_analyzer_config:
            ret['analyzer_config'] = anchore_analyzer_config[name]

    ret['name'] = name

    with open(argv[0], 'r') as FH:
        ret['selfcsum'] = hashlib.md5(FH.read().encode('utf-8')).hexdigest()

    ret['imgid'] = argv[2]

    # Removed by zhill since discover_imageId not migrated from anchore repo
    # try:
    #     fullid = discover_imageId(argv[2])
    # except:
    #fullid = None

    #if fullid:
    #    ret['imgid_full'] = fullid
    #else:
    ret['imgid_full'] = ret['imgid']

    ret['dirs'] = {}
    ret['dirs']['datadir'] = argv[3]
    ret['dirs']['outputdir'] = '/'.join([argv[4], "analyzer_output", name])
    ret['dirs']['unpackdir'] = argv[5]

    for d in list(ret['dirs'].keys()):
        if not os.path.isdir(ret['dirs'][d]):
            try:
                os.makedirs(ret['dirs'][d])
            except Exception as err:
                print("ERROR: cannot find/create input dir '"+ret['dirs'][d]+"'")
                raise err

    return ret

def _default_member_function(tfl, member, a, t=None):
    print ("{} {} - {}".format(a, t, member.name))

def run_tarfile_member_function(tarfilename, *args, member_regexp=None, func=_default_member_function, **kwargs):
    if not os.path.exists(tarfilename):
        raise ValueError("input tarfile {} not found - exception: {}".format(tarfilename, err))

    if member_regexp:
        memberpatt = re.compile(member_regexp)
    else:
        memberpatt = None

    ret = {}
    with tarfile.open(tarfilename, mode='r', format=tarfile.PAX_FORMAT) as tfl:
        memberhash = get_memberhash(tfl)
        kwargs['memberhash'] = memberhash
        #for member in tfl.getmembers():
        for member in list(memberhash.values()):
            if not memberpatt or memberpatt.match(member.name):
                if ret.get(member.name):
                    print("WARN: duplicate member name when preparing return from run_tarfile_member_function() - {}".format(member.name))

                ret[member.name] = func(tfl, member, *args, **kwargs)

    return ret

def run_tarfile_function(tarfile, func=None, *args, **kwargs):

    if not os.path.exists(tarfile):
        raise ValueError("input tarfile not found - exception: {}".format(err))

    ret = None
    with tarfile.open(tarfile, mode='r', format=tarfile.PAX_FORMAT) as tfl:
        ret = func(tfl, *args, **kwargs)

    return ret

def _search_tarfilenames_for_file(tarfilenames, searchfile):
    ret = None
    if searchfile in tarfilenames:
        ret = searchfile
    elif "./{}".format(searchfile) in tarfilenames:
        ret = "./{}".format(searchfile)
    elif "/{}".format(searchfile) in tarfilenames:
        ret = "/{}".format(searchfile)
    elif re.sub("^/", "", searchfile) in tarfilenames:
        ret = re.sub("^/", "", searchfile)
    return ret

def get_memberhash(tfl):
    memberhash = {}
    for member in tfl.getmembers():
        memberhash[member.name] = member
    return memberhash

def get_distro_from_squashtar(squashtar, unpackdir=None):
    if unpackdir and os.path.exists(os.path.join(unpackdir, 'analyzer_meta.json')):
        with open(os.path.join(unpackdir, 'analyzer_meta.json'), 'r') as FH:
            return json.loads(FH.read())

    meta = {
        'DISTRO':None,
        'DISTROVERS':None,
        'LIKEDISTRO':None
    }

    with tarfile.open(squashtar, mode='r', format=tarfile.PAX_FORMAT) as tfl:
        tarfilenames = tfl.getnames()

        metamap = {
            "os-release": _search_tarfilenames_for_file(tarfilenames, "etc/os-release"),
            "system-release-cpe": _search_tarfilenames_for_file(tarfilenames, "etc/system-release-cpe"),
            "redhat-release": _search_tarfilenames_for_file(tarfilenames, "etc/redhat-release"),
            "busybox": _search_tarfilenames_for_file(tarfilenames, "bin/busybox"),
            "debian_version": _search_tarfilenames_for_file(tarfilenames, "etc/debian_version"),
        }


        success = False
        if not success and metamap['os-release'] in tarfilenames:
            try:
                with tfl.extractfile(tfl.getmember(metamap['os-release'])) as FH:
                    for l in FH.readlines():
                        l = anchore_engine.utils.ensure_str(l)
                        l = l.strip()
                        try:
                            (key, val) = l.split("=")
                            val = re.sub(r'"', '', val)
                            if key == "ID":
                                meta['DISTRO'] = val
                            elif key == "VERSION_ID":
                                meta['DISTROVERS'] = val
                            elif key == "ID_LIKE":
                                meta['LIKEDISTRO'] = ','.join(val.split())
                        except Exception as err:
                            pass
                success = True
            except:
                success = False

        if not success and metamap['system-release-cpe'] in tarfilenames:
            try:
                with tfl.extractfile(tfl.getmember(metamap['system-release-cpe'])) as FH:
                    for l in FH.readlines():
                        l = anchore_engine.utils.ensure_str(l)
                        l = l.strip()
                        try:
                            vendor = l.split(':')[2]
                            distro = l.split(':')[3]
                            vers = l.split(':')[4]

                            if re.match(".*fedora.*", vendor.lower()):
                                distro = 'fedora'
                            elif re.match(".*redhat.*", vendor.lower()):
                                distro = 'rhel'
                            elif re.match(".*centos.*", vendor.lower()):
                                distro = 'centos'

                            meta['DISTRO'] = distro
                            meta['DISTROVERS'] = vers
                        except:
                            pass
                success = True
            except:
                success = False

        if not success and metamap["redhat-release"] in tarfilenames:
            try:
                with tfl.extractfile(tfl.getmember(metamap["redhat-release"])) as FH:
                    for l in FH.readlines():
                        l = anchore_engine.utils.ensure_str(l)
                        l = l.strip()
                        try:
                            distro = vers = None

                            if re.match(".*centos.*", l.lower()):
                                distro = 'centos'
                            elif re.match(".*redhat.*", l.lower()):
                                distro = 'rhel'
                            elif re.match(".*fedora.*", l.lower()):
                                distro = 'fedora'

                            patt = re.match(r".*(\d+\.\d+).*", l)
                            if patt:
                                vers = patt.group(1)

                            if not vers:
                                patt = re.match(r".*(\d+).*", l)
                                if patt:
                                    vers = patt.group(1)

                            if distro:
                                meta['DISTRO'] = distro
                            if vers:
                                meta['DISTROVERS'] = vers
                        except:
                            pass
                success = True
            except:
                success = False

        if not success and metamap["busybox"] in tarfilenames:
            try:
                meta['DISTRO'] = "busybox"
                meta['DISTROVERS'] = "0"
                try:
                    with tfl.extractfile(tfl.getmember(metamap["busybox"])) as FH:
                        for line in FH.readlines():
                            patt = re.match(rb".*BusyBox (v[\d|\.]+) \(.*", line)
                            if patt:
                                meta['DISTROVERS'] = anchore_engine.utils.ensure_str(patt.group(1))
                except Exception as err:
                    meta['DISTROVERS'] = "0"
                success = True
            except:
                success = False

        if meta['DISTRO'] == 'debian' and not meta['DISTROVERS'] and metamap["debian_version"] in tarfilenames:
            try:
                with tfl.extractfile(tfl.getmember(metamap["debian_version"])) as FH:
                    meta['DISTRO'] = 'debian'
                    for line in FH.readlines():
                        line = anchore_engine.utils.ensure_str(line)
                        line = line.strip()
                        patt = re.match(r"(\d+)\..*", line)
                        if patt:
                            meta['DISTROVERS'] = patt.group(1)
                        elif re.match(".*sid.*", line):
                            meta['DISTROVERS'] = 'unstable'
                success = True
            except:
                success = False

    if not meta['DISTRO']:
        meta['DISTRO'] = "Unknown"
    if not meta['DISTROVERS']:
        meta['DISTROVERS'] = "0"
    if not meta['LIKEDISTRO']:
        meta['LIKEDISTRO'] = meta['DISTRO']

    return meta

def grouper(inlist, chunksize):
    return (inlist[pos:pos + chunksize] for pos in range(0, len(inlist), chunksize))


### Metadata helpers

def get_distro_flavor(distro, version, likedistro=None):
    ret = {
        'flavor':'Unknown',
        'version':'0',
        'fullversion':version,
        'distro':distro,
        'likedistro':distro,
        'likeversion':version
    }

    if distro in ['centos', 'rhel', 'redhat', 'fedora']:
        ret['flavor'] = "RHEL"
        ret['likedistro'] = 'centos'
    elif distro in ['debian', 'ubuntu']:
        ret['flavor'] = "DEB"
    elif distro in ['busybox']:
        ret['flavor'] = "BUSYB"
    elif distro in ['alpine']:
        ret['flavor'] = "ALPINE"
    elif distro in ['ol']:
        ret['flavor'] = "RHEL"
        ret['likedistro'] = 'centos'

    if ret['flavor'] == 'Unknown' and likedistro:
        likedistros = likedistro.split(',')
        for distro in likedistros:
            if distro in ['centos', 'rhel', 'fedora']:
                ret['flavor'] = "RHEL"
                ret['likedistro'] = 'centos'
            elif distro in ['debian', 'ubuntu']:
                ret['flavor'] = "DEB"
            elif distro in ['busybox']:
                ret['flavor'] = "BUSYB"
            elif distro in ['alpine']:
                ret['flavor'] = "ALPINE"
            elif distro in ['ol']:
                ret['flavor'] = "RHEL"
                ret['likedistro'] = 'centos'

            if ret['flavor'] != 'Unknown':
                break

    patt = re.match(r"(\d*)\.*(\d*)", version)
    if patt:
        (vmaj, vmin) = patt.group(1,2)
        if vmaj:
            ret['version'] = vmaj
            ret['likeversion'] = vmaj

    patt = re.match(r"(\d+)\.*(\d+)\.*(\d+)", version)
    if patt:
        (vmaj, vmin, submin) = patt.group(1,2,3)
        if vmaj and vmin:
            ret['version'] = vmaj + "." + vmin
            ret['likeversion'] = vmaj + "." + vmin

    return ret

def _get_extractable_member(tfl, member, deref_symlink=False, alltfiles={}, memberhash={}):
    ret = None

    if member.isreg():
        return member

    if not memberhash:
        memberhash = get_memberhash(tfl)

    if deref_symlink and member.issym():
        if not alltfiles:
            alltfiles = {}
            alltnames = tfl.getnames()
            for f in alltnames:
                alltfiles[f] = True

        max_links=128
        done=False
        count=0
        namehistory = [member.name]
        nmember = member

        while not done and count < max_links:
            newmember = None

            # attempt to get the softlink destination
            if nmember.linkname[1:] in alltfiles:
                #newmember = tfl.getmember(nmember.linkname[1:])
                newmember = memberhash.get(nmember.linkname[1:])
            else:
                if nmember.linkname in alltfiles:
                    #newmember = tfl.getmember(nmember.linkname)
                    newmember = memberhash.get(nmember.linkname)
                else:
                    normpath = os.path.normpath(os.path.join(os.path.dirname(nmember.name), nmember.linkname))
                    if normpath in alltfiles:
                        #newmember = tfl.getmember(normpath)
                        newmember = memberhash.get(normpath)

            if not newmember:
                print("skipping file: looking for symlink destination for symlink file {} -> {}".format(member.name, member.linkname))
                done=True
            else:
                nmember = newmember

                if nmember.issym():
                    if nmember.name not in namehistory:
                        # do it all again
                        namehistory.append(nmember.name)
                    else:
                        done=True
                else:
                    if not nmember.isfile():
                        nmember = None
                    done=True
            count = count + 1

        if nmember and nmember.isreg():
            ret = nmember
        else:
            ret = None

    elif member.islnk():
        max_links=128
        done = False
        nmember = member
        count = 0
        namehistory = [member.name]

        while not done and count < max_links:
            try:
                #nmember = tfl.getmember(nmember.linkname)
                nmember = memberhash.get(nmember.linkname)
                if nmember.islnk():
                    if nmember.name not in namehistory:
                        # do it all again
                        namehistory.append(nmember.name)
                    else:
                        done=True
                else:
                    if not nmember.isreg():
                        nmember = None
                    done = True
            except Exception as err:
                print("WARN: exception while looking for hardlink destination for hardlink file {} - exception: {}".format(member.name, err))
                nmember = None
                done=True
            count = count + 1

        if nmember and nmember.isreg():
            ret = nmember
        else:
            ret = None

    return ret

def _checksum_member_function(tfl, member, csums=['sha256', 'md5'], memberhash={}):
    ret = {}

    funcmap = {
        'sha256': hashlib.sha256,
        'sha1': hashlib.sha1,
        'md5': hashlib.md5,
    }
    if member.isreg():
        extractable_member = member
    elif member.islnk():
        if not memberhash:
            memberhash = get_memberhash(tfl)
        extractable_member = _get_extractable_member(tfl, member, memberhash=memberhash)
    else:
        extractable_member = None

    for ctype in csums:
        if extractable_member:
            with tfl.extractfile(extractable_member) as mfd:
                ret[ctype] = funcmap[ctype](mfd.read()).hexdigest()
        else:
            ret[ctype] = "DIRECTORY_OR_OTHER"

    return ret

def get_checksums_from_squashtar(squashtar, csums=['sha256', 'md5']):
    allfiles = {}

    funcmap = {
        'sha256': hashlib.sha256,
        'sha1': hashlib.sha1,
        'md5': hashlib.md5,
    }

    try:
        results = anchore_engine.analyzers.utils.run_tarfile_member_function(squashtar, func=_checksum_member_function, csums=csums)
        for filename in results.keys():
            fkey = filename
            if not fkey or fkey[0] != '/':
                fkey = "/{}".format(filename)
            if fkey not in allfiles:
                allfiles[fkey] = results[filename]
    except Exception as err:
        print("EXC: {}".format(err))

    return allfiles

def get_files_from_squashtar(squashtar, unpackdir=None):

    filemap = {}
    allfiles = {}

    tfl = None
    try:
        with tarfile.open(squashtar, mode='r', format=tarfile.PAX_FORMAT) as tfl:
            memberhash = get_memberhash(tfl)
            #for member in tfl.getmembers():
            for member in list(memberhash.values()):
                filename = member.name
                filename = re.sub(r"^\./", "/", filename)
                if not filename:
                    filename = "/"
                if not re.match("^/", filename):
                    filename = "/{}".format(filename)

                finfo = {}
                finfo['name'] = filename
                finfo['fullpath'] = filename
                finfo['size'] = member.size
                #finfo['mode'] = member.mode
                modemask = 0o00000000
                if member.issym():
                    modemask = 0o00120000
                elif member.isfile() or member.islnk():
                    modemask = 0o00100000
                elif member.isblk():
                    modemask = 0o00060000
                elif member.isdir():
                    modemask = 0o00040000
                elif member.ischr():
                    modemask = 0o00020000
                elif member.isfifo():
                    modemask = 0o00010000

                #finfo['mode'] = int(oct(member.mode + 32768), 8)
                finfo['mode'] = int(oct(modemask | member.mode), 8)

                finfo['uid'] = member.uid
                finfo['gid'] = member.gid

                finfo['linkdst'] = None
                finfo['linkdst_fullpath'] = None
                if member.isfile():
                    finfo['type'] = 'file'
                elif member.isdir():
                    finfo['type'] = 'dir'
                elif member.issym():
                    finfo['type'] = 'slink'
                    finfo['linkdst'] = member.linkname
                    finfo['size'] = len(finfo['linkdst'])
                elif member.isdev():
                    finfo['type'] = 'dev'
                elif member.islnk():
                    finfo['type'] = 'file'
                    extractable_member = _get_extractable_member(tfl, member, memberhash=memberhash)
                    if extractable_member:
                        finfo['size'] = extractable_member.size
                else:
                    finfo['type'] = 'UNKNOWN'

                if finfo['type'] == 'slink':
                    if re.match("^/", finfo['linkdst']):
                        fullpath = finfo['linkdst']
                    else:
                        dstlist = finfo['linkdst'].split('/')
                        srclist = finfo['name'].split('/')
                        srcpath = srclist[0:-1]
                        fullpath = os.path.normpath(os.path.join(finfo['linkdst'], filename))
                    finfo['linkdst_fullpath'] = fullpath

                fullpath = finfo['fullpath']

                finfo['othernames'] = {}
                for f in [fullpath, finfo['linkdst_fullpath'], finfo['linkdst'], finfo['name']]:
                    if f:
                        finfo['othernames'][f] = True

                allfiles[finfo['name']] = finfo

            # first pass, set up the basic file map
            for name in list(allfiles.keys()):
                finfo = allfiles[name]
                finfo['othernames'][name] = True

                filemap[name] = finfo['othernames']
                for oname in finfo['othernames']:
                    filemap[oname] = finfo['othernames']

            # second pass, include second order
            newfmap = {}
            count = 0
            while newfmap != filemap or count > 5:
                count += 1
                filemap.update(newfmap)
                newfmap.update(filemap)
                for mname in list(newfmap.keys()):
                    for oname in list(newfmap[mname].keys()):
                        newfmap[oname].update(newfmap[mname])
    except Exception as err:
        print ("EXC: {}".format(err))

    return filemap, allfiles


### Package helpers

def rpm_get_all_packages_from_squashtar(unpackdir, squashtar):
    rpms = {}

    rpm_db_base_dir = rpm_prepdb_from_squashtar(unpackdir, squashtar)
    rpmdbdir = os.path.join(rpm_db_base_dir, "var", "lib", "rpm")

    try:
        sout = subprocess.check_output(['rpm', '--dbpath='+rpmdbdir, '--queryformat', '%{NAME} %{VERSION} %{RELEASE} %{ARCH}\n', '-qa'], stderr=subprocess.STDOUT)
        for l in sout.splitlines():
            l = l.strip()
            l = str(l, 'utf-8')
            #l = l.decode('utf8')
            (name, vers, rel, arch) = re.match(r'(\S*)\s*(\S*)\s*(\S*)\s*(.*)', l).group(1, 2, 3, 4)
            rpms[name] = {'version':vers, 'release':rel, 'arch':arch}
    except Exception as err:
        print(err.output)
        raise ValueError("could not get package list from RPM database: " + str(err))

    return rpms, rpmdbdir

def rpm_get_all_pkgfiles(unpackdir):
    rpmfiles = {}
    rpmdbdir = unpackdir

    try:
        sout = subprocess.check_output(['rpm', '--dbpath='+rpmdbdir, '-qal'])
        for l in sout.splitlines():
            l = l.strip()
            l = str(l, 'utf-8')
            #l = l.decode('utf8')
            rpmfiles[l] = True
    except Exception as err:
        raise ValueError("could not get file list from RPM database: " + str(err))

    return rpmfiles

def rpm_get_all_packages_detail_from_squashtar(unpackdir, squashtar):
    rpms = {}

    rpm_db_base_dir = rpm_prepdb_from_squashtar(unpackdir, squashtar)
    rpmdbdir = os.path.join(rpm_db_base_dir, "var", "lib", "rpm")

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

    try:
        hints = get_hintsfile(unpackdir, squashtar)
        for pkg in hints.get('packages', []):
            if pkg.get('type', "").lower() == 'rpm':
                try:
                    el = _hints_to_rpm(pkg)
                    rpms.update(el)                    
                except Exception as err:
                    print ("WARN: could not convert hints package to valid RPM analyzer output - exception: {}".format(err))
    except Exception as err:
        print ("WARN: problem honoring hints file - exception: {}".format(err))                                

                    
    return rpms, rpmdbdir


def _hints_to_rpm(pkg):
    pkg_type = 'rpm'
    pkg_name = anchore_engine.utils.ensure_str(pkg.get('name', ""))
    pkg_version = anchore_engine.utils.ensure_str(pkg.get('version', ""))
    pkg_arch = anchore_engine.utils.ensure_str(pkg.get('arch', 'x86_64'))
    pkg_release = anchore_engine.utils.ensure_str(pkg.get('release', ""))
    pkg_source = anchore_engine.utils.ensure_str(pkg.get('source', ""))
    pkg_origin = anchore_engine.utils.ensure_str(pkg.get('origin', ""))
    pkg_license = anchore_engine.utils.ensure_str(pkg.get('license', ""))
    pkg_size = anchore_engine.utils.ensure_str(str(pkg.get('size', "0")))

    if not pkg_name or not pkg_version or not pkg_type:
        raise Exception("bad hints record, all hints records must supply at least a name, version and type")
    if not pkg_release or not pkg_source:
        from anchore_engine.util.rpm import split_rpm_filename
        p_name, p_parsed_version, p_release, p_epoch, p_arch = split_rpm_filename("{}-{}.{}.rpm".format(pkg_name, pkg_version, pkg_arch))
        if pkg_name == p_parsed_version:
            raise Exception("hints package version for hints package ({}) is not valid for RPM package type".format(pkg_name))
    
        pkg_version = p_parsed_version

        if p_epoch:
            pkg_version = "{}:{}".format(p_epoch, p_parsed_version)

        pkg_release = p_release

        if p_arch:
            pkg_arch = p_arch

        if pkg_source:
            pkg_source = "{}-{}.{}.rpm".format(pkg_source, pkg_version, 'src')
        else:
            pkg_source = "{}-{}-{}.{}.rpm".format(pkg_name, pkg_version, pkg_release, 'src')            

    pkg_type = 'rpm'
    if pkg_arch == 'amd64':
        pkg_arch = 'x86_64'

    el = {
        pkg_name: {
            'version': pkg_version,
            'release': pkg_release,
            'arch': pkg_arch,
            'size': pkg_size,
            'license': pkg_license,
            'sourcepkg': pkg_source,
            'origin': pkg_origin,
            'type': 'rpm',                                                
        }
    }
    return el

def _hints_to_python(pkg):
    pkg_type = anchore_engine.utils.ensure_str(pkg.get('type', "python")).lower()    
    pkg_name = anchore_engine.utils.ensure_str(pkg.get('name', ""))
    pkg_version = anchore_engine.utils.ensure_str(pkg.get('version', ""))
    pkg_location = anchore_engine.utils.ensure_str(pkg.get('location', ""))
    pkg_license = anchore_engine.utils.ensure_str(pkg.get('license', ""))
    pkg_origin = anchore_engine.utils.ensure_str(pkg.get('origin', ""))
    pkg_files = pkg.get('files', [])
    pkg_metadata = json.dumps(pkg.get('metadata', {}))
    
    if not pkg_name or not pkg_version or not pkg_type:
        raise Exception("bad hints record, all hints records must supply at least a name, version and type")
    for inp in [pkg_files]:
        if type(inp) is not list:
            raise Exception("bad hints record ({}), versions, licenses, origins, and files if specified must be list types".format(pkg_name))
        
    if not pkg_location:
        pkg_location = "/virtual/pypkg/site-packages"
        pkg_key = "{}/{}-{}".format(pkg_location, pkg_name, pkg_version)
    else:
        pkg_key = "{}/{}".format(pkg_location, pkg_name)

    el = {
        'name': pkg_name,
        'version': pkg_version,
        'origin': pkg_origin,
        'license': pkg_license,
        'location': pkg_location,
        'metadata': pkg_metadata,
        'files': pkg_files,
        'type': pkg_type
    }
    return pkg_key, el

def _hints_to_go(pkg):
    pkg_type = anchore_engine.utils.ensure_str(pkg.get('type', "go")).lower()    
    pkg_name = anchore_engine.utils.ensure_str(pkg.get('name', ""))
    pkg_version = anchore_engine.utils.ensure_str(pkg.get('version', ""))
    pkg_location = anchore_engine.utils.ensure_str(pkg.get('location', "/virtual/gopkg/{}-{}".format(pkg_name, pkg_version)))
    pkg_license = anchore_engine.utils.ensure_str(pkg.get('license', ""))
    pkg_origin = anchore_engine.utils.ensure_str(pkg.get('origin', ""))
    pkg_source = anchore_engine.utils.ensure_str(pkg.get('source', pkg_name))
    pkg_arch = anchore_engine.utils.ensure_str(pkg.get('arch', "x86_64"))
    pkg_size = anchore_engine.utils.ensure_str(str(pkg.get('size', "0")))
    pkg_metadata = json.dumps(pkg.get('metadata', {}))

    if not pkg_name or not pkg_version or not pkg_type:
        raise Exception("bad hints record, all hints records must supply at least a name, version and type")
    
    el = {
        'name': pkg_name,
        'version': pkg_version,
        'arch': pkg_arch,
        'sourcepkg': pkg_source,
        'origin': pkg_origin,
        'license': pkg_license,
        'location': pkg_location,
        'size': pkg_size,
        'metadata': pkg_metadata,
        'type': pkg_type
    }

    return pkg_location, el    
    
def _hints_to_binary(pkg):
    pkg_type = anchore_engine.utils.ensure_str(pkg.get('type', "binary")).lower()    
    pkg_name = anchore_engine.utils.ensure_str(pkg.get('name', ""))
    pkg_version = anchore_engine.utils.ensure_str(pkg.get('version', ""))
    pkg_location = anchore_engine.utils.ensure_str(pkg.get('location', "/virtual/binarypkg/{}-{}".format(pkg_name, pkg_version)))
    pkg_license = anchore_engine.utils.ensure_str(pkg.get('license', ""))
    pkg_origin = anchore_engine.utils.ensure_str(pkg.get('origin', ""))
    pkg_files = pkg.get('files', [])
    pkg_metadata = json.dumps(pkg.get('metadata', {}))

    if not pkg_name or not pkg_version or not pkg_type:
        raise Exception("bad hints record, all hints records must supply at least a name, version and type")
    for inp in [pkg_files]:
        if type(inp) is not list:
            raise Exception("bad hints record ({}), versions, licenses, origins, and files if specified must be list types".format(pkg_name))
    el = {
        'name': pkg_name,
        'version': pkg_version,
        'origin': pkg_origin,
        'license': pkg_license,
        'location': pkg_location,
        'files': pkg_files,
        'metadata': pkg_metadata,
        'type': pkg_type
    }

    return pkg_location, el

def get_hintsfile(unpackdir, squashtar):
    ret = {}
    if os.path.exists(os.path.join(unpackdir, "anchore_hints.json")):
        with open(os.path.join(unpackdir, "anchore_hints.json"), 'r') as FH:
            try:
                ret = json.loads(FH.read())
            except Exception as err:
                print ("WARN: hintsfile found unpacked, but cannot be read - exception: {}".format(err))
                ret = {}
    else:
        with tarfile.open(squashtar, mode='r', format=tarfile.PAX_FORMAT) as tfl:
            memberhash = anchore_engine.analyzers.utils.get_memberhash(tfl)
            hints_member = None
            for hintsfile in ['anchore_hints.json', '/anchore_hints.json']:
                if hintsfile in memberhash:
                    hints_member = memberhash[hintsfile]

            if hints_member:
                try:
                    with tfl.extractfile(hints_member) as FH:
                        ret = json.loads(FH.read())
                except Exception as err:
                    print ("WARN: hintsfile found in squashtar, but cannot be read - exception: {}".format(err))
                    ret = {}
            else:
                ret = {}

    if ret and not os.path.exists(os.path.join(unpackdir, "anchore_hints.json")):
        with open(os.path.join(unpackdir, "anchore_hints.json"), 'w') as OFH:
            OFH.write(json.dumps(ret))
            
    return ret

def make_anchoretmpdir(tmproot):
    tmpdir = '/'.join([tmproot, str(random.randint(0, 9999999)) + ".anchoretmp"])
    try:
        os.makedirs(tmpdir)
        return tmpdir
    except:
        return False

    
def java_prepdb_from_squashtar(unpackdir, squashtar, java_file_regexp):
    javatmpdir = os.path.join(unpackdir, "javatmp")
    if not os.path.exists(javatmpdir):
        try:
            os.makedirs(javatmpdir)
        except Exception as err:
            raise err

    ret = os.path.join(javatmpdir, "rootfs")
    javafilepatt = re.compile(java_file_regexp)

    if not os.path.exists(os.path.join(ret)):
        with tarfile.open(squashtar, mode='r', format=tarfile.PAX_FORMAT) as tfl:
            javamembers = []
            for member in tfl.getmembers():
                filename = member.name
                if javafilepatt.match(filename): #re.match(java_file_regexp, filename):
                    javamembers.append(member)

            tfl.extractall(path=os.path.join(javatmpdir, "rootfs"), members=javamembers)
        ret = os.path.join(javatmpdir, "rootfs")

    return ret

def python_prepdb_from_squashtar(unpackdir, squashtar, py_file_regexp):
    pytmpdir = os.path.join(unpackdir, "pytmp")
    if not os.path.exists(pytmpdir):
        try:
            os.makedirs(pytmpdir)
        except Exception as err:
            raise err

    ret = os.path.join(pytmpdir, "rootfs")

    pyfilepatt = re.compile(py_file_regexp)

    if not os.path.exists(os.path.join(ret)):
        candidates = {}
        with tarfile.open(squashtar, mode='r', format=tarfile.PAX_FORMAT) as tfl:
            pymembers = []
            for filename in tfl.getnames():
                if pyfilepatt.match(filename):
                    candidate = os.path.dirname(filename)
                    if candidate not in candidates:
                        candidates[candidate] = True

            for member in tfl.getmembers():
                if member.isfile() or member.isdir():
                    filename = member.name
                    for candidate in candidates.keys():
                        if filename == candidate or filename.startswith(candidate):
                            pymembers.append(member)
                            break

            tfl.extractall(path=os.path.join(pytmpdir, "rootfs"), members=pymembers)
        ret = os.path.join(pytmpdir, "rootfs")

    return ret

def apk_prepdb_from_squashtar(unpackdir, squashtar):
    apktmpdir = os.path.join(unpackdir, "apktmp")
    if not os.path.exists(apktmpdir):
        try:
            os.makedirs(apktmpdir)
        except Exception as err:
            raise err

    ret = os.path.join(apktmpdir, "rootfs")

    if not os.path.exists(os.path.join(ret, 'lib', 'apk', 'db', 'installed')):
        with tarfile.open(squashtar, mode='r', format=tarfile.PAX_FORMAT) as tfl:
            tarfilenames = tfl.getnames()
            apkdbfile = _search_tarfilenames_for_file(tarfilenames, "lib/apk/db/installed")

            apkmembers = []
            apkmembers.append(tfl.getmember(apkdbfile))
            tfl.extractall(path=os.path.join(apktmpdir, "rootfs"), members=apkmembers)
        ret = os.path.join(apktmpdir, "rootfs")

    return ret

def dpkg_prepdb_from_squashtar(unpackdir, squashtar):
    dpkgtmpdir = os.path.join(unpackdir, "dpkgtmp")
    if not os.path.exists(dpkgtmpdir):
        try:
            os.makedirs(dpkgtmpdir)
        except Exception as err:
            raise err

    ret = os.path.join(dpkgtmpdir, "rootfs")

    if not os.path.exists(os.path.join(ret, "var", "lib", "dpkg")):

        with tarfile.open(squashtar, mode='r', format=tarfile.PAX_FORMAT) as tfl:
            dpkgmembers = []
            for member in tfl.getmembers():
                filename = member.name
                filename = re.sub(r"^\./|^/", "", filename)
                if filename.startswith("var/lib/dpkg") or filename.startswith("usr/share/doc"):
                    dpkgmembers.append(member)
            tfl.extractall(path=os.path.join(dpkgtmpdir, "rootfs"), members=dpkgmembers)

        ret = os.path.join(dpkgtmpdir, "rootfs")

    return ret

def rpm_prepdb_from_squashtar(unpackdir, squashtar):
    rpmtmpdir = os.path.join(unpackdir, "rpmtmp")
    if not os.path.exists(rpmtmpdir):
        try:
            os.makedirs(rpmtmpdir)
        except Exception as err:
            raise err

    ret = os.path.join(rpmtmpdir, "rpmdbfinal")

    if not os.path.exists(os.path.join(ret, "var", "lib", "rpm")):
        with tarfile.open(squashtar, mode='r', format=tarfile.PAX_FORMAT) as tfl:
            rpmmembers = []
            for member in tfl.getmembers():
                filename = member.name
                filename = re.sub(r"^\./|^/", "", filename)
                if filename.startswith("var/lib/rpm"):
                    rpmmembers.append(member)

            tfl.extractall(path=os.path.join(rpmtmpdir, "rootfs"), members=rpmmembers)

        rc = rpm_prepdb(rpmtmpdir)
        ret = os.path.join(rpmtmpdir, "rpmdbfinal") #, "var", "lib", "rpm")

    return ret

def rpm_prepdb(unpackdir):
    origrpmdir = os.path.join(unpackdir, 'rootfs', 'var', 'lib', 'rpm')
    ret = origrpmdir

    print ("prepping rpmdb {}".format(origrpmdir))

    if os.path.exists(origrpmdir):
        newrpmdirbase = os.path.join(unpackdir, "rpmdbfinal")
        if not os.path.exists(newrpmdirbase):
            os.makedirs(newrpmdirbase)
        newrpmdir = os.path.join(newrpmdirbase, 'var', 'lib', 'rpm')
        try:
            shutil.copytree(origrpmdir, newrpmdir)
            sout = subprocess.check_output(['rpmdb', '--root='+newrpmdirbase, '--dbpath=/var/lib/rpm', '--rebuilddb'])
            ret = newrpmdir
        except:
            pass

    return ret

def dpkg_get_all_pkgfiles_from_squashtar(unpackdir, squashtar):
    allfiles = {}

    try:
        (allpkgs, allpkgs_simple, actpkgs, othpkgs, dpkgdbdir) = dpkg_get_all_packages_detail_from_squashtar(unpackdir, squashtar)
        cmd = ["dpkg-query", "--admindir={}".format(os.path.join(unpackdir)), "-L"] + list(actpkgs.keys())
        sout = subprocess.check_output(cmd)
        for l in sout.splitlines():
            l = l.strip()
            l = str(l, 'utf-8')
            #l = l.decode('utf8')
            allfiles[l] = True

    except Exception as err:
        print("Could not run command: " + str(' '.join(cmd)))
        print("Exception: " + str(err))
        print("Please ensure the command 'dpkg' is available and try again")
        raise err

    return allfiles

def dpkg_get_all_packages_detail_from_squashtar(unpackdir, squashtar):
    all_packages = {}
    actual_packages = {}
    all_packages_simple = {}
    other_packages = {}

    dpkg_db_base_dir = dpkg_prepdb_from_squashtar(unpackdir, squashtar)
    dpkgdbdir = os.path.join(dpkg_db_base_dir, "var", "lib", "dpkg")
    dpkgdocsdir = os.path.join(dpkg_db_base_dir, "usr", "share", "doc")
    dpkgstatusddir = os.path.join(dpkg_db_base_dir, "var", "lib", "dpkg", "status.d")

    package_tuples = {}

    cmd = ["dpkg-query", "--admindir={}".format(dpkgdbdir), "-W", "-f="+"${Package}|ANCHORETOK|${Version}|ANCHORETOK|${Architecture}|ANCHORETOK|${Installed-Size}|ANCHORETOK|${source:Package}|ANCHORETOK|${source:Version}|ANCHORETOK|${Maintainer}|ANCHORETOK|${db:Status-Abbrev}\\n"]
    try:
        sout = subprocess.check_output(cmd)
        for l in sout.splitlines(True):
            l = l.strip()
            l = str(l, 'utf-8')
            (p, v, arch, rawsize, sp, sv, vendor, status) = l.split("|ANCHORETOK|")

            if status and not status.startswith("ii"):
                # skip this package if the status is returned, and is not reporting as explicitly installed (ii*)
                continue
            if p not in package_tuples:
                package_tuples[p] = (p,v,arch,rawsize,sp,sv,vendor,status)

    except Exception as err:
        print("Could not run command: {} - exception: {}".format(str(cmd), err))

    try:
        # inspect presence and contents of the status.d directory,
        # which is where distroless container images store information
        # about dpkg software that is installed

        if os.path.exists(dpkgstatusddir):
            for f in os.listdir(dpkgstatusddir):
                with open(os.path.join(dpkgstatusddir, f), 'r') as FH:
                    p = v = vendor = arch = size = sp = sv = status = None
                    for line in FH.readlines():
                        line = line.strip()
                        try:
                            (pk, pv) = line.split(":", 1)
                        except:
                            pk = pv = None

                        if pk == 'Package':
                            p = pv.strip()
                        elif pk == 'Version':
                            v = pv.strip()
                        elif pk == 'Maintainer':
                            vendor = pv.strip()
                        elif pk == 'Architecture':
                            arch = pv.strip()
                        elif pk == 'Installed-Size':
                            rawsize = pv.strip()
                        elif pk == 'Source':
                            sp = pv.strip()
                    if sp and v:
                        sv = v

                    if p not in package_tuples:
                        package_tuples[p] = (p,v,arch,rawsize,sp,sv,vendor,status)

    except Exception as err:
        print ("Could not parse package metadata from {} - exception: {}".format(dpkgstatusddir, err))

    for package_key in package_tuples.keys():
        (p, v, arch, rawsize, sp, sv, vendor, status) = package_tuples[package_key]

        if sp and sv:
            source = "{}-{}".format(sp, sv)
        else:
            source = ""

        try:
            size = str(int(rawsize) * 1000)
        except:
            size = str(0)

        sp = str(sp)
        sv = str(sv)
        vendor = str(vendor) + " (maintainer)"
        arch = str(arch)
        source = str(source)

        try:
            licfile = os.path.join(dpkgdocsdir, p, 'copyright')
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
        
        if p and v:
            if p not in actual_packages:
                actual_packages[p] = {'version':v, 'arch':arch}
            if p not in all_packages_simple:
                all_packages_simple[p] = {'version':v, 'arch':arch}
        if sp and sv:
            if sp not in all_packages_simple:
                all_packages_simple[sp] = {'version':sv, 'arch':arch}
        if p and v and sp and sv:
            if p == sp and v != sv:
                other_packages[p] = [{'version':sv, 'arch':arch}]
    try:
        hints = get_hintsfile(unpackdir, squashtar)
        for pkg in hints.get('packages', []):
            if pkg.get('type', "").lower() == 'dpkg':
                try:
                    el = _hints_to_dpkg(pkg)
                    all_packages.update(el)
                except Exception as err:
                    print ("WARN: could not convert hints package to valid DPKG analyzer output - exception: {}".format(err))
    except Exception as err:
        print ("WARN: problem honoring hints file - exception: {}".format(err))                                
                
    return all_packages, all_packages_simple, actual_packages, other_packages, dpkgdbdir


def _hints_to_dpkg(pkg):
    pkg_type = 'dpkg'    
    pkg_name = anchore_engine.utils.ensure_str(pkg.get('name'))
    pkg_version = anchore_engine.utils.ensure_str(pkg.get('version'))
    pkg_arch = anchore_engine.utils.ensure_str(pkg.get('arch', 'amd64'))
    pkg_release = anchore_engine.utils.ensure_str(pkg.get('release', ""))
    pkg_source = anchore_engine.utils.ensure_str(pkg.get('source', ""))
    pkg_origin = anchore_engine.utils.ensure_str(pkg.get('origin', ""))
    pkg_license = anchore_engine.utils.ensure_str(pkg.get('license', ""))
    pkg_size = anchore_engine.utils.ensure_str(str(pkg.get('size', "0")))

    if not pkg_name or not pkg_version or not pkg_type:
        raise Exception("bad hints record, all hints records must supply at least a name, version and type")
    
    if not pkg_source:
        pkg_source = "{}-{}".format(pkg_name, pkg_version)

    pkg_release = 'N/A'

    el = {
        pkg_name: {
            'version': pkg_version,
            'release': pkg_release,
            'arch': pkg_arch,
            'size': pkg_size,
            'license': pkg_license,
            'sourcepkg': pkg_source,
            'origin': pkg_origin,
            'type': 'dpkg',                             
        }
    }
    return el


def deb_copyright_getlics(licfile):
    ret = {}

    if os.path.exists(licfile):
        found=False
        FH=open(licfile, 'r')
        lictext = FH.read()
        for l in lictext.splitlines():
            l = l.strip()
            m = re.match(r"License: (\S*)", l)
            if m:
                lic = m.group(1)
                if lic:
                    ret[lic] = True
                    found=True
        FH.close()
    return ret

def apkg_parse_apkdb(apkdbfh):
    apkgs = {}
    apkg = {
        'version':"N/A",
        'sourcepkg':"N/A",
        'release':"N/A",
        'origin':"N/A",
        'arch':"N/A",
        'license':"N/A",
        'size':"N/A"
    }
    thename = ""
    thepath = ""
    thefiles = list()
    allfiles = list()

    if True:
        for l in apkdbfh.readlines():
            l = anchore_engine.utils.ensure_str(l)
            l = l.strip()

            if not l:
                apkgs[thename] = apkg
                if thepath:
                    flist = list()
                    for x in thefiles:
                        flist.append(os.path.join(thepath, x))
                    flist.append(os.path.join(thepath))
                    allfiles = allfiles + flist
                apkgs[thename]['files'] = allfiles
                apkg = {
                    'version':"N/A",
                    'sourcepkg':"N/A",
                    'release':"N/A",
                    'origin':"N/A",
                    'arch':"N/A",
                    'license':"N/A",
                    'size':"N/A",
                    'type':"APKG"
                }
                allfiles = list()
                thefiles = list()
                thepath = ""

            patt = re.match(r"(\S):(.*)", l)
            if patt:
                (k, v) = patt.group(1,2)
                apkg['type'] = "APKG"
                if k == 'P':
                    thename = v
                    apkg['name'] = v
                elif k == 'V':
                    vpatt = re.match(r"(\S*)-(\S*)", v)
                    if vpatt:
                        (vers, rel) = vpatt.group(1, 2)
                    else:
                        vers = v
                        rel = "N/A"
                    apkg['version'] = vers
                    apkg['release'] = rel
                elif k == 'm':
                    apkg['origin'] = v
                elif k == 'I':
                    apkg['size'] = v
                elif k == 'L' and v:
                    apkg['license'] = v
                elif k == 'o':
                    apkg['sourcepkg'] = v
                elif k == 'A':
                    apkg['arch'] = v
                elif k == 'F':
                    if thepath:
                        flist = list()
                        for x in thefiles:
                            flist.append(os.path.join(thepath, x))
                        flist.append(os.path.join(thepath))
                        allfiles = allfiles + flist

                    thepath = "/" + v
                    thefiles = list()
                elif k == 'R':
                    thefiles.append(v)

    return apkgs

def apkg_get_all_pkgfiles_from_squashtar(unpackdir, squashtar):
    ret = {}
    with tarfile.open(squashtar, mode='r', format=tarfile.PAX_FORMAT) as tfl:
        try:
            tarfilenames = tfl.getnames()
            apkdbfile = _search_tarfilenames_for_file(tarfilenames, "lib/apk/db/installed")
            member = tfl.getmember(apkdbfile)
            memberfd = tfl.extractfile(member)
            ret = apkg_parse_apkdb(memberfd)
        except Exception as err:
            raise ValueError("cannot locate APK installed DB in squashed.tar - exception: {}".format(err))
    try:
        hints = get_hintsfile(unpackdir, squashtar)
        for pkg in hints.get('packages', []):
            if pkg.get('type', "").lower() == 'apkg':
                try:
                    el = _hints_to_apkg(pkg)
                    ret.update(el)
                except Exception as err:
                    print ("WARN: could not convert hints package to valid APK analyzer output - exception: {}".format(err))
    except Exception as err:
        print ("WARN: problem honoring hints file - exception: {}".format(err))
        
    return ret

def _hints_to_apkg(pkg):
    pkg_type = 'apkg'        
    pkg_name = anchore_engine.utils.ensure_str(pkg.get('name', ""))
    pkg_version = anchore_engine.utils.ensure_str(pkg.get('version', ""))
    pkg_arch = anchore_engine.utils.ensure_str(pkg.get('arch', 'x86_64'))
    pkg_release = anchore_engine.utils.ensure_str(pkg.get('release', ""))
    pkg_source = anchore_engine.utils.ensure_str(pkg.get('source', ""))
    pkg_origin = anchore_engine.utils.ensure_str(pkg.get('origin', ""))
    pkg_license = anchore_engine.utils.ensure_str(pkg.get('license', ""))
    pkg_size = anchore_engine.utils.ensure_str(str(pkg.get('size', "0")))
    pkg_files = pkg.get('files', [])

    if not pkg_name or not pkg_version or not pkg_type:
        raise Exception("bad hints record, all hints records must supply at least a name, version and type")
    for inp in [pkg_files]:
        if type(inp) is not list:
            raise Exception("bad hints record ({}), versions, licenses, origins, and files if specified must be list types".format(pkg_name))    
    
    if not pkg_release:
        try:
            (v, r) = pkg_version.split('-', 2)
        except:
            raise Exception("hints package version for hints package ({}) is not valid for APKG package type".format(pkg_name))            

        pkg_release = r
        pkg_version = v

    if not pkg_source:
        pkg_source = pkg_name

    el = {
        pkg_name: {
            'name': pkg_name,
            'version': pkg_version,
            'release': pkg_release,
            'arch': pkg_arch,
            'size': pkg_size,
            'license': pkg_license,
            'sourcepkg': pkg_source,
            'origin': pkg_origin,
            'files': pkg_files,
            'type': 'APKG',
        }
    }
    return el    

def apkg_get_all_pkgfiles(unpackdir):
    apkdb = '/'.join([unpackdir, 'rootfs/lib/apk/db/installed'])

    if not os.path.exists(apkdb):
        raise ValueError("cannot locate APK installed DB '"+str(apkdb)+"'")

    ret = {}
    with open(apkdb, 'r') as FH:
        ret = apkg_parse_apkdb(FH)

    return ret

def gem_parse_meta(gem):
    ret = {}

    name = None
    versions = []
    lics = []
    latest = None
    origins = []
    sourcepkg = None
    rfiles = []

    try:
        for line in gem.splitlines():
            line = line.strip()
            line = re.sub(r"\.freeze", "", line)

            # look for the unicode \u{} format and try to convert to something python can use
            try:
                replline = line
                mat = "\\\\u{.*?}"
                patt = re.match(r".*("+mat+").*", replline)
                while patt:
                    replstr = ""
                    subpatt = re.match("\\\\u{(.*)}", patt.group(1))
                    if subpatt:
                        chars = subpatt.group(1).split()
                        for char in chars:
                            replstr += chr(int(char, 16))

                    if replstr:
                        replline = re.sub(re.escape(patt.group(1)), replstr, replline, 1)

                    patt = re.match(r".*("+mat+").*", replline)
                    line = replline
            except Exception as err:
                pass

            patt = re.match(r".*\.name *= *(.*) *", line)
            if patt:
                name = json.loads(patt.group(1))

            patt = re.match(r".*\.homepage *= *(.*) *", line)
            if patt:
                sourcepkg = json.loads(patt.group(1))

            patt = re.match(r".*\.version *= *(.*) *", line)
            if patt:
                v = json.loads(patt.group(1))
                latest = v
                versions.append(latest)

            patt = re.match(r".*\.licenses *= *(.*) *", line)
            if patt:
                lstr = re.sub(r"^\[|\]$", "", patt.group(1)).split(',')
                for thestr in lstr:
                    thestr = re.sub(' *" *', "", thestr)
                    lics.append(thestr)

            patt = re.match(r".*\.authors *= *(.*) *", line)
            if patt:
                lstr = re.sub(r"^\[|\]$", "", patt.group(1)).split(',')
                for thestr in lstr:
                    thestr = re.sub(' *" *', "", thestr)
                    origins.append(thestr)

            patt = re.match(r".*\.files *= *(.*) *", line)
            if patt:
                lstr = re.sub(r"^\[|\]$", "", patt.group(1)).split(',')
                for thestr in lstr:
                    thestr = re.sub(' *" *', "", thestr)
                    rfiles.append(thestr)

    except Exception as err:
        print("WARN could not fully parse gemspec file: " + str(name) + ": exception: " + str(err))
        return {}

    if name:
        ret[name] = {'name':name, 'lics':lics, 'versions':versions, 'latest':latest, 'origins':origins, 'sourcepkg':sourcepkg, 'files':rfiles}

    return ret

def _hints_to_gem(pkg):
    pkg_type = anchore_engine.utils.ensure_str(pkg.get('type', "gem")).lower()    
    pkg_name = anchore_engine.utils.ensure_str(pkg.get('name', ""))
    pkg_version = anchore_engine.utils.ensure_str(pkg.get('version', ""))
    pkg_versions = pkg.get('versions', [])    
    pkg_location = anchore_engine.utils.ensure_str(pkg.get('location', ""))
    pkg_license = anchore_engine.utils.ensure_str(pkg.get('license', ""))
    pkg_licenses = pkg.get('licenses', [])
    pkg_files = pkg.get('files', [])
    pkg_origin = anchore_engine.utils.ensure_str(pkg.get('origin', ""))
    pkg_origins = pkg.get('origins', [])
    pkg_source = anchore_engine.utils.ensure_str(pkg.get('source', pkg_name))

    if not pkg_name or not (pkg_version or pkg_versions) or not pkg_type:
        raise Exception("bad hints record, all hints records must supply at least a name, version and type")

    for inp in [pkg_versions, pkg_licenses, pkg_origins, pkg_files]:
        if type(inp) is not list:
            raise Exception("bad hints record ({}), versions, licenses, origins, and files if specified must be list types".format(pkg_name))
    
    if pkg_license and not pkg_licenses:
        pkg_licenses = [pkg_license]

    if pkg_version and not pkg_versions:
        pkg_versions = [pkg_version]

    if pkg_origin and not pkg_origins:
        pkg_origins = [pkg_origin]

    pkg_latest = pkg_versions[0]

    if not pkg_location:
        pkg_location = "/virtual/gempkg/{}-{}".format(pkg_name, pkg_latest)

    pkg_key = pkg_location

    el = {
        'name': pkg_name,
        'versions': pkg_versions,
        'latest': pkg_latest,
        'sourcepkg': pkg_source,
        'files': pkg_files,
        'origins': pkg_origins,
        'lics': pkg_licenses,
        'type': pkg_type
    }    
    return pkg_key, el

def npm_parse_meta(npm):

    record = {}

    name = npm.pop('name', None)
    if not name:
        return record

    lics = list()
    versions = list()
    latest = None
    origins = list()
    sourcepkg = None

    npmtime = npm.pop('time', None)
    npmdesc = npm.pop('description', None)
    npmdisttags = npm.pop('dist-tags', None)
    npmkeywords = npm.pop('keywords', None)


    npmlicense = npm.pop('license', None)
    npmversions = npm.pop('versions', None)
    npmversion = npm.pop('version', None)
    npmauthor = npm.pop('author', None)
    npmmaintainers = npm.pop('maintainers', None)
    npmrepository = npm.pop('repository', None)
    npmhomepage= npm.pop('homepage', None)

    if npmlicense:
        if isinstance(npmlicense, str):
            lics.append(npmlicense)
        elif isinstance(npmlicense, dict):
            for ktype in ['type', 'name', 'license', 'sourceType']:
                lic = npmlicense.pop(ktype, None)
                if lic:
                    lics.append(lic)
        elif isinstance(npmlicense, list):
            for lentry in npmlicense:
                if isinstance(lentry, str):
                    lics.append(lentry)
                elif isinstance(lentry, dict):
                    for ktype in ['type', 'name', 'license', 'sourceType']:
                        lic = lentry.pop(ktype, None)
                        if lic:
                            lics.append(lic)
        else:
            print("unknown type (" + str(name) + "): " + str(type(npmlicense)))


    if npmversions:
        if isinstance(npmversions, dict):
            versions = list(npmversions.keys())
            for v in npmversions:
                if npmversions[v] == 'latest':
                    latest = v
        elif isinstance(npmversions, list):
            versions = npmversions
    elif npmversion:
        versions.append(npmversion)

    astring = None
    if npmauthor:
        if isinstance(npmauthor, str):
            astring = npmauthor
        elif isinstance(npmauthor, dict):
            aname = npmauthor.pop('name', None)
            aurl = npmauthor.pop('url', None)
            if aname:
                astring = aname
                if aurl:
                    astring += " ("+aurl+")"
        else:
            print("unknown type (" + str(name) + "): "+ str(type(npmauthor)))

    elif npmmaintainers:
        for m in npmmaintainers:
            aname = m.pop('name', None)
            aemail = m.pop('email', None)
            if aname:
                astring = aname
                if aemail:
                    astring += " ("+aemail+")"

    if astring:
        origins.append(astring)

    if npmrepository:
        if isinstance(npmrepository, dict):
            sourcepkg = npmrepository.pop('url', None)
        elif isinstance(npmrepository, str):
            sourcepkg = npmrepository
        else:
            print("unknown type (" + str(name) + "): " + str(type(npmrepository)))

    elif npmhomepage:
        if isinstance(npmhomepage, str):
            sourcepkg = npmhomepage

    if not lics:
        print("WARN: ("+name+") no lics: " + str(npm))
    if not versions:
        print("WARN: ("+name+") no versions: " + str(npm))
    if not origins:
        print("WARN: ("+name+") no origins: " + str(npm))
    if not sourcepkg:
        print("WARN: ("+name+") no sourcepkg: " + str(npm))

    if name:
        record[name] = {'name':name, 'lics':lics, 'versions':versions, 'latest':latest, 'origins':origins, 'sourcepkg':sourcepkg}

    return record

def _hints_to_npm(pkg):
    pkg_type = anchore_engine.utils.ensure_str(pkg.get('type', "npm")).lower()    
    pkg_name = anchore_engine.utils.ensure_str(pkg.get('name', ""))
    pkg_version = anchore_engine.utils.ensure_str(pkg.get('version', ""))
    pkg_versions = pkg.get('versions', [])    
    pkg_location = anchore_engine.utils.ensure_str(pkg.get('location', ""))
    pkg_license = anchore_engine.utils.ensure_str(pkg.get('license', ""))
    pkg_licenses = pkg.get('licenses', [])
    pkg_files = pkg.get('files', [])
    pkg_origin = anchore_engine.utils.ensure_str(pkg.get('origin', ""))
    pkg_origins = pkg.get('origins', [])    
    pkg_source = anchore_engine.utils.ensure_str(pkg.get('source', pkg_name))

    if not pkg_name or not (pkg_version or pkg_versions) or not pkg_type:
        raise Exception("bad hints record, all hints records must supply at least a name, version and type")
    for inp in [pkg_versions, pkg_licenses, pkg_origins, pkg_files]:
        if type(inp) is not list:
            raise Exception("bad hints record ({}), versions, licenses, origins, and files if specified must be list types".format(pkg_name))
        
    if pkg_license and not pkg_licenses:
        pkg_licenses = [pkg_license]

    if pkg_version and not pkg_versions:
        pkg_versions = [pkg_version]

    if pkg_origin and not pkg_origins:
        pkg_origins = [pkg_origin]

    pkg_latest = pkg_versions[0]

    if not pkg_location:
        pkg_location = "/virtual/npmpkg/{}-{}".format(pkg_name, pkg_latest)

    pkg_key = pkg_location
    
    el = {
        'name': pkg_name,
        'versions': pkg_versions,
        'latest': pkg_latest,
        'sourcepkg': pkg_source,
        'files': pkg_files,
        'origins': pkg_origins,
        'lics': pkg_licenses,
        'type': pkg_type
    }    
    return pkg_key, el

def _hints_to_java(pkg):
    pkg_type = anchore_engine.utils.ensure_str(pkg.get('type', "java")).lower()
    pkg_jtype = '{}-jar'.format(pkg_type)
    
    pkg_name = anchore_engine.utils.ensure_str(pkg.get('name', ""))
    pkg_version = anchore_engine.utils.ensure_str(pkg.get('version', ""))
    pkg_location = anchore_engine.utils.ensure_str(pkg.get('location', "/virtual/javapkg/{}-{}.jar".format(pkg_name, pkg_version)))
    pkg_origin = anchore_engine.utils.ensure_str(pkg.get('origin', ""))
    pkg_metadata = pkg.get('metadata', {})

    if not pkg_name or not pkg_version or not pkg_type:
        raise Exception("bad hints record, all hints records must supply at least a name, version and type")
    
    pkg_key = pkg_location
    
    el = {
        'metadata': pkg_metadata,
        'specification-version': pkg_version,
        'implementation-version': pkg_version,
        'maven-version': pkg_version,
        'origin': pkg_origin,
        'location': pkg_location,
        'type': pkg_jtype,
        'name': pkg_name
    }

    return pkg_key, el
def rpm_get_file_package_metadata_from_squashtar(unpackdir, squashtar):
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

    record_template = {'digest': None, 'digestalgo': None, 'mode': None, 'group': None, 'user': None, 'size': None, 'package': None, 'conffile': False}

    result = {}

    rpm_db_base_dir = rpm_prepdb_from_squashtar(unpackdir, squashtar)
    rpmdbdir = os.path.join(rpm_db_base_dir, "var", "lib", "rpm")

    cmdstr = 'rpm --dbpath='+rpmdbdir+' -qa --queryformat [%{FILENAMES}|ANCHORETOK|%{FILEDIGESTS}|ANCHORETOK|%{FILEMODES:octal}|ANCHORETOK|%{FILEGROUPNAME}|ANCHORETOK|%{FILEUSERNAME}|ANCHORETOK|%{FILESIZES}|ANCHORETOK|%{=NAME}|ANCHORETOK|%{FILEFLAGS:fflags}|ANCHORETOK|%{=FILEDIGESTALGO}\\n]'
    cmd = cmdstr.split()
    print ("{} - {}".format(rpmdbdir, cmd))
    try:
        pipes = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        o, e = pipes.communicate()
        exitcode = pipes.returncode
        soutput = o
        serror = e

        if exitcode == 0:
            for l in soutput.splitlines():
                l = str(l.strip(), 'utf8')
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
                        print("WARN: unparsable output line - exception: " + str(err))
                        raise err
        else:
            raise Exception("rpm file metadata command failed with exitcode ("+str(exitcode)+") - stdoutput: " + str(soutput) + " : stderr: " + str(serror))

    except Exception as err:
        raise Exception("WARN: distro package metadata gathering failed - exception: " + str(err))

    return result

def dpkg_get_file_package_metadata_from_squashtar(unpackdir, squashtar):

    result = {}
    record_template = {'digest': None, 'digestalgo': None, 'mode': None, 'group': None, 'user': None, 'size': None, 'package': None, 'conffile': False}

    conffile_csums = {}

    dpkg_db_base_dir = dpkg_prepdb_from_squashtar(unpackdir, squashtar)
    dpkgdbdir = os.path.join(dpkg_db_base_dir, "var", "lib", "dpkg")
    dpkgdocsdir = os.path.join(dpkg_db_base_dir, "usr", "share", "doc")
    statuspath = os.path.join(dpkg_db_base_dir, "var", "lib", "dpkg", "status")

    try:
        if os.path.exists(statuspath):
            buf = None
            try:
                with open(statuspath, 'r') as FH:
                    buf = FH.read()
            except Exception as err:
                buf = None
                print("WARN: cannot read status file - exception: " + str(err))

            if buf:
                for line in buf.splitlines():
                    #line = str(line.strip(), 'utf8')
                    line = line.strip()
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
                                print("WARN: bad line in status for conffile line - exception: " + str(err))

    except Exception as err:
        import traceback
        traceback.print_exc()
        raise Exception("WARN: could not parse dpkg status file, looking for conffiles checksums - exception: " + str(err))

    metafiles = {}
    conffiles = {}
    metapath = os.path.join(dpkg_db_base_dir, "var", "lib", "dpkg", "info")
    try:
        if os.path.exists(metapath):
            for f in os.listdir(metapath):
                patt = re.match(r"(.*)\.md5sums", f)
                if patt:
                    pkgraw = patt.group(1)
                    patt = re.match("(.*):.*", pkgraw)
                    if patt:
                        pkg = patt.group(1)
                    else:
                        pkg = pkgraw

                    metafiles[pkg] = os.path.join(metapath, f)

                patt = re.match(r"(.*)\.conffiles", f)
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

        for pkg in list(metafiles.keys()):
            dinfo = None
            try:
                with open(metafiles[pkg], 'r') as FH:
                    dinfo = FH.read()
            except Exception as err:
                print("WARN: could not open/read metafile - exception: " + str(err))

            if dinfo:
                for line in dinfo.splitlines():
                    #line = str(line.strip(), 'utf8')
                    line = line.strip()
                    try:
                        (csum, fname) = line.split()
                        fname = '/' + fname
                        fname = re.sub(r"\/\/", r"\/", fname)

                        if fname not in result:
                            result[fname] = []

                        el = copy.deepcopy(record_template)
                        el.update({"package": pkg or None, "digest": csum or None, "digestalgo": "md5", "conffile": False})
                        result[fname].append(el)
                    except Exception as err:
                        print("WARN: problem parsing line from dpkg info file - exception: " + str(err))

        for pkg in list(conffiles.keys()):
            cinfo = None
            try:
                with open(conffiles[pkg], 'r') as FH:
                    cinfo = FH.read()
            except Exception as err:
                cinfo = None
                print("WARN: could not open/read conffile - exception: " + str(err))

            if cinfo:
                for line in cinfo.splitlines():
                    #line = str(line.strip(), 'utf8')
                    line = line.strip()
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
                        print("WARN: problem parsing line from dpkg conffile file - exception: " + str(err))

    except Exception as err:
        import traceback
        traceback.print_exc()
        raise Exception("WARN: could not find/parse dpkg info metadata files - exception: " + str(err))

    return result

def apk_get_file_package_metadata_from_squashtar(unpackdir, squashtar):
    # derived from alpine apk checksum logic
    #
    # a = "Q1XxRCAhhQ6eotekmwp6K9/4+DLwM="
    # sha1sum = a[2:].decode('base64').encode('hex')
    #

    result = {}
    record_template = {'digest': None, 'digestalgo': None, 'mode': None, 'group': None, 'user': None, 'size': None, 'package': None, 'conffile': False}

    apk_db_base_dir = apk_prepdb_from_squashtar(unpackdir, squashtar)
    apkdbpath = os.path.join(apk_db_base_dir, 'lib', 'apk', 'db', 'installed')

    try:
        if os.path.exists(apkdbpath):
            buf = None
            try:
                with open(apkdbpath, 'r') as FH:
                    buf = FH.read()

            except Exception as err:
                buf = None
                print("WARN: cannot read apk DB file - exception: " + str(err))

            if buf:
                fmode = raw_csum = uid = gid = sha1sum = fname = therealfile_apk = therealfile_fs = None
                for line in buf.splitlines():
                    #line = str(line.strip(), 'utf8')
                    line = line.strip()
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
                            therealfile_apk = re.sub(r"\/+", "/", '/'.join([unpackdir, 'rootfs', fname]))
                            therealfile_fs = os.path.realpath(therealfile_apk)
                            if therealfile_apk == therealfile_fs:
                                try:
                                    #sha1sum = raw_csum[2:].decode('base64').encode('hex')
                                    sha1sum = str(binascii.hexlify(base64.decodebytes(raw_csum[2:])), 'utf-8')
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

    return result


##### File IO helpers

def read_kvfile_todict(file):
    if not os.path.isfile(file):
        return {}

    ret = {}
    with open(file, 'r') as FH:
        for l in FH.readlines():
            l = l.strip()
            #l = l.strip().decode('utf8')
            if l:
                (k, v) = re.match(r'(\S*)\s*(.*)', l).group(1, 2)
                k = re.sub("____", " ", k)
                ret[k] = v

    return ret

def read_plainfile_tostr(file):
    if not os.path.isfile(file):
        return ""

    with open(file, 'r') as FH:
        ret = FH.read()
        #ret = FH.read().decode('utf8')

    return ret

def write_plainfile_fromstr(file, instr):
    with open(file, 'w') as FH:
        #thestr = instr.encode('utf8')
        FH.write(instr)

def write_kvfile_fromlist(file, list, delim=' '):
    with open(file, 'w') as OFH:
        for l in list:
            for i in range(0,len(l)):
                l[i] = re.sub(r"\s", "____", l[i])
            thestr = delim.join(l) + "\n"
            #thestr = thestr.encode('utf8')
            OFH.write(thestr)

def write_kvfile_fromdict(file, indict):
    dict = indict.copy()

    with open(file, 'w') as OFH:
        for k in list(dict.keys()):
            if not dict[k]:
                dict[k] = "none"
            cleank = re.sub(r"\s+", "____", k)
            thestr = ' '.join([cleank, dict[k], '\n'])
            #thestr = thestr.encode('utf8')
            OFH.write(thestr)
