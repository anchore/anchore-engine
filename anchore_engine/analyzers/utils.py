from functools import lru_cache
import logging
import os
import re
import hashlib
import yaml
import random
import json
import tarfile
import collections

import anchore_engine.utils

logger = logging.getLogger(__name__)


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
        raise ValueError("input tarfile not found: {}".format(tarfilename))

    if member_regexp:
        memberpatt = re.compile(member_regexp)
    else:
        memberpatt = None

    ret = {}
    with tarfile.open(tarfilename, mode='r', format=tarfile.PAX_FORMAT) as tfl:
        memberhash = get_memberhash(tfl)
        kwargs['memberhash'] = memberhash
        for member in list(memberhash.values()):
            if not memberpatt or memberpatt.match(member.name):
                if ret.get(member.name):
                    print("WARN: duplicate member name when preparing return from run_tarfile_member_function() - {}".format(member.name))

                ret[member.name] = func(tfl, member, *args, **kwargs)

    return ret


def run_tarfile_function(tarfile, func=None, *args, **kwargs):

    if not os.path.exists(tarfile):
        raise ValueError("input tarfile not found: {}".format(tarfile))

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


def get_hintsfile(unpackdir=None, squashtar=None):
    """
    Retrieve the hintsfile from the current unpackdir or from the container
    (within the squashed tarfile), following that order of precedence.

    This function makes the `unpackdir` and the `squashtar` arguments fully
    optional, falling back to retrieving the actual value of the `unpackdir`
    from the `ANCHORE_ANALYZERS_UNPACKDIR` environment variable.

    Finally, this function uses a caching closure , for up to 24 different
    calls. The Syft handlers will consume this hints function without passing
    any arguments at all for every package but relying on a unique path still,
    which is why it is useful to have the hints file contents cached.
    """
    if unpackdir is None:
        unpackdir = os.environ["ANCHORE_ANALYZERS_UNPACKDIR"]
        squashtar = os.path.join(unpackdir, "squashed.tar")
    ret = {}

    @lru_cache(maxsize=24)
    def read_hints(path):
        """
        Cached function to retrieve the contents of the hints file. Prevents
        reading the file for every package in a container
        """
        with open(path, 'r') as FH:
            try:
                return json.loads(FH.read())
            except Exception as err:
                print("WARN: hintsfile found unpacked, but cannot be read - exception: {}".format(err))
                return {}

    anchore_hints_path =  os.path.join(unpackdir, "anchore_hints.json")
    if os.path.exists(anchore_hints_path):
        ret = read_hints(anchore_hints_path)
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
                    print("WARN: hintsfile found in squashtar, but cannot be read - exception: {}".format(err))
                    ret = {}
            else:
                ret = {}

    if ret and not os.path.exists(os.path.join(unpackdir, "anchore_hints.json")):
        with open(os.path.join(unpackdir, "anchore_hints.json"), 'w') as OFH:
            OFH.write(json.dumps(ret))

    for pkg_type in ret.get("packages", []):
        if not all((pkg_type.get("name"), pkg_type.get("version"), pkg_type.get("type"))):
            logger.error("bad hints record, all hints records must supply at least a name, version and type")

    return ret


def make_anchoretmpdir(tmproot):
    tmpdir = '/'.join([tmproot, str(random.randint(0, 9999999)) + ".anchoretmp"])
    try:
        os.makedirs(tmpdir)
        return tmpdir
    except:
        return False


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
    """
    Writes a file with each line as 'key value' using a dict as input.
    Expects the value of each key in the dict to be a string

    :param file:
    :param indict:
    :return:
    """
    dict = indict.copy()

    with open(file, 'w') as OFH:
        for k in list(dict.keys()):
            if not dict[k]:
                dict[k] = "none"
            cleank = re.sub(r"\s+", "____", k)
            if type(dict[k]) != str:
                raise TypeError('Expected value of key {} to be a string, found {}'.format(k, type(dict[k])))

            thestr = ' '.join([cleank, dict[k], '\n'])
            #thestr = thestr.encode('utf8')
            OFH.write(thestr)


### data transform helpers


def defaultdict_to_dict(d):
    if isinstance(d, collections.defaultdict):
        d = {k: defaultdict_to_dict(v) for k, v in d.items()}
    return d


def merge_nested_dict(a, b, path=None):
    if path is None:
        path = []

    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                merge_nested_dict(a[key], b[key], path + [str(key)])
            elif a[key] == b[key]:
                continue # same leaf value
            else:
                raise Exception('dict merge conflict at %s' % '.'.join(path + [str(key)]))
        else:
            a[key] = b[key]
    return a


def dig(target, *keys, **kwargs):
    """
    Traverse a nested set of dictionaries, tuples, or lists similar to ruby's dig function.
    """
    end_of_chain = target
    for key in keys:
        if isinstance(end_of_chain, dict) and key in end_of_chain:
            end_of_chain = end_of_chain[key]
        elif isinstance(end_of_chain, (list, tuple)) and isinstance(key, int):
            end_of_chain = end_of_chain[key]
        else:
            if 'fail' in kwargs and kwargs['fail'] is True:
                if isinstance(end_of_chain, dict):
                    raise KeyError
                else:
                    raise IndexError
            elif 'default' in kwargs:
                return kwargs['default']
            else:
                return None

    return end_of_chain


def content_hints(pkg_type):
    """Content hints will provide the handlers with a means of inserting new data from
    the user.

    This function produces a dictionary with names as keys so that consumers
    avoid having to loop, and can do simpler (faster) `.get()` operations.
    """
    hints = get_hintsfile()
    packages = {}
    for package in hints.get("packages", []):
        if package.get("type", "") == pkg_type:
            # Do not allow nameless packages to be inserted. The hints loader
            # will warn if this is a problem, but will not stop execution
            if not package.get("name"):
                continue
            packages[package["name"]] = package

    return packages
