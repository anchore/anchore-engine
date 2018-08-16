import os
import shutil
import re
import subprocess
import hashlib
import yaml
import traceback
import random
import json
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

    #ret['anchore_config'] = anchore_conf.data

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

    return(ret)

def get_distro_from_path(inpath):

    meta = {
        'DISTRO':None,
        'DISTROVERS':None,
        'LIKEDISTRO':None
    }

    if os.path.exists('/'.join([inpath,"/etc/os-release"])):
        with open('/'.join([inpath,"/etc/os-release"]), 'r') as FH:
            for l in FH.readlines():
                l = l.strip()
                #l = l.decode('utf8')
                try:
                    (key, val) = l.split("=")
                    val = re.sub(r'"', '', val)
                    if key == "ID":
                        meta['DISTRO'] = val
                    elif key == "VERSION_ID":
                        meta['DISTROVERS'] = val
                    elif key == "ID_LIKE":
                        meta['LIKEDISTRO'] = ','.join(val.split())
                except:
                    pass

    elif os.path.exists('/'.join([inpath, "/etc/system-release-cpe"])):

        with open('/'.join([inpath, "/etc/system-release-cpe"]), 'r') as FH:
            for l in FH.readlines():
                l = l.strip()
                #l = l.decode('utf8')
                try:
                    distro = l.split(':')[2]
                    vers = l.split(':')[4]
                    meta['DISTRO'] = distro
                    meta['DISTROVERS'] = vers
                except:
                    pass

    elif os.path.exists('/'.join([inpath, "/etc/redhat-release"])):
        with open('/'.join([inpath, "/etc/redhat-release"]), 'r') as FH:
            for l in FH.readlines():
                l = l.strip()
                #l = l.decode('utf8')
                try:
                    distro = vers = None
                    patt = re.match(".*CentOS.*", l)
                    if patt:
                        distro = 'centos'

                    patt = re.match(".*(\d+\.\d+).*", l)
                    if patt:
                        vers = patt.group(1)

                    if distro:
                        meta['DISTRO'] = distro
                    if vers:
                        meta['DISTROVERS'] = vers
                except:
                    pass

    elif os.path.exists('/'.join([inpath, "/bin/busybox"])):
        meta['DISTRO'] = "busybox"
        try:
            sout = subprocess.check_output(['/'.join([inpath, "/bin/busybox"])])
            fline = str(sout.splitlines(True)[0], 'utf-8')
            slist = fline.split()
            meta['DISTROVERS'] = slist[1]
        except:
            meta['DISTROVERS'] = "0"

    if meta['DISTRO'] == 'debian' and not meta['DISTROVERS'] and os.path.exists('/'.join([inpath, "/etc/debian_version"])):
        with open('/'.join([inpath, "/etc/debian_version"]), 'r') as FH:
            meta['DISTRO'] = 'debian'
            for line in FH.readlines():
                line = line.strip()
                patt = re.match("(\d+)\..*", line)
                if patt:
                    meta['DISTROVERS'] = patt.group(1)
                elif re.match(".*sid.*", line):
                    meta['DISTROVERS'] = 'unstable'

    if not meta['DISTRO']:
        meta['DISTRO'] = "Unknown"
    if not meta['DISTROVERS']:
        meta['DISTROVERS'] = "0"
    if not meta['LIKEDISTRO']:
        meta['LIKEDISTRO'] = meta['DISTRO']

    return(meta)

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

    patt = re.match("(\d*)\.*(\d*)", version)
    if patt:
        (vmaj, vmin) = patt.group(1,2)
        if vmaj:
            ret['version'] = vmaj
            ret['likeversion'] = vmaj

    patt = re.match("(\d+)\.*(\d+)\.*(\d+)", version)
    if patt:
        (vmaj, vmin, submin) = patt.group(1,2,3)
        if vmaj and vmin:
            ret['version'] = vmaj + "." + vmin
            ret['likeversion'] = vmaj + "." + vmin

    return(ret)

def get_files_from_path(inpath):
    filemap = {}
    allfiles = {}
    real_root = os.open('/', os.O_RDONLY)

    try:
        os.chroot(inpath)
        #for root, dirs, files in os.walk('/', followlinks=True):
        for root, dirs, files in os.walk('/', followlinks=False):
            for name in dirs + files:
                filename = os.path.join(root, name) #.decode('utf8')
                osfilename = os.path.join(root, name)

                fstat = os.lstat(osfilename)

                finfo = {}
                finfo['name'] = filename
                finfo['fullpath'] = os.path.normpath(osfilename)
                finfo['size'] = fstat.st_size
                finfo['mode'] = fstat.st_mode
                finfo['uid'] = fstat.st_uid
                finfo['gid'] = fstat.st_gid
                
                mode = finfo['mode']
                finfo['linkdst'] = None
                finfo['linkdst_fullpath'] = None
                if S_ISREG(mode):
                    finfo['type'] = 'file'
                elif S_ISDIR(mode):
                    finfo['type'] = 'dir'
                elif S_ISLNK(mode):
                    finfo['type'] = 'slink'
                    finfo['linkdst'] = os.readlink(osfilename)
                elif S_ISCHR(mode) or S_ISBLK(mode):
                    finfo['type'] = 'dev'
                else:
                    finfo['type'] = 'UNKNOWN'

                if finfo['type'] == 'slink' or finfo['type'] == 'hlink':
                    if re.match("^/", finfo['linkdst']):
                        fullpath = finfo['linkdst']
                    else:
                        dstlist = finfo['linkdst'].split('/')
                        srclist = finfo['name'].split('/')
                        srcpath = srclist[0:-1]
                        fullpath = os.path.normpath(os.path.join(finfo['linkdst'], osfilename))
                    finfo['linkdst_fullpath'] = fullpath

                fullpath = os.path.realpath(osfilename)

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
        traceback.print_exc()
        print(str(err))
        pass
    finally:
        os.fchdir(real_root)
        os.chroot('.')

    return(filemap, allfiles)

### Package helpers

def rpm_get_all_packages(unpackdir):
    rpms = {}
    rpmdbdir = rpm_prepdb(unpackdir)
    try:
        sout = subprocess.check_output(['rpm', '--dbpath='+rpmdbdir, '--queryformat', '%{NAME} %{VERSION} %{RELEASE} %{ARCH}\n', '-qa'], stderr=subprocess.STDOUT)
        for l in sout.splitlines():
            l = l.strip()
            l = str(l, 'utf-8')
            #l = l.decode('utf8')
            (name, vers, rel, arch) = re.match('(\S*)\s*(\S*)\s*(\S*)\s*(.*)', l).group(1, 2, 3, 4)
            rpms[name] = {'version':vers, 'release':rel, 'arch':arch}
    except Exception as err:
        print(err.output)
        raise ValueError("could not get package list from RPM database: " + str(err))

    return(rpms)

def rpm_get_all_pkgfiles(unpackdir):
    rpmfiles = {}
    rpmdbdir = rpm_prepdb(unpackdir)
    try:
        sout = subprocess.check_output(['rpm', '--dbpath='+rpmdbdir, '-qal'])
        for l in sout.splitlines():
            l = l.strip()
            l = str(l, 'utf-8')
            #l = l.decode('utf8')
            rpmfiles[l] = True
    except Exception as err:
        raise ValueError("could not get file list from RPM database: " + str(err))

    return(rpmfiles)

def make_anchoretmpdir(tmproot):
    tmpdir = '/'.join([tmproot, str(random.randint(0, 9999999)) + ".anchoretmp"])
    try:
        os.makedirs(tmpdir)
        return(tmpdir)
    except:
        return(False)

def rpm_prepdb(unpackdir):
    origrpmdir = os.path.join(unpackdir, 'rootfs', 'var', 'lib', 'rpm')
    ret = origrpmdir

    if os.path.exists(origrpmdir):
        newrpmdirbase = make_anchoretmpdir(unpackdir)
        newrpmdir = os.path.join(newrpmdirbase, 'var', 'lib', 'rpm')
        try:
            shutil.copytree(origrpmdir, newrpmdir)
            sout = subprocess.check_output(['rpmdb', '--root='+newrpmdirbase, '--dbpath=/var/lib/rpm', '--rebuilddb'])
            ret = newrpmdir
        except:
            pass

    return(ret)

def dpkg_get_all_packages(unpackdir):
    actual_packages = {}
    all_packages = {}
    other_packages = {}
    cmd = ["dpkg-query", "--admindir="+unpackdir+"/rootfs/var/lib/dpkg", "-W", "-f="+"${Package} ${Version} ${source:Package} ${source:Version} ${Architecture}\\n"]
    try:
        sout = subprocess.check_output(cmd)
        for l in sout.splitlines(True):
            l = l.strip()
            l = str(l, 'utf-8')
            (p, v, sp, sv, arch) = re.match('(\S*)\s*(\S*)\s*(\S*)\s*(\S*)\s*(.*)', l).group(1, 2, 3, 4, 5)
            if p and v:
                if p not in actual_packages:
                    actual_packages[p] = {'version':v, 'arch':arch}
                if p not in all_packages:
                    all_packages[p] = {'version':v, 'arch':arch}
            if sp and sv:
                if sp not in all_packages:
                    all_packages[sp] = {'version':sv, 'arch':arch}
            if p and v and sp and sv:
                if p == sp and v != sv:
                    other_packages[p] = [{'version':sv, 'arch':arch}]

    except Exception as err:
        print("Could not run command: " + str(cmd))
        print("Exception: " + str(err))
        print("Please ensure the command 'dpkg' is available and try again")
        raise err

    ret = (all_packages, actual_packages, other_packages)
    return(ret)

def dpkg_get_all_pkgfiles(unpackdir):
    allfiles = {}

    try:
        (allpkgs, actpkgs, othpkgs) = dpkg_get_all_packages(unpackdir)    
        cmd = ["dpkg-query", "--admindir="+unpackdir+"/rootfs/var/lib/dpkg", "-L"] + list(actpkgs.keys())
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

    return(allfiles)

def apkg_parse_apkdb(apkdb):
    if not os.path.exists(apkdb):
        raise ValueError("cannot locate APK installed DB '"+str(apkdb)+"'")
        
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

    with open(apkdb, 'r') as FH:
        for l in FH.readlines():
            l = l.strip()
            #l = l.strip().decode('utf8')

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

            patt = re.match("(\S):(.*)", l)
            if patt:
                (k, v) = patt.group(1,2)
                apkg['type'] = "APKG"
                if k == 'P':
                    thename = v
                    apkg['name'] = v
                elif k == 'V':
                    vpatt = re.match("(\S*)-(\S*)", v)
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

    return(apkgs)

def apkg_get_all_pkgfiles(unpackdir):
    apkdb = '/'.join([unpackdir, 'rootfs/lib/apk/db/installed'])
    return(apkg_parse_apkdb(apkdb))

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
            line = re.sub("\.freeze", "", line)

            # look for the unicode \u{} format and try to convert to something python can use
            try:
                replline = line
                mat = "\\\\u{.*?}"
                patt = re.match(r".*("+mat+").*", replline)
                while(patt):
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

            patt = re.match(".*\.name *= *(.*) *", line)
            if patt:
                name = json.loads(patt.group(1))

            patt = re.match(".*\.homepage *= *(.*) *", line)
            if patt:
                sourcepkg = json.loads(patt.group(1))

            patt = re.match(".*\.version *= *(.*) *", line)
            if patt:
                v = json.loads(patt.group(1))
                latest = v
                versions.append(latest)

            patt = re.match(".*\.licenses *= *(.*) *", line)
            if patt:
                lstr = re.sub("^\[|\]$", "", patt.group(1)).split(',')
                for thestr in lstr:
                    thestr = re.sub(' *" *', "", thestr)
                    lics.append(thestr)

            patt = re.match(".*\.authors *= *(.*) *", line)
            if patt:
                lstr = re.sub("^\[|\]$", "", patt.group(1)).split(',')
                for thestr in lstr:
                    thestr = re.sub(' *" *', "", thestr)
                    origins.append(thestr)

            patt = re.match(".*\.files *= *(.*) *", line)
            if patt:
                lstr = re.sub("^\[|\]$", "", patt.group(1)).split(',')
                for thestr in lstr:
                    thestr = re.sub(' *" *', "", thestr)
                    rfiles.append(thestr)

    except Exception as err:
        print("WARN could not fully parse gemspec file: " + str(name) + ": exception: " + str(err))
        return({})

    if name:
        ret[name] = {'name':name, 'lics':lics, 'versions':versions, 'latest':latest, 'origins':origins, 'sourcepkg':sourcepkg, 'files':rfiles}

    return(ret)

def npm_parse_meta(npm):

    record = {}

    name = npm.pop('name', None)
    if not name:
        return(record)

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

    return(record)

def verify_file_packages(unpackdir, flavor):
    if flavor == 'RHEL':
        return(rpm_verify_file_packages(unpackdir))
    else:
        return(generic_verify_file_packages(unpackdir))
            
def generic_verify_file_packages(unpackdir):
    return({}, None, "", "", 255)

def rpm_verify_file_packages(unpackdir):

    rootfs = os.path.join(unpackdir, 'rootfs')
    verify_output = verify_error = ""
    verify_exitcode = 255

    tmpdbpath = prepdbpath = None
    try:

        prepdbpath = rpm_prepdb(unpackdir)
        if not os.path.exists(prepdbpath):
            raise Exception("no prepdbpath created ("+str(prepdbpath)+")")

        tmpdbpath = os.path.join(rootfs, 'tmprpmdb')
        shutil.copytree(prepdbpath, tmpdbpath)
        if not os.path.exists(tmpdbpath):
            raise Exception("no tmpdbpath created ("+str(tmpdbpath)+")")

    except:
        if tmpdbpath and os.path.exists(tmpdbpath):
            shutil.rmtree(tmpdbpath)
        raise Exception("failed to prep environment for rpm verify - exception: " + str(err))

    try:
        verify_cmd = 'rpm --root=' + rootfs + ' --dbpath=/tmprpmdb/' + ' --verify -a'
        pipes = subprocess.Popen(verify_cmd.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        o, e = pipes.communicate()
        verify_exitcode = pipes.returncode
        verify_output = str(o, 'utf-8')
        verify_error = str(e, 'utf-8')
    except Exception as err:
        raise ValueError("could not perform verify against RPM database: " + str(err))
    finally:
        if os.path.exists(tmpdbpath):
            shutil.rmtree(tmpdbpath)

    verify_hash = {}
    for line in verify_output.splitlines():
        el = line.split()
        file = el[-1]
        vresult = el[0]
        verify_hash[file] = vresult

    return(verify_hash, verify_cmd, verify_output, verify_error, verify_exitcode)


##### File IO helpers

def read_kvfile_todict(file):
    if not os.path.isfile(file):
        return ({})

    ret = {}
    with open(file, 'r') as FH:
        for l in FH.readlines():
            l = l.strip()
            #l = l.strip().decode('utf8')
            if l:
                (k, v) = re.match('(\S*)\s*(.*)', l).group(1, 2)
                k = re.sub("____", " ", k)
                ret[k] = v

    return (ret)

def read_plainfile_tostr(file):
    if not os.path.isfile(file):
        return ("")

    with open(file, 'r') as FH:
        ret = FH.read()
        #ret = FH.read().decode('utf8')

    return (ret)

def write_plainfile_fromstr(file, instr):
    with open(file, 'w') as FH:
        #thestr = instr.encode('utf8')
        FH.write(instr)

def write_kvfile_fromlist(file, list, delim=' '):
    with open(file, 'w') as OFH:
        for l in list:
            for i in range(0,len(l)):
                l[i] = re.sub("\s", "____", l[i])
            thestr = delim.join(l) + "\n"
            #thestr = thestr.encode('utf8')
            OFH.write(thestr)

def write_kvfile_fromdict(file, indict):
    dict = indict.copy()

    with open(file, 'w') as OFH:
        for k in list(dict.keys()):
            if not dict[k]:
                dict[k] = "none"
            cleank = re.sub("\s+", "____", k)
            thestr = ' '.join([cleank, dict[k], '\n'])
            #thestr = thestr.encode('utf8')
            OFH.write(thestr)
