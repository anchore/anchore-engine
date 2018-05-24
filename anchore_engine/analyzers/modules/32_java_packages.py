#!/usr/bin/env python3

import os
import re
import json
import sys
import zipfile
from io import BytesIO

import anchore_engine.analyzers.utils

analyzer_name = "package_list"

java_library_file = ".*\.([jwe]ar|[jh]pi)"

try:
    config = anchore_engine.analyzers.utils.init_analyzer_cmdline(sys.argv, analyzer_name)
except Exception as err:
    print(str(err))
    sys.exit(1)

imgname = config['imgid']
imgid = config['imgid_full']
outputdir = config['dirs']['outputdir']
unpackdir = config['dirs']['unpackdir']


def parse_properties(file):
    """
    Parses the given file using the Java properties file format.
    Lines beginning with # are ignored.
    :param file: an open iterator into the file
    :return: the properties in the file as a dictionary
    """
    props = {}
    for line in file:
        if not re.match("\s*(#.*)?$", line):
            kv = line.split('=')
            key = kv[0].strip()
            value = '='.join(kv[1:]).strip()
            props[key] = value
    return props


def process_java_archive(prefix, filename, inZFH=None):
    ret = []

    fullpath = '/'.join([prefix, filename])

    jtype = None
    patt = re.match(java_library_file, fullpath)
    if patt:
        jtype = patt.group(1)
    else:
        return []
    name = re.sub("\." + jtype + "$", "", fullpath.split("/")[-1])

    top_el = {}
    sub_els = []
    try:

        # set up the zipfile handle
        try:
            if not inZFH:
                if zipfile.is_zipfile(fullpath):
                    ZFH = zipfile.ZipFile(fullpath, 'r')
                    location = filename
                else:
                    return []
            else:
                zdata = BytesIO(inZFH.read())
                ZFH = zipfile.ZipFile(zdata, 'r')
                location = prefix + ":" + filename

        except Exception as err:
            raise err

        top_el = {
            'metadata': {},
            'specification-version': "N/A",
            'implementation-version': "N/A",
            'maven-version': "N/A",
            'origin': "N/A",
            'location': location,
            'type': "java-" + str(jtype),
            'name': name
        }

        sname = sversion = svendor = iname = iversion = ivendor = None

        filenames = ZFH.namelist()

        if 'META-INF/MANIFEST.MF' in filenames:
            try:
                with ZFH.open('META-INF/MANIFEST.MF', 'r') as MFH:
                    top_el['metadata']['MANIFEST.MF'] = MFH.read()

                for line in (top_el['metadata']['MANIFEST.MF'].splitlines()):
                    try:
                        (k, v) = line.split(": ", 1)
                        if k == 'Specification-Title':
                            sname = v
                        elif k == 'Specification-Version':
                            sversion = v
                        elif k == 'Specification-Vendor':
                            svendor = v
                        elif k == 'Implementation-Title':
                            iname = v
                        elif k == 'Implementation-Version':
                            iversion = v
                        elif k == 'Implementation-Vendor':
                            ivendor = v
                    except:
                        pass

                if sversion:
                    top_el['specification-version'] = sversion
                if iversion:
                    top_el['implementation-version'] = iversion

                if svendor:
                    top_el['origin'] = svendor
                elif ivendor:
                    top_el['origin'] = ivendor

            except:
                # no manifest could be parsed out, leave the el values unset
                pass
        else:
            print('WARN: no META-INF/MANIFEST.MF found in ' + fullpath)

        archives = [fname for fname in filenames if re.match(java_library_file, fname)]
        pomprops = [fname for fname in filenames if fname.endswith('/pom.properties')]

        for archive in archives:
            with ZFH.open(archive, 'r') as ZZFH:
                sub_els += process_java_archive(location, archive, ZZFH)

        for pomprop in pomprops:
            with ZFH.open(pomprop) as pomfile:
                props = parse_properties(pomfile)
                group = props.get('groupId')
                if group:
                    top_el['origin'] = group
                artifact = props.get('artifactId')
                if artifact:
                    top_el['name'] = artifact
                mversion = props.get('version')
                if mversion:
                    top_el['maven-version'] = mversion

    except Exception as err:
        raise err
    finally:
        if inZFH:
            try:
                inZFH.close()
            except:
                pass

    ret = [top_el]
    if sub_els:
        ret += sub_els

    return ret


resultlist = {}
try:
    allfiles = {}
    if os.path.exists(unpackdir + "/anchore_allfiles.json"):
        with open(unpackdir + "/anchore_allfiles.json", 'r') as FH:
            allfiles = json.loads(FH.read())
    else:
        fmap, allfiles = anchore_engine.analyzers.utils.get_files_from_path(unpackdir + "/rootfs")
        with open(unpackdir + "/anchore_allfiles.json", 'w') as OFH:
            OFH.write(json.dumps(allfiles))

    for f in list(allfiles.keys()):
        if allfiles[f]['type'] == 'file':
            prefix = '/'.join([unpackdir, 'rootfs'])
            els = process_java_archive(prefix, f.encode('utf8'))
            if els:
                for el in els:
                    resultlist[el['location']] = json.dumps(el)

except Exception as err:
    print("WARN: analyzer unable to complete - exception: " + str(err))

if resultlist:
    ofile = os.path.join(outputdir, 'pkgs.java')
    anchore_engine.analyzers.utils.write_kvfile_fromdict(ofile, resultlist)

sys.exit(0)
