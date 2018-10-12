#!/usr/bin/env python3

import os
import re
import json
import sys
import zipfile
from io import BytesIO

import anchore_engine.analyzers.utils
import anchore_engine.utils
import anchore_engine.util.java as java_util

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


def parse_properties(filebuf):
    """
    Parses the given file using the Java properties file format.
    Lines beginning with # are ignored.
    :param file: an open iterator into the file
    :return: the properties in the file as a dictionary
    """
    return java_util.parse_properties(filebuf.splitlines())

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
                    top_el['metadata']['MANIFEST.MF'] = anchore_engine.utils.ensure_str(MFH.read())

                manifest = java_util.parse_manifest(top_el['metadata']['MANIFEST.MF'].splitlines())
                sname = manifest['Specification-Title']
                sversion = manifest['Specification-Version']
                svendor = manifest['Specification-Vendor']
                iname = manifest['Implementation-Title']
                iversion = manifest['Implementation-Version']
                ivendor = manifest['Implementation-Vendor']

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
            pom_el = {
                'metadata': {},
                'specification-version': "N/A",
                'implementation-version': "N/A",
                'maven-version': "N/A",
                'origin': "N/A",
                'location': top_el['location'],
                'type': "java-" + str(jtype),
                'name': "N/A"
            }
            with ZFH.open(pomprop) as pomfile:
                pombuf = anchore_engine.utils.ensure_str(pomfile.read())
                props = parse_properties(pombuf)

                group = props.get('groupId', "N/A")
                artifact = props.get('artifactId', "N/A")
                mversion = props.get('version', "N/A")

                addnew = False
                if re.match("^{}.*".format(artifact), top_el['name']):
                    the_el = top_el
                else:
                    the_el = pom_el
                    the_el['location'] = ":".join([the_el['location'], artifact])
                    addnew = True

                the_el['metadata']['pom.properties'] = anchore_engine.utils.ensure_str(pombuf)
                if group:
                    the_el['origin'] = group
                if artifact:
                    the_el['name'] = artifact
                if mversion:
                    the_el['maven-version'] = mversion

                if addnew:
                    sub_els.append(the_el)

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
            els = process_java_archive(prefix, f)
            if els:
                for el in els:
                    resultlist[el['location']] = json.dumps(el)

except Exception as err:
    import traceback
    traceback.print_exc()
    print("WARN: analyzer unable to complete - exception: " + str(err))

if resultlist:
    ofile = os.path.join(outputdir, 'pkgs.java')
    anchore_engine.analyzers.utils.write_kvfile_fromdict(ofile, resultlist)

sys.exit(0)
