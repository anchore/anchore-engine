#!/usr/bin/env python3

import sys
import os
import re
import json
import traceback
import pkg_resources
import tarfile
from collections import OrderedDict

import anchore_engine.analyzers.utils, anchore_engine.utils

def get_python_evidence(tfl, member, memberhash, evidence):
    fullpath = "/{}".format(member.name)    
    filename = os.path.basename(fullpath)
    patt_bin = re.match("^python([0-9]+\.[0-9]+)$", filename)
    patt_lib = re.match("^libpython([0-9]+\.[0-9]+).so.*$", filename)
    if (patt_bin or patt_lib) and member.isreg():
        f_vers = ""
        if patt_bin:
            f_vers = patt_bin.group(1)
        elif patt_lib:
            f_vers = patt_lib.group(1)
        with tfl.extractfile(member) as FH:
            for line in FH.readlines():
                subline = line
                try:
                    the_re = ".*{}\.([0-9]+[-_a-zA-Z0-9]*).*".format(f_vers)
                    patt = re.match(anchore_engine.utils.ensure_bytes(the_re), subline)
                    if patt and f_vers:
                        b_vers = "{}.{}".format(f_vers, anchore_engine.utils.ensure_str(patt.group(1)))
                        if b_vers.startswith(f_vers):
                            evidence['python']['binary'].append( (b_vers, fullpath) )
                            break
                except Exception as err:
                    raise err                    


    elif filename == "patchlevel.h" and member.isreg():
        with tfl.extractfile(member) as FH:
            for line in FH.readlines():
                line = line.strip()
                patt = re.match(b".*#define +PY_VERSION +\"*([0-9\.\-_a-zA-Z]+)\"*", line)
                if patt:
                    h_vers = anchore_engine.utils.ensure_str(patt.group(1))
                    evidence['python']['devel'].append((h_vers, fullpath))
                    break

def get_golang_evidence(tfl, member, memberhash, evidence):
    fullpath = "/{}".format(member.name)
    filename = os.path.basename(fullpath)
    if filename in ['go'] and member.isreg():
        with tfl.extractfile(member) as FH:
            for line in FH.readlines():
                subline = line
                try:
                    the_re = ".*go([0-9]+\.[0-9]+(\.[0-9]+|beta[0-9]+|alpha[0-9]+|rc[0-9]+)).*"
                    patt = re.match(anchore_engine.utils.ensure_bytes(the_re), subline)
                    if patt:
                        vers = anchore_engine.utils.ensure_str(patt.group(1))
                        evidence['go']['binary'].append( (vers, fullpath) )
                        break
                except Exception as err:
                    raise err                    
    elif filename == "VERSION" and member.isreg():
        with tfl.extractfile(member) as FH:
            for line in FH.readlines():
                line = line.strip()
                patt = re.match(b".*go([0-9]+\.[0-9]+(\.[0-9]+|beta[0-9]+|alpha[0-9]+|rc[0-9]+)).*", line)
                if patt:
                    vers = anchore_engine.utils.ensure_str(patt.group(1))
                    final_loc = fullpath
                    if memberhash.get(os.path.join(os.path.dirname(member.name), 'bin', 'go'), None):
                        final_loc = os.path.join("/", os.path.dirname(member.name), 'bin', 'go')
                    evidence['go']['devel'].append( (vers, final_loc) )
                    break    

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
squashtar = os.path.join(unpackdir, "squashed.tar")

resultlist = {}
version_found_map = {}

try:
    allfiles = {}
    if os.path.exists(unpackdir + "/anchore_allfiles.json"):
        with open(unpackdir + "/anchore_allfiles.json", 'r') as FH:
            allfiles = json.loads(FH.read())
    else:
        fmap, allfiles = anchore_engine.analyzers.utils.get_files_from_squashtar(os.path.join(unpackdir, "squashed.tar"))
        with open(unpackdir + "/anchore_allfiles.json", 'w') as OFH:
            OFH.write(json.dumps(allfiles))

    # read in previous analyzer output for helping to increase accuracy of findings
    fname = os.path.join(outputdir, 'pkgfiles.all')
    pkgfilesall = anchore_engine.analyzers.utils.read_kvfile_todict(fname)
    
    evidence = OrderedDict()

    evidence['python'] = OrderedDict()
    evidence['python']['binary'] = []
    evidence['python']['devel'] = []    
    
    evidence['go'] = OrderedDict()
    evidence['go']['binary'] = []
    evidence['go']['devel'] = []        
    
    with tarfile.open(os.path.join(unpackdir, "squashed.tar"), mode='r', format=tarfile.PAX_FORMAT) as tfl:
        alltnames = tfl.getnames()
        alltfiles = {}
        for name in alltnames:
            alltfiles[name] = True

        memberhash = anchore_engine.analyzers.utils.get_memberhash(tfl)
        for member in list(memberhash.values()):
            try:
                get_python_evidence(tfl, member, memberhash, evidence)
            except Exception as err:
                print ("WARN: caught exception evaluating file ({}) for python runtime evidence: {}".format(member.name, str(err)))

            try:
                get_golang_evidence(tfl, member, memberhash, evidence)
            except Exception as err:
                print ("WARN: caught exception evaluating file ({}) for golang runtime evidence: {}".format(member.name, str(err)))

        resultlist = {}
        for runtime in evidence.keys(): #['python', 'go']:
            for e in evidence[runtime].keys(): #['binary', 'devel']:
                for t in evidence[runtime][e]:
                    version, location = t
                    if location in pkgfilesall:
                        print ("INFO: Skipping evidence {} - file is owned by OS package".format(location))
                    else:
                        key = "{}-{}".format(runtime, version)
                        if key not in version_found_map:
                            result = {
                                'name': runtime,
                                'version': version,
                                'location': location,
                                'type': 'binary',
                                'files': [],
                                'license': 'N/A',
                                'origin': 'N/A',
                                'metadata': json.dumps({"evidence_type": e})
                            }
                            resultlist[location] = json.dumps(result)
                            version_found_map[key] = True
except Exception as err:
    import traceback
    traceback.print_exc()
    print("WARN: analyzer unable to complete - exception: " + str(err))

if resultlist:
    ofile = os.path.join(outputdir, 'pkgs.binary')
    anchore_engine.analyzers.utils.write_kvfile_fromdict(ofile, resultlist)

sys.exit(0)
