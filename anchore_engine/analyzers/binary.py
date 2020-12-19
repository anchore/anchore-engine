import sys
import os
import re
import json
import tarfile
import collections

import anchore_engine.analyzers.utils
import anchore_engine.utils

binary_package_el = {
    "name": None,
    "version": None,
    "location": None,
    "type": "binary",
    "files": [],
    "license": "N/A",
    "origin": "N/A",
    "metadata": {},
}

def _get_python_evidence(tfl, member, memberhash, evidence):
    global binary_package_el

    fullpath = "/{}".format(member.name)
    filename = os.path.basename(fullpath)

    el = {}
    el.update(binary_package_el)

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
                        b_vers = "{}.{}".format(
                            f_vers, anchore_engine.utils.ensure_str(patt.group(1))
                        )
                        if b_vers.startswith(f_vers):
                            el["name"] = "python"
                            el["version"] = b_vers
                            el["location"] = fullpath
                            evidence["python"]["binary"].append(el)
                            break
                except Exception as err:
                    raise err

    elif filename == "patchlevel.h" and member.isreg():
        with tfl.extractfile(member) as FH:
            for line in FH.readlines():
                line = line.strip()
                patt = re.match(b'.*#define +PY_VERSION +"*([0-9\.\-_a-zA-Z]+)"*', line)
                if patt:
                    h_vers = anchore_engine.utils.ensure_str(patt.group(1))
                    el["name"] = "python"
                    el["version"] = h_vers
                    el["location"] = fullpath
                    evidence["python"]["devel"].append(el)
                    break


def _get_golang_evidence(tfl, member, memberhash, evidence):
    global binary_package_el

    fullpath = "/{}".format(member.name)
    filename = os.path.basename(fullpath)

    el = {}
    el.update(binary_package_el)

    if filename in ["go"] and member.isreg():
        with tfl.extractfile(member) as FH:
            for line in FH.readlines():
                subline = line
                try:
                    the_re = ".*go([0-9]+\.[0-9]+(\.[0-9]+|beta[0-9]+|alpha[0-9]+|rc[0-9]+)*).*"
                    patt = re.match(anchore_engine.utils.ensure_bytes(the_re), subline)
                    if patt:
                        vers = anchore_engine.utils.ensure_str(patt.group(1))
                        el["name"] = "go"
                        el["version"] = vers
                        el["location"] = fullpath
                        evidence["go"]["binary"].append(el)
                        break
                except Exception as err:
                    raise err
    elif filename == "VERSION" and member.isreg():
        with tfl.extractfile(member) as FH:
            for line in FH.readlines():
                line = line.strip()
                patt = re.match(
                    b".*go([0-9]+\.[0-9]+(\.[0-9]+|beta[0-9]+|alpha[0-9]+|rc[0-9]+)*).*",
                    line,
                )
                if patt:
                    vers = anchore_engine.utils.ensure_str(patt.group(1))
                    final_loc = fullpath
                    if memberhash.get(
                        os.path.join(os.path.dirname(member.name), "bin", "go"), None
                    ):
                        final_loc = os.path.join(
                            "/", os.path.dirname(member.name), "bin", "go"
                        )

                    el["name"] = "go"
                    el["version"] = vers
                    el["location"] = final_loc
                    evidence["go"]["devel"].append(el)
                    break


def _get_busybox_evidence(tfl, member, memberhash, distrodict, evidence):
    global binary_package_el

    fullpath = "/{}".format(member.name)
    filename = os.path.basename(fullpath)

    if filename == "busybox" and (member.isreg() or member.islnk()):
        # Perform any specific checks using prior metadata
        if distrodict.get("flavor", "") == "BUSYB":
            patt = re.match(
                ".*([0-9]+\.[0-9]+\.[0-9]+).*", distrodict.get("fullversion", "")
            )
            if patt:
                version = anchore_engine.utils.ensure_str(patt.group(1))
                el = {}
                el.update(binary_package_el)

                el["name"] = "busybox"
                el["version"] = version
                el["location"] = fullpath

                evidence["busybox"]["binary"].append(el)

# this is a direct port of the binary analyzer module to here... this should be refactored
def catalog_image(allpkgfiles, unpackdir):
    squashtar = os.path.join(unpackdir, "squashed.tar")

    # get a listing of all files from either a previous run or the squashtar
    allfiles = {}
    if os.path.exists(unpackdir + "/anchore_allfiles.json"):
        with open(unpackdir + "/anchore_allfiles.json", "r") as FH:
            allfiles = json.loads(FH.read())
    else:
        fmap, allfiles = anchore_engine.analyzers.utils.get_files_from_squashtar(
            os.path.join(unpackdir, "squashed.tar")
        )
        with open(unpackdir + "/anchore_allfiles.json", "w") as OFH:
            OFH.write(json.dumps(allfiles))

    # get distro information from the squashtar
    meta = anchore_engine.analyzers.utils.get_distro_from_squashtar(
        os.path.join(unpackdir, "squashed.tar"), unpackdir=unpackdir
    )
    distrodict = anchore_engine.analyzers.utils.get_distro_flavor(
        meta["DISTRO"], meta["DISTROVERS"], likedistro=meta["LIKEDISTRO"]
    )

    # set up ordered dictionary structure for the runtimes and evidence types
    evidence = collections.OrderedDict()
    for runtime in ["python", "go", "busybox"]:
        evidence[runtime] = collections.OrderedDict()
        for etype in ["binary", "devel"]:
            evidence[runtime][etype] = []
    
    # perform a per file routine to evaluate files for gathering binary package version evidence
    with tarfile.open(
        os.path.join(unpackdir, "squashed.tar"), mode="r", format=tarfile.PAX_FORMAT
    ) as tfl:
        alltnames = tfl.getnames()
        alltfiles = {}
        for name in alltnames:
            alltfiles[name] = True

        memberhash = anchore_engine.analyzers.utils.get_memberhash(tfl)
        for member in list(memberhash.values()):
            try:
                _get_python_evidence(tfl, member, memberhash, evidence)
            except Exception as err:
                print(
                    "WARN: caught exception evaluating file ({}) for python runtime evidence: {}".format(
                        member.name, str(err)
                    )
                )

            try:
                _get_golang_evidence(tfl, member, memberhash, evidence)
            except Exception as err:
                print(
                    "WARN: caught exception evaluating file ({}) for golang runtime evidence: {}".format(
                        member.name, str(err)
                    )
                )

            try:
                _get_busybox_evidence(tfl, member, memberhash, distrodict, evidence)
            except Exception as err:
                print(
                    "WARN: caught exception evaluating file ({}) for busybox runtime evidence: {}".format(
                        member.name, str(err)
                    )
                )

    # write evidence back to a results data structure
    resultlist = {}
    version_found_map = {}
    for runtime in evidence.keys():  # ['python', 'go']:
        for e in evidence[runtime].keys():  # ['binary', 'devel']:
            for t in evidence[runtime][e]:

                version = t.get("version")
                location = t.get("location")

                if location in allpkgfiles:
                    print(
                        "INFO: Skipping evidence {} - file is owned by OS package".format(
                            location
                        )
                    )
                else:
                    key = "{}-{}".format(runtime, version)
                    if key not in version_found_map:
                        result = {}
                        result.update(binary_package_el)
                        result.update(t)
                        result["metadata"] = {"evidence_type": e}
                        resultlist[location] = result
                        version_found_map[key] = True

    # process hints file ...
    # note: upstream of this has already wiped out the hints file contents if the service
    # doesn't have hints processing enabled.
    hints = anchore_engine.analyzers.utils.get_hintsfile(unpackdir, squashtar)
    for pkg in hints.get("packages", []):
        pkg_type = pkg.get("type", "").lower()
        if pkg_type == "binary":
            pkg_key, el = anchore_engine.analyzers.utils._hints_to_binary(pkg)

    # transform output into analyzer-module/service "raw" analyzer json document
    nested_dict = lambda: collections.defaultdict(nested_dict)
    findings = nested_dict()

    findings["package_list"]["pkgs.binary"]["base"] = resultlist

    return anchore_engine.analyzers.utils.defaultdict_to_dict(findings)