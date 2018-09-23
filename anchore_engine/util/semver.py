import json
import re
from distutils.version import LooseVersion, StrictVersion

from anchore_engine.subsys import logger

def normalized_version_match(rawsemver, rawpkgver, use_strict=True):
    versionmatch = False

    if use_strict:
        try:
            pkgver = StrictVersion(rawpkgver)
        except ValueError:
            use_strict = False
            pkgver = LooseVersion(rawpkgver)
    else:
        pkgver = LooseVersion(rawpkgver)

    vranges = rawsemver.split("||")
    # or check
    inrange = False
    for vrange in vranges:
        vrange = vrange.strip()
        if vrange in ['*', 'all']:
            inrange = True
            rangematch = vrange
            break

        tokre = re.compile("[!|<|>|=]+\s*[^\s]+")
        rangechecks = tokre.findall(vrange)

        # and check
        violation = False
        for rangecheck in rangechecks:
            rangecheck = re.sub(r"\s+", "", rangecheck)
            patt = re.match("([!|<|>|=]+)(.*)", rangecheck)
            if patt:
                op,verraw = (patt.group(1), patt.group(2))

                if use_strict:
                    try:
                        ver = StrictVersion(verraw)
                    except ValueError:
                        ver = LooseVersion(verraw)
                else:
                    ver = LooseVersion(verraw)

                if op == '>':
                    if not pkgver > ver:
                        violation = True
                        break
                elif op == '>=':
                    if not pkgver >= ver:
                        violation = True
                        break
                elif op == '<':
                    if not pkgver < ver:
                        violation = True
                        break
                elif op == '<=':
                    if not pkgver <= ver:
                        violation = True
                        break
                elif op in ['=', '==']:
                    if not pkgver == ver:
                        violation = True
                        break
                elif op == '!=':
                    if not pkgver != ver:
                        violation = True
                        break
                else:
                    raise Exception("unknown op {}".format(op))
            else:
                raise Exception("unknown range format {}".format(rangecheck))

        if not violation:
            inrange = True
            rangematch = vrange
            break

    if inrange:
        versionmatch = True

    #if (versionmatch):
    #    print ("MATCHINFO MATCH:{} PKGVER:{}, ACTUAL:{}, ALL:{}".format(versionmatch, rawpkgver, rangematch, rawsemver))
    #else:
    #    print ("MATCHINFO MATCH:{} PKGVER:{}, ALL:{}".format(versionmatch, rawpkgver, rawsemver))
    return(versionmatch)

def convert_mrange_to_srange(rawsemver):
    normal_ranges = []

    tokre = re.compile("[\[|\(][^[\]|\)]+[\]|\)]")
    vranges = tokre.findall(rawsemver)
    for vrange in vranges:
        patt = re.match("([\[|\(])([^[\]|\)]+)([\]|\)])", vrange)
        if patt:
            equalop = False
            nequalop = False
            startopraw = patt.group(1)
            endopraw = patt.group(3)

            try:
                startverraw, endverraw = patt.group(2).split(',', 2)
            except:
                if startopraw == '[':
                    equalop = True
                elif startopraw == '(':
                    nequalop = True
                else:
                    raise Exception("cannot handle range string {}".format(vrange))
                startverraw = endverraw = patt.group(2)

            if startverraw in ['0', '0.0', '0.0.0']:
                startverraw = None

            if endverraw in ['0', '0.0', '0.0.0']:
                endverraw = None

            normal_range = []
            if equalop:
                normal_range.append("=={}".format(startverraw))
            elif nequalop:
                normal_range.append("!={}".format(startverraw))
            else:
                if startverraw and startopraw == '[':
                    normal_range.append(">={}".format(startverraw))
                elif startverraw and startopraw == '(':
                    normal_range.append(">{}".format(startverraw))

                if endverraw and endopraw == ']':
                    normal_range.append("<={}".format(endverraw))
                elif endverraw and endopraw == ')':
                    normal_range.append("<{}".format(endverraw))
            normal_ranges.append(' '.join(normal_range))

    normal_semver = ' || '.join(normal_ranges)
    return(normal_semver)

def convert_rrange_to_srange(rawsemver):
    #toks = rawsemver.split(",")
    toks = re.split(", *", rawsemver)
    if len(toks) > 2:
        raise Exception("cannot handle range of len greater than 2")
    ret = " ".join(re.sub(' +', '', x) for x in toks)
    #ret = "{} {}".format(re.sub(' +', '', start), re.sub(' +', '', end))
    return(ret)

def convert_langversionlist_to_semver(versionlist, language):

    use_strict = False
    semvers = []

    for version in versionlist:
        normal_semver = None
        if language in ['python', 'maven', 'java']:
            normal_semver = convert_mrange_to_srange(version)
            if language == 'python':
                use_strict = True
            else:
                use_strict = False
        elif language in ['js', 'npm']:
            normal_semver = version
            use_strict = False
        elif language in ['ruby', 'gem']:
            normal_semver = convert_rrange_to_srange(version)
            use_strict = False
        else:
            pass

        if normal_semver:
            semvers.append(normal_semver)

    normal_semver_range = ' || '.join(semvers)
    return(normal_semver_range, use_strict)

def compare_versions(rawsemver, rawpkgver, language=None):
    ret = False
    versionmatch = False
    use_strict = False

    if language in ['python']:
        use_strict = True
    else:
        use_strict = False

    normal_semver = rawsemver
    ret = normalized_version_match(normal_semver, rawpkgver, use_strict=use_strict)
    return(ret)

