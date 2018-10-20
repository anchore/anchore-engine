import json
import re
import semantic_version

from distutils.version import LooseVersion, StrictVersion
from pkg_resources import parse_version

from anchore_engine.subsys import logger
from anchore_engine.util.maven import MavenVersion

zerolikes = ['0', '0.0', '0.0.0', '0.0.0.0']

def language_compare(a, op, b, language='python'):
    global zerolikes

    if op not in ['>', '<', '<=', '>=', '!=', '=', '==', '~', '^']:
        raise Exception("unknown op {}".format(op))
    elif not a or not b:
        raise Exception("must supply valid inputs a={} op={} b={}".format(a, op, b))

    aoptions = []
    boptions = []
    if language in ['java', 'maven']:
        aoptions = [MavenVersion(a)]
        boptions = [MavenVersion(b)]
    elif language in ['js', 'npm', 'ruby', 'gem']:
        try:
            aoptions = [semantic_version.Version.coerce(a)]
            boptions = [semantic_version.Version.coerce(b)]
        except:
            logger.debug("{} versions {}/{} unable to load as semantic_versions - falling back to parse_version".format(language, a, b))
            aoptions = [parse_version(a)]
            boptions = [parse_version(b)]
    elif language in ['python']:
        try:
            aoptions = [StrictVersion(a), LooseVersion(a)]
            boptions = [StrictVersion(b), LooseVersion(b)]
        except:
            logger.debug("python versions {}/{} unable to load as StrictVersion - falling back to LooseVersion/parse_version".format(a, b))
            aoptions = [LooseVersion(a), parse_version(a)]
            boptions = [LooseVersion(b), parse_version(b)]
    else:
        raise Exception("language {} not supported for version comparison".format(language))

    for i in range(0, len(aoptions)):
        try:
            if op == '>':
                if b in zerolikes:
                    return(True)
                if aoptions[i] > boptions[i]:
                    return(True)
                else:
                    return(False)
            elif op == '>=':
                if b in zerolikes:
                    return(True)
                if aoptions[i] >= boptions[i]:
                    return(True)
                else:
                    return(False)
            elif op == '<':
                if b in zerolikes:
                    return(False)
                if aoptions[i] < boptions[i]:
                    return(True)
                else:
                    return(False)
            elif op == '<=':
                if aoptions[i] <= boptions[i]:
                    return(True)
                else:
                    return(False)
            elif op in ['=', '==']:
                if aoptions[i] == boptions[i]:
                    return(True)
                else:
                    return(False)
            elif op == '!=':
                if aoptions[i] != boptions[i]:
                    return(True)
                else:
                    return(False)
            elif op == '~':
                # for these operations, attempt to coerce and compare with semantic_version
                ha = semantic_version.Version.coerce(str(aoptions[i]))
                hb = semantic_version.Version.coerce(str(boptions[i]))
                hs = semantic_version.Spec("~{}".format(hb))
                rc = hs.match(ha)
                return(rc)
            elif op == '^':
                # for these operations, attempt to coerce and compare with semantic_version
                ha = semantic_version.Version.coerce(str(aoptions[i]))
                hb = semantic_version.Version.coerce(str(boptions[i]))
                hs = semantic_version.Spec("^{}".format(hb))
                rc = hs.match(ha)
                return(rc)
        except Exception as err:
            pass

    return(False)

def normalized_version_match(rawsemver, rawpkgver, language='python'):
    versionmatch = False

    vranges = re.split(r" *\|\| *", rawsemver)
    # or check
    inrange = False
    for vrange in vranges:
        vrange = vrange.strip()
        if vrange in ['*', 'all']:
            inrange = True
            rangematch = vrange
            break

        tokre = re.compile(r"[!|<|>|=|~|^]+\s*[^\s]+")
        rangechecks = tokre.findall(vrange)

        # and check
        violation = False
        if not rangechecks:
            raise Exception("invalid range detected - {}".format(vrange))

        for rangecheck in rangechecks:
            rangecheck = re.sub(r"\s+", "", rangecheck)
            patt = re.match("([!|<|>|=|~|^]+)(.*)", rangecheck)
            if patt:
                op,verraw = (patt.group(1), patt.group(2))
                inrange = language_compare(rawpkgver, op, verraw, language=language)
                if not inrange:
                    violation = True
                    break
            else:
                raise Exception("unknown range format {}".format(rangecheck))

        if not violation:
            inrange = True
            rangematch = vrange
            break

    if inrange:
        versionmatch = True

    return(versionmatch)

def convert_mrange_to_srange(rawsemver):
    normal_ranges = []

    tokre = re.compile(r"[\[|\(][^[\]|\)]+[\]|\)]")
    vranges = tokre.findall(rawsemver)
    for vrange in vranges:
        patt = re.match(r"([\[|\(])([^[\]|\)]+)([\]|\)])", vrange)
        if patt:
            equalop = False
            nequalop = False
            startopraw = patt.group(1)
            endopraw = patt.group(3)

            try:
                startverraw, endverraw = patt.group(2).split(',', 2)
                startverraw = re.sub(" *", "", startverraw)
                endverraw = re.sub(" *", "", endverraw)
            except:
                if startopraw == '[':
                    equalop = True
                elif startopraw == '(':
                    nequalop = True
                else:
                    raise Exception("cannot handle range string {}".format(vrange))
                startverraw = endverraw = patt.group(2)

            normal_range = []
            if startverraw and equalop:
                normal_range.append("=={}".format(startverraw))
            elif startverraw and nequalop:
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
    toks = re.split(", *", rawsemver)
    if len(toks) > 2:
        raise Exception("cannot handle range of len greater than 2")
        
    ret = " ".join(re.sub(r'\s+', "", x) for x in toks)
    return(ret)

def cleanup_range(rawrange):
    vtoks = rawrange.split("||")
    final_vtoks = []
    for vtok in vtoks:
        toks = [vtok]
        final_toks = []
        for tok in toks:
            tok = re.sub(r"^\s+", "", tok)
            if tok:
                if tok[0] not in ['<', '>', '!', '=', '~', '^']:
                    final_toks.append("={}".format(tok))
                else:
                    final_toks.append(tok)        
            else:
                final_toks.append("<0.0.0")
        final_vtoks.append(" ".join(final_toks))
    retrange = " || ".join(final_toks)
    return(retrange)

def convert_langversionlist_to_semver(versionlist, language):
    semvers = []
    for version in versionlist:
        normal_semver = None
        if language in ['python', 'maven', 'java', 'dotnet']:
            normal_semver = cleanup_range(convert_mrange_to_srange(version))
        elif language in ['js', 'npm', 'golang', 'go']:
            normal_semver = cleanup_range(version)
        elif language in ['ruby', 'gem', 'php']:
            normal_semver = cleanup_range(convert_rrange_to_srange(version))
        else:
            pass

        if normal_semver:
            semvers.append(normal_semver)

    if semvers:
        normal_semver_range = ' || '.join(semvers)
    else:
        normal_semver_range = '*'
    
    return(normal_semver_range)

def langpack_is_all(rawsemver):
    global zerolikes

    if rawsemver in ['*', 'all']:
        return(True)
    
    for zl in zerolikes:
        if rawsemver == ">{}".format(zl) or rawsemver == ">={}".format(zl):
            return(True)

    return(False)

def compare_versions(rawsemver, rawpkgver, language='python'):
    ret = False
    versionmatch = False
    if not rawsemver:
        raise Exception("empty version range passed as input")
    normal_semver = rawsemver
    ret = normalized_version_match(normal_semver, rawpkgver, language=language)
    return(ret)
