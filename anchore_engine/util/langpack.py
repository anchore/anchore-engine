import re
import semantic_version

from distutils.version import LooseVersion, StrictVersion
from pkg_resources import parse_version

from anchore_engine.subsys import logger
from anchore_engine.util.maven import MavenVersion

zerolikes = ["0", "0.0", "0.0.0", "0.0.0.0"]


def language_compare(a, op, b, language="python"):
    if op not in [">", "<", "<=", ">=", "!=", "=", "==", "~", "^"]:
        raise Exception("unknown op {}".format(op))
    elif not a or not b:
        raise Exception("must supply valid inputs a={} op={} b={}".format(a, op, b))

    aoptions = []
    boptions = []
    if language in ["java", "maven"]:
        aoptions = [MavenVersion(a)]
        boptions = [MavenVersion(b)]
    elif language in ["js", "npm", "ruby", "gem", "nuget"]:
        try:
            aoptions = [semantic_version.Version.coerce(a)]
            boptions = [semantic_version.Version.coerce(b)]
        except ValueError:
            logger.debug(
                "{} versions {}/{} unable to load as semantic_versions - falling back to parse_version".format(
                    language, a, b
                )
            )
            aoptions = [parse_version(a)]
            boptions = [parse_version(b)]
    elif language in ["python"]:
        try:
            aoptions = [StrictVersion(a), LooseVersion(a)]
            boptions = [StrictVersion(b), LooseVersion(b)]
        except ValueError:
            logger.debug(
                "python versions {}/{} unable to load as StrictVersion - falling back to LooseVersion/parse_version".format(
                    a, b
                )
            )
            aoptions = [LooseVersion(a), parse_version(a)]
            boptions = [LooseVersion(b), parse_version(b)]
    else:
        raise Exception(
            "language {} not supported for version comparison".format(language)
        )

    for i in range(0, len(aoptions)):
        try:
            if op == ">":
                if b in zerolikes:
                    return True
                if aoptions[i] > boptions[i]:
                    return True
                else:
                    return False
            elif op == ">=":
                if b in zerolikes:
                    return True
                if aoptions[i] >= boptions[i]:
                    return True
                else:
                    return False
            elif op == "<":
                if b in zerolikes:
                    return False
                if aoptions[i] < boptions[i]:
                    return True
                else:
                    return False
            elif op == "<=":
                if aoptions[i] <= boptions[i]:
                    return True
                else:
                    return False
            elif op in ["=", "=="]:
                if aoptions[i] == boptions[i]:
                    return True
                else:
                    return False
            elif op == "!=":
                if aoptions[i] != boptions[i]:
                    return True
                else:
                    return False
            elif op == "~":
                # for these operations, attempt to coerce and compare with semantic_version
                ha = semantic_version.Version.coerce(str(aoptions[i]))
                hb = semantic_version.Version.coerce(str(boptions[i]))
                hs = semantic_version.Spec("~{}".format(hb))
                rc = hs.match(ha)
                return rc
            elif op == "^":
                # for these operations, attempt to coerce and compare with semantic_version
                ha = semantic_version.Version.coerce(str(aoptions[i]))
                hb = semantic_version.Version.coerce(str(boptions[i]))
                hs = semantic_version.Spec("^{}".format(hb))
                rc = hs.match(ha)
                return rc
        except TypeError:
            pass


def normalized_version_match(rawsemver, rawpkgver, language="python"):
    versionmatch = False

    vranges = re.split(r" *\|\| *", rawsemver)
    # or check
    inrange = False
    for vrange in vranges:
        vrange = vrange.strip()
        if vrange in ["*", "all"]:
            inrange = True
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
                op, verraw = (patt.group(1), patt.group(2))
                inrange = language_compare(rawpkgver, op, verraw, language=language)

                if not inrange:
                    violation = True
                    break

        if not violation:
            inrange = True
            break

    if inrange:
        versionmatch = True

    return versionmatch


def compare_versions(rawsemver, rawpkgver, language="python"):
    ret = False
    if not rawsemver:
        raise Exception("empty version range passed as input")
    normal_semver = rawsemver
    ret = normalized_version_match(normal_semver, rawpkgver, language=language)
    return ret
