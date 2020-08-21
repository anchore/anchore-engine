"""
Docker-related utilities for interacting with docker entities and mechanisms.

"""
import re

from anchore_engine.subsys import logger


def parse_dockerimage_string(instr, strict=True):
    """
    Parses a string you'd give 'docker pull' into its consitutent parts: registry, repository, tag and/or digest.
    Returns a dict with keys:

    host - hostname for registry
    port - port for registry
    repo - repository name and user/namespace if present
    tag - tag value
    registry - registry full string including host and port
    repotag - repo and tag section only: repo:tag
    fulltag - the full tag in pullable forn: registry/repo:tag
    digest - the digest component if present
    fulldigest - a pullable digest string of form: registry/repo@digest
    imageId - the image id if this is an image id only, in that case pullstring is None
    pullstring - a string you can use to pull the image


    Copied from the drogue code

    :param instr:
    :param strict: enforce that the input string input has all valid chars
    :raises: ValueError on invalid input (unless strict=False)
    :return: dict with keys described above
    """

    host = None
    port = None
    repo = None
    tag = None
    registry = None
    repotag = None
    fulltag = None
    fulldigest = None
    digest = None
    imageId = None

    logger.debug("input string to parse: {}".format(instr))
    instr = instr.strip()
    if strict is True:
        bad_chars = re.findall(r"[^a-zA-Z0-9@:/_\.\-]", instr)
        if bad_chars:
            raise ValueError("bad character(s) {} in dockerimage string input ({})".format(bad_chars, instr))

    if re.match(r"^sha256:.*", instr):
        registry = 'docker.io'
        digest = instr

    elif len(instr) == 64 and not re.findall(r"[^0-9a-fA-F]+", instr):
        imageId = instr
    else:

        # get the host/port
        patt = re.match(r"(.*?)/(.*)", instr)
        if patt:
            a = patt.group(1)
            remain = patt.group(2)
            patt = re.match(r"(.*?):(.*)", a)
            if patt:
                host = patt.group(1)
                port = patt.group(2)
            elif a == 'docker.io':
                host = 'docker.io'
                port = None
            elif a in ('localhost', 'localhost.localdomain', 'localbuild'):
                host = a
                port = None
            else:
                patt = re.match(r".*\..*", a)
                if patt:
                    host = a
                else:
                    host = 'docker.io'
                    remain = instr
                port = None

        else:
            host = 'docker.io'
            port = None
            remain = instr

        # get the repo/tag
        patt = re.match(r"(.*)@(.*)", remain)
        if patt:
            repo = patt.group(1)
            digest = patt.group(2)
        else:
            patt = re.match(r"(.*):(.*)", remain)
            if patt:
                repo = patt.group(1)
                tag = patt.group(2)
            else:
                repo = remain
                tag = "latest"

        if not tag:
            tag = "latest"

        if port:
            registry = ':'.join([host, port])
        else:
            registry = host

        if digest:
            repotag = '@'.join([repo, digest])
        else:
            repotag = ':'.join([repo, tag])

        fulltag = '/'.join([registry, repotag])

        if not digest:
            digest = None
        else:
            fulldigest = registry + '/' + repo + '@' + digest
            tag = None
            fulltag = None
            repotag = None

    ret = {}
    ret['host'] = host
    ret['port'] = port
    ret['repo'] = repo
    ret['tag'] = tag
    ret['registry'] = registry
    ret['repotag'] = repotag
    ret['fulltag'] = fulltag
    ret['digest'] = digest
    ret['fulldigest'] = fulldigest
    ret['imageId'] = imageId

    if ret['fulldigest']:
        ret['pullstring'] = ret['fulldigest']
    elif ret['fulltag']:
        ret['pullstring'] = ret['fulltag']
    else:
        ret['pullstring'] = None

    return ret
