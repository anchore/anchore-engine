"""
Docker-related utilities for interacting with docker entities and mechanisms.

"""
import copy
import json
import re

from anchore_engine.subsys import logger


def parse_dockerimage_string(instr, strict=True):
    """
    !!!! DEPRECATED !!! Please use DockerImageReference.parse instead

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
            raise ValueError(
                "bad character(s) {} in dockerimage string input ({})".format(
                    bad_chars, instr
                )
            )

    if re.match(r"^sha256:.*", instr):
        registry = "docker.io"
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
            elif a == "docker.io":
                host = "docker.io"
                port = None
            elif a in ("localhost", "localhost.localdomain", "localbuild"):
                host = a
                port = None
            else:
                patt = re.match(r".*\..*", a)
                if patt:
                    host = a
                else:
                    host = "docker.io"
                    remain = instr
                port = None

        else:
            host = "docker.io"
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
            registry = ":".join([host, port])
        else:
            registry = host

        if digest:
            repotag = "@".join([repo, digest])
        else:
            repotag = ":".join([repo, tag])

        fulltag = "/".join([registry, repotag])

        if not digest:
            digest = None
        else:
            fulldigest = registry + "/" + repo + "@" + digest
            tag = None
            fulltag = None
            repotag = None

    ret = {}
    ret["host"] = host
    ret["port"] = port
    ret["repo"] = repo
    ret["tag"] = tag
    ret["registry"] = registry
    ret["repotag"] = repotag
    ret["fulltag"] = fulltag
    ret["digest"] = digest
    ret["fulldigest"] = fulldigest
    ret["imageId"] = imageId

    if ret["fulldigest"]:
        ret["pullstring"] = ret["fulldigest"]
    elif ret["fulltag"]:
        ret["pullstring"] = ret["fulltag"]
    else:
        ret["pullstring"] = None

    return ret


class DockerImageTag:
    """
    Docker Image Tag strings can come in a few different formats:
        - registry_host:registry_port/repository@digest
        - registry_host:registry_port/repository:tag
        - simple_registry/repository:tag
        - simple_registry/repository@digest
        - repository:tag
            - in this case, we assume the registry is docker.io
        - repository@digest
            - in this case, we assume the registry is docker.io

    The aim of this class is to break this string into it's respective parts:
        - registry, repository, and (tag OR digest)
    """

    def __init__(self, docker_input: str):
        """
        docker_input should be a tag format (see above), not a digest or image ID
        """
        self.registry = "docker.io"
        self.repository = None
        self.tag = "latest"
        self.digest = None
        self.parse(docker_input)

    def get_host(self):
        registry_contains_port = re.match(r"(.*?):(.*)", self.registry)
        if registry_contains_port:
            return registry_contains_port.group(1)
        return self.registry

    def get_port(self):
        registry_contains_port = re.match(r"(.*?):(.*)", self.registry)
        if registry_contains_port:
            return registry_contains_port.group(2)
        return None

    def get_repository_tag(self):
        if self.digest:
            return "@".join([self.repository, self.digest])
        else:
            return ":".join([self.repository, self.tag])

    def get_full_tag(self):
        return "/".join([self.registry, self.get_repository_tag()])

    def get_full_digest(self):
        if self.digest:
            return "%s/%s@%s" % (self.registry, self.repository, self.digest)
        return None

    def parse_registry(self, docker_input: str):
        input_contains_registry = re.match(r"(.*?)/(.*)", docker_input)
        if input_contains_registry:
            self.registry = input_contains_registry.group(1)

    def parse_repository(self, docker_input: str):
        input_contains_registry = re.match(r"(.*?)/(.*)", docker_input)
        if input_contains_registry:
            repository_and_details = input_contains_registry.group(2)
        else:
            repository_and_details = docker_input

        contains_digest = re.match(r"(.*)@(.*)", repository_and_details)
        if contains_digest:
            self.repository = contains_digest.group(1)
        else:
            contains_tag = re.match(r"(.*):(.*)", repository_and_details)
            if contains_tag:
                self.repository = contains_tag.group(1)
            else:
                self.repository = repository_and_details

    def parse_digest(self, docker_input: str):
        input_is_repository_at_digest = re.match(r"(.*)@(.*)", docker_input)
        if input_is_repository_at_digest:
            self.digest = input_is_repository_at_digest.group(2)

    def parse_tag(self, docker_input: str):
        input_contains_tag = re.match(r"(.*):(.*)", docker_input)
        if input_contains_tag:
            self.tag = input_contains_tag.group(2)

    def parse(self, docker_input: str):
        self.parse_registry(docker_input)
        self.parse_repository(docker_input)
        self.parse_digest(docker_input)
        self.parse_tag(docker_input)

    def to_image_info_dict(self):
        return {
            "host": self.get_host(),
            "port": self.get_port(),
            "repo": self.repository,
            "tag": self.tag if not self.digest else None,
            "registry": self.registry,
            "repotag": self.get_repository_tag(),
            "fulltag": self.get_full_tag(),
            "digest": self.digest if self.digest else None,
            "fulldigest": self.get_full_digest(),
        }


class DockerImageReference:
    """
    An object representing an image reference in a registry
    """

    _tag_pullstring_format = "{registry}/{repository}:{tag}"
    _digest_pullstring_format = "{registry}/{repository}@{digest}"

    def __init__(self):
        self.host = None
        self.port = None
        self.registry = None
        self.repository = None
        self.tag = None
        self.digest = None
        self.image_id = None

    def has_tag(self):
        return self.tag is not None

    @staticmethod
    def is_digest(docker_input: str) -> bool:
        return re.match(r"^sha256:.*", docker_input)

    def has_digest(self):
        return self.digest is not None

    @staticmethod
    def is_id(docker_input: str) -> bool:
        return len(docker_input) == 64 and not re.findall(
            r"[^0-9a-fA-F]+", docker_input
        )

    def has_id(self):
        return self.image_id is not None

    def tag_pullstring(self):
        if not all((self.registry, self.repository, self.tag)):
            raise Exception(
                "missing one of registry, repository or tag to construct the pullstring"
            )
        return self._tag_pullstring_format.format(
            registry=self.registry, repository=self.repository, tag=self.tag
        )

    def digest_pullstring(self):
        if not all((self.registry, self.repository, self.tag)):
            raise Exception(
                "missing one of registry, repository or tag to construct the pullstring"
            )
        return self._digest_pullstring_format.format(
            registry=self.registry, repository=self.repository, digest=self.digest
        )

    @staticmethod
    def validate_input(docker_input: str):
        bad_chars = re.findall(r"[^a-zA-Z0-9@:/_\.\-]", docker_input)
        if bad_chars:
            raise ValueError(
                "bad character(s) {} in dockerimage string input ({})".format(
                    bad_chars, docker_input
                )
            )

    def parse(self, docker_input: str, strict=True) -> dict:
        logger.debug("input string to parse: %s", docker_input)
        docker_input = docker_input.strip()
        if strict is True:
            self.validate_input(docker_input)

        image_info = {
            "host": None,
            "port": None,
            "repo": None,
            "tag": None,
            "registry": None,
            "repotag": None,
            "fulltag": None,
            "digest": None,
            "fulldigest": None,
            "imageId": None,
            "pullstring": None,
        }
        if self.is_digest(docker_input):
            image_info["registry"] = "docker.io"
            image_info["digest"] = docker_input
        elif self.is_id(docker_input):
            image_info["imageId"] = docker_input
        else:
            tag = DockerImageTag(docker_input)
            image_info.update(tag.to_image_info_dict())

        if image_info["fulldigest"]:
            image_info["pullstring"] = image_info["fulldigest"]
        elif image_info["fulltag"]:
            image_info["pullstring"] = image_info["fulltag"]
        return image_info

    @classmethod
    def from_string(cls, input_string, strict=True):
        parsed = parse_dockerimage_string(input_string, strict)
        if not parsed:
            raise ValueError(
                "invalid format for docker reference: {}".format(input_string)
            )

        return cls.from_info_dict(parsed)

    @classmethod
    def from_info_dict(cls, image_info: dict):
        """

        :param image_info: dictionary output confirmant to output from the parse_dockerimage_string() function
        :return:
        """

        i = DockerImageReference()
        i.host = image_info.get("host")
        i.port = image_info.get("port")
        i.registry = image_info.get("registry")
        i.repository = image_info.get("repo")
        i.tag = image_info.get("tag")
        i.digest = image_info.get("digest")
        i.image_id = image_info.get("imageId")
        return i


class DockerV1ManifestMetadata:
    """
    Processed manifest data that exposes the history, inferred dockerfile, etc based on a Docker Image Manifest v2 schema 1: https://docs.docker.com/registry/spec/manifest-v2-1/
    """

    def __init__(self, manifest_json):
        self.raw = manifest_json
        self.layer_ids = self._layer_ids()
        self.history = self._history()
        self.inferred_dockerfile = self._infer_dockerfile()
        self.architecture = self._architecture()

    def _architecture(self):
        return self.raw.get("architecture")

    def _layer_ids(self):
        """
        Return list of layer ids in build execution order (index 0 is first cmd of build, index N-1 is last instruction)

        :return:
        """
        layers = [layer["blobSum"] for layer in self.raw.get("fsLayers", [])]

        # Reverse the order to normalize order w/V2
        layers.reverse()

        return layers

    def _history(self):
        history = []
        count = 0

        layers = self._layer_ids()
        layers.reverse()  # Reverse again to get back to original order

        for layer in self.raw.get("history", []):
            hel = json.loads(layer["v1Compatibility"])
            lsize = hel.get("Size", 0)

            lcreatedby = ""
            cmds = hel.get("container_config", {}).get("Cmd", [])
            if cmds:
                lcreatedby = " ".join(cmds)

            lcreated = hel.get("created", "")

            lid = layers[count]
            count = count + 1
            history.append(
                {
                    "Created": lcreated,
                    "CreatedBy": lcreatedby,
                    "Comment": "",
                    "Id": lid,
                    "Size": lsize,
                    "Tags": [],
                }
            )

        return history

    def _infer_dockerfile(self):
        # get dockerfile_contents (translate history to guessed DF)
        dockerfile_contents = "FROM scratch\n"
        for hel in self._history():
            patt = re.match(r"^/bin/sh -c #\(nop\) +(.*)", hel["CreatedBy"])
            if patt:
                cmd = patt.group(1)
            elif hel["CreatedBy"]:
                cmd = "RUN " + hel["CreatedBy"]
            else:
                cmd = None
            if cmd:
                dockerfile_contents = dockerfile_contents + cmd + "\n"

        return dockerfile_contents


class DockerV2ManifestMetadata:
    """
    Processed manifest data that exposes the history, inferred dockerfile, etc based on a Docker Image Manifest v2 schema 2: https://docs.docker.com/registry/spec/manifest-v2-2/
    """

    def __init__(self, manifest_json, image_config_json):
        """

        :param manifest_json:
        :param image_config_json:
        :param downloaded_blob_list: list of string filenames for blobs downloaded, assumed to be sh256 digests
        """

        self.raw = manifest_json
        self.image_config = image_config_json
        self.layer_ids = self._layer_ids()
        self.history = self._history()
        self.inferred_dockerfile = self._infer_dockerfile()
        self.architecture = self._architecture()

    def _architecture(self):
        if not self.image_config:
            # Cannot get it without the config, manifest is insufficient
            return None

        return self.image_config.get("architecture")

    def _layer_ids(self):
        # Filter out all empty layers
        return [
            x.get("digest")
            for x in self.raw.get("layers")
            if not x.get("empty_layer", False)
        ]

    def _history(self):
        # add support for cases where image metadata does not contain a history element at all
        rawhistory = copy.copy(self.image_config.get("history"))
        rawlayers = copy.copy(
            self.raw.get("layers", [])
        )  # This is carried over from old impl

        if rawhistory is None:
            # Construct the right number of empty history elements for each layer
            rawhistory = [{}] * len(rawlayers)

        history = []
        for entry in rawhistory:
            if entry.get("empty_layer", False):
                lid = "<missing>"
                lsize = 0
            else:
                lel = rawlayers.pop(0)
                lid = lel["digest"]
                lsize = lel["size"]

            history.append(
                {
                    "Created": entry.get("created", ""),
                    "CreatedBy": entry.get("created_by", ""),
                    "Comment": "",
                    "Id": lid,
                    "Size": lsize,
                    "Tags": [],
                }
            )

        return history

    def _infer_dockerfile(self):
        dockerfile_contents = "FROM scratch\n"
        for hel in self._history():
            patt = re.match(r"^/bin/sh -c #\(nop\) +(.*)", hel["CreatedBy"])
            if patt:
                cmd = patt.group(1)
            elif hel["CreatedBy"]:
                cmd = "RUN " + hel["CreatedBy"]
            else:
                cmd = None
            if cmd:
                dockerfile_contents = dockerfile_contents + cmd + "\n"

        return dockerfile_contents
