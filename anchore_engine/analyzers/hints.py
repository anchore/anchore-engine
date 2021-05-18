import json

from anchore_engine.subsys import logger
from anchore_engine.utils import ensure_str


class HintsTypeError(TypeError):
    """
    This error is raised when input arguments for a content hint are invalid
    """

    pass


class BaseHint:
    def __init__(self, pkg, type):
        self.type = type
        self.name = ensure_str(pkg.get("name", ""))
        self.version = ensure_str(pkg.get("version", ""))
        self.origin = ensure_str(pkg.get("origin", ""))

    def check_required_fields(self):
        if not all([self.name, self.version, self.type]):
            raise HintsTypeError(
                "bad hints record, all hints records must supply at least a name, version and type"
            )

    def normalize(self):
        pass

    @staticmethod
    def get_list_value(pkg, key):
        if not key:
            logger.debug("cannot get list value when key is not specified")
            return []
        value = ensure_str(pkg.get(key, ""))

        # For Gem/NPM hints, we search both the singular and plural key name, where the plural is a list
        list_value = pkg.get(key + "s", [])
        if value and not list_value:
            list_value = [value]
        return list_value

    def to_dict(self) -> dict:
        self.check_required_fields()
        self.normalize()
        return {
            "type": self.type,
            "name": self.name,
            "version": self.version,
            "origin": self.origin,
        }


class RPMHint(BaseHint):
    def __init__(self, pkg):
        super().__init__(pkg, "rpm")
        self.license = ensure_str(pkg.get("license", ""))
        self.arch = ensure_str(pkg.get("arch", "x86_64"))
        self.release = ensure_str(pkg.get("release", ""))
        self.source = ensure_str(pkg.get("source", ""))
        self.size = ensure_str(str(pkg.get("size", "0")))

    def resolve_rpm_fields(self):
        from anchore_engine.util.rpm import split_rpm_filename

        (
            parsed_name,
            parsed_version,
            parsed_release,
            parsed_epoch,
            parsed_arch,
        ) = split_rpm_filename(
            "{}-{}.{}.rpm".format(self.name, self.version, self.arch)
        )
        if self.name == parsed_version:
            raise HintsTypeError(
                "hints package version for hints package ({}) is not valid for RPM package type".format(
                    self.name
                )
            )
        return parsed_name, parsed_version, parsed_release, parsed_epoch, parsed_arch

    def normalize(self):
        if not self.release or not self.source:
            (
                parsed_name,
                parsed_version,
                parsed_release,
                parsed_epoch,
                parsed_arch,
            ) = self.resolve_rpm_fields()

            self.version = parsed_version

            if parsed_epoch:
                self.version = "{}:{}".format(parsed_epoch, parsed_version)

            self.release = parsed_release

            if parsed_arch:
                self.arch = parsed_arch

            if self.source:
                self.source = "{}-{}.{}.rpm".format(self.source, self.version, "src")
            else:
                self.source = "{}-{}-{}.{}.rpm".format(
                    self.name, self.version, self.release, "src"
                )

        if self.arch == "amd64":
            self.arch = "x86_64"

    def to_dict(self) -> dict:
        result = super().to_dict()
        result.update(
            {
                "license": self.license,
                "arch": self.arch,
                "release": self.release,
                "sourcepkg": self.source,
                "size": self.size,
            }
        )
        return result


class PythonHint(BaseHint):
    def __init__(self, pkg):
        super().__init__(pkg, ensure_str(pkg.get("type", "python")).lower())
        self.license = ensure_str(pkg.get("license", ""))
        self.files = pkg.get("files", [])
        self.metadata = json.dumps(pkg.get("metadata", {}))
        self.location = ensure_str(pkg.get("location", "/virtual/pypkg/site-packages"))

    def validate_files(self):
        if not isinstance(self.files, list):
            raise HintsTypeError(
                "bad hints record ({}), files, if specified must be list type".format(
                    self.name
                )
            )

    def normalize(self):
        self.validate_files()

    def to_dict(self) -> dict:
        result = super().to_dict()
        result.update(
            {
                "license": self.license,
                "location": self.location,
                "metadata": self.metadata,
                "files": self.files,
            }
        )
        return result


class GoHint(BaseHint):
    def __init__(self, pkg):
        super().__init__(pkg, ensure_str(pkg.get("type", "go").lower()))
        self.license = ensure_str(pkg.get("license", ""))
        self.arch = ensure_str(pkg.get("arch", "x86_64"))
        self.source = ensure_str(pkg.get("source", ""))
        self.size = ensure_str(str(pkg.get("size", "0")))
        self.metadata = json.dumps(pkg.get("metadata", {}))
        self.location = ensure_str(pkg.get("location", ""))

    def to_dict(self) -> dict:
        result = super().to_dict()
        result.update(
            {
                "license": self.license,
                "arch": self.arch,
                "sourcepkg": self.source,
                "size": self.size,
                "metadata": self.metadata,
                "location": self.location,
            }
        )
        return result


class BinaryHint(BaseHint):
    def __init__(self, pkg):
        super().__init__(pkg, ensure_str(pkg.get("type", "binary").lower()))
        self.license = ensure_str(pkg.get("license", ""))
        self.files = pkg.get("files", [])
        self.metadata = json.dumps(pkg.get("metadata", {}))
        self.location = ensure_str(pkg.get("location", ""))

    def validate_files(self):
        if not isinstance(self.files, list):
            raise HintsTypeError(
                "bad hints record ({}), files, if specified must be list types".format(
                    self.name
                )
            )

    def normalize(self):
        self.validate_files()

    def to_dict(self) -> dict:
        result = super().to_dict()
        result.update(
            {
                "license": self.license,
                "files": self.files,
                "metadata": self.metadata,
                "location": self.location,
            }
        )
        return result


class DebianHint(BaseHint):
    def __init__(self, pkg):
        super().__init__(pkg, "dpkg")
        self.license = ensure_str(pkg.get("license", ""))
        self.arch = ensure_str(pkg.get("arch", "x86_64"))
        self.release = ensure_str(pkg.get("release", ""))
        self.source = ensure_str(pkg.get("source", ""))
        self.size = ensure_str(str(pkg.get("size", "0")))

    def normalize(self):
        if not self.source:
            self.source = "%s-%s" % (self.name, self.version)
        self.release = "N/A"

    def to_dict(self) -> dict:
        result = super().to_dict()
        result.update(
            {
                "license": self.license,
                "arch": self.arch,
                "release": self.release,
                "sourcepkg": self.source,
                "size": self.size,
            }
        )
        return result


class AlpineHint(BaseHint):
    def __init__(self, pkg):
        super().__init__(pkg, "APKG")
        self.license = ensure_str(pkg.get("license", ""))
        self.arch = ensure_str(pkg.get("arch", "x86_64"))
        self.release = ensure_str(pkg.get("release", ""))
        self.source = ensure_str(pkg.get("source", ""))
        self.size = ensure_str(str(pkg.get("size", "0")))
        self.files = pkg.get("files", [])

    def normalize(self):
        if not self.release:
            try:
                self.version, self.release = self.version.split("-", 2)
            except ValueError:
                raise HintsTypeError(
                    "hints package version for hints package ({}) is not valid for APKG package type".format(
                        self.name
                    )
                )

        if not self.source:
            self.source = self.name

    def to_dict(self) -> dict:
        result = super().to_dict()
        result.update(
            {
                "license": self.license,
                "arch": self.arch,
                "release": self.release,
                "sourcepkg": self.source,
                "size": self.size,
                "files": self.files,
            }
        )
        return result


class GemHint(BaseHint):
    def __init__(self, pkg):
        super().__init__(pkg, ensure_str(pkg.get("type", "gem")).lower())
        self.version = self.get_list_value(pkg, "version")
        if self.version:
            self.latest_version = self.version[0]
        else:
            self.latest_version = ""
        self.origin = self.get_list_value(pkg, "origin")
        self.license = self.get_list_value(pkg, "license")
        self.source = ensure_str(pkg.get("source", self.name))
        self.files = pkg.get("files", [])
        self.location = ensure_str(pkg.get("location", ""))

    def normalize(self):
        for inp in [self.version, self.license, self.origin, self.files]:
            if type(inp) is not list:
                raise HintsTypeError(
                    "bad hints record ({}), versions, licenses, origins, and files if specified must be list types".format(
                        self.name
                    )
                )

        if not self.location:
            self.location = "/virtual/gempkg/{}-{}".format(
                self.name, self.latest_version
            )

    # TODO: The keys in this package record are non-standard with the rest of the packages
    # (plural, totally different (see lics))
    def to_dict(self) -> dict:
        self.check_required_fields()
        self.normalize()
        return {
            "type": self.type,
            "name": self.name,
            "versions": self.version,
            "latest": self.latest_version,
            "origins": self.origin,
            "lics": self.license,
            "sourcepkg": self.source,
            "files": self.files,
            "location": self.location,
        }


class NPMHint(BaseHint):
    def __init__(self, pkg):
        super().__init__(pkg, ensure_str(pkg.get("type", "npm")).lower())
        self.version = self.get_list_value(pkg, "version")
        if self.version:
            self.latest_version = self.version[0]
        else:
            self.latest_version = ""
        self.origin = self.get_list_value(pkg, "origin")
        self.license = self.get_list_value(pkg, "license")
        self.source = ensure_str(pkg.get("source", self.name))
        self.files = pkg.get("files", [])
        self.location = ensure_str(pkg.get("location", ""))

    def normalize(self):
        for inp in [self.version, self.license, self.origin, self.files]:
            if type(inp) is not list:
                raise HintsTypeError(
                    "bad hints record ({}), versions, licenses, origins, and files if specified must be list types".format(
                        self.name
                    )
                )

        if not self.location:
            self.location = "/virtual/npmpkg/{}-{}".format(
                self.name, self.latest_version
            )

    # TODO: The keys in this package record are non-standard with the rest of the packages
    # (plural, totally different (see lics))
    def to_dict(self) -> dict:
        self.check_required_fields()
        self.normalize()
        return {
            "type": self.type,
            "name": self.name,
            "versions": self.version,
            "latest": self.latest_version,
            "origins": self.origin,
            "lics": self.license,
            "sourcepkg": self.source,
            "files": self.files,
            "location": self.location,
        }


class JavaHint(BaseHint):
    def __init__(self, pkg):
        super().__init__(pkg, ensure_str(pkg.get("type", "java")).lower())
        self.jar_type = "%s-jar" % self.type
        self.location = ensure_str(
            pkg.get(
                "location", "/virtual/javapkg/%s-%s.jar" % (self.name, self.version)
            )
        )
        self.metadata = pkg.get("metadata", {})

    def to_dict(self) -> dict:
        result = super().to_dict()
        result.update(
            {
                "specification-version": self.version,
                "implementation-version": self.version,
                "maven-version": self.version,
                "metadata": self.metadata,
                "location": self.location,
                "type": self.jar_type,
            }
        )
        del result["version"]
        return result


hints_by_type = {
    "gem": GemHint,
    "python": PythonHint,
    "npm": NPMHint,
    "java": JavaHint,
    "apkg": AlpineHint,
    "rpm": RPMHint,
    "dpkg": DebianHint,
}
