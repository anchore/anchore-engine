import enum
from anchore_engine.services.policy_engine.engine.policy.gate import BaseTrigger, Gate, LifecycleStates
from anchore_engine.services.policy_engine.engine.policy.params import NameVersionStringListParameter, \
    CommaDelimitedStringListParameter
from anchore_engine.db import ImagePackage, ImagePackageManifestEntry
from anchore_engine.util.packages import compare_package_versions
from anchore_engine.services.policy_engine.engine.logs import get_logger

log = get_logger()


class VerifyTrigger(BaseTrigger):
    __lifecycle_state__ = LifecycleStates.deprecated
    __trigger_name__ = 'verify'
    __description__ = 'Check package integrity against package db in in the image. Triggers for changes or removal or content in all or the selected DIRS param if provided, and can filter type of check with the CHECK_ONLY param'

    pkgs = CommaDelimitedStringListParameter(name='pkgs', description='List of package names to verify', example_str='libssl,openssl,curl', is_required=False)
    directories = CommaDelimitedStringListParameter(name='dirs', description='List of directories to limit checks to so as to avoid checks on all dir', example_str='/usr/share,/usr,/var', is_required=False)
    check_only = CommaDelimitedStringListParameter(name='check_only', description='List of types of checks to perform instead of all', example_str='changed', is_required=False)

    analyzer_type = 'base'
    analyzer_id = 'file_package_verify'
    analyzer_artifact = 'distro.pkgfilemeta'

    class VerificationStates(enum.Enum):
        changed = 'changed'
        missing = 'missing'


    def evaluate(self, image_obj, context):
        pkg_names = self.pkgs.value(default_if_none=[])
        pkg_dirs = self.directories.value(default_if_none=[])
        checks = self.check_only.value(default_if_none=[])

        if image_obj.fs:
            extracted_files_json = image_obj.fs.files
        else:
            extracted_files_json = []

        if pkg_names:
            pkgs = image_obj.packages.filter(ImagePackage.name.in_(pkg_names)).all()
        else:
            pkgs = image_obj.packages.all()

        for pkg in pkgs:
            pkg_name = pkg.name
            records = []
            if pkg_dirs:
                # Filter the specified dirs
                for d in pkg_dirs:
                    records += pkg.pkg_db_entries.filter(ImagePackageManifestEntry.file_path.startswith(d))
            else:
                records = [x for x in pkg.pkg_db_entries.all()]

            for pkg_db_record in records:
                status = self._diff_pkg_meta_and_file(pkg_db_record, extracted_files_json.get(pkg_db_record.file_path))

                if status and (not checks or status.value in checks):
                    self._fire(msg="VERIFY check against package db for package '{}' failed on entry '{}' with status: '{}'".format(pkg_name, pkg_db_record.file_path, status.value))

    @classmethod
    def _diff_pkg_meta_and_file(cls, meta_db_entry, fs_entry):
        """
        Given the db record and the fs record, return one of [False, 'changed', 'removed'] for the diff depending on the diff detected.

        If entries are identical, return False since there is no diff.
        If there isa difference return a VerificationState.

        fs_entry is a dict expected to have the following keys:
        sha256_checksum
        md5_checksum
        sha1_checksum (expected but not required)
        mode - integer converted from the octal mode string
        size - integer size of the file

        :param meta_db_entry: An ImagePackageManifestEntry object built from the pkg db in the image indicating the expected state of the file
        :param fs_entry: A dict with metadata detected from image analysis
        :return: one of [False, <VerificationStates>]
        """

        # The fs record is None or empty
        if meta_db_entry and not fs_entry:
            return VerifyTrigger.VerificationStates.missing

        # This is unexpected
        if (fs_entry and not meta_db_entry) or fs_entry.get('name') != meta_db_entry.file_path:
            return False

        if meta_db_entry.is_config_file:
            return False # skip checks on config files if the flag is set

        # Store type of file
        fs_type = fs_entry.get('entry_type')

        # Check checksums
        if fs_type in ['file']:
            fs_digest = None
            if meta_db_entry.digest_algorithm == 'sha256':
                fs_digest = fs_entry.get('sha256_checksum')
            elif meta_db_entry.digest_algorithm == 'md5':
                fs_digest = fs_entry.get('md5_checksum')
            elif meta_db_entry.digest_algorithm == 'sha1':
                fs_digest = fs_entry.get('sha1_checksum')

            if meta_db_entry.digest and fs_digest and fs_digest != meta_db_entry.digest:
                return VerifyTrigger.VerificationStates.changed

        # Check mode
        if fs_type in ['file', 'dir']:
            fs_mode = fs_entry.get('mode')
            if meta_db_entry.mode and fs_mode:
                # Convert to octal for consistent checks
                oct_fs_mode = oct(fs_mode)[2:]
                oct_db_mode = oct(meta_db_entry.mode)[2:]

                # Trim mismatched lengths in octal mode
                if len(oct_db_mode) < len(oct_fs_mode):
                    oct_fs_mode = oct_fs_mode[-len(oct_db_mode):]
                elif len(oct_db_mode) > len(oct_fs_mode):
                    oct_db_mode = oct_db_mode[-len(oct_fs_mode):]

                if oct_db_mode != oct_fs_mode:
                    return VerifyTrigger.VerificationStates.changed

        if fs_type in ['file']:
            # Check size (Checksum should handle this)
            db_size = meta_db_entry.size
            fs_size = int(fs_entry.get('size'))
            if fs_size and db_size and fs_size != db_size:
                return VerifyTrigger.VerificationStates.changed

        # No changes or not enough data to compare
        return False


class PkgNotPresentTrigger(BaseTrigger):
    __lifecycle_state__ = LifecycleStates.deprecated
    __trigger_name__ = 'pkgnotpresent'
    __description__ = 'triggers if the package(s) specified in the params are not installed in the container image. The parameters specify different types of matches.',

    pkg_full_match = NameVersionStringListParameter(name='pkgfullmatch', description='Match these values on both name and exact version. Entries are comma-delimited with a pipe between pkg name and version', example_str='pkg1|version1,pkg2|version2', is_required=False)
    pkg_name_match = CommaDelimitedStringListParameter(name='pkgnamematch', description='List of names to match', example_str='wget,curl,libssl', is_required=False)
    pkg_version_match = NameVersionStringListParameter(name='pkgversmatch', description='Names and versions to do a minimum-version check on. Any package in the list with a version less than the specified version will cause the trigger to fire', example_str='wget|1.19.3,curl|7.55.1', is_required=False)

    def evaluate(self, image_obj, context):
        fullmatch = self.pkg_full_match.value(default_if_none={})
        namematch = self.pkg_name_match.value(default_if_none=[])
        vermatch = self.pkg_version_match.value(default_if_none={})

        names = set(fullmatch.keys()).union(set(namematch)).union(set(vermatch.keys()))
        if not names:
            return

        # Filter is possible since the lazy='dynamic' is set on the packages relationship in Image.
        for img_pkg in image_obj.packages.filter(ImagePackage.name.in_(names)).all():
            if img_pkg.name in fullmatch:
                if img_pkg.fullversion != fullmatch.get(img_pkg.name):
                    # Found but not right version
                    self._fire(msg="PKGNOTPRESENT input package (" + str(img_pkg.name) + ") is present (" + str(
                            img_pkg.fullversion) + "), but not at the version specified in policy (" + str(
                            fullmatch[img_pkg.name]) + ")")
                    fullmatch.pop(img_pkg.name)  # Assume only one version of a given package name is installed
                else:
                    # Remove it from the list
                    fullmatch.pop(img_pkg.name)

            # Name match is sufficient
            if img_pkg.name in namematch:
                namematch.remove(img_pkg.name)

            if img_pkg.name in vermatch:
                if img_pkg.fullversion != vermatch[img_pkg.name]:
                    # Check if version is less than param value
                    if compare_package_versions(img_pkg.distro_namespace_meta.flavor, img_pkg.name, img_pkg.version, img_pkg.name, vermatch[img_pkg.name]) < 0:
                        self._fire(msg="PKGNOTPRESENT input package (" + str(img_pkg.name) + ") is present (" + str(
                            img_pkg.fullversion) + "), but is lower version than what is specified in policy (" + str(
                            vermatch[img_pkg.name]) + ")")

                vermatch.pop(img_pkg.name)

        # Any remaining
        for pkg, version in list(fullmatch.items()):
            self._fire(msg="PKGNOTPRESENT input package (" + str(pkg) + "-" + str(version) + ") is not present in container image")

        for pkg, version in list(vermatch.items()):
            self._fire(msg="PKGNOTPRESENT input package (" + str(pkg) + "-" + str(
                version) + ") is not present in container image")

        for pkg in namematch:
            self._fire(msg="PKGNOTPRESENT input package (" + str(pkg) + ") is not present in container image")


class PackageCheckGate(Gate):
    __gate_name__ = 'pkgcheck'
    __description__ = 'Distro package checks'
    __lifecycle_state__ = LifecycleStates.deprecated
    __superceded_by__ = 'packages'
    __triggers__ = [
        PkgNotPresentTrigger,
        VerifyTrigger
    ]
