import enum
from anchore_engine.services.policy_engine.engine.policy.gate import BaseTrigger, Gate
from anchore_engine.services.policy_engine.engine.policy.params import NameVersionStringListParameter, \
    CommaDelimitedStringListParameter, EnumCommaDelimStringListParameter, EnumStringParameter, TypeValidator, TriggerParameter
from anchore_engine.db import ImagePackage, ImagePackageManifestEntry
from anchore_engine.util.packages import compare_package_versions
from anchore_engine.services.policy_engine.engine.logs import get_logger

log = get_logger()


class VerifyTrigger(BaseTrigger):
    __trigger_name__ = 'verify'
    __description__ = 'Check package integrity against package db in the image. Triggers for changes or removal or content in all or the selected "dirs" parameter if provided, and can filter type of check with the "check_only" parameter.'

    pkgs = CommaDelimitedStringListParameter(name='only_packages', example_str='libssl,openssl', description='List of package names to limit verification.', is_required=False, sort_order=1)
    directories = CommaDelimitedStringListParameter(name='only_directories', example_str='/usr,/var/lib', description='List of directories to limit checks so as to avoid checks on all dir.', is_required=False, sort_order=2)
    check_only = EnumStringParameter(name='check', enum_values=['changed', 'missing'], example_str='changed', description='Check to perform instead of all.', is_required=False, sort_order=3)

    analyzer_type = 'base'
    analyzer_id = 'file_package_verify'
    analyzer_artifact = 'distro.pkgfilemeta'

    class VerificationStates(enum.Enum):
        changed = 'changed'
        missing = 'missing'

    def evaluate(self, image_obj, context):
        pkg_names = self.pkgs.value(default_if_none=[])
        pkg_dirs = self.directories.value(default_if_none=[])
        check = self.check_only.value()

        if check:
            check = getattr(self.VerificationStates, check)

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

                if status and (check is None or status == check):
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
                # Add 2 to handle the '0o' prefix that oct() outputs in py3
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


class RequiredPackageTrigger(BaseTrigger):
    __trigger_name__ = 'required_package'
    __description__ = 'Triggers if the specified package and optionally a specific version is not found in the image.'

    pkg_name = TriggerParameter(name='name', example_str='libssl', description='Name of package that must be found installed in image.', is_required=True, validator=TypeValidator('string'), sort_order=1)
    pkg_version = TriggerParameter(name='version', example_str='1.10.3rc3', description='Optional version of package for exact version match.', is_required=False, validator=TypeValidator('string'), sort_order=2)
    version_comparison = EnumStringParameter(name='version_match_type', example_str='exact',
                                             enum_values=['exact', 'minimum'],
                                             is_required=False,
                                             description='The type of comparison to use for version if a version is provided.',
                                             sort_order=3)

    def evaluate(self, image_obj, context):
        name = self.pkg_name.value()
        version = self.pkg_version.value()
        comparison = self.version_comparison.value(default_if_none='exact')

        found = False

        # Filter is possible since the lazy='dynamic' is set on the packages relationship in Image.
        for img_pkg in image_obj.packages.filter(ImagePackage.name == name).all():
            if version is None:
                found = True
                break
            elif comparison == 'exact':
                if img_pkg.fullversion != version:
                    self._fire(msg="Required input package (" + str(img_pkg.name) + ") is present (" + str(
                        img_pkg.fullversion) + "), but not at the version specified in policy (" + str(name) + ")")

                found = True
                break
            elif comparison == 'minimum':
                if img_pkg.fullversion != version:
                    # Check if version is less than param value
                    if compare_package_versions(img_pkg.distro_namespace_meta.flavor, img_pkg.name, img_pkg.version,
                                                img_pkg.name, version) < 0:
                        self._fire(
                            msg="Required min-version input package (" + str(img_pkg.name) + ") is present (" + str(
                                img_pkg.fullversion) + "), but is lower version than what is specified in policy (" + str(
                                version) + ")")

                # >=, so ok
                found = True
                break

        if not found:
            if version and comparison != 'name_only':
                self._fire(msg="Required input package ({},{}) is not present in container image".format(str(name), str(version)))
            else:
                self._fire(msg="Required input package ({}) is not present in container image".format(str(name)))


class BlackListTrigger(BaseTrigger):
    __trigger_name__ = 'blacklist'
    __description__ = 'Triggers if the evaluated image has a package installed that matches the named package optionally with a specific version as well.'

    pkg_name = TriggerParameter(name='name', example_str='openssh-server', description="Package name to blacklist.", sort_order=1, validator=TypeValidator('string'), is_required=True)
    pkg_version = TriggerParameter(name='version', example_str='1.0.1', description='Specific version of package to blacklist.', validator=TypeValidator('string'), sort_order=2, is_required=False)

    def evaluate(self, image_obj, context):
        pkg = self.pkg_name.value()
        vers = self.pkg_version.value()

        try:
            if vers:
                matches = image_obj.packages.filter(ImagePackage.name == pkg, ImagePackage.version == vers)
                for m in matches:
                    self._fire(msg='Package is blacklisted: ' + m.name + "-" + m.version)
            else:
                matches = image_obj.packages.filter(ImagePackage.name == pkg)
                for m in matches:
                    self._fire(msg='Package is blacklisted: ' + m.name)
        except Exception as e:
            log.exception('Error filtering packages for full match')
            pass


class PackagesCheckGate(Gate):
    __gate_name__ = 'packages'
    __description__ = 'Distro package checks'
    __triggers__ = [
        RequiredPackageTrigger,
        VerifyTrigger,
        BlackListTrigger,
    ]
