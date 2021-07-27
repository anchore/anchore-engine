import base64
import hashlib
import re

from anchore_engine.common.helpers import safe_extract_json_value
from anchore_engine.db import (  # , ImageJava, ImagePython
    AnalysisArtifact,
    DistroNamespace,
    FilesystemAnalysis,
    Image,
    ImageCpe,
    ImageGem,
    ImageNpm,
    ImagePackage,
    ImagePackageManifestEntry,
)
from anchore_engine.services.policy_engine.engine.feeds.config import (
    get_provider_name,
    get_section_for_vulnerabilities,
)
from anchore_engine.subsys import logger
from anchore_engine.util.rpm import split_rpm_filename
from anchore_engine.utils import ensure_bytes

# this is a static mapping of known package names (keys) to official cpe names for each package
nomatch_inclusions = {
    "java": {
        "springframework": ["spring_framework", "springsource_spring_framework"],
        "spring-core": ["spring_framework", "springsource_spring_framework"],
    },
    "npm": {
        "hapi": ["hapi_server_framework"],
        "handlebars.js": ["handlebars"],
        "is-my-json-valid": ["is_my_json_valid"],
        "mustache": ["mustache.js"],
    },
    "gem": {
        "Arabic-Prawn": ["arabic_prawn"],
        "bio-basespace-sdk": ["basespace_ruby_sdk"],
        "cremefraiche": ["creme_fraiche"],
        "html-sanitizer": ["html_sanitizer"],
        "sentry-raven": ["raven-ruby"],
        "RedCloth": ["redcloth_library"],
        "VladTheEnterprising": ["vladtheenterprising"],
        "yajl-ruby": ["yajl-ruby_gem"],
    },
    "python": {
        "python-rrdtool": ["rrdtool"],
    },
}


class ImageLoader(object):
    """
    Takes an image analysis json and converts it to a set of records for commit to the db.

    Assumes there is a global session wrapper and will add items to the session but does not
    commit the session itself.
    """

    def __init__(self, analysis_json):
        self.start_time = None
        self.stop_time = None
        self.image_export_json = analysis_json

    def load(self):
        """
        Loads the exported image data into this system for usage.

        :param image_export_json:
        :return: an initialized Image() record, not persisted to DB yet
        """

        logger.info("Loading image json")

        if type(self.image_export_json) == list and len(self.image_export_json) == 1:
            image_id = self.image_export_json[0].get("image", {}).get("imageId")
            assert image_id
            self.image_export_json = (
                self.image_export_json[0].get("image", {}).get("imagedata", {})
            )
            logger.info(
                "Detected a direct export format for image id: {} rather than a catalog analysis export".format(
                    image_id
                )
            )

        analysis_report = self.image_export_json.get("analysis_report")
        image_report = self.image_export_json.get("image_report")

        image = Image()
        image.id = image_report.get("meta", {}).get("imageId")
        image.size = int(image_report.get("meta", {}).get("sizebytes", -1))
        repo_digests = image_report.get("docker_data", {}).get("RepoDigests", [])
        repo_tags = image_report.get("docker_data", {}).get("RepoTags", [])
        if len(repo_digests) > 1:
            logger.warn(
                "Found more than one digest for the image {}. Using the first. Digests: {}, Tags: {}".format(
                    image.id, repo_digests, repo_tags
                )
            )

        image.digest = repo_digests[0].split("@", 1)[1] if repo_digests else None

        # Tags handled in another phase using the docker_data in the image record.

        # get initial metadata
        analyzer_meta = (
            analysis_report.get("analyzer_meta", {})
            .get("analyzer_meta", {})
            .get("base", {})
        )

        if "LIKEDISTRO" in analyzer_meta:
            like_dist = analyzer_meta.get("LIKEDISTRO")
        else:
            like_dist = analyzer_meta.get("DISTRO")

        image.distro_name = analyzer_meta.get("DISTRO")
        image.distro_version = analyzer_meta.get("DISTROVERS")
        image.like_distro = like_dist

        image.dockerfile_mode = image_report.get("dockerfile_mode")

        # JSON data
        image.docker_data_json = image_report.get("docker_data")
        image.docker_history_json = image_report.get("docker_history")
        image.dockerfile_contents = image_report.get("dockerfile_contents")
        image.layers_to_dockerfile_json = analysis_report.get("layer_info")
        image.layers_json = image_report.get("layers")
        image.familytree_json = image_report.get("familytree")
        image.analyzer_manifest = self.image_export_json.get("analyzer_manifest")

        # Image content

        packages = []
        handled_ptypes = []

        # Packages
        logger.info("Loading image packages")
        os_packages, handled = self.load_and_normalize_packages(
            analysis_report.get("package_list", {}), image
        )
        packages = packages + os_packages
        handled_ptypes = handled_ptypes + handled

        # FileSystem
        logger.info("Loading image files")
        image.fs, handled = self.load_fsdump(analysis_report)
        handled_ptypes = handled_ptypes + handled

        # Npms
        logger.info("Loading image npms")
        npm_image_packages, handled = self.load_npms(analysis_report, image)
        packages = packages + npm_image_packages
        handled_ptypes = handled_ptypes + handled

        # Gems
        logger.info("Loading image gems")
        gem_image_packages, handled = self.load_gems(analysis_report, image)
        packages = packages + gem_image_packages
        handled_ptypes = handled_ptypes + handled

        ## Python
        logger.info("Loading image python packages")
        python_packages, handled = self.load_pythons(analysis_report, image)
        packages = packages + python_packages
        handled_ptypes = handled_ptypes + handled

        ## Java
        logger.info("Loading image java packages")
        java_packages, handled = self.load_javas(analysis_report, image)
        packages = packages + java_packages
        handled_ptypes = handled_ptypes + handled

        logger.info("Loading image generic package types")
        generic_packages, handled = self.load_generic_packages(
            analysis_report, image, excludes=handled_ptypes
        )
        packages = packages + generic_packages
        handled_ptypes = handled_ptypes + handled

        image.packages = packages

        # Package metadata
        logger.info("Loading image package db entries")
        self.load_package_verification(analysis_report, image)

        # CPEs
        logger.info("Loading image cpes")
        image.cpes = self.load_cpes_from_syft_output_with_fallback(
            analysis_report, image
        )

        analysis_artifact_loaders = [
            self.load_retrieved_files,
            self.load_content_search,
            self.load_secret_search,
            self.load_malware_findings
            # self.load_package_verification
        ]

        # Content searches
        image.analysis_artifacts = []
        for loader in analysis_artifact_loaders:
            for r in loader(analysis_report, image):
                image.analysis_artifacts.append(r)

        image.state = "analyzed"
        return image

    def load_package_verification(self, analysis_report, image_obj):
        """
        Loads package verification analysis data.
        Adds the package db metadata records to respective packages in the image_obj

        :param analysis_report:
        :param image_obj:
        :return: True on success
        """

        logger.info("Loading package verification data")
        analyzer = "file_package_verify"
        pkgfile_meta = "distro.pkgfilemeta"
        verify_result = "distro.verifyresult"
        digest_algos = ["sha1", "sha256", "md5"]

        package_verify_json = analysis_report.get(analyzer)
        if not package_verify_json:
            return []

        file_records = package_verify_json.get(pkgfile_meta, {}).get("base", {})
        verify_records = package_verify_json.get(verify_result, {}).get("base", {})

        # Re-organize the data from file-keyed to package keyed for efficient filtering
        packages = {}
        for path, file_meta in list(file_records.items()):
            for r in safe_extract_json_value(file_meta):
                pkg = r.pop("package")
                if not pkg:
                    continue

                if pkg not in packages:
                    packages[pkg] = {}

                # Add the entry for the file in the package
                packages[pkg][path] = r

        for package in image_obj.packages:
            pkg_entry = packages.get(package.name)
            entries = []
            if not pkg_entry:
                continue

            for f_name, entry in list(pkg_entry.items()):
                meta = ImagePackageManifestEntry()
                meta.pkg_name = package.name
                meta.pkg_version = package.version
                meta.pkg_type = package.pkg_type
                meta.pkg_arch = package.arch
                meta.image_id = package.image_id
                meta.image_user_id = package.image_user_id
                meta.file_path = f_name
                meta.digest_algorithm = entry.get("digestalgo")
                meta.digest = entry.get("digest")
                meta.file_user_name = entry.get("user")
                meta.file_group_name = entry.get("group")
                meta.is_config_file = entry.get("conffile")

                m = entry.get("mode")
                s = entry.get("size")
                meta.mode = (
                    int(m, 8) if m is not None else m
                )  # Convert from octal to decimal int
                meta.size = int(s) if s is not None else None

                entries.append(meta)

            package.pkg_db_entries = entries

        return True

        # records = []
        # for pkg_name, paths in packages.items():
        #
        #     r = AnalysisArtifact()
        #     r.image_user_id = image_obj.user_id
        #     r.image_id = image_obj.id
        #     r.analyzer_type = 'base'
        #     r.analyzer_id = 'file_package_verify'
        #     r.analyzer_artifact = 'distro.pkgfilemeta'
        #     r.artifact_key = pkg_name
        #     r.json_value = paths
        #     records.append(r)
        # return records

    def load_retrieved_files(self, analysis_report, image_obj):
        """
        Loads the analyzer retrieved files from the image, saves them in the db

        :param retrieve_files_json:
        :param image_obj:
        :return:
        """
        logger.info("Loading retrieved files")
        retrieve_files_json = analysis_report.get("retrieve_files")
        if not retrieve_files_json:
            return []

        matches = retrieve_files_json.get("file_content.all", {}).get("base", {})
        records = []

        for filename, match_string in list(matches.items()):
            match = AnalysisArtifact()
            match.image_user_id = image_obj.user_id
            match.image_id = image_obj.id
            match.analyzer_id = "retrieve_files"
            match.analyzer_type = "base"
            match.analyzer_artifact = "file_content.all"
            match.artifact_key = filename
            try:
                match.binary_value = base64.b64decode(ensure_bytes(match_string))
            except:
                logger.exception(
                    "Could not b64 decode the file content for {}".format(filename)
                )
                raise
            records.append(match)

        return records

    def load_content_search(self, analysis_report, image_obj):
        """
        Load content search results from analysis if present
        :param content_search_json:
        :param image_obj:
        :return:
        """
        logger.info("Loading content search results")
        content_search_json = analysis_report.get("content_search")
        if not content_search_json:
            return []

        matches = content_search_json.get("regexp_matches.all", {}).get("base", {})
        records = []

        for filename, match_string in list(matches.items()):
            match = AnalysisArtifact()
            match.image_user_id = image_obj.user_id
            match.image_id = image_obj.id
            match.analyzer_id = "content_search"
            match.analyzer_type = "base"
            match.analyzer_artifact = "regexp_matches.all"
            match.artifact_key = filename
            try:
                match.json_value = safe_extract_json_value(match_string)
            except:
                logger.exception(
                    "json decode failed for regex match record on {}. Saving as raw text".format(
                        filename
                    )
                )
                match.str_value = match_string

            records.append(match)

        return records

    def load_secret_search(self, analysis_report, image_obj):
        """
        Load content search results from analysis if present
        :param content_search_json:
        :param image_obj:
        :return:
        """
        logger.info("Loading secret search results")
        content_search_json = analysis_report.get("secret_search")
        if not content_search_json:
            return []

        matches = content_search_json.get("regexp_matches.all", {}).get("base", {})
        records = []

        for filename, match_string in list(matches.items()):
            match = AnalysisArtifact()
            match.image_user_id = image_obj.user_id
            match.image_id = image_obj.id
            match.analyzer_id = "secret_search"
            match.analyzer_type = "base"
            match.analyzer_artifact = "regexp_matches.all"
            match.artifact_key = filename
            try:
                match.json_value = safe_extract_json_value(match_string)
            except:
                logger.exception(
                    "json decode failed for regex match record on {}. Saving as raw text".format(
                        filename
                    )
                )
                match.str_value = match_string

            records.append(match)

        return records

    def load_malware_findings(self, analysis_report, image_obj):
        """
        Load malware results from analysis if present.

        Example malware analysis result:
        {
        ...
        "malware": {
              "malware": {
                "base": {
                  "clamav": "{\"scanner\": \"clamav\", \"findings\": [{\"path\": \"elf_payload1\", \"signature\": \"Unix.Trojan.MSShellcode-40\"}], \"metadata\": {\"db_version\": {\"daily\": \"\", \"main\": \"59\", \"bytecode\": \"331\"}}}"
                }
              }
            },
        ...
        }

        The key is the scanner name, and the result is the findings for that scanner (e.g. clamav)

        :param analysis_report:
        :param image_obj:
        :return:
        """
        malware_analyzer_name = "malware"
        base_default = "base"

        logger.info("Loading malware scan findings")
        malware_json = analysis_report.get(malware_analyzer_name)
        if not malware_json:
            return []

        matches = malware_json.get(malware_analyzer_name, {}).get(base_default, {})
        records = []

        for scanner_name, scan_result in matches.items():
            scan_artifact = AnalysisArtifact()
            scan_artifact.image_user_id = image_obj.user_id
            scan_artifact.image_id = image_obj.id
            scan_artifact.analyzer_id = malware_analyzer_name
            scan_artifact.analyzer_type = "base"
            scan_artifact.analyzer_artifact = malware_analyzer_name
            scan_artifact.artifact_key = scanner_name
            try:
                scan_artifact.json_value = safe_extract_json_value(scan_result)
            except:
                logger.exception(
                    "json decode failed for malware scan result on {}. Saving as raw text".format(
                        scan_result
                    )
                )
                scan_artifact.str_value = scan_result

            records.append(scan_artifact)

        return records

    def load_and_normalize_packages(self, package_analysis_json, image_obj):
        """
        Loads and normalizes package data from all distros

        :param image_obj:
        :param package_analysis_json:
        :return: list of Package objects that can be added to an image
        """
        pkgs = []
        handled_pkgtypes = ["pkgs.allinfo", "pkgs.all"]

        img_distro = DistroNamespace.for_obj(image_obj)

        # pkgs.allinfo handling
        pkgs_all = list(package_analysis_json.get("pkgs.allinfo", {}).values())
        if not pkgs_all:
            return [], handled_pkgtypes
        else:
            pkgs_all = pkgs_all[0]

        for pkg_name, metadata_str in list(pkgs_all.items()):
            metadata = safe_extract_json_value(metadata_str)

            p = ImagePackage()
            p.distro_name = image_obj.distro_name
            p.distro_version = image_obj.distro_version
            p.like_distro = image_obj.like_distro

            p.name = pkg_name
            p.version = metadata.get("version")
            p.origin = metadata.get("origin")
            try:
                psize = int(metadata.get("size", 0))
            except:
                psize = 0
            p.size = psize
            # p.size = metadata.get('size')
            p.arch = metadata.get("arch")
            p.license = (
                metadata.get("license")
                if metadata.get("license")
                else metadata.get("lics")
            )
            p.release = metadata.get("release", "N/A")
            p.pkg_type = metadata.get("type")
            p.src_pkg = metadata.get("sourcepkg")
            p.image_user_id = image_obj.user_id
            p.image_id = image_obj.id

            # if 'files' in metadata:
            #    # Handle file data
            #    p.files = metadata.get('files')

            if p.release != "N/A":
                p.fullversion = p.version + "-" + p.release
            else:
                p.fullversion = p.version

            if img_distro.flavor == "DEB":
                cleanvers = re.sub(re.escape("+b") + "\d+.*", "", p.version)
                spkg = re.sub(re.escape("-" + cleanvers), "", p.src_pkg)
            else:
                spkg = re.sub(re.escape("-" + p.version) + ".*", "", p.src_pkg)

            p.normalized_src_pkg = spkg
            pkgs.append(p)

        if pkgs:
            return pkgs, handled_pkgtypes
        else:
            # todo is this even correct?
            logger.warn("Pkg Allinfo not found, reverting to using pkgs.all")

        # below logic doesn't do anything, ImagePackage instances are created and dropped

        all_pkgs = package_analysis_json["pkgs.all"]["base"]
        all_pkgs_src = package_analysis_json["pkgs_plus_source.all"]["base"]

        for pkg_name, version in list(all_pkgs.items()):
            p = ImagePackage()
            p.image_user_id = image_obj.user_id
            p.image_id = image_obj.id
            p.name = pkg_name
            p.version = version
            p.fullversion = all_pkgs_src[pkg_name]

            if img_distro.flavor == "RHEL":
                name, parsed_version, release, epoch, arch = split_rpm_filename(
                    pkg_name + "-" + version + ".tmparch.rpm"
                )
                p.version = parsed_version
                p.release = release
                p.pkg_type = "RPM"
                p.origin = "N/A"
                p.src_pkg = "N/A"
                p.license = "N/A"
                p.arch = "N/A"
            elif img_distro.flavor == "DEB":
                try:
                    p.version, p.release = version.split("-")
                except:
                    p.version = version
                    p.release = None

        return pkgs, handled_pkgtypes

    def load_fsdump(self, analysis_report_json):
        """
        Returns a single FSDump entity composed of a the compressed and hashed json of the fs entries along with some statistics.
        This function will pull necessariy bits from the fully analysis to construct a view of the FS suitable for gate eval.

        :param analysis_report_json: the full json analysis report
        :return:
        """

        handled_pkgtypes = [
            "files.allinfo",
            "files.all",
            "files.md5sums",
            "files.sha256sums",
            "files.sha1sums",
            "files.suids",
            "pkgfiles.all",
        ]
        file_entries = {}
        all_infos = (
            analysis_report_json.get("file_list", {})
            .get("files.allinfo", {})
            .get("base", {})
        )
        file_perms = (
            analysis_report_json.get("file_list", {})
            .get("files.all", {})
            .get("base", {})
        )
        md5_checksums = (
            analysis_report_json.get("file_checksums", {})
            .get("files.md5sums", {})
            .get("base", {})
        )
        sha256_checksums = (
            analysis_report_json.get("file_checksums", {})
            .get("files.sha256sums", {})
            .get("base", {})
        )
        sha1_checksums = (
            analysis_report_json.get("file_checksums", {})
            .get("files.sha1sums", {})
            .get("base", {})
        )
        suids = (
            analysis_report_json.get("file_suids", {})
            .get("files.suids", {})
            .get("base", {})
        )
        pkgd = (
            analysis_report_json.get("package_list", {})
            .get("pkgfiles.all", {})
            .get("base", {})
        )

        path_map = {
            path: safe_extract_json_value(value)
            for path, value in list(all_infos.items())
        }
        entry = FilesystemAnalysis()
        entry.file_count = 0
        entry.directory_count = 0
        entry.non_packaged_count = 0
        entry.suid_count = 0
        entry.total_entry_count = 0

        # TODO: replace this with the load_fs_item call and convert the returned items to JSON for clarity and consistency.
        # items = self.load_files(all_infos, suids, checksums, pkgd)
        # for item in items:
        #     f = item.json()

        for path, metadata in list(path_map.items()):
            try:
                full_path = metadata["fullpath"]
                f = {
                    "fullpath": full_path,
                    "name": metadata["name"],
                    "mode": metadata["mode"],
                    "permissions": file_perms.get(path),
                    "linkdst_fullpath": metadata["linkdst_fullpath"],
                    "linkdst": metadata["linkdst"],
                    "size": metadata["size"],
                    "entry_type": metadata["type"],
                    "is_packaged": path in pkgd,
                    "md5_checksum": md5_checksums.get(path, "DIRECTORY_OR_OTHER"),
                    "sha256_checksum": sha256_checksums.get(path, "DIRECTORY_OR_OTHER"),
                    "sha1_checksum": sha1_checksums.get(path, "DIRECTORY_OR_OTHER")
                    if sha1_checksums
                    else None,
                    "othernames": [],
                    "suid": suids.get(path),
                }
            except KeyError as e:
                logger.exception("Could not find data for {}".format(e))
                raise

            # Increment counters as needed
            if f["suid"]:
                entry.suid_count += 1

            if not f["is_packaged"]:
                entry.non_packaged_count += 1

            if f["entry_type"] == "file":
                entry.file_count += 1
            elif f["entry_type"] == "dir":
                entry.directory_count += 1

            file_entries[path] = f

        # Compress and set the data
        entry.total_entry_count = len(file_entries)
        entry.files = file_entries
        return entry, handled_pkgtypes

    def load_npms(self, analysis_json, containing_image):
        handled_pkgtypes = ["pkgs.npms"]
        npms_json = (
            analysis_json.get("package_list", {}).get("pkgs.npms", {}).get("base")
        )
        if not npms_json:
            return [], handled_pkgtypes

        npms = []
        image_packages = []
        for path, npm_str in list(npms_json.items()):
            npm_json = safe_extract_json_value(npm_str)

            # TODO: remove this usage of ImageNPM, that is deprecated
            n = ImageNpm()
            n.path_hash = hashlib.sha256(ensure_bytes(path)).hexdigest()
            n.path = path
            n.name = npm_json.get("name")
            n.src_pkg = npm_json.get("src_pkg")
            n.origins_json = npm_json.get("origins")
            n.licenses_json = npm_json.get("lics")
            n.latest = npm_json.get("latest")
            n.versions_json = npm_json.get("versions")
            n.image_user_id = containing_image.user_id
            n.image_id = containing_image.id
            # npms.append(n)

            np = ImagePackage()
            # primary keys
            np.name = n.name
            if len(n.versions_json):
                version = n.versions_json[0]
            else:
                version = "N/A"
            np.version = version
            np.pkg_type = "npm"
            np.arch = "N/A"
            np.image_user_id = n.image_user_id
            np.image_id = n.image_id
            np.pkg_path = n.path
            # other
            np.pkg_path_hash = n.path_hash
            np.distro_name = "npm"
            np.distro_version = "N/A"
            np.like_distro = "npm"
            np.fullversion = np.version
            np.license = " ".join(n.licenses_json)
            np.origin = " ".join(n.origins_json)
            fullname = np.name
            np.normalized_src_pkg = fullname
            np.src_pkg = fullname
            image_packages.append(np)

        return image_packages, handled_pkgtypes

    def load_gems(self, analysis_json, containing_image):
        handled_pkgtypes = ["pkgs.gems"]
        gems_json = (
            analysis_json.get("package_list", {}).get("pkgs.gems", {}).get("base")
        )
        if not gems_json:
            return [], handled_pkgtypes

        gems = []
        image_packages = []
        for path, gem_str in list(gems_json.items()):
            gem_json = safe_extract_json_value(gem_str)

            # TODO: remove this usage of ImageGem, that is deprecated
            n = ImageGem()
            n.path_hash = hashlib.sha256(ensure_bytes(path)).hexdigest()
            n.path = path
            n.name = gem_json.get("name")
            n.src_pkg = gem_json.get("src_pkg")
            n.origins_json = gem_json.get("origins")
            n.licenses_json = gem_json.get("lics")
            n.versions_json = gem_json.get("versions")
            n.latest = gem_json.get("latest")
            n.image_user_id = containing_image.user_id
            n.image_id = containing_image.id
            # gems.append(n)

            np = ImagePackage()
            # primary keys
            np.name = n.name
            if len(n.versions_json):
                version = n.versions_json[0]
            else:
                version = "N/A"
            np.version = version
            np.pkg_type = "gem"
            np.arch = "N/A"
            np.image_user_id = n.image_user_id
            np.image_id = n.image_id
            np.pkg_path = n.path
            # other
            np.pkg_path_hash = n.path_hash
            np.distro_name = "gem"
            np.distro_version = "N/A"
            np.like_distro = "gem"
            np.fullversion = np.version
            np.license = " ".join(n.licenses_json)
            np.origin = " ".join(n.origins_json)
            fullname = np.name
            np.normalized_src_pkg = fullname
            np.src_pkg = fullname
            image_packages.append(np)

        return image_packages, handled_pkgtypes

    def load_pythons(self, analysis_json, containing_image):
        handled_pkgtypes = ["pkgs.python"]
        pkgs_json = (
            analysis_json.get("package_list", {}).get("pkgs.python", {}).get("base")
        )
        if not pkgs_json:
            return [], handled_pkgtypes

        pkgs = []
        for path, pkg_str in list(pkgs_json.items()):
            pkg_json = safe_extract_json_value(pkg_str)

            n = ImagePackage()
            # primary keys
            n.name = pkg_json.get("name")
            n.pkg_path = path
            n.version = pkg_json.get("version")
            n.pkg_type = "python"
            n.arch = "N/A"
            n.image_user_id = n.image_user_id
            n.image_id = n.image_id
            # other
            n.pkg_path_hash = hashlib.sha256(ensure_bytes(path)).hexdigest()
            n.distro_name = "python"
            n.distro_version = "N/A"
            n.like_distro = "python"
            n.fullversion = n.version
            n.license = pkg_json.get("license")
            n.origin = pkg_json.get("origin")

            m = {"files": pkg_json.get("files")}
            n.metadata_json = m

            fullname = n.name
            n.normalized_src_pkg = fullname
            n.src_pkg = fullname
            pkgs.append(n)

        return pkgs, handled_pkgtypes

    def load_javas(self, analysis_json, containing_image):
        handled_pkgtypes = ["pkgs.java"]
        pkgs_json = (
            analysis_json.get("package_list", {}).get("pkgs.java", {}).get("base")
        )
        if not pkgs_json:
            return [], handled_pkgtypes

        pkgs = []
        for path, pkg_str in list(pkgs_json.items()):
            pkg_json = safe_extract_json_value(pkg_str)

            n = ImagePackage()

            # primary keys
            # TODO - some java names have a version in it, need to clean that up
            n.name = pkg_json.get("name")
            n.pkg_type = "java"
            n.arch = "N/A"
            n.pkg_path = path

            metaversion = None
            versions_json = {}
            for k in [
                "maven-version",
                "implementation-version",
                "specification-version",
            ]:
                if not metaversion and pkg_json.get(k, "N/A") != "N/A":
                    metaversion = pkg_json.get(k)
                versions_json[k] = pkg_json.get(k, "N/A")

            n.image_user_id = containing_image.user_id
            n.image_id = containing_image.id

            # other non-PK values
            n.pkg_path_hash = hashlib.sha256(ensure_bytes(path)).hexdigest()
            n.distro_name = "java"
            n.distro_version = "N/A"
            n.like_distro = "java"

            m = pkg_json.get("metadata")
            m["java_versions"] = versions_json
            n.metadata_json = m

            fullname = n.name
            pomprops = n.get_pom_properties()
            pomversion = None
            if pomprops:
                fullname = "{}:{}".format(
                    pomprops.get("groupId"), pomprops.get("artifactId")
                )
                pomversion = pomprops.get("version", None)

            n.normalized_src_pkg = fullname
            n.src_pkg = fullname

            # final version decision - try our best to get an accurate version/name pair
            n.version = "N/A"
            if pomversion:
                n.version = pomversion
            elif metaversion:
                n.version = metaversion
            else:
                try:
                    patt = re.match(r"(.*)-(([\d]\.)+.*)", n.name)
                    if patt and patt.group(1):
                        n.version = patt.group(2)
                        n.name = patt.group(1)
                except Exception as err:
                    pass
            n.fullversion = n.version

            pkgs.append(n)

        return pkgs, handled_pkgtypes

    def load_generic_packages(self, analysis_json, containing_image, excludes=[]):
        pkgs = []
        handled_pkgtypes = []
        package_types = analysis_json.get("package_list", {})
        for package_type in package_types:
            if package_type not in excludes:
                patt = re.match(r"pkgs\.(.*)", package_type)
                if patt:
                    ptype = patt.group(1)
                    handled_pkgtypes.append(ptype)
                    pkgs_json = (
                        analysis_json.get("package_list", {})
                        .get(package_type, {})
                        .get("base", {})
                    )

                    if not pkgs_json:
                        return [], handled_pkgtypes

                    for path, pkg_str in list(pkgs_json.items()):
                        pkg_json = safe_extract_json_value(pkg_str)
                        n = ImagePackage()
                        # primary keys
                        n.name = pkg_json.get("name")
                        n.pkg_path = path
                        n.version = pkg_json.get("version")
                        n.pkg_type = pkg_json.get("type", "N/A")
                        n.arch = "N/A"
                        n.image_user_id = n.image_user_id
                        n.image_id = n.image_id
                        # other
                        n.pkg_path_hash = hashlib.sha256(ensure_bytes(path)).hexdigest()
                        n.distro_name = n.pkg_type
                        n.distro_version = "N/A"
                        n.like_distro = n.pkg_type
                        n.fullversion = n.version
                        n.license = pkg_json.get("license", "N/A")
                        n.origin = pkg_json.get("origin", "N/A")

                        fullname = n.name
                        n.normalized_src_pkg = fullname
                        n.src_pkg = fullname
                        pkgs.append(n)

        return pkgs, handled_pkgtypes

    def _fuzzy_go(self, input_el_name, input_el_version):
        ret_names = [input_el_name]
        ret_versions = [input_el_version]

        patt = re.match(".*([0-9]+\.[0-9]+\.[0-9]+).*", input_el_version)
        if patt:
            candidate_version = patt.group(1)

        if candidate_version not in ret_versions:
            ret_versions.append(candidate_version)

        return ret_names, ret_versions

    def _fuzzy_python(self, input_el):
        global nomatch_inclusions

        known_nomatch_inclusions = nomatch_inclusions.get("python", {})

        ret_names = [input_el]

        if input_el in known_nomatch_inclusions:
            for n in known_nomatch_inclusions[input_el]:
                if n not in ret_names:
                    ret_names.append(n)

        return ret_names

    def _fuzzy_npm(self, input_el):
        global nomatch_inclusions

        known_nomatch_inclusions = nomatch_inclusions.get("npm", {})

        ret_names = [input_el]

        if input_el in known_nomatch_inclusions:
            for n in known_nomatch_inclusions[input_el]:
                if n not in ret_names:
                    ret_names.append(n)

        return ret_names

    def _fuzzy_gem(self, input_el):
        global nomatch_inclusions

        known_nomatch_inclusions = nomatch_inclusions.get("gem", {})

        ret_names = [input_el]

        if input_el in known_nomatch_inclusions:
            for n in known_nomatch_inclusions[input_el]:
                if n not in ret_names:
                    ret_names.append(n)

        return ret_names

    def _fuzzy_java(self, input_el):
        global nomatch_inclusions

        known_nomatch_inclusions = nomatch_inclusions.get("java", {})

        ret_names = []
        ret_versions = []

        iversion = input_el.get("implementation-version", "N/A")
        if iversion != "N/A":
            ret_versions.append(iversion)

        sversion = input_el.get("specification-version", "N/A")
        if sversion != "N/A":
            if sversion not in ret_versions:
                ret_versions.append(sversion)

        mversion = input_el.get("maven-version", "N/A")
        if mversion != "N/A" and mversion not in ret_versions:
            if mversion not in ret_versions:
                ret_versions.append(mversion)

        for rversion in ret_versions:
            clean_version = re.sub("\.(RELEASE|GA|SEC.*)$", "", rversion)
            if clean_version not in ret_versions:
                ret_versions.append(clean_version)

        # do some heuristic tokenizing
        try:
            toks = re.findall("[^-]+", input_el["name"])
            firstname = None
            fullname = []
            firstversion = None
            fullversion = []

            doingname = True
            for tok in toks:
                if re.match("^[0-9]", tok):
                    doingname = False

                if doingname:
                    if not firstname:
                        firstname = tok
                    else:
                        fullname.append(tok)
                else:
                    if not firstversion:
                        firstversion = tok
                    else:
                        fullversion.append(tok)

            if firstname:
                firstname_nonums = re.sub("[0-9].*$", "", firstname)
                for gthing in [firstname, firstname_nonums]:
                    if gthing not in ret_names:
                        ret_names.append(gthing)
                    if "-".join([gthing] + fullname) not in ret_names:
                        ret_names.append("-".join([gthing] + fullname))

            if firstversion:
                firstversion_nosuffix = re.sub(
                    "\.(RELEASE|GA|SEC.*)$", "", firstversion
                )
                for gthing in [firstversion, firstversion_nosuffix]:
                    if gthing not in ret_versions:
                        ret_versions.append(gthing)
                    if "-".join([gthing] + fullversion) not in ret_versions:
                        ret_versions.append("-".join([gthing] + fullversion))

            # attempt to get some hints from the manifest, if available
            try:
                manifest = input_el["metadata"].get("MANIFEST.MF", None)
                if manifest:
                    pnames = []
                    manifest = re.sub("\r\n ", "", manifest)
                    for mline in manifest.splitlines():
                        if mline:
                            key, val = mline.split(" ", 1)
                            if key.lower() == "export-package:":
                                val = re.sub(';uses:=".*?"', "", val)
                                val = re.sub(';version=".*?"', "", val)
                                val = val.split(";")[0]
                                pnames = pnames + val.split(",")
                            # elif key.lower() == 'bundle-symbolicname:':
                            #    pnames.append(val)
                            # elif key.lower() == 'name:':
                            #    tmp = val.split("/")
                            #    pnames.append('.'.join(tmp[:-1]))

                    packagename = None
                    if pnames:
                        shortest = min(pnames)
                        longest = max(pnames)
                        if shortest == longest:
                            packagename = shortest
                        else:
                            for i in range(0, len(shortest)):
                                if i > 0 and shortest[i] != longest[i]:
                                    packagename = shortest[: i - 1]
                                    break
                    if packagename:
                        candidate = packagename.split(".")[-1]
                        if candidate in list(known_nomatch_inclusions.keys()):
                            for matchmap_candidate in known_nomatch_inclusions[
                                candidate
                            ]:
                                if matchmap_candidate not in ret_names:
                                    ret_names.append(matchmap_candidate)
                        elif (
                            candidate not in ["com", "org", "net"]
                            and len(candidate) > 2
                        ):
                            for r in list(ret_names):
                                if r in candidate and candidate not in ret_names:
                                    ret_names.append(candidate)

            except Exception as err:
                logger.err(err)

        except Exception as err:
            logger.warn(
                "failed to detect java package name/version guesses - exception: "
                + str(err)
            )

        for rname in list(ret_names):
            underscore_name = re.sub("-", "_", rname)
            if underscore_name not in ret_names:
                ret_names.append(underscore_name)

        for rname in list(ret_names):
            if rname in list(known_nomatch_inclusions.keys()):
                for matchmap_candidate in known_nomatch_inclusions[rname]:
                    if matchmap_candidate not in ret_names:
                        ret_names.append(matchmap_candidate)

        return ret_names, ret_versions

    def load_cpes_from_syft_output_with_fallback(self, analysis_json, image):
        allcpes = {}
        cpes = []
        package_list = analysis_json.get("package_list", {})

        java_base = package_list.get("pkgs.java", {}).get("base", {})
        if java_base:
            java_cpes = self.extract_syft_cpes(allcpes, java_base, image, "java")
            if not java_cpes:
                java_cpes = self.get_fuzzy_java_cpes(analysis_json, allcpes, image)
            cpes.extend(java_cpes)

        python_base = package_list.get("pkgs.python", {}).get("base", {})
        if python_base:
            python_cpes = self.extract_syft_cpes(allcpes, python_base, image, "python")
            if not python_cpes:
                python_cpes = self.get_fuzzy_python_cpes(analysis_json, allcpes, image)
            cpes.extend(python_cpes)

        gems_base = package_list.get("pkgs.gems", {}).get("base", {})
        if gems_base:
            gems_cpes = self.extract_syft_cpes(allcpes, gems_base, image, "gem")
            if not gems_cpes:
                gems_cpes = self.get_fuzzy_gem_cpes(analysis_json, allcpes, image)
            cpes.extend(gems_cpes)

        npms_base = package_list.get("pkgs.npms", {}).get("base", {})
        if npms_base:
            npms_cpes = self.extract_syft_cpes(allcpes, npms_base, image, "npm")
            if not npms_cpes:
                npms_cpes = self.get_fuzzy_npm_cpes(analysis_json, allcpes, image)
            cpes.extend(npms_cpes)

        cpes.extend(self.get_fuzzy_go_cpes(analysis_json, allcpes, image))
        cpes.extend(self.get_fuzzy_binary_cpes(analysis_json, allcpes, image))

        # temporary workaround for supporting nvd matching for alpine os packages in grype integration
        if get_provider_name(get_section_for_vulnerabilities()) == "grype":
            os_pkgs_base = package_list.get("pkgs.allinfo", {}).get("base", {})
            if os_pkgs_base:
                os_pkgs_cpes = self.extract_syft_cpes_for_os_packages(
                    allcpes, os_pkgs_base, image
                )
                cpes.extend(os_pkgs_cpes)

        return cpes

    def extract_syft_cpes(self, allcpes, package_dict, image, pkg_type):
        cpes = []
        for pkg_key, pkg_json_str in package_dict.items():
            pkg = safe_extract_json_value(pkg_json_str)
            pkg_cpes = pkg.get("cpes", [])

            cpes.extend(
                self._make_image_cpes(image, allcpes, pkg_cpes, pkg_type, pkg_key)
            )

        return cpes

    def _make_image_cpes(self, image, allcpes, pkg_cpes, pkg_type, pkg_path):
        cpes = []
        for cpe in pkg_cpes:
            decomposed_cpe = self.decompose_cpe(cpe)
            cpekey = ":".join(decomposed_cpe + [pkg_path])

            if cpekey not in allcpes:
                allcpes[cpekey] = True
                image_cpe = ImageCpe()
                image_cpe.pkg_type = pkg_type
                image_cpe.pkg_path = pkg_path
                image_cpe.cpetype = decomposed_cpe[2]
                image_cpe.vendor = decomposed_cpe[3]
                image_cpe.name = decomposed_cpe[4]
                image_cpe.version = decomposed_cpe[5]
                image_cpe.update = decomposed_cpe[6]
                image_cpe.meta = decomposed_cpe[7]
                image_cpe.image_user_id = image.user_id
                image_cpe.image_id = image.id
                cpes.append(image_cpe)

        return cpes

    def extract_syft_cpes_for_os_packages(self, allcpes, package_dict, image):
        """
        Utility function for parsing cpes for os packages only. Mostly a duplicate of extract_syft_cpes with the exception of pkg_type and pkg_path.
        For os packages pkg_path is always pkgdb. pkg_type is picked up from the data instead of passing it as a function argument

        """
        cpes = []
        for pkg_key, pkg_json_str in package_dict.items():
            pkg = safe_extract_json_value(pkg_json_str)
            pkg_path = f"pkgdb/{pkg_key}"  # os package location is always pkgdb. this is a deviation to tie a package with it's cpes
            pkg_cpes = pkg.get("cpes", [])
            pkg_type = pkg.get("type")

            cpes.extend(
                self._make_image_cpes(image, allcpes, pkg_cpes, pkg_type, pkg_path)
            )

        return cpes

    @staticmethod
    def decompose_cpe(rawcpe: str):
        """
        Simplified decomposition method borrowed from the the ImageLoader
        """
        toks = rawcpe.split(":")
        final_cpe = ["cpe", "-", "-", "-", "-", "-", "-", "-"]
        for i in range(1, len(final_cpe)):
            try:
                if toks[i]:
                    final_cpe[i] = toks[i]
                else:
                    final_cpe[i] = "-"
            except IndexError:
                final_cpe[i] = "-"
        return final_cpe

    def get_fuzzy_java_cpes(self, analysis_json, allcpes, containing_image):
        cpes = []
        java_json_raw = (
            analysis_json.get("package_list", {}).get("pkgs.java", {}).get("base")
        )
        if java_json_raw:
            for path, java_str in list(java_json_raw.items()):
                java_json = safe_extract_json_value(java_str)
                try:
                    guessed_names, guessed_versions = self._fuzzy_java(java_json)
                except Exception as err:
                    guessed_names = guessed_versions = []

                for n in guessed_names:
                    for v in guessed_versions:
                        rawcpe = "cpe:/a:-:{}:{}".format(n, v)

                        toks = rawcpe.split(":")
                        final_cpe = ["cpe", "-", "-", "-", "-", "-", "-"]
                        for i in range(1, len(final_cpe)):
                            try:
                                if toks[i]:
                                    final_cpe[i] = toks[i]
                                else:
                                    final_cpe[i] = "-"
                            except:
                                final_cpe[i] = "-"
                        cpekey = ":".join(final_cpe + [path])
                        if cpekey not in allcpes:
                            allcpes[cpekey] = True

                            cpe = ImageCpe()
                            cpe.pkg_type = "java"
                            cpe.pkg_path = path
                            cpe.cpetype = final_cpe[1]
                            cpe.vendor = final_cpe[2]
                            cpe.name = final_cpe[3]
                            cpe.version = final_cpe[4]
                            cpe.update = final_cpe[5]
                            cpe.meta = final_cpe[6]
                            cpe.image_user_id = containing_image.user_id
                            cpe.image_id = containing_image.id

                            cpes.append(cpe)
        return cpes

    def get_fuzzy_python_cpes(self, analysis_json, allcpes, containing_image):
        cpes = []
        python_json_raw = (
            analysis_json.get("package_list", {}).get("pkgs.python", {}).get("base")
        )
        if python_json_raw:
            for path, python_str in list(python_json_raw.items()):
                python_json = safe_extract_json_value(python_str)
                guessed_names = self._fuzzy_python(python_json["name"])
                guessed_versions = [python_json["version"]]

                for n in guessed_names:
                    for v in guessed_versions:
                        rawcpe = "cpe:/a:-:{}:{}:-:~~~python~~".format(n, v)

                        toks = rawcpe.split(":")
                        final_cpe = ["cpe", "-", "-", "-", "-", "-", "-"]
                        for i in range(1, len(final_cpe)):
                            try:
                                if toks[i]:
                                    final_cpe[i] = toks[i]
                                else:
                                    final_cpe[i] = "-"
                            except:
                                final_cpe[i] = "-"
                        cpekey = ":".join(final_cpe + [path])

                        if cpekey not in allcpes:
                            allcpes[cpekey] = True

                            cpe = ImageCpe()
                            cpe.pkg_type = "python"
                            cpe.pkg_path = path
                            cpe.cpetype = final_cpe[1]
                            cpe.vendor = final_cpe[2]
                            cpe.name = final_cpe[3]
                            cpe.version = final_cpe[4]
                            cpe.update = final_cpe[5]
                            cpe.meta = final_cpe[6]
                            cpe.image_user_id = containing_image.user_id
                            cpe.image_id = containing_image.id

                            cpes.append(cpe)
        return cpes

    def get_fuzzy_gem_cpes(self, analysis_json, allcpes, containing_image):
        cpes = []
        gem_json_raw = (
            analysis_json.get("package_list", {}).get("pkgs.gems", {}).get("base")
        )
        if gem_json_raw:
            for path, gem_str in list(gem_json_raw.items()):
                gem_json = safe_extract_json_value(gem_str)
                guessed_names = self._fuzzy_gem(gem_json["name"])
                guessed_versions = gem_json["versions"]
                for n in guessed_names:
                    for v in guessed_versions:
                        rawcpe = "cpe:/a:-:{}:{}:-:~~~ruby~~".format(n, v)

                        toks = rawcpe.split(":")
                        final_cpe = ["cpe", "-", "-", "-", "-", "-", "-"]
                        for i in range(1, len(final_cpe)):
                            try:
                                if toks[i]:
                                    final_cpe[i] = toks[i]
                                else:
                                    final_cpe[i] = "-"
                            except:
                                final_cpe[i] = "-"
                        cpekey = ":".join(final_cpe + [path])

                        if cpekey not in allcpes:
                            allcpes[cpekey] = True

                            cpe = ImageCpe()
                            cpe.pkg_type = "gem"
                            cpe.pkg_path = path
                            cpe.cpetype = final_cpe[1]
                            cpe.vendor = final_cpe[2]
                            cpe.name = final_cpe[3]
                            cpe.version = final_cpe[4]
                            cpe.update = final_cpe[5]
                            cpe.meta = final_cpe[6]
                            cpe.image_user_id = containing_image.user_id
                            cpe.image_id = containing_image.id

                            cpes.append(cpe)
        return cpes

    def get_fuzzy_npm_cpes(self, analysis_json, allcpes, containing_image):
        cpes = []
        npm_json_raw = (
            analysis_json.get("package_list", {}).get("pkgs.npms", {}).get("base")
        )
        if npm_json_raw:
            for path, npm_str in list(npm_json_raw.items()):
                npm_json = safe_extract_json_value(npm_str)
                guessed_names = self._fuzzy_npm(npm_json["name"])
                guessed_versions = npm_json["versions"]
                for n in guessed_names:
                    for v in guessed_versions:
                        rawcpe = "cpe:/a:-:{}:{}:-:~~~node.js~~".format(n, v)

                        toks = rawcpe.split(":")
                        final_cpe = ["cpe", "-", "-", "-", "-", "-", "-"]
                        for i in range(1, len(final_cpe)):
                            try:
                                if toks[i]:
                                    final_cpe[i] = toks[i]
                                else:
                                    final_cpe[i] = "-"
                            except:
                                final_cpe[i] = "-"
                        cpekey = ":".join(final_cpe + [path])

                        if cpekey not in allcpes:
                            allcpes[cpekey] = True

                            cpe = ImageCpe()
                            cpe.pkg_type = "npm"
                            cpe.pkg_path = path
                            cpe.cpetype = final_cpe[1]
                            cpe.vendor = final_cpe[2]
                            cpe.name = final_cpe[3]
                            cpe.version = final_cpe[4]
                            cpe.update = final_cpe[5]
                            cpe.meta = final_cpe[6]
                            cpe.image_user_id = containing_image.user_id
                            cpe.image_id = containing_image.id

                            cpes.append(cpe)
        return cpes

    def get_fuzzy_go_cpes(self, analysis_json, allcpes, containing_image):
        cpes = []
        go_json_raw = (
            analysis_json.get("package_list", {}).get("pkgs.go", {}).get("base")
        )
        if go_json_raw:
            for path, go_str in list(go_json_raw.items()):
                go_json = safe_extract_json_value(go_str)
                guessed_names, guessed_versions = self._fuzzy_go(
                    go_json["name"], go_json["version"]
                )
                # guessed_names = [go_json['name']]
                # guessed_versions = [go_json['version']]
                for n in guessed_names:
                    for v in guessed_versions:
                        rawcpe = "cpe:/a:-:{}:{}:-:".format(n, v)

                        toks = rawcpe.split(":")
                        final_cpe = ["cpe", "-", "-", "-", "-", "-", "-"]
                        for i in range(1, len(final_cpe)):
                            try:
                                if toks[i]:
                                    final_cpe[i] = toks[i]
                                else:
                                    final_cpe[i] = "-"
                            except:
                                final_cpe[i] = "-"
                        cpekey = ":".join(final_cpe + [path])

                        if cpekey not in allcpes:
                            allcpes[cpekey] = True

                            cpe = ImageCpe()
                            cpe.pkg_type = "go"
                            cpe.pkg_path = path
                            cpe.cpetype = final_cpe[1]
                            cpe.vendor = final_cpe[2]
                            cpe.name = final_cpe[3]
                            cpe.version = final_cpe[4]
                            cpe.update = final_cpe[5]
                            cpe.meta = final_cpe[6]
                            cpe.image_user_id = containing_image.user_id
                            cpe.image_id = containing_image.id

                            cpes.append(cpe)
        return cpes

    def get_fuzzy_binary_cpes(self, analysis_json, allcpes, containing_image):
        cpes = []
        bin_json_raw = (
            analysis_json.get("package_list", {}).get("pkgs.binary", {}).get("base")
        )
        if bin_json_raw:
            for path, bin_str in list(bin_json_raw.items()):
                bin_json = safe_extract_json_value(bin_str)
                guessed_names = [bin_json["name"]]
                guessed_versions = [bin_json["version"]]
                for n in guessed_names:
                    for v in guessed_versions:
                        rawcpe = "cpe:/a:-:{}:{}:-:".format(n, v)

                        toks = rawcpe.split(":")
                        final_cpe = ["cpe", "-", "-", "-", "-", "-", "-"]
                        for i in range(1, len(final_cpe)):
                            try:
                                if toks[i]:
                                    final_cpe[i] = toks[i]
                                else:
                                    final_cpe[i] = "-"
                            except:
                                final_cpe[i] = "-"
                        cpekey = ":".join(final_cpe + [path])

                        if cpekey not in allcpes:
                            allcpes[cpekey] = True

                            cpe = ImageCpe()
                            cpe.pkg_type = "binary"
                            cpe.pkg_path = path
                            cpe.cpetype = final_cpe[1]
                            cpe.vendor = final_cpe[2]
                            cpe.name = final_cpe[3]
                            cpe.version = final_cpe[4]
                            cpe.update = final_cpe[5]
                            cpe.meta = final_cpe[6]
                            cpe.image_user_id = containing_image.user_id
                            cpe.image_id = containing_image.id

                            cpes.append(cpe)
        return cpes
