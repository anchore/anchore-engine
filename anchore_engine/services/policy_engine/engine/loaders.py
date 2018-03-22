import hashlib
import json
import re

from anchore_engine.db import DistroNamespace
from anchore_engine.db import Image, ImagePackage, FilesystemAnalysis, ImageNpm, ImageGem, AnalysisArtifact, ImagePackageManifestEntry, ImageCpe
from .logs import get_logger
from .util.rpm import split_rpm_filename

log = get_logger()


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

        log.info('Loading image json')

        if type(self.image_export_json) == list and len(self.image_export_json) == 1:
            image_id = self.image_export_json[0]['image']['imageId']
            self.image_export_json = self.image_export_json[0]['image']['imagedata']
            log.info('Detected a direct export format for image id: {} rather than a catalog analysis export'.format(
                image_id))

        analysis_report = self.image_export_json['analysis_report']
        image_report = self.image_export_json['image_report']

        image = Image()
        image.id = image_report['meta']['imageId']
        image.size = int(image_report['meta']['sizebytes'])
        repo_digests = image_report['docker_data'].get('RepoDigests', [])
        repo_tags = image_report['docker_data'].get('RepoTags', [])
        if len(repo_digests) > 1:
            log.warn(
                'Found more than one digest for the image {}. Using the first. Digests: {}, Tags: {}'.format(image.id,
                                                                                                             repo_digests,
                                                                                                             repo_tags))

        image.digest = repo_digests[0].split('@', 1)[1] if repo_digests else None

        # Tags handled in another phase using the docker_data in the image record.

        # get initial metadata
        analyzer_meta = analysis_report['analyzer_meta']['analyzer_meta']['base']
        if 'LIKEDISTRO' in analyzer_meta:
            like_dist = analyzer_meta['LIKEDISTRO']
        else:
            like_dist = analyzer_meta['DISTRO']

        image.distro_name = analyzer_meta['DISTRO']
        image.distro_version = analyzer_meta['DISTROVERS']
        image.like_distro = like_dist

        image.dockerfile_mode = image_report['dockerfile_mode']

        # JSON data
        image.docker_data_json = image_report['docker_data']
        image.docker_history_json = image_report['docker_history']
        image.dockerfile_contents = image_report['dockerfile_contents']
        image.layers_to_dockerfile_json = analysis_report.get('layer_info')
        image.layers_json = image_report['layers']
        image.familytree_json = image_report['familytree']
        image.analyzer_manifest = self.image_export_json['analyzer_manifest']

        # Image content

        # Packages
        log.info('Loading image packages')
        image.packages = self.load_and_normalize_packages(analysis_report.get('package_list', {}), image)

        # Package metadata
        log.info('Loading image package db entries')
        self.load_package_verification(analysis_report, image)

        # FileSystem
        log.info('Loading image files')
        image.fs = self.load_fsdump(analysis_report)

        # Npms
        log.info('Loading image npms')
        image.npms = self.load_npms(analysis_report, image)

        # Gems
        log.info('Loading image gems')
        image.gems = self.load_gems(analysis_report, image)

        # CPEs
        log.info('Loading image cpes')
        image.cpes = self.load_cpes(analysis_report, image)

        analysis_artifact_loaders = [
            self.load_retrieved_files,
            self.load_content_search,
            self.load_secret_search
            #self.load_package_verification
        ]

        # Content searches
        image.analysis_artifacts = []
        for loader in analysis_artifact_loaders:
            for r in loader(analysis_report, image):
                image.analysis_artifacts.append(r)

        image.state = 'analyzed'
        return image

    def load_package_verification(self, analysis_report, image_obj):
        """
        Loads package verification analysis data.
        Adds the package db metadata records to respective packages in the image_obj

        :param analysis_report:
        :param image_obj:
        :return: True on success
        """

        log.info('Loading package verification data')
        analyzer = 'file_package_verify'
        pkgfile_meta = 'distro.pkgfilemeta'
        verify_result = 'distro.verifyresult'
        digest_algos = [
            'sha1',
            'sha256',
            'md5'
        ]

        package_verify_json = analysis_report.get(analyzer)
        if not package_verify_json:
            return []

        file_records = package_verify_json.get(pkgfile_meta, {}).get('base', {})
        verify_records = package_verify_json.get(verify_result, {}).get('base', {})


        # Re-organize the data from file-keyed to package keyed for efficient filtering
        packages = {}
        for path, file_meta in file_records.items():
            for r in json.loads(file_meta):
                pkg = r.pop('package')
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

            for f_name, entry in pkg_entry.items():
                meta = ImagePackageManifestEntry()
                meta.pkg_name = package.name
                meta.pkg_version = package.version
                meta.pkg_type = package.pkg_type
                meta.pkg_arch = package.arch
                meta.image_id = package.image_id
                meta.image_user_id = package.image_user_id
                meta.file_path = f_name
                meta.digest_algorithm = entry.get('digestalgo')
                meta.digest = entry.get('digest')
                meta.file_user_name = entry.get('user')
                meta.file_group_name = entry.get('group')
                meta.is_config_file = entry.get('conffile')

                m = entry.get('mode')
                s = entry.get('size')
                meta.mode = int(m, 8) if m is not None else m # Convert from octal to decimal int
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
        #return records

    def load_retrieved_files(self, analysis_report, image_obj):
        """
        Loads the analyzer retrieved files from the image, saves them in the db

        :param retrieve_files_json:
        :param image_obj:
        :return:
        """
        log.info('Loading retrieved files')
        retrieve_files_json = analysis_report.get('retrieve_files')
        if not retrieve_files_json:
            return []

        matches = retrieve_files_json.get('file_content.all', {}).get('base', {})
        records = []

        for filename, match_string in matches.items():
            match = AnalysisArtifact()
            match.image_user_id = image_obj.user_id
            match.image_id = image_obj.id
            match.analyzer_id = 'retrieve_files'
            match.analyzer_type = 'base'
            match.analyzer_artifact = 'file_content.all'
            match.artifact_key = filename
            try:
                match.binary_value = bytearray(match_string.decode('base64'))
            except:
                log.exception('Could not b64 decode the file content for {}'.format(filename))
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
        log.info('Loading content search results')
        content_search_json = analysis_report.get('content_search')
        if not content_search_json:
            return []

        matches = content_search_json.get('regexp_matches.all', {}).get('base', {})
        records = []

        for filename, match_string in matches.items():
            match = AnalysisArtifact()
            match.image_user_id = image_obj.user_id
            match.image_id = image_obj.id
            match.analyzer_id = 'content_search'
            match.analyzer_type = 'base'
            match.analyzer_artifact = 'regexp_matches.all'
            match.artifact_key = filename
            try:
                match.json_value = json.loads(match_string)
            except:
                log.exception('json decode failed for regex match record on {}. Saving as raw text'.format(filename))
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
        log.info('Loading content search results')
        content_search_json = analysis_report.get('secret_search')
        if not content_search_json:
            return []

        matches = content_search_json.get('regexp_matches.all', {}).get('base', {})
        records = []

        for filename, match_string in matches.items():
            match = AnalysisArtifact()
            match.image_user_id = image_obj.user_id
            match.image_id = image_obj.id
            match.analyzer_id = 'secret_search'
            match.analyzer_type = 'base'
            match.analyzer_artifact = 'regexp_matches.all'
            match.artifact_key = filename
            try:
                match.json_value = json.loads(match_string)
            except:
                log.exception('json decode failed for regex match record on {}. Saving as raw text'.format(filename))
                match.str_value = match_string

            records.append(match)

        return records

    def load_and_normalize_packages(self, package_analysis_json, image_obj):
        """
        Loads and normalizes package data from all distros

        :param image_obj:
        :param package_analysis_json:
        :return: list of Package objects that can be added to an image
        """
        pkgs = []

        img_distro = DistroNamespace.for_obj(image_obj)

        # pkgs.allinfo handling
        pkgs_all = package_analysis_json.get('pkgs.allinfo', {}).values()
        if not pkgs_all:
            return []
        else:
            pkgs_all = pkgs_all[0]

        for pkg_name, metadata_str in pkgs_all.items():
            metadata = json.loads(metadata_str)

            p = ImagePackage()
            p.distro_name = image_obj.distro_name
            p.distro_version = image_obj.distro_version
            p.like_distro = image_obj.like_distro

            p.name = pkg_name
            p.version = metadata.get('version')
            p.origin = metadata.get('origin')
            p.size = metadata.get('size')
            p.arch = metadata.get('arch')
            p.license = metadata.get('license') if metadata.get('license') else metadata.get('lics')
            p.release = metadata.get('release', 'N/A')
            p.pkg_type = metadata.get('type')
            p.src_pkg = metadata.get('sourcepkg')
            p.image_user_id = image_obj.user_id
            p.image_id = image_obj.id

            if 'files' in metadata:
                # Handle file data
                p.files = metadata.get('files')

            if p.release != 'N/A':
                p.fullversion = p.version + '-' + p.release
            else:
                p.fullversion = p.version

            if img_distro.flavor == 'DEB':
                cleanvers = re.sub(re.escape("+b") + "\d+.*", "", p.version)
                spkg = re.sub(re.escape("-" + cleanvers), "", p.src_pkg)
            else:
                spkg = re.sub(re.escape("-" + p.version) + ".*", "", p.src_pkg)

            p.normalized_src_pkg = spkg
            pkgs.append(p)

        if pkgs:
            return pkgs
        else:
            log.warn('Pkg Allinfo not found, reverting to using pkgs.all')

        all_pkgs = package_analysis_json['pkgs.all']['base']
        all_pkgs_src = package_analysis_json['pkgs_plus_source.all']['base']

        for pkg_name, version in all_pkgs.items():
            p = ImagePackage()
            p.image_user_id = image_obj.user_id
            p.image_id = image_obj.id
            p.name = pkg_name
            p.version = version
            p.fullversion = all_pkgs_src[pkg_name]

            if img_distro.flavor == 'RHEL':
                name, parsed_version, release, epoch, arch = split_rpm_filename(
                    pkg_name + '-' + version + '.tmparch.rpm')
                p.version = parsed_version
                p.release = release
                p.pkg_type = 'RPM'
                p.origin = 'N/A'
                p.src_pkg = 'N/A'
                p.license = 'N/A'
                p.arch = 'N/A'
            elif img_distro.flavor == 'DEB':
                try:
                    p.version, p.release = version.split('-')
                except:
                    p.version = version
                    p.release = None

        return pkgs

    def load_fsdump(self, analysis_report_json):
        """
        Returns a single FSDump entity composed of a the compressed and hashed json of the fs entries along with some statistics.
        This function will pull necessariy bits from the fully analysis to construct a view of the FS suitable for gate eval.

        :param analysis_report_json: the full json analysis report
        :return:
        """

        file_entries = {}
        all_infos = analysis_report_json.get('file_list').get('files.allinfo', {}).get('base', [])
        file_perms = analysis_report_json.get('file_list').get('files.all', {}).get('base', [])
        md5_checksums = analysis_report_json.get('file_checksums').get('files.md5sums', {}).get('base', {})
        sha256_checksums = analysis_report_json.get('file_checksums').get('files.sha256sums', {}).get('base', {})
        sha1_checksums = analysis_report_json.get('file_checksums').get('files.sha1sums', {}).get('base', {})
        non_pkged = analysis_report_json.get('file_list').get('files.nonpkged', {}).get('base', [])
        suids = analysis_report_json.get('file_suids', {}).get('files.suids', {}).get('base', {})
        pkgd = analysis_report_json.get('package_list', {}).get('pkgfiles.all', {}).get('base', [])

        path_map = {path: json.loads(value) for path, value in all_infos.items()}
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

        for path, metadata in path_map.items():
            try:
                full_path = metadata['fullpath']
                f = {
                    'fullpath': full_path,
                    'name': metadata['name'],
                    'mode': metadata['mode'],
                    'permissions': file_perms.get(path),
                    'linkdst_fullpath': metadata['linkdst_fullpath'],
                    'linkdst': metadata['linkdst'],
                    'size': metadata['size'],
                    'entry_type': metadata['type'],
                    'is_packaged': path in pkgd,
                    'md5_checksum': md5_checksums.get(path, 'DIRECTORY_OR_OTHER'),
                    'sha256_checksum': sha256_checksums.get(path, 'DIRECTORY_OR_OTHER'),
                    'sha1_checksum': sha1_checksums.get(path, 'DIRECTORY_OR_OTHER') if sha1_checksums else None,
                    'othernames': [],
                    'suid': suids.get(path)
                }
            except KeyError as e:
                log.exception('Could not find data for {}'.format(e))
                raise

            # Increment counters as needed
            if f['suid']:
                entry.suid_count += 1

            if not f['is_packaged']:
                entry.non_packaged_count += 1

            if f['entry_type'] == 'file':
                entry.file_count += 1
            elif f['entry_type'] == 'dir':
                entry.directory_count += 1

            file_entries[path] = f

        # Compress and set the data
        entry.total_entry_count = len(file_entries)
        entry.files = file_entries
        return entry

    def load_npms(self, analysis_json, containing_image):
        npms_json = analysis_json.get('package_list', {}).get('pkgs.npms',{}).get('base')
        if not npms_json:
            return []

        npms = []
        for path, npm_str in npms_json.items():
            npm_json = json.loads(npm_str)
            n = ImageNpm()
            n.path_hash = hashlib.sha256(path).hexdigest()
            n.path = path
            n.name = npm_json.get('name')
            n.src_pkg = npm_json.get('src_pkg')
            n.origins_json = npm_json.get('origins')
            n.licenses_json = npm_json.get('lics')
            n.latest = npm_json.get('latest')
            n.versions_json = npm_json.get('versions')
            n.image_user_id = containing_image.user_id
            n.image_id = containing_image.id
            npms.append(n)

        return npms

    def load_gems(self, analysis_json, containing_image):
        gems_json = analysis_json.get('package_list', {}).get('pkgs.gems', {}).get('base')
        if not gems_json:
            return []

        gems = []
        for path, gem_str in gems_json.items():
            gem_json = json.loads(gem_str)
            n = ImageGem()
            n.path_hash = hashlib.sha256(path).hexdigest()
            n.path = path
            n.name = gem_json.get('name')
            n.src_pkg = gem_json.get('src_pkg')
            n.origins_json = gem_json.get('origins')
            n.licenses_json = gem_json.get('lics')
            n.versions_json = gem_json.get('versions')
            n.latest = gem_json.get('latest')
            n.image_user_id = containing_image.user_id
            n.image_id = containing_image.id
            gems.append(n)

        return gems

    def _fuzzy_java(self, input_el):
        ret_names = []
        ret_versions = []

        iversion = input_el.get('implementation-version', "N/A")
        if iversion != 'N/A':
            ret_versions.append(iversion)

        sversion = input_el.get('specification-version', "N/A")
        if sversion != 'N/A':
            if sversion not in ret_versions:
                ret_versions.append(sversion)

        # do some heuristic tokenizing
        try:
            toks = re.findall("[^-]+", input_el['name'])
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
                    if '-'.join([gthing]+fullname) not in ret_names:
                        ret_names.append('-'.join([gthing]+fullname))

            if firstversion:
                firstversion_nosuffix = re.sub("\.(RELEASE|GA)$", "", firstversion)
                for gthing in [firstversion, firstversion_nosuffix]:
                    if gthing not in ret_versions:
                        ret_versions.append(gthing)
                    if '-'.join([gthing]+fullversion) not in ret_versions:
                        ret_versions.append('-'.join([gthing]+fullversion))

        except Exception as err:
            log.warn("failed to detect java package name/version guesses - exception: " + str(err))

        return(ret_names, ret_versions)

    def load_cpes(self, analysis_json, containing_image):
        allcpes = {}
        cpes = []
        
        # do java first (from analysis)
        java_json = analysis_json.get('package_list', {}).get('pkgs.java', {}).get('base')
        if java_json:
            for path, java_str in java_json.items():
                java_json = json.loads(java_str)

                try:
                    guessed_names, guessed_versions = self._fuzzy_java(java_json)
                except Exception as err:
                    guessed_names = guessed_versions = []

                for n in guessed_names:
                    for v in guessed_versions:
                        rawcpe = "cpe:/a:-:{}:{}".format(n, v)

                        toks = rawcpe.split(":")
                        final_cpe = ['cpe', '-', '-', '-', '-', '-', '-']
                        for i in range(1, len(final_cpe)):
                            try:
                                if toks[i]:
                                    final_cpe[i] = toks[i]
                                else:
                                    final_cpe[i] = '-'
                            except:
                                final_cpe[i] = '-'
                        thecpe = ':'.join(final_cpe)

                        if thecpe not in allcpes:
                            allcpes[thecpe] = True

                            cpe = ImageCpe()
                            cpe.pkg_type = "java"
                            cpe.cpetype = final_cpe[1]
                            cpe.vendor = final_cpe[2]
                            cpe.name = final_cpe[3]
                            cpe.version = final_cpe[4]
                            cpe.update = final_cpe[5]
                            cpe.meta = final_cpe[6]
                            cpe.image_user_id = containing_image.user_id
                            cpe.image_id = containing_image.id

                            cpes.append(cpe)

        # disable for now
        if True:
            if containing_image.gems:
                for gem in containing_image.gems:
                    for version in gem.versions_json:
                        rawcpe = "cpe:/a:-:{}:{}:-:~~~ruby~~".format(gem.name, version)

                        toks = rawcpe.split(":")
                        final_cpe = ['cpe', '-', '-', '-', '-', '-', '-']
                        for i in range(1, len(final_cpe)):
                            try:
                                if toks[i]:
                                    final_cpe[i] = toks[i]
                                else:
                                    final_cpe[i] = '-'
                            except:
                                final_cpe[i] = '-'
                        thecpe = ':'.join(final_cpe)

                        if thecpe not in allcpes:
                            allcpes[thecpe] = True

                            cpe = ImageCpe()
                            cpe.pkg_type = "gem"
                            cpe.cpetype = final_cpe[1]
                            cpe.vendor = final_cpe[2]
                            cpe.name = final_cpe[3]
                            cpe.version = final_cpe[4]
                            cpe.update = final_cpe[5]
                            cpe.meta = final_cpe[6]
                            cpe.image_user_id = containing_image.user_id
                            cpe.image_id = containing_image.id

                            cpes.append(cpe)

            if containing_image.npms:
                for npm in containing_image.npms:
                    for version in npm.versions_json:
                        rawcpe = "cpe:/a:-:{}:{}:-:~~~node.js~~".format(npm.name, version)

                        toks = rawcpe.split(":")
                        final_cpe = ['cpe', '-', '-', '-', '-', '-', '-']
                        for i in range(1, len(final_cpe)):
                            try:
                                if toks[i]:
                                    final_cpe[i] = toks[i]
                                else:
                                    final_cpe[i] = '-'
                            except:
                                final_cpe[i] = '-'
                        thecpe = ':'.join(final_cpe)

                        if thecpe not in allcpes:
                            allcpes[thecpe] = True

                            cpe = ImageCpe()
                            cpe.pkg_type = "npm"
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
