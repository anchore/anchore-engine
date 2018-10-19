from anchore_engine.services.policy_engine.engine.policy.gate import Gate, BaseTrigger
from anchore_engine.services.policy_engine.engine.policy.params import TypeValidator, TriggerParameter
from anchore_engine.db import NpmMetadata
from anchore_engine.services.policy_engine.engine.logs import get_logger
from anchore_engine.services.policy_engine.engine.feeds import DataFeeds

log = get_logger()

# TODO; generalize these for any feed, with base classes and children per feed type

FEED_KEY = 'npm'
NPM_LISTING_KEY = 'npms'
NPM_MATCH_KEY = 'matched_feed_npms'


class NotLatestTrigger(BaseTrigger):
    __trigger_name__ = 'newer_version_in_feed'
    __description__ = 'Triggers if an installed NPM is not the latest version according to NPM data feed.'

    def evaluate(self, image_obj, context):
        """
        Fire for any npm in the image that is in the official npm feed but is not the latest version.
        Mutually exclusive to NPMNOTOFFICIAL and NPMBADVERSION

        """
        feed_npms = context.data.get(NPM_MATCH_KEY)
        img_npms = context.data.get(NPM_LISTING_KEY)

        if feed_npms or not img_npms:
            return

        feed_names = {p.name: p.latest for p in feed_npms}

        for npm, versions in list(img_npms.items()):
            if npm not in feed_names:
                continue # Not an official

            for v in versions:
                if v and v != feed_names.get(npm):
                    self._fire(msg="NPMNOTLATEST Package ({}) version ({}) installed but is not the latest version ({})".format(npm, v, feed_names[npm]['latest']))


class NotOfficialTrigger(BaseTrigger):
    __trigger_name__ = 'unknown_in_feeds'
    __description__ = 'Triggers if an installed NPM is not in the official NPM database, according to NPM data feed.'

    def evaluate(self, image_obj, context):
        """
        Fire for any npm that is not in the official npm feed data set.

        Mutually exclusive to NPMNOTLATEST and NPMBADVERSION

        :param image_obj:
        :param context:
        :return:
        """

        feed_npms = context.data.get(NPM_MATCH_KEY)
        img_npms = context.data.get(NPM_LISTING_KEY)

        if feed_npms or not img_npms:
            return

        feed_names = {p.name: p.versions_json for p in feed_npms}

        for npm in list(img_npms.keys()):
            if npm not in feed_names:
                self._fire(msg="NPMNOTOFFICIAL Package ("+str(npm)+") in container but not in official NPM feed.")


class BadVersionTrigger(BaseTrigger):
    __trigger_name__ = 'version_not_in_feeds'
    __description__ = 'Triggers if an installed NPM version is not listed in the official NPM feed as a valid version.'

    def evaluate(self, image_obj, context):
        """
        Fire for any npm that is in the official npm set but is not one of the official versions.

        Mutually exclusive to NPMNOTOFFICIAL and NPMNOTLATEST

        :param image_obj:
        :param context:
        :return:
        """
        feed_npms = context.data.get(NPM_MATCH_KEY)
        img_npms = context.data.get(NPM_LISTING_KEY)

        if feed_npms or not img_npms:
            return

        feed_names = {p.name: p.versions_json for p in feed_npms}

        for npm, versions in list(img_npms.items()):
            if npm not in feed_names:
                continue

            non_official_versions = set(versions).difference(set(feed_names.get(npm, [])))
            for v in non_official_versions:
                self._fire(msg="NPMBADVERSION Package ("+npm+") version ("+v+") installed but version is not in the official feed for this package ("+str(feed_names.get(npm, '')) + ")")


class PkgMatchTrigger(BaseTrigger):
    __trigger_name__ = 'blacklisted_name_version'
    __description__ = 'Triggers if the evaluated image has an NPM package installed that matches the name and optionally a version specified in the parameters.'

    name = TriggerParameter(validator=TypeValidator('string'), name='name', is_required=True, description='Npm package name to blacklist.', example_str='time_diff', sort_order=1)
    version = TriggerParameter(validator=TypeValidator('string'), name='version', is_required=False, description='Npm package version to blacklist specifically.', example_str='0.2.9', sort_order=2)

    def evaluate(self, image_obj, context):
        """
        Fire for any npm that is on the blacklist with a full name + version match
        :param image_obj:
        :param context:
        :return:
        """
        npms = image_obj.get_packages_by_type('npm')
        if not npms:
            return

        pkgs = context.data.get(NPM_LISTING_KEY)
        if not pkgs:
            return

        name = self.name.value()
        version = self.version.value(default_if_none=None)

        if name in pkgs:
            pkg_versions = pkgs.get(name)
            if not pkg_versions:
                pkg_versions = []
            if version and version in pkg_versions:
                self._fire(msg='NPM Package is blacklisted: ' + name + "-" + version)
            elif version is None:
                self._fire(msg='NPM Package is blacklisted: ' + name)


class NoFeedTrigger(BaseTrigger):
    __trigger_name__ = 'feed_data_unavailable'
    __description__ = 'Triggers if the engine does not have access to the NPM data feed.'
    __msg__ = "NPM packages are present but the anchore npm feed is not available - will be unable to perform checks that require feed data"

    def evaluate(self, image_obj, context):
        try:
            feed_meta = DataFeeds.instance().packages.group_by_name(FEED_KEY)
            if feed_meta and feed_meta[0].last_sync:
                return
        except Exception as e:
            log.exception('Error determining feed presence for npms. Defaulting to firing trigger')

        self._fire()
        return


class NpmCheckGate(Gate):
        __gate_name__ = 'npms'
        __description__ = 'NPM Checks'
        __triggers__ = [
            NotLatestTrigger,
            NotOfficialTrigger,
            BadVersionTrigger,
            PkgMatchTrigger,
            NoFeedTrigger
        ]

        def prepare_context(self, image_obj, context):
            """
            Prep the npm names and versions
            :rtype: 
            :param image_obj:
            :param context:
            :return:
            """

            db_npms = image_obj.get_packages_by_type('npm')
            if not db_npms:
                return context

            #context.data[NPM_LISTING_KEY] = {p.name: p.versions_json for p in image_obj.npms}
            npm_listing_key_data = {}
            for p in db_npms:
                if p.name not in npm_listing_key_data:
                    npm_listing_key_data[p.name] = []
                npm_listing_key_data[p.name].append(p.version)
            context.data[NPM_LISTING_KEY] = npm_listing_key_data

            npms = list(context.data[NPM_LISTING_KEY].keys())
            context.data[NPM_MATCH_KEY] = []
            chunks = [npms[i: i+100] for i in range(0, len(npms), 100)]
            for key_range in chunks:
                context.data[NPM_MATCH_KEY] += context.db.query(NpmMetadata).filter(NpmMetadata.name.in_(key_range)).all()

            return context
